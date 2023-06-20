# Python Substrate Interface Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import warnings

from datetime import datetime
from hashlib import blake2b

import json
import logging

import requests
from typing import Optional, Union, List

from websocket import create_connection, WebSocketConnectionClosedException

from scalecodec.base import ScaleBytes, RuntimeConfigurationObject, ScaleType
from scalecodec.types import GenericCall, GenericExtrinsic, Extrinsic, MultiAccountId, GenericRuntimeCallDefinition
from scalecodec.type_registry import load_type_registry_preset
from scalecodec.updater import update_type_registries
from .extensions import Extension
from .interfaces import ExtensionInterface

from .storage import StorageKey

from .exceptions import SubstrateRequestException, ConfigurationError, StorageFunctionNotFound, BlockNotFound, \
    ExtrinsicNotFound, ExtensionCallNotFound
from .constants import *
from .keypair import Keypair, KeypairType, MnemonicLanguageCode
from .utils.ss58 import ss58_decode, ss58_encode, is_valid_ss58_address, get_ss58_format


__all__ = ['SubstrateInterface', 'ExtrinsicReceipt', 'logger']

logger = logging.getLogger(__name__)


def list_remove_iter(xs: list):
    removed = False
    def remove():
        nonlocal removed
        removed = True

    i = 0
    while i < len(xs):
        removed = False
        yield xs[i], remove
        if removed:
            xs.pop(i)
        else:
            i += 1


class SubstrateInterface:

    def __init__(self, url=None, websocket=None, ss58_format=None, type_registry=None, type_registry_preset=None,
                 cache_region=None, runtime_config=None, use_remote_preset=False, ws_options=None,
                 auto_discover=True, auto_reconnect=True):
        """
        A specialized class in interfacing with a Substrate node.

        Parameters
        ----------
        url: the URL to the substrate node, either in format https://127.0.0.1:9933 or wss://127.0.0.1:9944
        ss58_format: The address type which account IDs will be SS58-encoded to Substrate addresses. Defaults to 42, for Kusama the address type is 2
        type_registry: A dict containing the custom type registry in format: {'types': {'customType': 'u32'},..}
        type_registry_preset: The name of the predefined type registry shipped with the SCALE-codec, e.g. kusama
        cache_region: a Dogpile cache region as a central store for the metadata cache
        use_remote_preset: When True preset is downloaded from Github master, otherwise use files from local installed scalecodec package
        ws_options: dict of options to pass to the websocket-client create_connection function
        """

        if (not url and not websocket) or (url and websocket):
            raise ValueError("Either 'url' or 'websocket' must be provided")

        # Initialize lazy loading variables
        self.__version = None
        self.__name = None
        self.__properties = None
        self.__chain = None

        self.__token_decimals = None
        self.__token_symbol = None
        self.__ss58_format = None

        if not runtime_config:
            runtime_config = RuntimeConfigurationObject()

        self.runtime_config = runtime_config

        self.cache_region = cache_region

        if ss58_format is not None:
            self.ss58_format = ss58_format

        self.type_registry_preset = type_registry_preset
        self.type_registry = type_registry

        self.request_id = 1
        self.url = url
        self.websocket = None

        # Websocket connection options
        self.ws_options = ws_options or {}

        if 'max_size' not in self.ws_options:
            self.ws_options['max_size'] = 2 ** 32

        if 'read_limit' not in self.ws_options:
            self.ws_options['read_limit'] = 2 ** 32

        if 'write_limit' not in self.ws_options:
            self.ws_options['write_limit'] = 2 ** 32

        self.__rpc_message_queue = []

        if self.url and (self.url[0:6] == 'wss://' or self.url[0:5] == 'ws://'):
            self.connect_websocket()

        elif websocket:
            self.websocket = websocket

        self.mock_extrinsics = None
        self.default_headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }

        self.metadata = None

        self.runtime_version = None
        self.transaction_version = None

        self.block_hash = None
        self.block_id = None

        self.__metadata_cache = {}

        self.config = {
            'use_remote_preset': use_remote_preset,
            'auto_discover': auto_discover,
            'auto_reconnect': auto_reconnect,
            'rpc_methods': None
        }

        # Initialize extension interface
        self.extensions = ExtensionInterface(self)

        self.session = requests.Session()

        self.reload_type_registry(use_remote_preset=use_remote_preset, auto_discover=auto_discover)

    def connect_websocket(self):
        """
        (Re)creates the websocket connection, if the URL contains a 'ws' or 'wss' scheme

        Returns
        -------

        """
        if self.url and (self.url[0:6] == 'wss://' or self.url[0:5] == 'ws://'):
            self.debug_message("Connecting to {} ...".format(self.url))
            self.websocket = create_connection(
                self.url,
                **self.ws_options
            )

    def close(self):
        """
        Cleans up resources for this instance like active websocket connection and active extensions

        Returns
        -------

        """
        if self.websocket:
            self.debug_message("Closing websocket connection")
            self.websocket.close()

        self.extensions.unregister_all()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def debug_message(message: str):
        """
        Submits a message to the debug logger

        Parameters
        ----------
        message: str Debug message

        Returns
        -------

        """
        logger.debug(message)

    def supports_rpc_method(self, name: str) -> bool:
        """
        Check if substrate RPC supports given method
        Parameters
        ----------
        name: name of method to check

        Returns
        -------
        bool
        """
        if self.config.get('rpc_methods') is None:
            self.config['rpc_methods'] = []
            result = self.rpc_request("rpc_methods", []).get('result')
            if result:
                self.config['rpc_methods'] = result.get('methods', [])

        return name in self.config['rpc_methods']

    def rpc_request(self, method, params, result_handler=None):
        """
        Method that handles the actual RPC request to the Substrate node. The other implemented functions eventually
        use this method to perform the request.

        Parameters
        ----------
        result_handler: Callback function that processes the result received from the node
        method: method of the JSONRPC request
        params: a list containing the parameters of the JSONRPC request

        Returns
        -------
        a dict with the parsed result of the request.
        """

        request_id = self.request_id
        self.request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }

        self.debug_message('RPC request #{}: "{}"'.format(request_id, method))

        if self.websocket:
            try:
                self.websocket.send(json.dumps(payload))
            except WebSocketConnectionClosedException:
                if self.config.get('auto_reconnect') and self.url:
                    # Try to reconnect websocket and retry rpc_request
                    self.debug_message("Connection Closed; Trying to reconnecting...")
                    self.connect_websocket()

                    return self.rpc_request(method=method, params=params, result_handler=result_handler)
                else:
                    # websocket connection is externally created, re-raise exception
                    raise

            update_nr = 0
            json_body = None
            subscription_id = None

            while json_body is None:
                # Search for subscriptions
                for message, remove_message in list_remove_iter(self.__rpc_message_queue):

                    # Check if result message is matching request ID
                    if 'id' in message and message['id'] == request_id:

                        remove_message()

                        # Check if response has error
                        if 'error' in message:
                            raise SubstrateRequestException(message['error'])

                        # If result handler is set, pass result through and loop until handler return value is set
                        if callable(result_handler):

                            # Set subscription ID and only listen to messages containing this ID
                            subscription_id = message['result']
                            self.debug_message(f"Websocket subscription [{subscription_id}] created")

                        else:
                            json_body = message

                # Process subscription updates
                for message, remove_message in list_remove_iter(self.__rpc_message_queue):
                    # Check if message is meant for this subscription
                    if 'params' in message and message['params']['subscription'] == subscription_id:

                        remove_message()

                        self.debug_message(f"Websocket result [{subscription_id} #{update_nr}]: {message}")

                        # Call result_handler with message for processing
                        callback_result = result_handler(message, update_nr, subscription_id)
                        if callback_result is not None:
                            json_body = callback_result

                        update_nr += 1

                # Read one more message to queue
                if json_body is None:
                    self.__rpc_message_queue.append(json.loads(self.websocket.recv()))

        else:

            if result_handler:
                raise ConfigurationError("Result handlers only available for websockets (ws://) connections")

            response = self.session.request("POST", self.url, data=json.dumps(payload), headers=self.default_headers)

            if response.status_code != 200:
                raise SubstrateRequestException(
                    "RPC request failed with HTTP status code {}".format(response.status_code))

            json_body = response.json()

            # Check if response has error
            if 'error' in json_body:
                raise SubstrateRequestException(json_body['error'])

        return json_body

    @property
    def name(self):
        if self.__name is None:
            self.__name = self.rpc_request("system_name", []).get('result')
        return self.__name

    @property
    def properties(self):
        if self.__properties is None:
            self.__properties = self.rpc_request("system_properties", []).get('result')
        return self.__properties

    @property
    def chain(self):
        if self.__chain is None:
            self.__chain = self.rpc_request("system_chain", []).get('result')
        return self.__chain

    @property
    def version(self):
        if self.__version is None:
            self.__version = self.rpc_request("system_version", []).get('result')
        return self.__version

    @property
    def token_decimals(self):
        if self.__token_decimals is None:
            self.__token_decimals = self.properties.get('tokenDecimals')
        return self.__token_decimals

    @token_decimals.setter
    def token_decimals(self, value):
        if type(value) is not int and value is not None:
            raise TypeError('Token decimals must be an int')
        self.__token_decimals = value

    @property
    def token_symbol(self):
        if self.__token_symbol is None:
            if self.properties:
                self.__token_symbol = self.properties.get('tokenSymbol')
            else:
                self.__token_symbol = 'UNIT'
        return self.__token_symbol

    @token_symbol.setter
    def token_symbol(self, value):
        self.__token_symbol = value

    @property
    def ss58_format(self):
        if self.__ss58_format is None:
            if self.properties:

                if self.properties.get('ss58Format') is not None:
                    self.__ss58_format = self.properties.get('ss58Format')
                elif self.properties.get('SS58Prefix') is not None:
                    self.__ss58_format = self.properties.get('SS58Prefix')
            else:
                self.__ss58_format = 42
        return self.__ss58_format

    @ss58_format.setter
    def ss58_format(self, value):
        if type(value) is not int and value is not None:
            raise TypeError('ss58_format must be an int')
        self.__ss58_format = value

        if self.runtime_config:
            self.runtime_config.ss58_format = value

    def implements_scaleinfo(self) -> Optional[bool]:
        """
        Returns True if current runtime implementation a `PortableRegistry` (`MetadataV14` and higher)

        Returns
        -------
        bool
        """
        if self.metadata:
            return self.metadata.portable_registry is not None

    def get_chain_head(self):
        """
        A pass-though to existing JSONRPC method `chain_getHead`

        Returns
        -------

        """
        if self.supports_rpc_method("chain_getHead"):
            response = self.rpc_request("chain_getHead", [])
        else:
            response = self.rpc_request("chain_getBlockHash", [])

        if response is not None:
            if 'error' in response:
                raise SubstrateRequestException(response['error']['message'])

            return response.get('result')

    def get_chain_finalised_head(self):
        """
        A pass-though to existing JSONRPC method `chain_getFinalizedHead`

        Returns
        -------

        """
        response = self.rpc_request("chain_getFinalizedHead", [])

        if response is not None:
            if 'error' in response:
                raise SubstrateRequestException(response['error']['message'])

            return response.get('result')

    def get_block_hash(self, block_id: int = None) -> str:
        """
        A pass-though to existing JSONRPC method `chain_getBlockHash`

        Parameters
        ----------
        block_id

        Returns
        -------

        """
        response = self.rpc_request("chain_getBlockHash", [block_id])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])
        else:
            return response.get('result')

    def get_block_number(self, block_hash: str) -> int:
        """
        A convenience method to get the block number for given block_hash

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        response = self.rpc_request("chain_getHeader", [block_hash])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        elif 'result' in response:

            if response['result']:
                return int(response['result']['number'], 16)

    def get_block_metadata(self, block_hash=None, decode=True):
        """
        A pass-though to existing JSONRPC method `state_getMetadata`.

        Parameters
        ----------
        block_hash
        decode: True for decoded version

        Returns
        -------

        """
        params = None
        if block_hash:
            params = [block_hash]
        response = self.rpc_request("state_getMetadata", params)

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        if response.get('result') and decode:
            metadata_decoder = self.runtime_config.create_scale_object(
                'MetadataVersioned', data=ScaleBytes(response.get('result'))
            )
            metadata_decoder.decode()

            return metadata_decoder

        return response

    def get_storage_by_key(self, block_hash: str, storage_key: str):
        """
        A pass-though to existing JSONRPC method `state_getStorage`

        Parameters
        ----------
        block_hash
        storage_key

        Returns
        -------

        """

        if self.supports_rpc_method('state_getStorageAt'):
            response = self.rpc_request("state_getStorageAt", [storage_key, block_hash])
        else:
            response = self.rpc_request("state_getStorage", [storage_key, block_hash])

        if 'result' in response:
            return response.get('result')
        elif 'error' in response:
            raise SubstrateRequestException(response['error']['message'])
        else:
            raise SubstrateRequestException("Unknown error occurred during retrieval of events")

    def get_block_runtime_version(self, block_hash):
        """
        Retrieve the runtime version id of given block_hash
        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        if self.supports_rpc_method("state_getRuntimeVersion"):
            response = self.rpc_request("state_getRuntimeVersion", [block_hash])
        else:
            response = self.rpc_request("chain_getRuntimeVersion", [block_hash])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        return response.get('result')

    def generate_storage_hash(self, storage_module: str, storage_function: str, params: list = None,
                              hashers: list = None):
        """
        Generate a storage key for given module/function

        Parameters
        ----------
        storage_module
        storage_function
        params: Parameters of the storage function, provided in scale encoded hex-bytes or ScaleBytes instances
        hashers: Hashing methods used to determine storage key, defaults to 'Twox64Concat' if not provided

        Returns
        -------
        str Hexstring respresentation of the storage key
        """
        warnings.warn("Use StorageKey.generate() instead", DeprecationWarning)

        storage_key = StorageKey.create_from_storage_function(
            storage_module, storage_function, params, runtime_config=self.runtime_config, metadata=self.metadata
        )

        return '0x{}'.format(storage_key.data.hex())

    def convert_storage_parameter(self, scale_type, value):
        warnings.warn("Use StorageKey.generate() instead", DeprecationWarning)

        if type(value) is bytes:
            value = f'0x{value.hex()}'

        if scale_type == 'AccountId':
            if value[0:2] != '0x':
                return '0x{}'.format(ss58_decode(value, self.ss58_format))

        return value

    # Runtime functions used by Substrate API

    def init_runtime(self, block_hash=None, block_id=None):
        """
        This method is used by all other methods that deals with metadata and types defined in the type registry.
        It optionally retrieves the block_hash when block_id is given and sets the applicable metadata for that
        block_hash. Also it applies all the versioned types at the time of the block_hash.

        Because parsing of metadata and type registry is quite heavy, the result will be cached per runtime id.
        In the future there could be support for caching backends like Redis to make this cache more persistent.

        Parameters
        ----------
        block_hash
        block_id

        Returns
        -------

        """

        if block_id and block_hash:
            raise ValueError('Cannot provide block_hash and block_id at the same time')

        # Check if runtime state already set to current block
        if (block_hash and block_hash == self.block_hash) or (block_id and block_id == self.block_id):
            return

        if block_id is not None:
            block_hash = self.get_block_hash(block_id)

        if not block_hash:
            block_hash = self.get_chain_head()

        self.block_hash = block_hash
        self.block_id = block_id

        # In fact calls and storage functions are decoded against runtime of previous block, therefor retrieve
        # metadata and apply type registry of runtime of parent block
        block_header = self.rpc_request('chain_getHeader', [self.block_hash])

        if block_header['result'] is None:
            raise BlockNotFound(f'Block not found for "{self.block_hash}"')

        parent_block_hash = block_header['result']['parentHash']

        if parent_block_hash == '0x0000000000000000000000000000000000000000000000000000000000000000':
            runtime_block_hash = self.block_hash
        else:
            runtime_block_hash = parent_block_hash

        runtime_info = self.get_block_runtime_version(block_hash=runtime_block_hash)

        if runtime_info is None:
            raise SubstrateRequestException(f"No runtime information for block '{block_hash}'")

        # Check if runtime state already set to current block
        if runtime_info.get("specVersion") == self.runtime_version:
            return

        self.runtime_version = runtime_info.get("specVersion")
        self.transaction_version = runtime_info.get("transactionVersion")

        if self.cache_region and self.runtime_version not in self.__metadata_cache:
            # Try to retrieve metadata from Dogpile cache
            cached_metadata = self.cache_region.get('METADATA_{}'.format(self.runtime_version))
            if cached_metadata:
                self.debug_message('Retrieved metadata for {} from Redis'.format(self.runtime_version))
                self.__metadata_cache[self.runtime_version] = cached_metadata

        if self.runtime_version in self.__metadata_cache:
            # Get metadata from cache
            self.debug_message('Retrieved metadata for {} from memory'.format(self.runtime_version))
            self.metadata = self.__metadata_cache[self.runtime_version]
        else:
            self.metadata = self.get_block_metadata(block_hash=runtime_block_hash, decode=True)
            self.debug_message('Retrieved metadata for {} from Substrate node'.format(self.runtime_version))

            # Update metadata cache
            self.__metadata_cache[self.runtime_version] = self.metadata

            if self.cache_region:
                self.debug_message('Stored metadata for {} in Redis'.format(self.runtime_version))
                self.cache_region.set('METADATA_{}'.format(self.runtime_version), self.metadata)

        # Update type registry
        self.reload_type_registry(
            use_remote_preset=self.config.get('use_remote_preset'),
            auto_discover=self.config.get('auto_discover')
        )

        # Check if PortableRegistry is present in metadata (V14+), otherwise fall back on legacy type registry (<V14)
        if self.implements_scaleinfo():
            self.debug_message('Add PortableRegistry from metadata to type registry')
            self.runtime_config.add_portable_registry(self.metadata)

        # Set active runtime version
        self.runtime_config.set_active_spec_version_id(self.runtime_version)

        # Check and apply runtime constants
        ss58_prefix_constant = self.get_constant("System", "SS58Prefix", block_hash=block_hash)

        if ss58_prefix_constant:
            self.ss58_format = ss58_prefix_constant.value

        # Set runtime compatibility flags
        try:
            _ = self.runtime_config.create_scale_object("sp_weights::weight_v2::Weight")
            self.config['is_weight_v2'] = True
            self.runtime_config.update_type_registry_types({'Weight': 'sp_weights::weight_v2::Weight'})
        except NotImplementedError:
            self.config['is_weight_v2'] = False
            self.runtime_config.update_type_registry_types({'Weight': 'WeightV1'})

    def query_map(self, module: str, storage_function: str, params: Optional[list] = None, block_hash: str = None,
                  max_results: int = None, start_key: str = None, page_size: int = 100,
                  ignore_decoding_errors: bool = True) -> 'QueryMapResult':
        """
        Iterates over all key-pairs located at the given module and storage_function. The storage
        item must be a map.

        Example:

        ```
        result = substrate.query_map('System', 'Account', max_results=100)

        for account, account_info in result:
            print(f"Free balance of account '{account.value}': {account_info.value['data']['free']}")
        ```

        Parameters
        ----------
        module: The module name in the metadata, e.g. System or Balances.
        storage_function: The storage function name, e.g. Account or Locks.
        params: The input parameters in case of for example a `DoubleMap` storage function
        block_hash: Optional block hash for result at given block, when left to None the chain tip will be used.
        max_results: the maximum of results required, if set the query will stop fetching results when number is reached
        start_key: The storage key used as offset for the results, for pagination purposes
        page_size: The results are fetched from the node RPC in chunks of this size
        ignore_decoding_errors: When set this will catch all decoding errors, set the item to None and continue decoding

        Returns
        -------
        QueryMapResult
        """

        if block_hash is None:
            # Retrieve chain tip
            block_hash = self.get_chain_head()

        if params is None:
            params = []

        self.init_runtime(block_hash=block_hash)

        metadata_pallet = self.metadata.get_metadata_pallet(module)

        if not metadata_pallet:
            raise StorageFunctionNotFound(f'Pallet "{module}" not found')

        storage_item = metadata_pallet.get_storage_function(storage_function)

        if not metadata_pallet or not storage_item:
            raise StorageFunctionNotFound(f'Storage function "{module}.{storage_function}" not found')

        value_type = storage_item.get_value_type_string()
        param_types = storage_item.get_params_type_string()
        key_hashers = storage_item.get_param_hashers()

        # Check MapType condititions
        if len(param_types) == 0:
            raise ValueError('Given storage function is not a map')

        if len(params) != len(param_types) - 1:
            raise ValueError(f'Storage function map requires {len(param_types) -1} parameters, {len(params)} given')

        # Generate storage key prefix
        storage_key = StorageKey.create_from_storage_function(
            module, storage_function, params, runtime_config=self.runtime_config, metadata=self.metadata
        )
        prefix = storage_key.to_hex()

        if not start_key:
            start_key = prefix

        # Make sure if the max result is smaller than the page size, adjust the page size
        if max_results is not None and max_results < page_size:
            page_size = max_results

        # Retrieve storage keys
        response = self.rpc_request(method="state_getKeysPaged", params=[prefix, page_size, start_key, block_hash])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        result_keys = response.get('result')

        result = []
        last_key = None

        def concat_hash_len(key_hasher: str) -> int:
            if key_hasher == "Blake2_128Concat":
                return 32
            elif key_hasher == "Twox64Concat":
                return 16
            elif key_hasher == "Identity":
                return 0
            else:
                raise ValueError('Unsupported hash type')

        if len(result_keys) > 0:

            last_key = result_keys[-1]

            # Retrieve corresponding value
            response = self.rpc_request(method="state_queryStorageAt", params=[result_keys, block_hash])

            if 'error' in response:
                raise SubstrateRequestException(response['error']['message'])

            for result_group in response['result']:
                for item in result_group['changes']:
                    try:
                        item_key = self.decode_scale(
                            type_string=param_types[len(params)],
                            scale_bytes='0x' + item[0][len(prefix) + concat_hash_len(key_hashers[len(params)]):],
                            return_scale_obj=True,
                            block_hash=block_hash
                        )
                    except Exception:
                        if not ignore_decoding_errors:
                            raise
                        item_key = None

                    try:
                        item_value = self.decode_scale(
                            type_string=value_type,
                            scale_bytes=item[1],
                            return_scale_obj=True,
                            block_hash=block_hash
                        )
                    except Exception:
                        if not ignore_decoding_errors:
                            raise
                        item_value = None

                    result.append([item_key, item_value])

        return QueryMapResult(
            records=result, page_size=page_size, module=module, storage_function=storage_function, params=params,
            block_hash=block_hash, substrate=self, last_key=last_key, max_results=max_results,
            ignore_decoding_errors=ignore_decoding_errors
        )

    def query_multi(self, storage_keys: List[StorageKey], block_hash: Optional[str] = None) -> list:
        """
        Query multiple storage keys in one request.

        Example:

        ```
        storage_keys = [
            substrate.create_storage_key(
                "System", "Account", ["F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T"]
            ),
            substrate.create_storage_key(
                "System", "Account", ["GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi"]
            )
        ]

        result = substrate.query_multi(storage_keys)
        ```

        Parameters
        ----------
        storage_keys: list of StorageKey objects
        block_hash: Optional block_hash of state snapshot

        Returns
        -------
        list of `(storage_key, scale_obj)` tuples
        """

        self.init_runtime(block_hash=block_hash)

        # Retrieve corresponding value
        response = self.rpc_request("state_queryStorageAt", [[s.to_hex() for s in storage_keys], block_hash])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        result = []

        storage_key_map = {s.to_hex(): s for s in storage_keys}

        for result_group in response['result']:
            for change_storage_key, change_data in result_group['changes']:
                # Decode result for specified storage_key
                storage_key = storage_key_map[change_storage_key]
                if change_data is not None:
                    change_data = ScaleBytes(change_data)

                result.append((storage_key, storage_key.decode_scale_value(change_data)))

        return result

    def query(self, module: str, storage_function: str, params: list = None, block_hash: str = None,
              subscription_handler: callable = None, raw_storage_key: bytes = None) -> ScaleType:
        """
        Retrieves the storage entry for given module, function and optional parameters at given block hash.

        When a subscription_handler callback function is passed, a subscription will be maintained as long as this
        handler doesn't return a value.

        Example of subscription handler:
        ```
        def subscription_handler(obj, update_nr, subscription_id):

            if update_nr == 0:
                print('Initial data:', obj.value)

            if update_nr > 0:
                # Do something with the update
                print('data changed:', obj.value)

            # The execution will block until an arbitrary value is returned, which will be the result of the `query`
            if update_nr > 1:
                return obj
        ```

        Parameters
        ----------
        module: The module name in the metadata, e.g. Balances or Account
        storage_function: The storage function name, e.g. FreeBalance or AccountNonce
        params: list of params, in the decoded format of the applicable ScaleTypes
        block_hash: Optional block hash, when omitted the chain tip will be used
        subscription_handler: Callback function that processes the updates of the storage query subscription
        raw_storage_key: Optional raw storage key to query decode instead of generating one

        Returns
        -------
        ScaleType
        """

        if block_hash is not None:
            # Check requirements
            if callable(subscription_handler):
                raise ValueError("Subscriptions can only be registered for current state; block_hash cannot be set")
        else:
            # Retrieve chain tip
            block_hash = self.get_chain_head()

        if params is None:
            params = []

        self.init_runtime(block_hash=block_hash)

        if module == 'Substrate':
            # Search for 'well-known' storage keys
            return self.__query_well_known(storage_function, block_hash)

        # Search storage call in metadata
        metadata_pallet = self.metadata.get_metadata_pallet(module)

        if not metadata_pallet:
            raise StorageFunctionNotFound(f'Pallet "{module}" not found')

        storage_item = metadata_pallet.get_storage_function(storage_function)

        if not metadata_pallet or not storage_item:
            raise StorageFunctionNotFound(f'Storage function "{module}.{storage_function}" not found')

        # SCALE type string of value
        param_types = storage_item.get_params_type_string()
        value_scale_type = storage_item.get_value_type_string()

        if len(params) != len(param_types):
            raise ValueError(f'Storage function requires {len(param_types)} parameters, {len(params)} given')

        if raw_storage_key:
            storage_key = StorageKey.create_from_data(
                data=raw_storage_key, pallet=module, storage_function=storage_function,
                value_scale_type=value_scale_type, metadata=self.metadata, runtime_config=self.runtime_config
            )
        else:

            storage_key = StorageKey.create_from_storage_function(
                module, storage_function, params, runtime_config=self.runtime_config, metadata=self.metadata
            )

        if callable(subscription_handler):

            # Wrap subscription handler to discard storage key arg
            def result_handler(storage_key, updated_obj, update_nr, subscription_id):
                return subscription_handler(updated_obj, update_nr, subscription_id)

            return self.subscribe_storage([storage_key], result_handler)

        else:

            if self.supports_rpc_method('state_getStorageAt'):
                response = self.rpc_request("state_getStorageAt", [storage_key.to_hex(), block_hash])
            else:
                response = self.rpc_request("state_getStorage", [storage_key.to_hex(), block_hash])

            if 'error' in response:
                raise SubstrateRequestException(response['error']['message'])

            if 'result' in response:
                if value_scale_type:

                    if response.get('result') is not None:
                        query_value = response.get('result')
                    elif storage_item.value['modifier'] == 'Default':
                        # Fallback to default value of storage function if no result
                        query_value = storage_item.value_object['default'].value_object
                    else:
                        # No result is interpreted as an Option<...> result
                        value_scale_type = f'Option<{value_scale_type}>'
                        query_value = storage_item.value_object['default'].value_object

                    obj = self.runtime_config.create_scale_object(
                        type_string=value_scale_type,
                        data=ScaleBytes(query_value),
                        metadata=self.metadata
                    )
                    obj.decode()
                    obj.meta_info = {'result_found': response.get('result') is not None}

                    return obj

    def __query_well_known(self, name: str, block_hash: str) -> ScaleType:
        """
        Query well-known storage keys as defined in Substrate

        Parameters
        ----------
        name
        block_hash

        Returns
        -------
        Optional[ScaleType]
        """
        if name not in WELL_KNOWN_STORAGE_KEYS:
            raise StorageFunctionNotFound(f'Well known storage key for "{name}" not found')

        result = self.get_storage_by_key(block_hash, WELL_KNOWN_STORAGE_KEYS[name]['storage_key'])
        obj = self.runtime_config.create_scale_object(
            WELL_KNOWN_STORAGE_KEYS[name]['value_type_string']
        )
        if result:
            obj.decode(ScaleBytes(result))
            obj.meta_info = {'result_found': True}
            return obj
        elif WELL_KNOWN_STORAGE_KEYS[name]['default']:
            obj.decode(ScaleBytes(WELL_KNOWN_STORAGE_KEYS[name]['default']))
            obj.meta_info = {'result_found': False}
            return obj
        else:
            raise ValueError("No value to decode")

    def create_storage_key(self, pallet: str, storage_function: str, params: Optional[list] = None) -> StorageKey:
        """
        Create a `StorageKey` instance providing storage function details. See `subscribe_storage()`.

        Parameters
        ----------
        pallet: name of pallet
        storage_function: name of storage function
        params: Optional list of parameters in case of a Mapped storage function

        Returns
        -------
        StorageKey
        """

        self.init_runtime()

        return StorageKey.create_from_storage_function(
            pallet, storage_function, params, runtime_config=self.runtime_config, metadata=self.metadata
        )

    def subscribe_storage(self, storage_keys: List[StorageKey], subscription_handler: callable):
        """

        Subscribe to provided storage_keys and keep tracking until `subscription_handler` returns a value

        Example of a StorageKey:
        ```
        StorageKey.create_from_storage_function(
            "System", "Account", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]
        )
        ```

        Example of a subscription handler:
        ```
        def subscription_handler(storage_key, obj, update_nr, subscription_id):

            if update_nr == 0:
                print('Initial data:', storage_key, obj.value)

            if update_nr > 0:
                # Do something with the update
                print('data changed:', storage_key, obj.value)

            # The execution will block until an arbitrary value is returned, which will be the result of the function
            if update_nr > 1:
                return obj
        ```

        Parameters
        ----------
        storage_keys: StorageKey list of storage keys to subscribe to
        subscription_handler: callable to handle value changes of subscription

        Returns
        -------

        """
        self.init_runtime()

        storage_key_map = {s.to_hex(): s for s in storage_keys}

        def result_handler(message, update_nr, subscription_id):
            # Process changes
            for change_storage_key, change_data in message['params']['result']['changes']:
                # Check for target storage key
                storage_key = storage_key_map[change_storage_key]
                result_found = False

                if change_data is not None:
                    change_scale_type = storage_key.value_scale_type
                    result_found = True
                elif storage_key.metadata_storage_function.value['modifier'] == 'Default':
                    # Fallback to default value of storage function if no result
                    change_scale_type = storage_key.value_scale_type
                    change_data = storage_key.metadata_storage_function.value_object['default'].value_object
                else:
                    # No result is interpreted as an Option<...> result
                    change_scale_type = f'Option<{storage_key.value_scale_type}>'
                    change_data = storage_key.metadata_storage_function.value_object['default'].value_object

                # Decode SCALE result data
                updated_obj = self.runtime_config.create_scale_object(
                    type_string=change_scale_type,
                    data=ScaleBytes(change_data),
                    metadata=self.metadata
                )
                updated_obj.decode()
                updated_obj.meta_info = {'result_found': result_found}

                subscription_result = subscription_handler(storage_key, updated_obj, update_nr, subscription_id)

                if subscription_result is not None:
                    # Handler returned end result: unsubscribe from further updates
                    self.rpc_request("state_unsubscribeStorage", [subscription_id])

                    return subscription_result

        if not callable(subscription_handler):
            raise ValueError('Provided "subscription_handler" is not callable')

        return self.rpc_request(
            "state_subscribeStorage", [[s.to_hex() for s in storage_keys]], result_handler=result_handler
        )

    def retrieve_pending_extrinsics(self) -> list:
        """
        Retrieves and decodes pending extrinsics from the node's transaction pool

        Returns
        -------
        list of extrinsics
        """

        self.init_runtime()

        result_data = self.rpc_request("author_pendingExtrinsics", [])

        extrinsics = []

        for extrinsic_data in result_data['result']:
            extrinsic = self.runtime_config.create_scale_object('Extrinsic', metadata=self.metadata)
            extrinsic.decode(ScaleBytes(extrinsic_data))
            extrinsics.append(extrinsic)

        return extrinsics

    def runtime_call(self, api: str, method: str, params: Union[list, dict] = None, block_hash: str = None) -> ScaleType:
        """
        Calls a runtime API method

        Parameters
        ----------
        api: Name of the runtime API e.g. 'TransactionPaymentApi'
        method: Name of the method e.g. 'query_fee_details'
        params: List of parameters needed to call the runtime API
        block_hash: Hash of the block at which to make the runtime API call

        Returns
        -------
        ScaleType
        """
        self.init_runtime()

        self.debug_message(f"Executing Runtime Call {api}.{method}")

        if params is None:
            params = {}

        try:
            runtime_call_def = self.runtime_config.type_registry["runtime_api"][api]['methods'][method]
            runtime_api_types = self.runtime_config.type_registry["runtime_api"][api].get("types", {})
        except KeyError:
            raise ValueError(f"Runtime API Call '{api}.{method}' not found in registry")

        if type(params) is list and len(params) != len(runtime_call_def['params']):
            raise ValueError(
                f"Number of parameter provided ({len(params)}) does not "
                f"match definition {len(runtime_call_def['params'])}"
            )

        # Add runtime API types to registry
        self.runtime_config.update_type_registry_types(runtime_api_types)

        # Encode params
        param_data = ScaleBytes(bytes())
        for idx, param in enumerate(runtime_call_def['params']):
            scale_obj = self.runtime_config.create_scale_object(param['type'])
            if type(params) is list:
                param_data += scale_obj.encode(params[idx])
            else:
                if param['name'] not in params:
                    raise ValueError(f"Runtime Call param '{param['name']}' is missing")

                param_data += scale_obj.encode(params[param['name']])

        # RPC request
        result_data = self.rpc_request("state_call", [f'{api}_{method}', str(param_data), block_hash])

        # Decode result
        result_obj = self.runtime_config.create_scale_object(runtime_call_def['type'])
        result_obj.decode(ScaleBytes(result_data['result']))

        return result_obj

    def get_events(self, block_hash: str = None) -> list:
        """
        Convenience method to get events for a certain block (storage call for module 'System' and function 'Events')

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """
        events = []

        if not block_hash:
            block_hash = self.get_chain_head()

        storage_obj = self.query(module="System", storage_function="Events", block_hash=block_hash)
        if storage_obj:
            events += storage_obj.elements
        return events

    def get_metadata(self, block_hash=None):
        """
        Returns `MetadataVersioned` object for given block_hash or chaintip if block_hash is omitted


        Parameters
        ----------
        block_hash

        Returns
        -------
        MetadataVersioned
        """
        self.init_runtime(block_hash=block_hash)

        return self.metadata

    def get_runtime_metadata(self, block_hash=None):
        """
        Retrieves and decodes the metadata for given block or chaintip if block_hash is omitted.

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        warnings.warn("get_runtime_metadata() will be removed in future releases", DeprecationWarning)

        params = None
        if block_hash:
            params = [block_hash]
        response = self.rpc_request("state_getMetadata", params)

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        if 'result' in response:
            metadata_decoder = self.runtime_config.create_scale_object(
                'MetadataVersioned', data=ScaleBytes(response.get('result')))
            response['result'] = metadata_decoder.decode()

        return response

    def create_scale_object(
            self, type_string: str, data: ScaleBytes = None, block_hash: str = None, **kwargs
    ) -> 'ScaleType':
        """
        Convenience method to create a SCALE object of type `type_string`, this will initialize the runtime
        automatically at moment of `block_hash`, or chain tip if omitted.

        Parameters
        ----------
        type_string: str Name of SCALE type to create
        data: ScaleBytes Optional ScaleBytes to decode
        block_hash: Optional block hash for moment of decoding, when omitted the chain tip will be used
        kwargs

        Returns
        -------
        ScaleType
        """
        self.init_runtime(block_hash=block_hash)

        if 'metadata' not in kwargs:
            kwargs['metadata'] = self.metadata

        return self.runtime_config.create_scale_object(type_string, data=data, **kwargs)

    def compose_call(self, call_module: str, call_function: str, call_params: dict = None, block_hash: str = None):
        """
        Composes a call payload which can be used in an extrinsic.

        Parameters
        ----------
        call_module: Name of the runtime module e.g. Balances
        call_function: Name of the call function e.g. transfer
        call_params: This is a dict containing the params of the call. e.g. `{'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk', 'value': 1000000000000}`
        block_hash: Use metadata at given block_hash to compose call

        Returns
        -------
        GenericCall
        """

        if call_params is None:
            call_params = {}

        self.init_runtime(block_hash=block_hash)

        call = self.runtime_config.create_scale_object(
            type_string='Call', metadata=self.metadata
        )

        call.encode({
            'call_module': call_module,
            'call_function': call_function,
            'call_args': call_params
        })

        return call

    def get_account_nonce(self, account_address) -> int:
        """
        Returns current nonce for given account address

        Parameters
        ----------
        account_address: SS58 formatted address

        Returns
        -------
        int
        """
        if self.supports_rpc_method('state_call'):
            nonce_obj = self.runtime_call("AccountNonceApi", "account_nonce", [account_address])
            return nonce_obj.value
        else:
            response = self.rpc_request("system_accountNextIndex", [account_address])
        return response.get('result', 0)

    def generate_signature_payload(self, call: GenericCall, era=None, nonce: int = 0, tip: int = 0,
                                   tip_asset_id: int = None, include_call_length: bool = False) -> ScaleBytes:

        # Retrieve genesis hash
        genesis_hash = self.get_block_hash(0)

        if not era:
            era = '00'

        if era == '00':
            # Immortal extrinsic
            block_hash = genesis_hash
        else:
            # Determine mortality of extrinsic
            era_obj = self.runtime_config.create_scale_object('Era')

            if isinstance(era, dict) and 'current' not in era and 'phase' not in era:
                raise ValueError('The era dict must contain either "current" or "phase" element to encode a valid era')

            era_obj.encode(era)
            block_hash = self.get_block_hash(block_id=era_obj.birth(era.get('current')))

        # Create signature payload
        signature_payload = self.runtime_config.create_scale_object('ExtrinsicPayloadValue')

        # Process signed extensions in metadata
        if 'signed_extensions' in self.metadata[1][1]['extrinsic']:

            # Base signature payload
            signature_payload.type_mapping = [['call', 'CallBytes']]

            # Add signed extensions to payload
            signed_extensions = self.metadata.get_signed_extensions()

            if 'CheckMortality' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['era', signed_extensions['CheckMortality']['extrinsic']]
                )

            if 'CheckEra' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['era', signed_extensions['CheckEra']['extrinsic']]
                )

            if 'CheckNonce' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['nonce', signed_extensions['CheckNonce']['extrinsic']]
                )

            if 'ChargeTransactionPayment' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['tip', signed_extensions['ChargeTransactionPayment']['extrinsic']]
                )

            if 'ChargeAssetTxPayment' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['asset_id', signed_extensions['ChargeAssetTxPayment']['extrinsic']]
                )

            if 'CheckSpecVersion' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['spec_version', signed_extensions['CheckSpecVersion']['additional_signed']]
                )

            if 'CheckTxVersion' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['transaction_version', signed_extensions['CheckTxVersion']['additional_signed']]
                )

            if 'CheckGenesis' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['genesis_hash', signed_extensions['CheckGenesis']['additional_signed']]
                )

            if 'CheckMortality' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['block_hash', signed_extensions['CheckMortality']['additional_signed']]
                )

            if 'CheckEra' in signed_extensions:
                signature_payload.type_mapping.append(
                    ['block_hash', signed_extensions['CheckEra']['additional_signed']]
                )

        if include_call_length:

            length_obj = self.runtime_config.create_scale_object('Bytes')
            call_data = str(length_obj.encode(str(call.data)))

        else:
            call_data = str(call.data)

        payload_dict = {
            'call': call_data,
            'era': era,
            'nonce': nonce,
            'tip': tip,
            'spec_version': self.runtime_version,
            'genesis_hash': genesis_hash,
            'block_hash': block_hash,
            'transaction_version': self.transaction_version,
            'asset_id': {'tip': tip, 'asset_id': tip_asset_id}
        }

        signature_payload.encode(payload_dict)

        if signature_payload.data.length > 256:
            return ScaleBytes(data=blake2b(signature_payload.data.data, digest_size=32).digest())

        return signature_payload.data

    def create_signed_extrinsic(self, call: GenericCall, keypair: Keypair, era: dict = None, nonce: int = None,
                                tip: int = 0, tip_asset_id: int = None, signature: Union[bytes, str] = None) -> GenericExtrinsic:
        """
        Creates a extrinsic signed by given account details

        Parameters
        ----------
        call: GenericCall to create extrinsic for
        keypair: Keypair used to sign the extrinsic
        era: Specify mortality in blocks in follow format: {'period': [amount_blocks]} If omitted the extrinsic is immortal
        nonce: nonce to include in extrinsics, if omitted the current nonce is retrieved on-chain
        tip: The tip for the block author to gain priority during network congestion
        tip_asset_id: Optional asset ID with which to pay the tip
        signature: Optionally provide signature if externally signed

        Returns
        -------
        GenericExtrinsic The signed Extrinsic
        """

        self.init_runtime()

        # Check requirements
        if not isinstance(call, GenericCall):
            raise TypeError("'call' must be of type Call")

        # Check if extrinsic version is supported
        if self.metadata[1][1]['extrinsic']['version'] != 4:
            raise NotImplementedError(
                f"Extrinsic version {self.metadata[1][1]['extrinsic']['version']} not supported"
            )

        # Retrieve nonce
        if nonce is None:
            nonce = self.get_account_nonce(keypair.ss58_address) or 0

        # Process era
        if era is None:
            era = '00'
        else:
            if isinstance(era, dict) and 'current' not in era and 'phase' not in era:
                # Retrieve current block id
                era['current'] = self.get_block_number(self.get_chain_finalised_head())

        if signature is not None:

            if type(signature) is str and signature[0:2] == '0x':
                signature = bytes.fromhex(signature[2:])

            # Check if signature is a MultiSignature and contains signature version
            if len(signature) == 65:
                signature_version = signature[0]
                signature = signature[1:]
            else:
                signature_version = keypair.crypto_type

        else:
            # Create signature payload
            signature_payload = self.generate_signature_payload(
                call=call, era=era, nonce=nonce, tip=tip, tip_asset_id=tip_asset_id
            )

            # Set Signature version to crypto type of keypair
            signature_version = keypair.crypto_type

            # Sign payload
            signature = keypair.sign(signature_payload)

        # Create extrinsic
        extrinsic = self.runtime_config.create_scale_object(type_string='Extrinsic', metadata=self.metadata)

        value = {
            'account_id': f'0x{keypair.public_key.hex()}',
            'signature': f'0x{signature.hex()}',
            'call_function': call.value['call_function'],
            'call_module': call.value['call_module'],
            'call_args': call.value['call_args'],
            'nonce': nonce,
            'era': era,
            'tip': tip,
            'asset_id': {'tip': tip, 'asset_id': tip_asset_id}
        }

        # Check if ExtrinsicSignature is MultiSignature, otherwise omit signature_version
        signature_cls = self.runtime_config.get_decoder_class("ExtrinsicSignature")
        if issubclass(signature_cls, self.runtime_config.get_decoder_class('Enum')):
            value['signature_version'] = signature_version

        extrinsic.encode(value)

        return extrinsic

    def create_unsigned_extrinsic(self, call: GenericCall) -> GenericExtrinsic:
        """
        Create unsigned extrinsic for given `Call`
        Parameters
        ----------
        call: GenericCall the call the extrinsic should contain

        Returns
        -------
        GenericExtrinsic
        """

        self.init_runtime()

        # Create extrinsic
        extrinsic = self.runtime_config.create_scale_object(type_string='Extrinsic', metadata=self.metadata)

        extrinsic.encode({
            'call_function': call.value['call_function'],
            'call_module': call.value['call_module'],
            'call_args': call.value['call_args']
        })

        return extrinsic

    def generate_multisig_account(self, signatories: list, threshold: int) -> MultiAccountId:
        """
        Generate deterministic Multisig account with supplied signatories and threshold
        Parameters
        ----------
        signatories: List of signatories
        threshold: Amount of approvals needed to execute

        Returns
        -------
        MultiAccountId
        """

        multi_sig_account = MultiAccountId.create_from_account_list(signatories, threshold)

        multi_sig_account.ss58_address = ss58_encode(multi_sig_account.value.replace('0x', ''), self.ss58_format)

        return multi_sig_account

    def create_multisig_extrinsic(self, call: GenericCall, keypair: Keypair, multisig_account: MultiAccountId,
                                  max_weight: Optional[Union[dict, int]] = None, era: dict = None, nonce: int = None,
                                  tip: int = 0, tip_asset_id: int = None, signature: Union[bytes, str] = None
                                  ) -> GenericExtrinsic:
        """
        Create a Multisig extrinsic that will be signed by one of the signatories. Checks on-chain if the threshold
        of the multisig account is reached and try to execute the call accordingly.

        Parameters
        ----------
        call: GenericCall to create extrinsic for
        keypair: Keypair of the signatory to approve given call
        multisig_account: MultiAccountId to use of origin of the extrinsic (see `generate_multisig_account()`)
        max_weight: Maximum allowed weight to execute the call ( Uses `get_payment_info()` by default)
        era: Specify mortality in blocks in follow format: {'period': [amount_blocks]} If omitted the extrinsic is immortal
        nonce: nonce to include in extrinsics, if omitted the current nonce is retrieved on-chain
        tip: The tip for the block author to gain priority during network congestion
        tip_asset_id: Optional asset ID with which to pay the tip
        signature: Optionally provide signature if externally signed

        Returns
        -------
        GenericExtrinsic
        """
        if max_weight is None:
            payment_info = self.get_payment_info(call, keypair)
            max_weight = payment_info["weight"]

        # Check if call has existing approvals
        multisig_details = self.query("Multisig", "Multisigs", [multisig_account.value, call.call_hash])

        if multisig_details.value:
            maybe_timepoint = multisig_details.value['when']
        else:
            maybe_timepoint = None

        # Compose 'as_multi' when final, 'approve_as_multi' otherwise
        if multisig_details.value and len(multisig_details.value['approvals']) + 1 == multisig_account.threshold:
            multi_sig_call = self.compose_call("Multisig", "as_multi", {
                'other_signatories': [s for s in multisig_account.signatories if s != f'0x{keypair.public_key.hex()}'],
                'threshold': multisig_account.threshold,
                'maybe_timepoint': maybe_timepoint,
                'call': call,
                'store_call': False,
                'max_weight': max_weight
            })
        else:
            multi_sig_call = self.compose_call("Multisig", "approve_as_multi", {
                'other_signatories': [s for s in multisig_account.signatories if s != f'0x{keypair.public_key.hex()}'],
                'threshold': multisig_account.threshold,
                'maybe_timepoint': maybe_timepoint,
                'call_hash': call.call_hash,
                'max_weight': max_weight
            })

        return self.create_signed_extrinsic(
            multi_sig_call, keypair, era=era, nonce=nonce, tip=tip, tip_asset_id=tip_asset_id, signature=signature
        )

    def submit_extrinsic(self, extrinsic: GenericExtrinsic, wait_for_inclusion: bool = False,
                         wait_for_finalization: bool = False) -> "ExtrinsicReceipt":
        """
        Submit an extrinsic to the connected node, with the possibility to wait until the extrinsic is included
         in a block and/or the block is finalized. The receipt returned provided information about the block and
         triggered events

        Parameters
        ----------
        extrinsic: Extrinsic The extrinsic to be sent to the network
        wait_for_inclusion: wait until extrinsic is included in a block (only works for websocket connections)
        wait_for_finalization: wait until extrinsic is finalized (only works for websocket connections)

        Returns
        -------
        ExtrinsicReceipt

        """

        # Check requirements
        if not isinstance(extrinsic, GenericExtrinsic):
            raise TypeError("'extrinsic' must be of type Extrinsics")

        def result_handler(message, update_nr, subscription_id):
            # Check if extrinsic is included and finalized
            if 'params' in message and type(message['params']['result']) is dict:

                # Convert result enum to lower for backwards compatibility
                message_result = {k.lower(): v for k, v in message['params']['result'].items()}

                if 'finalized' in message_result and wait_for_finalization:
                    self.rpc_request('author_unwatchExtrinsic', [subscription_id])
                    return {
                        'block_hash': message_result['finalized'],
                        'extrinsic_hash': '0x{}'.format(extrinsic.extrinsic_hash.hex()),
                        'finalized': True
                    }
                elif 'inblock' in message_result and wait_for_inclusion and not wait_for_finalization:
                    self.rpc_request('author_unwatchExtrinsic', [subscription_id])
                    return {
                        'block_hash': message_result['inblock'],
                        'extrinsic_hash': '0x{}'.format(extrinsic.extrinsic_hash.hex()),
                        'finalized': False
                    }

        if wait_for_inclusion or wait_for_finalization:
            response = self.rpc_request(
                "author_submitAndWatchExtrinsic",
                [str(extrinsic.data)],
                result_handler=result_handler
            )

            result = ExtrinsicReceipt(
                substrate=self,
                extrinsic_hash=response['extrinsic_hash'],
                block_hash=response['block_hash'],
                finalized=response['finalized']
            )

        else:

            response = self.rpc_request("author_submitExtrinsic", [str(extrinsic.data)])

            if 'result' not in response:
                raise SubstrateRequestException(response.get('error'))

            result = ExtrinsicReceipt(
                substrate=self,
                extrinsic_hash=response['result']
            )

        return result

    def get_payment_info(self, call: GenericCall, keypair: Keypair):
        """
        Retrieves fee estimation via RPC for given extrinsic

        Parameters
        ----------
        call: Call object to estimate fees for
        keypair: Keypair of the sender, does not have to include private key because no valid signature is required

        Returns
        -------
        Dict with payment info

        E.g. `{'class': 'normal', 'partialFee': 151000000, 'weight': {'ref_time': 143322000}}`

        """

        # Check requirements
        if not isinstance(call, GenericCall):
            raise TypeError("'call' must be of type Call")

        if not isinstance(keypair, Keypair):
            raise TypeError("'keypair' must be of type Keypair")

        # No valid signature is required for fee estimation
        signature = '0x' + '00' * 64

        # Create extrinsic
        extrinsic = self.create_signed_extrinsic(
            call=call,
            keypair=keypair,
            signature=signature
        )

        if self.supports_rpc_method('state_call'):
            extrinsic_len = self.runtime_config.create_scale_object('u32')
            extrinsic_len.encode(len(extrinsic.data))

            result = self.runtime_call("TransactionPaymentApi", "query_info", [extrinsic, extrinsic_len])

            return result.value
        else:
            # Backwards compatibility; deprecated RPC method
            payment_info = self.rpc_request('payment_queryInfo', [str(extrinsic.data)])

            # convert partialFee to int
            if 'result' in payment_info:
                payment_info['result']['partialFee'] = int(payment_info['result']['partialFee'])

                if type(payment_info['result']['weight']) is int:
                    # Transform format to WeightV2 if applicable as per https://github.com/paritytech/substrate/pull/12633
                    try:
                        weight_obj = self.runtime_config.create_scale_object("sp_weights::weight_v2::Weight")
                        if weight_obj is not None:
                            payment_info['result']['weight'] = {
                                'ref_time': payment_info['result']['weight'],
                                'proof_size': 0
                            }
                    except NotImplementedError:
                        pass

                return payment_info['result']
            else:
                raise SubstrateRequestException(payment_info['error']['message'])

    def get_type_registry(self, block_hash: str = None, max_recursion: int = 4) -> dict:
        """
        Generates an exhaustive list of which RUST types exist in the runtime specified at given block_hash (or
        chaintip if block_hash is omitted)

        MetadataV14 or higher is required.

        Parameters
        ----------
        block_hash: Chaintip will be used if block_hash is omitted
        max_recursion: Increasing recursion will provide more detail but also has impact on performance

        Returns
        -------
        dict
        """
        self.init_runtime(block_hash=block_hash)

        if not self.implements_scaleinfo():
            raise NotImplementedError("MetadataV14 or higher runtimes is required")

        type_registry = {}

        for scale_info_type in self.metadata.portable_registry['types']:

            if 'path' in scale_info_type.value['type'] and len(scale_info_type.value['type']['path']) > 0:
                type_string = '::'.join(scale_info_type.value["type"]["path"])
            else:
                type_string = f'scale_info::{scale_info_type.value["id"]}'

            scale_cls = self.runtime_config.get_decoder_class(type_string)
            type_registry[type_string] = scale_cls.generate_type_decomposition(
                max_recursion=max_recursion
            )

        return type_registry

    def get_type_definition(self, type_string: str, block_hash: str = None):
        """
        Retrieves SCALE encoding specifications of given type_string

        Parameters
        ----------
        type_string: RUST variable type, e.g. Vec<Address> or scale_info::0
        block_hash

        Returns
        -------

        """
        scale_obj = self.create_scale_object(type_string, block_hash=block_hash)
        return scale_obj.generate_type_decomposition()

    def get_metadata_modules(self, block_hash=None):
        """
        Retrieves a list of modules in metadata for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        return [{
            'metadata_index': idx,
            'module_id': module.get_identifier(),
            'name': module.name,
            'spec_version': self.runtime_version,
            'count_call_functions': len(module.calls or []),
            'count_storage_functions': len(module.storage or []),
            'count_events': len(module.events or []),
            'count_constants': len(module.constants or []),
            'count_errors': len(module.errors or []),
        } for idx, module in enumerate(self.metadata.pallets)]

    def get_metadata_module(self, name, block_hash=None):
        """
        Retrieves modules in metadata by name for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        name
        block_hash

        Returns
        -------
        MetadataModule
        """
        self.init_runtime(block_hash=block_hash)

        return self.metadata.get_metadata_pallet(name)

    def get_metadata_call_functions(self, block_hash=None) -> list:
        """
        Retrieves a list of all call functions in metadata active for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """
        self.init_runtime(block_hash=block_hash)

        call_list = []

        for pallet in self.metadata.pallets:
            if pallet.calls:
                for call in pallet.calls:

                    call_list.append(
                        self.serialize_module_call(
                            pallet, call, self.runtime_version, ''
                        )
                    )

        return call_list

    def get_metadata_call_function(self, module_name: str, call_function_name: str, block_hash: str = None):
        """
        Retrieves the details of a call function given module name, call function name and block_hash
        (or chaintip if block_hash is omitted)

        Parameters
        ----------
        module_name
        call_function_name
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        for pallet in self.metadata.pallets:
            if pallet.name == module_name and pallet.calls:
                for call in pallet.calls:
                    if call.name == call_function_name:
                        return call

    def get_metadata_events(self, block_hash=None) -> list:
        """
        Retrieves a list of all events in metadata active for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """

        self.init_runtime(block_hash=block_hash)

        event_list = []

        for event_index, (module, event) in self.metadata.event_index.items():
            event_list.append(
                self.serialize_module_event(
                    module, event, self.runtime_version, event_index
                )
            )

        return event_list

    def get_metadata_event(self, module_name, event_name, block_hash=None):
        """
        Retrieves the details of an event for given module name, call function name and block_hash
        (or chaintip if block_hash is omitted)

        Parameters
        ----------
        module_name
        event_name
        block_hash

        Returns
        -------

        """

        self.init_runtime(block_hash=block_hash)

        for pallet in self.metadata.pallets:
            if pallet.name == module_name and pallet.events:
                for event in pallet.events:
                    if event.name == event_name:
                        return event

    def get_metadata_constants(self, block_hash=None) -> list:
        """
        Retrieves a list of all constants in metadata active at given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """

        self.init_runtime(block_hash=block_hash)

        constant_list = []

        for module_idx, module in enumerate(self.metadata.pallets):
            for constant in module.constants or []:
                constant_list.append(
                    self.serialize_constant(
                        constant, module, self.runtime_version
                    )
                )

        return constant_list

    def get_metadata_constant(self, module_name, constant_name, block_hash=None):
        """
        Retrieves the details of a constant for given module name, call function name and block_hash
        (or chaintip if block_hash is omitted)

        Parameters
        ----------
        module_name
        constant_name
        block_hash

        Returns
        -------
        MetadataModuleConstants
        """

        self.init_runtime(block_hash=block_hash)

        for module_idx, module in enumerate(self.metadata.pallets):

            if module_name == module.name and module.constants:

                for constant in module.constants:
                    if constant_name == constant.value['name']:
                        return constant

    def get_constant(self, module_name, constant_name, block_hash=None) -> Optional[ScaleType]:
        """
        Returns the decoded `ScaleType` object of the constant for given module name, call function name and block_hash
        (or chaintip if block_hash is omitted)

        Parameters
        ----------
        module_name
        constant_name
        block_hash

        Returns
        -------
        ScaleType
        """

        constant = self.get_metadata_constant(module_name, constant_name, block_hash=block_hash)
        if constant:
            # Decode to ScaleType
            return self.decode_scale(
                constant.type, ScaleBytes(constant.constant_value), block_hash=block_hash, return_scale_obj=True
            )

    def get_metadata_storage_functions(self, block_hash=None) -> list:
        """
        Retrieves a list of all storage functions in metadata active at given block_hash (or chaintip if block_hash is
        omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """
        self.init_runtime(block_hash=block_hash)

        storage_list = []

        for module_idx, module in enumerate(self.metadata.pallets):
            if module.storage:
                for storage in module.storage:
                    storage_list.append(
                        self.serialize_storage_item(
                            storage_item=storage,
                            module=module,
                            spec_version_id=self.runtime_version
                        )
                    )

        return storage_list

    def get_metadata_storage_function(self, module_name, storage_name, block_hash=None):
        """
        Retrieves the details of a storage function for given module name, call function name and block_hash

        Parameters
        ----------
        module_name
        storage_name
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        pallet = self.metadata.get_metadata_pallet(module_name)

        if pallet:
            return pallet.get_storage_function(storage_name)

    def get_metadata_errors(self, block_hash=None) -> list:
        """
        Retrieves a list of all errors in metadata active at given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------
        list
        """
        self.init_runtime(block_hash=block_hash)

        error_list = []

        for module_idx, module in enumerate(self.metadata.pallets):
            if module.errors:
                for error in module.errors:
                    error_list.append(
                        self.serialize_module_error(
                            module=module, error=error, spec_version=self.runtime_version
                        )
                    )

        return error_list

    def get_metadata_error(self, module_name, error_name, block_hash=None):
        """
        Retrieves the details of an error for given module name, call function name and block_hash

        Parameters
        ----------
        module_name
        error_name
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        for module_idx, module in enumerate(self.metadata.pallets):
            if module.name == module_name and module.errors:
                for error in module.errors:
                    if error_name == error.name:
                        return error

    def get_metadata_runtime_call_functions(self) -> list:
        """
        Get a list of available runtime API calls

        Returns
        -------
        list
        """
        self.init_runtime()
        call_functions = []

        for api, methods in self.runtime_config.type_registry["runtime_api"].items():
            for method in methods["methods"].keys():
                call_functions.append(self.get_metadata_runtime_call_function(api, method))

        return call_functions

    def get_metadata_runtime_call_function(self, api: str, method: str) -> GenericRuntimeCallDefinition:
        """
        Get details of a runtime API call

        Parameters
        ----------
        api: Name of the runtime API e.g. 'TransactionPaymentApi'
        method: Name of the method e.g. 'query_fee_details'

        Returns
        -------
        GenericRuntimeCallDefinition
        """
        self.init_runtime()

        try:
            runtime_call_def = self.runtime_config.type_registry["runtime_api"][api]['methods'][method]
            runtime_call_def['api'] = api
            runtime_call_def['method'] = method
            runtime_api_types = self.runtime_config.type_registry["runtime_api"][api].get("types", {})
        except KeyError:
            raise ValueError(f"Runtime API Call '{api}.{method}' not found in registry")

        # Add runtime API types to registry
        self.runtime_config.update_type_registry_types(runtime_api_types)

        runtime_call_def_obj = self.create_scale_object("RuntimeCallDefinition")
        runtime_call_def_obj.encode(runtime_call_def)

        return runtime_call_def_obj

    def __get_block_handler(self, block_hash: str, ignore_decoding_errors: bool = False, include_author: bool = False,
                            header_only: bool = False, finalized_only: bool = False,
                            subscription_handler: callable = None):

        try:
            self.init_runtime(block_hash=block_hash)
        except BlockNotFound:
            return None

        def decode_block(block_data, block_data_hash=None):

            if block_data:
                if block_data_hash:
                    block_data['header']['hash'] = block_data_hash

                if type(block_data['header']['number']) is str:
                    # Convert block number from hex (backwards compatibility)
                    block_data['header']['number'] = int(block_data['header']['number'], 16)

                extrinsic_cls = self.runtime_config.get_decoder_class('Extrinsic')

                if 'extrinsics' in block_data:
                    for idx, extrinsic_data in enumerate(block_data['extrinsics']):
                        extrinsic_decoder = extrinsic_cls(
                            data=ScaleBytes(extrinsic_data),
                            metadata=self.metadata,
                            runtime_config=self.runtime_config
                        )
                        try:
                            extrinsic_decoder.decode()
                            block_data['extrinsics'][idx] = extrinsic_decoder

                        except Exception as e:
                            if not ignore_decoding_errors:
                                raise
                            block_data['extrinsics'][idx] = None

                for idx, log_data in enumerate(block_data['header']["digest"]["logs"]):
                    if type(log_data) is str:
                        # Convert digest log from hex (backwards compatibility)
                        try:
                            log_digest_cls = self.runtime_config.get_decoder_class('sp_runtime::generic::digest::DigestItem')

                            if log_digest_cls is None:
                                raise NotImplementedError("No decoding class found for 'DigestItem'")

                            log_digest = log_digest_cls(data=ScaleBytes(log_data))
                            log_digest.decode()

                            block_data['header']["digest"]["logs"][idx] = log_digest

                            if include_author and 'PreRuntime' in log_digest.value:

                                if self.implements_scaleinfo():

                                    engine = bytes(log_digest[1][0])
                                    # Retrieve validator set
                                    validator_set = self.query("Session", "Validators", block_hash=block_hash)

                                    if engine == b'BABE':
                                        babe_predigest = self.runtime_config.create_scale_object(
                                            type_string='RawBabePreDigest',
                                            data=ScaleBytes(bytes(log_digest[1][1]))
                                        )

                                        babe_predigest.decode()

                                        rank_validator = babe_predigest[1].value['authority_index']

                                        block_author = validator_set[rank_validator]
                                        block_data['author'] = block_author.value

                                    elif engine == b'aura':
                                        aura_predigest = self.runtime_config.create_scale_object(
                                            type_string='RawAuraPreDigest',
                                            data=ScaleBytes(bytes(log_digest[1][1]))
                                        )

                                        aura_predigest.decode()

                                        rank_validator = aura_predigest.value['slot_number'] % len(validator_set)

                                        block_author = validator_set[rank_validator]
                                        block_data['author'] = block_author.value
                                    else:
                                        raise NotImplementedError(
                                            f"Cannot extract author for engine {log_digest.value['PreRuntime'][0]}"
                                        )
                                else:

                                    if log_digest.value['PreRuntime']['engine'] == 'BABE':
                                        validator_set = self.query("Session", "Validators", block_hash=block_hash)
                                        rank_validator = log_digest.value['PreRuntime']['data']['authority_index']

                                        block_author = validator_set.elements[rank_validator]
                                        block_data['author'] = block_author.value
                                    else:
                                        raise NotImplementedError(
                                            f"Cannot extract author for engine {log_digest.value['PreRuntime']['engine']}"
                                        )

                        except Exception:
                            if not ignore_decoding_errors:
                                raise
                            block_data['header']["digest"]["logs"][idx] = None

            return block_data

        if callable(subscription_handler):

            rpc_method_prefix = 'Finalized' if finalized_only else 'New'

            def result_handler(message, update_nr, subscription_id):

                new_block = decode_block({'header': message['params']['result']})

                subscription_result = subscription_handler(new_block, update_nr, subscription_id)

                if subscription_result is not None:
                    # Handler returned end result: unsubscribe from further updates
                    self.rpc_request(f"chain_unsubscribe{rpc_method_prefix}Heads", [subscription_id])

                return subscription_result

            result = self.rpc_request(f"chain_subscribe{rpc_method_prefix}Heads", [], result_handler=result_handler)

            return result

        else:

            if header_only:
                response = self.rpc_request('chain_getHeader', [block_hash])
                return decode_block({'header': response['result']}, block_data_hash=block_hash)

            else:
                response = self.rpc_request('chain_getBlock', [block_hash])
                return decode_block(response['result']['block'], block_data_hash=block_hash)

    def get_block(self, block_hash: str = None, block_number: int = None, ignore_decoding_errors: bool = False,
                  include_author: bool = False, finalized_only: bool = False) -> Optional[dict]:
        """
        Retrieves a block and decodes its containing extrinsics and log digest items. If `block_hash` and `block_number`
        is omited the chain tip will be retrieve, or the finalized head if `finalized_only` is set to true.

        Either `block_hash` or `block_number` should be set, or both omitted.

        Parameters
        ----------
        block_hash: the hash of the block to be retrieved
        block_number: the block number to retrieved
        ignore_decoding_errors: When set this will catch all decoding errors, set the item to None and continue decoding
        include_author: This will retrieve the block author from the validator set and add to the result
        finalized_only: when no `block_hash` or `block_number` is set, this will retrieve the finalized head

        Returns
        -------
        A dict containing the extrinsic and digest logs data
        """
        if block_hash and block_number:
            raise ValueError('Either block_hash or block_number should be be set')

        if block_number is not None:
            block_hash = self.get_block_hash(block_number)

            if block_hash is None:
                return

        if block_hash and finalized_only:
            raise ValueError('finalized_only cannot be True when block_hash is provided')

        if block_hash is None:
            # Retrieve block hash
            if finalized_only:
                block_hash = self.get_chain_finalised_head()
            else:
                block_hash = self.get_chain_head()

        return self.__get_block_handler(
            block_hash=block_hash, ignore_decoding_errors=ignore_decoding_errors, header_only=False,
            include_author=include_author
        )

    def get_block_header(self, block_hash: str = None, block_number: int = None, ignore_decoding_errors: bool = False,
                         include_author: bool = False, finalized_only: bool = False):
        """
        Retrieves a block header and decodes its containing log digest items. If `block_hash` and `block_number`
        is omited the chain tip will be retrieve, or the finalized head if `finalized_only` is set to true.

        Either `block_hash` or `block_number` should be set, or both omitted.

        See `get_block()` to also include the extrinsics in the result

        Parameters
        ----------
        block_hash: the hash of the block to be retrieved
        block_number: the block number to retrieved
        ignore_decoding_errors: When set this will catch all decoding errors, set the item to None and continue decoding
        include_author: This will retrieve the block author from the validator set and add to the result
        finalized_only: when no `block_hash` or `block_number` is set, this will retrieve the finalized head

        Returns
        -------
        A dict containing the header and digest logs data
        """
        if block_hash and block_number:
            raise ValueError('Either block_hash or block_number should be be set')

        if block_number is not None:
            block_hash = self.get_block_hash(block_number)

            if block_hash is None:
                return

        if block_hash and finalized_only:
            raise ValueError('finalized_only cannot be True when block_hash is provided')

        if block_hash is None:
            # Retrieve block hash
            if finalized_only:
                block_hash = self.get_chain_finalised_head()
            else:
                block_hash = self.get_chain_head()

        else:
            # Check conflicting scenarios
            if finalized_only:
                raise ValueError('finalized_only cannot be True when block_hash is provided')

        return self.__get_block_handler(
            block_hash=block_hash, ignore_decoding_errors=ignore_decoding_errors, header_only=True,
            include_author=include_author
        )

    def subscribe_block_headers(self, subscription_handler: callable, ignore_decoding_errors: bool = False,
                                include_author: bool = False, finalized_only=False):
        """
        Subscribe to new block headers as soon as they are available. The callable `subscription_handler` will be
        executed when a new block is available and execution will block until `subscription_handler` will return
        a result other than `None`.

        Example:

        ```
        def subscription_handler(obj, update_nr, subscription_id):

            print(f"New block #{obj['header']['number']} produced by {obj['header']['author']}")

            if update_nr > 10
              return {'message': 'Subscription will cancel when a value is returned', 'updates_processed': update_nr}


        result = substrate.subscribe_block_headers(subscription_handler, include_author=True)
        ```

        Parameters
        ----------
        subscription_handler
        ignore_decoding_errors: When set this will catch all decoding errors, set the item to None and continue decoding
        include_author: This will retrieve the block author from the validator set and add to the result
        finalized_only: when no `block_hash` or `block_number` is set, this will retrieve the finalized head

        Returns
        -------
        Value return by `subscription_handler`
        """
        # Retrieve block hash
        if finalized_only:
            block_hash = self.get_chain_finalised_head()
        else:
            block_hash = self.get_chain_head()

        return self.__get_block_handler(
            block_hash, subscription_handler=subscription_handler, ignore_decoding_errors=ignore_decoding_errors,
            include_author=include_author, finalized_only=finalized_only
        )

    def retrieve_extrinsic_by_identifier(self, extrinsic_identifier: str) -> "ExtrinsicReceipt":
        """
        Retrieve an extrinsic by its identifier in format "[block_number]-[extrinsic_index]" e.g. 333456-4

        Parameters
        ----------
        extrinsic_identifier

        Returns
        -------
        ExtrinsicReceipt
        """
        return ExtrinsicReceipt.create_from_extrinsic_identifier(
            substrate=self, extrinsic_identifier=extrinsic_identifier
        )

    def retrieve_extrinsic_by_hash(self, block_hash: str, extrinsic_hash: str) -> "ExtrinsicReceipt":
        """
        Retrieve an extrinsic by providing the block_hash and the extrinsic hash

        Parameters
        ----------
        block_hash
        extrinsic_hash

        Returns
        -------
        ExtrinsicReceipt
        """
        return ExtrinsicReceipt(
            substrate=self,
            block_hash=block_hash,
            extrinsic_hash=extrinsic_hash
        )

    def get_extrinsics(self, block_hash: str = None, block_number: int = None) -> list:
        """
        Return extrinsics for given block_hash or block_number

        Parameters
        ----------
        block_hash
        block_number

        Returns
        -------

        """
        block = self.get_block(block_hash=block_hash, block_number=block_number)
        if block:
            return block['extrinsics']

    def extension_call(self, name, **kwargs):
        for extension in self.extensions:
            if isinstance(extension, Extension):
                if hasattr(extension, name):
                    try:
                        self.debug_message(f"Call '{name}' using extension {extension.__class__.__name__} ...")
                        results = getattr(extension, name)(**kwargs)
                        return results
                    except NotImplementedError:
                        pass

        raise ExtensionCallNotFound(f"No extension found that implements '{name}'")

    def filter_extrinsics(self, **kwargs) -> list:
        return self.extension_call('filter_extrinsics', **kwargs)

    def filter_events(self, **kwargs) -> list:
        return self.extension_call('filter_events', **kwargs)

    def search_block_number(self, block_datetime: datetime, block_time: int = 6) -> int:
        return self.extension_call('search_block_number', block_datetime=block_datetime, block_time=block_time)

    def get_block_timestamp(self, block_number: int) -> int:
        return self.extension_call('get_block_timestamp', block_number=block_number)

    def decode_scale(self, type_string, scale_bytes, block_hash=None, return_scale_obj=False):
        """
        Helper function to decode arbitrary SCALE-bytes (e.g. 0x02000000) according to given RUST type_string
        (e.g. BlockNumber). The relevant versioning information of the type (if defined) will be applied if block_hash
        is set

        Parameters
        ----------
        type_string
        scale_bytes
        block_hash
        return_scale_obj: if True the SCALE object itself is returned, otherwise the serialized dict value of the object

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        if type(scale_bytes) == str:
            scale_bytes = ScaleBytes(scale_bytes)

        obj = self.runtime_config.create_scale_object(
            type_string=type_string,
            data=scale_bytes,
            metadata=self.metadata
        )

        obj.decode()

        if return_scale_obj:
            return obj
        else:
            return obj.value

    def encode_scale(self, type_string, value, block_hash=None) -> ScaleBytes:
        """
        Helper function to encode arbitrary data into SCALE-bytes for given RUST type_string

        Parameters
        ----------
        type_string
        value
        block_hash

        Returns
        -------
        ScaleBytes
        """
        self.init_runtime(block_hash=block_hash)

        obj = self.runtime_config.create_scale_object(
            type_string=type_string, metadata=self.metadata
        )
        return obj.encode(value)

    def ss58_encode(self, public_key: Union[str, bytes], ss58_format: int = None) -> str:
        """
        Helper function to encode a public key to SS58 address.

        If no target `ss58_format` is provided, it will default to the ss58 format of the network it's connected to.

        Parameters
        ----------
        public_key: 32 bytes or hex-string. e.g. 0x6e39f36c370dd51d9a7594846914035de7ea8de466778ea4be6c036df8151f29
        ss58_format: target networkID to format the address for, defaults to the network it's connected to

        Returns
        -------
        str containing the SS58 address
        """

        if ss58_format is None:
            ss58_format = self.ss58_format

        return ss58_encode(public_key, ss58_format=ss58_format)

    def ss58_decode(self, ss58_address: str) -> str:
        """
        Helper function to decode a SS58 address to a public key

        Parameters
        ----------
        ss58_address

        Returns
        -------
        str containing the hex representation of the public key
        """
        return ss58_decode(ss58_address, valid_ss58_format=self.ss58_format)

    def is_valid_ss58_address(self, value: str) -> bool:
        """
        Helper function to validate given value as ss58_address for current network/ss58_format

        Parameters
        ----------
        value

        Returns
        -------
        bool
        """
        return is_valid_ss58_address(value, valid_ss58_format=self.ss58_format)

    # Serializing helper function

    def serialize_storage_item(self, storage_item, module, spec_version_id) -> dict:
        """
        Helper function to serialize a storage item

        Parameters
        ----------
        storage_item
        module
        spec_version_id

        Returns
        -------
        dict
        """
        storage_dict = {
            "storage_name": storage_item.name,
            "storage_modifier": storage_item.modifier,
            "storage_default_scale": storage_item['default'].get_used_bytes(),
            "storage_default": None,
            "documentation": '\n'.join(storage_item.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.value['storage']['prefix'],
            "module_name": module.name,
            "spec_version": spec_version_id,
            "type_keys": storage_item.get_params_type_string(),
            "type_hashers": storage_item.get_param_hashers(),
            "type_value": storage_item.get_value_type_string()
        }

        type_class, type_info = next(iter(storage_item.type.items()))

        storage_dict["type_class"] = type_class

        value_scale_type = storage_item.get_value_type_string()

        if storage_item.value['modifier'] == 'Default':
            # Fallback to default value of storage function if no result
            query_value = storage_item.value_object['default'].value_object
        else:
            # No result is interpreted as an Option<...> result
            value_scale_type = f'Option<{value_scale_type}>'
            query_value = storage_item.value_object['default'].value_object

        try:
            obj = self.runtime_config.create_scale_object(
                type_string=value_scale_type,
                data=ScaleBytes(query_value),
                metadata=self.metadata
            )
            obj.decode()
            storage_dict["storage_default"] = obj.decode()
        except Exception:
            storage_dict["storage_default"] = '[decoding error]'

        return storage_dict

    def serialize_constant(self, constant, module, spec_version_id) -> dict:
        """
        Helper function to serialize a constant

        Parameters
        ----------
        constant
        module
        spec_version_id

        Returns
        -------
        dict
        """
        try:
            value_obj = self.runtime_config.create_scale_object(
                type_string=constant.type, data=ScaleBytes(constant.constant_value)
            )
            constant_decoded_value = value_obj.decode()
        except Exception:
            constant_decoded_value = '[decoding error]'

        return {
            "constant_name": constant.name,
            "constant_type": constant.type,
            "constant_value": constant_decoded_value,
            "constant_value_scale": f"0x{constant.constant_value.hex()}",
            "documentation": '\n'.join(constant.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.value['storage']['prefix'] if module.value['storage'] else None,
            "module_name": module.name,
            "spec_version": spec_version_id
        }

    def serialize_module_call(self, module, call, spec_version, call_index=None) -> dict:
        """
        Helper function to serialize a call function

        Parameters
        ----------
        module
        call
        spec_version
        call_index

        Returns
        -------
        dict
        """
        return {
            # "call_id": call.get_identifier(),
            "call_name": call.name,
            "call_args": [call_arg.value for call_arg in call.args],
            # "lookup": '0x{}'.format(call_index),
            "documentation": '\n'.join(call.docs),
            # "module_id": module.get_identifier(),
            "module_prefix": module.value['storage']['prefix'] if module.value['storage'] else None,
            "module_name": module.name,
            "spec_version": spec_version
        }

    def serialize_module_event(self, module, event, spec_version, event_index) -> dict:
        """
        Helper function to serialize an event

        Parameters
        ----------
        module
        event
        spec_version
        event_index

        Returns
        -------
        dict
        """
        return {
            "event_id": event.name,
            "event_name": event.name,
            "event_args": [
                {
                    "event_arg_index": idx,
                    "type": arg
                } for idx, arg in enumerate(event.args)
            ],
            "lookup": '0x{}'.format(event_index),
            "documentation": '\n'.join(event.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version
        }

    def serialize_module_error(self, module, error, spec_version) -> dict:
        """
        Helper function to serialize an error

        Parameters
        ----------
        module
        error
        spec_version

        Returns
        -------
        dict
        """
        return {
            "error_name": error.name,
            "documentation": '\n'.join(error.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.value['storage']['prefix'] if module.value['storage'] else None,
            "module_name": module.name,
            "spec_version": spec_version
        }

    def update_type_registry_presets(self) -> bool:
        try:
            update_type_registries()
            self.reload_type_registry(use_remote_preset=False)
            return True
        except Exception:
            return False

    def reload_type_registry(self, use_remote_preset: bool = True, auto_discover: bool = True):
        """
        Reload type registry and preset used to instantiate the SubtrateInterface object. Useful to periodically apply
        changes in type definitions when a runtime upgrade occurred

        Parameters
        ----------
        use_remote_preset: When True preset is downloaded from Github master, otherwise use files from local installed scalecodec package
        auto_discover

        Returns
        -------

        """
        self.runtime_config.clear_type_registry()

        self.runtime_config.implements_scale_info = self.implements_scaleinfo()

        # Load metadata types in runtime configuration
        self.runtime_config.update_type_registry(load_type_registry_preset(name="core"))
        self.apply_type_registry_presets(use_remote_preset=use_remote_preset, auto_discover=auto_discover)

    def apply_type_registry_presets(self, use_remote_preset: bool = True, auto_discover: bool = True):
        if self.type_registry_preset is not None:
            # Load type registry according to preset
            type_registry_preset_dict = load_type_registry_preset(
                name=self.type_registry_preset, use_remote_preset=use_remote_preset
            )

            if not type_registry_preset_dict:
                raise ValueError(f"Type registry preset '{self.type_registry_preset}' not found")

        elif auto_discover:
            # Try to auto discover type registry preset by chain name
            type_registry_name = self.chain.lower().replace(' ', '-')
            try:
                type_registry_preset_dict = load_type_registry_preset(type_registry_name)
                self.debug_message(f"Auto set type_registry_preset to {type_registry_name} ...")
                self.type_registry_preset = type_registry_name
            except ValueError:
                type_registry_preset_dict = None

        else:
            type_registry_preset_dict = None

        if type_registry_preset_dict:
            # Load type registries in runtime configuration
            if self.implements_scaleinfo() is False:
                # Only runtime with no embedded types in metadata need the default set of explicit defined types
                self.runtime_config.update_type_registry(
                    load_type_registry_preset("legacy", use_remote_preset=use_remote_preset)
                )

            if self.type_registry_preset != "legacy":
                self.runtime_config.update_type_registry(type_registry_preset_dict)

        if self.type_registry:
            # Load type registries in runtime configuration
            self.runtime_config.update_type_registry(self.type_registry)

    def register_extension(self, extension: Extension):
        """
        Register an Extension and adds its functionality to the ExtensionRegistry

        Parameters
        ----------
        extension: Extension

        Returns
        -------

        """
        self.extensions.register(extension)


class ExtrinsicReceipt:
    """
    Object containing information of submitted extrinsic. Block hash where extrinsic is included is required
        when retrieving triggered events or determine if extrinsic was succesfull
    """

    def __init__(self, substrate: SubstrateInterface, extrinsic_hash: str = None, block_hash: str = None,
                 block_number: int = None, extrinsic_idx: int = None, finalized=None):
        """
        Object containing information of submitted extrinsic. Block hash where extrinsic is included is required
        when retrieving triggered events or determine if extrinsic was succesfull

        Parameters
        ----------
        substrate
        extrinsic_hash
        block_hash
        finalized
        """
        self.substrate = substrate
        self.extrinsic_hash = extrinsic_hash
        self.block_hash = block_hash
        self.block_number = block_number
        self.finalized = finalized

        self.__extrinsic_idx = extrinsic_idx
        self.__extrinsic = None

        self.__triggered_events = None
        self.__is_success = None
        self.__error_message = None
        self.__weight = None
        self.__total_fee_amount = None

    def get_extrinsic_identifier(self) -> str:
        """
        Returns the on-chain identifier for this extrinsic in format "[block_number]-[extrinsic_idx]" e.g. 134324-2
        Returns
        -------
        str
        """
        if self.block_number is None:
            if self.block_hash is None:
                raise ValueError('Cannot create extrinsic identifier: block_hash is not set')

            self.block_number = self.substrate.get_block_number(self.block_hash)

            if self.block_number is None:
                raise ValueError('Cannot create extrinsic identifier: unknown block_hash')

        return f'{self.block_number}-{self.extrinsic_idx}'

    @classmethod
    def create_from_extrinsic_identifier(
            cls, substrate: SubstrateInterface, extrinsic_identifier: str
    ) -> "ExtrinsicReceipt":
        """
        Create an `ExtrinsicReceipt` with on-chain identifier for this extrinsic in format
        "[block_number]-[extrinsic_idx]" e.g. 134324-2

        Parameters
        ----------
        substrate: SubstrateInterface
        extrinsic_identifier: str

        Returns
        -------
        ExtrinsicReceipt
        """
        id_parts = extrinsic_identifier.split('-', maxsplit=1)
        block_number: int = int(id_parts[0])
        extrinsic_idx: int = int(id_parts[1])

        # Retrieve block hash
        block_hash = substrate.get_block_hash(block_number)

        return cls(
            substrate=substrate,
            block_hash=block_hash,
            block_number=block_number,
            extrinsic_idx=extrinsic_idx
        )

    def retrieve_extrinsic(self):
        if not self.block_hash:
            raise ValueError("ExtrinsicReceipt can't retrieve events because it's unknown which block_hash it is "
                             "included, manually set block_hash or use `wait_for_inclusion` when sending extrinsic")
        # Determine extrinsic idx

        block = self.substrate.get_block(block_hash=self.block_hash)

        extrinsics = block['extrinsics']

        if len(extrinsics) > 0:
            if self.__extrinsic_idx is None:
                self.__extrinsic_idx = self.__get_extrinsic_index(
                    block_extrinsics=extrinsics,
                    extrinsic_hash=self.extrinsic_hash
                )

            if self.__extrinsic_idx >= len(extrinsics):
                raise ExtrinsicNotFound()

            self.__extrinsic = extrinsics[self.__extrinsic_idx]

    @property
    def extrinsic_idx(self) -> int:
        """
        Retrieves the index of this extrinsic in containing block

        Returns
        -------
        int
        """
        if self.__extrinsic_idx is None:
            self.retrieve_extrinsic()
        return self.__extrinsic_idx

    @property
    def extrinsic(self) -> GenericExtrinsic:
        """
        Retrieves the `Extrinsic` subject of this receipt

        Returns
        -------
        Extrinsic
        """
        if self.__extrinsic is None:
            self.retrieve_extrinsic()
        return self.__extrinsic

    @property
    def triggered_events(self) -> list:
        """
        Gets triggered events for submitted extrinsic. block_hash where extrinsic is included is required, manually
        set block_hash or use `wait_for_inclusion` when submitting extrinsic

        Returns
        -------
        list
        """
        if self.__triggered_events is None:
            if not self.block_hash:
                raise ValueError("ExtrinsicReceipt can't retrieve events because it's unknown which block_hash it is "
                                 "included, manually set block_hash or use `wait_for_inclusion` when sending extrinsic")

            if self.extrinsic_idx is None:
                self.retrieve_extrinsic()

            self.__triggered_events = []

            for event in self.substrate.get_events(block_hash=self.block_hash):
                if event.extrinsic_idx == self.extrinsic_idx:
                    self.__triggered_events.append(event)

        return self.__triggered_events

    def process_events(self):
        if self.triggered_events:

            self.__total_fee_amount = 0

            # Process fees
            has_transaction_fee_paid_event = False

            for event in self.triggered_events:
                if event.value['module_id'] == 'TransactionPayment' and event.value['event_id'] == 'TransactionFeePaid':
                    self.__total_fee_amount = event.value['attributes']['actual_fee']
                    has_transaction_fee_paid_event = True

            # Process other events
            for event in self.triggered_events:

                # Check events
                if self.substrate.implements_scaleinfo():

                    if event.value['module_id'] == 'System' and event.value['event_id'] == 'ExtrinsicSuccess':
                        self.__is_success = True
                        self.__error_message = None

                        if 'dispatch_info' in event.value['attributes']:
                            self.__weight = event.value['attributes']['dispatch_info']['weight']
                        else:
                            # Backwards compatibility
                            self.__weight = event.value['attributes']['weight']

                    elif event.value['module_id'] == 'System' and event.value['event_id'] == 'ExtrinsicFailed':
                        self.__is_success = False

                        if type(event.value['attributes']) is dict:
                            dispatch_info = event.value['attributes']['dispatch_info']
                            dispatch_error = event.value['attributes']['dispatch_error']
                        else:
                            # Backwards compatibility
                            dispatch_info = event.value['attributes'][1]
                            dispatch_error = event.value['attributes'][0]

                        self.__weight = dispatch_info['weight']

                        if 'Module' in dispatch_error:

                            if type(dispatch_error['Module']) is tuple:
                                module_index = dispatch_error['Module'][0]
                                error_index = dispatch_error['Module'][1]
                            else:
                                module_index = dispatch_error['Module']['index']
                                error_index = dispatch_error['Module']['error']

                            if type(error_index) is str:
                                # Actual error index is first u8 in new [u8; 4] format
                                error_index = int(error_index[2:4], 16)

                            module_error = self.substrate.metadata.get_module_error(
                                module_index=module_index,
                                error_index=error_index
                            )
                            self.__error_message = {
                                'type': 'Module',
                                'name': module_error.name,
                                'docs': module_error.docs
                            }
                        elif 'BadOrigin' in dispatch_error:
                            self.__error_message = {
                                'type': 'System',
                                'name': 'BadOrigin',
                                'docs': 'Bad origin'
                            }
                        elif 'CannotLookup' in dispatch_error:
                            self.__error_message = {
                                'type': 'System',
                                'name': 'CannotLookup',
                                'docs': 'Cannot lookup'
                            }
                        elif 'Other' in dispatch_error:
                            self.__error_message = {
                                'type': 'System',
                                'name': 'Other',
                                'docs': 'Unspecified error occurred'
                            }

                    elif not has_transaction_fee_paid_event:

                        if event.value['module_id'] == 'Treasury' and event.value['event_id'] == 'Deposit':
                            if type(event.value['attributes']) is dict:
                                self.__total_fee_amount += event.value['attributes']['value']
                            else:
                                # Backwards compatibility
                                self.__total_fee_amount += event.value['attributes']

                        elif event.value['module_id'] == 'Balances' and event.value['event_id'] == 'Deposit':
                            if type(event.value['attributes']) is dict:
                                self.__total_fee_amount += event.value['attributes']['amount']
                            else:
                                # Backwards compatibility
                                self.__total_fee_amount += event.value['attributes'][1]

                else:

                    if event.event_module.name == 'System' and event.event.name == 'ExtrinsicSuccess':
                        self.__is_success = True
                        self.__error_message = None

                        for param in event.params:
                            if param['type'] == 'DispatchInfo':
                                self.__weight = param['value']['weight']

                    elif event.event_module.name == 'System' and event.event.name == 'ExtrinsicFailed':
                        self.__is_success = False

                        for param in event.params:
                            if param['type'] == 'DispatchError':
                                if 'Module' in param['value']:

                                    if type(param['value']['Module']['error']) is str:
                                        # Actual error index is first u8 in new [u8; 4] format (e.g. 0x01000000)
                                        error_index = int(param['value']['Module']['error'][2:4], 16)
                                    else:
                                        error_index = param['value']['Module']['error']

                                    module_error = self.substrate.metadata.get_module_error(
                                        module_index=param['value']['Module']['index'],
                                        error_index=error_index
                                    )
                                    self.__error_message = {
                                        'type': 'Module',
                                        'name': module_error.name,
                                        'docs': module_error.docs
                                    }
                                elif 'BadOrigin' in param['value']:
                                    self.__error_message = {
                                        'type': 'System',
                                        'name': 'BadOrigin',
                                        'docs': 'Bad origin'
                                    }
                                elif 'CannotLookup' in param['value']:
                                    self.__error_message = {
                                        'type': 'System',
                                        'name': 'CannotLookup',
                                        'docs': 'Cannot lookup'
                                    }
                                elif 'Other' in param['value']:
                                    self.__error_message = {
                                        'type': 'System',
                                        'name': 'Other',
                                        'docs': 'Unspecified error occurred'
                                    }

                            if param['type'] == 'DispatchInfo':
                                self.__weight = param['value']['weight']

                    elif event.event_module.name == 'Treasury' and event.event.name == 'Deposit':
                        self.__total_fee_amount += event.params[0]['value']

                    elif event.event_module.name == 'Balances' and event.event.name == 'Deposit':
                        self.__total_fee_amount += event.params[1]['value']

    @property
    def is_success(self) -> bool:
        """
        Returns `True` if `ExtrinsicSuccess` event is triggered, `False` in case of `ExtrinsicFailed`
        In case of False `error_message` will contain more details about the error


        Returns
        -------
        bool
        """
        if self.__is_success is None:
            self.process_events()

        return self.__is_success

    @property
    def error_message(self) -> Optional[dict]:
        """
        Returns the error message if the extrinsic failed in format e.g.:

        `{'type': 'System', 'name': 'BadOrigin', 'docs': 'Bad origin'}`

        Returns
        -------
        dict
        """
        if self.__error_message is None:
            if self.is_success:
                return None
            self.process_events()
        return self.__error_message

    @property
    def weight(self) -> Union[int, dict]:
        """
        Contains the actual weight when executing this extrinsic

        Returns
        -------
        int (WeightV1) or dict (WeightV2)
        """
        if self.__weight is None:
            self.process_events()
        return self.__weight

    @property
    def total_fee_amount(self) -> int:
        """
        Contains the total fee costs deducted when executing this extrinsic. This includes fee for the validator (
        (`Balances.Deposit` event) and the fee deposited for the treasury (`Treasury.Deposit` event)

        Returns
        -------
        int
        """
        if self.__total_fee_amount is None:
            self.process_events()
        return self.__total_fee_amount

    # Helper functions
    @staticmethod
    def __get_extrinsic_index(block_extrinsics: list, extrinsic_hash: str) -> int:
        """
        Returns the index of a provided extrinsic
        """
        for idx, extrinsic in enumerate(block_extrinsics):
            if extrinsic.extrinsic_hash and f'0x{extrinsic.extrinsic_hash.hex()}' == extrinsic_hash:
                return idx
        raise ExtrinsicNotFound()

    # Backwards compatibility methods
    def __getitem__(self, item):
        return getattr(self, item)

    def __iter__(self):
        for item in self.__dict__.items():
            yield item

    def get(self, name):
        return self[name]


class QueryMapResult:

    def __init__(self, records: list, page_size: int, module: str = None, storage_function: str = None,
                 params: list = None, block_hash: str = None, substrate: SubstrateInterface = None,
                 last_key: str = None, max_results: int = None, ignore_decoding_errors: bool = False):
        self.current_index = -1
        self.records = records
        self.page_size = page_size
        self.module = module
        self.storage_function = storage_function
        self.block_hash = block_hash
        self.substrate = substrate
        self.last_key = last_key
        self.max_results = max_results
        self.params = params
        self.ignore_decoding_errors = ignore_decoding_errors
        self.loading_complete = False

    def retrieve_next_page(self, start_key) -> list:
        if not self.substrate:
            return []

        result = self.substrate.query_map(module=self.module, storage_function=self.storage_function,
                                          params=self.params, page_size=self.page_size, block_hash=self.block_hash,
                                          start_key=start_key, max_results=self.max_results,
                                          ignore_decoding_errors=self.ignore_decoding_errors)

        # Update last key from new result set to use as offset for next page
        self.last_key = result.last_key

        return result.records

    def __iter__(self):
        self.current_index = -1
        return self

    def __next__(self):
        self.current_index += 1

        if self.max_results is not None and self.current_index >= self.max_results:
            self.loading_complete = True
            raise StopIteration

        if self.current_index >= len(self.records) and not self.loading_complete:
            # try to retrieve next page from node
            self.records += self.retrieve_next_page(start_key=self.last_key)

        if self.current_index >= len(self.records):
            self.loading_complete = True
            raise StopIteration

        return self.records[self.current_index]

    def __getitem__(self, item):
        return self.records[item]
