# Python Substrate Interface
#
# Copyright 2018-2020 openAware BV (NL).
# This file is part of Polkascan.
#
# Polkascan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Polkascan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Polkascan. If not, see <http://www.gnu.org/licenses/>.

import asyncio
import binascii
import json
import re

import requests
import websockets

from scalecodec import ScaleBytes
from scalecodec.base import ScaleDecoder, RuntimeConfiguration
from scalecodec.block import ExtrinsicsDecoder, EventsDecoder, LogDigest
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset

from .utils.hasher import blake2_256, two_x64_concat, xxh64, xxh128, blake2_128, blake2_128_concat, identity
from .exceptions import SubstrateRequestException
from .constants import *
from .utils.ss58 import ss58_decode


class SubstrateInterface:

    def __init__(self, url, address_type=None, type_registry=None, type_registry_preset=None, cache_region=None):
        """
        A specialized class in interfacing with a Substrate node.

        Parameters
        ----------
        url: the URL to the substrate node, either in format https://127.0.0.1:9933 or wss://127.0.0.1:9944
        address_type: : The address type which account IDs will be SS58-encoded to Substrate addresses. Defaults to 42, for Kusama the address type is 2
        type_registry: A dict containing the custom type registry in format: {'types': {'customType': 'u32'},..}
        type_registry_preset: The name of the predefined type registry shipped with the SCALE-codec, e.g. kusama
        cache_region: a Dogpile cache region as a central store for the metadata cache
        """
        self.cache_region = cache_region
        if type_registry or type_registry_preset:

            RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

            if type_registry:
                # Load type registries in runtime configuration
                RuntimeConfiguration().update_type_registry(type_registry)
            if type_registry_preset:
                # Load type registries in runtime configuration
                RuntimeConfiguration().update_type_registry(load_type_registry_preset(type_registry_preset))

        self.request_id = 1
        self.url = url

        self._ws_result = None

        self.address_type = address_type

        self.mock_extrinsics = None
        self._version = None
        self.default_headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }

        self.metadata_decoder = None
        self.runtime_version = None
        self.block_hash = None

        self.metadata_cache = {}
        self.type_registry_cache = {}

        self.debug = False

    def debug_message(self, message):
        if self.debug:
            print('DEBUG', message)

    async def ws_request(self, payload):
        """
        Internal method to handle the request if url is a websocket address (wss:// or ws://)

        Parameters
        ----------
        payload: a dict that contains the JSONRPC payload of the request

        Returns
        -------
        This method doesn't return but sets the `_ws_result` object variable with the result
        """
        async with websockets.connect(
                self.url
        ) as websocket:
            await websocket.send(json.dumps(payload))
            self._ws_result = json.loads(await websocket.recv())

    def rpc_request(self, method, params):
        """
        Method that handles the actual RPC request to the Substrate node. The other implemented functions eventually
        use this method to perform the request.

        Parameters
        ----------
        method: method of the JSONRPC request
        params: a list containing the parameters of the JSONRPC request

        Returns
        -------
        a dict with the parsed result of the request.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }

        self.debug_message('RPC request "{}"'.format(method))

        if self.url[0:6] == 'wss://' or self.url[0:5] == 'ws://':
            asyncio.get_event_loop().run_until_complete(self.ws_request(payload))
            json_body = self._ws_result

        else:
            response = requests.request("POST", self.url, data=json.dumps(payload), headers=self.default_headers)

            if response.status_code != 200:
                raise SubstrateRequestException("RPC request failed with HTTP status code {}".format(response.status_code))

            json_body = response.json()

        return json_body

    def get_system_name(self):
        """
        A pass-though to existing JSONRPC method `system_name`

        Returns
        -------

        """
        response = self.rpc_request("system_name", [])
        return response.get('result')

    def get_version(self):
        """
        A pass-though to existing JSONRPC method `system_version`

        Returns
        -------

        """
        if not self._version:
            response = self.rpc_request("system_version", [])
            self._version = response.get('result')
        return self._version

    def get_chain_head(self):
        """
        A pass-though to existing JSONRPC method `chain_getHead`

        Returns
        -------

        """
        response = self.rpc_request("chain_getHead", [])
        return response.get('result')

    def get_chain_finalised_head(self):
        """
        A pass-though to existing JSONRPC method `chain_getFinalisedHead`

        Returns
        -------

        """
        response = self.rpc_request("chain_getFinalisedHead", [])
        return response.get('result')

    def get_chain_block(self, block_hash=None, block_id=None, metadata_decoder=None):
        """
        A pass-though to existing JSONRPC method `chain_getBlock`. For a decoded version see `get_runtime_block()`

        Parameters
        ----------
        block_hash
        block_id
        metadata_decoder

        Returns
        -------

        """

        if block_id:
            block_hash = self.get_block_hash(block_id)

        response = self.rpc_request("chain_getBlock", [block_hash]).get('result')

        if self.mock_extrinsics:
            # Extend extrinsics with mock_extrinsics for e.g. performance tests
            response['block']['extrinsics'].extend(self.mock_extrinsics)

        # Decode extrinsics
        if metadata_decoder:

            response['block']['header']['number'] = int(response['block']['header']['number'], 16)

            for idx, extrinsic_data in enumerate(response['block']['extrinsics']):
                extrinsic_decoder = ExtrinsicsDecoder(
                    data=ScaleBytes(extrinsic_data),
                    metadata=metadata_decoder
                )
                extrinsic_decoder.decode()
                response['block']['extrinsics'][idx] = extrinsic_decoder.value

            for idx, log_data in enumerate(response['block']['header']["digest"]["logs"]):
                log_digest = LogDigest(ScaleBytes(log_data))
                log_digest.decode()
                response['block']['header']["digest"]["logs"][idx] = log_digest.value

        return response

    def get_block_hash(self, block_id):
        """
        A pass-though to existing JSONRPC method `chain_getBlockHash`

        Parameters
        ----------
        block_id

        Returns
        -------

        """
        return self.rpc_request("chain_getBlockHash", [block_id]).get('result')

    def get_block_header(self, block_hash):
        """
        A pass-though to existing JSONRPC method `chain_getHeader`

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        response = self.rpc_request("chain_getHeader", [block_hash])
        return response.get('result')

    def get_block_number(self, block_hash):
        """
        A convenience method to get the block number for given block_hash

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        response = self.rpc_request("chain_getHeader", [block_hash])
        return int(response['result']['number'], 16)

    def get_block_metadata(self, block_hash=None, decode=True):
        """
        A pass-though to existing JSONRPC method `state_getMetadata`. For a decoded version see `get_runtime_metadata()`

        Parameters
        ----------
        block_hash
        decode: DEPRECATED use `get_runtime_metadata()` for decoded version

        Returns
        -------

        """
        params = None
        if block_hash:
            params = [block_hash]
        response = self.rpc_request("state_getMetadata", params)

        if decode:
            metadata_decoder = MetadataDecoder(ScaleBytes(response.get('result')))
            metadata_decoder.decode()

            return metadata_decoder

        return response

    def get_storage(self, block_hash, module, function, params=None, return_scale_type=None, hasher=None,
                    spec_version_id='default', metadata=None, metadata_version=None):
        """
        Retrieves the storage entry for given module, function and optional parameters at given block.

        DEPRECATED: use `get_runtime_state()`

        Parameters
        ----------
        block_hash
        module
        function
        params
        return_scale_type: Scale type string to interprete result
        hasher: Hashing method used to determine storage key, defaults to 'Twox64Concat' if not provided
        spec_version_id: DEPRECATED
        metadata
        metadata_version: Version index of Metadata, e.g. 9 for MetadataV9

        Returns
        -------

        """
        storage_hash = self.generate_storage_hash(
            storage_module=module,
            storage_function=function,
            params=params,
            hasher=hasher,
            metadata_version=metadata_version
        )
        response = self.rpc_request("state_getStorageAt", [storage_hash, block_hash])

        if 'result' in response:

            if return_scale_type and response.get('result'):
                obj = ScaleDecoder.get_decoder_class(
                    return_scale_type,
                    ScaleBytes(response.get('result')),
                    metadata=metadata
                )
                return obj.decode()
            else:
                return response.get('result')
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_storage_by_key(self, block_hash, storage_key):
        """
        A pass-though to existing JSONRPC method `state_getStorageAt`

        Parameters
        ----------
        block_hash
        storage_key

        Returns
        -------

        """

        response = self.rpc_request("state_getStorageAt", [storage_key, block_hash])
        if 'result' in response:
            return response.get('result')
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_block_events(self, block_hash, metadata_decoder=None):
        """
        A convenience method to fetch the undecoded events from storage

        Parameters
        ----------
        block_hash
        metadata_decoder

        Returns
        -------

        """

        if metadata_decoder and metadata_decoder.version.index >= 9:
            storage_hash = STORAGE_HASH_SYSTEM_EVENTS_V9
        else:
            storage_hash = STORAGE_HASH_SYSTEM_EVENTS

        response = self.rpc_request("state_getStorageAt", [storage_hash, block_hash])

        if response.get('result'):

            if metadata_decoder:
                # Process events
                events_decoder = EventsDecoder(
                    data=ScaleBytes(response.get('result')),
                    metadata=metadata_decoder
                )
                events_decoder.decode()

                return events_decoder

            else:
                return response
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_block_runtime_version(self, block_hash):
        """
        Retrieve the runtime version id of given block_hash
        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        response = self.rpc_request("chain_getRuntimeVersion", [block_hash])
        return response.get('result')

    def generate_storage_hash(self, storage_module, storage_function, params=None, hasher=None, key2_hasher=None, metadata_version=None):
        """
        Generate a storage key for given module/function

        Parameters
        ----------
        storage_module
        storage_function
        params: Parameters of the storage function, provided in scale encoded hex-bytes
        hasher: Hashing method used to determine storage key, defaults to 'Twox64Concat' if not provided
        metadata_version: Version index of Metadata, e.g. 9 for MetadataV9

        Returns
        -------

        """

        if metadata_version and metadata_version >= 9:
            storage_hash = xxh128(storage_module.encode()) + xxh128(storage_function.encode())

            if params:

                if type(params) is not list:
                    params = [params]

                for idx, param in enumerate(params):
                    if idx == 0:
                        param_hasher = hasher
                    elif idx == 1:
                        param_hasher = key2_hasher
                    else:
                        raise ValueError('Unexpected third parameter for storage call')

                    params_key = bytes()

                    if type(param) is str:
                        params_key += binascii.unhexlify(param)
                    elif type(param) is ScaleBytes:
                        params_key += param.data
                    elif isinstance(param, ScaleDecoder):
                        params_key += param.data.data

                    if not param_hasher:
                        param_hasher = 'Twox128'

                    if param_hasher == 'Blake2_256':
                        storage_hash += blake2_256(params_key)

                    elif param_hasher == 'Blake2_128':
                        storage_hash += blake2_128(params_key)

                    elif param_hasher == 'Blake2_128Concat':
                        storage_hash += blake2_128_concat(params_key)

                    elif param_hasher == 'Twox128':
                        storage_hash += xxh128(params_key)

                    elif param_hasher == 'Twox64Concat':
                        storage_hash += two_x64_concat(params_key)

                    elif param_hasher == 'Identity':
                        storage_hash += identity(params_key)

                    else:
                        raise ValueError('Unknown storage hasher "{}"'.format(param_hasher))

            return '0x{}'.format(storage_hash)

        else:
            storage_hash = storage_module.encode() + b" " + storage_function.encode()

            if params:
                storage_hash += binascii.unhexlify(params)

            # Determine hasher function
            if not hasher:
                hasher = 'Twox128'

            if hasher == 'Blake2_256':
                return "0x{}".format(blake2_256(storage_hash))

            elif hasher == 'Twox128':
                return "0x{}".format(xxh128(storage_hash))

            elif hasher == 'Twox64Concat':
                return "0x{}".format(two_x64_concat(storage_hash))

    def convert_storage_parameter(self, scale_type, value):
        if scale_type == 'AccountId':
            if value[0:2] != '0x':
                return '0x{}'.format(ss58_decode(value, self.address_type))

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

        if block_id:
            block_hash = self.get_block_hash(block_id)

        self.block_hash = block_hash

        self.runtime_version = self.get_block_runtime_version(block_hash=self.block_hash).get("specVersion")

        # Set active runtime version
        RuntimeConfiguration().set_active_spec_version_id(self.runtime_version)

        if self.runtime_version not in self.metadata_cache and self.cache_region:
            # Try to retrieve metadata from Dogpile cache
            cached_metadata = self.cache_region.get('METADATA_{}'.format(self.runtime_version))
            if cached_metadata:
                self.debug_message('Retrieved metadata for {} from Redis'.format(self.runtime_version))
                self.metadata_cache[self.runtime_version] = cached_metadata

        if self.runtime_version in self.metadata_cache:
            # Get metadata from cache
            self.debug_message('Retrieved metadata for {} from memory'.format(self.runtime_version))
            self.metadata_decoder = self.metadata_cache[self.runtime_version]
        else:
            self.metadata_decoder = self.get_block_metadata(block_hash=self.block_hash, decode=True)
            self.debug_message('Retrieved metadata for {} from Substrate node'.format(self.runtime_version))

            # Update metadata cache
            self.metadata_cache[self.runtime_version] = self.metadata_decoder

            if self.cache_region:
                self.debug_message('Stored metadata for {} in Redis'.format(self.runtime_version))
                self.cache_region.set('METADATA_{}'.format(self.runtime_version), self.metadata_decoder)

    def get_runtime_state(self, module, storage_function, params=None, block_hash=None):
        """
        Retrieves the storage entry for given module, function and optional parameters at given block hash

        Parameters
        ----------
        module: The module name in the metadata, e.g. Balances or Account
        storage_function: The storage function name, e.g. FreeBalance or AccountNonce
        params: list of params, in the decoded format of the applicable ScaleTypes
        block_hash: Optional block hash, when left to None the chain tip will be used

        Returns
        -------

        """

        self.init_runtime(block_hash=block_hash)

        # Search storage call in metadata
        for metadata_module in self.metadata_decoder.metadata.modules:
            if metadata_module.name == module:
                if metadata_module.storage:
                    for storage_item in metadata_module.storage.items:
                        if storage_item.name == storage_function:

                            key2_hasher = None

                            if 'PlainType' in storage_item.type:
                                hasher = 'Twox64Concat'
                                return_scale_type = storage_item.type.get('PlainType')
                                if params:
                                    raise ValueError('Storage call of type "PlainType" doesn\'t accept params')

                            elif 'MapType' in storage_item.type:

                                map_type = storage_item.type.get('MapType')
                                hasher = map_type.get('hasher')
                                return_scale_type = map_type.get('value')

                                if not params or len(params) != 1:
                                    raise ValueError('Storage call of type "MapType" requires 1 parameter')

                                # Encode parameter
                                params[0] = self.convert_storage_parameter(map_type['key'], params[0])
                                param_obj = ScaleDecoder.get_decoder_class(map_type['key'])
                                params[0] = param_obj.encode(params[0])

                            elif 'DoubleMapType' in storage_item.type:

                                map_type = storage_item.type.get('DoubleMapType')
                                hasher = map_type.get('hasher')
                                key2_hasher = map_type.get('key2Hasher')
                                return_scale_type = map_type.get('value')

                                if not params or len(params) != 2:
                                    raise ValueError('Storage call of type "DoubleMapType" requires 2 parameters')

                                # Encode parameter 1
                                params[0] = self.convert_storage_parameter(map_type['key1'], params[0])
                                param_obj = ScaleDecoder.get_decoder_class(map_type['key1'])
                                params[0] = param_obj.encode(params[0])

                                # Encode parameter 2
                                params[1] = self.convert_storage_parameter(map_type['key2'], params[1])
                                param_obj = ScaleDecoder.get_decoder_class(map_type['key2'])
                                params[1] = param_obj.encode(params[1])

                            else:
                                raise NotImplementedError("Storage type not implemented")

                            storage_hash = self.generate_storage_hash(
                                storage_module=module,
                                storage_function=storage_function,
                                params=params,
                                hasher=hasher,
                                key2_hasher=key2_hasher,
                                metadata_version=self.metadata_decoder.version.index
                            )

                            response = self.rpc_request("state_getStorageAt", [storage_hash, block_hash])

                            if 'result' in response:

                                if return_scale_type and response.get('result'):
                                    obj = ScaleDecoder.get_decoder_class(
                                        return_scale_type,
                                        ScaleBytes(response.get('result')),
                                        metadata=self.metadata_decoder
                                    )
                                    response['result'] = obj.decode()

                            return response

        raise ValueError('Storage function "{}.{}" not found'.format(module, storage_function))

    def get_runtime_events(self, block_hash=None):
        """
        Convenience method to get events for a certain block (storage call for module 'System' and function 'Events')

        Parameters
        ----------
        block_hash

        Returns
        -------
        Collection of events
        """
        return self.get_runtime_state(
            module="System",
            storage_function="Events",
            block_hash=block_hash
        )

    def get_runtime_metadata(self, block_hash=None):
        """
        Retrieves and decodes the metadata for given block or chaintip if block_hash is omitted.

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        params = None
        if block_hash:
            params = [block_hash]
        response = self.rpc_request("state_getMetadata", params)

        if 'result' in response:
            metadata_decoder = MetadataDecoder(ScaleBytes(response.get('result')))
            response['result'] = metadata_decoder.decode()

        return response

    def compose_call(self, call_module, call_function, call_params=(), block_hash=None):
        """
        Composes a call payload which can be used as an unsigned extrinsic or a proposal.

        Parameters
        ----------
        call_module: Name of the runtime module e.g. Balances
        call_function: Name of the call function e.g. transfer
        call_params: This is a dict containing the params of the call. e.g. `{'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk', 'value': 1000000000000}`
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        extrinsic = ExtrinsicsDecoder(metadata=self.metadata_decoder, address_type=self.address_type)

        payload = extrinsic.encode({
            'call_module': call_module,
            'call_function': call_function,
            'call_args': call_params
        })

        return str(payload)

    def process_metadata_typestring(self, type_string):
        """
        Process how given type_string is decoded with active runtime and type registry

        Parameters
        ----------
        type_string: RUST variable type, e.g. Vec<Address>

        Returns
        -------

        dict of properties for given type_string

        E.g.

        `{
            "type_string": "Vec<Address>",
            "decoder_class": "Vec",
            "is_primitive_runtime": false,
            "is_primitive_core": false,
            "spec_version": 1030
        }`

        """
        decoder_class_obj = None

        type_info = {
            "type_string": type_string,
            "decoder_class": None,
            "is_primitive_runtime": None,
            "is_primitive_core": False,
            "spec_version": self.runtime_version
        }

        if self.runtime_version not in self.type_registry_cache:
            self.type_registry_cache[self.runtime_version] = {}

        # Check if already added
        if type_string.lower() in self.type_registry_cache[self.runtime_version]:
            return self.type_registry_cache[self.runtime_version][type_string.lower()]['decoder_class']

        # Try to get decoder class
        decoder_class = RuntimeConfiguration().get_decoder_class(type_string)

        if not decoder_class:

            # Not in type registry, try get hard coded decoder classes
            try:
                decoder_class_obj = ScaleDecoder.get_decoder_class(type_string)
                decoder_class = decoder_class_obj.__class__
            except NotImplementedError as e:
                decoder_class = None

        # Process classes that contain subtypes (e.g. Option<ChangesTrieConfiguration>)
        if decoder_class_obj and decoder_class_obj.sub_type:
            type_info["is_primitive_runtime"] = False

            # Try to split on ',' (e.g. ActiveRecovery<BlockNumber, BalanceOf, AccountId>)
            if not re.search('[<()>]', decoder_class_obj.sub_type):
                for element in decoder_class_obj.sub_type.split(','):
                    if element not in ['T', 'I']:
                        self.process_metadata_typestring(element.strip())

        # Process classes that contain type_mapping (e.g. Struct and Enum)
        if decoder_class and hasattr(decoder_class, 'type_mapping') and decoder_class.type_mapping:

            if type_string[0] == '(':
                type_info["is_primitive_runtime"] = False

            for key, data_type in decoder_class.type_mapping:
                self.process_metadata_typestring(data_type)

        # Try to get superclass as actual decoding class if not root level 'ScaleType'
        if decoder_class and len(decoder_class.__mro__) > 1 and decoder_class.__mro__[1].__name__ != 'ScaleType':
            decoder_class = decoder_class.__mro__[1]

        if decoder_class:
            type_info['decoder_class'] = decoder_class.__name__

            if type_info["is_primitive_runtime"] is None:
                type_info["is_primitive_runtime"] = True

            if type_info["is_primitive_runtime"] and type_string.lower() in ScaleDecoder.PRIMITIVES:
                type_info["is_primitive_core"] = True
        else:
            type_info["is_primitive_runtime"] = None
            type_info["is_primitive_core"] = None

        self.type_registry_cache[self.runtime_version][type_string.lower()] = type_info

        return decoder_class

    def get_type_registry(self, block_hash=None):
        """
        Generates an exhaustive list of which RUST types exist in the runtime specified at given block_hash (or
        chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash: Chaintip will be used if block_hash is omitted

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        if self.runtime_version not in self.type_registry_cache:

            for module in self.metadata_decoder.metadata.modules:

                # Storage backwards compt check
                if module.storage and isinstance(module.storage, list):
                    storage_functions = module.storage
                elif module.storage and isinstance(getattr(module.storage, 'value'), dict):
                    storage_functions = module.storage.items
                else:
                    storage_functions = []

                if len(module.calls or []) > 0:
                    for idx, call in enumerate(module.calls):
                        for arg in call.args:
                            self.process_metadata_typestring(arg.type)

                if len(module.events or []) > 0:
                    for event_index, event in enumerate(module.events):

                        for arg_index, arg in enumerate(event.args):
                            self.process_metadata_typestring(arg)

                if len(storage_functions) > 0:
                    for idx, storage in enumerate(storage_functions):

                        # Determine type
                        type_key1 = None
                        type_key2 = None
                        type_value = None

                        if storage.type.get('PlainType'):
                            type_value = storage.type.get('PlainType')

                        elif storage.type.get('MapType'):
                            type_key1 = storage.type['MapType'].get('key')
                            type_value = storage.type['MapType'].get('value')

                        elif storage.type.get('DoubleMapType'):
                            type_key1 = storage.type['DoubleMapType'].get('key1')
                            type_key2 = storage.type['DoubleMapType'].get('key2')
                            type_value = storage.type['DoubleMapType'].get('value')

                        self.process_metadata_typestring(type_value)

                        if type_key1:
                            self.process_metadata_typestring(type_key1)

                        if type_key2:
                            self.process_metadata_typestring(type_key2)

                if len(module.constants or []) > 0:
                    for idx, constant in enumerate(module.constants):

                        # Check if types already registered in database
                        self.process_metadata_typestring(constant.type)

        return self.type_registry_cache[self.runtime_version]

    def get_type_definition(self, type_string, block_hash=None):
        """
        Retrieves decoding specifications of given type_string

        Parameters
        ----------
        type_string: RUST variable type, e.g. Vec<Address>
        block_hash

        Returns
        -------

        """
        type_registry = self.get_type_registry(block_hash=block_hash)
        return type_registry.get(type_string)

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
            'prefix': module.prefix,
            'spec_version': self.runtime_version,
            'count_call_functions': len(module.calls or []),
            'count_storage_functions': len(module.calls or []),
            'count_events': len(module.events or []),
            'count_constants': len(module.constants or []),
            'count_errors': len(module.errors or []),
        } for idx, module in enumerate(self.metadata_decoder.metadata.modules)]

    def get_metadata_call_functions(self, block_hash=None):
        """
        Retrieves a list of all call functions in metadata active for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        call_list = []

        for call_index, (module, call) in self.metadata_decoder.call_index.items():
            call_list.append(
                self.serialize_module_call(
                    module, call, self.runtime_version, call_index
                )
            )
        return call_list

    def get_metadata_call_function(self, module_name, call_function_name, block_hash=None):
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

        result = None

        for call_index, (module, call) in self.metadata_decoder.call_index.items():
            if module.name == module_name and \
                    call.get_identifier() == call_function_name:
                result = self.serialize_module_call(
                    module, call, self.runtime_version, call_index
                )
                break

        return result

    def get_metadata_events(self, block_hash=None):
        """
        Retrieves a list of all events in metadata active for given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """

        self.init_runtime(block_hash=block_hash)

        event_list = []

        for event_index, (module, event) in self.metadata_decoder.event_index.items():
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

        for event_index, (module, event) in self.metadata_decoder.event_index.items():
            if module.name == module_name and \
                    event.name == event_name:
                return self.serialize_module_event(
                    module, event, self.runtime_version, event_index
                )

    def get_metadata_constants(self, block_hash=None):
        """
        Retrieves a list of all constants in metadata active at given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """

        self.init_runtime(block_hash=block_hash)

        constant_list = []

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
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

        """

        self.init_runtime(block_hash=block_hash)

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):

            if module_name == module.name and module.constants:

                for constant in module.constants:
                    if constant_name == constant.name:
                        return self.serialize_constant(
                            constant, module, self.runtime_version
                        )

    def get_metadata_storage_functions(self, block_hash=None):
        """
        Retrieves a list of all storage functions in metadata active at given block_hash (or chaintip if block_hash is
        omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        storage_list = []

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
            if module.storage:
                for storage in module.storage.items:
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

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
            if module.name == module_name and module.storage:
                for storage in module.storage.items:
                    if storage.name == storage_name:
                        return self.serialize_storage_item(
                            storage_item=storage,
                            module=module,
                            spec_version_id=self.runtime_version
                        )

    def get_metadata_errors(self, block_hash=None):
        """
        Retrieves a list of all errors in metadata active at given block_hash (or chaintip if block_hash is omitted)

        Parameters
        ----------
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        error_list = []

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
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

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
            if module.name == module_name and module.errors:
                for error in module.errors:
                    if error_name == error.name:
                        return self.serialize_module_error(
                            module=module, error=error, spec_version=self.runtime_version
                        )

    def get_runtime_block(self, block_hash=None, block_id=None):
        """
        Retrieves a block with method `chain_getBlock` and in addition decodes extrinsics and log items

        Parameters
        ----------
        block_hash
        block_id

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash, block_id=block_id)

        response = self.rpc_request("chain_getBlock", [block_hash]).get('result')

        response['block']['header']['number'] = int(response['block']['header']['number'], 16)

        for idx, extrinsic_data in enumerate(response['block']['extrinsics']):
            extrinsic_decoder = ExtrinsicsDecoder(
                data=ScaleBytes(extrinsic_data),
                metadata=self.metadata_decoder
            )
            extrinsic_decoder.decode()
            response['block']['extrinsics'][idx] = extrinsic_decoder.value

        for idx, log_data in enumerate(response['block']['header']["digest"]["logs"]):
            log_digest = LogDigest(ScaleBytes(log_data))
            log_digest.decode()
            response['block']['header']["digest"]["logs"][idx] = log_digest.value

        return response

    def decode_scale(self, type_string, scale_bytes, block_hash=None):
        """
        Helper function to decode arbitrary SCALE-bytes (e.g. 0x02000000) according to given RUST type_string
        (e.g. BlockNumber). The relevant versioning information of the type (if defined) will be applied if block_hash
        is set

        Parameters
        ----------
        type_string
        scale_bytes
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        obj = ScaleDecoder.get_decoder_class(type_string, ScaleBytes(scale_bytes), metadata=self.metadata_decoder)
        return obj.decode()

    def encode_scale(self, type_string, value, block_hash=None):
        """
        Helper function to encode arbitrary data into SCALE-bytes for given RUST type_string

        Parameters
        ----------
        type_string
        value
        block_hash

        Returns
        -------

        """
        self.init_runtime(block_hash=block_hash)

        obj = ScaleDecoder.get_decoder_class(type_string)
        return str(obj.encode(value))

    # Serializing helper function

    def serialize_storage_item(self, storage_item, module, spec_version_id):
        """
        Helper function to serialize a storage item

        Parameters
        ----------
        storage_item
        module
        spec_version_id

        Returns
        -------

        """
        storage_dict = {
            "storage_name": storage_item.name,
            "storage_modifier": storage_item.modifier,
            "storage_fallback_scale": storage_item.fallback,
            "storage_fallback": None,
            "documentation": '\n'.join(storage_item.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version_id,
            "type_key1": None,
            "type_key2": None,
            "type_hasher_key1": None,
            "type_hasher_key2": None,
            "type_value": None,
            "type_is_linked": None
        }

        type_class, type_info = next(iter(storage_item.type.items()))

        storage_dict["type_class"] = type_class

        if type_class == 'PlainType':
            storage_dict["type_value"] = type_info

        elif type_class == 'MapType':
            storage_dict["type_value"] = type_info["value"]
            storage_dict["type_key1"] = type_info["key"]
            storage_dict["type_hasher_key1"] = type_info["hasher"]
            storage_dict["type_is_linked"] = type_info["isLinked"]

        elif type_class == 'DoubleMapType':

            storage_dict["type_value"] = type_info["value"]
            storage_dict["type_key1"] = type_info["key1"]
            storage_dict["type_key2"] = type_info["key2"]
            storage_dict["type_hasher_key1"] = type_info["hasher"]
            storage_dict["type_hasher_key1"] = type_info["key2Hasher"]

        if storage_item.fallback != '0x00':
            # Decode fallback
            try:
                fallback_obj = ScaleDecoder.get_decoder_class(storage_dict["type_value"],
                                                              ScaleBytes(storage_item.fallback))
                storage_dict["storage_fallback"] = fallback_obj.decode()
            except Exception:
                storage_dict["storage_fallback"] = '[decoding error]'

        return storage_dict

    def serialize_constant(self, constant, module, spec_version_id):
        """
        Helper function to serialize a constant

        Parameters
        ----------
        constant
        module
        spec_version_id

        Returns
        -------

        """
        try:
            value_obj = ScaleDecoder.get_decoder_class(constant.type,
                                                       ScaleBytes(constant.constant_value))
            constant_decoded_value = value_obj.decode()
        except Exception:
            constant_decoded_value = '[decoding error]'

        return {
            "constant_name": constant.name,
            "constant_type": constant.type,
            "constant_value": constant_decoded_value,
            "constant_value_scale": constant.constant_value,
            "documentation": '\n'.join(constant.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version_id
        }

    def serialize_module_call(self, module, call, spec_version, call_index):
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

        """
        return {
            "call_id": call.get_identifier(),
            "call_name": call.name,
            "call_args": [call_arg.value for call_arg in call.args],
            "lookup": '0x{}'.format(call_index),
            "documentation": '\n'.join(call.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version
        }

    def serialize_module_event(self, module, event, spec_version, event_index):
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

    def serialize_module_error(self, module, error, spec_version):
        """
        Helper function to serialize an error

        Parameters
        ----------
        module
        error
        spec_version

        Returns
        -------

        """
        return {
            "error_name": error.name,
            "documentation": '\n'.join(error.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version
        }
