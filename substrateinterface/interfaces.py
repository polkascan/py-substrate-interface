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

from typing import Callable, List, TYPE_CHECKING, Union, Optional, Tuple

from scalecodec.base import ScaleType, ScaleBytes
from scalecodec.exceptions import ScaleDecodeException

# from .contracts import ContractMetadata

from .keypair import Keypair, KeypairType, MnemonicLanguageCode
from .extensions import Extension
from .exceptions import ExtensionCallNotFound, StorageFunctionNotFound, SubstrateRequestException

__all__ = ['ExtensionInterface', 'RuntimeInterface', 'BlockInterface', 'ChainInterface', 'ContractInterface']

from .scale.extrinsic import GenericCall, GenericExtrinsic

from .scale.metadata import GenericStorageEntryMetadata

from .storage import StorageKey

if TYPE_CHECKING:
    from .base import SubstrateInterface


class Interface:
    pass


class StorageFunctionInterface(Interface):

    def __init__(self, pallet_interface: 'RuntimePalletInterface', name: str):
        self.pallet_interface = pallet_interface
        self.name = name

    @property
    def substrate(self):
        return self.pallet_interface.runtime_interface.substrate

    def get_metadata_obj(self) -> GenericStorageEntryMetadata:
        pallet = self.pallet_interface.get_metadata_obj()

        if not pallet:
            raise StorageFunctionNotFound(f'Pallet "{self.pallet_interface.name}" not found')

        storage = pallet.get_storage_function(self.name)
        if not storage:
            raise StorageFunctionNotFound(f'Storage function "{self.pallet_interface.name}.{self.name}" not found')

        return storage

    def create_storage_key(self, *args) -> StorageKey:
        """
        Create a `StorageKey` instance providing storage function details. See `subscribe_storage()`.


        Returns
        -------
        StorageKey
        """

        self.pallet_interface.runtime_interface.init()

        return StorageKey.create_from_storage_function(
            self.pallet_interface.name, self.name, list(args),
            runtime_config=self.substrate.runtime_config, metadata=self.substrate.metadata
        )

    def get(self, *args, raw_storage_key=None):

        self.pallet_interface.runtime_interface.init()

        block_hash = self.pallet_interface.runtime_interface.block_hash
        substrate = self.pallet_interface.runtime_interface.substrate

        # SCALE type string of value
        storage_function = self.get_metadata_obj()
        value_scale_type_id = storage_function.get_value_type_id()

        if raw_storage_key:
            storage_key = StorageKey.create_from_data(
                data=raw_storage_key,
                pallet=self.pallet_interface.name,
                storage_function=storage_function.value['name'],
                value_scale_type=value_scale_type_id,
                metadata=substrate.metadata,
                runtime_config=substrate.runtime_config
            )
        else:
            storage_key = StorageKey.create_from_storage_function(
                self.pallet_interface.name, storage_function.value['name'], list(args),
                metadata=substrate.metadata,
                runtime_config=substrate.runtime_config
            )

        # RPC call node
        if substrate.supports_rpc_method('state_getStorageAt'):
            response = substrate.rpc_request("state_getStorageAt", [storage_key.to_hex(), block_hash])
        else:
            response = substrate.rpc_request("state_getStorage", [storage_key.to_hex(), block_hash])

        if 'error' in response:
            raise SubstrateRequestException(response['error']['message'])

        if 'result' in response:
            return storage_key.decode_scale_value(response.get('result'))

    def list(self, *args, max_results: int = None, start_key: str = None, page_size: int = 100,
             ignore_decoding_errors: bool = True) -> 'QueryMapResult':

        self.pallet_interface.runtime_interface.init()

        block_hash = self.pallet_interface.runtime_interface.block_hash
        substrate = self.pallet_interface.runtime_interface.substrate

        # SCALE type string of value
        storage_item = self.get_metadata_obj()

        # param_scale_type_id = storage_item.get_params_type_id()
        key_hashers = storage_item.get_param_hashers()

        # Generate storage key prefix
        storage_key = StorageKey.create_from_storage_function(
            pallet=self.pallet_interface.name, storage_function=storage_item.value['name'], params=list(args),
            metadata=substrate.metadata, runtime_config=substrate.runtime_config
        )

        if len(storage_key.param_scale_types) == 0:
            raise ValueError('Given storage function is not a map')

        prefix = storage_key.to_hex()

        if not start_key:
            start_key = prefix

        # Make sure if the max result is smaller than the page size, adjust the page size
        if max_results is not None and max_results < page_size:
            page_size = max_results

        # Retrieve storage keys
        response = substrate.rpc_request(method="state_getKeysPaged", params=[prefix, page_size, start_key, block_hash])

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
            response = substrate.rpc_request(method="state_queryStorageAt", params=[result_keys, block_hash])

            if 'error' in response:
                raise SubstrateRequestException(response['error']['message'])

            for result_group in response['result']:
                for item in result_group['changes']:
                    try:

                        item_key = storage_key.decode_key_data(item[0], len(args))

                        # strip key_hashers to use as item key
                        if len(storage_key.param_scale_types) - len(args) == 1:
                            item_key = item_key.value_object[1]
                        else:
                            item_key = tuple(
                                item_key.value_object[key + 1] for key in
                                range(len(args), len(storage_key.param_scale_types) + 1, 2)
                            )

                    except ScaleDecodeException:
                        if not ignore_decoding_errors:
                            raise
                        item_key = None

                    try:
                        item_value = storage_key.decode_scale_value(item[1])

                    except ScaleDecodeException:
                        if not ignore_decoding_errors:
                            raise
                        item_value = None

                    result.append([item_key, item_value])

        return QueryMapResult(
            records=result, page_size=page_size, module=self.pallet_interface.name, storage_function=self.name,
            params=list(args), block_hash=block_hash, storage_function_interface=self,
            last_key=last_key, max_results=max_results, ignore_decoding_errors=ignore_decoding_errors
        )

    def multi(self, params_list: list) -> list:
        pass

    def subscribe(self, **kwargs):
        pass


class RuntimeCallInterface(Interface):

    def __init__(self, pallet_interface: 'RuntimePalletInterface', name: str):
        self.pallet_interface = pallet_interface
        self.name = name

    @property
    def substrate(self) -> 'SubstrateInterface':
        return self.pallet_interface.runtime_interface.substrate

    def create(self, **kwargs) -> GenericCall:
        self.pallet_interface.runtime_interface.init()

        call = self.substrate.metadata.get_call_type_def().new(metadata=self.substrate.metadata)

        try:
            call.encode({self.pallet_interface.name: {self.name: kwargs}})
        except ValueError as e:
            raise ValueError(f"Could not encode Call: {e}")

        return call

    def create_extrinsic(self, **kwargs) -> 'ExtrinsicInterface':
        return ExtrinsicInterface(substrate=self.substrate, call=self.create(**kwargs))

    def get_param_info(self):
        pass

    def get_metadata_info(self):
        # TODO determine final name
        self.pallet_interface.runtime_interface.init()

        pallet = self.pallet_interface.get_metadata_obj()

        if not pallet:
            raise ValueError(f'Pallet "{self.pallet_interface.name}" not found')

        for call in pallet.calls:
            if call.name == self.name:
                return call

        raise ValueError(f'Storage function "{self.pallet_interface.name}.{self.name}" not found')


class ExtrinsicInterface(Interface):

    def __init__(self, substrate: 'SubstrateInterface', call: GenericCall):
        self.substrate = substrate
        self.call = call

    def sign(self, keypair: Keypair, era: dict = None, nonce: int = None, tip: int = 0) -> GenericExtrinsic:
        return self.substrate.create_signed_extrinsic(
            call=self.call, keypair=keypair, era=era, nonce=nonce, tip=tip
        )

    def sign_and_submit(self, keypair: Keypair, era: dict = None, nonce: int = None, tip: int = 0,
                        wait_for_inclusion: bool = False, wait_for_finalization: bool = False
                        ) -> "ExtrinsicReceipt":

        extrinsic = self.sign(keypair=keypair, era=era, nonce=nonce, tip=tip)

        return self.substrate.submit_extrinsic(
            extrinsic, wait_for_inclusion=wait_for_inclusion, wait_for_finalization=wait_for_finalization
        )


class ConstantInterface(Interface):
    def __init__(self, runtime_interface):
        self.runtime_interface = runtime_interface

    def get(self, **kwargs):
        pass

    def info(self):
        pass


class StorageInterface(Interface):

    def __init__(self, runtime_interface: 'RuntimeInterface'):
        self.runtime_interface = runtime_interface

    @property
    def substrate(self):
        return self.runtime_interface.substrate

    def multi(self, storage_keys: List[StorageKey]) -> List[Tuple[StorageKey, ScaleType]]:
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

        result = xxxxxxxx
        ```

        Parameters
        ----------
        storage_keys: list of StorageKey objects
        block_hash: Optional block_hash of state snapshot

        Returns
        -------
        list of `(storage_key, scale_obj)` tuples
        """

        self.runtime_interface.init()

        # Retrieve corresponding value
        response = self.substrate.rpc_request(
            "state_queryStorageAt", [[s.to_hex() for s in storage_keys], self.runtime_interface.block_hash]
        )

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

    def subscribe(self, storage_keys: List[StorageKey], subscription_handler: callable):
        self.runtime_interface.init()

        storage_key_map = {s.to_hex(): s for s in storage_keys}

        def result_handler(message, update_nr, subscription_id):
            # Process changes
            for change_storage_key, change_data in message['params']['result']['changes']:
                # Check for target storage key
                storage_key = storage_key_map[change_storage_key]

                updated_obj = storage_key.decode_scale_value(change_data)

                # Process subscription handler
                subscription_result = subscription_handler(storage_key, updated_obj, update_nr, subscription_id)

                if subscription_result is not None:
                    # Handler returned end result: unsubscribe from further updates
                    self.substrate.rpc_request("state_unsubscribeStorage", [subscription_id])

                    return subscription_result

        if not callable(subscription_handler):
            raise ValueError('Provided "subscription_handler" is not callable')

        return self.substrate.rpc_request(
            "state_subscribeStorage", [[s.to_hex() for s in storage_keys]], result_handler=result_handler
        )


class RuntimePalletInterface(Interface):

    def __init__(self, runtime_interface: 'RuntimeInterface', name: str):
        self.runtime_interface = runtime_interface
        self.name = name

    @property
    def substrate(self):
        return self.runtime_interface.substrate

    def get_metadata_obj(self) -> 'GenericPalletMetadata':
        return self.substrate.metadata.get_metadata_pallet(self.name)

    def call(self, name) -> RuntimeCallInterface:
        return RuntimeCallInterface(self, name)

    def storage(self, name: str) -> StorageFunctionInterface:
        return StorageFunctionInterface(self, name)

    def constant(self, name):
        pass


class RuntimeApiCallInterface(Interface):

    def __init__(self, runtime_api_interface: 'RuntimeApiInterface', name: str):
        self.runtime_api_interface = runtime_api_interface
        self.name = name

        self.api = None
        self.api_method = None
        self.params = None

    def init(self):
        self.runtime_api_interface.runtime_interface.init()
        self.api = self.substrate.metadata.get_api(self.runtime_api_interface.name)
        self.api_method = self.api.get_method(self.name)
        self.params = self.api_method.get_params(self.substrate.metadata)

    @property
    def substrate(self):
        return self.runtime_api_interface.runtime_interface.substrate

    def execute(self, *args):

        self.init()

        if len(self.params) != len(args):
            raise ValueError(
                f"Number of arguments provided ({len(args)}) does not "
                f"match definition ({len(self.params)})"
            )

        param_data = ScaleBytes(bytes())
        for idx, param in enumerate(self.params):
            param_data += param['type_def'].new().encode(args[idx])

        # RPC request
        result_data = self.substrate.rpc_request(
            "state_call",
            [f'{self.api.name}_{self.api_method.name}', str(param_data), self.runtime_api_interface.runtime_interface.block_hash]
        )

        result_obj = self.api_method.get_return_type_def(self.substrate.metadata).new()
        result_obj.decode(ScaleBytes(result_data['result']))

        return result_obj

    def get_param_info(self):
        self.init()
        params = self.api_method.get_params(self.substrate.metadata)
        return [p['type_def'].example_value() for p in params]


class RuntimeApiInterface(Interface):

    def __init__(self, runtime_interface: 'RuntimeInterface', name: str):
        self.runtime_interface = runtime_interface
        self.name = name

    @property
    def substrate(self):
        return self.runtime_interface.substrate

    def call(self, name) -> RuntimeApiCallInterface:
        return RuntimeApiCallInterface(self, name)

    def list(self):
        raise NotImplementedError()


class RuntimeInterface(Interface):

    def __init__(self, substrate: 'SubstrateInterface', block_hash: str = None):
        self.substrate = substrate
        self.config = substrate.runtime_config
        self.block_hash = block_hash

    def init(self, block_hash: str = None):
        if block_hash:
            self.block_hash = block_hash

        # TODO move implementation of init here
        self.substrate.init_runtime(block_hash=self.block_hash)

    def at(self, block_hash: str):
        if block_hash is None:
            block_hash = self.substrate.get_chain_head()

        self.init(block_hash=block_hash)
        return self

    def create_scale_object(self, si_type_id: int) -> ScaleType:
        self.init()
        type_def = self.substrate.metadata.portable_registry.get_scale_type_def(si_type_id)
        if not type_def:
            raise ValueError("Type def not found for {}".format(si_type_id))
        return type_def.new()

    def pallet(self, name: str) -> RuntimePalletInterface:
        return RuntimePalletInterface(self, name)

    def get_spec_version(self):
        raise NotImplementedError()

    # def api_call(self, api, name):
    #     pass

    def api(self, name) -> RuntimeApiInterface:
        return RuntimeApiInterface(self, name)

    # def subscribe_storage(self, storage_keys):
    #     raise NotImplementedError()

    @property
    def storage(self) -> StorageInterface:
        return StorageInterface(self)

    @property
    def metadata(self):
        self.init()
        return self.substrate.metadata


class BlockInterface(Interface):

    def __init__(self, substrate: 'SubstrateInterface', number_or_hash: Union[int, str] = None) -> None:
        self.substrate = substrate

        if type(number_or_hash) is int:
            number_or_hash = self.substrate.get_block_hash(number_or_hash)

        self.block_hash = number_or_hash

    # def __init__(self, chain_interface: 'ChainInterface', block_hash: str):
    #     self.chain_interface = chain_interface
    #     self.block_hash = block_hash

    def number(self, block_number: int):
        return self.at(self.substrate.get_block_hash(block_number))

    def at(self, block_hash: str):
        self.block_hash = block_hash
        return self

    def extrinsics(self):
        return self.substrate.get_extrinsics(block_hash=self.block_hash)

    def header(self):
        pass

    def author(self):
        pass

    def events(self):
        return self.substrate.runtime.at(self.block_hash).pallet("System").storage("Events").get()


class ChainInterface(Interface):
    def __init__(self, substrate: 'SubstrateInterface'):
        self.substrate = substrate

    def get_block_hash(self, block_number: int = None):
        return self.substrate.get_block_hash(block_number)

    def block(self):
        return BlockInterface(self.substrate)

    def get_extrinsic(self, identifier: str):
        pass


class ExtensionInterface(Interface):
    """
    Keeps tracks of active extensions and which calls can be made
    """

    def __init__(self, substrate):
        self.substrate = substrate
        self.extensions = []

    def __len__(self):
        return len(self.extensions)

    def __iter__(self):
        for item in self.extensions:
            yield item

    def __add__(self, other):
        self.register(other)
        return self

    def register(self, extension: Extension):
        """
        Register an extension instance to the registry and calls initialization

        Parameters
        ----------
        extension: Extension

        Returns
        -------

        """
        if not isinstance(extension, Extension):
            raise ValueError("Provided extension is not a subclass of Extension")

        extension.init(self.substrate)

        self.extensions.append(extension)

    def unregister_all(self):
        """
        Unregister all extensions and free used resources and connections

        Returns
        -------

        """
        for extension in self.extensions:
            extension.close()

    def call(self, name: str, *args, **kwargs):
        """
        Tries to call extension function with `name` and provided args and kwargs

        Will raise a `ExtensionCallNotFound` when no method is found in current extensions

        Parameters
        ----------
        name
        args
        kwargs

        Returns
        -------

        """
        return self.get_extension_callable(name)(*args, **kwargs)

    def get_extension_callable(self, name: str) -> Callable:

        for extension in self.extensions:
            if isinstance(extension, Extension):
                if hasattr(extension, name):
                    try:
                        # Call extension that implements functionality
                        self.substrate.debug_message(f"Call '{name}' using extension {extension.__class__.__name__} ...")
                        return getattr(extension, name)
                    except NotImplementedError:
                        pass

        raise ExtensionCallNotFound(f"No extension registered that implements call '{name}'")

    def __getattr__(self, name):
        return self.get_extension_callable(name)


class ContractMetadataInterface(Interface):

    def __init__(self, contract_interface):
        self.contract_interface = contract_interface

    def create_from_file(self, metadata_file: str) -> "ContractMetadata":
        from .contracts import ContractMetadata
        return ContractMetadata.create_from_file(
            metadata_file=metadata_file, substrate=self.contract_interface.substrate
        )


class ContractInstanceInterface(Interface):
    def __init__(self, contract_bundle_interface, address: str):
        self.contract_bundle_interface = contract_bundle_interface
        self.address = address


class ContractBundleInterface(Interface):

    def __init__(self, contract_interface, bundle_data: dict):
        self.contract_interface = contract_interface
        self.bundle_data = bundle_data

    def deploy(self):
        pass

    def instantiate(self, keypair: Keypair, constructor: str, args: dict = None, value: int = 0, gas_limit: dict = None,
               deployment_salt: str = None, upload_code: bool = False, storage_deposit_limit: int = None):
        pass

    def instance(self, address: str):
        return ContractInstanceInterface(self, address)


class ContractInterface(Interface):

    def __init__(self, substrate):
        self.substrate = substrate

    def metadata(self):
        return ContractMetadataInterface(self)

    # def instance(self, contract_address, metadata_file):
    def bundle(self, bundle_data: dict):
        return ContractBundleInterface(self, bundle_data)


class UtilsInterface(Interface):

    def __init__(self, substrate):
        self.substrate = substrate


class KeyringInterface(Interface):

    def __init__(self, substrate):
        self.substrate = substrate

    def create_from_uri(
            self, uri: str, crypto_type=KeypairType.SR25519, language_code: str = MnemonicLanguageCode.ENGLISH
    ) -> Keypair:
        return Keypair.create_from_uri(
            suri=uri, crypto_type=crypto_type, ss58_format=self.substrate.ss58_format, language_code=language_code
        )

    def create_from_mnemonic(
            self, mnemonic: str, crypto_type=KeypairType.SR25519, language_code: str = MnemonicLanguageCode.ENGLISH
    ) -> Keypair:
        return Keypair.create_from_mnemonic(
            mnemonic=mnemonic, crypto_type=crypto_type, ss58_format=self.substrate.ss58_format,
            language_code=language_code
        )


class QueryMapResult:

    def __init__(self, records: list, page_size: int, module: str = None, storage_function: str = None,
                 params: list = None, block_hash: str = None,
                 storage_function_interface: 'StorageFunctionInterface' = None,
                 last_key: str = None, max_results: int = None, ignore_decoding_errors: bool = False):
        self.current_index = -1
        self.records = records
        self.page_size = page_size
        self.module = module
        self.storage_function = storage_function
        self.block_hash = block_hash
        self.storage_function_interface = storage_function_interface
        self.last_key = last_key
        self.max_results = max_results
        self.params = params
        self.ignore_decoding_errors = ignore_decoding_errors
        self.loading_complete = False

    def retrieve_next_page(self, start_key) -> list:
        if not self.storage_function_interface:
            return []

        result = self.storage_function_interface.list(*self.params, page_size=self.page_size, start_key=start_key,
                                                      max_results=self.max_results,
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
