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

from typing import Callable, List, TYPE_CHECKING

from scalecodec.base import ScaleType, ScaleBytes
from scalecodec.types import Option, GenericStorageEntryMetadata, Call, GenericCall, GenericExtrinsic
# from .contracts import ContractMetadata

from .keypair import Keypair
from .extensions import Extension
from .exceptions import ExtensionCallNotFound, StorageFunctionNotFound, SubstrateRequestException

__all__ = ['ExtensionInterface', 'RuntimeInterface']

from .storage import StorageKey

if TYPE_CHECKING:
    from .base import SubstrateInterface


class Interface:
    pass


class StorageFunctionInterface(Interface):

    def __init__(self, pallet_interface: 'RuntimePalletInterface', name: str):
        self.pallet_interface = pallet_interface
        self.name = name

    def get_metadata_obj(self) -> GenericStorageEntryMetadata:
        pallet = self.pallet_interface.get_metadata_obj()

        if not pallet:
            raise StorageFunctionNotFound(f'Pallet "{self.pallet_interface.name}" not found')

        storage = pallet.get_storage_function(self.name)
        if not storage:
            raise StorageFunctionNotFound(f'Storage function "{self.pallet_interface.name}.{self.name}" not found')

        return storage

    def get(self, *args, raw_storage_key=None):

        self.pallet_interface.runtime_interface.init()

        block_hash = self.pallet_interface.runtime_interface.block_hash
        substrate = self.pallet_interface.runtime_interface.substrate

        # SCALE type string of value
        storage_function = self.get_metadata_obj()
        param_scale_type_id = storage_function.get_params_type_id()
        value_scale_type_id = storage_function.get_value_type_id()

        if raw_storage_key:
            storage_key = StorageKey.create_from_data(
                data=raw_storage_key, pallet=self.pallet_interface.name,
                storage_function=self.name, value_scale_type=value_scale_type_id,
                metadata=substrate.metadata,
                runtime_config=substrate.runtime_config
            )
        else:
            storage_key = StorageKey.create_from_storage_function(
                self.pallet_interface.name, self.name, list(args),
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
            if value_scale_type_id:

                value_scale_type_def = substrate.metadata.portable_registry.get_scale_type_def(value_scale_type_id)

                if response.get('result') is not None:
                    query_value = response.get('result')
                elif storage_function.value['modifier'] == 'Default':
                    # Fallback to default value of storage function if no result
                    query_value = storage_function.value_object['default'].value_object
                else:
                    # No result is interpreted as an Option<...> result
                    value_scale_type_def = Option(value_scale_type_def)
                    query_value = storage_function.value_object['default'].value_object

                obj = value_scale_type_def.new()
                obj.decode(ScaleBytes(query_value))
                obj.meta_info = {'result_found': response.get('result') is not None}

                return obj

    def list(self, *args, max_results: int = None, start_key: str = None, page_size: int = 100,
             ignore_decoding_errors: bool = True) -> 'QueryMapResult':

        self.pallet_interface.runtime_interface.init()

        block_hash = self.pallet_interface.runtime_interface.block_hash
        substrate = self.pallet_interface.runtime_interface.substrate

        # SCALE type string of value
        storage_item = self.get_metadata_obj()

        value_scale_type_id = storage_item.get_value_type_id()
        param_scale_type_id = storage_item.get_params_type_id()
        key_hashers = storage_item.get_param_hashers()

        # Check MapType condititions
        if param_scale_type_id is None:
            raise ValueError('Given storage function is not a map')

        # if len(args) != len(param_types) - 1:
        #     raise ValueError(f'Storage function map requires {len(param_types) - 1} parameters, {len(args)} given')

        # Generate storage key prefix
        storage_key = StorageKey.create_from_storage_function(
            pallet=self.pallet_interface.name, storage_function=self.name, params=list(args),
            metadata=substrate.metadata, runtime_config=substrate.runtime_config
        )
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


                        item_key = substrate.decode_scale(
                            type_string=param_types[len(args)],
                            scale_bytes='0x' + item[0][len(prefix) + concat_hash_len(key_hashers[len(params)]):],
                            return_scale_obj=True,
                            block_hash=block_hash
                        )
                    except Exception:
                        if not ignore_decoding_errors:
                            raise
                        item_key = None

                    try:
                        item_value = substrate.decode_scale(
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
            records=result, page_size=page_size, module=self.pallet_interface.name, storage_function=self.name,
            params=list(args), block_hash=block_hash, substrate=substrate, last_key=last_key, max_results=max_results,
            ignore_decoding_errors=ignore_decoding_errors
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

    def multi(self, storage_keys: List[StorageKey]):
        pass

    def subscribe(self, storage_keys: List[StorageKey], subscription_handler: callable):
        pass


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

    @property
    def substrate(self):
        return self.runtime_api_interface.runtime_interface.substrate

    def execute(self, *args):
        self.runtime_api_interface.runtime_interface.init()

        api = self.substrate.metadata.get_api(self.runtime_api_interface.name)

        api_method = api.get_method(self.name)

        params = api_method.get_params(self.substrate.metadata)

        if len(params) != len(args):
            raise ValueError(
                f"Number of arguments provided ({len(args)}) does not "
                f"match definition ({len(params)})"
            )

        param_data = ScaleBytes(bytes())
        for idx, param in enumerate(params):
            param_data += param['type_def'].new().encode(args[idx])

        # RPC request
        result_data = self.substrate.rpc_request(
            "state_call",
            [f'{api.name}_{api_method.name}', str(param_data), self.runtime_api_interface.runtime_interface.block_hash]
        )

        result_obj = api_method.get_return_type_def(self.substrate.metadata).new()
        result_obj.decode(ScaleBytes(result_data['result']))

        return result_obj

    def get_param_info(self):
        raise NotImplementedError()


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

    def create_scale_type(self, type_string: str, data: ScaleBytes = None) -> ScaleType:
        self.init()
        return self.config.create_scale_object(type_string=type_string, data=data)

    def pallet(self, name: str) -> RuntimePalletInterface:
        return RuntimePalletInterface(self, name)

    def get_spec_version(self):
        raise NotImplementedError()

    # def api_call(self, api, name):
    #     pass

    def api(self, name) -> RuntimeApiInterface:
        return RuntimeApiInterface(self, name)

    def subscribe_storage(self, storage_keys):
        raise NotImplementedError()

    @property
    def storage(self):
        return StorageInterface(self)

    @property
    def metadata(self):
        self.init()
        return self.substrate.metadata


class BlockInterface(Interface):

    def __init__(self, substrate: 'SubstrateInterface'):
        self.substrate = substrate
        self.block_hash = None

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

class QueryMapResult:

    def __init__(self, records: list, page_size: int, module: str = None, storage_function: str = None,
                 params: list = None, block_hash: str = None, substrate: 'SubstrateInterface' = None,
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
