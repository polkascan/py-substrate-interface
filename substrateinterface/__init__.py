# Python Substrate Interface
#
# Copyright 2018-2019 openAware BV (NL).
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

import binascii
import json
import requests

from scalecodec import ScaleBytes
from scalecodec.base import ScaleDecoder, RuntimeConfiguration
from scalecodec.block import ExtrinsicsDecoder, EventsDecoder, LogDigest
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset

from .utils.hasher import blake2_256, two_x64_concat
from .exceptions import SubstrateRequestException
from .constants import *
from .utils.ss58 import ss58_decode


class SubstrateInterface:

    def __init__(self, url, address_type=None, type_registry=None, type_registry_preset=None, metadata_version=4):

        RuntimeConfiguration().update_type_registry(load_type_registry_preset("default"))

        if type_registry:
            # Load type registries in runtime configuration
            RuntimeConfiguration().update_type_registry(type_registry)
        if type_registry_preset:
            # Load type registries in runtime configuration
            RuntimeConfiguration().update_type_registry(load_type_registry_preset(type_registry_preset))

        self.request_id = 1
        self.url = url
        self.address_type = address_type or 42

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

    def rpc_request(self, method, params):

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }

        response = requests.request("POST", self.url, data=json.dumps(payload), headers=self.default_headers)

        if response.status_code != 200:
            raise SubstrateRequestException("RPC request failed with HTTP status code {}".format(response.status_code))

        json_body = response.json()

        return json_body

    def get_system_name(self):
        response = self.rpc_request("system_name", [])
        return response.get('result')

    def get_version(self):
        if not self._version:
            response = self.rpc_request("system_version", [])
            self._version = response.get('result')
        return self._version

    def get_chain_head(self):
        response = self.rpc_request("chain_getHead", [])
        return response.get('result')

    def get_chain_finalised_head(self):
        response = self.rpc_request("chain_getFinalisedHead", [])
        return response.get('result')

    def get_chain_block(self, block_hash=None, block_id=None, metadata_decoder=None):

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
        return self.rpc_request("chain_getBlockHash", [block_id]).get('result')

    def get_block_header(self, block_hash):
        response = self.rpc_request("chain_getHeader", [block_hash])
        return response.get('result')

    def get_block_number(self, block_hash):
        response = self.rpc_request("chain_getHeader", [block_hash])
        return int(response['result']['number'], 16)

    def get_block_metadata(self, block_hash=None, decode=True):
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
        Retrieves the storage for given module, function and optional parameters at given block
        :param metadata_version: Version index of Metadata, e.g. 9 for MetadataV9
        :param metadata:
        :param spec_version_id:
        :param hasher: Hashing method used to determine storage key, defaults to 'Twox64Concat' if not provided
        :param return_scale_type: Scale type string to interprete result
        :param block_hash:
        :param module:
        :param function:
        :param params:
        :return:
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

        response = self.rpc_request("state_getStorageAt", [storage_key, block_hash])
        if 'result' in response:
            return response.get('result')
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_block_events(self, block_hash, metadata_decoder=None):

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
        response = self.rpc_request("chain_getRuntimeVersion", [block_hash])
        return response.get('result')

    def generate_storage_hash(self, storage_module, storage_function, params=None, hasher=None, metadata_version=None):
        """
        Generate a storage key for given module/function
        :param metadata_version: Version index of Metadata, e.g. 9 for MetadataV9
        :param hasher: Hashing method used to determine storage key, defaults to 'Twox64Concat' if not provided
        :param storage_module:
        :param storage_function:
        :param params: Parameters of the storage function, provided in scale encoded hex-bytes
        :return:
        """

        if metadata_version and metadata_version >= 9:
            storage_hash = two_x64_concat(storage_module.encode()) + two_x64_concat(storage_function.encode())
            if params:

                if type(params) is not list:
                    params = [params]

                params_key = bytes()

                for param in params:
                    if type(param) is str:
                        params_key += binascii.unhexlify(param)
                    elif type(param) is ScaleBytes:
                        params_key += param.data
                    elif isinstance(param, ScaleDecoder):
                        params_key += param.data.data

                if not hasher:
                    hasher = 'Twox64Concat'

                if hasher == 'Blake2_256':
                    storage_hash += blake2_256(params_key)

                elif hasher == 'Twox64Concat':
                    storage_hash += two_x64_concat(params_key)

            return '0x{}'.format(storage_hash)

        else:
            storage_hash = storage_module.encode() + b" " + storage_function.encode()

            if params:
                storage_hash += binascii.unhexlify(params)

            # Determine hasher function
            if not hasher:
                hasher = 'Twox64Concat'

            if hasher == 'Blake2_256':
                return "0x{}".format(blake2_256(storage_hash))

            elif hasher == 'Twox64Concat':
                return "0x{}".format(two_x64_concat(storage_hash))

    def convert_storage_parameter(self, scale_type, value):
        if scale_type == 'AccountId':
            if value[0:2] != '0x':
                return '0x{}'.format(ss58_decode(value, self.address_type))

        return value

    # Runtime functions used by Substrate API

    def init_runtime_request(self, block_hash=None, block_id=None):

        if block_id and block_hash:
            raise ValueError('Cannot provide block_hash and block_id at the same time')

        if block_id:
            block_hash = self.get_block_hash(block_id)

        self.block_hash = block_hash

        self.runtime_version = self.get_block_runtime_version(block_hash=self.block_hash).get("specVersion")

        # Set active runtime version
        RuntimeConfiguration().set_active_spec_version_id(self.runtime_version)

        if self.runtime_version in self.metadata_cache:
            # Get metadata from cache
            self.metadata_decoder = self.metadata_cache[self.runtime_version]
        else:
            self.metadata_decoder = self.get_block_metadata(block_hash=self.block_hash, decode=True)

            # Update metadata cache
            self.metadata_cache[self.runtime_version] = self.metadata_decoder

    def get_runtime_state(self, module, storage_function, params=None, block_hash=None):
        """
        Retrieves the storage for given module, function and optional parameters at given block
        :param metadata:
        :param module:
        :param storage_function:
        :param params: list of params, can be list of Scalebytes
        :param block_hash:
        :return:
        """

        self.init_runtime_request(block_hash=block_hash)

        # Search storage call in metadata
        for metadata_module in self.metadata_decoder.metadata.modules:
            if metadata_module.name == module:
                if metadata_module.storage:
                    for storage_item in metadata_module.storage.items:
                        if storage_item.name == storage_function:

                            if 'PlainType' in storage_item.type:
                                hasher = 'Twox64Concat'
                                return_scale_type = storage_item.type.get('PlainType')
                                if params:
                                    raise ValueError('Storage call of type "PlainType" doesn\'t accept params')

                            elif 'MapType' in storage_item.type:

                                map_type = storage_item.type.get('MapType')
                                hasher = map_type.get('hasher')
                                return_scale_type = map_type.get('value')

                                if len(params) != 1:
                                    raise ValueError('Storage call of type "MapType" requires 1 parameter')

                                # Encode parameter
                                params[0] = self.convert_storage_parameter(map_type['key'], params[0])
                                param_obj = ScaleDecoder.get_decoder_class(map_type['key'])
                                params[0] = param_obj.encode(params[0])

                            else:
                                raise NotImplementedError("Storage type not implemented")

                            storage_hash = self.generate_storage_hash(
                                storage_module=module,
                                storage_function=storage_function,
                                params=params,
                                hasher=hasher,
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

    def get_runtime_metadata(self, block_hash=None):
        params = None
        if block_hash:
            params = [block_hash]
        response = self.rpc_request("state_getMetadata", params)

        if 'result' in response:
            metadata_decoder = MetadataDecoder(ScaleBytes(response.get('result')))
            response['result'] = metadata_decoder.decode()

        return response

    def compose_call(self, call_module, call_function, call_params=(), block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

        extrinsic = ExtrinsicsDecoder(metadata=self.metadata_decoder, address_type=self.address_type)

        payload = extrinsic.encode({
            'call_module': call_module,
            'call_function': call_function,
            'call_args': call_params
        })

        return str(payload)

    def get_type_registry(self):
        raise NotImplementedError()

    def get_metadata_modules(self, block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

        call_list = []

        for call_index, (module, call) in self.metadata_decoder.call_index.items():
            call_list.append(
                self.serialize_module_call(
                    module, call, self.runtime_version, call_index
                )
            )
        return call_list

    def get_metadata_call_function(self, module_name, call_function_name, block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

        event_list = []

        for event_index, (module, event) in self.metadata_decoder.event_index.items():
            event_list.append(
                self.serialize_module_event(
                    module, event, self.runtime_version, event_index
                )
            )

        return event_list

    def get_metadata_event(self, module_name, event_name, block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

        for event_index, (module, event) in self.metadata_decoder.event_index.items():
            if module.name == module_name and \
                    event.name == event_name:
                return self.serialize_module_event(
                    module, event, self.runtime_version, event_index
                )

    def get_metadata_constants(self, block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):

            if module_name == module.name and module.constants:

                for constant in module.constants:
                    if constant_name == constant.name:
                        return self.serialize_constant(
                            constant, module, self.runtime_version
                        )

    def get_metadata_storage_functions(self, block_hash=None):

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

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

        self.init_runtime_request(block_hash=block_hash)

        for module_idx, module in enumerate(self.metadata_decoder.metadata.modules):
            if module.name == module_name and module.errors:
                for error in module.errors:
                    if error_name == error.name:
                        return self.serialize_module_error(
                            module=module, error=error, spec_version=self.runtime_version
                        )

    def get_runtime_block(self, block_hash=None, block_id=None):

        self.init_runtime_request(block_hash=block_hash, block_id=block_id)

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

    # Serializing helper function

    def serialize_storage_item(self, storage_item, module, spec_version_id):
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
        return {
            "error_name": error.name,
            "documentation": '\n'.join(error.docs),
            "module_id": module.get_identifier(),
            "module_prefix": module.prefix,
            "module_name": module.name,
            "spec_version": spec_version
        }

