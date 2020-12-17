# Python Substrate Interface Library
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
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

import json
import os
from hashlib import blake2b

from substrateinterface.exceptions import ExtrinsicFailedException, DeployContractFailedException, \
    ContractReadFailedException
from scalecodec import ScaleBytes, Struct, ScaleType, ScaleDecoder
from substrateinterface.base import SubstrateInterface, Keypair, ExtrinsicReceipt

__all__ = ['ContractExecutionReceipt', 'ContractMetadata', 'ContractCode', 'ContractInstance']


class ContractMetadata:

    def __init__(self, metadata_dict: dict, substrate: SubstrateInterface):
        self.metadata_dict = metadata_dict
        self.substrate = substrate
        self.type_registry = {}

        self.type_string_prefix = f"ink.{self.metadata_dict['source']['hash']}"

        self.__parse_type_registry()

    @classmethod
    def create_from_file(cls, metadata_file: str, substrate: SubstrateInterface):
        with open(os.path.abspath(metadata_file), 'r') as fp:
            metadata_string = fp.read()
        return cls(json.loads(metadata_string), substrate)

    def __getattr__(self, item):
        if item in self.metadata_dict:
            return self.metadata_dict[item]
        else:
            raise AttributeError("'{}' object has no attribute '{}'".format(self.__class__.__name__, item))

    def __parse_type_registry(self):

        for idx, metadata_type in enumerate(self.metadata_dict['types']):
            if idx + 1 not in self.type_registry:
                self.type_registry[idx+1] = self.get_type_string_for_metadata_type(idx+1)

    def generate_constructor_data(self, name, args: dict = None) -> ScaleBytes:

        if not args:
            args = {}

        for constructor in self.metadata_dict['spec']['constructors']:
            if name in constructor['name']:
                data = ScaleBytes(constructor['selector'])

                for arg in constructor['args']:
                    if arg['name'] not in args:
                        raise ValueError(f"Argument \"{arg['name']}\" is missing")
                    else:
                        data += self.substrate.encode_scale(
                            type_string=self.get_type_string_for_metadata_type(arg['type']['type']),
                            value=args[arg['name']]
                        )
                return data

        raise ValueError(f'Constructor "{name}" not found')

    def get_type_string_for_metadata_type(self, type_id: int):

        # Check if already processed
        if type_id in self.type_registry:
            return self.type_registry[type_id]

        if type_id > len(self.metadata_dict['types']):
            raise ValueError(f'type_id {type_id} not found in metadata')

        arg_type = self.metadata_dict['types'][type_id - 1]

        if 'path' in arg_type:
            if arg_type['path'] == ['ink_env', 'types', 'AccountId']:
                return 'AccountId'

        if 'primitive' in arg_type['def']:
            return arg_type['def']['primitive']

        elif 'array' in arg_type['def']:
            array_type = self.get_type_string_for_metadata_type(arg_type['def']['array']['type'])
            return f"[{array_type}; {arg_type['def']['array']['len']}]"

        elif 'variant' in arg_type['def']:
            # Create Enum
            type_definition = {
              "type": "enum",
              "type_mapping": []
            }
            for variant in arg_type['def']['variant']['variants']:

                if 'fields' in variant:
                    if len(variant['fields']) > 1:
                        raise NotImplementedError('Tuples as element of enums not supported')

                    enum_value = self.get_type_string_for_metadata_type(variant['fields'][0]['type'])

                else:
                    enum_value = 'Null'

                type_definition['type_mapping'].append(
                    [variant['name'], enum_value]
                )

            # Add to type registry
            self.substrate.runtime_config.update_type_registry_types(
                {f'{self.type_string_prefix}.{type_id}': type_definition}
            )
            self.type_registry[type_id] = f'{self.type_string_prefix}.{type_id}'

            return f'{self.type_string_prefix}.{type_id}'

        elif 'composite' in arg_type['def']:
            # Create Struct
            type_definition = {
                "type": "struct",
                "type_mapping": []
            }

            for field in arg_type['def']['composite']['fields']:
                type_definition['type_mapping'].append(
                    [field['name'], self.get_type_string_for_metadata_type(field['type'])]
                )

            # Add to type registry
            self.substrate.runtime_config.update_type_registry_types(
                {f'{self.type_string_prefix}.{type_id}': type_definition}
            )

            self.type_registry[type_id] = f'{self.type_string_prefix}.{type_id}'

            return f'{self.type_string_prefix}.{type_id}'
        elif 'tuple' in arg_type['def']:
            # Create tuple
            elements = [self.get_type_string_for_metadata_type(element) for element in arg_type['def']['tuple']]
            return f"({','.join(elements)})"

        raise NotImplementedError(f"Type '{arg_type}' not supported")

    def get_return_type_string_for_message(self, name):
        for message in self.metadata_dict['spec']['messages']:
            if name in message['name']:
                return self.get_type_string_for_metadata_type(message['returnType']['type'])

        raise ValueError(f'Message "{name}" not found')

    def generate_message_data(self, name, args: dict = None) -> ScaleBytes:
        if not args:
            args = {}

        for message in self.metadata_dict['spec']['messages']:
            if name in message['name']:
                data = ScaleBytes(message['selector'])

                for arg in message['args']:
                    if arg['name'] not in args:
                        raise ValueError(f"Argument \"{arg['name']}\" is missing")
                    else:

                        data += self.substrate.encode_scale(
                            type_string=self.get_type_string_for_metadata_type(arg['type']['type']),
                            value=args[arg['name']]
                        )
                return data

        raise ValueError(f'Message "{name}" not found')

    def get_event_data(self, event_id: int):
        if event_id > len(self.metadata_dict['spec']['events']):
            raise ValueError(f'Event ID {event_id} not found')

        return self.metadata_dict['spec']['events'][event_id]


class ContractEvent(ScaleType):

    def __init__(self, *args, contract_metadata: ContractMetadata = None, **kwargs):
        self.contract_metadata = contract_metadata
        self.event_id = None
        self.name = None
        self.docs = None
        self.args = []
        super().__init__(*args, **kwargs)

    def process(self):
        self.event_id = self.process_type('u8').value

        event_data = self.contract_metadata.get_event_data(self.event_id)

        self.name = event_data['name']
        self.docs = event_data['docs']
        self.args = event_data['args']

        for arg in self.args:
            # Decode value of event arg with type_string registered in contract
            arg_type_string = self.contract_metadata.get_type_string_for_metadata_type(arg['type']['type'])
            arg['value'] = self.process_type(arg_type_string).value

        return {
            'name': self.name,
            'docs': self.docs,
            'args': self.args
        }

    def process_encode(self, value):
        raise NotImplementedError()


class ContractExecutionReceipt(ExtrinsicReceipt):

    def __init__(self, *args, **kwargs):
        self.__contract_events = None
        self.contract_metadata = kwargs.pop('contract_metadata')
        super(ContractExecutionReceipt, self).__init__(*args, **kwargs)

    @classmethod
    def create_from_extrinsic_receipt(cls, receipt: ExtrinsicReceipt, contract_metadata: ContractMetadata):
        return cls(
            substrate=receipt.substrate,
            extrinsic_hash=receipt.extrinsic_hash,
            block_hash=receipt.block_hash,
            finalized=receipt.finalized,
            contract_metadata=contract_metadata
        )

    def process_events(self):
        super().process_events()

        if self.triggered_events:

            self.__contract_events = []

            for event in self.triggered_events:
                if event.event_module.name == 'Contracts' and event.event.name == 'ContractExecution':

                    # Create contract event
                    contract_event_obj = ContractEvent(
                        data=ScaleBytes(event.params[1]['value']),
                        runtime_config=self.substrate.runtime_config,
                        contract_metadata=self.contract_metadata
                    )

                    contract_event_obj.decode()

                    self.__contract_events.append(contract_event_obj)

    @property
    def contract_events(self):
        if self.__contract_events is None:
            self.process_events()

        return self.__contract_events


class ContractCode:

    def __init__(self, code_hash: bytes = None, metadata: ContractMetadata = None, wasm_bytes: bytes = None,
                 substrate: SubstrateInterface = None):
        self.code_hash = code_hash
        self.metadata = metadata
        self.wasm_bytes = wasm_bytes
        self.substrate = substrate

    @classmethod
    def create_from_contract_files(cls, wasm_file, metadata_file, substrate: SubstrateInterface):

        with open(os.path.abspath(wasm_file), 'rb') as fp:
            wasm_bytes = fp.read()
            code_hash = blake2b(wasm_bytes, digest_size=32).digest()

        metadata = ContractMetadata.create_from_file(metadata_file, substrate=substrate)

        return cls(code_hash=code_hash, metadata=metadata, wasm_bytes=wasm_bytes, substrate=substrate)

    def upload_wasm(self, keypair):
        if not self.wasm_bytes:
            raise ValueError("No WASM bytes to upload")

        call = self.substrate.compose_call(
            call_module='Contracts',
            call_function='put_code',
            call_params={
                'code': '0x{}'.format(self.wasm_bytes.hex())
            }
        )

        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        return self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    def deploy(self, keypair, endowment, gas_limit, constructor, args: dict = None):

        # Lookup constructor
        data = self.metadata.generate_constructor_data(name=constructor, args=args)

        call = self.substrate.compose_call(
            call_module='Contracts',
            call_function='instantiate',
            call_params={
                'endowment': endowment,
                'gas_limit': gas_limit,
                'code_hash': f'0x{self.code_hash.hex()}',
                'data': data.to_hex()
            }
        )

        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        result = self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        if not result.is_succes:
            raise ExtrinsicFailedException(result.error_message)

        for event in result.triggered_events:
            if event.event.name == 'Instantiated':
                return ContractInstance(
                    contract_address=self.substrate.ss58_encode(event.params[1]['value']),
                    metadata=self.metadata,
                    substrate=self.substrate
                )

        raise DeployContractFailedException()


class ContractInstance:

    def __init__(self, contract_address: str, metadata: ContractMetadata = None, substrate: SubstrateInterface = None):
        self.substrate = substrate
        self.contract_address = contract_address
        self.metadata = metadata

    # @classmethod
    # def create_from_code_hash(cls, code_hash, metadata_file):
    #     with open(os.path.abspath(metadata_file), 'r') as fp:
    #         metadata_string = fp.read()
    #
    #     return cls(code_hash=code_hash, metadata=json.loads(metadata_string))

    @classmethod
    def create_from_address(cls, contract_address: str, metadata_file: str,
                            substrate: SubstrateInterface = None):

        metadata = ContractMetadata.create_from_file(metadata_file, substrate=substrate)

        return cls(contract_address=contract_address, metadata=metadata, substrate=substrate)

    def read(self, keypair: Keypair, method: str, args: dict = None, value: int = 0, gas_limit: int = 5000000000000):

        input_data = self.metadata.generate_message_data(name=method, args=args)

        response = self.substrate.rpc_request(method='contracts_call', params=[{
            'dest': self.contract_address,
            'gasLimit': gas_limit,
            'inputData': input_data.to_hex(),
            'origin': keypair.ss58_address,
            'value': value
        }])

        if 'result' in response:

            if 'success' in response['result']:

                try:

                    response['result']['success']['data'] = self.substrate.decode_scale(
                        type_string=self.metadata.get_return_type_string_for_message(method),
                        scale_bytes=ScaleBytes(response['result']['success']['data'])
                    )
                except NotImplementedError:
                    pass

            # Wrap the result in a ContractExecResult Enum because the exec will result in the same
            ContractExecResult = self.substrate.runtime_config.get_decoder_class('ContractExecResult')

            contract_exec_result = ContractExecResult()
            contract_exec_result.value = response['result']

            return contract_exec_result

        raise ContractReadFailedException(response)

    def exec(self, keypair: Keypair, method: str, args: dict = None, value: int = 0, gas_limit: int = 200000):

        input_data = self.metadata.generate_message_data(name=method, args=args)

        call = self.substrate.compose_call(
            call_module='Contracts',
            call_function='call',
            call_params={
                'dest': self.contract_address,
                'value': value,
                'gas_limit': gas_limit,
                'data': input_data.to_hex()
            }
        )

        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        receipt = self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return ContractExecutionReceipt.create_from_extrinsic_receipt(receipt, self.metadata)

