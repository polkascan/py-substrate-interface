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

from substrateinterface.exceptions import ExtrinsicFailedException, DeployContractFailedException
from scalecodec import ScaleBytes
from substrateinterface.base import SubstrateInterface, Keypair, ExtrinsicReceipt

__all__ = ['ContractExecutionReceipt', 'ContractMetadata', 'ContractCode', 'ContractInstance']


class ContractExecutionReceipt(ExtrinsicReceipt):

    @classmethod
    def create_from_extrinsic_receipt(cls, receipt: ExtrinsicReceipt):
        return cls(
            substrate=receipt.substrate,
            extrinsic_hash=receipt.extrinsic_hash,
            block_hash=receipt.block_hash,
            finalized=receipt.finalized
        )


class ContractMetadata:

    def __init__(self, metadata_dict: dict, substrate: SubstrateInterface):
        self.metadata_dict = metadata_dict
        self.substrate = substrate

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

    def get_type_string_for_metadata_type(self, type_id: int) -> str:
        if type_id > len(self.metadata_dict['types']):
            raise ValueError(f'type_id {type_id} not found in metadata')

        arg_type = self.metadata_dict['types'][type_id - 1]

        if 'primitive' in arg_type['def']:
            return arg_type['def']['primitive']
        elif 'path' in arg_type:
            if arg_type['path'] == ['ink_env', 'types', 'AccountId']:
                return 'AccountId'

        # elif 'array' in arg_type['def']:
        #     return ''

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

        return ContractExecutionReceipt.create_from_extrinsic_receipt(receipt)

