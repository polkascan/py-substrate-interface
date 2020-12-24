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

import os
import unittest

from scalecodec import ScaleBytes
from substrateinterface import SubstrateInterface, ContractMetadata, ContractInstance, Keypair
from substrateinterface.contracts import ContractEvent
from substrateinterface.exceptions import ContractMetadataParseException
from substrateinterface.utils.ss58 import ss58_encode
from test import settings


class ContractMetadataTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(url=settings.KUSAMA_NODE_URL)

    def setUp(self) -> None:
        self.contract_metadata = ContractMetadata.create_from_file(
            metadata_file=os.path.join(os.path.dirname(__file__), 'fixtures', 'erc20.json'),
            substrate=self.substrate
        )

    def test_metadata_parsed(self):
        self.assertNotEqual(self.contract_metadata.metadata_dict, {})

    def test_incorrect_metadata_file(self):
        with self.assertRaises(ContractMetadataParseException):
            ContractMetadata.create_from_file(
                metadata_file=os.path.join(os.path.dirname(__file__), 'fixtures', 'incorrect_metadata.json'),
                substrate=self.substrate
            )

    def test_extract_typestring_from_types(self):
        self.assertEqual('u128', self.contract_metadata.get_type_string_for_metadata_type(1))
        self.assertEqual('AccountId', self.contract_metadata.get_type_string_for_metadata_type(5))
        self.assertEqual('[u8; 32]', self.contract_metadata.get_type_string_for_metadata_type(6))
        self.assertEqual('Option<AccountId>', self.contract_metadata.get_type_string_for_metadata_type(15))

    def test_invalid_type_id(self):
        with self.assertRaises(ValueError):
            self.contract_metadata.get_type_string_for_metadata_type(99)

    def test_contract_types_added_type_registry(self):

        for type_id in range(1, 16):
            type_string = self.contract_metadata.get_type_string_for_metadata_type(type_id)
            self.assertIsNotNone(self.substrate.runtime_config.get_decoder_class(type_string))

    def test_return_type_for_message(self):
        self.assertEqual('u128', self.contract_metadata.get_return_type_string_for_message('total_supply'))
        self.assertEqual('u128', self.contract_metadata.get_return_type_string_for_message('balance_of'))
        self.assertEqual(
            'ink.0x6e689bb2d2a19d1821177a607480a4527195b76dffec908f94ad7af0ed80c21f.12',
            self.contract_metadata.get_return_type_string_for_message('approve')
        )

    def test_invalid_constructor_name(self):
        with self.assertRaises(ValueError):
            self.contract_metadata.generate_constructor_data("invalid")

    def test_constructor_missing_arg(self):
        with self.assertRaises(ValueError):
            self.contract_metadata.generate_constructor_data("new", args={'test': 2})

    def test_constructor_data(self):

        scale_data = self.contract_metadata.generate_constructor_data("new", args={'initial_supply': 1000})
        self.assertEqual('0xd183512be8030000000000000000000000000000', scale_data.to_hex())

    def test_invalid_message_name(self):
        with self.assertRaises(ValueError):
            self.contract_metadata.generate_message_data("invalid_msg_name")

    def test_generate_message_data(self):

        scale_data = self.contract_metadata.generate_message_data("total_supply")
        self.assertEqual('0xdcb736b5', scale_data.to_hex())

    def test_generate_message_data_with_args(self):

        scale_data = self.contract_metadata.generate_message_data("transfer", args={
            'to': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
            'value': 10000
        })
        self.assertEqual(
            '0xfae3a09d8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4810270000000000000000000000000000',
            scale_data.to_hex()
        )

    def test_generate_message_data_missing_arg(self):
        with self.assertRaises(ValueError):
            self.contract_metadata.generate_message_data("transfer", args={
                'value': 10000
            })

    def test_contract_event_decoding(self):
        contract_event_data = '0x0001d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d018eaf04151687' + \
                              '736326c9fea17e25fc5287613693c912909cb226aa4794f26a480000a7dcf75015000000000000000000'

        contract_event_obj = ContractEvent(
            data=ScaleBytes(contract_event_data),
            runtime_config=self.substrate.runtime_config,
            contract_metadata=self.contract_metadata
        )

        contract_event_obj.decode()

        self.assertEqual(
            '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY', ss58_encode(contract_event_obj.args[0]['value'], 42)
        )
        self.assertEqual(
            '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty', ss58_encode(contract_event_obj.args[1]['value'], 42)
        )
        self.assertEqual(6000000000000000, contract_event_obj.args[2]['value'])

    def test_unsupported_ink_env_type_handling(self):
        with self.assertRaises(NotImplementedError):

            ContractMetadata.create_from_file(
                metadata_file=os.path.join(os.path.dirname(__file__), 'fixtures', 'unsupported_type_metadata.json'),
                substrate=self.substrate
            )


class ContractInstanceTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        class MockedSubstrateInterface(SubstrateInterface):

            def rpc_request(self, method, params, result_handler=None):

                if method == 'contracts_call':
                    return {
                        'jsonrpc': '2.0',
                        'result': {
                            'success': {
                                'data': '0x000064a7b3b6e00d0000000000000000', 'flags': 0, 'gas_consumed': 2616500000
                            }
                         }, 'id': self.request_id
                    }

                return super().rpc_request(method, params, result_handler)

        cls.substrate = MockedSubstrateInterface(url=settings.KUSAMA_NODE_URL)

        cls.keypair = Keypair.create_from_uri('//Alice')

    def setUp(self) -> None:
        self.contract = ContractInstance.create_from_address(
            contract_address="5FV9cnzFc2tDrWcDkmoup7VZWpH9HrTaw8STnWpAQqT7KvUK",
            metadata_file=os.path.join(os.path.dirname(__file__), 'fixtures', 'erc20.json'),
            substrate=self.substrate
        )

    def test_instance_read(self):

        result = self.contract.read(self.keypair, 'total_supply')

        self.assertEqual(1000000000000000000, result.contract_result_data.value)

    def test_instance_read_with_args(self):

        result = self.contract.read(self.keypair, 'balance_of',
                                    args={'owner': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'})

        self.assertEqual(1000000000000000000, result.contract_result_data.value)
        self.assertEqual('u128', result.contract_result_scale_type)


if __name__ == '__main__':
    unittest.main()
