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
from unittest.mock import MagicMock

from scalecodec.type_registry import load_type_registry_file
from substrateinterface.exceptions import SubstrateRequestException
from scalecodec.base import ScaleBytes
from substrateinterface import SubstrateInterface


class TestHelperFunctions(unittest.TestCase):

    test_metadata_version = 'V13'

    @classmethod
    def setUpClass(cls):

        cls.substrate = SubstrateInterface(url='dummy', ss58_format=42, type_registry_preset='kusama')

        cls.metadata_fixture_dict = load_type_registry_file(
            os.path.join(os.path.dirname(__file__), 'fixtures', 'metadata_hex.json')
        )

        metadata_decoder = cls.substrate.runtime_config.create_scale_object('MetadataVersioned')
        metadata_decoder.decode(ScaleBytes(cls.metadata_fixture_dict[cls.test_metadata_version]))

        cls.substrate.get_block_metadata = MagicMock(return_value=metadata_decoder)

        def mocked_request(method, params):
            if method == 'chain_getRuntimeVersion':
                return {
                    "jsonrpc": "2.0",
                    "result": {"specVersion": 2023},
                    "id": 1
                }
            elif method == 'chain_getHeader':
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "digest": {
                            "logs": [
                            ]
                        },
                        "extrinsicsRoot": "0xa94148d938c7b7976abf4272dca95724d7a74da2f3649ec0bd53dc3daaedda44",
                        "number": "0x4abaaa",
                        "parentHash": "0xe1781813275653a970b4260298b3858b36d38e072256dad674f7c786a0cae236",
                        "stateRoot": "0xb6aa468385c82d15b343a676b3488d9f141ac100fc548bb8a546f27a7241c44a"
                    },
                    "id": 1
                }
            elif method == 'chain_getHead':
                return {
                    "jsonrpc": "2.0",
                    "result": "0xe1781813275653a970b4260298b3858b36d38e072256dad674f7c786a0cae236",
                    "id": 1
                }

            raise NotImplementedError(method)

        cls.substrate.rpc_request = MagicMock(side_effect=mocked_request)

        cls.empty_substrate = SubstrateInterface(url='dummy', ss58_format=42, type_registry_preset='kusama')

        def mocked_request(method, params):

            return {'jsonrpc': '2.0', 'result': None, 'id': 1}

        cls.empty_substrate.rpc_request = MagicMock(side_effect=mocked_request)

        cls.error_substrate = SubstrateInterface(url='wss://kusama-rpc.polkadot.io', ss58_format=2, type_registry_preset='kusama')

        # def mocked_request(method, params):
        #     return {'jsonrpc': '2.0', 'error': {
        #         'code': -32602, 'message': 'Generic error message'
        #     }, 'id': 1}
        #
        # cls.error_substrate.rpc_request = MagicMock(side_effect=mocked_request)

    def test_decode_scale(self):
        self.assertEqual(self.substrate.decode_scale('Compact<u32>', '0x08'), 2)

    def test_encode_scale(self):
        self.assertEqual(self.substrate.encode_scale('Compact<u32>', 3), ScaleBytes('0x0c'))

    def test_create_scale_object(self):
        scale_obj = self.substrate.create_scale_object("Bytes")

        self.assertEqual(scale_obj.encode("Test"), ScaleBytes("0x1054657374"))
        self.assertEqual(scale_obj.decode(ScaleBytes("0x1054657374")), "Test")

    def test_get_type_definition(self):
        self.assertDictEqual(self.substrate.get_type_definition('Bytes'), {
            'decoder_class': 'Bytes',
            'is_primitive_core': False,
            'is_primitive_runtime': True,
            'spec_version': 2023,
            'type_string': 'Bytes'}
        )

    def test_get_metadata_modules(self):
        for module in self.substrate.get_metadata_modules():
            self.assertIn('module_id', module)
            self.assertIn('name', module)
            self.assertEqual(module['spec_version'], 2023)

    def test_get_metadata_call_function(self):
        call_function = self.substrate.get_metadata_call_function("Balances", "transfer")
        self.assertEqual("transfer", call_function.name)
        self.assertEqual('dest', call_function.args[0].name)
        self.assertEqual('value', call_function.args[1].name)

    def test_get_metadata_call_functions(self):
        call_functions = self.substrate.get_metadata_call_functions()
        self.assertGreater(len(call_functions), 0)

    def test_get_metadata_event(self):
        event = self.substrate.get_metadata_event("Balances", "Transfer")
        self.assertEqual("Transfer", event.name)
        self.assertEqual('AccountId', event.args[0].type)
        self.assertEqual('AccountId', event.args[1].type)
        self.assertEqual('Balance', event.args[2].type)

    def test_get_metadata_constant(self):
        constant = self.substrate.get_metadata_constant("System", "BlockHashCount")
        self.assertEqual("BlockHashCount", constant.name)
        self.assertEqual("BlockNumber", constant.type)
        self.assertEqual("0x60090000", f"0x{constant.constant_value.hex()}")

    def test_get_metadata_constants(self):
        constants = self.substrate.get_metadata_constants()
        self.assertGreater(len(constants), 0)

    def test_get_constant(self):
        constant = self.substrate.get_constant("System", "BlockHashCount")
        self.assertEqual(2400, constant.value)

        constant = self.substrate.get_constant("Balances", "ExistentialDeposit")
        self.assertEqual(100000000000000, constant.value)

        # Also test cache method doesn't mix up results
        constant = self.substrate.get_constant("System", "BlockHashCount")
        self.assertEqual(2400, constant.value)

    def test_get_metadata_storage_function(self):
        storage = self.substrate.get_metadata_storage_function("System", "Account")
        self.assertEqual("Account", storage.name)
        self.assertEqual("AccountId", storage.get_params_type_string()[0])
        self.assertEqual("Blake2_128Concat", storage.type['Map']['hasher'])

    def test_get_metadata_storage_functions(self):
        storages = self.substrate.get_metadata_storage_functions()
        self.assertGreater(len(storages), 0)

    def test_get_metadata_error(self):
        error = self.substrate.get_metadata_error("System", "InvalidSpecName")
        self.assertEqual("InvalidSpecName", error.name)
        self.assertIsNotNone(error.docs)

    def test_get_metadata_errors(self):
        errors = self.substrate.get_metadata_errors()
        self.assertGreater(len(errors), 0)

    def test_helper_functions_should_return_null_not_exists(self):
        self.assertIsNone(self.empty_substrate.get_block_number(
            block_hash="0x6666666666666666666666666666666666666666666666666666666666666666"
        ))

        self.assertIsNone(self.empty_substrate.get_block_hash(block_id=99999999999999999))
        self.assertIsNone(self.empty_substrate.get_block_header(block_hash='0x'))
        self.assertIsNone(self.empty_substrate.get_block_metadata(block_hash='0x')['result'])
        self.assertIsNone(self.empty_substrate.get_block_runtime_version(block_hash='0x'))

    def test_helper_functions_invalid_input(self):
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_block_number, "0x6666666666666666")
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_block_hash, -1)
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_block_header, '0x')
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_block_metadata, '0x')
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_block_runtime_version, '0x')
        self.assertRaises(ValueError, self.error_substrate.query, 'System', 'Account', ['0x'])
        self.assertRaises(SubstrateRequestException, self.error_substrate.get_runtime_metadata, '0x')

    def test_storage_function_param_info(self):
        storage_function = self.substrate.get_metadata_storage_function("System", "Account")
        with self.assertRaises(NotImplementedError):
            storage_function.get_param_info()


class TestHelperFunctionsV14(TestHelperFunctions):
    test_metadata_version = 'V14'

    def test_get_metadata_constant(self):
        constant = self.substrate.get_metadata_constant("System", "BlockHashCount")
        self.assertEqual("BlockHashCount", constant.name)
        self.assertEqual("scale_info::4", constant.type)
        self.assertEqual("0x60090000", f"0x{constant.constant_value.hex()}")

    def test_get_metadata_storage_function(self):
        storage = self.substrate.get_metadata_storage_function("System", "Account")
        self.assertEqual("Account", storage.name)
        self.assertEqual("scale_info::0", storage.get_params_type_string()[0])
        self.assertEqual("Blake2_128Concat", storage.type['Map']['hashers'][0])

    def test_get_metadata_event(self):
        event = self.substrate.get_metadata_event("Balances", "Transfer")
        self.assertEqual("Transfer", event.name)
        self.assertEqual('scale_info::0', event.args[0].type)
        self.assertEqual('scale_info::0', event.args[1].type)
        self.assertEqual('scale_info::6', event.args[2].type)

    def test_storage_function_param_info(self):
        storage_function = self.substrate.get_metadata_storage_function("System", "Account")
        info = storage_function.get_param_info()
        self.assertEqual(1, len(info))


class TestHelperFunctionsKarura(TestHelperFunctionsV14):
    test_metadata_version = 'karura_test'

    def test_storage_function_param_info(self):
        storage_function = self.substrate.get_metadata_storage_function("Tokens", "TotalIssuance")
        info = storage_function.get_param_info()

        self.assertEqual(1, len(info))
        self.assertEqual('Token', info[0]['variant']['variants'][0]['name'])
        self.assertEqual('ACA', info[0]['variant']['variants'][0]['value']['variant']['variants'][0]['name'])

        storage_function = self.substrate.get_metadata_storage_function("Rewards", "PoolInfos")
        info = storage_function.get_param_info()

        self.assertEqual(1, len(info))
        self.assertEqual('Loans', info[0]['variant']['variants'][0]['name'])
        self.assertEqual('Token', info[0]['variant']['variants'][0]['value']['variant']['variants'][0]['name'])
        self.assertEqual('ACA', info[0]['variant']['variants'][0]['value']['variant']['variants'][0]['value']
                                    ['variant']['variants'][0]['name'])

        storage_function = self.substrate.get_metadata_storage_function("Dex", "TradingPairStatuses")
        info = storage_function.get_param_info()

        self.assertEqual(1, len(info))
        self.assertEqual('Token', info[0]['composite']['fields'][0]['value']['variant']['variants'][0]['name'])

    def test_get_type_definition(self):
        # TODO refactor get_type_definition
        pass

    def test_get_metadata_constant(self):
        constant = self.substrate.get_metadata_constant("System", "BlockHashCount")
        self.assertEqual("BlockHashCount", constant.name)
        self.assertEqual("scale_info::4", constant.type)
        self.assertEqual("0xb0040000", f"0x{constant.constant_value.hex()}")

    def test_get_constant(self):
        constant = self.substrate.get_constant("System", "BlockHashCount")
        self.assertEqual(1200, constant.value)

        constant = self.substrate.get_constant("Balances", "ExistentialDeposit")
        self.assertEqual(100000000000, constant.value)

        # Also test cache method doesn't mix up results
        constant = self.substrate.get_constant("System", "BlockHashCount")
        self.assertEqual(1200, constant.value)


if __name__ == '__main__':
    unittest.main()
