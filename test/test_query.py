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

import unittest
from unittest.mock import MagicMock

from substrateinterface import SubstrateInterface
from test import settings


class QueryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kusama_substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            ss58_format=2,
            type_registry_preset='kusama'
        )

        cls.polkadot_substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            ss58_format=0,
            type_registry_preset='polkadot'
        )

    def test_system_account(self):

        result = self.kusama_substrate.query(
            module='System',
            storage_function='Account',
            params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'],
            block_hash='0x176e064454388fd78941a0bace38db424e71db9d5d5ed0272ead7003a02234fa'
        )

        self.assertEqual(7673, result.value['nonce'])
        self.assertEqual(637747267365404068, result.value['data']['free'])

    def test_system_account_non_existing(self):
        result = self.kusama_substrate.query(
            module='System',
            storage_function='Account',
            params=['GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi']
        )

        self.assertIsNone(result)

    def test_non_existing_query(self):
        with self.assertRaises(ValueError):
            self.kusama_substrate.query("Unknown", "StorageFunction")

    def test_identity_hasher(self):
        result = self.kusama_substrate.query("Claims", "Claims", ["0x00000a9c44f24e314127af63ae55b864a28d7aee"])
        self.assertEqual(45880000000000, result.value)

    def test_map_type_iterate_map(self):

        orig_rpc_request = self.kusama_substrate.rpc_request

        def mocked_request(method, params):
            if method == 'state_getPairs':
                return {
                    'jsonrpc': '2.0',
                    'result': [
                        ['0x5f3e4907f716ac89b6347d15ececedca3ed14b45ed20d054f05e37e2542cfe70e535263148daaf49be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f', '0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d']
                    ],
                    'id': 8
                }
            return orig_rpc_request(method, params)

        self.kusama_substrate.rpc_request = MagicMock(side_effect=mocked_request)

        all_bonded_stash_ctrls = self.kusama_substrate.iterate_map(
            module='Staking',
            storage_function='Bonded'
        )

        self.assertEqual(1, len(all_bonded_stash_ctrls))
        self.assertEqual(
            '0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f', all_bonded_stash_ctrls[0][0]
        )
        self.assertEqual(
            '0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d', all_bonded_stash_ctrls[0][1]
        )

    def test_identity_iterate_map(self):

        orig_rpc_request = self.kusama_substrate.rpc_request

        def mocked_request(method, params):
            if method == 'state_getPairs':
                return {
                    'jsonrpc': '2.0',
                    'result': [
                        ['0x8985776095addd4789fccbce8ca77b23e9d6db8868a37d79930bc3f7f33950d1484aa6d852c96a543053f402f397a285d768c12afde025ce37244f6238714b4c', '0x0001081234'],
                        ['0x8985776095addd4789fccbce8ca77b23e9d6db8868a37d79930bc3f7f33950d14e8c9e912385f4025cf1e341b7462ab33765b6a564e71e8d2bf29f45d3b8c99c', '0x0001083456']
                    ], 'id': 8
                }
            return orig_rpc_request(method, params)

        self.kusama_substrate.rpc_request = MagicMock(side_effect=mocked_request)

        result = self.kusama_substrate.iterate_map('TechnicalCommittee', 'ProposalOf')

        self.assertEqual(2, len(result))
        self.assertEqual('0x484aa6d852c96a543053f402f397a285d768c12afde025ce37244f6238714b4c', result[0][0])
        self.assertEqual('System', result[1][1]['call_module'])
        self.assertEqual('remark', result[1][1]['call_function'])
        self.assertEqual('0x4e8c9e912385f4025cf1e341b7462ab33765b6a564e71e8d2bf29f45d3b8c99c', result[1][0])

    def test_blake2_256_iterate_map(self):

        storage_functions = self.kusama_substrate.get_metadata_storage_functions()

        orig_rpc_request = self.kusama_substrate.rpc_request

        def mocked_request(method, params):
            if method == 'state_getPairs':
                return {
                    'jsonrpc': '2.0',
                    'result': [
                        ['0x8985776095addd4789fccbce8ca77b23e9d6db8868a37d79930bc3f7f33950d1484aa6d852c96a543053f402f397a285d768c12afde025ce37244f6238714b4c', '0x0001081234'],
                        ['0x8985776095addd4789fccbce8ca77b23e9d6db8868a37d79930bc3f7f33950d14e8c9e912385f4025cf1e341b7462ab33765b6a564e71e8d2bf29f45d3b8c99c', '0x0001083456']
                    ], 'id': 8
                }
            return orig_rpc_request(method, params)

        self.kusama_substrate.rpc_request = MagicMock(side_effect=mocked_request)

        result = self.kusama_substrate.iterate_map('TechnicalCommittee', 'ProposalOf')

        self.assertEqual(2, len(result))
        self.assertEqual('0x484aa6d852c96a543053f402f397a285d768c12afde025ce37244f6238714b4c', result[0][0])
        self.assertEqual('System', result[1][1]['call_module'])
        self.assertEqual('remark', result[1][1]['call_function'])
        self.assertEqual('0x4e8c9e912385f4025cf1e341b7462ab33765b6a564e71e8d2bf29f45d3b8c99c', result[1][0])


if __name__ == '__main__':
    unittest.main()
