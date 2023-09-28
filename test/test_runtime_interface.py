#  Polkascan API extension for Substrate Interface Library
#
#  Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

# Python Substrate Interface Library
#
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
from substrateinterface.exceptions import StorageFunctionNotFound
from test import settings


class RuntimeInterfaceTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL
        )

    def test_system_account(self):

        result = self.substrate.runtime.at(
            "0x176e064454388fd78941a0bace38db424e71db9d5d5ed0272ead7003a02234fa"
        ).pallet("System").storage("Account").get("F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T")

        self.assertEqual(7673, result.value['nonce'])
        self.assertEqual(637747267365404068, result.value['data']['free'])
        self.assertEqual(result.meta_info['result_found'], True)

    def test_create_call(self):
        call = self.substrate.runtime.pallet("Balances").call("transfer").create(
            dest='F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T',
            value=2131234324
        )
        self.assertEqual(call.value['call_args']['value'], 2131234324)
        self.assertEqual(call.value['call_args']['dest'], 'F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T')

    def test_claims_claim_map(self):

        result = self.substrate.runtime.pallet("Claims").storage("Claims").list(max_results=3)

        records = [item for item in result]

        self.assertEqual(3, len(records))
        self.assertEqual(45880000000000, records[0][1].value)
        self.assertEqual('0x00000a9c44f24e314127af63ae55b864a28d7aee', records[0][0].value)
        self.assertEqual('0x00002f21194993a750972574e2d82ce8c95078a6', records[1][0].value)
        self.assertEqual('0x0000a940f973ccf435ae9c040c253e1c043c5fb2', records[2][0].value)

    def test_system_account_non_existing(self):
        result = self.substrate.runtime.pallet("System").storage("Account").get("GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi")

        # result = self.kusama_substrate.query(
        #     module='System',
        #     storage_function='Account',
        #     params=['GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi']
        # )

        self.assertEqual(
            {
                'nonce': 0, 'consumers': 0, 'providers': 0, 'sufficients': 0,
                'data': {
                    'free': 0, 'reserved': 0, 'misc_frozen': 0, 'fee_frozen': 0
                }
            }, result.value)


    def test_block_extrinsics(self):

        extrinsics = self.substrate.block.hash(100).extrinsics()
        print(extrinsics)

    #
    # def test_non_existing_query(self):
    #     with self.assertRaises(StorageFunctionNotFound) as cm:
    #         self.kusama_substrate.query("Unknown", "StorageFunction")
    #
    #     self.assertEqual('Pallet "Unknown" not found', str(cm.exception))
    #
    # def test_missing_params(self):
    #     with self.assertRaises(ValueError) as cm:
    #         self.kusama_substrate.query("System", "Account")
    #
    # def test_modifier_default_result(self):
    #     result = self.kusama_substrate.query(
    #         module='Staking',
    #         storage_function='HistoryDepth',
    #         block_hash='0x4b313e72e3a524b98582c31cd3ff6f7f2ef5c38a3c899104a833e468bb1370a2'
    #     )
    #
    #     self.assertEqual(84, result.value)
    #     self.assertEqual(result.meta_info['result_found'], False)
    #
    # def test_modifier_option_result(self):
    #
    #     result = self.kusama_substrate.query(
    #         module='Identity',
    #         storage_function='IdentityOf',
    #         params=["DD6kXYJPHbPRbBjeR35s1AR7zDh7W2aE55EBuDyMorQZS2a"],
    #         block_hash='0x4b313e72e3a524b98582c31cd3ff6f7f2ef5c38a3c899104a833e468bb1370a2'
    #     )
    #
    #     self.assertIsNone(result.value)
    #     self.assertEqual(result.meta_info['result_found'], False)
    #
    # def test_identity_hasher(self):
    #     result = self.kusama_substrate.query("Claims", "Claims", ["0x00000a9c44f24e314127af63ae55b864a28d7aee"])
    #     self.assertEqual(45880000000000, result.value)
    #
    # def test_well_known_keys_result(self):
    #     result = self.kusama_substrate.query("Substrate", "Code")
    #     self.assertIsNotNone(result.value)
    #
    # def test_well_known_keys_default(self):
    #     result = self.kusama_substrate.query("Substrate", "HeapPages")
    #     self.assertEqual(0, result.value)
    #
    # def test_well_known_keys_not_found(self):
    #     with self.assertRaises(StorageFunctionNotFound):
    #         self.kusama_substrate.query("Substrate", "Unknown")
    #
    # def test_well_known_pallet_version(self):
    #
    #     sf = self.kusama_substrate.get_metadata_storage_function("System", "PalletVersion")
    #     self.assertEqual(sf.value['name'], ':__STORAGE_VERSION__:')
    #
    #     result = self.kusama_substrate.query("System", "PalletVersion")
    #     self.assertGreaterEqual(result.value, 0)


if __name__ == '__main__':
    unittest.main()
