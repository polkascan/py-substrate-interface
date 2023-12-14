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
from substrateinterface.exceptions import StorageFunctionNotFound
from test import settings


class QueryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kusama_substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL
        )

        cls.polkadot_substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL
        )

    def test_system_account(self):

        result = self.kusama_substrate.runtime.at(
            '0xbf787e2f322080e137ed53e763b1cc97d5c5585be1f736914e27d68ac97f5f2c'
        ).pallet('System').storage('Account').get(
            'F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'
        )

        self.assertEqual(67501, result.value['nonce'])
        self.assertEqual(1099945000512, result.value['data']['free'])
        self.assertEqual(result.meta_info['result_found'], True)

    def test_system_account_non_existing(self):
        result = self.kusama_substrate.runtime.pallet('System').storage('Account').get(
            'GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi'
        )

        self.assertEqual(
            {
                'nonce': 0, 'consumers': 0, 'providers': 0, 'sufficients': 0,
                'data': {
                    'free': 0, 'reserved': 0, 'frozen': 0, 'flags': 170141183460469231731687303715884105728
                }
            }, result.value)

    def test_multiple_params(self):
        result = self.kusama_substrate.runtime.at(
            '0xbf787e2f322080e137ed53e763b1cc97d5c5585be1f736914e27d68ac97f5f2c'
        ).pallet('Staking').storage('ErasStakers').get(
            5946, 'EiBh85f6jURjXKovmokab4Li9QcHejecoaj2ADVeRWZWsAw'
        )

        self.assertEqual(8335009536888687, result.value['total'])
        self.assertEqual(10000000000000, result.value['own'])
        self.assertEqual(result.meta_info['result_found'], True)

    def test_non_existing_query(self):
        with self.assertRaises(StorageFunctionNotFound) as cm:
            self.kusama_substrate.query("Unknown", "StorageFunction")

        self.assertEqual('Pallet "Unknown" not found', str(cm.exception))

    def test_missing_params(self):
        with self.assertRaises(ValueError) as cm:
            self.kusama_substrate.query("System", "Account")

    def test_modifier_default_result(self):

        result = self.kusama_substrate.runtime.at(
            '0xbf787e2f322080e137ed53e763b1cc97d5c5585be1f736914e27d68ac97f5f2c'
        ).pallet('Staking').storage('MinCommission').get()

        self.assertEqual(84, result.value)
        self.assertEqual(result.meta_info['result_found'], False)

    def test_modifier_option_result(self):

        result = self.kusama_substrate.runtime.at(
            '0xbf787e2f322080e137ed53e763b1cc97d5c5585be1f736914e27d68ac97f5f2c'
        ).pallet('Identity').storage('IdentityOf').get("DD6kXYJPHbPRbBjeR35s1AR7zDh7W2aE55EBuDyMorQZS2a")

        self.assertIsNone(result.value)
        self.assertEqual(result.meta_info['result_found'], False)

    def test_identity_hasher(self):
        result = self.kusama_substrate.query("Claims", "Claims", ["0x00000a9c44f24e314127af63ae55b864a28d7aee"])
        self.assertEqual(45880000000000, result.value)

    def test_well_known_keys_result(self):
        result = self.kusama_substrate.query("Substrate", "Code")
        self.assertIsNotNone(result.value)

    def test_well_known_keys_default(self):
        result = self.kusama_substrate.query("Substrate", "HeapPages")
        self.assertEqual(0, result.value)

    def test_well_known_keys_not_found(self):
        with self.assertRaises(StorageFunctionNotFound):
            self.kusama_substrate.query("Substrate", "Unknown")

    def test_well_known_pallet_version(self):

        sf = self.kusama_substrate.get_metadata_storage_function("System", "PalletVersion")
        self.assertEqual(sf.value['name'], ':__STORAGE_VERSION__:')

        result = self.kusama_substrate.query("System", "PalletVersion")
        self.assertGreaterEqual(result.value, 0)

    def test_query_multi(self):

        storage_keys = [
            self.kusama_substrate.create_storage_key(
                "System", "Account", ["F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T"]
            ),
            self.kusama_substrate.create_storage_key(
                "System", "Account", ["GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi"]
            ),
            self.kusama_substrate.create_storage_key(
                "Staking", "Bonded", ["GSEX8kR4Kz5UZGhvRUCJG93D5hhTAoVZ5tAe6Zne7V42DSi"]
            )
        ]

        result = self.kusama_substrate.query_multi(storage_keys)

        self.assertEqual(len(result), 3)
        self.assertEqual(result[0][0].params[0], "F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T")
        self.assertGreater(result[0][1].value['nonce'], 0)
        self.assertEqual(result[1][1].value['nonce'], 0)

    def test_storage_key_unknown(self):
        with self.assertRaises(StorageFunctionNotFound):
            self.kusama_substrate.create_storage_key("Unknown", "Unknown")

        with self.assertRaises(StorageFunctionNotFound):
            self.kusama_substrate.create_storage_key("System", "Unknown")


if __name__ == '__main__':
    unittest.main()
