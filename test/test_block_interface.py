# Python Substrate Interface Library
#
# Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
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


class BlockInterfaceTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL
        )

    def test_block_extrinsics(self):

        extrinsics = self.substrate.block.number(19044074).extrinsics()
        self.assertEqual(3, len(extrinsics))
        self.assertEqual('13p5KBsP6ebGNvNxEPKRjrpftqZUUrUqvgfipijiq8hWmnKj', extrinsics[2].value['address']['Id'])

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
