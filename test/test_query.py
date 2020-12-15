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


if __name__ == '__main__':
    unittest.main()
