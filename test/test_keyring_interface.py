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

from substrateinterface import SubstrateInterface, KeypairType
from substrateinterface.exceptions import StorageFunctionNotFound
from test import settings


class KeyringInterfaceTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL
        )

    def test_create_keypair_uri(self):

        keypair = self.substrate.keyring.create_from_uri('//Alice')
        self.assertEqual('15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5', keypair.ss58_address)

    def test_create_keypair_mnemonic(self):
        mnemonic = "old leopard transfer rib spatial phone calm indicate online fire caution review"
        keypair = self.substrate.keyring.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ED25519)
        self.assertEqual("16dYRUXznyhvWHS1ktUENGfNAEjCawyDzHRtN9AdFnJRc38h", keypair.ss58_address)


if __name__ == '__main__':
    unittest.main()
