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

from substrateinterface import Keypair
from bip39 import bip39_validate


class KeyPairTestCase(unittest.TestCase):

    def test_generate_mnemonic(self):
        mnemonic = Keypair.generate_mnemonic()
        self.assertTrue(bip39_validate(mnemonic))

    def test_invalid_mnemic(self):
        mnemonic = "This is an invalid mnemonic"
        self.assertFalse(bip39_validate(mnemonic))

    def test_sign_and_verify(self):
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic)
        signature = keypair.sign("Test123")
        self.assertTrue(keypair.verify("Test123", signature))

    def test_sign_and_verify_invalid_signature(self):
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic)
        signature = "0x4c291bfb0bb9c1274e86d4b666d13b2ac99a0bacc04a4846fb8ea50bda114677f83c1f164af58fc184451e5140cc8160c4de626163b11451d3bbb208a1889f8a"
        self.assertFalse(keypair.verify("Test123", signature))

    def test_sign_and_verify_invalid_message(self):
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic)
        signature = keypair.sign("Test123")
        self.assertFalse(keypair.verify("OtherMessage", signature))


if __name__ == '__main__':
    unittest.main()
