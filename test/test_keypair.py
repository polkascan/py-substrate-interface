#  Polkascan Substrate Interface GUI
#
#  Copyright 2018-2020 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  test_keypair.py
#

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
