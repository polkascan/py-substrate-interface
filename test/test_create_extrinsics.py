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
#  test_create_extrinsics.py
#

#  Polkascan Substrate Interface GUI
#
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
#  test_create_extrinsics.py
#

import unittest
from substrateinterface import SubstrateInterface, Keypair, SubstrateRequestException
from test import settings


class CreateExtrinsicsTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.NODE_URL,
            address_type=2,
            type_registry_preset='kusama'
        )

    def test_create_balance_transfer(self):
        # Create new keypair
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic, 2)

        # Create balance transfer call
        call = self.substrate.compose_call(
            call_module='Balances',
            call_function='transfer',
            call_params={
                'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                'value': 2 * 10 ** 3
            }
        )

        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair)

        self.assertEqual(extrinsic.address.value, keypair.public_key)
        self.assertEqual(extrinsic.call_module.name, 'Balances')
        self.assertEqual(extrinsic.call.name, 'transfer')

        # Randomly created account should always have 0 nonce, otherwise account already exists
        self.assertEqual(extrinsic.nonce.value, 0)

        try:
            self.substrate.submit_extrinsic(extrinsic)

            self.fail('Should raise no funds to pay fees exception')

        except SubstrateRequestException as e:
            # Extrinsic should be successful if account had balance, eitherwise 'Bad proof' error should be raised
            self.assertEqual(e.args[0]['data'], 'Inability to pay some fees (e.g. account balance too low)')


if __name__ == '__main__':
    unittest.main()
