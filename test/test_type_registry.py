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

from scalecodec.base import RuntimeConfiguration, ScaleType

from substrateinterface import SubstrateInterface, Keypair, SubstrateRequestException
from test import settings


class KusamaTypeRegistryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            address_type=2,
            type_registry_preset='kusama'
        )

    def test_type_registry_compatibility(self):

        for scale_type in self.substrate.get_type_registry():
            obj = RuntimeConfiguration().get_decoder_class(scale_type)

            self.assertIsNotNone(obj, '{} not supported'.format(scale_type))


class PolkadotTypeRegistryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            address_type=0,
            type_registry_preset='polkadot'
        )

    def test_type_registry_compatibility(self):

        for scale_type in self.substrate.get_type_registry():

            obj = RuntimeConfiguration().get_decoder_class(scale_type)

            self.assertIsNotNone(obj, '{} not supported'.format(scale_type))


if __name__ == '__main__':
    unittest.main()
