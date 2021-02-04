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

import os
import sys

sys.path.append(os.path.abspath('../../py-scale-codec'))

import unittest

from scalecodec.base import ScaleBytes

from substrateinterface import SubstrateInterface
from test import settings


class KusamaTypeRegistryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            ss58_format=2,
            type_registry_preset='kusama'
        )

    def test_type_registry_compatibility(self):

        for scale_type in self.substrate.get_type_registry():
            obj = self.substrate.runtime_config.get_decoder_class(scale_type)

            self.assertIsNotNone(obj, '{} not supported'.format(scale_type))


class PolkadotTypeRegistryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            ss58_format=0,
            type_registry_preset='polkadot'
        )

    def test_type_registry_compatibility(self):

        for scale_type in self.substrate.get_type_registry():

            obj = self.substrate.runtime_config.get_decoder_class(scale_type)

            self.assertIsNotNone(obj, '{} not supported'.format(scale_type))


class MultipleTypeRegistryTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.polkadot_substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            ss58_format=0,
            type_registry_preset='polkadot',
            type_registry={
                'types': {
                    'TestType': 'u8'
                }
            }
        )

        cls.kusama_substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            ss58_format=2,
            type_registry_preset='kusama',
            type_registry={
                'types': {
                    'TestType': 'u16'
                }
            }
        )

    def test_correct_type_registry_persists(self):
        self.assertEqual(self.kusama_substrate.encode_scale('TestType', 16), ScaleBytes('0x1000'))
        self.assertEqual(self.polkadot_substrate.encode_scale('TestType', 16), ScaleBytes('0x10'))


class ReloadTypeRegistryTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.substrate = SubstrateInterface(
            url='dummy',
            ss58_format=42,
            type_registry_preset='test'
        )

    def test_initial_correct_type_local(self):
        decoding_class = self.substrate.runtime_config.type_registry['types']['blocknumber']
        self.assertEqual(self.substrate.runtime_config.get_decoder_class('u64'), decoding_class)

    def test_reloading_use_remote_preset(self):

        # Intentionally overwrite type in local preset
        u32_cls = self.substrate.runtime_config.get_decoder_class('u32')
        u64_cls = self.substrate.runtime_config.get_decoder_class('u64')

        self.substrate.runtime_config.type_registry['types']['blocknumber'] = u32_cls

        self.assertEqual(u32_cls, self.substrate.runtime_config.get_decoder_class('BlockNumber'))

        # Reload type registry
        self.substrate.reload_type_registry()

        self.assertEqual(u64_cls, self.substrate.runtime_config.get_decoder_class('BlockNumber'))

    def test_reloading_use_local_preset(self):

        # Intentionally overwrite type in local preset
        u32_cls = self.substrate.runtime_config.get_decoder_class('u32')
        u64_cls = self.substrate.runtime_config.get_decoder_class('u64')

        self.substrate.runtime_config.type_registry['types']['blocknumber'] = u32_cls

        self.assertEqual(u32_cls, self.substrate.runtime_config.get_decoder_class('BlockNumber'))

        # Reload type registry
        self.substrate.reload_type_registry(use_remote_preset=False)

        self.assertEqual(u64_cls, self.substrate.runtime_config.get_decoder_class('BlockNumber'))


if __name__ == '__main__':
    unittest.main()
