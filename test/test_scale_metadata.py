# Python SCALE Codec Library
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
import json

import os
import unittest

from scalecodec.base import ScaleBytes
from substrateinterface.scale.metadata import MetadataVersioned
from substrateinterface.utils import load_json_file


class TestMetadataRegistry(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        module_path = os.path.dirname(__file__)
        cls.metadata_fixture_dict = load_json_file(
            os.path.join(module_path, 'fixtures', 'scale_metadata_hex.json')
        )

    def test_metadata_registry_decode_v14(self):
        metadata_obj = MetadataVersioned.new()

        metadata_obj.decode(ScaleBytes(self.metadata_fixture_dict['V14']))

        self.assertEqual(metadata_obj.value_object[1].index, 14)
        self.assertIsNotNone(metadata_obj.portable_registry)

        self.assertGreater(len(metadata_obj[1][1]['pallets']), 0)
        self.assertGreater(len(metadata_obj.value[1]['V14']['pallets']), 0)

        self.assertGreater(len(metadata_obj.get_signed_extensions().items()), 0)

    def test_metadata_registry_decode_v15(self):
        metadata_obj = MetadataVersioned.new()

        metadata_obj.decode(ScaleBytes(self.metadata_fixture_dict['V15']))
        self.assertEqual(metadata_obj.value_object[1].index, 15)
        self.assertIsNotNone(metadata_obj.portable_registry)

        self.assertGreater(len(metadata_obj[1][1]['pallets']), 0)
        self.assertGreater(len(metadata_obj.value[1]['V15']['pallets']), 0)

        self.assertGreater(len(metadata_obj.get_signed_extensions().items()), 0)

