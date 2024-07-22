#  Polkascan API extension for Substrate Interface Library
#
#  Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import unittest

from scalecodec.base import ScaleBytes
from substrateinterface.scale.extrinsic import Era


class TestExtrinsicEra(unittest.TestCase):

    def test_era_immortal(self):
        obj = Era().new()
        obj.decode(ScaleBytes('0x00'))
        self.assertEqual(obj.value, 'Immortal')
        self.assertIsNone(obj.period)
        self.assertIsNone(obj.phase)

    def test_era_mortal(self):
        obj = Era().new()
        obj.decode(ScaleBytes('0x4e9c'))
        self.assertDictEqual(obj.value, {'Mortal': (32768, 20000)})
        self.assertEqual(obj.period, 32768)
        self.assertEqual(obj.phase, 20000)

        obj = Era().new()
        obj.decode(ScaleBytes('0xc503'))
        self.assertDictEqual(obj.value, {'Mortal': (64, 60)})
        self.assertEqual(obj.period, 64)
        self.assertEqual(obj.phase, 60)

        obj = Era().new()
        obj.decode(ScaleBytes('0x8502'))
        self.assertDictEqual(obj.value, {'Mortal': (64, 40)})
        self.assertEqual(obj.period, 64)
        self.assertEqual(obj.phase, 40)

    def test_era_methods(self):
        obj = Era().new()
        obj.encode('Immortal')
        self.assertTrue(obj.is_immortal())
        self.assertEqual(obj.birth(1400), 0)
        self.assertEqual(obj.death(1400), 2**64 - 1)

        obj = Era().new()
        obj.encode({'Mortal': (256, 120)})
        self.assertFalse(obj.is_immortal())
        self.assertEqual(obj.birth(1400), 1400)
        self.assertEqual(obj.birth(1410), 1400)
        self.assertEqual(obj.birth(1399), 1144)
        self.assertEqual(obj.death(1400), 1656)

    def test_era_invalid_encode(self):
        obj = Era().new()
        self.assertRaises(ValueError, obj.encode, (1, 120))
        self.assertRaises(ValueError, obj.encode, ('64', 60))
        self.assertRaises(ValueError, obj.encode, 'x')
        self.assertRaises(ValueError, obj.encode, {'phase': 2})
        self.assertRaises(ValueError, obj.encode, {'period': 2})

    def test_era_invalid_decode(self):
        obj = Era().new()
        self.assertRaises(ValueError, obj.decode, ScaleBytes('0x0101'))

    def test_era_immortal_encode(self):
        obj = Era().new()
        obj.encode('Immortal')
        self.assertEqual(str(obj.data), '0x00')

    def test_era_mortal_encode(self):
        obj = Era().new()
        obj.encode((32768, 20000))
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = Era().new()
        obj.encode((64, 60))
        self.assertEqual(str(obj.data), '0xc503')

        obj = Era().new()
        obj.encode((64, 40))
        self.assertEqual(str(obj.data), '0x8502')

    def test_era_mortal_encode_dict(self):
        obj = RuntimeConfiguration().create_scale_object('Era')
        obj.encode({'period': 32768, 'phase': 20000})
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = RuntimeConfiguration().create_scale_object('Era')
        obj.encode({'period': 32768, 'current': (32768 * 3) + 20000})
        self.assertEqual(str(obj.data), '0x4e9c')

        obj = RuntimeConfiguration().create_scale_object('Era')
        obj.encode({'period': 200, 'current': 1400})
        obj2 = RuntimeConfiguration().create_scale_object('Era')
        obj2.encode((256, 120))
        self.assertEqual(str(obj.data), str(obj2.data))
