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
#  test_scale_info.py
#
import os
import unittest

from scalecodec.base import ScaleBytes
from substrateinterface.scale.account import GenericAccountId
from substrateinterface.scale.metadata import MetadataVersioned
from substrateinterface.utils import load_json_file


class ScaleInfoTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        module_path = os.path.dirname(__file__)

        # scale_info_defaults = load_type_registry_file(os.path.join(module_path, 'fixtures', 'scale_info_defaults.json'))

        # cls.runtime_config = RuntimeConfigurationObject(ss58_format=42)
        # cls.runtime_config.update_type_registry(load_type_registry_preset("core"))
        # # cls.runtime_config.update_type_registry(scale_info_defaults)

        cls.metadata_fixture_dict = load_json_file(
            os.path.join(module_path, 'fixtures', 'scale_metadata_hex.json')
        )
        cls.metadata_obj = MetadataVersioned.new()

        cls.metadata_obj.decode(ScaleBytes(cls.metadata_fixture_dict['V14']))

        # cls.runtime_config.add_portable_registry(cls.metadata_obj)

    def test_create_all_types(self):
        for type_info in self.metadata_obj.portable_registry['types']:
            try:
                scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(type_info.value['id'])
                obj = scale_type_def.new()
                self.assertIsNotNone(obj)
                example_value = obj.example_value()
                # print(example_value)
            except Exception as e:
                raise Exception(f"Failed generate {type_info}: {e}")

        self.assertGreater(len(self.metadata_obj.portable_registry.si_type_registry), 0)

    def test_path_overrides(self):
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(0)
        obj = scale_type_def.new()
        obj.encode("0x88f01441682a17b52d6ae12d1a5670cf675fd254897efabaa5069eb3a701ab73")
        self.assertIsInstance(obj, GenericAccountId)

    def test_primitives(self):
        # scale_info::2 = u8
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(2)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x02"))
        self.assertEqual(obj.value, 2)

        # scale_info::4 = u32
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(4)
        obj = scale_type_def.new()
        obj.decode(ScaleBytes("0x2efb0000"))
        self.assertEqual(obj.value, 64302)

    def test_compact(self):
        # scale_info::98 = compact<u32>
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(10)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x02093d00"))
        self.assertEqual(obj.value, 1000000)

        # scale_info::63 = compact<u128>
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(60)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x130080cd103d71bc22"))
        self.assertEqual(obj.value, 2503000000000000000)

    def test_array(self):
        # scale_info::14 = [u8; 4]
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(17)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x01020304"))
        self.assertEqual(obj.value, "0x01020304")

    def test_enum(self):
        # ['sp_runtime', 'generic', 'digest', 'DigestItem']

        scale_type_id = self.metadata_obj.portable_registry.get_si_type_id('sp_runtime::generic::digest::DigestItem')
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(scale_type_id)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x001054657374"))
        self.assertEqual({"Other": '0x54657374'}, obj.value)

        obj.encode({'Other': "Test"})
        self.assertEqual(obj.data.to_hex(), "0x001054657374")

    def test_enum_multiple_fields(self):

        scale_type_id = self.metadata_obj.portable_registry.get_si_type_id('sp_runtime::generic::digest::DigestItem')
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(scale_type_id)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x06010203041054657374"))

        self.assertEqual({'PreRuntime': ("0x01020304", "0x54657374")}, obj.value)

        data = obj.encode({'PreRuntime': ("0x01020304", "Test")})
        self.assertEqual("0x06010203041054657374", data.to_hex())

    def test_enum_no_value(self):
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(21)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x02"))
        self.assertEqual('CodeUpdated', obj.value)

    def test_named_struct(self):
        # scale_info::111 = ['frame_support', 'weights', 'RuntimeDbWeight']
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(111)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0xe110000000000000d204000000000000"))

        self.assertEqual(obj.value, {
            'read': 4321,
            'write': 1234
        })

        obj.encode({
            'read': 4321,
            'write': 1234
        })

        self.assertEqual(obj.data.to_hex(), '0xe110000000000000d204000000000000')

    def test_unnamed_struct_one_element(self):
        # ('sp_arithmetic::per_things::percent', <class 'abc.scale_info::205'>)
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(203)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x04"))
        self.assertEqual(obj.value, 4)

        obj.encode(5)
        self.assertEqual(obj.data.to_hex(), "0x05")

    def test_unnamed_struct_multiple_elements(self):
        # pallet_democracy::vote::PriorLock
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(377)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x0c00000022000000000000000000000000000000"))
        self.assertEqual((12, 34), obj.value)

        data = obj.encode((12, 34))
        self.assertEqual(data.to_hex(), '0x0c00000022000000000000000000000000000000')

    def test_tuple(self):
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(31)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x0400000003000000"))

        self.assertEqual((4, 3), obj.value)

    def test_option_none(self):
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(74)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x00"))

        self.assertIsNone(obj.value)

        data = obj.encode(None)

        self.assertEqual('0x00', data.to_hex())

    def test_option_some(self):
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(35)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x0101"))
        self.assertEqual('Signed', obj.value)

        data = obj.encode('OnChain')
        self.assertEqual(data.to_hex(), '0x0100')

    def test_weak_bounded_vec(self):
        # 87 = ['frame_support', 'storage', 'weak_bounded_vec', 'WeakBoundedVec']
        obj = self.runtime_config.create_scale_object(
            'scale_info::318',
            ScaleBytes("0x0401020304050607080a00000000000000000000000000000000")
        )
        obj.decode()

        self.assertEqual([{"id": "0x0102030405060708", 'amount': 10, 'reasons': "Fee"}], obj.value)

        data = obj.encode([{"id": "0x0102030405060708", 'amount': 10, 'reasons': "Fee"}])
        self.assertEqual('0x0401020304050607080a00000000000000000000000000000000', data.to_hex())

    def test_bounded_vec(self):
        # 'scale_info::90' = frame_support::storage::bounded_vec::BoundedVec
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(90)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x084345"))

        self.assertEqual('CE', obj.value)

        data = obj.encode([67, 69])
        self.assertEqual('0x084345', data.to_hex())

        data = obj.encode('CE')
        self.assertEqual('0x084345', data.to_hex())

    def test_data(self):
        # 'scale_info::247' = pallet_identity::types::data
        scale_type_id = self.metadata_obj.portable_registry.get_si_type_id('pallet_identity::types::data')
        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(scale_type_id)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x065465737431"))

        self.assertEqual({"Raw": b"Test1"}, obj.value)

        data = obj.encode({"Raw": "Test123"})
        self.assertEqual('0x0854657374313233', data.to_hex())

    def test_era(self):
        # 'scale_info::516' = sp_runtime::generic::era::era

        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(516)
        obj = scale_type_def.new()
        obj.decode(ScaleBytes("0x4e9c"))

        self.assertTupleEqual(obj.value, (32768, 20000))
        self.assertEqual(obj.period, 32768)
        self.assertEqual(obj.phase, 20000)
        self.assertFalse(obj.is_immortal())

    def test_multiaddress(self):
        # 'scale_info::139' = sp_runtime::multiaddress::MultiAddress

        scale_type_def = self.metadata_obj.portable_registry.get_scale_type_def(139)
        obj = scale_type_def.new()

        obj.decode(ScaleBytes("0x00d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"))

        self.assertEqual('5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY', obj.value)
        self.assertEqual('d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d', obj.account_id)

        data = obj.encode({'Id': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'})
        self.assertEqual(ScaleBytes('0x00d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d'), data)
        self.assertEqual('d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d', obj.account_id)

    def test_unknown_scale_info_type(self):

        unknown_type = self.runtime_config.create_scale_object('RegistryType')

        unknown_type.value = {
            'path': [],
            'params': [],
            'def': 'unknown',
            'docs': []
        }

        with self.assertRaises(NotImplementedError):
            self.runtime_config.get_decoder_class_for_scale_info_definition('unknown::type', unknown_type, 'runtime')

    def test_encode_call(self):

        call = self.metadata_obj.get_call_type_def().new()

        call.encode({"Balances": {"transfer_keep_alive": {"dest": "5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY", "value": 3}}})
        self.assertEqual(
            call.data.to_hex(),
            '0x050300be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f0c'
        )

    def test_decode_call(self):

        call = self.metadata_obj.get_call_type_def().new()

        call.decode(ScaleBytes("0x050300be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f0c"))
        self.assertDictEqual(
            call.value,
            {"Balances": {"transfer_keep_alive": {"dest": {'Id': '5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY'}, "value": 3}}}
        )


if __name__ == '__main__':
    unittest.main()
