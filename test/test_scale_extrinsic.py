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
import os
import unittest

from scalecodec.base import ScaleBytes
from substrateinterface.scale.extrinsic import Extrinsic
from substrateinterface.scale.metadata import MetadataVersioned
from substrateinterface.utils import load_json_file


class TestScaleTypeEncoding(unittest.TestCase):

    def setUp(self) -> None:
        pass

    @classmethod
    def setUpClass(cls):
        cls.metadata_fixture_dict = load_json_file(
            os.path.join(os.path.dirname(__file__), 'fixtures', 'metadata_hex.json')
        )

        cls.metadata_obj = MetadataVersioned.new()

        cls.metadata_obj.decode(ScaleBytes(cls.metadata_fixture_dict['V14']))

    def test_encode_utility_batch_single_payload_scaletype_v14(self):
        call = self.metadata_obj.get_call_type_def().new()

        call.encode({
            'Balances': {
                'transfer_keep_alive': {
                    'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                    'value': 1000000000000
                }
            }
        })

        extrinsic = self.metadata_obj.get_extrinsic_type_def().new()

        payload = extrinsic.encode({'call': call})

        self.assertEqual(
            "0xa804050700586cb27c291c813ce74e86a60dad270609abf2fc8bee107e44a80ac00225c409070010a5d4e8", str(payload)
        )

    def test_encode_utility_batch_multiple_payload_scaletype_v14(self):
        call = self.metadata_obj.get_call_type_def().new()

        call.encode(
            {
                'Balances': {
                    'transfer_keep_alive': {
                        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                        'value': 1000000000000
                    }
                }
            }
        )

        extrinsic = self.metadata_obj.get_extrinsic_type_def().new()

        payload = extrinsic.encode({'call': {'Utility': {'batch': {'calls': [call, call]}}}})

        self.assertEqual("0x5901041a0008050700586cb27c291c813ce74e86a60dad270609abf2fc8bee107e44a80ac00225c409070010a5d4e8050700586cb27c291c813ce74e86a60dad270609abf2fc8bee107e44a80ac00225c409070010a5d4e8", str(payload))

    def test_encode_utility_cancel_as_multi_payload(self):
        extrinsic = Extrinsic(metadata=self.metadata_decoder)

        payload = extrinsic.encode({
            'call_module': 'Utility',
            'call_function': 'cancel_as_multi',
            'call_args': {
                'call_hash': '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                'other_signatories': [],
                'threshold': 5,
                'timepoint': {
                    'height': 10000,
                    'index': 1
                }
            }
        })

        self.assertEqual(str(payload), "0xb804180405000010270000010000000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

    def test_signed_extrinsic(self):
        extrinsic = Extrinsic(metadata=self.metadata_obj).new()

        extrinsic_value = {
            'address': '0xe0420e20d53ecb69d6e0ec2f7e27e08074b46b3243dc1d45113a817668db3409',
            'signature': {'Sr25519': '0xfc41fd72b66266af1611e1efe0c7292e0ccbdcb24bf2deb76198c00a4c92596812d8f0732796191f73d5e69ae4cf6aec2886fa13bfc907731c7dddc7aa18a787'},
            'era': 'Immortal',
            'nonce': 0,
            'tip': 1,
            'call': {
                'Balances': {
                    'transfer_keep_alive': {
                        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                        'value': 3000
                    }
                }
            },
            'asset_id': {
                'tip': 1, 'asset_id': None
            }
        }

        extrinsic_hex = extrinsic.encode(extrinsic_value)

        decoded_extrinsic = extrinsic.decode(extrinsic_hex)

        self.assertEqual(extrinsic_value['signature'], decoded_extrinsic['signature'])
        self.assertEqual(
            extrinsic_value['call']['Balances']['transfer_keep_alive']['value'],
            decoded_extrinsic['call']['Balances']['transfer_keep_alive']['value']
        )

    def test_mortal_extrinsic(self):
        extrinsic = Extrinsic(metadata=self.metadata_obj).new()

        extrinsic_value = {
            'address': '0xe0420e20d53ecb69d6e0ec2f7e27e08074b46b3243dc1d45113a817668db3409',
            'signature': {
                'Sr25519': '0xfc41fd72b66266af1611e1efe0c7292e0ccbdcb24bf2deb76198c00a4c92596812d8f0732796191f73d5e69ae4cf6aec2886fa13bfc907731c7dddc7aa18a787'},
            'era': {'Mortal': (666, 4950)},
            'nonce': 0,
            'tip': 1,
            'call': {
                'Balances': {
                    'transfer_keep_alive': {
                        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                        'value': 3000
                    }
                }
            },
            'asset_id': {
                'tip': 1, 'asset_id': None
            }
        }

        extrinsic_hex = extrinsic.encode(extrinsic_value)

        decoded_extrinsic = extrinsic.decode(extrinsic_hex)

        self.assertEqual(extrinsic_value['signature'], decoded_extrinsic['signature'])
        self.assertEqual(
            extrinsic_value['call']['Balances']['transfer_keep_alive']['value'],
            decoded_extrinsic['call']['Balances']['transfer_keep_alive']['value']
        )

        # self.assertEqual(extrinsic['era'].period, era_obj.period)
        # self.assertEqual(extrinsic['era'].phase, era_obj.phase)
        # self.assertEqual(extrinsic['era'].get_used_bytes(), era_obj.data.data)
        #
        # # Check lifetime of transaction
        # self.assertEqual(extrinsic['era'].birth(4955), 4950)
        # self.assertEqual(extrinsic['era'].death(4955), 5974)

    def test_encode_mortal_extrinsic(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset("substrate-node-template"))
        RuntimeConfiguration().set_active_spec_version_id(1)

        metadata_decoder = RuntimeConfiguration().create_scale_object(
            'MetadataVersioned', ScaleBytes(metadata_substrate_node_template)
        )
        metadata_decoder.decode()

        extrinsic = Extrinsic(metadata=metadata_decoder)

        extrinsic_value = {
            'account_id': '5ChV6DCRkvaTfwNHsiE2y3oQyPwTJqDPmhEUoEx1t1dupThE',
            'signature_version': 1,
            'signature': '0x86be385b2f7b25525518259b00e6b8a61e7e821544f102dca9b6d89c60fc327922229c975c2fa931992b17ab9d5b26f9848eeeff44e0333f6672a98aa8b11383',
            'call': {
                'call_function': 'transfer_keep_alive',
                'call_module': 'Balances',
                'call_args': {
                    'dest': '5ChV6DCRkvaTfwNHsiE2y3oQyPwTJqDPmhEUoEx1t1dupThE',
                    'value': 1000000000000000
                }
            },
            'nonce': 1,
            'era': {'period': 666, 'current': 4950},
            'tip': 0
        }

        extrinsic_hex = extrinsic.encode(extrinsic_value)
        extrinsic_scale = '0x4102841c0d1aa34c4be7eaddc924b30bab35e45ec22307f2f7304d6e5f9c8f3753de560186be385b2f7b25525518259b00e6b8a61e7e821544f102dca9b6d89c60fc327922229c975c2fa931992b17ab9d5b26f9848eeeff44e0333f6672a98aa8b113836935040005031c0d1aa34c4be7eaddc924b30bab35e45ec22307f2f7304d6e5f9c8f3753de560f0080c6a47e8d03'

        self.assertEqual(str(extrinsic_hex), extrinsic_scale)
