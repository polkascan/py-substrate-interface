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
from scalecodec.exceptions import ScaleEncodeException

from substrateinterface.scale.account import AccountId, MultiAccountId, MultiAddress, GenericMultiAddress
from substrateinterface.utils.ss58 import ss58_decode


class TestMultiAddress(unittest.TestCase):

    def test_create_multi_sig_address(self):

        account1 = AccountId(ss58_format=2).new()
        account1.deserialize("CdVuGwX71W4oRbXHsLuLQxNPns23rnSSiZwZPN4etWf6XYo")

        account2 = AccountId(ss58_format=2).new()
        account2.deserialize("J9aQobenjZjwWtU2MsnYdGomvcYbgauCnBeb8xGrcqznvJc")

        account3 = AccountId(ss58_format=2).new()
        account3.deserialize("HvqnQxDQbi3LL2URh7WQfcmi8b2ZWfBhu7TEDmyyn5VK8e2")

        multi_account_id = MultiAccountId([account1, account2, account3], 2, ss58_format=2).new()

        self.assertEqual(multi_account_id.ss58_address, "HFXXfXavDuKhLLBhFQTat2aaRQ5CMMw9mwswHzWi76m6iLt")


    def test_multiaddress_ss58_address_as_str(self):
        obj = MultiAddress(ss58_format=2).new()
        ss58_address = "CdVuGwX71W4oRbXHsLuLQxNPns23rnSSiZwZPN4etWf6XYo"

        public_key = ss58_decode(ss58_address)

        data = obj.encode(ss58_address)
        decode_obj = MultiAddress(ss58_format=2).new()
        decode_obj.decode(data)

        self.assertEqual(decode_obj.public_key, f'0x{public_key}')

    def test_multiaddress_ss58_address_as_str_runtime_config(self):
        obj = MultiAddress(ss58_format=2).new()
        ss58_address = "CdVuGwX71W4oRbXHsLuLQxNPns23rnSSiZwZPN4etWf6XYo"

        data = obj.encode(ss58_address)

        self.assertEqual(obj.decode(data), ss58_address)

    def test_multiaddress_ss58_index_as_str(self):
        obj = MultiAddress().new()
        ss58_address = "F7Hs"

        index_id = ss58_decode_account_index(ss58_address)

        data = obj.encode(ss58_address)
        decode_obj = RuntimeConfiguration().create_scale_object('MultiAddress', data=data)

        self.assertEqual(decode_obj.decode(), index_id)

    def test_multiaddress_account_id(self):
        # Decoding
        obj = MultiAddress().new()
        obj.decode(ScaleBytes('0x00f6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'))
        self.assertEqual({'Id': '5He5wScLMseSXNqdkS5pVoTag7w9GXwXSNHZUFw5j1r3czsF'}, obj.value)
        self.assertEqual(
            '0xf6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45',
            obj.value_object[1].public_key
        )

        # Encoding
        self.assertEqual(
            ScaleBytes('0x00f6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'),
            obj.encode('0xf6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45')
        )
        self.assertEqual(
            ScaleBytes('0x00f6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'),
            obj.encode({'Id': '0xf6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'})
        )

    def test_multiaddress_index(self):
        # Decoding
        obj = MultiAddress().new()
        obj.decode(data=ScaleBytes('0x0104'))
        self.assertEqual({'Index': 1}, obj.value)

        # Encoding
        self.assertEqual(ScaleBytes('0x0104'), obj.encode(1))
        self.assertEqual(ScaleBytes('0x0104'), obj.encode({'Index': 1}))
        self.assertEqual(ScaleBytes('0x0104'), obj.encode('F7NZ'))

    def test_multiaddress_address20(self):
        obj = MultiAddress().new()
        obj.decode(ScaleBytes('0x0467f89207abe6e1b093befd84a48f033137659292'))
        self.assertEqual({'Address20': '0x67f89207abe6e1b093befd84a48f033137659292'}, obj.value)

    def test_multiaddress_address32(self):
        obj = MultiAddress().new()
        obj.decode(ScaleBytes('0x03f6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'))
        self.assertEqual({'Address32': '0xf6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'}, obj.value)

        # Encoding
        self.assertEqual(
            ScaleBytes('0x03f6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'),
            obj.encode({'Address32': '0xf6a299ecbfec56e238b5feedfb4cba567d2902af5d946eaf05e3badf05790e45'})
        )

    def test_multiaddress_bytes_cap(self):
        # Test decoding
        obj = MultiAddress().new()
        obj.decode(ScaleBytes(
            '0x02b4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'
        ))
        self.assertEqual(
            {'Raw': '0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'},
            obj.value
        )

        # Test encoding
        self.assertEqual(
            ScaleBytes(
                '0x02b4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'
            ),
            obj.encode(
                {'Raw': '0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
            )
        )

        with self.assertRaises(ScaleEncodeException):
            obj.encode('0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111')

    def test_multiaddress_bytes_pad(self):
        # Test decoding
        obj = MultiAddress().new()
        obj.decode(ScaleBytes('0x02081234'))
        self.assertEqual(
            {'Raw': '0x1234'},
            obj.value
        )
        self.assertEqual('1234000000000000000000000000000000000000000000000000000000000000', obj.account_id)

        # Test encoding
        self.assertEqual(
            ScaleBytes(
                '0x02081234'
            ),
            obj.encode(
                {'Raw': '0x1234'}
            )
        )

        with self.assertRaises(NotImplementedError):
            obj.encode('0x1234')
