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
from unittest.mock import MagicMock

from scalecodec import ScaleBytes
from scalecodec.base import RuntimeConfiguration
from scalecodec.metadata import MetadataDecoder
from scalecodec.type_registry import load_type_registry_preset

from substrateinterface import SubstrateInterface
from test.fixtures import metadata_v10_hex


class TestRuntimeState(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        metadata_decoder = MetadataDecoder(ScaleBytes(metadata_v10_hex))
        metadata_decoder.decode()

        cls.substrate = SubstrateInterface(url='dummy', address_type=2, type_registry_preset='kusama')
        cls.substrate.get_block_metadata = MagicMock(return_value=metadata_decoder)

    def test_plaintype_call(self):

        def mocked_request(method, params):
            if method == 'chain_getRuntimeVersion':
                return {
                    "jsonrpc": "2.0",
                    "result": {"specVersion": 1042},
                    "id": 1
                }
            if method == 'state_getStorageAt':
                return {
                    "jsonrpc": "2.0",
                    "result": "0x1400000000000000102700000101000001000000000040420f0000010000020000000d0600b4c40400000000000000000000000000000200000002045cd448276e6e02ff57864cd1d87b6613e14bd51457c167d26f3b04f447f89c17002d31010000000000000000000000000000020000000000400d0300000100",
                    "id": 1
                }

        self.substrate.rpc_request = MagicMock(side_effect=mocked_request)

        response = self.substrate.get_runtime_state(
            module='System',
            storage_function='Events'
        )

        self.assertEqual(len(response['result']), 5)

        self.assertEqual(response['result'][0]['module_id'], 'System')
        self.assertEqual(response['result'][0]['event_id'], 'ExtrinsicSuccess')
        self.assertEqual(response['result'][1]['module_id'], 'System')
        self.assertEqual(response['result'][1]['event_id'], 'ExtrinsicSuccess')
        self.assertEqual(response['result'][2]['module_id'], 'Treasury')
        self.assertEqual(response['result'][2]['event_id'], 'Deposit')
        self.assertEqual(response['result'][3]['module_id'], 'Balances')
        self.assertEqual(response['result'][3]['event_id'], 'Deposit')
        self.assertEqual(response['result'][4]['module_id'], 'System')
        self.assertEqual(response['result'][4]['event_id'], 'ExtrinsicSuccess')

    def test_maptype_call(self):

        def mocked_request(method, params):
            if method == 'chain_getRuntimeVersion':
                return {
                    "jsonrpc": "2.0",
                    "result": {"specVersion": 1042},
                    "id": 1
                }
            elif method == 'state_getStorageAt':
                return {
                    'jsonrpc': '2.0',
                    'result': '0x36fb1042cdcc00000000000000000000',
                    'id': 1
                }

        self.substrate.rpc_request = MagicMock(side_effect=mocked_request)

        response = self.substrate.get_runtime_state(
            module='Balances',
            storage_function='FreeBalance',
            params=['EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk']
        )

        self.assertEqual(response['result'], 225181948771126)


if __name__ == '__main__':
    unittest.main()
