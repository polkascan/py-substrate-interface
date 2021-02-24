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

from scalecodec import GenericAccountId

from substrateinterface.exceptions import SubstrateRequestException

from substrateinterface import SubstrateInterface
from test import settings


class QueryMapTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.kusama_substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            ss58_format=2,
            type_registry_preset='kusama'
        )

        orig_rpc_request = cls.kusama_substrate.rpc_request

        def mocked_request(method, params):
            if method == 'state_getKeysPaged':
                if params[3] == '0x2e8047826d028f5cc092f5e694860efbd4f74ee1535424cdf3626a175867db62':

                    if params[2] == params[0]:
                        return {
                            'jsonrpc': '2.0',
                            'result': [
                                '0x9c5d795d0297be56027a4b2464e333979c5d795d0297be56027a4b2464e3339700000a9c44f24e314127af63ae55b864a28d7aee',
                                '0x9c5d795d0297be56027a4b2464e333979c5d795d0297be56027a4b2464e3339700002f21194993a750972574e2d82ce8c95078a6',
                                '0x9c5d795d0297be56027a4b2464e333979c5d795d0297be56027a4b2464e333970000a940f973ccf435ae9c040c253e1c043c5fb2',
                                '0x9c5d795d0297be56027a4b2464e333979c5d795d0297be56027a4b2464e3339700010b75619f666c3f172f0d1c7fa86d02adcf9c'
                            ],
                            'id': 8
                        }
                    else:
                        return {
                            'jsonrpc': '2.0',
                            'result': [
                            ],
                            'id': 8
                        }
            return orig_rpc_request(method, params)

        cls.kusama_substrate.rpc_request = MagicMock(side_effect=mocked_request)

    def test_claims_claim_map(self):

        result = self.kusama_substrate.query_map('Claims', 'Claims', max_results=2)

        self.assertEqual(2, len(result.records))
        self.assertEqual('H160', result[0][0].__class__.__name__)
        self.assertEqual('U128', result[0][1].__class__.__name__)
        self.assertEqual(45880000000000, result[0][1].value)
        self.assertEqual('0x00000a9c44f24e314127af63ae55b864a28d7aee', result[0][0].value)

    def test_system_account_map_block_hash(self):

        # Retrieve first two records from System.Account query map

        result = self.kusama_substrate.query_map(
            'System', 'Account', page_size=1,
            block_hash="0x587a1e69871c09f2408d724ceebbe16edc4a69139b5df9786e1057c4d041af73"
        )

        record_1_1 = next(result)

        self.assertEqual(type(record_1_1[0]), GenericAccountId)
        self.assertIn('data', record_1_1[1].value)
        self.assertIn('nonce', record_1_1[1].value)

        # Next record set must trigger RPC call

        record_1_2 = next(result)

        self.assertEqual(type(record_1_2[0]), GenericAccountId)
        self.assertIn('data', record_1_2[1].value)
        self.assertIn('nonce', record_1_2[1].value)

        # Same query map with yield of 2 must result in same records

        result = self.kusama_substrate.query_map(
            'System', 'Account', page_size=2,
            block_hash="0x587a1e69871c09f2408d724ceebbe16edc4a69139b5df9786e1057c4d041af73"
        )

        record_2_1 = next(result)
        record_2_2 = next(result)

        self.assertEqual(record_1_1[0].value, record_2_1[0].value)
        self.assertEqual(record_1_1[1].value, record_2_1[1].value)
        self.assertEqual(record_1_2[0].value, record_2_2[0].value)
        self.assertEqual(record_1_2[1].value, record_2_2[1].value)

    def test_max_results(self):
        result = self.kusama_substrate.query_map('Claims', 'Claims', max_results=3, page_size=100)

        # Keep iterating shouldn't trigger retrieve next page
        result_count = 0
        for _ in result:
            result_count += 1

        self.assertEqual(3, result_count)

        result = self.kusama_substrate.query_map('Claims', 'Claims', max_results=3, page_size=1)

        # Keep iterating shouldn't exceed max_results
        result_count = 0
        for _ in result:
            result_count += 1

        self.assertEqual(3, result_count)

    def test_result_exhausted(self):
        result = self.kusama_substrate.query_map(
            module='Claims', storage_function='Claims',
            block_hash='0x2e8047826d028f5cc092f5e694860efbd4f74ee1535424cdf3626a175867db62'
        )

        result_count = 0
        for _ in result:
            result_count += 1

        self.assertEqual(4, result_count)

    def test_non_existing_query_map(self):
        with self.assertRaises(ValueError) as cm:
            self.kusama_substrate.query_map("Unknown", "StorageFunction")

        self.assertEqual('Storage function "Unknown.StorageFunction" not found', str(cm.exception))

    def test_non_map_function_query_map(self):
        with self.assertRaises(ValueError) as cm:
            self.kusama_substrate.query_map("System", "Events")

        self.assertEqual('Given storage function is not a map', str(cm.exception))

    def test_exceed_maximum_page_size(self):
        with self.assertRaises(SubstrateRequestException):
            self.kusama_substrate.query_map(
                'System', 'Account', page_size=9999999
            )


if __name__ == '__main__':
    unittest.main()
