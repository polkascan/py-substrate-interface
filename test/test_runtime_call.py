# Python Substrate Interface Library
#
# Copyright 2018-2022 Stichting Polkascan (Polkascan Foundation).
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

from scalecodec.types import U32
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import StorageFunctionNotFound
from test import settings


class RuntimeCallTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            # url='ws://127.0.0.1:9944'
            url=settings.POLKADOT_NODE_URL
        )
        # Create new keypair
        mnemonic = Keypair.generate_mnemonic()
        cls.keypair = Keypair.create_from_mnemonic(mnemonic)

    # def test_list_api_methods(self):
    #     pass

    def test_core_version(self):
        # result = self.substrate.runtime_call("Core", "version")
        result = self.substrate.runtime.api("Core").call("version").execute()

        self.assertGreater(result.value['spec_version'], 0)
        self.assertEqual('polkadot', result.value['spec_name'])

    def test_core_version_at_not_best_block(self):
        block_hash = "0x4baab1f281c516935b81da79b37cabf31500c65caa1f0a606245c8b0f98d11a8"
        result = self.substrate.runtime.at(block_hash).api("Core").call("version").execute()

        self.assertEqual(result.value['spec_version'], 9430)
        self.assertEqual('polkadot', result.value['spec_name'])

    def test_account_nonce(self):
        result = self.substrate.runtime.api("AccountNonceApi").call("account_nonce").execute(self.keypair.ss58_address)
        self.assertEqual(result.value, 0)

    def test_transaction_payment(self):
        call = self.substrate.compose_call(
            call_module='Balances',
            call_function='transfer_keep_alive',
            call_params={
                'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                'value': 3 * 10 ** 3
            }
        )

        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=self.keypair, tip=1)

        result = self.substrate.runtime.api("TransactionPaymentApi").call("query_fee_details").execute(extrinsic, len(extrinsic.data))

        self.assertGreater(result.value['inclusion_fee']['base_fee'], 0)
        self.assertEqual(0, result.value['tip'])

    def test_metadata_call_info(self):

        param_info = self.substrate.runtime.api("TransactionPaymentApi").call("query_fee_details").get_param_info()

        self.assertEqual('<Extrinsic>', param_info[0])
        self.assertEqual(32, param_info[1])

    def test_unknown_runtime_call(self):
        with self.assertRaises(ValueError):
            self.substrate.runtime.api("Foo").call("bar").execute()


if __name__ == '__main__':
    unittest.main()
