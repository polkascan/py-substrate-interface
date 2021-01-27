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

from scalecodec.type_registry import load_type_registry_preset
from substrateinterface import SubstrateInterface, Keypair, ExtrinsicReceipt
from substrateinterface.exceptions import SubstrateRequestException
from test import settings


class CreateExtrinsicsTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kusama_substrate = SubstrateInterface(
            url=settings.KUSAMA_NODE_URL,
            ss58_format=2,
            type_registry_preset='kusama'
        )

        cls.polkadot_substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            ss58_format=0,
            type_registry_preset='polkadot'
        )

    def test_compatibility_polkadot_runtime(self):
        type_reg = load_type_registry_preset("polkadot")

        runtime_data = self.polkadot_substrate.rpc_request('state_getRuntimeVersion', [])
        self.assertLessEqual(
            runtime_data['result']['specVersion'], type_reg.get('runtime_id'), 'Current runtime is incompatible'
        )

    def test_compatibility_kusama_runtime(self):
        type_reg = load_type_registry_preset("kusama")

        runtime_data = self.kusama_substrate.rpc_request('state_getRuntimeVersion', [])
        self.assertLessEqual(
            runtime_data['result']['specVersion'], type_reg.get('runtime_id'), 'Current runtime is incompatible'
        )

    def test_create_balance_transfer(self):
        # Create new keypair
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic, ss58_format=2)

        for substrate in [self.kusama_substrate, self.polkadot_substrate]:

            # Create balance transfer call
            call = substrate.compose_call(
                call_module='Balances',
                call_function='transfer',
                call_params={
                    'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                    'value': 2 * 10 ** 3
                }
            )

            extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

            self.assertEqual(extrinsic.address.value, keypair.public_key)
            self.assertEqual(extrinsic.call_module.name, 'Balances')
            self.assertEqual(extrinsic.call.name, 'transfer')

            # Randomly created account should always have 0 nonce, otherwise account already exists
            self.assertEqual(extrinsic.nonce.value, 0)

            try:
                substrate.submit_extrinsic(extrinsic)

                self.fail('Should raise no funds to pay fees exception')

            except SubstrateRequestException as e:
                # Extrinsic should be successful if account had balance, eitherwise 'Bad proof' error should be raised
                self.assertEqual(e.args[0]['data'], 'Inability to pay some fees (e.g. account balance too low)')

    def test_create_mortal_extrinsic(self):
        # Create new keypair
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic, ss58_format=2)

        for substrate in [self.kusama_substrate, self.polkadot_substrate]:

            # Create balance transfer call
            call = substrate.compose_call(
                call_module='Balances',
                call_function='transfer',
                call_params={
                    'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                    'value': 2 * 10 ** 3
                }
            )

            extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair, era={'period': 64})

            try:
                substrate.submit_extrinsic(extrinsic)

                self.fail('Should raise no funds to pay fees exception')

            except SubstrateRequestException as e:
                # Extrinsic should be successful if account had balance, eitherwise 'Bad proof' error should be raised
                self.assertEqual(e.args[0]['data'], 'Inability to pay some fees (e.g. account balance too low)')

    def test_create_unsigned_extrinsic(self):

        call = self.kusama_substrate.compose_call(
            call_module='Timestamp',
            call_function='set',
            call_params={
                'now': 1602857508000,
            }
        )

        extrinsic = self.kusama_substrate.create_unsigned_extrinsic(call)
        self.assertEqual(str(extrinsic.data), '0x280402000ba09cc0317501')

    def test_payment_info(self):
        keypair = Keypair(ss58_address="EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk")

        call = self.kusama_substrate.compose_call(
            call_module='Balances',
            call_function='transfer',
            call_params={
                'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
                'value': 2 * 10 ** 3
            }
        )
        payment_info = self.kusama_substrate.get_payment_info(call=call, keypair=keypair)

        self.assertIn('class', payment_info)
        self.assertIn('partialFee', payment_info)
        self.assertIn('weight', payment_info)

        self.assertGreater(payment_info['partialFee'], 0)

    def test_generate_signature_payload_lte_256_bytes(self):

        call = self.kusama_substrate.compose_call(
            call_module='System',
            call_function='remark',
            call_params={
                '_remark': '0x' + ('01' * 177)
            }
        )

        signature_payload = self.kusama_substrate.generate_signature_payload(call=call)

        self.assertEqual(signature_payload.length, 256)

    def test_generate_signature_payload_gt_256_bytes(self):

        call = self.kusama_substrate.compose_call(
            call_module='System',
            call_function='remark',
            call_params={
                '_remark': '0x' + ('01' * 178)
            }
        )

        signature_payload = self.kusama_substrate.generate_signature_payload(call=call)

        self.assertEqual(signature_payload.length, 32)

    def test_check_extrinsic_receipt(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0x5bcb59fdfc2ba852dabf31447b84764df85c8f64073757ea800f25b48e63ebd2",
            block_hash="0x8dae706d0f4882a7db484e708e27d9363a3adfa53baaac8b58c30f7c519a2520"
        )

        self.assertTrue(result.is_success)

    def test_check_extrinsic_failed_result(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100",
            block_hash="0x4b459839cc0b8c807061b5bfc68ca78b2039296174ed0a7754a70b84b287181e"
        )

        self.assertFalse(result.is_success)

    def test_check_extrinsic_failed_error_message(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100",
            block_hash="0x4b459839cc0b8c807061b5bfc68ca78b2039296174ed0a7754a70b84b287181e"
        )

        self.assertEqual(result.error_message['name'], 'LiquidityRestrictions')

    def test_check_extrinsic_failed_error_message2(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0x6147478693eb1ccbe1967e9327c5db093daf5f87bbf6822b4bd8d3dc3bf4e356",
            block_hash="0x402f22856baf7aaca9510c317b1c392e4d9e6133aabcc0c26f6c5b40dcde70a7"
        )

        self.assertEqual(result.error_message['name'], 'MustBeVoter')

    def test_check_extrinsic_total_fee_amount(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100",
            block_hash="0x4b459839cc0b8c807061b5bfc68ca78b2039296174ed0a7754a70b84b287181e"
        )

        self.assertEqual(2583332366, result.total_fee_amount)

    def test_check_extrinsic_total_fee_amount2(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0x7347df791b8e47a5eba29c2123783cac638acbe63b4a99024eade4e7805d7ab7",
            block_hash="0xffbf45b4dfa1be1929b519d5bf6558b2c972ea2e0fe24b623111b238cf67e095"
        )

        self.assertEqual(2749998966, result.total_fee_amount)

    def test_check_failed_extrinsic_weight(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100",
            block_hash="0x4b459839cc0b8c807061b5bfc68ca78b2039296174ed0a7754a70b84b287181e"
        )

        self.assertEqual(216625000, result.weight)

    def test_check_success_extrinsic_weight(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0x5bcb59fdfc2ba852dabf31447b84764df85c8f64073757ea800f25b48e63ebd2",
            block_hash="0x8dae706d0f4882a7db484e708e27d9363a3adfa53baaac8b58c30f7c519a2520"
        )

        self.assertEqual(10000, result.weight)

    def test_check_success_extrinsic_weight2(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0x7347df791b8e47a5eba29c2123783cac638acbe63b4a99024eade4e7805d7ab7",
            block_hash="0xffbf45b4dfa1be1929b519d5bf6558b2c972ea2e0fe24b623111b238cf67e095"
        )

        self.assertEqual(252000000, result.weight)

    def test_extrinsic_result_set_readonly_attr(self):
        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100"
        )
        with self.assertRaises(AttributeError):
            result.is_success = False

        with self.assertRaises(AttributeError):
            result.triggered_events = False

    def test_extrinsic_result_no_blockhash_check_events(self):

        result = ExtrinsicReceipt(
            substrate=self.kusama_substrate,
            extrinsic_hash="0xa5f2b9f4b8ea9f357780dd49010c99708f580a02624e4500af24b20b92773100"
        )

        with self.assertRaises(ValueError):
            events = result.triggered_events


if __name__ == '__main__':
    unittest.main()
