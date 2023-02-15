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
from time import sleep
from unittest.mock import patch, MagicMock

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import StorageFunctionNotFound
from test import settings


class RPCCallTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.substrate = SubstrateInterface(
            url=settings.POLKADOT_NODE_URL,
            ss58_format=0,
            type_registry_preset='polkadot'
        )
        # Create new keypair
        mnemonic = Keypair.generate_mnemonic()
        cls.keypair = Keypair.create_from_mnemonic(mnemonic)

        cls.substrate.orig_rpc_request = cls.substrate.rpc_request

        def mocked_request(method, params):
            if method == 'author_pendingExtrinsics':
                return {
                    'jsonrpc': '2.0', 'result': [
                        '0x910584002534454d30f8a028e42654d6b535e0651d1d026ddf115cef59ae1dd71bae074e00245ee2a4e2189bb0d8ab6b2d573fd224d2d902c1e136b3bf1aa4b288ecf59843f3f795ba9b1c072503315866760f5e447ee50cfbc015177ad476f3d5d43aa803c5002e040f00001a021805000019e3a788a770a10d14cbc6b3a0955addef7c48bf2556a656d68df39e97535150070008f6a4e8050000c56832bef06e12549a2ea67ce2cd390b207e0185045f9f2138bced0155e6dfca0b00dfc1961c01050000113bb2aaa8e32ea117dec6f8e30512b4f3fa72259caaad78a2075187c0c2bc7d075c796ec10405000065e6879c5f78d90b9c2e80b5ba5a1ad8eefdb5a592d779317a64748396352c060714fdeca60a050000ba5a44203f0f0aef04913d8cbceca016c27088b3c0cdacced6fa0785ecf6b46e078071e5492a05000009ebb8c62e3fb085a84a912d4b54aa9555ee30084d964172df298200c65ffb080700e0c71817',
                        '0xe9098400c6a7919e4d7051a1285070b6f5a80e882d858942ca21a32e62598ad72b2bee4c01ce0f96a2d4a2f8033038bea0f4b1f9bc1e761662f9ee56f8f5016c804d8f140d95e24ce428ee6a125779b1bfe7cbf562babe87f3b6a7779d78e1b93e3d2dfc884503080007054000b2e07be4d6d82f546ec91d6009ee215bb736be5b4362e66e7b466ec72d47624f0004926296ae6c9155557a6c5aac98d9775664efd8607e894ef210fa2c80b6594100d05490aa747179f2b895c2c5171e9cb10a474fd07d1a8069389678e165369e5600fabfc151a66d7cbd2cfebbdea1954d13fa4721a568a8086386f445c2cefa261c00ca0c59a8141101a8f9c99e3f8a85c77b0ccb57ca6121cf9edc436092e9bbd17c0032aee225f2714c573eec965a9dd1e1ca399636d9158ce068842f0558f360a435008ae437cc2420c617f2cdec05405db6c449bada7d2b2063eadeae636a25c5ca790094211c46d7bb07c67c2bc80e7d5ba4623f8ef0d565d266723ec60497f0375b3b00587b19cc62e01cdc18a1499cda27b0fb33264d0c3817668609bb58f76201269800d6c29a7c39cee45b0e045a94081bc188ef73be2be086d66aefd850fc7eeacc4500f278bbe8c33fe8fe03c6c684b44dfc26dfb5bcefb3ef511f5446530af859c1120066ced89b9a76de4d3dc384b45fdf0bd2f1629f15dd3e44ea14c31ba16181a25500b9f26de7808ffcf087492fc04a2c00178c3bf9ae512d1fc817f8430f6009380100c6477bfd57c12587b1075a80d944c7829784eed61a5c8b8255817e1d62d1070e002c2a55b59ed1954e80bf1349ee5882d429d261cf9962bc5d88a1fc176e60c918008e41df7864847ec31fc0168967dd5b7912c21f4a597438c697f7f4c1a29c4d57'],
                     'id': 17
                }

            return cls.substrate.orig_rpc_request(method, params)

        cls.substrate.rpc_request = MagicMock(side_effect=mocked_request)

    def test_author_pending_extrinsics(self):

        result = self.substrate.rpc_call("author", "pendingExtrinsics")

        self.assertGreater(result.value['spec_version'], 0)
        self.assertEqual('polkadot', result.value['spec_name'])

    def test_unknown_rpc_call(self):
        with self.assertRaises(ValueError):
            self.substrate.rpc_call("Foo", "bar")


if __name__ == '__main__':
    unittest.main()
