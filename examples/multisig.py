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

from substrateinterface import SubstrateInterface, Keypair

import logging
logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

keypair_alice = Keypair.create_from_uri('//Alice', ss58_format=substrate.ss58_format)
keypair_bob = Keypair.create_from_uri('//Bob', ss58_format=substrate.ss58_format)
keypair_charlie = Keypair.create_from_uri('//Charlie', ss58_format=substrate.ss58_format)

# Generate multi-sig account from signatories and threshold
multisig_account = substrate.generate_multisig_account(
    signatories=[
        keypair_alice.ss58_address,
        keypair_bob.ss58_address,
        keypair_charlie.ss58_address
    ],
    threshold=2
)

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': keypair_alice.ss58_address,
        'value': 3 * 10 ** 3
    }
)

# Initiate multisig tx
extrinsic = substrate.create_multisig_extrinsic(call, keypair_alice, multisig_account, era={'period': 64})

receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

if not receipt.is_success:
    print(f"⚠️ {receipt.error_message}")
    exit()

# Finalize multisig tx with other signatory
extrinsic = substrate.create_multisig_extrinsic(call, keypair_bob, multisig_account, era={'period': 64})

receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

if receipt.is_success:
    print(f"✅ {receipt.triggered_events}")
else:
    print(f"⚠️ {receipt.error_message}")




