# Python Substrate Interface Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
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
from substrateinterface.exceptions import SubstrateRequestException

# import logging
# logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",

)
result = substrate.runtime.api("Core").call("version").execute()
block_hash = substrate.runtime.pallet("System").storage("BlockHash").get(3358739)


keypair = Keypair.create_from_uri('//Alice')
# borrow_rate = substrate.query("Loans", "BorrowRate", [101], block_hash="0x24155c44e47572496091f4a0216155dc6e503150a1f10881c90d3484bbeea7e3")

receipt = substrate.runtime.pallet("Balances").call("transfer_keep_alive").create_extrinsic(
    dest='5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
    value=1 * 10**15
).sign_and_submit(keypair=keypair, era={'period': 64}, wait_for_inclusion=True)


try:
    print('Extrinsic "{}" included in block "{}"'.format(
        receipt.extrinsic_hash, receipt.block_hash
    ))

    if receipt.is_success:

        print('✅ Success, triggered events:')
        for event in receipt.triggered_events:
            print(f'* {event.value}')

    else:
        print('⚠️ Extrinsic Failed: ', receipt.error_message)


except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
