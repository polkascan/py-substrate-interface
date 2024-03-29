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


# import logging
# logging.basicConfig(level=logging.DEBUG)


substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)

keypair = Keypair.create_from_uri('//Alice')

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer_keep_alive',
    call_params={
        'dest': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 1 * 10**15
    }
)

# Get payment info
payment_info = substrate.get_payment_info(call=call, keypair=keypair)

print("Payment info: ", payment_info)
