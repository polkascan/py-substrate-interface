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

from substrateinterface import SubstrateInterface

# # Enable for debugging purposes
# import logging
# logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

block_number = 10
block_hash = substrate.get_block_hash(block_number)

result = substrate.query(
    "System", "Account", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"], block_hash=block_hash
)


def format_balance(amount: int):
    amount = format(amount / 10**substrate.properties.get('tokenDecimals', 0), ".15g")
    return f"{amount} {substrate.properties.get('tokenSymbol', 'UNIT')}"


balance = (result.value["data"]["free"] + result.value["data"]["reserved"])

print(f"Balance @ {block_number}: {format_balance(balance)}")
