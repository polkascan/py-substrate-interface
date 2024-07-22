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

from substrateinterface import SubstrateInterface

# import logging
# logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")


def subscription_handler(obj, update_nr, subscription_id):
    print(f"New block #{obj['header']['number']}")

    block = substrate.get_block(block_number=obj['header']['number'])

    for idx, extrinsic in enumerate(block['extrinsics']):
        print(f'# {idx}:  {extrinsic.value}')

    if update_nr > 2:
        return {'message': 'Subscription will cancel when a value is returned', 'updates_processed': update_nr}


result = substrate.subscribe_block_headers(subscription_handler)
print(result)
