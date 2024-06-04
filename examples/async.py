#  Polkascan Substrate Interface Library
#
#  Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import asyncio

from substrateinterface import SubstrateInterface

async def main():

    uri = "ws://localhost:9944"

    # old non async example
    substrate = SubstrateInterface(uri)
    print(substrate.rpc_request('system_name', []))

    async with SubstrateInterface(uri, use_async=True) as substrate:

        async def storage_result_handler(message, update_nr, subscription_id):
            for change_storage_key, change_data in message['params']['result']['changes']:
                # TODO decode storage key and data
                print(f'{change_storage_key}: {change_data}')
            # subscription will end when result_handler return a result
            # Example usage, keep for 10 updates; will likely end with 10 blocks because of event subscription
            if update_nr > 10:
                return {'message': 'Task finished', 'subscription_id': subscription_id}

        payloads = [
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload(
                "state_subscribeStorage",
                # storage keys: System.Account Alice, Bob; System.Events
                [[
                     '0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d',
                     '0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da94f9aea1afa791265fae359272badc1cf8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48',
                     '0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7']],
                result_handler=storage_result_handler
            ),
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
            substrate.create_request_payload('system_name') ,
        ]
        responses = await substrate.send_rpc_requests(payloads)

        for payload in responses:
            print(payload.response)


if __name__ == "__main__":
    asyncio.run(main())

