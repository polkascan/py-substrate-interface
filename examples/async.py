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
import json

import asyncio
import websockets

from substrateinterface import SubstrateInterface


class Api:
    def __init__(self):
        self.last_request_id = 0
        self.last_message_event = asyncio.Event()

    def close(self):
        self.last_message_event.set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

async def message_handler(websocket, api):
    async for message in websocket:
        print(f"<: {message}")
        message_dict = json.loads(message)
        if api.last_message_event.is_set() and message_dict['id'] >= api.last_request_id:
            break


def create_payload(request_id, method, params = []):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": request_id
    }
    return json.dumps(payload)


async def send_messages(websocket, api):

    while api.last_request_id < 100:
        api.last_request_id += 1
        payload = create_payload(api.last_request_id, "system_health")
        print (f'>: {payload}')
        await websocket.send(payload)
        # await asyncio.sleep(.0001)

    # api.last_message_event.set()


async def hello():

    uri = "ws://localhost:9944"

    # api = Api()
    #
    # async with SubstrateInterface(uri, use_async=True) as substrate:
    #     # print(substrate.name)
    #     await substrate.websocket.send(substrate.create_payload(substrate.request_id, 'system_name'))
    #     substrate.config['async_stop_event'].set()
    #     print('hallo')
    #
    # exit()

    async with websockets.connect(uri) as websocket:

        with Api() as api:
            receive_task = asyncio.create_task(message_handler(websocket, api))
            send_task = asyncio.create_task(send_messages(websocket, api))

        await asyncio.gather(send_task, receive_task)


if __name__ == "__main__":
    asyncio.run(hello())
