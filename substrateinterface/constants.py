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

STORAGE_HASH_SYSTEM_EVENTS = "0xcc956bdb7605e3547539f321ac2bc95c"
STORAGE_HASH_SYSTEM_EVENTS_V9 = "0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7"

DEV_PHRASE = 'bottom drive obey lake curtain smoke basket hold race lonely fit walk'

WELL_KNOWN_STORAGE_KEYS = {
    "Code": {
        "storage_key": "0x3a636f6465",
        "value_type_string": "RawBytes",
        "docs": "Wasm code of the runtime",
        "default": '0x'
    },
    "HeapPages": {
        "storage_key": "0x3a686561707061676573",
        "value_type_string": "u64",
        "docs": "Number of wasm linear memory pages required for execution of the runtime.",
        "default": "0x0000000000000000"
    },
    "ExtrinsicIndex": {
        "storage_key": "0x3a65787472696e7369635f696e646578",
        "value_type_string": "u32",
        "docs": "Number of wasm linear memory pages required for execution of the runtime.",
        "default": "0x00000000"
    },
}
