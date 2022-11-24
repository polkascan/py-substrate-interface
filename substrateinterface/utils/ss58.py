# Python Substrate Interface Library
#
# Copyright 2018-2021 Stichting Polkascan (Polkascan Foundation).
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
#
#  ss58.py

""" SS58 is a simple address format designed for Substrate based chains.
    Encoding/decoding according to specification on
    https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)

"""
from scalecodec.utils.ss58 import ss58_decode, ss58_encode, ss58_decode_account_index, ss58_encode_account_index, \
    is_valid_ss58_address, get_ss58_format


ss58_decode = ss58_decode
ss58_encode = ss58_encode
ss58_decode_account_index = ss58_decode_account_index
ss58_encode_account_index = ss58_encode_account_index
is_valid_ss58_address = is_valid_ss58_address
get_ss58_format = get_ss58_format
