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

""" Helper functions used to calculate keys for Substrate storage items
"""

from hashlib import blake2b
import xxhash


def blake2_256(data):
    """
    Helper function to calculate a 32 bytes Blake2b hash for provided data, used as key for Substrate storage items

    Parameters
    ----------
    data

    Returns
    -------

    """
    return blake2b(data, digest_size=32).digest()


def blake2_128(data):
    """
    Helper function to calculate a 16 bytes Blake2b hash for provided data, used as key for Substrate storage items

    Parameters
    ----------
    data

    Returns
    -------

    """
    return blake2b(data, digest_size=16).digest()


def blake2_128_concat(data):
    """
    Helper function to calculate a 16 bytes Blake2b hash for provided data, concatenated with data, used as key
    for Substrate storage items

    Parameters
    ----------
    data

    Returns
    -------

    """
    return blake2b(data, digest_size=16).digest() + data


def xxh128(data):
    """
    Helper function to calculate a 2 concatenated xxh64 hash for provided data, used as key for several Substrate

    Parameters
    ----------
    data

    Returns
    -------

    """
    storage_key1 = bytearray(xxhash.xxh64(data, seed=0).digest())
    storage_key1.reverse()

    storage_key2 = bytearray(xxhash.xxh64(data, seed=1).digest())
    storage_key2.reverse()

    return storage_key1 + storage_key2


def two_x64_concat(data):
    """
    Helper function to calculate a xxh64 hash with concatenated data for provided data,
    used as key for several Substrate

    Parameters
    ----------
    data

    Returns
    -------

    """
    storage_key = bytearray(xxhash.xxh64(data, seed=0).digest())
    storage_key.reverse()

    return storage_key + data


def xxh64(data):
    storage_key = bytearray(xxhash.xxh64(data, seed=0).digest())
    storage_key.reverse()

    return storage_key


def identity(data):
    return data


def concat_hash_len(key_hasher: str) -> int:
    if key_hasher == "Blake2_128Concat":
        return 16
    elif key_hasher == "Twox64Concat":
        return 8
    elif key_hasher == "Identity":
        return 0
    else:
        raise ValueError('Unsupported hash type')
