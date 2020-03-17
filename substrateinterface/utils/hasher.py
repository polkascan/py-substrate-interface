# Python Substrate Interface
#
# Copyright 2018-2020 openAware BV (NL).
# This file is part of Polkascan.
#
# Polkascan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Polkascan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Polkascan. If not, see <http://www.gnu.org/licenses/>.

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
    return blake2b(data, digest_size=32).digest().hex()


def blake2_128(data):
    """
    Helper function to calculate a 16 bytes Blake2b hash for provided data, used as key for Substrate storage items

    Parameters
    ----------
    data

    Returns
    -------

    """
    return blake2b(data, digest_size=16).digest().hex()


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
    return "{}{}".format(blake2b(data, digest_size=16).digest().hex(), data.hex())


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

    return "{}{}".format(storage_key1.hex(), storage_key2.hex())


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

    return "{}{}".format(storage_key.hex(), data.hex())


def xxh64(data):
    storage_key = bytearray(xxhash.xxh64(data, seed=0).digest())
    storage_key.reverse()

    return "{}".format(storage_key.hex())


def identity(data):
    return data.hex()
