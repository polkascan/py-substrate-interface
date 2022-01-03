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

import hashlib
import hmac
import struct

from ecdsa import SigningKey
from ecdsa.curves import SECP256k1
from eth_keys.datatypes import Signature
from eth_utils import to_checksum_address, keccak as eth_utils_keccak

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'
ETH_DERIVATION_PATH = "m/44'/60'/0'/0"


class PublicKey:
    def __init__(self, private_key):
        self.point = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator

    def __bytes__(self):
        xstr = self.point.x().to_bytes(32, byteorder='big')
        parity = self.point.y() & 1
        return (2 + parity).to_bytes(1, byteorder='big') + xstr

    def address(self):
        x = self.point.x()
        y = self.point.y()
        s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        return to_checksum_address(eth_utils_keccak(s)[12:])


def mnemonic_to_bip39seed(mnemonic, passphrase):
    mnemonic = bytes(mnemonic, 'utf8')
    salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code


def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & BIP32_PRIVDEV) != 0:
        key = b'\x00' + parent_key
    else:
        key = bytes(PublicKey(parent_key))
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % BIP32_CURVE.order
        if a < BIP32_CURVE.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code


def parse_derivation_path(str_derivation_path):
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(BIP32_PRIVDEV + int(i[:-1]))
        else:
            path.append(int(i))
    return path


def mnemonic_to_ecdsa_private_key(mnemonic: str, str_derivation_path: str = None, passphrase: str = "") -> bytes:

    if str_derivation_path is None:
        str_derivation_path = f'{ETH_DERIVATION_PATH}/0'

    derivation_path = parse_derivation_path(str_derivation_path)
    bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key


def ecdsa_sign(private_key: bytes, message: bytes) -> bytes:
    sk = SigningKey.from_string(
        private_key, curve=SECP256k1)
    return sk.sign(message)


def ecdsa_verify(signature: bytes, data: bytes, address: bytes) -> bool:
    signature_obj = Signature(signature)
    recovered_pubkey = signature_obj.recover_public_key_from_msg(data)
    return recovered_pubkey.to_canonical_address() == address
