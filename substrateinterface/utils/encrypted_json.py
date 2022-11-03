import base64
import json
from os import urandom

from typing import Union, Optional

from nacl.hashlib import scrypt
from nacl.secret import SecretBox
from sr25519 import pair_from_ed25519_secret_key


NONCE_LENGTH = 24
SCRYPT_LENGTH = 32 + (3 * 4)
PKCS8_DIVIDER = bytes([161, 35, 3, 33, 0])
PKCS8_HEADER = bytes([48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32])
PUB_LENGTH = 32
SALT_LENGTH = 32
SEC_LENGTH = 64
SEED_LENGTH = 32

SCRYPT_N = 1 << 15
SCRYPT_P = 1
SCRYPT_R = 8


def decode_pair_from_encrypted_json(json_data: Union[str, dict], passphrase: str) -> tuple:
    """
    Decodes encrypted PKCS#8 message from PolkadotJS JSON format

    Parameters
    ----------
    json_data
    passphrase

    Returns
    -------
    tuple containing private and public key
    """
    if type(json_data) is str:
        json_data = json.loads(json_data)

    # Check requirements
    if json_data.get('encoding', {}).get('version') != "3":
        raise ValueError("Unsupported JSON format")

    encrypted = base64.b64decode(json_data['encoded'])

    if 'scrypt' in json_data['encoding']['type']:
        salt = encrypted[0:32]
        n = int.from_bytes(encrypted[32:36], byteorder='little')
        p = int.from_bytes(encrypted[36:40], byteorder='little')
        r = int.from_bytes(encrypted[40:44], byteorder='little')

        password = scrypt(passphrase.encode(), salt, n=n, r=r, p=p, dklen=32, maxmem=2 ** 26)
        encrypted = encrypted[SCRYPT_LENGTH:]

    else:
        password = passphrase.encode().rjust(32, b'\x00')

    if "xsalsa20-poly1305" not in json_data['encoding']['type']:
        raise ValueError("Unsupported encoding type")

    nonce = encrypted[0:NONCE_LENGTH]
    message = encrypted[NONCE_LENGTH:]

    secret_box = SecretBox(key=password)
    decrypted = secret_box.decrypt(message, nonce)

    # Decode PKCS8 message
    secret_key, public_key = decode_pkcs8(decrypted)

    if 'sr25519' in json_data['encoding']['content']:
        # Secret key from PolkadotJS is an Ed25519 expanded secret key, so has to be converted
        # https://github.com/polkadot-js/wasm/blob/master/packages/wasm-crypto/src/rs/sr25519.rs#L125
        converted_public_key, secret_key = pair_from_ed25519_secret_key(secret_key)
        assert(public_key == converted_public_key)

    return secret_key, public_key


def decode_pkcs8(ciphertext: bytes) -> tuple:
    current_offset = 0

    header = ciphertext[current_offset:len(PKCS8_HEADER)]
    if header != PKCS8_HEADER:
        raise ValueError("Invalid Pkcs8 header found in body")

    current_offset += len(PKCS8_HEADER)

    secret_key = ciphertext[current_offset:current_offset + SEC_LENGTH]
    current_offset += SEC_LENGTH

    divider = ciphertext[current_offset:current_offset + len(PKCS8_DIVIDER)]

    if divider != PKCS8_DIVIDER:
        raise ValueError("Invalid Pkcs8 divider found in body")

    current_offset += len(PKCS8_DIVIDER)

    public_key = ciphertext[current_offset: current_offset + PUB_LENGTH]

    return secret_key, public_key


def encode_pkcs8(public_key: bytes, private_key: bytes) -> bytes:
    return PKCS8_HEADER + private_key + PKCS8_DIVIDER + public_key


def encode_pair(public_key: bytes, private_key: bytes, passphrase: str) -> bytes:
    """
    Encode a public/private pair to PKCS#8 format, encrypted with provided passphrase

    Parameters
    ----------
    public_key: 32 bytes public key
    private_key: 64 bytes private key
    passphrase: passphrase to encrypt the PKCS#8 message

    Returns
    -------
    (Encrypted) PKCS#8 message bytes
    """
    message = encode_pkcs8(public_key, private_key)


    salt = urandom(SALT_LENGTH)
    password = scrypt(passphrase.encode(), salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=2 ** 26)

    secret_box = SecretBox(key=password)
    message = secret_box.encrypt(message)

    scrypt_params = SCRYPT_N.to_bytes(4, 'little') + SCRYPT_P.to_bytes(4, 'little') + SCRYPT_R.to_bytes(4, 'little')

    return salt + scrypt_params + message.nonce + message.ciphertext

