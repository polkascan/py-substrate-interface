# Keypair creation and signing

Keypairs are used to sign transactions and encrypt/decrypt messages. They consist of a public/private key and can be 
generated in several ways like by a BIP39 mnemonic:

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_mnemonic(mnemonic)
signature = keypair.sign("Test123")
if keypair.verify("Test123", signature):
    print('Verified')
```

By default, a keypair is using [SR25519](https://research.web3.foundation/en/latest/polkadot/keys/1-accounts-more.html) 
cryptography, alternatively ED25519 and ECDSA (for Ethereum-style addresses) can be explicitly specified:

```python
keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ECDSA)
print(keypair.ss58_address)
# '0x6741864968e8b87c6e32e19cde88A11a3Cc636E9'
```

## Creating keypairs with soft and hard key derivation paths

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_uri(mnemonic + '//hard/soft')
```

By omitting the mnemonic the default development mnemonic is used: 

```python
keypair = Keypair.create_from_uri('//Alice')
```

## Creating ECDSA keypairs with BIP44 derivation paths 

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_uri(f"{mnemonic}/m/44'/60'/0'/0/0", crypto_type=KeypairType.ECDSA)
```

## Create Keypair from PolkadotJS JSON format

```python
with open('5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY.json', 'r') as fp:
    json_data = fp.read()
    keypair = Keypair.create_from_encrypted_json(json_data, passphrase="test", ss58_format=42)
```

## Verify generated signature with public address

_Example: Substrate style addresses_
```python
keypair = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
signature = keypair.sign('test')

keypair_public = Keypair(ss58_address='5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY', crypto_type=KeypairType.SR25519)
result = keypair_public.verify('test', signature)
```

_Example: Ethereum style addresses_
```python
keypair = Keypair.create_from_uri("/m/44'/60/0'/0", crypto_type=KeypairType.ECDSA)
signature = keypair.sign('test')

keypair_public = Keypair(public_key='0x5e20a619338338772e97aa444e001043da96a43b', crypto_type=KeypairType.ECDSA)
result = keypair_public.verify('test', signature)
```

## Offline signing of extrinsics

This example generates a signature payload which can be signed on another (offline) machine and later on sent to the 
network with the generated signature.

1. Generate signature payload on online machine:
```python
substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    ss58_format=42,
    type_registry_preset='substrate-node-template',
)

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer_keep_alive',
    call_params={
        'dest': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY',
        'value': 2 * 10**8
    }
)

era = {'period': 64, 'current': 22719}
nonce = 0

signature_payload = substrate.generate_signature_payload(call=call, era=era, nonce=nonce)
```

2. Then on another (offline) machine generate the signature with given `signature_payload`:

```python
keypair = Keypair.create_from_mnemonic("nature exchange gasp toy result bacon coin broccoli rule oyster believe lyrics")
signature = keypair.sign(signature_payload)
```

3. Finally on the online machine send the extrinsic with generated signature:

```python
keypair = Keypair(ss58_address="5EChUec3ZQhUvY1g52ZbfBVkqjUY9Kcr6mcEvQMbmd38shQL")

extrinsic = substrate.create_signed_extrinsic(
    call=call,
    keypair=keypair,
    era=era,
    nonce=nonce,
    signature=signature
)

result = substrate.submit_extrinsic(
    extrinsic=extrinsic
)

print(result.extrinsic_hash)
```
