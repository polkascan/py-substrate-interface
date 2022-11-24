# Python Substrate Interface

[![Build Status](https://img.shields.io/github/workflow/status/polkascan/py-substrate-interface/Run%20unit%20tests)](https://github.com/polkascan/py-substrate-interface/actions?query=workflow%3A%22Run+unit+tests%22)
[![Latest Version](https://img.shields.io/pypi/v/substrate-interface.svg)](https://pypi.org/project/substrate-interface/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/substrate-interface.svg)](https://pypi.org/project/substrate-interface/)
[![License](https://img.shields.io/pypi/l/substrate-interface.svg)](https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE)


## Description
This library specializes in interfacing with a Substrate node; querying storage, composing extrinsics, 
SCALE encoding/decoding and providing additional convenience methods to deal with the features and metadata of 
the Substrate runtime.

## Table of Contents
* [Installation](#installation)
* [API reference documentation](#api-reference-documentation)
* [Initialization](#initialization) 
* [SCALE](#scale)
* [Query storage](#query-storage)
* [Using ScaleType objects](#using-scaletype-objects)
* [Call runtime APIs](#call-runtime-apis)
* [Keypair creation and signing](#keypair-creation-and-signing)
* [Creating extrinsics](#creating-extrinsics)
* [ink! contract interfacing](#ink-contract-interfacing)
* [Subscriptions](#subscriptions)
* [Cleanup and context manager](#cleanup-and-context-manager)  
* [Contact and Support](#contact-and-support)
* [License](#license)

## Installation
```bash
pip install substrate-interface
```

## API reference documentation
https://polkascan.github.io/py-substrate-interface/

## Initialization

```python
substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)
```

After connecting certain properties like `ss58_format` will be determined automatically by querying the RPC node. At 
the moment this will work for most `MetadataV14` and above runtimes like Polkadot, Kusama, Acala, Moonbeam. For 
older or runtimes under development the `ss58_format` (default 42) and other properties should be set manually. 


## SCALE
[Substrate](https://github.com/paritytech/substrate) uses a lightweight and efficient 
[encoding and decoding program](https://docs.substrate.io/reference/scale-codec/) to optimize how data is sent and 
received over the network. The program used to serialize and deserialize data is called the SCALE codec, with SCALE 
being an acronym for **S**imple **C**oncatenated **A**ggregate **L**ittle-**E**ndian.

This library utilizes [py-scale-codec](https://github.com/polkascan/py-scale-codec) for encoding and decoding SCALE, see 
[this overview](https://github.com/polkascan/py-scale-codec#examples-of-different-types) for more information how 
to encode data from Python.

## Query storage

In Substrate, any pallet can introduce new storage items that will become part of the blockchain state. These storage 
items can be simple single values, or more complex storage maps.

The runtime exposes several storage functions to query those storage items and are provided in the metadata 
(see `substrate.get_metadata_storage_function()`).

### Example

```python
result = substrate.query(
    module='System',
    storage_function='Account',
    params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T']
)

print(result.value['nonce']) #  7695
print(result.value['data']['free']) # 635278638077956496
```

### State at a specific block hash

```python
account_info = substrate.query(
    module='System',
    storage_function='Account',
    params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'],
    block_hash='0x176e064454388fd78941a0bace38db424e71db9d5d5ed0272ead7003a02234fa'
)

print(account_info['nonce'].value) #  7673
print(account_info['data']['free'].value) # 637747267365404068
```

### Type decomposition information

Some storage functions need parameters and some of those parameter types can be quite complex to compose.

To retrieve more information how to format those storage function parameters, the helper function `get_param_info()` is available:

```python
storage_function = substrate.get_metadata_storage_function("Tokens", "TotalIssuance")

print(storage_function.get_param_info())
# [{
#   'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 
#   'DexShare': ({'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16'}, {'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16'}), 
#   'Erc20': '[u8; 20]', 
#   'StableAssetPoolToken': 'u32', 
#   'LiquidCrowdloan': 'u32', 
#   'ForeignAsset': 'u16'
# }]
```

### Query a mapped storage function
Mapped storage functions can be iterated over all key/value pairs, for these type of storage functions `query_map()` 
can be used.

The result is a `QueryMapResult` object, which is an iterator:

```python
# Retrieve the first 199 System.Account entries
result = substrate.query_map('System', 'Account', max_results=199)

for account, account_info in result:
    print(f"Free balance of account '{account.value}': {account_info.value['data']['free']}")
```

These results are transparently retrieved in batches capped by the `page_size` kwarg, currently the 
maximum `page_size` restricted by the RPC node is 1000    

```python
# Retrieve all System.Account entries in batches of 200 (automatically appended by `QueryMapResult` iterator)
result = substrate.query_map('System', 'Account', page_size=200, max_results=400)

for account, account_info in result:
    print(f"Free balance of account '{account.value}': {account_info.value['data']['free']}")
```

Querying a `DoubleMap` storage function:

```python
era_stakers = substrate.query_map(
    module='Staking',
    storage_function='ErasStakers',
    params=[2100]
)
```

## Using ScaleType objects

The result of the previous storage query example is a `ScaleType` object, more specific a `Struct`. 

The nested object structure of this `account_info` object is as follows:
```
account_info = <AccountInfo(value={'nonce': <U32(value=5)>, 'consumers': <U32(value=0)>, 'providers': <U32(value=1)>, 'sufficients': <U32(value=0)>, 'data': <AccountData(value={'free': 1152921503981846391, 'reserved': 0, 'misc_frozen': 0, 'fee_frozen': 0})>})>
```

Every `ScaleType` have the following characteristics:

### Shorthand lookup of nested types

Inside the `AccountInfo` struct there are several `U32` objects that represents for example a nonce or the amount of provider, 
also another struct object `AccountData` which contains more nested types. 


To access these nested structures you can access those formally using:

`account_info.value_object['data'].value_object['free']`

As a convenient shorthand you can also use:

`account_info['data']['free']`

`ScaleType` objects can also be automatically converted to an iterable, so if the object
is for example the `others` in the result Struct of `Staking.eraStakers` can be iterated via:

```python
for other_info in era_stakers['others']:
    print(other_info['who'], other_info['value'])
```

### Serializable
Each `ScaleType` holds a complete serialized version of itself in the `account_info.serialize()` property, so it can easily store or used to create JSON strings.

So the whole result of `account_info.serialize()` will be a `dict` containing the following:

```json
{
    "nonce": 5,
    "consumers": 0,
    "providers": 1,
    "sufficients": 0,
    "data": {
        "free": 1152921503981846391,
        "reserved": 0,
        "misc_frozen": 0,
        "fee_frozen": 0
    }
}
```

### Comparing values with `ScaleType` objects

It is possible to compare ScaleType objects directly to Python primitives, internally the serialized `value` attribute
is compared:

```python
metadata_obj[1][1]['extrinsic']['version'] # '<U8(value=4)>'
metadata_obj[1][1]['extrinsic']['version'] == 4 # True
```

## Call runtime APIs

Each Substrate node contains a runtime. The runtime contains the business logic of the chain. It defines what 
transactions are valid and invalid and determines how the chain's state changes in response to transactions. 

A Runtime API facilitates this kind of communication between the outer node and the runtime. 
[More information about Runtime APIs](https://substrate.recipes/runtime-api.html)

### Example
```python
result = substrate.runtime_call("AccountNonceApi", "account_nonce", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"])
# <U32(value=2)>
```

### List of available runtime APIs and methods

```python
runtime_calls = substrate.get_metadata_runtime_call_functions()
#[
#    <RuntimeCallDefinition(value={'description': 'The API to query account nonce (aka transaction index)', 'params': [{'name': 'account_id', 'type': 'AccountId'}], 'type': 'Index', 'api': 'AccountNonceApi', 'method': 'account_nonce'})>
#    ...
#]
```

### Get param type decomposition
A helper function to compose the parameters for this runtime API call

```python
runtime_call = substrate.get_metadata_runtime_call_function("ContractsApi", "call")
param_info = runtime_call.get_param_info()
# ['AccountId', 'AccountId', 'u128', 'u64', (None, 'u128'), 'Bytes']
```

## Keypair creation and signing

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

### Creating keypairs with soft and hard key derivation paths

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_uri(mnemonic + '//hard/soft')
```

By omitting the mnemonic the default development mnemonic is used: 

```python
keypair = Keypair.create_from_uri('//Alice')
```

### Creating ECDSA keypairs with BIP44 derivation paths 

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_uri(f"{mnemonic}/m/44'/60'/0'/0/0", crypto_type=KeypairType.ECDSA)
```

### Create Keypair from PolkadotJS JSON format

```python
with open('5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY.json', 'r') as fp:
    json_data = fp.read()
    keypair = Keypair.create_from_encrypted_json(json_data, passphrase="test", ss58_format=42)
```

### Verify generated signature with public address

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

### Offline signing of extrinsics

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
    call_function='transfer',
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

## Creating extrinsics

In Substrate, transactions are often more broadly referred to as (signed) extrinsics. The term extrinsic is generally 
used to mean any information that originates outside of the runtime. An extrinsic is basically a vehicle that carries
the intention to execute a function call in the runtime, along with proof of the account that wants to execute it. 

_Example:_

```python
call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': '5E9oDs9PjpsBbxXxRE9uMaZZhnBAV38n2ouLB28oecBDdeQo',
        'value': 1 * 10**12
    }
)

extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

try:
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    print(f"Extrinsic '{receipt.extrinsic_hash}' sent and included in block '{receipt.block_hash}'")

except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
```

The `wait_for_inclusion` keyword argument used in the example above will block giving the result until it gets 
confirmation from the node that the extrinsic is succesfully included in a block. The `wait_for_finalization` keyword
will wait until extrinsic is finalized. Note this feature is only available for websocket connections.

### Extrinsic Receipts

The `substrate.submit_extrinsic()` example above returns an `ExtrinsicReceipt` object, which contains information about the on-chain 
execution of the extrinsic. Because the `block_hash` is necessary to retrieve the triggered events from storage, most
information is only available when `wait_for_inclusion=True` or `wait_for_finalization=True` is used when submitting
an extrinsic. 


Examples:
```python
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
print(receipt.is_success) # False
print(receipt.weight) # 216625000
print(receipt.total_fee_amount) # 2749998966
print(receipt.error_message['name']) # 'LiquidityRestrictions'
```

`ExtrinsicReceipt` objects can also be created for all existing extrinsics on-chain:

```python

receipt = substrate.retrieve_extrinsic_by_identifier("5233297-1")

print(receipt.is_success) # False
print(receipt.extrinsic.call_module.name) # 'Identity'
print(receipt.extrinsic.call.name) # 'remove_sub'
print(receipt.weight) # 359262000
print(receipt.total_fee_amount) # 2483332406
print(receipt.error_message['docs']) # [' Sender is not a sub-account.']

for event in receipt.triggered_events:
    print(f'* {event.value}')
```

### Multisig extrinsics
Substrate has the functionality for multi-signature dispatch, allowing multiple signed origins (accounts) to coordinate 
and dispatch a call, derivable deterministically from the set of account IDs and the threshold number of accounts from 
the set that must approve it.

To initiate and finalize multisig extrinsics, the following helper functions are available:

_Define the multisig account by supplying its signatories and threshold:_
```python
keypair_alice = Keypair.create_from_uri('//Alice', ss58_format=substrate.ss58_format)

multisig_account = substrate.generate_multisig_account(
    signatories=[
        keypair_alice.ss58_address, 
        '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty', 
        '5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y'
    ], 
    threshold=2
)
```

_Then initiate the multisig extrinsic by providing the call and a keypair of one of its signatories:_

```python
call = substrate.compose_call(
    call_module='System',
    call_function='remark_with_event',
    call_params={
        'remark': 'Multisig test'
    }
)

extrinsic = substrate.create_multisig_extrinsic(call, keypair_alice, multisig_account, era={'period': 64})
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
```

_Then a second signatory approves and finalizes the call by providing the same call to another multisig extrinsic:_

```python
# Define the multisig account by supplying its signatories and threshold
keypair_charlie = Keypair.create_from_uri('//Charlie', ss58_format=substrate.ss58_format)

multisig_account = substrate.generate_multisig_account(
    signatories=[
        keypair_charlie.ss58_address, 
        '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY', 
        '5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y'
    ], 
    threshold=2
)

extrinsic = substrate.create_multisig_extrinsic(call, keypair_charlie, multisig_account, era={'period': 64})
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
```

The call will be executed when the second and final multisig extrinsic is submitted, condition and state of the multig 
will be checked on-chain during processing of the multisig extrinsic.

### Type decomposition of call params

The structure of certain call parameters can be quite complex, then the `get_param_info()` function of the call function object
can provide more insight how to construct those parameters:

```python
call_function = substrate.get_metadata_call_function("XTokens", "transfer")

param_info = call_function.get_param_info()
# {
#   'currency_id': {
#       'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'TAP', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 
#       'DexShare': ({'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'TAP', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16', 'StableAssetPoolToken': 'u32'}, {'Token': ('ACA', 'AUSD', 'DOT', 'LDOT', 'TAP', 'RENBTC', 'CASH', 'KAR', 'KUSD', 'KSM', 'LKSM', 'TAI', 'BNC', 'VSKSM', 'PHA', 'KINT', 'KBTC'), 'Erc20': '[u8; 20]', 'LiquidCrowdloan': 'u32', 'ForeignAsset': 'u16', 'StableAssetPoolToken': 'u32'}), 
#       'Erc20': '[u8; 20]', 
#       'StableAssetPoolToken': 'u32', 
#       'LiquidCrowdloan': 'u32', 
#       'ForeignAsset': 'u16'
#   }, 
#   'amount': 'u128', 
#   'dest': {
#       'V0': {'Null': None, 'X1': {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, 'X2': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X3': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X4': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X5': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X6': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X7': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X8': ({'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parent': None, 'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}})}, 
#       'V1': {'parents': 'u8', 'interior': {'Here': None, 'X1': {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, 'X2': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X3': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X4': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X5': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X6': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X7': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}), 'X8': ({'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}}, {'Parachain': 'u32', 'AccountId32': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'id': '[u8; 32]'}, 'AccountIndex64': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'index': 'u64'}, 'AccountKey20': {'network': {'Any': None, 'Named': 'Bytes', 'Polkadot': None, 'Kusama': None}, 'key': '[u8; 20]'}, 'PalletInstance': 'u8', 'GeneralIndex': 'u128', 'GeneralKey': 'Bytes', 'OnlyChild': None, 'Plurality': {'id': {'Unit': None, 'Named': 'Bytes', 'Index': 'u32', 'Executive': None, 'Technical': None, 'Legislative': None, 'Judicial': None}, 'part': {'Voice': None, 'Members': {'count': 'u32'}, 'Fraction': {'nom': 'u32', 'denom': 'u32'}, 'AtLeastProportion': {'nom': 'u32', 'denom': 'u32'}, 'MoreThanProportion': {'nom': 'u32', 'denom': 'u32'}}}})}}
#    }, 
#   'dest_weight': 'u64'
#}
```

### Estimate of network fees

```python
payment_info = substrate.get_payment_info(call=call, keypair=keypair)
# {'class': 'normal', 'partialFee': 2499999066, 'weight': 216625000}
```

### Mortal extrinsics

By default, _immortal_ extrinsics are created, which means they have an indefinite lifetime for being included in a 
block. However, it is recommended to use specify an expiry window, so you know after a certain amount of time if the 
extrinsic is not included in a block, it will be invalidated.

```python 
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair, era={'period': 64})
```

The `period` specifies the number of blocks the extrinsic is valid counted from current head.


## ink! contract interfacing

### Deploy a contract 

Tested on [canvas-node](https://github.com/paritytech/canvas-node) with the [Flipper contract from the tutorial](https://docs.substrate.io/tutorials/smart-contracts/prepare-your-first-contract/):

```python
substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    type_registry_preset='canvas'
)

keypair = Keypair.create_from_uri('//Alice')

# Deploy contract
code = ContractCode.create_from_contract_files(
    metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
    wasm_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.wasm'),
    substrate=substrate
)

contract = code.deploy(
    keypair=keypair,
    endowment=10 ** 15,
    gas_limit=1000000000000,
    constructor="new",
    args={'init_value': True},
    upload_code=True
)

print(f'✅ Deployed @ {contract.contract_address}')
```

### Work with an existing instance:

```python
# Create contract instance from deterministic address
contract = ContractInstance.create_from_address(
    contract_address=contract_address,
    metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
    substrate=substrate
)
```

### Read data from a contract:

```python
result = contract.read(keypair, 'get')
print('Current value of "get":', result.contract_result_data)
```

### Execute a contract call

```python
 # Do a gas estimation of the message
gas_predit_result = contract.read(keypair, 'flip')

print('Result of dry-run: ', gas_predit_result.contract_result_data)
print('Gas estimate: ', gas_predit_result.gas_required)

# Do the actual call
print('Executing contract call...')
contract_receipt = contract.exec(keypair, 'flip', args={

}, gas_limit=gas_predit_result.gas_required)

if contract_receipt.is_success:
    print(f'Events triggered in contract: {contract_receipt.contract_events}')
else:
    print(f'Call failed: {contract_receipt.error_message}')
```

See complete [code example](https://github.com/polkascan/py-substrate-interface/blob/master/examples/create_and_exec_contract.py) for more details

## Subscriptions

It is possible to create subscriptions for certain data to get updates pushed as they happen. These subscriptions are 
blocking until the subscription is closed.

### Storage subscriptions

When a callable is passed as kwarg `subscription_handler` in the `query()` function, there will be a subscription 
created for given storage query. Updates will be pushed to the callable and will block execution until a final value 
is returned. This value will be returned as a result of the query and finally automatically unsubscribed from further 
updates.

```python
def subscription_handler(account_info_obj, update_nr, subscription_id):

    if update_nr == 0:
        print('Initial account data:', account_info_obj.value)

    if update_nr > 0:
        # Do something with the update
        print('Account data changed:', account_info_obj.value)

    # The execution will block until an arbitrary value is returned, which will be the result of the `query`
    if update_nr > 5:
        return account_info_obj


result = substrate.query("System", "Account", ["5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY"],
                         subscription_handler=subscription_handler)

print(result)
```

### Subscribe to new block headers

```python
def subscription_handler(obj, update_nr, subscription_id):

    print(f"New block #{obj['header']['number']} produced by {obj['author']}")

    if update_nr > 10:
        return {'message': 'Subscription will cancel when a value is returned', 'updates_processed': update_nr}


result = substrate.subscribe_block_headers(subscription_handler, include_author=True)
```

## Cleanup and context manager

At the end of the lifecycle of a `SubstrateInterface` instance, calling the `close()` method will do all the necessary 
cleanup, like closing the websocket connection.

When using the context manager this will be done automatically:

```python
with SubstrateInterface(url="wss://rpc.polkadot.io") as substrate:
    events = substrate.query("System", "Events")

# connection is now closed
```


## Contact and Support 

For questions, please see the [Substrate StackExchange](https://substrate.stackexchange.com/questions/tagged/python) or 
reach out to us on our [matrix](http://matrix.org) chat group: [Polkascan Technical](https://matrix.to/#/#polkascan:matrix.org).

## License
https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE
