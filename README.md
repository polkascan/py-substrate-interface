# Python Substrate Interface

[![Build Status](https://img.shields.io/github/workflow/status/polkascan/py-substrate-interface/Run%20unit%20tests)](https://github.com/polkascan/py-substrate-interface/actions?query=workflow%3A%22Run+unit+tests%22)
[![Latest Version](https://img.shields.io/pypi/v/substrate-interface.svg)](https://pypi.org/project/substrate-interface/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/substrate-interface.svg)](https://pypi.org/project/substrate-interface/)
[![License](https://img.shields.io/pypi/l/substrate-interface.svg)](https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE)

Python Substrate Interface Library

## Description
This library specializes in interfacing with a Substrate node, providing additional convenience methods to deal with
SCALE encoding/decoding (the default output and input format of the Substrate JSONRPC), metadata parsing, type registry
management and versioning of types.

## Table of Contents

* [Documentation](#documentation)
* [Installation](#installation)
* [Initialization](#hello-world--the-flipper)
  * [Autodiscover mode](#autodiscover-mode)
  * [Manually set required properties](#manually-set-required-properties)  
  * [Substrate Node Template](#substrate-node-template)
* [Features](#features)
  * [Storage queries](#storage-queries)
  * [Create and send signed extrinsics](#create-and-send-signed-extrinsics)
  * [Examining the ExtrinsicReceipt object](#examining-the-extrinsicreceipt-object)
  * [ink! contract interfacing](#ink-contract-interfacing)
  * [Create mortal extrinsics](#create-mortal-extrinsics)
  * [Keypair creation and signing](#keypair-creation-and-signing)
  * [Creating keypairs with soft and hard key derivation paths](#creating-keypairs-with-soft-and-hard-key-derivation-paths)
  * [Getting estimate of network fees for extrinsic in advance](#getting-estimate-of-network-fees-for-extrinsic-in-advance)
  * [Offline signing of extrinsics](#offline-signing-of-extrinsics)
  * [Get extrinsics for a certain block](#get-extrinsics-for-a-certain-block)
* [Keeping type registry presets up to date](#keeping-type-registry-presets-up-to-date)  
* [License](#license)

## Documentation
https://polkascan.github.io/py-substrate-interface/

## Installation
```bash
pip install substrate-interface
```

## Initialization

The following examples show how to initialize for supported chains:

### Autodiscover mode

```python
substrate = SubstrateInterface(
    url="wss://rpc.polkadot.io"
)
```

When only an `url` is provided, it tries to determine certain properties like `ss58_format` and 
`type_registry_preset` automatically by calling the RPC method `system_properties`. 

At the moment this will work for Polkadot, Kusama, Kulupu and Westend nodes, for other chains the `ss58_format` 
(default 42) and  `type_registry` (defaults to latest vanilla Substrate types) should be set manually. 

### Manually set required properties

Polkadot

```python
substrate = SubstrateInterface(
    url="wss://rpc.polkadot.io",
    ss58_format=0,
    type_registry_preset='polkadot'
)
```

Kusama

```python
substrate = SubstrateInterface(
    url="wss://kusama-rpc.polkadot.io/",
    ss58_format=2,
    type_registry_preset='kusama'
)
```

Kulupu

```python
substrate = SubstrateInterface(
    url="wss://rpc.kulupu.corepaper.org/ws",
    ss58_format=16,
    type_registry_preset='kulupu'
)
```

Westend

```python
substrate = SubstrateInterface(
    url="wss://westend-rpc.polkadot.io",
    ss58_format=42,
    type_registry_preset='westend'
)
```

### Substrate Node Template
Compatible with https://github.com/substrate-developer-hub/substrate-node-template 

```python
substrate = SubstrateInterface(
    url="http://127.0.0.1:9933",
    ss58_format=42,
    type_registry_preset='substrate-node-template'
)
 
```

If custom types are introduced in the Substrate chain, the following example will add compatibility by creating a custom type 
registry JSON file and including this during initialization:

```json
{
  "runtime_id": 2,
  "types": {
    "MyCustomInt": "u32",
    "MyStruct": {
      "type": "struct",
      "type_mapping": [
         ["account", "AccountId"],
         ["message", "Vec<u8>"]
      ]
    }
  },
  "versioning": [
  ]
}
```

```python
custom_type_registry = load_type_registry_file("my-custom-types.json")

substrate = SubstrateInterface(
    url="http://127.0.0.1:9933",
    ss58_format=42,
    type_registry_preset='substrate-node-template',
    type_registry=custom_type_registry
)
 
```

## Features

### Storage queries
The modules and storage functions are provided in the metadata (see `substrate.get_metadata_storage_functions()`),
parameters will be automatically converted to SCALE-bytes (also including decoding of SS58 addresses).

Example: 

```python
result = substrate.query(
    module='System',
    storage_function='Account',
    params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T']
)

print(result.value['nonce']) #  7695
print(result.value['data']['free']) # 635278638077956496
```

Or get the account info at a specific block hash:

```python
account_info = substrate.query(
    module='System',
    storage_function='Account',
    params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'],
    block_hash='0x176e064454388fd78941a0bace38db424e71db9d5d5ed0272ead7003a02234fa'
)

print(account_info.value['nonce']) #  7673
print(account_info.value['data']['free']) # 637747267365404068
```

Or get all the key pairs of a map:

```python
# Get all the stash and controller bondings.
all_bonded_stash_ctrls = substrate.iterate_map(
    module='Staking',
    storage_function='Bonded',
    block_hash=block_hash
)
```

### Create and send signed extrinsics

The following code snippet illustrates how to create a call, wrap it in an signed extrinsic and send it to the network:

```python
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    ss58_format=42,
    type_registry_preset='kusama'
)

keypair = Keypair.create_from_mnemonic('episode together nose spoon dose oil faculty zoo ankle evoke admit walnut')

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
    print("Extrinsic '{}' sent and included in block '{}'".format(receipt.extrinsic_hash, receipt.block_hash))

except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
```

The `wait_for_inclusion` keyword argument used in the example above will block giving the result until it gets 
confirmation from the node that the extrinsic is succesfully included in a block. The `wait_for_finalization` keyword
will wait until extrinsic is finalized. Note this feature is only available for websocket connections. 

### Examining the ExtrinsicReceipt object

The `substrate.submit_extrinsic` example above returns an `ExtrinsicReceipt` object, which contains information about the on-chain 
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

receipt = ExtrinsicReceipt(
    substrate=substrate,
    extrinsic_hash="0x56fea3010910bd8c0c97253ffe308dc13d1613b7e952e7e2028257d2b83c027a",
    block_hash="0x04fb003f8bc999eeb284aa8e74f2c6f63cf5bd5c00d0d0da4cd4d253a643e4c9"
)

print(receipt.is_success) # False
print(receipt.extrinsic.call_module.name) # 'Identity'
print(receipt.extrinsic.call.name) # 'remove_sub'
print(receipt.weight) # 359262000
print(receipt.total_fee_amount) # 2483332406
print(receipt.error_message['docs']) # [' Sender is not a sub-account.']

for event in receipt.triggered_events:
    print(f'* {event.value}')
```

### ink! contract interfacing

#### Deploy a contract 

_Tested on [Substrate 2.0.0-533bbbd](https://github.com/paritytech/substrate/tree/533bbbd2315d55906a6dac5726a722e094656d52) and [canvas-node](https://github.com/paritytech/canvas-node) with the [ERC20 contract from the tutorial](https://substrate.dev/substrate-contracts-workshop/#/2/introduction)_:

```python
substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
)

keypair = Keypair.create_from_uri('//Alice')

# Upload WASM code
code = ContractCode.create_from_contract_files(
    metadata_file=os.path.join(os.path.dirname(__file__), 'erc20.json'),
    wasm_file=os.path.join(os.path.dirname(__file__), 'erc20.wasm'),
    substrate=substrate
)

receipt = code.upload_wasm(keypair)

if receipt.is_success:
    print('* Contract WASM Uploaded')

    for event in receipt.triggered_events:
        print(f'* {event.value}')

    # Deploy contract
    contract = code.deploy(
        keypair=keypair, endowment=10 ** 15, gas_limit=1000000000000,
        constructor="new",
        args={'initial_supply': 1000 * 10 ** 15}
    )

    print(f'Deployed @ {contract.contract_address}')

else:
    print(f'Failed: {receipt.error_message}')
```

#### Work with an existing instance:

```python
contract = ContractInstance.create_from_address(
    contract_address="5FV9cnzFc2tDrWcDkmoup7VZWpH9HrTaw8STnWpAQqT7KvUK",
    metadata_file=os.path.join(os.path.dirname(__file__), 'erc20.json'),
    substrate=substrate
)
```

#### Read data from a contract:

```python
result = contract.read(keypair, 'total_supply')
print('Total supply:', result.contract_result_data)
# Total supply: 1000000000000000000

result = contract.read(keypair, 'balance_of', args={'owner': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'})
print('Balance:', result.value)
# Balance: {'success': {'data': 994000000000000000, 'flags': 0, 'gas_consumed': 7251500000}}
```

#### Execute a contract call

```python
# Do a dry run of the transfer
gas_predit_result = contract.read(keypair, 'transfer', args={
    'to': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
    'value': 6 * 1000000000000000,
})

print('Result of dry-run: ', gas_predit_result.contract_result_data)
# Result of dry-run:  {'Ok': None}

print('Gas estimate: ', gas_predit_result.gas_consumed)
# Gas estimate:  24091000000

# Do the actual transfer
contract_receipt = contract.exec(keypair, 'transfer', args={
    'to': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
    'value': 6 * 1000000000000000,
}, gas_limit=gas_predit_result.gas_consumed)

if contract_receipt.is_success:
    print('Transfer success, triggered contract event:')

    for contract_event in contract_receipt.contract_events:
        print(f'* {contract_event.value}')
        # {'name': 'Transfer', 'docs': [' Event emitted when a token transfer occurs.'], 'args': [ ... ] }

    print('All triggered events:')
    for event in contract_receipt.triggered_events:
        print(f'* {event.value}')
else:
    print('ERROR: ', contract_receipt.error_message)
```


### Create mortal extrinsics

By default, _immortal_ extrinsics are created, which means they have an indefinite lifetime for being included in a 
block. However, it is recommended to use specify an expiry window, so you know after a certain amount of time if the 
extrinsic is not included in a block, it will be invalidated.

```python 
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair, era={'period': 64})
```

The `period` specifies the number of blocks the extrinsic is valid counted from current head.


### Keypair creation and signing

```python
mnemonic = Keypair.generate_mnemonic()
keypair = Keypair.create_from_mnemonic(mnemonic)
signature = keypair.sign("Test123")
if keypair.verify("Test123", signature):
    print('Verified')
```

By default, a keypair is using SR25519 cryptography, alternatively ED25519 can be explictly specified:

```python
keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ED25519)
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

### Getting estimate of network fees for extrinsic in advance

```python
keypair = Keypair(ss58_address="EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk")

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
        'value': 2 * 10 ** 3
    }
)
payment_info = substrate.get_payment_info(call=call, keypair=keypair)
# {'class': 'normal', 'partialFee': 2499999066, 'weight': 216625000}
```

### Offline signing of extrinsics

This example generates a signature payload which can be signed on another (offline) machine and later on sent to the 
network with the generated signature.

- Generate signature payload on online machine:
```python
substrate = SubstrateInterface(
    url="http://127.0.0.1:9933",
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

- Then on another (offline) machine generate the signature with given `signature_payload`:

```python
keypair = Keypair.create_from_mnemonic("nature exchange gasp toy result bacon coin broccoli rule oyster believe lyrics")
signature = keypair.sign(signature_payload)
```

- Finally on the online machine send the extrinsic with generated signature:

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

print(result['extrinsic_hash'])
```

### Get extrinsics for a certain block

```python
# Set block_hash to None for chaintip
block_hash = "0x588930468212316d8a75ede0bec0bc949451c164e2cea07ccfc425f497b077b7"

# Retrieve extrinsics in block
result = substrate.get_runtime_block(block_hash=block_hash)

for extrinsic in result['block']['extrinsics']:

    if 'account_id' in extrinsic:
        signed_by_address = ss58_encode(address=extrinsic['account_id'], address_type=2)
    else:
        signed_by_address = None

    print('\nModule: {}\nCall: {}\nSigned by: {}'.format(
        extrinsic['call_module'],
        extrinsic['call_function'],
        signed_by_address
    ))

    # Loop through params
    for param in extrinsic['params']:

        if param['type'] == 'Address':
            param['value'] = ss58_encode(address=param['value'], address_type=2)

        if param['type'] == 'Compact<Balance>':
            param['value'] = '{} DOT'.format(param['value'] / 10**12)

        print("Param '{}': {}".format(param['name'], param['value']))
```
## Keeping type registry presets up to date

When on-chain runtime upgrades occur, types used in call- or storage functions can be added or modified. Therefor it is
important to keep the type registry presets up to date, otherwise this can lead to decoding errors like 
`RemainingScaleBytesNotEmptyException`. 

At the moment the type registry presets for Polkadot, Kusama, Rococo and
Westend are being actively maintained for this library, and a check and update procedure can be triggered with:
 
```python
substrate.reload_type_registry()
```

This will also activate the updated preset for the current instance.

It is also possible to always use 
the remote type registry preset from Github with the `use_remote_preset` kwarg when instantiating:

```python
substrate = SubstrateInterface(
    url="wss://rpc.polkadot.io",
    ss58_format=0,
    type_registry_preset='polkadot',
    use_remote_preset=True
)
```

To check for updates after instantiating the `substrate` object, using `substrate.reload_type_registry()` will download 
the most recent type registry preset from Github and apply changes to current object.  

## License
https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE
