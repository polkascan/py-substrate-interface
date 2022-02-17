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
* [Initialization](#initialization)
  * [Autodiscover mode](#autodiscover-mode)
  * [Manually set required properties](#manually-set-required-properties)  
  * [Substrate Node Template](#substrate-node-template)
* [Features](#features)
  * [Get extrinsics for a certain block](#retrieve-extrinsics-for-a-certain-block)
  * [Subscribe to new block headers](#subscribe-to-new-block-headers)
  * [Storage queries](#storage-queries)
  * [Storage subscriptions](#storage-subscriptions)
  * [Query a mapped storage function](#query-a-mapped-storage-function)
  * [Create and send signed extrinsics](#create-and-send-signed-extrinsics)
  * [Examining the ExtrinsicReceipt object](#examining-the-extrinsicreceipt-object)
  * [ink! contract interfacing](#ink-contract-interfacing)
  * [Create mortal extrinsics](#create-mortal-extrinsics)
  * [Keypair creation and signing](#keypair-creation-and-signing)
  * [Creating keypairs with soft and hard key derivation paths](#creating-keypairs-with-soft-and-hard-key-derivation-paths)
  * [Creating ECDSA keypairs with BIP44 derivation paths](#creating-ecdsa-keypairs-with-bip44-derivation-paths)
  * [Getting estimate of network fees for extrinsic in advance](#getting-estimate-of-network-fees-for-extrinsic-in-advance)
  * [Offline signing of extrinsics](#offline-signing-of-extrinsics)
  * [Accessing runtime constants](#accessing-runtime-constants)
* [Keeping type registry presets up to date](#keeping-type-registry-presets-up-to-date)
* [Cleanup and context manager](#cleanup-and-context-manager)  
* [Contact and Support](#contact-and-support)
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

At the moment this will work for most `MetadataV14` and above chains like Polkadot, Kusama, Acala, Moonbeam, for other 
chains the `ss58_format` (default 42) and  `type_registry` (defaults to the latest vanilla Substrate types) should be 
set manually. 

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

Rococo

```python
substrate = SubstrateInterface(
    url="wss://rococo-rpc.polkadot.io",
    ss58_format=42,
    type_registry_preset='rococo'
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
    url="ws://127.0.0.1:9944",
    ss58_format=42,
    type_registry_preset='substrate-node-template'
)
 
```

## Features

### Retrieve extrinsics for a certain block 

#### Method 1: access serialized value

```python
# Set block_hash to None for chaintip
block_hash = "0x51d15792ff3c5ee9c6b24ddccd95b377d5cccc759b8e76e5de9250cf58225087"

# Retrieve extrinsics in block
result = substrate.get_block(block_hash=block_hash)

for extrinsic in result['extrinsics']:

    if 'address' in extrinsic.value:
        signed_by_address = extrinsic.value['address']
    else:
        signed_by_address = None

    print('\nPallet: {}\nCall: {}\nSigned by: {}'.format(
        extrinsic.value["call"]["call_module"],
        extrinsic.value["call"]["call_function"],
        signed_by_address
    ))

    # Loop through call params
    for param in extrinsic.value["call"]['call_args']:

        if param['type'] == 'Balance':
            param['value'] = '{} {}'.format(param['value'] / 10 ** substrate.token_decimals, substrate.token_symbol)

        print("Param '{}': {}".format(param['name'], param['value']))
```

#### Method 2: access nested objects

```python
# Set block_hash to None for chaintip
block_hash = "0x51d15792ff3c5ee9c6b24ddccd95b377d5cccc759b8e76e5de9250cf58225087"

# Retrieve extrinsics in block
result = substrate.get_block(block_hash=block_hash)

for extrinsic in result['extrinsics']:

    if 'address' in extrinsic:
        signed_by_address = extrinsic['address'].value
    else:
        signed_by_address = None

    print('\nPallet: {}\nCall: {}\nSigned by: {}'.format(
        extrinsic["call"]["call_module"].name,
        extrinsic["call"]["call_function"].name,
        signed_by_address
    ))

    # Loop through call params
    for param in extrinsic["call"]['call_args']:

        if param['type'] == 'Balance':
            param['value'] = '{} {}'.format(param['value'] / 10 ** substrate.token_decimals, substrate.token_symbol)

        print("Param '{}': {}".format(param['name'], param['value']))
```

### Subscribe to new block headers

```python
def subscription_handler(obj, update_nr, subscription_id):

    print(f"New block #{obj['header']['number']} produced by {obj['author']}")

    if update_nr > 10:
        return {'message': 'Subscription will cancel when a value is returned', 'updates_processed': update_nr}


result = substrate.subscribe_block_headers(subscription_handler, include_author=True)
```

### Storage queries
The modules and storage functions are provided in the metadata (see `substrate.get_metadata_storage_functions()`),
parameters will be automatically converted to SCALE-bytes (also including decoding of SS58 addresses).

#### Example 

```python
result = substrate.query(
    module='System',
    storage_function='Account',
    params=['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T']
)

print(result.value['nonce']) #  7695
print(result.value['data']['free']) # 635278638077956496
```

#### Get the account info at a specific block hash:

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

#### Type information about how to format parameters

To retrieve more information about how to format the parameters of a storage function:

```python
storage_function = self.substrate.get_metadata_storage_function("Tokens", "TotalIssuance")

print(storage_function.get_param_info())
# [{'variant': {'variants': [{'name': 'Token', 'fields': [{'name': None, 'type': 44, 'typeName': 'TokenSymbol', 'docs': []}], 'index': 0, 'docs': [], 'value': {'variant': {'variants': [{'name': 'ACA', 'fields': [], 'index': 0, 'docs': []}, {'name': 'AUSD', 'fields': [], 'index': 1, 'docs': []}, {'name': 'DOT', 'fields': [], 'index': 2, 'docs': []}, {'name': 'LDOT', 'fields': [], 'index': 3, 'docs': []}, {'name': 'RENBTC', 'fields': [], 'index': 20, 'docs': []}, {'name': 'CASH', 'fields': [], 'index': 21, 'docs': []}, {'name': 'KAR', 'fields': [], 'index': 128, 'docs': []}, {'name': 'KUSD', 'fields': [], 'index': 129, 'docs': []}, {'name': 'KSM', 'fields': [], 'index': 130, 'docs': []}, {'name': 'LKSM', 'fields': [], 'index': 131, 'docs': []}, {'name': 'TAI', 'fields': [], 'index': 132, 'docs': []}, {'name': 'BNC', 'fields': [], 'index': 168, 'docs': []}, {'name': 'VSKSM', 'fields': [], 'index': 169, 'docs': []}, {'name': 'PHA', 'fields': [], 'index': 170, 'docs': []}, {'name': 'KINT', 'fields': [], 'index': 171, 'docs': []}, {'name': 'KBTC', 'fields': [], 'index': 172, 'docs': []}]}}}, {'name': 'DexShare', 'fields': [{'name': None, 'type': 45, 'typeName': 'DexShare', 'docs': []}, {'name': None, 'type': 45, 'typeName': 'DexShare', 'docs': []}], 'index': 1, 'docs': [], 'value': {'variant': {'variants': [{'name': 'Token', 'fields': [{'name': None, 'type': 44, 'typeName': 'TokenSymbol', 'docs': []}], 'index': 0, 'docs': [], 'value': {'variant': {'variants': [{'name': 'ACA', 'fields': [], 'index': 0, 'docs': []}, {'name': 'AUSD', 'fields': [], 'index': 1, 'docs': []}, {'name': 'DOT', 'fields': [], 'index': 2, 'docs': []}, {'name': 'LDOT', 'fields': [], 'index': 3, 'docs': []}, {'name': 'RENBTC', 'fields': [], 'index': 20, 'docs': []}, {'name': 'CASH', 'fields': [], 'index': 21, 'docs': []}, {'name': 'KAR', 'fields': [], 'index': 128, 'docs': []}, {'name': 'KUSD', 'fields': [], 'index': 129, 'docs': []}, {'name': 'KSM', 'fields': [], 'index': 130, 'docs': []}, {'name': 'LKSM', 'fields': [], 'index': 131, 'docs': []}, {'name': 'TAI', 'fields': [], 'index': 132, 'docs': []}, {'name': 'BNC', 'fields': [], 'index': 168, 'docs': []}, {'name': 'VSKSM', 'fields': [], 'index': 169, 'docs': []}, {'name': 'PHA', 'fields': [], 'index': 170, 'docs': []}, {'name': 'KINT', 'fields': [], 'index': 171, 'docs': []}, {'name': 'KBTC', 'fields': [], 'index': 172, 'docs': []}]}}}, {'name': 'Erc20', 'fields': [{'name': None, 'type': 46, 'typeName': 'EvmAddress', 'docs': []}], 'index': 1, 'docs': [], 'value': {'composite': {'fields': [{'name': None, 'type': 47, 'typeName': '[u8; 20]', 'docs': [], 'value': {'array': {'len': 20, 'type': 2, 'value': {'primitive': 'u8'}}}}]}}}, {'name': 'LiquidCrowdloan', 'fields': [{'name': None, 'type': 4, 'typeName': 'Lease', 'docs': []}], 'index': 2, 'docs': [], 'value': {'primitive': 'u32'}}, {'name': 'ForeignAsset', 'fields': [{'name': None, 'type': 36, 'typeName': 'ForeignAssetId', 'docs': []}], 'index': 3, 'docs': [], 'value': {'primitive': 'u16'}}]}}}, {'name': 'Erc20', 'fields': [{'name': None, 'type': 46, 'typeName': 'EvmAddress', 'docs': []}], 'index': 2, 'docs': [], 'value': {'composite': {'fields': [{'name': None, 'type': 47, 'typeName': '[u8; 20]', 'docs': [], 'value': {'array': {'len': 20, 'type': 2, 'value': {'primitive': 'u8'}}}}]}}}, {'name': 'StableAssetPoolToken', 'fields': [{'name': None, 'type': 4, 'typeName': 'StableAssetPoolId', 'docs': []}], 'index': 3, 'docs': [], 'value': {'primitive': 'u32'}}, {'name': 'LiquidCrowdloan', 'fields': [{'name': None, 'type': 4, 'typeName': 'Lease', 'docs': []}], 'index': 4, 'docs': [], 'value': {'primitive': 'u32'}}, {'name': 'ForeignAsset', 'fields': [{'name': None, 'type': 36, 'typeName': 'ForeignAssetId', 'docs': []}], 'index': 5, 'docs': [], 'value': {'primitive': 'u16'}}]}}]
```

The `query_map()` function can also be used to see examples of used parameters:

```python
result = substrate.query_map("Tokens", "TotalIssuance")

print(list(result))
# [[<scale_info::43(value={'DexShare': ({'Token': 'KSM'}, {'Token': 'LKSM'})})>, <U128(value=11513623028320124)>], [<scale_info::43(value={'DexShare': ({'Token': 'KUSD'}, {'Token': 'BNC'})})>, <U128(value=2689948474603237982)>], [<scale_info::43(value={'DexShare': ({'Token': 'KSM'}, {'ForeignAsset': 0})})>, <U128(value=5285939253205090)>], [<scale_info::43(value={'Token': 'VSKSM'})>, <U128(value=273783457141483)>], [<scale_info::43(value={'DexShare': ({'Token': 'KAR'}, {'Token': 'KSM'})})>, <U128(value=1175872380578192993)>], [<scale_info::43(value={'DexShare': ({'Token': 'KUSD'}, {'Token': 'KSM'})})>, <U128(value=3857629383220790030)>], [<scale_info::43(value={'DexShare': ({'Token': 'KUSD'}, {'ForeignAsset': 0})})>, <U128(value=494116000924219532)>], [<scale_info::43(value={'Token': 'KSM'})>, <U128(value=77261320750464113)>], [<scale_info::43(value={'Token': 'TAI'})>, <U128(value=10000000000000000000)>], [<scale_info::43(value={'Token': 'LKSM'})>, <U128(value=681009957030687853)>], [<scale_info::43(value={'DexShare': ({'Token': 'KUSD'}, {'Token': 'LKSM'})})>, <U128(value=4873824439975242272)>], [<scale_info::43(value={'Token': 'KUSD'})>, <U128(value=5799665835441836111)>], [<scale_info::43(value={'ForeignAsset': 0})>, <U128(value=2319784932899895)>], [<scale_info::43(value={'DexShare': ({'Token': 'KAR'}, {'Token': 'LKSM'})})>, <U128(value=635158183535133903)>], [<scale_info::43(value={'Token': 'BNC'})>, <U128(value=1163757660576711961)>]]
```

### Using ScaleType objects

The result of the previous storage query example is a `ScaleType` object, more specific a `Struct`. 

The nested object structure of this `account_info` object is as follows:
```
account_info = <AccountInfo(value={'nonce': <U32(value=5)>, 'consumers': <U32(value=0)>, 'providers': <U32(value=1)>, 'sufficients': <U32(value=0)>, 'data': <AccountData(value={'free': 1152921503981846391, 'reserved': 0, 'misc_frozen': 0, 'fee_frozen': 0})>})>
```

Every `ScaleType` have the following characteristics:

#### Shorthand lookup of nested types

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

#### Serializable
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

#### Comparing values with `ScaleType` objects

It is possible to compare ScaleType objects directly to Python primitives, internally the serialized `value` attribute
is compared:

```python
metadata_obj[1][1]['extrinsic']['version'] # '<U8(value=4)>'
metadata_obj[1][1]['extrinsic']['version'] == 4 # True
```

### Storage subscriptions

When a callable is passed as kwarg `subscription_handler`, there will be a subscription created for given storage query. 
Updates will be pushed to the callable and will block execution until a final value is returned. This value will be returned
as a result of the query and finally automatically unsubscribed from further updates.

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

### Query a mapped storage function
Mapped storage functions can be iterated over all key/value pairs, for these type of storage functions `query_map` 
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

### Create and send signed extrinsics

The following code snippet illustrates how to create a call, wrap it in a signed extrinsic and send it to the network:

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

receipt = ExtrinsicReceipt.create_from_extrinsic_identifier(
    substrate=substrate, extrinsic_identifier="5233297-1"
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

Tested on [canvas-node](https://github.com/paritytech/canvas-node) with the [Flipper contract from the tutorial](https://substrate.dev/substrate-contracts-workshop/#/0/deploy-contract)_:

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

#### Work with an existing instance:

```python
# Create contract instance from deterministic address
contract = ContractInstance.create_from_address(
    contract_address=contract_address,
    metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
    substrate=substrate
)
```

#### Read data from a contract:

```python
result = contract.read(keypair, 'get')
print('Current value of "get":', result.contract_result_data)
```

#### Execute a contract call

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

By default, a keypair is using SR25519 cryptography, alternatively ED25519 and ECDSA can be explicitly specified:

```python
keypair = Keypair.create_from_mnemonic(mnemonic, crypto_type=KeypairType.ECDSA)
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

print(result.extrinsic_hash)
```

### Accessing runtime constants
All runtime constants are provided in the metadata (see `substrate.get_metadata_constants()`),
to access these as a decoded `ScaleType` you can use the function `substrate.get_constant()`:

```python

constant = substrate.get_constant("Balances", "ExistentialDeposit")

print(constant.value) # 10000000000
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

## Keeping type registry presets up to date

> :information_source: Only applicable for chains with metadata < V14

When on-chain runtime upgrades occur, types used in call- or storage functions can be added or modified. Therefore it is
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

## Contact and Support 

For questions, please reach out to us on our [matrix](http://matrix.org) chat group: [Polkascan Technical](https://matrix.to/#/#polkascan:matrix.org).

## License
https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE
