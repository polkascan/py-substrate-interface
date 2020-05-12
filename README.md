# Python Substrate Interface
 
[![Travis CI Build Status](https://api.travis-ci.org/polkascan/py-substrate-interface.svg?branch=master)](https://travis-ci.org/polkascan/py-substrate-interface)
[![Latest Version](https://img.shields.io/pypi/v/substrate-interface.svg)](https://pypi.org/project/substrate-interface/) 
[![Supported Python versions](https://img.shields.io/pypi/pyversions/substrate-interface.svg)](https://pypi.org/project/substrate-interface/)
[![License](https://img.shields.io/pypi/l/substrate-interface.svg)](https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE)

Python Substrate Interface Library

## Description
This library specializes in interfacing with a Substrate node, providing additional convenience methods to deal with
SCALE encoding/decoding (the default output and input format of the Substrate JSONRPC), metadata parsing, type registry 
management and versioning of types.

## Documentation
https://polkascan.github.io/py-substrate-interface/

## Installation
```bash
pip install substrate-interface
```

## Examples

Simple example, initialize interface and get head block hash of Kusama chain:

### Initialization

```python
substrate = SubstrateInterface(
    url="wss://kusama-rpc.polkadot.io/",
    address_type=2,
    type_registry_preset='kusama'
)

substrate.get_chain_head() 
```
Note on support for wss, this is still quite limited at the moment as connections are not reused yet. Until support is
improved it is prefered to use http endpoints (e.g. http://127.0.0.1:9933)
   
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


### Make a storage call
The modules and storage functions are provided in the metadata (see `substrate.get_metadata_storage_functions()`), 
parameters will be automatically converted to SCALE-bytes (also including decoding of SS58 addresses).   

```python
balance_info = substrate.get_runtime_state(
    module='System',
    storage_function='Account',
    params=['5E9oDs9PjpsBbxXxRE9uMaZZhnBAV38n2ouLB28oecBDdeQo']
).get('result')

if balance_info:
    print("\n\nCurrent free balance: {} KSM".format(
        balance_info.get('data').get('free', 0) / 10**12
    ))
```

Or get a historic balance at a certain block hash:

```python
balance_info = substrate.get_runtime_state(
    module='System',
    storage_function='Account',
    params=['5E9oDs9PjpsBbxXxRE9uMaZZhnBAV38n2ouLB28oecBDdeQo'],
    block_hash=block_hash
).get('result')

if balance_info:
    print("\n\nFree balance @ {}: {} KSM".format(
        block_hash,
        balance_info.get('data').get('free', 0) / 10**12
    ))
```

### Create and send signed extrinsics

The following code snippet illustrates how to create a call, wrap it in an signed extrinsic and send it to the network:

```python
from substrateinterface import SubstrateInterface, SubstrateRequestException, Keypair

substrate = SubstrateInterface(
    url="http://127.0.0.1:9933",
    address_type=42,
    type_registry_preset='kusama'
)

keypair = Keypair(
    ss58_address='5HmubXCdmtEvKmvqjJ7fXkxhPXcg6JTS62kMMphqxpEE6zcG',
    public_key='0xfc99becc4334e76e75d2e3bd3be759728b843c53954f1cada66ae9f6da97ab54',
    private_key='0x8bb70006b5ca74fc1f26afaab8c65b6dc3c8fe9983c2c99880e5ffb74d1dcb09d8784e4a1befd363b34ac6bad337fa75dee8e4373914aa10d0263aefe04346dd',
    suri='episode together nose spoon dose oil faculty zoo ankle evoke admit walnut'
)

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
    extrinsic_hash = substrate.send_extrinsic(extrinsic)
    print("Extrinsic sent: {}".format(extrinsic_hash))

except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))

```

Py-substrate-interface makes it also possible to easily interprete changed types and historic runtimes. As an example
we create an (not very useful) historic call of a module that has been removed later on: retrieval of historic metadata and 
apply the correct version of types in the type registry is all done automatically. Because parsing of metadata and 
type registry is quite heavy, the result will be cached per runtime id. In the future there could be support for 
caching backends like Redis to make this cache more persistent.

Create an unsigned extrinsic of a module that was removed by providing block hash:

```python
payload = substrate.compose_call(
    call_module='Nicks',
    call_function='clear_name',
    call_params={},
    block_hash="0x918107632d7994d50f3661db3af353d2aa378f696e47a393bab573f63f7d6c3a"
)
```

## License
https://github.com/polkascan/py-substrate-interface/blob/master/LICENSE
