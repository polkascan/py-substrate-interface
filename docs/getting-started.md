## Installation
```bash
pip install substrate-interface
```

## Initialization

```python
substrate = SubstrateInterface(url="ws://127.0.0.1:9944")
```

After connecting certain properties like `ss58_format` will be determined automatically by querying the RPC node. At 
the moment this will work for most `MetadataV14` and above runtimes like Polkadot, Kusama, Acala, Moonbeam. For 
older or runtimes under development the `ss58_format` (default 42) and other properties should be set manually. 

## Quick usage

### Balance information of an account
```python
result = substrate.query('System', 'Account', ['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'])
print(result.value['data']['free']) # 635278638077956496
```
### Create balance transfer extrinsic

```python
call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': '5E9oDs9PjpsBbxXxRE9uMaZZhnBAV38n2ouLB28oecBDdeQo',
        'value': 1 * 10**12
    }
)
keypair = Keypair.create_from_uri('//Alice')
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

print(f"Extrinsic '{receipt.extrinsic_hash}' sent and included in block '{receipt.block_hash}'")
```

## Common concepts

### SS58 address formatting

SS58 is a simple address format designed for Substrate based chains. For more information about its specification 
see the [Substrate documentation about SS58](https://docs.substrate.io/reference/address-formats/) 

### SCALE
Substrate uses a lightweight and efficient 
[encoding and decoding program](https://docs.substrate.io/reference/scale-codec/) to optimize how data is sent and 
received over the network. The program used to serialize and deserialize data is called the SCALE codec, with SCALE 
being an acronym for **S**imple **C**oncatenated **A**ggregate **L**ittle-**E**ndian.

This library utilizes [py-scale-codec](https://github.com/polkascan/py-scale-codec) for encoding and decoding SCALE, see 
[this overview](https://github.com/polkascan/py-scale-codec#examples-of-different-types) for more information how 
to encode data from Python.

### Extrinsics

Extrinsics within Substrate are basically signed transactions, a vehicle to execute a call function within the 
Substrate runtime, originated from outside the runtime. More information about extrinsics 
on [Substrate docs](https://docs.substrate.io/reference/transaction-format/). For more information on which call 
functions are available in existing Substrate implementations, refer to 
the [PySubstrate Metadata Docs](https://polkascan.github.io/py-substrate-metadata-docs/)

