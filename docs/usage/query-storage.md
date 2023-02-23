# Query storage

In Substrate, any pallet can introduce new storage items that will become part of the blockchain state. These storage 
items can be simple single values, or more complex storage maps.

The runtime exposes several storage functions to query those storage items and are provided in the metadata 
(see `substrate.get_metadata_storage_function()`).

## Example

```python
result = substrate.query('System', 'Account', ['F4xQKRUagnSGjFqafyhajLs94e7Vvzvr8ebwYJceKpr8R7T'])

print(result.value['nonce']) #  7695
print(result.value['data']['free']) # 635278638077956496
```

## State at a specific block hash

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

## Type decomposition information

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

## Query a mapped storage function
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
