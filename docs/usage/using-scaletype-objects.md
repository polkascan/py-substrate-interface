# Using ScaleType objects

The result of the previous storage query example is a `ScaleType` object, more specific a `Struct`. 

The nested object structure of this `account_info` object is as follows:
```
account_info = <AccountInfo(value={'nonce': <U32(value=5)>, 'consumers': <U32(value=0)>, 'providers': <U32(value=1)>, 'sufficients': <U32(value=0)>, 'data': <AccountData(value={'free': 1152921503981846391, 'reserved': 0, 'misc_frozen': 0, 'fee_frozen': 0})>})>
```

Every `ScaleType` have the following characteristics:

## Shorthand lookup of nested types

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

## Serializable
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

## Comparing values with `ScaleType` objects

It is possible to compare ScaleType objects directly to Python primitives, internally the serialized `value` attribute
is compared:

```python
metadata_obj[1][1]['extrinsic']['version'] # '<U8(value=4)>'
metadata_obj[1][1]['extrinsic']['version'] == 4 # True
```
