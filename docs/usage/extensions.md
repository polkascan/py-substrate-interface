# Extensions

The extension framework is designed to enhance and improve search capabilities of the Substrate node. 
It allows for the integration of third-party search indices, which can be easily interchanged with 
other data sources that provide the same functionality, as long as they adhere to standardized naming conventions in
the registry.

## Search extensions

At present, the only type of extension that has been implemented is the search extension. While other types of 
extensions may be developed in the future, the current implementation provides a fallback option that uses only 
existing Substrate RPC methods. However, it is important to note that this fallback implementation is significantly 
inefficient, and it is encouraged to utilize third-party search indices where possible for optimal search performance.

### Available extension calls

|                 |                                                                                                                         |
|-----------------|-------------------------------------------------------------------------------------------------------------------------|
| `filter_events` | Filters events to match provided search criteria e.g. block range, pallet name, accountID in attributes                 |
| `filter_extrinsics` | Filters extrinsics to match provided search criteria e.g. block range, pallet name, signed by accountID                 |
| `search_block_number` | Search corresponding block number for provided `block_datetime`. the prediction tolerance is provided with `block_time` |
| `get_block_timestamp` | Return a UNIX timestamp for given `block_number`. |



## SubstrateNodeSearchExtension

### Initialization

```python
substrate = SubstrateInterface(url="ws://127.0.0.1:9944")
# Provide maximum block range (bigger range descreases performance) 
substrate.register_extension(SubstrateNodeSearchExtension(max_block_range=100))
```

### Implemented extension calls

#### filter_events
```python
# Returns all `Balances.Transfer` events from the last 30 blocks
events = substrate.extensions.filter_events(pallet_name="Balances", event_name="Transfer", block_start=-30)
```

#### filter_extrinsics

```python
# All Timestamp extrinsics in block range #3 until #6
extrinsics = substrate.extensions.filter_extrinsics(pallet_name="Timestamp", block_start=3, block_end=6)
```

#### search_block_number

```python
# Search for block number corresponding a specific datetime
block_datetime = datetime(2020, 7, 12, 0, 0, 0)

block_number = substrate.extensions.search_block_number(block_datetime=block_datetime)
```

## Third party extensions 

* `PolkascanSearchExtension` - _Work in progress_
