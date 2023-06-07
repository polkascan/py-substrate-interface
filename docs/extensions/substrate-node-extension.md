# SubstrateNodeExtension

This extensions is meant as a fallback option that uses only existing Substrate RPC methods. 
However, it is important to note that this fallback implementation is significantly inefficient, and it is encouraged to utilize third-party search indices where possible for optimal search performance.

## Initialization

```python
substrate = SubstrateInterface(url="ws://127.0.0.1:9944")
# Provide maximum block range (bigger range descreases performance) 
substrate.register_extension(SubstrateNodeExtension(max_block_range=100))
```

## Implemented extension calls

### filter_events
```python
# Returns all `Balances.Transfer` events from the last 30 blocks
events = substrate.extensions.filter_events(pallet_name="Balances", event_name="Transfer", block_start=-30)
```

### filter_extrinsics

```python
# All Timestamp extrinsics in block range #3 until #6
extrinsics = substrate.extensions.filter_extrinsics(pallet_name="Timestamp", block_start=3, block_end=6)
```

### search_block_number

```python
# Search for block number corresponding a specific datetime
block_datetime = datetime(2020, 7, 12, 0, 0, 0)

block_number = substrate.extensions.search_block_number(block_datetime=block_datetime)
```

### get_block_timestamp

```python
# Get timestamp for specific block number
block_timestamp = substrate.extensions.get_block_timestamp(block_number)
```
