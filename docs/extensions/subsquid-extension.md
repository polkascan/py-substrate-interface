# SubsquidExtension

This extension enables utilisation of [Giant Squid indexes](https://docs.subsquid.io/giant-squid-api/statuses/) provided by [Subsquid](https://subsquid.io)

Maintained by [Polkascan Foundation](https://github.com/polkascan/py-substrate-interface-extension-subsquid).

## Installation
```bash
pip install substrate-interface-subsquid
```

## Initialization

```python
from substrateinterface import SubstrateInterface
from substrateinterface_subsquid.extensions import SubsquidExtension

substrate = SubstrateInterface(url="wss://rpc.polkadot.io")

substrate.register_extension(SubsquidExtension(url='https://squid.subsquid.io/gs-explorer-polkadot/graphql'))
```

## Implemented extension calls

### Filter events

```python
events = substrate.extensions.filter_events(
    pallet_name="Balances", event_name="Transfer", account_id="12L9MSmxHY8YvtZKpA7Vpvac2pwf4wrT3gd2Tx78sCctoXSE", 
    page_size=25
)
```

### Filter extrinsics

```python
extrinsics = substrate.extensions.filter_extrinsics(
    ss58_address="12L9MSmxHY8YvtZKpA7Vpvac2pwf4wrT3gd2Tx78sCctoXSE",
    pallet_name="Balances", call_name="transfer_keep_alive", page_size=25
)
```

### Search block number

```python
block_datetime = datetime(2020, 7, 12, 0, 0, 0, tzinfo=timezone.utc)

block_number = substrate.extensions.search_block_number(block_datetime=block_datetime)
```
