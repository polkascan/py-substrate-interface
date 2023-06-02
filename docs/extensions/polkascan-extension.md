# PolkascanSearchExtension

This extension enables indexes provided by [Polkascan Explorer API](https://github.com/polkascan/explorer#explorer-api-component).

Maintained by [Polkascan Foundation](https://github.com/polkascan/py-substrate-interface-extension-polkascan).

## Installation
```bash
pip install substrate-interface-polkascan
```

## Initialization

```python
from substrateinterface import SubstrateInterface 
from substrateinterface_polkascan.extensions import PolkascanSearchExtension

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

substrate.register_extension(PolkascanSearchExtension(url='http://127.0.0.1:8000/graphql/'))
```

## Implemented extension calls

### Filter events

```python
events = substrate.extensions.filter_events(pallet_name="Balances", event_name="Transfer", page_size=25)
```

### Filter extrinsics

```python
extrinsics = substrate.extensions.filter_extrinsics(
    ss58_address="12L9MSmxHY8YvtZKpA7Vpvac2pwf4wrT3gd2Tx78sCctoXSE",
    pallet_name="Balances", call_name="transfer_keep_alive", page_size=25
)
```
