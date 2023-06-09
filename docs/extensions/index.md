# Extensions

The extension framework is designed to enhance and improve search capabilities on top of existing functionality provided 
by the Substrate node. 

It allows for the integration of third-party search indices, which can be easily interchanged with 
other data sources that provide the same functionality, as long as they adhere to standardized naming conventions in
the extension registry.

## Available extensions

| Name                                                 | Maintained by        | Code                                                                              |
|------------------------------------------------------|----------------------|-----------------------------------------------------------------------------------|
| [SubstrateNodeExtension](./substrate-node-extension) | Polkascan Foundation | [Github](https://github.com/polkascan/py-substrate-interface)                     |
| [PolkascanExtension](./polkascan-extension.md)       | Polkascan Foundation | [Github](https://github.com/polkascan/py-substrate-interface-extension-polkascan) |
| [SubsquidExtension](./subsquid-extension.md)         | Polkascan Foundation | [Github](https://github.com/polkascan/py-substrate-interface-extension-subsquid)  |

## Available extension calls

|                 |                                                                                                                         |
|-----------------|-------------------------------------------------------------------------------------------------------------------------|
| `filter_events` | Filters events to match provided search criteria e.g. block range, pallet name, accountID in attributes                 |
| `filter_extrinsics` | Filters extrinsics to match provided search criteria e.g. block range, pallet name, signed by accountID                 |
| `search_block_number` | Search corresponding block number for provided `block_datetime`. the prediction tolerance is provided with `block_time` |
| `get_block_timestamp` | Return a UNIX timestamp for given `block_number`. |

