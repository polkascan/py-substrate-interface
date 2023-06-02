# Extensions

The extension framework is designed to enhance and improve search capabilities on top of existing functionality provided 
by the Substrate node. 
It allows for the integration of third-party search indices, which can be easily interchanged with 
other data sources that provide the same functionality, as long as they adhere to standardized naming conventions in
the extension registry.

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

