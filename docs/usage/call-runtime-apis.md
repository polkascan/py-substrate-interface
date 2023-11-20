# Call runtime APIs

Each Substrate node contains a runtime. The runtime contains the business logic of the chain. It defines what 
transactions are valid and invalid and determines how the chain's state changes in response to transactions. 

A Runtime API facilitates this kind of communication between the outer node and the runtime. 
[More information about Runtime APIs](https://docs.substrate.io/reference/runtime-apis/)

## Example
```python
result = substrate.runtime_call("AccountNonceApi", "account_nonce", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"])
# <U32(value=2)>
```

## List of available runtime APIs and methods

```python
runtime_calls = substrate.get_metadata_runtime_call_functions()
#[
#   <RuntimeApiMetadataV14(value={'name': 'AccountNonceApi', 'methods': [{'name': 'account_nonce', 'inputs': [{'name': 'account_id', 'type': 'AccountId'}], 'output': 'Index', 'docs': ['The API to query account nonce (aka transaction index)']}], 'docs': []})>
#    ...
#]
```

## Get param type decomposition
A helper function to compose the parameters for this runtime API call

```python
runtime_call = substrate.get_metadata_runtime_call_function("ContractsApi", "call")
param_info = runtime_call.get_param_info()
# ['AccountId', 'AccountId', 'u128', (None, {'proof_size': 'u64', 'ref_time': 'u64'}), (None, 'u128'), 'Bytes']
```
