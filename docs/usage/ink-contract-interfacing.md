# ink! contract interfacing

## Deploy a contract 

Tested on [substrate-contracts-node](https://github.com/paritytech/substrate-contracts-node) with the [Flipper contract from the tutorial](https://docs.substrate.io/tutorials/smart-contracts/prepare-your-first-contract/):

```python
substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    type_registry_preset='canvas'
)

keypair = Keypair.create_from_uri('//Alice')

# Deploy contract
code = ContractCode.create_from_contract_files(
    metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
    wasm_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.wasm'),
    substrate=substrate
)

contract = code.deploy(
    keypair=keypair,
    endowment=0,
    gas_limit=1000000000000,
    constructor="new",
    args={'init_value': True},
    upload_code=True
)

print(f'✅ Deployed @ {contract.contract_address}')
```

## Work with an existing instance:

```python
# Create contract instance from deterministic address
contract = ContractInstance.create_from_address(
    contract_address=contract_address,
    metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
    substrate=substrate
)
```

## Read data from a contract:

```python
result = contract.read(keypair, 'get')
print('Current value of "get":', result.contract_result_data)
```

## Execute a contract call

```python
# Do a gas estimation of the message
gas_predit_result = contract.read(keypair, 'flip')

print('Result of dry-run: ', gas_predit_result.value)
print('Gas estimate: ', gas_predit_result.gas_required)

# Do the actual call
print('Executing contract call...')
contract_receipt = contract.exec(keypair, 'flip', args={

}, gas_limit=gas_predit_result.gas_required)

if contract_receipt.is_success:
    print(f'Events triggered in contract: {contract_receipt.contract_events}')
else:
    print(f'Error message: {contract_receipt.error_message}')
```

See complete [code example](https://github.com/polkascan/py-substrate-interface/blob/master/examples/create_and_exec_contract.py) for more details
