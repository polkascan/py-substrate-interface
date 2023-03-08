## Batch call

```python
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)

keypair = Keypair.create_from_uri('//Alice')

balance_call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 1 * 10**15
    }
)

call = substrate.compose_call(
    call_module='Utility',
    call_function='batch',
    call_params={
        'calls': [balance_call, balance_call]
    }
)

extrinsic = substrate.create_signed_extrinsic(
    call=call,
    keypair=keypair,
    era={'period': 64}
)


try:
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    print('Extrinsic "{}" included in block "{}"'.format(
        receipt.extrinsic_hash, receipt.block_hash
    ))

    if receipt.is_success:

        print('✅ Success, triggered events:')
        for event in receipt.triggered_events:
            print(f'* {event.value}')

    else:
        print('⚠️ Extrinsic Failed: ', receipt.error_message)


except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
```

## Fee info

```python
from substrateinterface import SubstrateInterface, Keypair


# import logging
# logging.basicConfig(level=logging.DEBUG)


substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)

keypair = Keypair.create_from_uri('//Alice')

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 1 * 10**15
    }
)

# Get payment info
payment_info = substrate.get_payment_info(call=call, keypair=keypair)

print("Payment info: ", payment_info)
```

## Query a Mapped storage function

```python
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)

result = substrate.query_map("System", "Account", max_results=100)

for account, account_info in result:
    print(f'* {account.value}: {account_info.value}')
```

## Multisig transaction

```python
from substrateinterface import SubstrateInterface, Keypair

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

keypair_alice = Keypair.create_from_uri('//Alice', ss58_format=substrate.ss58_format)
keypair_bob = Keypair.create_from_uri('//Bob', ss58_format=substrate.ss58_format)
keypair_charlie = Keypair.create_from_uri('//Charlie', ss58_format=substrate.ss58_format)

# Generate multi-sig account from signatories and threshold
multisig_account = substrate.generate_multisig_account(
    signatories=[
        keypair_alice.ss58_address,
        keypair_bob.ss58_address,
        keypair_charlie.ss58_address
    ],
    threshold=2
)

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': keypair_alice.ss58_address,
        'value': 3 * 10 ** 3
    }
)

# Initiate multisig tx
extrinsic = substrate.create_multisig_extrinsic(call, keypair_alice, multisig_account, era={'period': 64})

receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

if not receipt.is_success:
    print(f"⚠️ {receipt.error_message}")
    exit()

# Finalize multisig tx with other signatory
extrinsic = substrate.create_multisig_extrinsic(call, keypair_bob, multisig_account, era={'period': 64})

receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

if receipt.is_success:
    print(f"✅ {receipt.triggered_events}")
else:
    print(f"⚠️ {receipt.error_message}")
```

## Create and call ink! contract

```python
import os

from substrateinterface.contracts import ContractCode, ContractInstance
from substrateinterface import SubstrateInterface, Keypair

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944",
    type_registry_preset='canvas'
)

keypair = Keypair.create_from_uri('//Alice')
contract_address = "5GhwarrVMH8kjb8XyW6zCfURHbHy3v84afzLbADyYYX6H2Kk"

# Check if contract is on chain
contract_info = substrate.query("Contracts", "ContractInfoOf", [contract_address])

if contract_info.value:

    print(f'Found contract on chain: {contract_info.value}')

    # Create contract instance from deterministic address
    contract = ContractInstance.create_from_address(
        contract_address=contract_address,
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
        substrate=substrate
    )
else:

    # Upload WASM code
    code = ContractCode.create_from_contract_files(
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.json'),
        wasm_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper.wasm'),
        substrate=substrate
    )

    # Deploy contract
    print('Deploy contract...')
    contract = code.deploy(
        keypair=keypair,
        endowment=0,
        gas_limit=1000000000000,
        constructor="new",
        args={'init_value': True},
        upload_code=True
    )

    print(f'✅ Deployed @ {contract.contract_address}')

# Read current value
result = contract.read(keypair, 'get')
print('Current value of "get":', result.contract_result_data)

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

result = contract.read(keypair, 'get')

print('Current value of "get":', result.contract_result_data)

```

## Historic balance

```python
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

block_number = 10
block_hash = substrate.get_block_hash(block_number)

result = substrate.query(
    "System", "Account", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"], block_hash=block_hash
)


def format_balance(amount: int):
    amount = format(amount / 10**substrate.properties.get('tokenDecimals', 0), ".15g")
    return f"{amount} {substrate.properties.get('tokenSymbol', 'UNIT')}"


balance = (result.value["data"]["free"] + result.value["data"]["reserved"])

print(f"Balance @ {block_number}: {format_balance(balance)}")
```

## Block headers subscription

```python
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")


def subscription_handler(obj, update_nr, subscription_id):
    print(f"New block #{obj['header']['number']}")

    block = substrate.get_block(block_number=obj['header']['number'])

    for idx, extrinsic in enumerate(block['extrinsics']):
        print(f'# {idx}:  {extrinsic.value}')

    if update_nr > 2:
        return {'message': 'Subscription will cancel when a value is returned', 'updates_processed': update_nr}


result = substrate.subscribe_block_headers(subscription_handler)
print(result)
```

## Storage subscription

```python
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(
    url="ws://127.0.0.1:9944"
)


def subscription_handler(account_info_obj, update_nr, subscription_id):

    if update_nr == 0:
        print('Initial account data:', account_info_obj.value)

    if update_nr > 0:
        # Do something with the update
        print('Account data changed:', account_info_obj.value)

    # The execution will block until an arbitrary value is returned, which will be the result of the `query`
    if update_nr > 5:
        return account_info_obj


result = substrate.query("System", "Account", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"],
                         subscription_handler=subscription_handler)

print(result)
```

## Subscribe to multiple storage keys 

```python
from substrateinterface import SubstrateInterface


def subscription_handler(storage_key, updated_obj, update_nr, subscription_id):
    print(f"Update for {storage_key.params[0]}: {updated_obj.value}")


substrate = SubstrateInterface(url="ws://127.0.0.1:9944")

# Accounts to track
storage_keys = [
    substrate.create_storage_key(
        "System", "Account", ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]
    ),
    substrate.create_storage_key(
        "System", "Account", ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"]
    )
]

result = substrate.subscribe_storage(
    storage_keys=storage_keys, subscription_handler=subscription_handler
)
```
