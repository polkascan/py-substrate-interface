# Python Substrate Interface Library
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from substrateinterface.contracts import ContractCode, ContractInstance
from substrateinterface import SubstrateInterface, Keypair

# import logging
# logging.basicConfig(level=logging.DEBUG)

try:
    substrate = SubstrateInterface(
        url="ws://127.0.0.1:9944",
        # type_registry_preset='development'
        type_registry_preset='canvas'
    )

except ConnectionRefusedError:
    print("⚠️ No local Substrate node running, try running 'start_local_substrate_node.sh' first")
    exit()

keypair = Keypair.create_from_uri('//Alice')

# Check if contract is on chain
contract_info = substrate.query("Contracts", "ContractInfoOf", ['5DS85d9YE5KHqoffuYpLHwL3XNjJPQKc7ftrxdqS7S282gkK'])

if contract_info:
    # Create contract instance from deterministic address
    contract = ContractInstance.create_from_address(
        contract_address="5DS85d9YE5KHqoffuYpLHwL3XNjJPQKc7ftrxdqS7S282gkK",
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'erc20.json'),
        substrate=substrate
    )

else:
    # Upload WASM code
    code = ContractCode.create_from_contract_files(
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'erc20.json'),
        wasm_file=os.path.join(os.path.dirname(__file__), 'assets', 'erc20.wasm'),
        substrate=substrate
    )

    receipt = code.upload_wasm(keypair)

    if receipt.is_success:
        print('✅ Contract WASM Uploaded')

        for event in receipt.triggered_events:
            print(f'* {event.value}')

        # Deploy contract
        contract = code.deploy(
            keypair=keypair, endowment=10**15, gas_limit=1000000000000,
            constructor="new",
            args={'initial_supply': 1000 * 10**15}
        )

        print(f'✅ Deployed @ {contract.contract_address}')

    else:
        contract = None
        print(f'⚠️ Failed: {receipt.error_message}')

if contract:

    result = contract.read(keypair, 'total_supply')

    print('Total supply:', result.contract_result_data)

    result = contract.read(keypair, 'balance_of', args={'owner': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'})

    print('Current balance:', result.contract_result_data)

    # Do a gas estimation of the transfer
    gas_predit_result = contract.read(keypair, 'transfer', args={
        'to': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 6 * 10**15
    })

    print('Gas estimate on local node: ', gas_predit_result.gas_consumed)

    # Do the actual transfer
    contract_receipt = contract.exec(keypair, 'transfer', args={
        'to': '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
        'value': 6 * 10**15,
    }, gas_limit=gas_predit_result.gas_consumed)

    if contract_receipt.is_success:
        print('✅ Transfer success, contract events: ')
        for contract_event in contract_receipt.contract_events:
            print(f'* {contract_event.name} {contract_event.docs}:  {contract_event.value}')

        print('All triggered events:')
        for event in contract_receipt.triggered_events:
            print(f'* {event.value}')
    else:
        print('⚠️ ERROR: ', contract_receipt.error_message)
