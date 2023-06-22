# Python Substrate Interface Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
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

# Enable for debugging purposes
import logging
logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url='wss://rococo-contracts-rpc.polkadot.io')
keypair = Keypair.create_from_uri('//Alice')
contract_address = "5DYXHYiH5jPj8orDw5HSFJhmATe8NtmbguG3vs53v8RgSHTW"

# Check if contract is on chain
contract_info = substrate.query("Contracts", "ContractInfoOf", [contract_address])

if contract_info.value:

    print(f'Found contract on chain: {contract_info.value}')

    # Create contract instance from deterministic address
    contract = ContractInstance.create_from_address(
        contract_address=contract_address,
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper-v4.json'),
        substrate=substrate
    )
else:

    # Upload WASM code
    code = ContractCode.create_from_contract_files(
        metadata_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper-v4.json'),
        wasm_file=os.path.join(os.path.dirname(__file__), 'assets', 'flipper-v4.wasm'),
        substrate=substrate
    )

    # Deploy contract
    print('Deploy contract...')
    contract = code.deploy(
        keypair=keypair,
        constructor="new",
        args={'init_value': True},
        value=0,
        gas_limit={'ref_time': 147523041, 'proof_size': 16689},
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
