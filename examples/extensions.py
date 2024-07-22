from datetime import datetime, timedelta

from substrateinterface import SubstrateInterface
from substrateinterface.extensions import SubstrateNodeExtension

import logging
logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url="wss://rpc.polkadot.io")

substrate.extensions.register(SubstrateNodeExtension(max_block_range=100))

# Search for block number corresponding a specific datetime
block_datetime = datetime(2022, 12, 31, 0, 0, 0)
block_number = substrate.extensions.search_block_number(block_datetime=block_datetime)
print(f'Block number for {block_datetime}: #{block_number}')
block_hash = substrate.get_block_hash(block_number)

account_info = substrate.runtime.at(block_hash).pallet("System").storage("Account").get("13GnsRKEXCAYLJNScBEDj7rHTXkkHAVTj5QMNp6rnyGuTAVN")

def format_balance(amount: int):
    amount = format(amount / 10**substrate.properties.get('tokenDecimals', 0), ".15g")
    return f"{amount} {substrate.properties.get('tokenSymbol', 'UNIT')}"

balance = (account_info.value["data"]["free"] + account_info.value["data"]["reserved"])

print(f"Balance @ {block_number}: {format_balance(balance)}")

exit()

# Returns all `Balances.Transfer` events from the last 30 blocks
events = substrate.extensions.filter_events(pallet_name="Balances", event_name="Transfer", block_start=-30)
print(events)

# All Timestamp extrinsics in block range #3 until #6
extrinsics = substrate.extensions.filter_extrinsics(pallet_name="Timestamp", block_start=3, block_end=6)
print(extrinsics)
