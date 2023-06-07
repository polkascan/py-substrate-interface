from datetime import datetime, timedelta

from substrateinterface import SubstrateInterface
from substrateinterface.extensions import SubstrateNodeExtension

import logging
logging.basicConfig(level=logging.DEBUG)

substrate = SubstrateInterface(url="wss://rpc.polkadot.io")

substrate.register_extension(SubstrateNodeExtension(max_block_range=100))

# Search for block number corresponding a specific datetime
block_datetime = datetime(2022, 1, 1, 0, 0, 0)
block_number = substrate.extensions.search_block_number(block_datetime=block_datetime)
print(f'Block number for {block_datetime}: #{block_number}')

# account_info = substrate.runtime.
# exit()

# Returns all `Balances.Transfer` events from the last 30 blocks
events = substrate.extensions.filter_events(pallet_name="Balances", event_name="Transfer", block_start=-30)
print(events)

# All Timestamp extrinsics in block range #3 until #6
extrinsics = substrate.extensions.filter_extrinsics(pallet_name="Timestamp", block_start=3, block_end=6)
print(extrinsics)
