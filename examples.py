from substrateinterface import SubstrateInterface
from substrateinterface.utils.ss58 import ss58_encode

substrate = SubstrateInterface(
    url="wss://kusama-rpc.polkadot.io/",
    address_type=2,
    type_registry_preset='kusama'
)

# Set block_hash to None for chaintip
block_hash = "0x588930468212316d8a75ede0bec0bc949451c164e2cea07ccfc425f497b077b7"


# Retrieve extrinsics in block
result = substrate.get_runtime_block(block_hash=block_hash)

for extrinsic in result['block']['extrinsics']:

    if 'account_id' in extrinsic:
        signed_by_address = ss58_encode(address=extrinsic['account_id'], address_type=2)
    else:
        signed_by_address = None

    print('\nModule: {}\nCall: {}\nSigned by: {}'.format(
        extrinsic['call_module'],
        extrinsic['call_function'],
        signed_by_address
    ))

    for param in extrinsic['params']:

        if param['type'] == 'Address':
            param['value'] = ss58_encode(address=param['value'], address_type=2)

        if param['type'] == 'Compact<Balance>':
            param['value'] = '{} DOT'.format(param['value'] / 10**12)

        print("Param '{}': {}".format(param['name'], param['value']))

# Storage call examples
print("\n\nCurrent balance: {} DOT".format(
    substrate.get_runtime_state(
        module='Balances',
        storage_function='FreeBalance',
        params=['EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk']
    ).get('result') / 10**12
))

print("Balance @ {}: {} DOT".format(
    block_hash,
    substrate.get_runtime_state(
        module='Balances',
        storage_function='FreeBalance',
        params=['EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk'],
        block_hash=block_hash
    ).get('result') / 10**12
))

# Unsigned extrinsic example
payload = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
        'value': 1000000000000
    }
)

print("\n\nUnsigned balance transfer extrinsic: {}".format(payload))

# Create historic unsigned extrinsic by providing block hash
payload = substrate.compose_call(
    call_module='Nicks',
    call_function='clear_name',
    call_params={},
    block_hash="0x918107632d7994d50f3661db3af353d2aa378f696e47a393bab573f63f7d6c3a"
)

print("\n\nUnsigned deprecated nicks clear_name extrinsic: {}".format(payload))
