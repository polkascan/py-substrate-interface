from substrateinterface import SubstrateInterface, Keypair, SubstrateRequestException
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
print("\n\nCurrent Account info: {} DOT".format(
    substrate.get_runtime_state(
        module='System',
        storage_function='Account',
        params=['EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk']
    ).get('result')
))

print("Balance @ {}: {} DOT".format(
    block_hash,
    substrate.get_runtime_state(
        module='Balances',
        storage_function='FreeBalance',
        params=['EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk'],
        block_hash=block_hash
    ).get('result')
))

# Create, sign and submit extrinsic example

mnemonic = Keypair.generate_mnemonic()

keypair = Keypair.create_from_mnemonic(mnemonic, 2)

print("Created address: {}".format(keypair.ss58_address))

call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': 'EaG2CRhJWPb7qmdcJvy3LiWdh26Jreu9Dx6R1rXxPmYXoDk',
        'value': 2 * 10**3
    }
)

extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

try:
    # result = substrate.send_extrinsic(extrinsic)
    result = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

    print('Extrinsic "{}" included in block "{}"'.format(
        result['extrinsic_hash'], result.get('block_hash')
    ))

except SubstrateRequestException as e:
    print("Failed to send: {}".format(e))
