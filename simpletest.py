import substrateinterface

RPC_URL = "https://dev-node.substrate.dev:9933/"
SI = substrateinterface.SubstrateInterface(url=RPC_URL)

block_hash = SI.get_chain_head()
print (block_hash, " = block hash of chain head")

storage_key_name = "Sudo Key"
storage_key = substrateinterface.xxh6464(storage_key_name)

r1 = SI.get_storage_by_key(storage_key=storage_key, block_hash=block_hash)
print (r1, " = get_storage_by_key(storage_key=%s)" % storage_key)

r2 = SI.get_storage_by_key(storage_key_name=storage_key_name, block_hash=block_hash)
print (r2, " = get_storage_by_key(storage_key_name='%s')" % storage_key_name)

print("both None: ", end=" ")
try:
    SI.get_storage_by_key(block_hash=block_hash)
except Exception as e:
    print (type(e), e)

print("both given:", end=" ")
try:
    SI.get_storage_by_key(storage_key_name=storage_key_name, storage_key=storage_key, block_hash=block_hash)
except Exception as e:
    print (type(e), e)

storage_key_name = "what if this is much longer and 2 times 64 bits are not enough?"
storage_key = substrateinterface.xxh6464(storage_key_name)
r3 = SI.get_storage_by_key(storage_key_name=storage_key_name, block_hash=block_hash)
print (r3, " = get_storage_by_key(storage_key_name='%s')" % storage_key_name)
