# Cleanup and context manager

At the end of the lifecycle of a `SubstrateInterface` instance, calling the `close()` method will do all the necessary 
cleanup, like closing the websocket connection.

When using the context manager this will be done automatically:

```python
with SubstrateInterface(url="wss://rpc.polkadot.io") as substrate:
    events = substrate.query("System", "Events")

# connection is now closed
```
