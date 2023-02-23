
## SCALE
Substrate uses a lightweight and efficient 
[encoding and decoding program](https://docs.substrate.io/reference/scale-codec/) to optimize how data is sent and 
received over the network. The program used to serialize and deserialize data is called the SCALE codec, with SCALE 
being an acronym for **S**imple **C**oncatenated **A**ggregate **L**ittle-**E**ndian.

This library utilizes [py-scale-codec](https://github.com/polkascan/py-scale-codec) for encoding and decoding SCALE, see 
[this overview](https://polkascan.github.io/py-scale-codec/#examples-of-different-types) for more information how 
to encode data from Python.

## SS58 address formatting

SS58 is a simple address format designed for Substrate based chains. For more information about its specification 
see the [Substrate documentation about SS58](https://docs.substrate.io/reference/address-formats/)

## Extrinsics

Extrinsics within Substrate are basically signed transactions, a vehicle to execute a call function within the 
Substrate runtime, originated from outside the runtime. More information about extrinsics 
on [Substrate docs](https://docs.substrate.io/reference/transaction-format/). For more information on which call 
functions are available in existing Substrate implementations, refer to 
the [PySubstrate Metadata Docs](https://polkascan.github.io/py-substrate-metadata-docs/)

