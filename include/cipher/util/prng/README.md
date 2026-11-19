# PRNG Engine(s)

Refer to the [PRNG documentation](../../../../docs/sphinx_rsts/modules/core/utils/prng.rst) for more information.

Additionally, we refer users to [sampling documentation](../../math/SAMPLING_README.md) for
more information about sampling in Cipher, as well as how to use these samplers.

## Blake2

- Our cryptographic hash function is based off of [Blake2b](https://blake2.net), which allows fast hashing.

## Using a custom PRNG Engine

To define new `PRNG` engines, refer to [blake2_engine.h](blake2_engine.h).
