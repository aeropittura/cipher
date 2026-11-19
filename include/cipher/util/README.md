# Misc. Utils

## Exceptions and debugging

- [exception.h](exception.h) defines `CipherException` and the `CIPHER_THROW` macro.

- [debug.h](debug.h) provides the `CIPHER_DEBUG*` macros; [diagnostic_output.h](diagnostic_output.h) routes library diagnostics.

## PRNG

- Our cryptographic hash function is based off of [Blake2b](https://blake2.net), which allows fast hashing.

- To define new `PRNG` engines, refer to [blake2_engine.h](prng/blake2_engine.h).

- Additionally, we refer users to the [sampling documentation](../math/SAMPLING_README.md) for more information about sampling in Cipher, as well as how to use these samplers.
