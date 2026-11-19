Cipher Examples
=================

Cipher ships example programs in the [`examples/`](../../examples) directory of this repository. They are built with
`-DCIPHER_BUILD_EXAMPLES=ON` (the default) into `<build>/bin/examples/{core,fhe,boolean}`.

- [`examples/fhe/`](../../examples/fhe): BFV, BGV and CKKS, bootstrapping, threshold FHE, proxy re-encryption, scheme
  switching and serialization; see its [README](../../examples/fhe/README.md).
- [`examples/boolean/`](../../examples/boolean): Boolean gates and small-integer lookup tables with FHEW/DM,
  CGGI/TFHE and LMKCDEY; see its [README](../../examples/boolean/README.md).
- [`examples/core/`](../../examples/core): sampling, parallelism and plugging in an external PRNG.
- [`examples/extras/`](../../examples/extras): experimental programs, built with `-DCIPHER_BUILD_EXTRAS=ON`.
- [`examples/standalone/CMakeLists.txt`](../../examples/standalone/CMakeLists.txt): a template for a project that
  uses an installed Cipher.

Upstream examples
-----------------

The PALISADE and OpenFHE projects, from which Cipher descends, published further example repositories
(for instance [palisade-integer-examples](https://gitlab.com/palisade/palisade-integer-examples),
[palisade-serial-examples](https://gitlab.com/palisade/palisade-serial-examples) and
[openfhe-python](https://github.com/openfheorg/openfhe-python)). They are written against the PALISADE/OpenFHE APIs,
not Cipher's, but remain useful as illustrations of the same algorithms.
