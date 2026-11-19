# Boolean FHE (`Cipher::boolean`)

## Examples

The examples are in [examples/boolean](../../examples/boolean); the `pke` subdirectory holds the public-key variants.

### Simple Boolean

- evaluation of binary gates and multi-input gates
- bootstrapping for `AP` (DM), `GINX` (CGGI) and `LMKCDEY`
- serialization to binary and json formats

### Evaluation of functions

The supported function evaluations are based on the functionalities described
in [Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337).

- digit decomposition
- floor function (reduce by a certain number of bits)
- arbitrary function(lookup table) _f: Z<sub>p</sub> -> Z<sub>p</sub>_ on the input ciphertext
- sign function to get the MSB of an input

## Headers

- [include/cipher/boolean](../../include/cipher/boolean)

## Implementation

- [source/boolean](../../source/boolean)
