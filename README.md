# Cipher

Cipher is a C++17 library for lattice-based fully homomorphic encryption (FHE): computing on
encrypted data without access to the secret key. It is derived from
[OpenFHE](https://github.com/openfheorg/openfhe-development) and keeps its algorithms. The source
tree, build system and API naming have been reorganized. See [NOTICE.md](NOTICE.md) for
attribution and [PROVENANCE.md](PROVENANCE.md) for how the history was imported.

## Schemes

| Module | Header | What it provides |
|---|---|---|
| `Cipher::fhe` | `cipher/cipher.h` | BFV and BGV (exact integer arithmetic), CKKS (approximate real/complex arithmetic, bootstrapping), threshold FHE, proxy re-encryption, CKKS ⇄ FHEW scheme switching, functional bootstrapping |
| `Cipher::boolean` | `cipher/boolean/context.h` | FHEW/DM, CGGI/TFHE and LMKCDEY bootstrapping for Boolean gates and small-integer lookup tables |
| `Cipher::core` | `cipher/core.h` | Big-integer backends, number theory, NTT, polynomial rings (RNS), Gaussian sampling |

## Quick start

```cpp
#include "cipher/cipher.h"
using namespace cipher;

int main() {
    ContextParams<BfvRnsContext> params;
    params.set_plaintext_modulus(65537);
    params.set_multiplicative_depth(2);

    CryptoContext<RnsPoly> cc = make_crypto_context(params);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    KeyPair<RnsPoly> keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);

    auto a = cc->encrypt(keys.public_key, cc->make_packed_plaintext({1, 2, 3, 4}));
    auto b = cc->encrypt(keys.public_key, cc->make_packed_plaintext({5, 6, 7, 8}));
    auto product = cc->eval_mult(a, b);

    Plaintext result;
    cc->decrypt(keys.secret_key, product, &result);
    result->set_length(4);
    std::cout << result << std::endl;  // (5, 12, 21, 32, ... )
}
```

## Building

Requirements: CMake ≥ 3.16, a C++17 compiler (GCC ≥ 9 or Clang ≥ 10), and optionally OpenMP
(`libomp` on macOS).

```sh
git submodule update --init extern/cereal extern/google-test extern/google-benchmark
cmake -S . -B build -G Ninja            # add -DCIPHER_WITH_OPENMP=OFF if OpenMP is unavailable
cmake --build build
ctest --test-dir build                  # or: cmake --build build --target check
cmake --install build                   # installs under CMAKE_INSTALL_PREFIX
```

Commonly used options (all listed in [cmake/CipherOptions.cmake](cmake/CipherOptions.cmake)):

| Option | Default | Meaning |
|---|---|---|
| `CIPHER_BUILD_SHARED` / `CIPHER_BUILD_STATIC` | `ON` / `OFF` | Library flavors to build |
| `CIPHER_BUILD_TESTS`, `CIPHER_BUILD_EXAMPLES`, `CIPHER_BUILD_BENCHMARKS` | `ON` | In-tree programs |
| `CIPHER_WITH_OPENMP` | `ON` | Multithreading with OpenMP |
| `CIPHER_MATH_BACKEND` | `4` | Default big-integer backend: 2 (fixed), 4 (dynamic), 6 (NTL) |
| `CIPHER_NATIVE_SIZE` | `64` | Native integer width: 32, 64 or 128 |
| `CIPHER_WITH_NATIVEOPT` | `OFF` | Optimize for the build machine |

## Using an installed Cipher

```cmake
find_package(Cipher CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Cipher::fhe)   # Cipher::fhe_static for static builds
```

A complete template is in [examples/standalone/CMakeLists.txt](examples/standalone/CMakeLists.txt).

## Repository layout

```
include/cipher/   public headers: math/, ring/, util/, fhe/{bfv,bgv,ckks,base,rns,...}, boolean/
source/           implementation, mirroring include/cipher/
tests/            GoogleTest suites (core, fhe, boolean)
examples/         example programs; examples/extras/ holds experimental ones
bench/            google-benchmark programs
cmake/            build-system modules and package configuration
extern/           third-party submodules (cereal, googletest, google-benchmark, gperftools)
docs/             Sphinx documentation sources
tools/            maintenance scripts
```

## Naming conventions

Types are `PascalCase` (`RnsPoly`, `CkksRnsScheme`), functions and variables are `snake_case`
(`eval_mult`, `get_ring_dimension`), and data members end with an underscore (`params_`). Where
the case of a single letter carries mathematical meaning it is kept (`get_N()` is the ring
dimension, `get_n()` the LWE dimension). Macros and build options use the `CIPHER_` prefix.

## Serialization compatibility

Serialized contexts, keys and ciphertexts use the same on-disk format and type names as OpenFHE
1.6.1, so files written by either library can be read by the other (binary and JSON).

## Documentation

- Examples: [examples/fhe/README.md](examples/fhe/README.md) and the programs next to it
- Best performance: [docs/static_docs/Best_Performance.md](docs/static_docs/Best_Performance.md)
- Design paper of the underlying library: <https://eprint.iacr.org/2022/915>

## License

BSD 2-Clause; see [LICENSE](LICENSE). The original copyright notices are retained in every
source file.
