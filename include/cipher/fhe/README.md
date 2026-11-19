# FHE (public-key schemes) Documentation

Headers of the `Cipher::fhe` module. Scheme-specific code is in [bfv](bfv), [bgv](bgv) and [ckks](ckks); shared
base classes are in [base](base) and [rns](rns); parameters in [config](config); plaintext encodings in
[encoding](encoding); keys in [key](key); key switching in [keyswitch](keyswitch).

[ciphertext.h](ciphertext.h)

- for the representation of ciphertext in Cipher

- provides `CiphertextImpl` which is used to contain encrypted text

[ciphertext_ser.h](ciphertext_ser.h)

- exposes serialization methods for ciphertexts to [USCiLab - cereal](https://github.com/USCiLab/cereal)

- must be included any time we need ciphertext serialization

[constants.h](constants.h)

- Contains the various constants used throughout the FHE module including:
  - PKE Scheme Feature: Lists all features supported by PKE schemees.
    - PKE (PKE)
    - Keyswitch (KEYSWITCH)
    - proxy-reencryption (PRE)
    - Leveled Somewhat Homomorphic Encryption (LEVELED SHE)
    - Advanced Somewhat Homomorphic Encryption (ADVANCEDSHE)
    - Threshold FHE (MULTIPARTY)
    - Fully Homomorphic Encryption (FHE)
    - Scheme switching (SCHEMESWITCH)

  - Secret key distribution (`SecretKeyDist`)
    - Ring Learning with Error (GAUSSIAN)
    - Optimized (UNIFORM_TERNARY)
    - Sparse (SPARSE_TERNARY; Hamming weight is 192; discouraged for CKKS bootstrapping because of a high probability of failure)
    - Sparse encapsulated (SPARSE_ENCAPSULATED; Hamming weight of 32 for the key used in bootstrapping and 192 for other operations; recommended for CKKS bootstrapping, probability of failure below 2^-128)

  - Scaling Technique
    - Fixed Manual (FIXEDMANUAL)
    - Fixed Auto (FIXEDAUTO)
    - Flexible Auto (FLEXIBLEAUTO)
    - Flexible Auto Extended (FLEXIBLEAUTOEXT)
    - Composite scaling (COMPOSITESCALINGAUTO, COMPOSITESCALINGMANUAL; CKKS only)
    - No Rescaling (NORESCALE)

  - Key Switch Technique
    - BV (See Appendix of https://eprint.iacr.org/2021/204)
    - HYBRID (See Appendix of https://eprint.iacr.org/2021/204)

  - Encryption Technique
    - Standard (STANDARD)
    - Extended (EXTENDED)

  - Multiplication Technique
    - Bajard-Eynard-Hasan-Zucca (BEHZ)
    - Halevi-Polyakov-Shoup (HPS)
    - Halevi-Polyakov-Shoup P over Q (HPSPOVERQ)
    - Halevi-Polyakov-Shoup P over Q Leveled Multiplication (HPSPOVERQLEVELED)

[context_factory.h](context_factory.h)

- `ContextFactory`: generates and caches new `CryptoContext`s from user parameters

[context.h](context.h)

- defines `CryptoContextImpl`, which is used to access the Cipher library

- all Cipher objects are created "within" a `CryptoContext` which acts like an object "manager".
Objects can only be used in the context they were created in


[context_ser.h](context_ser.h)

- exposes serialization methods for `CryptoContext` to [USCiLab - cereal](https://github.com/USCiLab/cereal)

- must be included any time we need `CryptoContext` serialization

[crypto_object.h](crypto_object.h)

- comprises a `context`, and `keytag`:
  - `context`: `CryptoContext` this object belongs to
  - `keytag`: tag that is used to find the evaluation key needed for various operations

[context_gen.h](context_gen.h)

- `make_crypto_context`: constructs a `CryptoContext` from a `ContextParams<BfvRnsContext>`, `ContextParams<BgvRnsContext>` or `ContextParams<CkksRnsContext>`

[globals.h](globals.h)

- Global value definitions

[metadata.h](metadata.h)

- metadata container and helper function definition

[metadata_ser.h](metadata_ser.h)

- exposes serialization methods for `Metadata` to [USCiLab - cereal](https://github.com/USCiLab/cereal)

- must be included any time we need `Metadata` serialization

[cipher/cipher.h](../cipher.h)

- top-level header for ease of import
