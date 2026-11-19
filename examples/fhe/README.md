Cipher Lattice Cryptography Library - Examples
=============================================

[License Information](../../LICENSE)

Document Description
===================
This document describes the examples included with the Cipher lattice crypto library.

Examples Directory Description
==========================

Directory Objective
-------------------
This directory contains examples that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

*Example programs*

- [advanced_ckks_bootstrapping.cpp](advanced_ckks_bootstrapping.cpp): an example showing CKKS bootstrapping for a ciphertext with sparse packing
- [advanced_real_numbers.cpp](advanced_real_numbers.cpp): shows several advanced examples of approximate homomorphic encryption using CKKS
- [advanced_real_numbers_128.cpp](advanced_real_numbers_128.cpp): shows several advanced examples of approximate homomorphic encryption using high-precision CKKS
- [ckks_bootstrap_keys_serial.cpp](ckks_bootstrap_keys_serial.cpp): demonstrates serialization and deserialization of the CKKS bootstrapping keys (`serialize_eval_bootstrap_key` and `deserialize_eval_bootstrap_key`), so that bootstrapping can run on a party that did not generate the keys
- [ckks_noise_flooding.cpp](ckks_noise_flooding.cpp): demonstrates use of experimental feature NOISE_FLOODING_DECRYPT mode in CKKS, which enhances security
- [ckks_release_memory.cpp](ckks_release_memory.cpp): demonstrates how to release the memory held by the CKKS bootstrapping precomputations, comparing `clear_bootstrap_precom` with `ContextFactory<RnsPoly>::release_all_contexts`
- [depth_bfvrns.cpp](depth_bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [depth_bfvrns_behz.cpp](depth_bfvrns_behz.cpp): demonstrates use of the BEHZ BFV variant for basic homomorphic encryption
- [depth_bgvrns.cpp](depth_bgvrns.cpp): demonstrates use of the BGVrns scheme for basic homomorphic encryption
- [FE_functional_bootstrapping_ckks.cpp](FE_functional_bootstrapping_ckks.cpp): demonstrates CKKS functional bootstrapping from Fourier extension, evaluating several functions on one refreshed ciphertext
- [function_evaluation.cpp](function_evaluation.cpp): demonstrates the evaluation of a non-polynomial function using a Chebyshev approximation using CKKS
- [functional_bootstrapping_ckks.cpp](functional_bootstrapping_ckks.cpp): demonstrates the evaluation of a discrete lookup table over a RLWE ciphertext using CKKS
- [inner_product.cpp](inner_product.cpp): demonstrates the evaluation of inner product using CKKS and BFV
- [interactive_bootstrapping.cpp](interactive_bootstrapping.cpp): two examples of $2$-party interactive bootstrapping (the second one is with Chebyshev interpolation)
- [iterative_ckks_bootstrapping.cpp](iterative_ckks_bootstrapping.cpp): demonstrates how to run multiple iterations of CKKS bootstrapping to improve precision
- [iterative_ckks_bootstrapping_composite_scaling.cpp](iterative_ckks_bootstrapping_composite_scaling.cpp): double-precision CKKS bootstrapping in the CKKS composite scaling mode
- [linearwsum_evaluation.cpp](linearwsum_evaluation.cpp): demonstrates the evaluation of a linear weighted sum using CKKS
- [polynomial_evaluation.cpp](polynomial_evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [polynomial_evaluation_high_precision_composite_scaling.cpp](polynomial_evaluation_high_precision_composite_scaling.cpp): high-precision (80-bit scaling factor) power series evaluation in the CKKS composite scaling mode
- [pre_buffer.cpp](pre_buffer.cpp): demonstrates use of Cipher for encryption, re-encryption and decryption of packed vector of binary data
- [pre_hra_secure.cpp](pre_hra_secure.cpp): shows examples of HRA-secure PRE based on BGV
- [rotation.cpp](rotation.cpp): demonstrates use of `eval_rotate` for different schemes
- [scheme_switching.cpp](scheme_switching.cpp): demonstrates several use cases for switching between CKKS and FHEW ciphertexts
- [scheme_switching_serial.cpp](scheme_switching_serial.cpp): provides an example of CKKS <-> FHEW scheme switching with serialization
- [simple_ckks_bootstrapping.cpp](simple_ckks_bootstrapping.cpp): simple example showing CKKS bootstrapping for a ciphertext with full packing
- [simple_ckks_bootstrapping_composite_scaling.cpp](simple_ckks_bootstrapping_composite_scaling.cpp): single-precision CKKS bootstrapping in the CKKS composite scaling mode
- [simple_complex_numbers.cpp](simple_complex_numbers.cpp): leveled FHE and bootstrapping examples for CKKS over complex numbers
- [simple_composite_scaling_manual.cpp](simple_composite_scaling_manual.cpp): basic CKKS arithmetic in the COMPOSITESCALINGMANUAL mode, with the register word size and composite degree set explicitly
- [simple_integers.cpp](simple_integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple_integers_bgvrns.cpp](simple_integers_bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGV
- [simple_integers_serial.cpp](simple_integers_serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple_integers_serial_bgvrns.cpp](simple_integers_serial_bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGV
- [simple_real_numbers.cpp](simple_real_numbers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [simple_real_numbers_composite_scaling.cpp](simple_real_numbers_composite_scaling.cpp): basic CKKS arithmetic in the CKKS composite scaling mode
- [simple_real_numbers_serial.cpp](simple_real_numbers_serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [tckks_interactive_mp_bootstrapping.cpp](tckks_interactive_mp_bootstrapping.cpp): an example of $n$-party interactive bootstrapping
- [tckks_interactive_mp_bootstrapping_Chebyshev.cpp](tckks_interactive_mp_bootstrapping_Chebyshev.cpp): an example of $n$-party interactive bootstrapping with Chebyshev interpolation
- [threshold_fhe.cpp](threshold_fhe.cpp): shows several examples of threshold FHE in BGV, BFV, and CKKS
- [threshold_fhe_5p.cpp](threshold_fhe_5p.cpp): shows example of threshold FHE with 5 parties in BFV

*Documentation for advanced capabilities*

- [CKKS_BOOTSTRAPPING.md](CKKS_BOOTSTRAPPING.md): the CKKS bootstrapping pipeline and its variants, the secret key distributions and their probabilities of failure, and the bootstrapping parameters
- [CKKS_FUNCTIONAL_BOOTSTRAPING.md](CKKS_FUNCTIONAL_BOOTSTRAPING.md): CKKS functional bootstrapping, for lookup tables over integers and for smooth functions over real numbers (Fourier extension)
- [CKKS_NOISE_FLOODING.md](CKKS_NOISE_FLOODING.md): the NOISE_FLOODING_DECRYPT mode of CKKS for $\textsf{IND-CPA}^D$ security
- [COMPOSITE_SCALING.md](COMPOSITE_SCALING.md): the CKKS composite scaling modes, for scaling factors larger than the hardware word size
- [FUNCTION_EVALUATION.md](FUNCTION_EVALUATION.md): evaluation of smooth functions in CKKS using Chebyshev approximation
- [INTERACTIVE_BOOTSTRAPPING.md](INTERACTIVE_BOOTSTRAPPING.md): 2-party and $n$-party interactive CKKS bootstrapping
- [SCHEME_SWITCHING_CAPABILITY.md](SCHEME_SWITCHING_CAPABILITY.md): switching between CKKS and FHEW ciphertexts

Building and Running the Examples
===================
The examples are built when `CIPHER_BUILD_EXAMPLES=ON` (the default). Each source file becomes one
executable named after the file, written to `<build>/bin/examples/fhe/`:
```
    cmake -S . -B build
    cmake --build build --target fhe_examples
    ./build/bin/examples/fhe/simple_integers
```

How To Link Your Own Project After Having Cipher Installed
===================
1. Install Cipher with `cmake --install build` (you may need admin rights, or set `CMAKE_INSTALL_PREFIX`).
2. Go to a new directory where you will keep the "my_own_project.cpp" file.
3. Copy [examples/standalone/CMakeLists.txt](../standalone/CMakeLists.txt) to the new directory.
4. Open CMakeLists.txt for editing and add lines to its end as suggested in the comments in CMakeLists.txt. Something like this:
```
    add_executable(my_own_project my_own_project.cpp)
    target_link_libraries(my_own_project PRIVATE ${CIPHER_LIB})
```
5. Configure, build and run:
```
    cmake -S . -B build -DCMAKE_PREFIX_PATH=<Cipher install prefix>
    cmake --build build
    ./build/my_own_project
```

Generating a CryptoContext using make_crypto_context()
===================
1. Pick the scheme you want to use. We use CKKS for this tutorial example.
2. Include `cipher/cipher.h`\
    **NOTE for Cipher contributors**\
    Inside the library, instead of including `cipher/cipher.h`, your code should include `cipher/fhe/context_gen.h` and the header with the scheme-specific context generator (`cipher/fhe/<scheme>/context_gen.h`). Example:
```
    #include "cipher/fhe/ckks/context_gen.h"
    #include "cipher/fhe/context_gen.h"
```
3. Create a parameter object to be passed to make_crypto_context(). Its generic form is `ContextParams<GeneratorName>`, where GeneratorName is the name of the class defined in `cipher/fhe/<scheme>/context_gen.h` (`BfvRnsContext`, `BgvRnsContext` or `CkksRnsContext`). In our case it is `CkksRnsContext` and the line to add is
```
    ContextParams<CkksRnsContext> parameters;
    // std::cout << parameters << std::endl;  // prints all parameter values
```
4. Adjust the parameters' values with the set functions of `ContextParams<CkksRnsContext>`, as the object is created using default values from [cipher/fhe/config/params_defaults.h](../../include/cipher/fhe/config/params_defaults.h). The set functions can be found in [cipher/fhe/config/params.h](../../include/cipher/fhe/config/params.h). For example, we can set the multiplicative depth to be 1 as shown below.
```
    parameters.set_multiplicative_depth(1);
```
5. Call make_crypto_context() to generate the cryptocontext.
```
    auto crypto_context = make_crypto_context(parameters);
```
6. Enable the features that we want to use. For example, if we want to perform an encrypted rotation, then we need encryption, key switching, and leveled somewhat homomorphic encryption (SHE) operations.
```
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
```

Now your code should look like this:
```
    #include "cipher/cipher.h"
    using namespace cipher;
    ...........................................
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(8);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(16);

    auto crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    ...........................................
```

## Description of the CryptoContext parameters and their restrictions
Choosing the CryptoContext parameters is important for obtaining the best performance for your encrypted application, while maintaining the desired level of security. We strongly recommend that you specify the security level and have Cipher automatically select the other parameters, unless you are an expert in homomorphic encryption. If you would like to modify the parameters to understand how they affect noise growth and performance, we provide descriptions below.

The default values for all the parameters can be found in [params_defaults.h](../../include/cipher/fhe/config/params_defaults.h)

If the set function is called for a parameter which is not available for the given scheme, then an exception will be thrown at run-time.

**PlaintextModulus ptModulus (BGV/BFV only)** - impacts noise growth and has to be set by user as it can not be zero. The set method is `set_plaintext_modulus`.

**uint32_t digitSize** - used in digit decomposition and impacts noise growth. The set method is `set_digit_size`.

**float standardDeviation** - error distribution parameter (recommended for advanced users), used for Gaussian error generation. The set method is `set_standard_deviation`.

**SecretKeyDist secretKeyDist** - secret key distribution: GAUSSIAN, UNIFORM_TERNARY, SPARSE_TERNARY, SPARSE_ENCAPSULATED. The set method is `set_secret_key_dist`. For CKKS bootstrapping, SPARSE_ENCAPSULATED is recommended (probability of failure below 2^-128); UNIFORM_TERNARY can be used when uniform ternary secrets are required (probability of failure 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing); SPARSE_TERNARY is discouraged (about 2^-23 for N = 2^16). See [CKKS_BOOTSTRAPPING.md](CKKS_BOOTSTRAPPING.md).

**uint32_t maxRelinSkDeg** - max relinearization degree of secret key polynomial (used for lazy relinearization). The set method is `set_max_relin_sk_deg`.

**KeySwitchTechnique ksTech**:  BV or HYBRID. The set method is `set_key_switch_technique`.
- For BV, we do not have extra modulus, so the security depends on ciphertext modulus Q
- For BV, we need digitSize - digit size in digit decomposition
- For HYBRID, we do have an extra modulus P, so the security depends on modulus P*Q
- For HYBRID, we need numLargeDigits - number of digits in digit decomposition

**ScalingTechnique scalTech (CKKS/BGV only)** - rescaling/modulus switching technique: FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO (CKKS only), COMPOSITESCALINGMANUAL (CKKS only). NORESCALE is not allowed (used for BFV internally). See https://eprint.iacr.org/2022/915 for additional details. The set method is `set_scaling_technique`.

**uint32_t batchSize** - max batch size of messages to be packed in encoding (number of slots). The set method is `set_batch_size`.

**ProxyReEncryptionMode PREMode** - PRE security mode: NOT_SET (the default), INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA. With the default NOT_SET, proxy re-encryption is disabled and `re_key_gen`/`re_encrypt` throw for HYBRID key switching, so the mode has to be set explicitly to use PRE. NOISE_FLOODING_HRA supported only in BGV for scaleTech=FIXEDMANUAL. The set method is `set_pre_mode`.

**MultipartyMode multipartyMode (BFV/BGV only)** - multiparty security mode. The NOISE_FLOODING_MULTIPARTY mode adds extra noise and gives enhanced security compared to the FIXED_NOISE_MULTIPARTY mode. Not available for CKKS, but FIXED_NOISE_MULTIPARTY is used for CKKS internally. The set method is `set_multiparty_mode`.

**DecryptionNoiseMode decryptionNoiseMode (CKKS only)** - NOISE_FLOODING_DECRYPT mode is more secure (provable secure) than FIXED_NOISE_DECRYPT, but it requires executing all computations twice. The set method is `set_decryption_noise_mode`.

**ExecutionMode executionMode (CKKS only)** - The execution mode is only used in NOISE_FLOODING_DECRYPT mode. The set method is `set_execution_mode`.
- EXEC_NOISE_ESTIMATION - we estimate the noise we need to add to the actual computation to guarantee good security.
- EXEC_EVALUATION - we input our noise estimate and perform the desired secure encrypted computation.
- Although not available for BGV/BFV, EXEC_EVALUATION is used for these schemes internally.

**double noiseEstimate (CKKS only)** - This estimate is obtained from running the computation in EXEC_NOISE_ESTIMATION mode. It is only used in the NOISE_FLOODING_DECRYPT mode. The set method is `set_noise_estimate`.

**double desiredPrecision (CKKS only)** - desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling factor. The set method is `set_desired_precision`.

**uint32_t statisticalSecurity (BGV/CKKS only)** - statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success that any adversary can have. Specifically, they have a probability of success of at most 2^(-statisticalSecurity). Used for BGV when PREMode=NOISE_FLOODING_HRA and for CKKS when multipartyMode=NOISE_FLOODING_MULTIPARTY. The set method is `set_statistical_security`.

**uint32_t numAdversarialQueries (BGV/CKKS only)** - this is the number of adversarial queries a user is expecting for their application, which we use to ensure security of CKKS in NOISE_FLOODING_DECRYPT mode. Used for BGV when PREMode=NOISE_FLOODING_HRA and for CKKS when multipartyMode=NOISE_FLOODING_MULTIPARTY. The set method is `set_num_adversarial_queries`.

**uint32_t thresholdNumOfParties (BGV/BFV only)** - number of parties in a threshold application, which is used for the bound on the joint secret key. The set method is `set_threshold_num_of_parties`.

**uint32_t firstModSize (CKKS/BGV only) and uint32_t scalingModSize** - are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q':
- q_0 is first prime, and it's number of bits is firstModSize
- q_i have same number of bits and is equal to scalingModSize
- the prime q' is not explicitly given, but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
- **firstModSize** is allowed for BGV with **scalTech = FIXEDMANUAL** only
- **scalingModSize** is allowed for BGV with **scalTech = FIXEDMANUAL** and **scalingModSize** must be < 60 for CKKS and `CIPHER_NATIVE_SIZE=64`
- **firstModSize and scalingModSize** are not available for BGV if PREMode=NOISE_FLOODING_HRA.

The set methods are `set_first_mod_size` and `set_scaling_mod_size`.

**uint32_t numLargeDigits** - number of digits in HYBRID key switching (see KeySwitchTechnique). The set method is `set_num_large_digits`.

**uint32_t multiplicativeDepth** - the maximum number of multiplications (in a binary tree manner) we can perform before bootstrapping. Must be 0 for BGV if PREMode=NOISE_FLOODING_HRA. The set method is `set_multiplicative_depth`.

**SecurityLevel securityLevel** - We use the values from the security standard at http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf for ring dimensions up to 32K, and from https://cic.iacr.org/p/1/4/26/pdf for 64K and 128K. Given the ring dimension and security level, we have upper bound of possible highest modulus (Q for BV or P*Q for HYBRID). The set method is `set_security_level`.

**uint32_t ringDim** - ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1). Must be > 0 for BGV if PREMode=NOISE_FLOODING_HRA. The set method is `set_ring_dim`.

**uint32_t evalAddCount (BGV/BFV only)** - maximum number of additions (used for setting noise). In BGV, it is the maximum number of additions at any level. The set method is `set_eval_add_count`.

**EncryptionTechnique encryptionTechnique (BFV only)** - STANDARD or EXTENDED mode for BFV encryption; EXTENDED slightly reduces the size of Q (by few bits) but makes encryption somewhat slower (see https://eprint.iacr.org/2022/915 for details). Although not available for CKKS/BGV, STANDARD is used for these 2 schemes internally. The set method is `set_encryption_technique`.

**MultiplicationTechnique multiplicationTechnique (BFV only)** - multiplication method in BFV: BEHZ, HPS, HPSPOVERQ, HPSPOVERLEVELED (see https://eprint.iacr.org/2022/915 for details). The set method is `set_multiplication_technique`.

**uint32_t keySwitchCount (BGV/BFV only)** - maximum number of key switching operations (used for setting noise). The set method is `set_key_switch_count`.

**uint32_t PRENumHops (BGV only)** - number of hops supported for PRE in the provable HRA setting:
- used only with multipartyMode=NOISE_FLOODING_MULTIPARTY
- if PREMode=NOISE_FLOODING_HRA, then **PRENumHops** must be > 0

The set method is `set_pre_num_hops`.

**CompressionLevel interactiveBootCompressionLevel (CKKS only)** - interactive multi-party bootstrapping parameter which sets the compression level in ciphertext to SLACK (has weaker security assumption, thus less efficient) or COMPACT (has stronger security assumption, thus more efficient).  The set method is `set_interactive_boot_compression_level`.

**uint32_t registerWordSize (CKKS only)** - register word size for the CKKS composite scaling mode (should match the hardware architecture on which the FHE computation will be run). The word size should be between 20 and 64. The actual moduli are determined by evenly splitting the scaling factor into approximately equal moduli, which cannot be not higher than the register word size. The set method is `set_register_word_size`.

**uint32_t compositeDegree (CKKS only)** - specifies how many words should be used to represent the CKKS scaling factor in the CKKS composite scaling mode. This setting is only used for the COMPOSITESCALINGMANUAL scaling techique. The supported values are 1, 2, 3, and 4. The set method is `set_composite_degree`.

**CKKSDataType ckksDataType (CKKS only)** - defines the CKKS data type: COMPLEX (for complex numbers) or REAL (for real numbers). If the mode is COMPLEX, dynamic noise estimation is disabled; and the user has to set the noise using `set_noise_estimate` if $IND-CPA^D$ security is desired. If the mode is REAL, the dynamic noise is estimated using the imaginary component (this matches the behavior of upstream OpenFHE versions below 1.3.0). The set method is `set_ckks_data_type`.
