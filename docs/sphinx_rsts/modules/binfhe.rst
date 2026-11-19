Boolean FHE (cipher/boolean) documentation
===========================================

.. contents:: Page Contents
   :local:

The ``Cipher::boolean`` library (headers in `include/cipher/boolean <../../../include/cipher/boolean>`_, implementation in `source/boolean <../../../source/boolean>`_, examples in `examples/boolean <../../../examples/boolean>`_) implements the following Boolean circuit evaluation schemes:

- `Ducas-Micciancio (DM or FHEW) <https://eprint.iacr.org/2014/816.pdf>`_

- `Chillotti-Gama-Georgieva-Izabachene (CGGI or TFHE)  <https://eprint.iacr.org/2018/421.pdf>`_

- `Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo (LMKCDEY)  <https://eprint.iacr.org/2022/198.pdf>`_

`examples/boolean/pke <../../../examples/boolean/pke>`_ implements the public key encryption (pke) version of the boolean examples.

File Listings
-----------------------

`BooleanContext Serialization (context_ser.h) <../../../include/cipher/boolean/context_ser.h>`_

- Adds serialization support to Boolean Circuit FHE

`BooleanContext (context.h) <../../../include/cipher/boolean/context.h>`_

- ``BooleanContext``, the context for the Boolean circuit FHE schemes (include ``cipher/boolean/context.h``).
- A ``BooleanContext`` is the primary object through which we interact with the Boolean FHE capabilities (``generate_boolean_context``, ``key_gen``, ``bt_key_gen``, ``encrypt``, ``eval_bin_gate``, ``decrypt``, ...)

.. note:: various parameter ``enum`` are also provided
- ``BINFHE_PARAMSET`` that defines the security level and parameters
- ``BINFHE_METHOD`` to choose the bootstrapping method: AP (DM/FHEW scheme) or GINX (CGGI/TFHE scheme)
- ``BINFHE_OUTPUT`` specifies whether fresh ciphertext should be bootstrapped. The FRESH and BOOTSTRAPPED are now obsolete but kept for backward compatibility. This option is now used to specify LARGE_DIM (ciphertext of dimension N) or SMALL_DIM (ciphertext of dimension n after modswitch and keyswitch)
- ``KEYGEN_MODE`` specifies if a public key along with the bootstrapping keys are generated

`DM/CGGI Cryptosystem (base_scheme.h) <../../../include/cipher/boolean/base_scheme.h>`_

- The main cryptosystem implementation used for DM/CGGI schemes
- The scheme is described in `Bootstrapping in FHEW-like Cryptosystems <https://eprint.iacr.org/2020/086>`_ from Daniele Micciancio and Yuriy Polyakov as published in Cryptology ePrint Archive, Report 2020/086

`Parameters for DM/CGGI Cryptosystem (base_params.h) <../../../include/cipher/boolean/base_params.h>`_

- Stores the parameters for all cryptographic schemes, including LWE, RLWE, and RGSW

`Constants for DM/CGGI Cryptosystem (constants.h) <../../../include/cipher/boolean/constants.h>`_

- Defines all options for ``BINFHE_PARAMSET``, ``BINFHE_METHOD``, and ``BINFHE_OUTPUT`` enums

`LWE Ciphertext (lwe_ciphertext.h) <../../../include/cipher/boolean/lwe_ciphertext.h>`_

`LWE Crypto Parameters (lwe_params.h) <../../../include/cipher/boolean/lwe_params.h>`_

`LWE Switching Key (lwe_switch_key.h) <../../../include/cipher/boolean/lwe_switch_key.h>`_

`LWE Scheme (lwe_pke.h) <../../../include/cipher/boolean/lwe_pke.h>`_

`LWE Private Key (lwe_private_key.h) <../../../include/cipher/boolean/lwe_private_key.h>`_

`LWE Public Key (lwe_public_key.h) <../../../include/cipher/boolean/lwe_public_key.h>`_

`LWE Key Pair (lwe_key_pair.h) <../../../include/cipher/boolean/lwe_key_pair.h>`_

`Parent RGSW Accumulator Scheme (rgsw_acc.h) <../../../include/cipher/boolean/rgsw_acc.h>`_

`CGGI RGSW Accumulator Scheme (rgsw_acc_cggi.h) <../../../include/cipher/boolean/rgsw_acc_cggi.h>`_

`DM RGSW Accumulator Scheme (rgsw_acc_dm.h) <../../../include/cipher/boolean/rgsw_acc_dm.h>`_

`RGSW Refreshing Key (rgsw_acc_key.h) <../../../include/cipher/boolean/rgsw_acc_key.h>`_

`RGSW Crypto Parameters (rgsw_params.h) <../../../include/cipher/boolean/rgsw_params.h>`_

`RGSW Evaluation Key/Ciphertext (rgsw_eval_key.h) <../../../include/cipher/boolean/rgsw_eval_key.h>`_

`RLWE Ciphertext (rlwe_ciphertext.h) <../../../include/cipher/boolean/rlwe_ciphertext.h>`_
