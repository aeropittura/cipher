.. _quickstart:

Examples
====================================

Cipher provides the following examples which should provide the reader with a basic understanding of how to use the
library for various purposes.


.. contents:: Page Contents
   :local:


Boolean FHE
----------------------------

`Boolean Fully Homomorphic Encryption Examples <../../../examples/boolean>`_

At a high level:

-  `boolean.cpp: GINX (CGGI) Bootstrapping <../../../examples/boolean/boolean.cpp>`__:

   -  bootstrapping as described in `TFHE: Fast Fully Homomorphic
      Encryption over the Torus <https://eprint.iacr.org/2018/421>`__
      and in `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__


-  `boolean_ap.cpp: AP (DM) Bootstrapping <../../../examples/boolean/boolean_ap.cpp>`__:

   -  bootstrapping as described in `FHEW: Bootstrapping Homomorphic
      Encryption in less than a
      second <https://eprint.iacr.org/2014/816.pdf>`__ and in
      `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__

-  `boolean_lmkcdey.cpp: LMKCDEY Bootstrapping <../../../examples/boolean/boolean_lmkcdey.cpp>`__:

   -  bootstrapping as described in `Efficient FHEW Bootstrapping with Small Evaluation Keys, and
      Applications to Threshold Homomorphic Encryption <https://eprint.iacr.org/2022/198.pdf>`__

-  `boolean_serial_binary.cpp: Boolean Serialization <../../../examples/boolean/boolean_serial_binary.cpp>`_:

   - serializing ``CryptoContext``, various keys, and ciphertext to a file in binary format


-  `boolean_serial_json.cpp: Boolean Serialization - json <../../../examples/boolean/boolean_serial_json.cpp>`_:

   - serializing ``CryptoContext``, various keys, and ciphertext to a file in json format


-  `boolean_truth_tables.cpp: Boolean Truth Tables <../../../examples/boolean/boolean_truth_tables.cpp>`_:

   -  prints out the truth tables for all supported binary gates


-  `eval_decomp.cpp: Eval Decomposition <../../../examples/boolean/eval_decomp.cpp>`_:

   -  runs a homomorphic digit decomposition process on the input ciphertext


-  `eval_flooring.cpp: Eval Flooring <../../../examples/boolean/eval_flooring.cpp>`_:

   -  rounds down the input ciphertext by certain number of bits


-  `eval_function.cpp: Eval Function <../../../examples/boolean/eval_function.cpp>`_:

   -  evaluates a function *f: Z_p -> Z_p* on the input ciphertext


-  `eval_sign.cpp: Eval Sign <../../../examples/boolean/eval_sign.cpp>`_:

   -  evaluates the most-significant bit of the input ciphertext


Core
----------------------------

`Core Examples <../../../examples/core>`_:

- `parallel.cpp <../../../examples/core/parallel.cpp>`_:

  - provides an example of parallelization in ``Cipher`` with `OpenMP <https://www.openmp.org/>`_


- `sampling.cpp <../../../examples/core/sampling.cpp>`_:

  - provides an example of doing integer Gaussian sampling using the `Cipher samplers <../../../include/cipher/math>`_.

  - For more information on sampling, read :doc:`sampling documentation <../modules/core/math/sampling>`


FHE - SIMD FHE
----------------------------

`SIMD Fully Homomorphic Encryption Examples <../../../examples/fhe>`_:

Basic Homomorphic Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Demonstrates basic homomorphic encryption using the various schemes:

- `BFVrns (depth_bfvrns.cpp) <../../../examples/fhe/depth_bfvrns.cpp>`_

- `BGVrns (depth_bgvrns.cpp) <../../../examples/fhe/depth_bgvrns.cpp>`_


Simple Mathematical Operations and Serialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Demonstrates the following mathematical operations on vectors of appropriate type (integers in the case of `BGV` and `BFV`, and real numbers in `CKKS`):

- homomorphic additions,
- homomorphic multiplications
- homomorphic rotations

Additionally, we include the variants detailing how to do serialization-deserialization.

**Schemes**:

- `Standard BGV-rns (simple_integers_bgvrns.cpp) <../../../examples/fhe/simple_integers_bgvrns.cpp>`_

- `BGV-rns with Serialization/Deserialization (simple_integers_serial_bgvrns.cpp) <../../../examples/fhe/simple_integers_serial_bgvrns.cpp>`_


- `Standard BFV-rns (simple_integers.cpp) <../../../examples/fhe/simple_integers.cpp>`_

- `BFV-rns with Serialization/Deserialization (simple_integers_serial.cpp) <../../../examples/fhe/simple_integers_serial.cpp>`_


- `Standard CKKS-rns (simple_real_numbers.cpp) <../../../examples/fhe/simple_real_numbers.cpp>`__:

- `CKKS-rns with Serialization/Deserialization (simple_real_numbers_serial.cpp) <../../../examples/fhe/simple_real_numbers_serial.cpp>`_

Advanced CKKS Usage
^^^^^^^^^^^^^^^^^^^^^^^^

Demonstrates advanced operations on real-number vectors using ``CKKS``:

- High-precision CKKS
- Rescaling (automatic and manual)
- hybrid key-switching
- hoisting

**Formats**

-  `Standard-precision Advanced CKKS Examples (advanced_real_numbers.cpp) <../../../examples/fhe/advanced_real_numbers.cpp>`__:

-  `High-precision Advanced CKKS Examples (advanced_real_numbers_128.cpp) <../../../examples/fhe/advanced_real_numbers_128.cpp>`__:

-  `CKKS Bootstrapping with Full Packing (simple_ckks_bootstrapping.cpp) <../../../examples/fhe/simple_ckks_bootstrapping.cpp>`__:

-  `CKKS Bootstrapping with Sparse Packing (advanced_ckks_bootstrapping.cpp) <../../../examples/fhe/advanced_ckks_bootstrapping.cpp>`__:

Misc. Operations across Schemes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  `rotation.cpp <../../../examples/fhe/rotation.cpp>`__:

   - demonstrates the use of ``eval_rotate`` and ``eval_merge`` for different schemes


- `linearwsum_evaluation.cpp <../../../examples/fhe/linearwsum_evaluation.cpp>`_:

  - demonstrates the process of taking the linear weighted sum of a vector of ciphertexts against a vector of plaintext data in the `CKKS` scheme


-  `polynomial_evaluation.cpp <../../../examples/fhe/polynomial_evaluation.cpp>`__:

   - demonstrates an evaluation of a polynomial (power series) using ``CKKS``

-  `pre_buffer.cpp <../../../examples/fhe/pre_buffer.cpp>`__:

   - demonstrates use of Cipher for encryption, re-encryption and decryption of packed vector of binary data


-  `threshold_fhe.cpp <../../../examples/fhe/threshold_fhe.cpp>`__:

   - shows several examples of threshold FHE in ``BGVrns``, ``BFVrns``, and ``CKKSrns``

-  `threshold_fhe_5p.cpp <../../../examples/fhe/threshold_fhe_5p.cpp>`__:

   - shows example of threshold FHE with 5 parties in ``BFVrns``
