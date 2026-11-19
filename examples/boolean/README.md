# Boolean FHE Examples

This folder contains examples of the Boolean FHE module (`Cipher::boolean`, header
`cipher/boolean/context.h`, class `BooleanContext`). For further details about the module, see the
[Boolean FHE documentation](../../docs/sphinx_rsts/modules/binfhe.rst).

The examples are built when `CIPHER_BUILD_EXAMPLES=ON` (the default). Each source file becomes one
executable named after the file: `<build>/bin/examples/boolean/<name>` for the files in this folder and
`<build>/bin/examples/boolean/pke/<name>` for the files in [`pke/`](pke).

At a high level:

- GINX Bootstrapping:
  - [`boolean.cpp`](boolean.cpp)
    - bootstrapping as described
      in [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/421) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)
  - [`pke/boolean_pke.cpp`](pke/boolean_pke.cpp)
    - Public Key Encryption (PKE) version of the `boolean.cpp` example
  - [`boolean_multi_input.cpp`](boolean_multi_input.cpp)
    - evaluates gates with more than two inputs

- AP Bootstrapping:
  - [`boolean_ap.cpp`](boolean_ap.cpp)
    - bootstrapping as described
      in [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816.pdf) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)
  - [`pke/boolean_ap_pke.cpp`](pke/boolean_ap_pke.cpp)
    - PKE version of the `boolean_ap.cpp` example

- LMKCDEY Bootstrapping:
  - [`boolean_lmkcdey.cpp`](boolean_lmkcdey.cpp)
    - bootstrapping as described in [Efficient FHEW Bootstrapping with Small Evaluation Keys, and Applications to Threshold Homomorphic Encryption](https://eprint.iacr.org/2022/198)

- Boolean Serialization - binary format:
    - [`boolean_serial_binary.cpp`](boolean_serial_binary.cpp)
    - [`pke/boolean_serial_binary_pke.cpp`](pke/boolean_serial_binary_pke.cpp)
        - PKE version of the `boolean_serial_binary.cpp` example

- Boolean Serialization - json format:
    - [`boolean_serial_json.cpp`](boolean_serial_json.cpp)
    - [`pke/boolean_serial_json_pke.cpp`](pke/boolean_serial_json_pke.cpp)
        - PKE version of the `boolean_serial_json.cpp` example

- Boolean Truth Tables:
    - [`boolean_truth_tables.cpp`](boolean_truth_tables.cpp)
        - prints out the truth tables for all supported binary gates
    - [`pke/boolean_truth_tables_pke.cpp`](pke/boolean_truth_tables_pke.cpp)
        - PKE version of the `boolean_truth_tables.cpp` example

Examples below are based on the functionalities described
in [Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337)

Note that for these advanced features, only GINX bootstrapping with 128-bit security (and toy security) is supported. To use these features, `BooleanContext::generate_boolean_context` needs to be called with at least two parameters: security parameter and whether arbitrary function evaluation is needed. For homomorphic sign evaluation and homomorphic digit decomposition, the large precision Q also needs to be specified. Please see the examples for details.

- Eval Decomposition: [`eval_decomp.cpp`](eval_decomp.cpp)
    - runs a homomorphic digit decomposition process on the input ciphertext (`eval_decomp`)

- Eval Flooring:
    - [`eval_flooring.cpp`](eval_flooring.cpp)
        - rounds down the input ciphertext by certain number of bits (`eval_floor`)
    - [`pke/eval_flooring_pke.cpp`](pke/eval_flooring_pke.cpp)
        - PKE version of the `eval_flooring.cpp` example

- Eval Function:
    - [`eval_function.cpp`](eval_function.cpp)
        - evaluates a function _f: Z<sub>p</sub> -> Z<sub>p</sub>_ on the input ciphertext (`eval_func`)
    - [`pke/eval_function_pke.cpp`](pke/eval_function_pke.cpp)
        - PKE version of the `eval_function.cpp` example

- Eval Sign: [`eval_sign.cpp`](eval_sign.cpp)
    - evaluates the most-significant bit of the input ciphertext (`eval_sign`)

- Serialization for a larger precision scenario - binary format: [`boolean_serial_binary_dynamic_large_precision.cpp`](boolean_serial_binary_dynamic_large_precision.cpp)

- Serialization for a larger precision scenario - json format: [`boolean_serial_json_dynamic_large_precision.cpp`](boolean_serial_json_dynamic_large_precision.cpp)
