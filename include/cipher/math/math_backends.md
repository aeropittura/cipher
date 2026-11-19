# Math Backends

- By selecting a particular `CIPHER_MATH_BACKEND`, we are choosing a default implementation for:
    - `BigInteger`
    - `BigVector`
    - `Poly` and `ciphertext modulus` used in `RnsPoly`

- For native arithmetic, `NativeInteger` and `NativeVector` is available.

- All implementations for Big/Native Integer/Vector are based on [integer.h](backend/integer.h).

## Design

**Goal**: Support choosing, at **run-time**, which math backend to use.

**Currently**: **Compile-time** choice of which backend to use

## Choosing a Backend

- Set the CMake option at configure time: `cmake -S . -B build -DCIPHER_MATH_BACKEND=4`
  (2, 4 or 6; the default is 4). The selection is implemented in [backend/big_int_backend.h](backend/big_int_backend.h).
- Backends other than the default can additionally be compiled in with `CIPHER_WITH_BE2=ON`, `CIPHER_WITH_BE4=ON`
  or `CIPHER_WITH_NTL=ON` (backend 6).

## Math Backend Descriptions

### CIPHER_MATH_BACKEND=2 (fixed-width, [backend/fixed](backend/fixed))

- Max size of `BigInteger` will be `BigIntegerBitLength` (defined in [backend/fixed/integer.h](backend/fixed/integer.h)), which has a default of 3500 bits (8000 bits for `CIPHER_NATIVE_SIZE=128`).
- It is advisable to select a value for `BigIntegerBitLength` larger than double the `bitwidth` of the largest (
  ciphertext) modulus.
- This parameter can be decreased for runtime/space optimization when the largest modulus is under 1500 bits.

- **Note**: The underlying implementation is fixed-size array of native ints.
    - Native integer used is defined by the `typedef` using `integral_dtype` and MUST be `uint32_t`; using other types
      is an open work item

### CIPHER_MATH_BACKEND=4 (dynamic, [backend/dynamic](backend/dynamic))

- No Explicit max size of `BigInteger`
- Size grows dynamically and is only constrained by memory
- The implementation (`ubint<limb_t>` in [backend/dynamic/integer.h](backend/dynamic/integer.h)) uses 32-bit limbs
- **Note**: 64-bit limbs are not supported. It is however an open work item.

### CIPHER_MATH_BACKEND=6 (NTL, [backend/ntl](backend/ntl))

- Integration of the `NTL` library with Cipher (`NtlInteger`, `NtlModVector`)
- Only available when Cipher is configured with `-DCIPHER_WITH_NTL=ON`, which requires NTL and GMP to be installed

# Supported Math Operations

## Modular Multiplication

We use the following naming conventions:

- `mod_mul(b, mod_value)`
    - Naive modular multiplication that uses % operator for modular reduction
    - usually slow.

- `mod_mul(b, mod_value, mu)`
    - Barrett modular multiplication. `mu` for Barrett modulo can be precomputed by `mod_value.compute_mu()`.

- `mod_mul_fast(b, mod_value)`
    - Naive modular multiplication w/ operands < mod

- `mod_mul_fast(b, mod_value, mu)`
    - Barrett modular multiplication w/ operands < mod

- `mod_mul_fast_const(b, mod_value, bPrecomp)`
    - modular multiplication using precomputed information on b, w/ operands < mod.
    - `bPrecomp` can be precomputed by `b.prep_mod_mul_const(mod_value)`.
    - This method is currently implemented only for NativeInteger class.
    - The fastest method.

## Other Modular Operations

| Variant | Naive          | Barrett            | Fast Naive         | Fast Barrett           | Fast Const                        |
|---------|----------------|--------------------|--------------------|------------------------|-----------------------------------|
| mod     | mod(m)          | mod(m, mu)          | -                    | -                        | -                                       |
| mod_add | mod_add(b, m)   | mod_add(b, m, mu)   | mod_add_fast(b, m)   | -                        | -                                       |
| mod_sub | mod_sub(b, m)   | mod_sub(b, m, mu)   | mod_sub_fast(b, m)   | -                        | -                                       |
| mod_mul | mod_mul(b, m)   | mod_mul(b, m, mu)   | mod_mul_fast(b, m)   | mod_mul_fast(b, m, mu)   | mod_mul_fast_const(b, m, b_precomp)     |
