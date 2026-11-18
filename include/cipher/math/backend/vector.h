//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  This file contains the interfaces for the math vector data types
 */

#ifndef CIPHER_MATH_BACKEND_VECTOR_H_
#define CIPHER_MATH_BACKEND_VECTOR_H_

#include <cstdint>
#include <initializer_list>
#include <string>

#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * @brief Interface (CRTP base) implemented by every vector-of-integers backend: a vector of
 * residues sharing one modulus. T is the derived vector type and I its integer type. Naming
 * conventions: the plain method returns a new vector, the "Eq" suffix performs the
 * operation in place on *this and returns *this, and "NoCheck" variants skip the length and
 * modulus compatibility checks of the checked forms.
 * @tparam T the derived vector type
 * @tparam I the integer type of the entries
 */
template <typename T, typename I>
class BigVectorInterface {
  public:
    /// the integer type of the vector entries
    typedef I Integer;

    // CONSTRUCTORS

    // Constructors should be implemented in the derived classes
    // The derived classes should implement constructors from initializer lists of
    // integers and strings

    // ASSIGNMENT OPERATORS

    /**
     * Copy assignment operator.
     *
     * @param vec is the vector to be assigned from.
     * @return assigned vector ref.
     */
    T& operator=(const T& vec);

    /**
     * Move assignment operator.
     *
     * @param vec is the vector to be assigned from.
     * @return assigned vector ref.
     */
    T& operator=(T&& vec);

    /**
     * Assignment operator from initializer list of strings.
     *
     * @param strvec is the list of strings.
     * @return assigned vector ref.
     */
    T& operator=(std::initializer_list<std::string> strvec);

    /**
     * Assignment operator from initializer list of unsigned integers.
     *
     * @param vec is the list of integers.
     * @return assigned vector ref.
     */
    T& operator=(std::initializer_list<uint64_t> vec);

    /**
     * Assignment operator to assign value val to first entry, 0 for the rest of
     * entries.
     *
     * @param val is the unsigned integer the first entry to be assigned from.
     * @return assigned vector ref.
     */
    T& operator=(uint64_t val);

    // EQUALS OPERATORS

    /**
     * Equals to operator.
     *
     * @param a is the first vector to be compared.
     * @param b is the second vector to be compared.
     * @return true if equal and false otherwise.
     */
    friend inline bool operator==(const T& a, const T& b) {
        if ((a.get_length() != b.get_length()) || (a.get_modulus() != b.get_modulus())) {
            return false;
        }
        for (uint32_t i = 0; i < a.get_length(); ++i) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Not equal to operator.
     *
     * @param a is the first vector to be compared.
     * @param b is the second vector to be compared.
     * @return true if not equal and false otherwise.
     */
    friend inline bool operator!=(const T& a, const T& b) {
        return !(a == b);
    }

    // ACCESSORS

    // The derived class must implement at and operator[]

    /**
     * Range-checked access to an entry.
     *
     * @param idx is the index of the entry.
     * @return reference to the entry at the index; throws if idx is out of range.
     */
    I& at(size_t idx);

    /**
     * Range-checked read access to an entry.
     *
     * @param idx is the index of the entry.
     * @return const reference to the entry at the index; throws if idx is out of range.
     */
    const I& at(size_t idx) const;

    /**
     * Unchecked access to an entry.
     *
     * @param idx is the index of the entry.
     * @return reference to the entry at the index; no range check is performed.
     */
    I& operator[](size_t idx);

    /**
     * Unchecked read access to an entry.
     *
     * @param idx is the index of the entry.
     * @return const reference to the entry at the index; no range check is performed.
     */
    const I& operator[](size_t idx) const;

    /**
     * Sets the vector modulus.
     *
     * @param value is the modulus value to set.
     */
    void set_modulus(const I& value);

    /**
     * Sets the vector modulus and changes the values to match the new modulus.
     *
     * @param value is the modulus value to set.
     */
    void switch_modulus(const I& value);

    /**
     * Sets the vector modulus and reduces every entry modulo the new modulus as a non-negative
     * integer, without the centered (signed) adjustment performed by switch_modulus.
     *
     * @param value is the modulus value to set.
     */
    void lazy_switch_modulus(const I& value);

    /**
     * Fused multiply-accumulate: *this += vec * value (mod the vector modulus), without length
     * or modulus validation. The entries of *this must be reduced; the entries of vec need not
     * be reduced, and value is reduced internally.
     *
     * @param vec is the vector to multiply and accumulate.
     * @param value is the scalar multiplier.
     * @return *this after the accumulation.
     */
    T& mult_acc_eq_no_check(const T& vec, const I& value);

    /**
     * Gets the vector modulus.
     *
     * @return the vector modulus.
     */
    const I& get_modulus() const;

    /**
     * Gets the vector length.
     *
     * @return vector length.
     */
    size_t get_length() const;

    // MODULUS ARITHMETIC OPERATIONS

    /**
     * Vector modulus operator.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    T mod(const I& modulus) const;

    /**
     * Vector modulus operator. In-place variant.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    T& mod_eq(const I& modulus);

    /// inline operators for the modulus operations.
    friend T operator%(const T& a, const I& b) {
        return a.mod(b);
    }
    /// inline in-place operator for the modulus operation.
    friend T& operator%=(T& a, const I& b) {
        return a.mod_eq(b);
    }

    /**
     * Scalar-to-vector modulus addition operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    T mod_add(const I& b) const;

    /**
     * Scalar-to-vector modulus addition operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    T& mod_add_eq(const I& b);

    /// inline operators for the scalar-to-vector modulus addition operations.
    friend T operator+(const T& a, const I& b) {
        return a.mod_add(b);
    }
    /// inline in-place operator for the scalar-to-vector modulus addition.
    friend T& operator+=(T& a, const I& b) {
        return a.mod_add_eq(b);
    }

    /**
     * Scalar modulus addition at a particular index.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    T mod_add_at_index(uint32_t i, const I& b) const;

    /**
     * Scalar modulus addition at a particular index. In-place variant.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    T& mod_add_at_index_eq(uint32_t i, const I& b);

    /**
     * Vector component wise modulus addition.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    T mod_add(const T& b) const;

    /**
     * Vector component wise modulus addition. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    T& mod_add_eq(const T& b);

    /**
     * Vector component wise modulus addition. In-place variant that skips the length and
     * modulus compatibility check of mod_add_eq; b must have the same length and modulus.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    T& mod_add_no_check_eq(const T& b);

    /// inline operators for the vector component wise modulus addition
    /// operations.
    friend T operator+(const T& a, const T& b) {
        return a.mod_add(b);
    }
    /// inline in-place operator for the vector component wise modulus addition.
    friend T& operator+=(T& a, const T& b) {
        return a.mod_add_eq(b);
    }

    /**
     * Scalar-from-vector modulus subtraction operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    T mod_sub(const I& b) const;

    /**
     * Scalar-from-vector modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    T& mod_sub_eq(const I& b);

    /// inline operators for the scalar-from-vector modulus subtraction
    /// operations.
    friend T operator-(const T& a, const I& b) {
        return a.mod_sub(b);
    }
    /// inline in-place operator for the scalar-from-vector modulus subtraction.
    friend T& operator-=(T& a, const I& b) {
        return a.mod_sub_eq(b);
    }

    /**
     * Vector component wise modulus subtraction.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    T mod_sub(const T& b) const;

    /**
     * Vector component wise modulus subtraction. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    T& mod_sub_eq(const T& b);

    /// inline operators for the vector component wise modulus subtraction
    /// operations.
    inline friend T operator-(const T& a, const T& b) {
        return a.mod_sub(b);
    }
    /// inline in-place operator for the vector component wise modulus subtraction.
    inline friend const T& operator-=(T& a, const T& b) {
        return a.mod_sub_eq(b);
    }

    /// inline operator for the unary minus
    inline friend T operator-(const T& a) {
        return a.mod_mul(a.get_modulus() - I(1));
    }

    /**
     * Scalar-to-vector modulus multiplication operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul(const I& b) const;

    /**
     * Scalar-to-vector modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_eq(const I& b);

    /// inline operators for the scalar-to-vector modulus multiplication
    /// operations.
    friend T operator*(const T& a, const I& b) {
        return a.mod_mul(b);
    }
    /// inline in-place operator for the scalar-to-vector modulus multiplication.
    friend T& operator*=(T& a, const I& b) {
        return a.mod_mul_eq(b);
    }

    /**
     * Vector component wise modulus multiplication.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    T mod_mul(const T& b) const;

    /**
     * Vector component wise modulus multiplication. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    T& mod_mul_eq(const T& b);

    /**
     * Vector component wise modulus multiplication. In-place variant that skips the length and
     * modulus compatibility check of mod_mul_eq; b must have the same length and modulus.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication operation.
     */
    T& mod_mul_no_check_eq(const T& b);

    /// inline operators for the vector component wise modulus multiplication
    /// operations.
    friend T operator*(const T& a, const T& b) {
        return a.mod_mul(b);
    }
    /// inline in-place operator for the vector component wise modulus multiplication.
    friend T& operator*=(T& a, const T& b) {
        return a.mod_mul_eq(b);
    }

    /**
     * Scalar modulus exponentiation operation.
     * Computes this[i]^b mod modulus for each component. The exponent is used
     * as given and is not reduced by the vector modulus, matching the scalar
     * mod_exp semantics.
     *
     * @param b is the scalar exponent to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    T mod_exp(const I& b) const;

    /**
     * Scalar modulus exponentiation operation. In-place variant.
     * Computes this[i]^b mod modulus for each component. The exponent is used
     * as given and is not reduced by the vector modulus, matching the scalar
     * mod_exp semantics.
     *
     * @param b is the scalar exponent to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    T& mod_exp_eq(const I& b);

    /**
     * Modulus inverse operation.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    T mod_inverse() const;

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    T& mod_inverse_eq();

    /**
     * Modulus 2 operation, also a least significant bit.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    T mod_by_two() const;

    /**
     * Modulus 2 operation, also a least significant bit. In-place variant.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    T& mod_by_two_eq();

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    T multiply_and_round(const I& p, const I& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    T& multiply_and_round_eq(const I& p, const I& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    T divide_and_round(const I& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    T& divide_and_round_eq(const I& q);

    // OTHER FUNCTIONS

    /**
     * Digit vector at a specific index for all entries for a given number base.
     * Example: for vector (83, 1, 45), index 2 and base 4 we have:
     *
     *                           index:0,1,2,3
     * |83|                           |3,0,1,1|                 |1|
     * |1 | --base 4 decomposition--> |1,0,0,0| --at index 2--> |0|
     * |45|                           |1,3,2,0|                 |2|
     *
     * The return vector is (1,0,2)
     *
     * @param index is the index to return the digit from in all entries.
     * @param base is the base to use for the operation.
     * @return is the digit at a specific index for all entries for a given number
     * base
     */
    T get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

  protected:
    ~BigVectorInterface() = default;

    // STRINGS & STREAMS

    // SERIALIZATION
};

}  // namespace cipher
#endif  // CIPHER_MATH_BACKEND_VECTOR_H_
