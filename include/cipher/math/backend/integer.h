//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This file contains the interfaces for the math integer data types
 */

#ifndef CIPHER_MATH_BACKEND_INTEGER_H_
#define CIPHER_MATH_BACKEND_INTEGER_H_

#include <cstdint>
#include <string>

#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * @brief Interface (CRTP base) implemented by every big-integer backend; T is the derived
 * integer type. Naming conventions: the plain method returns a new value, the "Eq" suffix
 * performs the operation in place on *this and returns *this, and "Fast" variants skip the
 * reduction of their inputs (the operands must already be < modulus). The "Barrett"
 * overloads take mu, the value precomputed by compute_mu() for the modulus.
 * @tparam T the derived big-integer type
 */
template <typename T>
class BigIntegerInterface {
  public:
    // CONSTRUCTORS

    // Constructors must be implemented in the derived classes
    // There are no base class constructors that need to be called

    // The derived classes should implement constructors from uint64_t,
    // NativeInteger, and strings There should be copy and move constructors, as
    // well as copy and move assignment

    /**
     * Set from a string
     *
     * @param str is the string representation of the value
     */
    void set_value(const std::string& str);

    // ARITHMETIC OPERATIONS

    /**
     * Addition operation.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    T add(const T& b) const;

    /**
     * Addition operation. In-place variant.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    T& add_eq(const T& b);

    /// inline operators for the addition operation.
    friend T operator+(const T& a, const T& b) {
        return a.add(b);
    }
    /// inline in-place operator for the addition operation.
    friend T& operator+=(T& a, const T& b) {
        return a.add_eq(b);
    }

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    T sub(const T& b) const;

    /**
     * Subtraction operation. In-place variant.
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    T& sub_eq(const T& b);

    /// inline operators for the subtraction operation.
    friend T operator-(const T& a, const T& b) {
        return a.sub(b);
    }
    /// inline in-place operator for the subtraction operation.
    friend T& operator-=(T& a, const T& b) {
        return a.sub_eq(b);
    }

    /**
     * Multiplication operation.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    T mul(const T& b) const;

    /**
     * Multiplication operation. In-place variant.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    T& mul_eq(const T& b);

    /// inline operators for the multiplication operation.
    friend T operator*(const T& a, const T& b) {
        return a.mul(b);
    }
    /// inline in-place operator for the multiplication operation.
    friend T& operator*=(T& a, const T& b) {
        return a.mul_eq(b);
    }

    /**
     * Division operation.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    T divided_by(const T& b) const;

    /**
     * Division operation. In-place variant.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    T& divided_by_eq(const T& b);

    /// inline operators for the division operation.
    friend T operator/(const T& a, const T& b) {
        return a.divided_by(b);
    }
    /// inline in-place operator for the division operation.
    friend T& operator/=(T& a, const T& b) {
        return a.divided_by_eq(b);
    }

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    T multiply_and_round(const T& p, const T& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    T& multiply_and_round_eq(const T& p, const T& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    T divide_and_round(const T& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    T& divide_and_round_eq(const T& q);

    // MODULAR ARITHMETIC OPERATIONS

    /**
     * Naive modulus operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    T mod(const T& modulus) const;

    /**
     * Naive modulus operation. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    T& mod_eq(const T& modulus);

    /// inline operators for the modulus operation.
    friend T operator%(const T& a, const T& b) {
        return a.mod(b);
    }
    /// inline in-place operator for the modulus operation.
    friend T& operator%=(T& a, const T& b) {
        return a.mod_eq(b);
    }

    /**
     * Precomputes a parameter mu for Barrett modular reduction.
     *
     * @return the precomputed parameter mu.
     */
    T compute_mu() const;

    /**
     * Barrett modulus operation.
     * Implements generalized Barrett modular reduction algorithm. Uses one
     * precomputed value of mu.
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    T mod(const T& modulus, const T& mu) const;

    /**
     * Barrett modulus operation using the precomputed value mu. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    T& mod_eq(const T& modulus, const T& mu);

    /**
     * Modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    T mod_add(const T& b, const T& modulus) const;

    /**
     * Modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    T& mod_add_eq(const T& b, const T& modulus);

    /**
     * Modulus addition where operands are < modulus.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    T mod_add_fast(const T& b, const T& modulus) const;

    /**
     * Modulus addition where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    T& mod_add_fast_eq(const T& b, const T& modulus);

    /**
     * Barrett modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    T mod_add(const T& b, const T& modulus, const T& mu) const;

    /**
     * Barrett modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    T& mod_add_eq(const T& b, const T& modulus, const T& mu);

    /**
     * Modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    T mod_sub(const T& b, const T& modulus) const;

    /**
     * Modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    T& mod_sub_eq(const T& b, const T& modulus);

    /**
     * Modulus subtraction where operands are < modulus.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    T mod_sub_fast(const T& b, const T& modulus) const;

    /**
     * Modulus subtraction where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    T& mod_sub_fast_eq(const T& b, const T& modulus);

    /**
     * Barrett modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    T mod_sub(const T& b, const T& modulus, const T& mu) const;

    /**
     * Barrett modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    T& mod_sub_eq(const T& b, const T& modulus, const T& mu);

    /**
     * Modulus multiplication operation.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul(const T& b, const T& modulus) const;

    /**
     * Modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_eq(const T& b, const T& modulus);

    /**
     * Barrett modulus multiplication.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul(const T& b, const T& modulus, const T& mu) const;

    /**
     * Barrett modulus multiplication. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_eq(const T& b, const T& modulus, const T& mu);

    /**
     * Modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul_fast(const T& b, const T& modulus) const;

    /**
     * Modulus multiplication that assumes the operands are < modulus. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_fast_eq(const T& b, const T& modulus);

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul_fast(const T& b, const T& modulus, const T& mu) const;

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_fast_eq(const T& b, const T& modulus, const T& mu);

    /**
     * NTL-optimized modular multiplication using a precomputation for the
     * multiplicand. Assumes operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param b_inv NTL precomputation for b.
     * @return is the result of the modulus multiplication operation.
     */
    T mod_mul_fast_const(const T& b, const T& modulus, const T& b_inv) const;

    /**
     * NTL-optimized modular multiplication using a precomputation for the
     * multiplicand. Assumes operands are < modulus. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param b_inv NTL precomputation for b.
     * @return is the result of the modulus multiplication operation.
     */
    T& mod_mul_fast_const_eq(const T& b, const T& modulus, const T& b_inv);

    /**
     * Modulus exponentiation operation.
     *
     * @param b is the exponent.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    T mod_exp(const T& b, const T& modulus) const;

    /**
     * Modulus exponentiation operation. In-place variant.
     *
     * @param b is the exponent.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    T& mod_exp_eq(const T& b, const T& modulus);

    /**
     * Modulus inverse operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    T mod_inverse(const T& modulus) const;

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    T& mod_inverse_eq(const T& modulus);

    // SHIFT OPERATIONS

    /**
     * Left shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    T l_shift(uint16_t shift) const;

    /**
     * Left shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    T& l_shift_eq(uint16_t shift);

    /// inline operators for the left shift operations.
    friend T operator<<(const T& a, uint16_t shift) {
        return a.l_shift(shift);
    }
    /// inline in-place operator for the left shift operation.
    friend T& operator<<=(T& a, uint16_t shift) {
        return a.l_shift_eq(shift);
    }

    /**
     * Right shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    T r_shift(uint16_t shift) const;

    /**
     * Right shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    T& r_shift_eq(uint16_t shift);

    /// inline operators for the right shift operations.
    friend T operator>>(const T& a, uint16_t shift) {
        return a.r_shift(shift);
    }
    /// inline in-place operator for the right shift operation.
    friend T& operator>>=(T& a, uint16_t shift) {
        return a.r_shift_eq(shift);
    }

    /**
     * Compares the current BigInteger to BigInteger a.
     *
     * @param a is the BigInteger to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
     * greater than conditions.
     */
    int Compare(const T& a) const;

    //// relational operators, using Compare
    /// equality, using Compare
    friend bool operator==(const T& a, const T& b) {
        return a.Compare(b) == 0;
    }
    /// inequality, using Compare
    friend bool operator!=(const T& a, const T& b) {
        return a.Compare(b) != 0;
    }
    /// strictly greater than, using Compare
    friend bool operator>(const T& a, const T& b) {
        return a.Compare(b) > 0;
    }
    /// greater than or equal to, using Compare
    friend bool operator>=(const T& a, const T& b) {
        return a.Compare(b) >= 0;
    }
    /// strictly less than, using Compare
    friend bool operator<(const T& a, const T& b) {
        return a.Compare(b) < 0;
    }
    /// less than or equal to, using Compare
    friend bool operator<=(const T& a, const T& b) {
        return a.Compare(b) <= 0;
    }

    /**
     * Convert the value to an int.
     *
     * @return the int representation of the value.
     */
    uint64_t convert_to_int() const;

    // OTHER FUNCTIONS

    /**
     * Returns the MSB location of the value.
     *
     * @return the index of the most significant bit.
     */
    uint32_t get_msb() const;

    /**
     * Get the number of digits using a specific base - support for arbitrary base
     * may be needed.
     *
     * @param base is the base with which to determine length in.
     * @return the length of the representation in a specific base.
     */
    uint32_t get_length_for_base(uint32_t base) const;

    /**
     * Get the digit at a specific index using a specific base - support for arbitrary base
     * may be needed. Example: for number 83, index 2 and base 4 we have:
     *
     *                         index:0,1,2,3
     * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
     *
     * The return number is 1.
     *
     * @param index is the location to return value from in the specific base.
     * @param base is the base of the digit decomposition.
     * @return the digit at the specific index in the specific base.
     */
    uint32_t get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    // STRINGS

    // The derived classes MAY implement std::ostream& operator<< but are not
    // required to

    /**
     * Convert this integer into a std::string, for serialization
     *
     * @return the value of this T as a string.
     */
    const std::string to_string() const;

  protected:
    ~BigIntegerInterface() = default;

    // SERIALIZATION
};

// TODO
class BigMatrixInterface {};
}  // namespace cipher

#endif  // CIPHER_MATH_BACKEND_INTEGER_H_
