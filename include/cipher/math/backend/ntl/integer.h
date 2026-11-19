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
  This file contains the C++ code for implementing the main class for big integers:
  gmpint which replaces BBI and uses NTL
 */

//==================================================================================
// This file is included only if CIPHER_WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================
#ifndef CIPHER_MATH_BACKEND_NTL_INTEGER_H_
#define CIPHER_MATH_BACKEND_NTL_INTEGER_H_

#include <cstdint>

#include "cipher/config.h"
#ifdef CIPHER_WITH_NTL

    #include <NTL/ZZ.h>
    #include <NTL/ZZ_limbs.h>

    #include <exception>
    #include <fstream>
    #include <functional>
    #include <limits>
    #include <memory>
    #include <ostream>
    #include <sstream>
    #include <string>
    #include <type_traits>
    #include <typeinfo>
    #include <vector>

    #include "cipher/math/backend/basic_int.h"
    #include "cipher/math/backend/integer.h"
    #include "cipher/util/debug.h"
    #include "cipher/util/diagnostic_output.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/memory.h"
    #include "cipher/util/base64.h"
    #include "cipher/util/parallel.h"
    #include "cipher/util/serializable.h"

/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL {

// forward declaration for aliases
class NtlInteger;

// Create default type for the CIPHER_MATH_BACKEND 6 integer
using BigInteger = NtlInteger;

// log2 constants
/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 *
 * @tparam N bitwidth.
 */
template <uint32_t N>
struct Log2 {
    static const uint32_t value = 1 + Log2<N / 2>::value;
};

/**
 * @brief Struct to find log 2 value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 */
template <>
struct Log2<2> {
    static const uint32_t value = 1;
};

class NtlInteger : public NTL::ZZ, public cipher::BigIntegerInterface<NtlInteger> {
  public:
    // CONSTRUCTORS

    /**
     * Default constructor.
     */
    NtlInteger();

    /**
     * Copy constructor.
     *
     * @param val is the ZZ to be copied.
     */
    NtlInteger(const NTL::ZZ& val);  // NOLINT

    /**
     * Move constructor.
     *
     * @param val is the ZZ to be moved.
     */
    NtlInteger(NTL::ZZ&& val);  // NOLINT

    // TODO: figure out how to do && for wrapper
    // NtlInteger(NTL::myZZ_p &&a);

    /**
     * Constructor from a string.
     *
     * @param strval is the initial integer represented as a string.
     */
    explicit NtlInteger(const std::string& strval);
    explicit NtlInteger(const char* strval) : NtlInteger(std::string(strval)) {}

    /**
     * Constructor from an unsigned integer.
     *
     * @param val is the initial integer represented as a uint64_t.
     */
    NtlInteger(uint64_t val);  // NOLINT
    #if defined(CIPHER_HAVE_INT128)
    NtlInteger(uint128_t val);  // NOLINT
    #endif

    /**
     * Constructors from smaller basic types
     *
     * @param val is the initial integer represented as a basic integer type.
     */
    NtlInteger(int val) : NtlInteger(uint64_t(val)) {}        // NOLINT
    NtlInteger(uint32_t val) : NtlInteger(uint64_t(val)) {}   // NOLINT
    NtlInteger(long val) : NtlInteger(uint64_t(val)) {}       // NOLINT
    NtlInteger(long long val) : NtlInteger(uint64_t(val)) {}  // NOLINT

    /**
     * Constructor from a NativeInteger
     *
     * @param val is the initial integer represented as a native integer.
     */
    template <typename T,
              typename std::enable_if<
                      !std::is_same<T, int>::value && !std::is_same<T, uint32_t>::value &&
                              !std::is_same<T, uint64_t>::value && !std::is_same<T, long>::value &&  // NOLINT
                              !std::is_same<T, long long>::value &&                                  // NOLINT
                              !std::is_same<T, const std::string>::value &&                          // NOLINT
                              !std::is_same<T, const char*>::value && !std::is_same<T, const char>::value &&
                              !std::is_same<T, NtlInteger>::value && !std::is_same<T, double>::value,
                      bool>::type = true>
    NtlInteger(const T& val) : NtlInteger(val.convert_to_int()) {}  // NOLINT

    /**
     * Constructor from double is not permitted
     *
     * @param val
     */
    NtlInteger(double val) __attribute__((deprecated("Cannot construct from a double")));  // NOLINT

    // ASSIGNMENT OPERATORS

    /**
     * Copy assignment operator
     *
     * @param val is the NtlInteger to be assigned from.
     * @return assigned NtlInteger ref.
     */
    NtlInteger& operator=(const NtlInteger& val);

    // TODO move assignment operator?

    /**
     * Assignment operator from string
     *
     * @param strval is the string to be assigned from
     * @return the assigned NtlInteger ref.
     */
    inline const NtlInteger& operator=(std::string strval) {
        *this = NtlInteger(strval);
        return *this;
    }

    /**
     * Assignment operator from unsigned integer
     *
     * @param val is the unsigned integer to be assigned from.
     * @return the assigned NtlInteger ref.
     */
    NtlInteger& operator=(uint64_t val) {
        *this = NtlInteger(val);
        return *this;
    }

    // ACCESSORS

    /**
     * Basic set method for setting the value of a NtlInteger
     *
     * @param strval is the string representation of the NtlInteger to be copied.
     */
    void set_value(const std::string& strval);

    /**
     * Basic set method for setting the value of a NtlInteger
     *
     * @param val is the NtlInteger whose value is to be assigned.
     */
    void set_value(const NtlInteger& val);

    void set_identity() {
        *this = 1;
    }

    // ARITHMETIC OPERATIONS

    /**
     * Addition operation.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    NtlInteger add(const NtlInteger& b) const {
        return *static_cast<const ZZ*>(this) + static_cast<const ZZ&>(b);
    }

    /**
     * Addition operation. In-place variant.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    NtlInteger& add_eq(const NtlInteger& b) {
        *static_cast<ZZ*>(this) += static_cast<const ZZ&>(b);
        return *this;
    }

    /**
     * Subtraction operation.
     * Note that in Sub we return 0, if a<b
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    NtlInteger sub(const NtlInteger& b) const {
        return (*this < b) ? ZZ(0) : (*static_cast<const ZZ*>(this) - static_cast<const ZZ&>(b));
    }

    /**
     * Subtraction operation. In-place variant.
     * Note that in Sub we return 0, if a<b
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    NtlInteger& sub_eq(const NtlInteger& b) {
        if (*this < b) {
            *this = ZZ(0);
        } else {
            *static_cast<ZZ*>(this) -= static_cast<const ZZ&>(b);
        }
        return *this;
    }

    /**
     * Multiplication operation.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    NtlInteger mul(const NtlInteger& b) const {
        return *static_cast<const ZZ*>(this) * static_cast<const ZZ&>(b);
    }

    /**
     * Multiplication operation. In-place variant.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    NtlInteger& mul_eq(const NtlInteger& b) {
        *static_cast<ZZ*>(this) *= static_cast<const ZZ&>(b);
        return *this;
    }

    /**
     * Division operation.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    NtlInteger divided_by(const NtlInteger& b) const {
        return *static_cast<const ZZ*>(this) / static_cast<const ZZ&>(b);
    }

    /**
     * Division operation. In-place variant.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    NtlInteger& divided_by_eq(const NtlInteger& b) {
        *static_cast<ZZ*>(this) /= static_cast<const ZZ&>(b);
        return *this;
    }

    /**
     * Exponentiation operation. Returns x^p.
     *
     * @param p the exponent.
     * @return is the result of the exponentiation operation.
     */
    NtlInteger raise_to(const uint32_t p) const {
        return power(*this, p);
    }

    /**
     * Exponentiation operation. Returns x^p. In-place variant.
     *
     * @param p the exponent.
     * @return is the result of the exponentiation operation.
     */
    NtlInteger& exp_eq(const uint32_t p) {
        *this = power(*this, p);
        return *this;
    }

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    NtlInteger multiply_and_round(const NtlInteger& p, const NtlInteger& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    NtlInteger& multiply_and_round_eq(const NtlInteger& p, const NtlInteger& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    NtlInteger divide_and_round(const NtlInteger& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    NtlInteger& divide_and_round_eq(const NtlInteger& q);

    // MODULAR ARITHMETIC OPERATIONS

    /**
     * Naive modulus operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    NtlInteger mod(const NtlInteger& modulus) const {
        return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);
    }

    /**
     * Naive modulus operation. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    NtlInteger& mod_eq(const NtlInteger& modulus) {
        *static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);
        return *this;
    }

    /**
     * Pre-computes the mu factor that is used in Barrett modulo reduction
     *
     * @return the value of mu
     */
    NtlInteger compute_mu() const {
        NtlInteger temp(1);
        temp <<= (2 * this->get_msb() + 3);
        return temp.divided_by(*this);
    }

    /**
     * Barrett modulus operation.
     * Implements generalized Barrett modular reduction algorithm. Uses one
     * precomputed value of mu.
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    NtlInteger mod(const NtlInteger& modulus, const NtlInteger& mu) const {
        return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);
    }

    /**
     * Barrett modulus operation. In-place variant.
     * Implements generalized Barrett modular reduction algorithm. Uses one
     * precomputed value of mu.
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    NtlInteger& mod_eq(const NtlInteger& modulus, const NtlInteger& mu) {
        *static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);
        return *this;
    }

    /**
     * Modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger mod_add(const NtlInteger& b, const NtlInteger& modulus) const {
        return AddMod(this->mod(modulus), b.mod(modulus), modulus);
    }

    /**
     * Modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger& mod_add_eq(const NtlInteger& b, const NtlInteger& modulus) {
        AddMod(*this, this->mod(modulus), b.mod(modulus), modulus);
        return *this;
    }

    /**
     * Modulus addition where operands are < modulus.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger mod_add_fast(const NtlInteger& b, const NtlInteger& modulus) const {
        return AddMod(*this, b, modulus);
    }

    /**
     * Modulus addition where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger& mod_add_fast_eq(const NtlInteger& b, const NtlInteger& modulus) {
        *this = AddMod(*this, b, modulus);
        return *this;
    }

    /**
     * Barrett modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger mod_add(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) const {
        return AddMod(*this, b, modulus);
    }

    /**
     * Barrett modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    NtlInteger& mod_add_eq(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) {
        *this = AddMod(*this, b, modulus);
        return *this;
    }

    /**
     * Modulus subtraction operation.
     * NOTE mod_sub needs to return signed modulus (i.e. -1/2..q/2) in order
     * to be consistent with BE 2
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger mod_sub(const NtlInteger& b, const NtlInteger& modulus) const {
        NtlInteger newthis(*this % modulus);
        NtlInteger newb(b % modulus);
        if (newthis >= newb) {
            NtlInteger tmp(SubMod(newthis, newb, modulus));  // normal mod sub
            return tmp;
        } else {
            NtlInteger tmp(newthis + modulus - newb);  // signed mod
            return tmp;
        }
    }

    /**
     * Modulus subtraction operation. In-place variant.
     * NOTE mod_sub needs to return signed modulus (i.e. -1/2..q/2) in order
     * to be consistent with BE 2
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger& mod_sub_eq(const NtlInteger& b, const NtlInteger& modulus) {
        this->mod_eq(modulus);
        NtlInteger newb(b % modulus);
        if (*this >= newb) {
            SubMod(*this, *this, newb, modulus);  // normal mod sub
            return *this;
        } else {
            this->add_eq(modulus);
            this->sub_eq(newb);  // signed mod
            return *this;
        }
    }

    /**
     * Modulus subtraction where operands are < modulus.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger mod_sub_fast(const NtlInteger& b, const NtlInteger& modulus) const {
        if (*this >= b) {
            return SubMod(*this, b, modulus);  // normal mod sub
        } else {
            return (*this + modulus - b);  // signed mod
        }
    }

    /**
     * Modulus subtraction where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger& mod_sub_fast_eq(const NtlInteger& b, const NtlInteger& modulus) {
        if (*this >= b) {
            return *this = SubMod(*this, b, modulus);  // normal mod sub
        } else {
            return *this = (*this + modulus - b);  // signed mod
        }
    }

    /**
     * Barrett modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger mod_sub(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) const {
        NtlInteger newthis(*this % modulus);
        NtlInteger newb(b % modulus);
        if (newthis >= newb) {
            NtlInteger tmp(SubMod(newthis, newb, modulus));  // normal mod sub
            return tmp;
        } else {
            NtlInteger tmp(newthis + modulus - newb);  // signed mod
            return tmp;
        }
    }

    /**
     * Barrett modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    NtlInteger& mod_sub_eq(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) {
        this->mod_eq(modulus);
        NtlInteger newb(b % modulus);
        if (*this >= newb) {
            SubMod(*this, *this, newb, modulus);  // normal mod sub
            return *this;
        } else {
            this->add_eq(modulus);
            this->sub_eq(newb);  // signed mod
            return *this;
        }
    }

    /**
     * Modulus multiplication operation.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger mod_mul(const NtlInteger& b, const NtlInteger& modulus) const {
        return MulMod(this->mod(modulus), b.mod(modulus), modulus);
    }

    /**
     * Modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger& mod_mul_eq(const NtlInteger& b, const NtlInteger& modulus) {
        MulMod(*this, this->mod(modulus), b.mod(modulus), modulus);
        return *this;
    }

    /**
     * Barrett modulus multiplication.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger mod_mul(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) const {
        return MulMod(this->mod(modulus), b.mod(modulus), modulus);
    }

    /**
     * Barrett modulus multiplication. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger& mod_mul_eq(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) {
        MulMod(*this, this->mod(modulus), b.mod(modulus), modulus);
        return *this;
    }

    /**
     * Modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    inline NtlInteger mod_mul_fast(const NtlInteger& b, const NtlInteger& modulus) const {
        return MulMod(*this, b, modulus);
    }

    /**
     * Modulus multiplication that assumes the operands are < modulus. In-place
     * variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger& mod_mul_fast_eq(const NtlInteger& b, const NtlInteger& modulus) {
        *this = MulMod(*this, b, modulus);
        return *this;
    }

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    inline NtlInteger mod_mul_fast(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) const {
        return MulMod(*this, b, modulus);
    }

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus.
     * In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    NtlInteger& mod_mul_fast_eq(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& mu) {
        *this = MulMod(*this, b, modulus);
        return *this;
    }

    NtlInteger mod_mul_fast_const(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& b_inv) const {
        CIPHER_THROW("mod_mul_fast_const is not implemented for backend 6");
    }

    NtlInteger& mod_mul_fast_const_eq(const NtlInteger& b, const NtlInteger& modulus, const NtlInteger& b_inv) {
        CIPHER_THROW("mod_mul_fast_const_eq is not implemented for backend 6");
    }

    /**
     * Modulus exponentiation operation.
     *
     * @param b is the exponent.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    inline NtlInteger mod_exp(const NtlInteger& b, const NtlInteger& modulus) const {
        NtlInteger res;
        PowerMod(res, *this, b, modulus);
        return res;
    }

    /**
     * Modulus exponentiation operation. In-place variant.
     *
     * @param b is the exponent.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    NtlInteger& mod_exp_eq(const NtlInteger& b, const NtlInteger& modulus) {
        PowerMod(*this, *this, b, modulus);
        return *this;
    }

    /**
     * Modulus inverse operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    NtlInteger mod_inverse(const NtlInteger& modulus) const {
        if (modulus == NtlInteger(0)) {
            CIPHER_THROW("zero has no inverse");
        }
        NtlInteger tmp(0);
        try {
            tmp = InvMod(*this % modulus, modulus);
        } catch (InvModErrorObject& e) {  // note this code requires NTL Excptions coto be turned
                                          // on. TODO: provide alternative when that is off.
            std::stringstream errmsg;
            errmsg << "mod_inverse exception " << " this: " << *this << " modulus: " << modulus << "GCD(" << e.get_a()
                   << "," << e.get_n() << "!=1" << std::endl;
            CIPHER_THROW(errmsg.str());
        }
        return tmp;
    }

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    NtlInteger& mod_inverse_eq(const NtlInteger& modulus) {
        if (modulus == NtlInteger(0)) {
            CIPHER_THROW("zero has no inverse");
        }
        try {
            *this = InvMod(*this % modulus, modulus);
        } catch (InvModErrorObject& e) {  // note this code requires NTL Excptions coto be turned
                                          // on. TODO: provide alternative when that is off.
            std::stringstream errmsg;
            errmsg << "mod_inverse exception " << " this: " << *this << " modulus: " << modulus << "GCD(" << e.get_a()
                   << "," << e.get_n() << "!=1" << std::endl;
            CIPHER_THROW(errmsg.str());
        }
        return *this;
    }

    /**
     * Left shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NtlInteger l_shift(uint16_t shift) const {
        return *static_cast<const ZZ*>(this) << shift;
    }

    /**
     * Left shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NtlInteger& l_shift_eq(uint16_t shift) {
        *static_cast<ZZ*>(this) <<= shift;
        return *this;
    }

    /**
     * Right shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NtlInteger r_shift(uint16_t shift) const {
        return *static_cast<const ZZ*>(this) >> shift;
    }

    /**
     * Right shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NtlInteger& r_shift_eq(uint16_t shift) {
        *static_cast<ZZ*>(this) >>= shift;
        return *this;
    }

    // COMPARE

    // comparison method inline for speed
    int compare_with(const NtlInteger& a) const {
        return compare(*this, a);
    }

    // CONVERTING

    // Cipher conversion methods
    template <typename T = BasicInteger>
    T convert_to_int() const {
    #if defined(CIPHER_HAVE_INT128)
        if constexpr (std::is_same_v<T, uint128_t>) {
            uint128_t tmp2 = (*this >> 64).convert_to_int<uint64_t>();
            return (tmp2 << 64) | (*this % NtlInteger(1).l_shift_eq(64)).convert_to_int<uint64_t>();
        } else
    #endif
        {
            std::stringstream s;  // slower
            s << *this;
            T result;
            s >> result;

            if ((this->get_msb() > (sizeof(T) * 8)) || (this->get_msb() > NTL_ZZ_NBITS)) {
                CIPHER_DIAGNOSTIC_ERR << "Warning NtlInteger::convert_to_int() Loss of precision. " << std::endl;
                CIPHER_DIAGNOSTIC_ERR << "input  " << *this << std::endl;
                CIPHER_DIAGNOSTIC_ERR << "result  " << result << std::endl;
            }
            return result;
        }
    }
    uint64_t convert_to_uint64() const;
    double convert_to_double() const;

    /**
     * Convert a string representation of a binary number to a NtlInteger.
     * Note: needs renaming to a generic form since the variable type name is
     * embedded in the function name. Suggest from_binary_string()
     * @param bit_string the binary num in string.
     * @return the number represented as a NtlInteger.
     */
    static NtlInteger from_binary_string(const std::string& bit_string);

    // OTHER FUNCTIONS

    // adapter kit that wraps ZZ with BACKEND 2 functionality

    static const NtlInteger& zero();

    uint32_t get_msb() const;

    /**
     * Get the number of digits using a specific base - support for
     * arbitrary base may be needed.
     *
     * @param base is the base with which to determine length in.
     * @return the length of the representation in a specific base.
     */
    uint32_t get_length_for_base(uint32_t base) const {
        return get_msb();
    }

    /**
     * Get the integer value of the of a subfield of bits. Where the length of
     * the field is specifice by a power of two base
     * Warning: only power-of-2 bases are currently supported.
     * Example: for number 83, index 2 and base 4 we have:
     *
     *                         index:0,1,2,3
     * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
     *
     * The return number is 1.
     *
     * @param index is the bit location (lsb)
     * @param base such that log2(base)+1 is the bitwidth of the subfield
     * @return the unsigned integer value of the subfield
     */
    uint32_t get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    // variable to store the log(base 2) of the number of bits in the
    // limb data type.
    static const uint32_t log2_limb_bit_length_;

    /**
     * Gets a subset of bits of a given length with LSB at specified index.
     * optimized for speed in backend 6
     * @param index of the set of bit to get. LSB=1
     * @param length of the set of bits to get. LSB=1
     * @return resulting unsigned in formed by set of bits.
     */
    uint32_t get_bit_range_at_index(uint32_t index, uint32_t length) const;

    /**
     * Gets the bit at the specified index.
     *
     * @param index of the bit to get. LSB=1
     * @return resulting bit.
     */
    uint8_t get_bit_at_index(uint32_t index) const;

    /**
     * A zero allocator that is called by the Matrix class. It is used to
     * initialize a Matrix of NtlInteger objects.
     */
    static NtlInteger allocator() {
        return 0;
    }

    // STRINGS & STREAMS

    // Cipher string conversion
    const std::string to_string() const;

    static const std::string integer_type_name() {
        return "UBNTLINT";
    }

    // big integer stream output
    friend std::ostream& operator<<(std::ostream& os, const NtlInteger& ptr_obj);

    /**
     * Gets a copy of the internal limb storage
     * Used primarily for debugging
     * @return string with the space-separated limb values, least significant limb first
     */
    std::string get_internal_representation(void) const {
        std::string ret("");
        const ZZ_limb_t* zlp = ZZ_limbs_get(*this);

        size_t max = static_cast<size_t>(this->size());
        for (size_t i = 0; i < max; i++) {
            ret += std::to_string(zlp[i]);
            if (i < (max - 1)) {
                ret += " ";
            }
        }
        return ret;
    }

    /// SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        ::cereal::size_type len = static_cast<::cereal::size_type>(NTL::NumBytes(*this));
        ar(::cereal::binary_data(&len, sizeof(len)));
        if (len != 0) {
            std::vector<unsigned char> bytes(len);
            NTL::BytesFromZZ(bytes.data(), *this, static_cast<long>(len));  // NOLINT: NTL takes long
            ar(::cereal::binary_data(bytes.data(), len));
            ar(::cereal::make_nvp("mb", msb_));
        }
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", to_string()));
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ::cereal::size_type len;
        ar(::cereal::binary_data(&len, sizeof(len)));
        if (len == 0) {
            *this = 0;
            return;
        }

        std::vector<unsigned char> bytes(len);
        ar(::cereal::binary_data(bytes.data(), len));
        NTL::ZZFromBytes(*this, bytes.data(), static_cast<long>(len));  // NOLINT: NTL takes long

        ar(::cereal::make_nvp("mb", msb_));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        std::string s;
        ar(::cereal::make_nvp("v", s));
        *this = s;
    }

    std::string serialized_object_name() const {
        return "NTLInteger";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // adapter kits
    void set_msb();

    /**
     * function to return the ceiling of the input number divided by
     * the number of bits in the limb data type.  DBC this is to
     * determine how many limbs are needed for an input bitsize.
     * @param Number is the number to be divided.
     * @return the ceiling of Number/(bits in the limb data type)
     */
    // todo: rename to MSB2NLimbs()
    static uint32_t ceil_int_by_u_int(const ZZ_limb_t number_value);

    mutable ::cereal::size_type msb_;
    uint32_t get_msb_limb(ZZ_limb_t x) const;
};
// class ends

NTL_DECLARE_RELOCATABLE((NtlInteger*))
}  // namespace NTL

#endif  // CIPHER_WITH_NTL

#endif  // CIPHER_MATH_BACKEND_NTL_INTEGER_H_
