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
  This file contains the main class for unsigned big integers: ubint. Big integers are
  represented as arrays of machine native unsigned integers. The native integer type is
  supplied as a template parameter. Currently implementation based on uint32_t and uint64_t is
  supported. a native double the base integer size is also needed.
 */

#ifndef CIPHER_MATH_BACKEND_DYNAMIC_INTEGER_H_
#define CIPHER_MATH_BACKEND_DYNAMIC_INTEGER_H_

#include <cstdint>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include <functional>
    #include <limits>
    #include <ostream>
    #include <string>
    #include <type_traits>
    #include <utility>
    #include <vector>

    #include "cipher/math/backend/basic_int.h"
    #include "cipher/math/backend/integer.h"
    #include "cipher/math/number_theory.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"
    #include "cipher/util/utilities.h"

    // clang-format off
        // TODO: fix shifting issue when limb_t == Dlimb_t
        #if (CIPHER_NATIVE_INT >= 64 && defined(CIPHER_HAVE_INT128))
            using expdtype = uint64_t;
        #else
            using expdtype = uint32_t;
        #endif
    // clang-format on

    #define _SECURE_SCL 0  // to speed up VS
    #define NO_BARRETT     // currently barrett is slower than mod

namespace dynamic_int {

template <typename limb_t>
class ubint;

/** Define the mapping for ExpBigInteger (experimental) */
using xubint = ubint<expdtype>;
using BigInteger = xubint;

template <class ubint_el_t>
class mubintvec;

/**
 * @brief Struct to find log 2 value of N.
 * Used in preprocessing of ubint to determine bitwidth.
 */
template <uint32_t N>
struct Log2 {
    static constexpr uint32_t value = 1 + Log2<N / 2>::value;
};
template <>
struct Log2<2> {
    static constexpr uint32_t value = 1;
};

// @brief A pre-computed constant of Log base 2 of 10.
// constexpr double LOG2_10 = 3.32192809489;

/**
 * @brief Struct to determine other datatyps based on utype.
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DataTypes {
    using SignedType = void;
    using DoubleType = void;
    using SignedDoubleType = void;
};
template <>
struct DataTypes<uint32_t> {
    using SignedType = int32_t;
    using DoubleType = uint64_t;
    using SignedDoubleType = int64_t;
};
template <>
struct DataTypes<uint64_t> {
    using SignedType = int64_t;
    #if defined(CIPHER_HAVE_INT128)
    using DoubleType = uint128_t;
    using SignedDoubleType = int128_t;
    #else
    using DoubleType = uint64_t;
    using SignedDoubleType = int64_t;
    #endif
};
    #if defined(CIPHER_HAVE_INT128)
template <>
struct DataTypes<uint128_t> {
    using SignedType = int128_t;
    using DoubleType = uint128_t;
    using SignedDoubleType = int128_t;
};
    #endif

template <typename limb_t>
class ubint final : public cipher::BigIntegerInterface<ubint<limb_t>> {
  private:
    // variable that stores the MOST SIGNIFICANT BIT position in the
    uint32_t msb_{0};
    // vector storing the native integers. stored little endian
    std::vector<limb_t> value_{0};
    // variable to store the maximum value of the limb data type
    static constexpr limb_t max_limb_{std::numeric_limits<limb_t>::max()};
    // variable to store the bitlength of the limb data type
    static constexpr uint32_t limb_bit_length_{sizeof(limb_t) * 8};
    // variable to store the log2 of the number of bits in the limb data type
    static constexpr uint32_t log2_limb_bit_length_{Log2<sizeof(limb_t) * 8>::value};

    friend class mubintvec<ubint<limb_t>>;

  public:
    using Integer = limb_t;
    using Slimb_t = typename DataTypes<limb_t>::SignedType;
    using Dlimb_t = typename DataTypes<limb_t>::DoubleType;
    using SDlimb_t = typename DataTypes<limb_t>::SignedDoubleType;

    ubint() = default;

    explicit operator bool() noexcept {
        return msb_ != 0;
    }

    /**
     * Copy constructor.
     * @param val is the ubint to be copied.
     */
    ubint(const ubint& val) noexcept : msb_{val.msb_}, value_{val.value_} {}

    ubint(const std::vector<limb_t>& v) noexcept : value_{v} {
        this->ubint::normalize_limbs();
    }

    /**
     * Move constructor.
     * @param val is the ubint to be moved.
     */
    ubint(ubint&& val) noexcept : msb_{std::move(val.msb_)}, value_{std::move(val.value_)} {}

    ubint(std::vector<limb_t>&& v) noexcept : value_{std::move(v)} {
        this->ubint::normalize_limbs();
    }

    /**
     * Constructor from a string.
     * @param strval is the initial integer represented as a string.
     */
    explicit ubint(const std::string& strval) {
        this->ubint::set_value(strval);
    }
    explicit ubint(const char* strval) {
        this->ubint::set_value(std::string(strval));
    }
    explicit ubint(const char strval) : ubint(limb_t(strval - '0')) {}

    /**
     * Constructor from an integer.
     * @param val is the initial integer represented as an integral type T.
     */
    template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    ubint(T val) : msb_{cipher::get_msb(val)}, value_{limb_t(val)} {
        if constexpr (sizeof(T) > sizeof(limb_t)) {
            if ((val >>= limb_bit_length_) > 0) {
                value_.resize(ubint::msb_to_limbs(msb_));
                for (size_t i{1}; i < value_.size(); ++i, val >>= limb_bit_length_)
                    value_[i] = limb_t(val);
            }
        }
    }

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    ubint(T val) = delete;

    template <typename T, std::enable_if_t<!std::is_integral_v<T> && !std::is_floating_point_v<T>, bool> = true>
    ubint(T val) : ubint(BasicInteger(val)) {}

    /**
     * Copy assignment operator
     *
     * @param val is the ubint to be assigned from.
     * @return assigned ubint ref.
     */
    ubint& operator=(const ubint& val) noexcept {
        msb_ = val.msb_;
        value_ = val.value_;
        return *this;
    }

    ubint& operator=(const limb_t& val) noexcept {
        msb_ = cipher::get_msb(val);
        value_.resize(1);
        value_[0] = val;
        return *this;
    }

    ubint& operator=(ubint&& val) noexcept {
        if (this != &val) {
            msb_ = std::move(val.msb_);
            value_ = std::move(val.value_);
        }
        return *this;
    }

    /**
     * Assignment operator for all other types that have not already got their own
     * assignment operators.
     * @param val is the value to be assign from
     * @return the assigned BigInteger ref.
     */
    template <typename T, std::enable_if_t<!std::is_same_v<T, const ubint>, bool> = true>
    ubint& operator=(T val) {
        return *this = ubint(val);
    }

    /**
     * Basic set method for setting the value of a ubint
     * @param strval is the string representation of the ubint to be copied.
     */
    void set_value(const std::string& strval);

    /**
     * Basic set method for setting the value of a ubint
     * @param val is the ubint representation of the ubint to be assigned.
     */
    void set_value(const ubint& val) noexcept {
        msb_ = val.msb_;
        value_ = val.value_;
    }

    void set_identity() noexcept {
        msb_ = 1;
        value_.resize(1);
        value_[0] = 1;
    }

    /**
     * Addition operation.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    ubint add(const ubint& b) const;
    ubint& add_eq(const ubint& b);

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    ubint sub(const ubint& b) const;
    ubint& sub_eq(const ubint& b);

    // this is a negation operator which really doesn't make sense for ubint
    // TODO: returns zero due to saturated subtraction
    ubint operator-() const {
        // return ubint().sub(*this);
        return ubint();
    }

    /**
     * Multiplication operation.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    ubint mul(const ubint& b) const;
    ubint& mul_eq(const ubint& b) {
        return *this = this->ubint::mul(b);
    }

    /**
     * Division operation.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    ubint divided_by(const ubint& b) const;
    ubint& divided_by_eq(const ubint& b);

    /**
     * Exponentiation operation. Returns x^p.
     *
     * @param p the exponent.
     * @return is the result of the exponentiation operation.
     */
    ubint Exp(uint32_t p) const;
    ubint& exp_eq(uint32_t p) {
        return *this = this->ubint::Exp(p);
    }

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    ubint multiply_and_round(const ubint& p, const ubint& q) const;
    ubint& multiply_and_round_eq(const ubint& p, const ubint& q) {
        return *this = this->ubint::multiply_and_round(p, q);
    }

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    ubint divide_and_round(const ubint& q) const;
    ubint& divide_and_round_eq(const ubint& q) {
        return *this = this->ubint::divide_and_round(q);
    }

    /**
     * Naive modulus operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    ubint mod(const ubint& modulus) const;
    ubint& mod_eq(const ubint& modulus);

    /**
     * Pre-computes the mu factor that is used in Barrett modulo reduction
     *
     * @return the value of mu
     */
    ubint compute_mu() const {
        return (ubint(1) << (2 * msb_ + 3)).divided_by(*this);
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
    template <typename T = limb_t>
    ubint mod(const ubint& modulus, const ubint& mu,
              typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return this->ubint::mod(modulus);
    }

    template <typename T = limb_t>
    ubint mod(const ubint& modulus, const ubint& mu,
              typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        if (*this < modulus)
            return *this;
        int n(modulus.msb_);
        int alpha(n + 3);
        int beta(-2);
        ubint q(mu * this->ubint::r_shift(n + beta));
        q >>= alpha - beta;
        ubint z(this->ubint::sub(q * modulus));
        if (z >= modulus)
            return z.sub(modulus);
        return z;
    }

    template <typename T = limb_t>
    ubint& mod_eq(const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::mod_eq(modulus);
    }

    template <typename T = limb_t>
    ubint& mod_eq(const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        if (*this < modulus)
            return *this;
        int n(modulus.msb_);
        int alpha(n + 3);
        int beta(-2);
        ubint q(mu * this->ubint::r_shift(n + beta));
        q >>= alpha - beta;
        this->ubint::sub_eq(q * modulus);
        if (*this >= modulus)
            return this->ubint::sub_eq(modulus);
        return *this;
    }

    /**
     * Modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    ubint mod_add(const ubint& b, const ubint& modulus) const;
    ubint& mod_add_eq(const ubint& b, const ubint& modulus);

    /**
     * Modulus addition where operands are < modulus.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    ubint mod_add_fast(const ubint& b, const ubint& modulus) const;
    ubint& mod_add_fast_eq(const ubint& b, const ubint& modulus);

    /**
     * Barrett modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    template <typename T = limb_t>
    ubint mod_add(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.mod_add(*this, modulus);
    }

    template <typename T = limb_t>
    ubint mod_add(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.add(*this).mod(modulus, mu);
    }

    template <typename T = limb_t>
    ubint& mod_add_eq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::mod_add_eq(b, modulus);
    }

    template <typename T = limb_t>
    ubint& mod_add_eq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        return *this = b.add(*this).mod(modulus, mu);
    }

    /**
     * Modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    ubint mod_sub(const ubint& b, const ubint& modulus) const;
    ubint& mod_sub_eq(const ubint& b, const ubint& modulus);

    /**
     * Modulus subtraction where operands are < modulus.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    ubint mod_sub_fast(const ubint& b, const ubint& modulus) const;
    ubint& mod_sub_fast_eq(const ubint& b, const ubint& modulus);

    /**
     * Barrett modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    template <typename T = limb_t>
    ubint mod_sub(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return this->ubint::mod_sub(b, modulus);
    }

    template <typename T = limb_t>
    ubint mod_sub(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.mod_eq(modulus, mu);
        if (av >= modulus)
            av.mod_eq(modulus, mu);
        if (av < bv)
            av = modulus.add(av);
        return av.sub_eq(bv);
    }

    template <typename T = limb_t>
    ubint& mod_sub_eq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::mod_sub_eq(b, modulus);
    }

    template <typename T = limb_t>
    ubint& mod_sub_eq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        auto bv(b);
        if (bv >= modulus)
            bv.mod_eq(modulus, mu);
        if (*this >= modulus)
            this->ubint::mod_eq(modulus, mu);
        if (*this < bv)
            *this = modulus.add(*this);
        return this->ubint::sub_eq(bv);
    }

    /**
     * Modulus multiplication operation.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    template <typename T = limb_t>
    ubint mod_mul(const ubint& b, const ubint& modulus,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.mod_eq(modulus);
        if (av >= modulus)
            av.mod_eq(modulus);
        return av.mod_mul_fast(bv, modulus);
    }

    template <typename T = limb_t>
    ubint mod_mul(const ubint& b, const ubint& modulus,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.mod_mul(*this, modulus, modulus.compute_mu());
    }

    template <typename T = limb_t>
    ubint& mod_mul_eq(const ubint& b, const ubint& modulus,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        auto bv(b);
        if (bv >= modulus)
            bv.mod_eq(modulus);
        if (*this >= modulus)
            this->ubint::mod_eq(modulus);
        return *this = bv.mod_mul_fast(*this, modulus);
    }

    template <typename T = limb_t>
    ubint& mod_mul_eq(const ubint& b, const ubint& modulus,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        return *this = b.mod_mul(*this, modulus, modulus.compute_mu());
    }

    /**
     * Barrett modulus multiplication.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    ubint mod_mul(const ubint& b, const ubint& modulus, const ubint& mu) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.mod_eq(modulus, mu);
        if (av >= modulus)
            av.mod_eq(modulus, mu);
        return av.mul(bv).mod(modulus, mu);
    }

    ubint& mod_mul_eq(const ubint& b, const ubint& modulus, ubint& mu) {
        auto bv(b);
        if (bv >= modulus)
            bv.mod_eq(modulus, mu);
        if (*this >= modulus)
            this->ubint::mod_eq(modulus, mu);
        return *this = bv.mul(*this).mod(modulus, mu);
    }

    /**
     * Modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    ubint mod_mul_fast(const ubint& b, const ubint& modulus) const;
    ubint& mod_mul_fast_eq(const ubint& b, const ubint& modulus) {
        return *this = this->ubint::mod_mul_fast(b, modulus);
    }

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    ubint mod_mul_fast(const ubint& b, const ubint& modulus, const ubint& mu) const {
        return b.mul(*this).mod(modulus, mu);
    }

    ubint& mod_mul_fast_eq(const ubint& b, const ubint& modulus, const ubint& mu) {
        return *this = b.mul(*this).mod(modulus, mu);
    }

    ubint mod_mul_fast_const(const ubint& b, const ubint& modulus, const ubint& b_inv) const {
        CIPHER_THROW("ModMulFastConst is not implemented for backend 4");
    }
    ubint& mod_mul_fast_const_eq(const ubint& b, const ubint& modulus, const ubint& b_inv) {
        CIPHER_THROW("ModMulFastConstEq is not implemented for backend 4");
    }

    /**
     * Modulus exponentiation operation. Square-and-multiply algorithm is used.
     *
     * @param b is the exponent.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    ubint mod_exp(const ubint& b, const ubint& modulus) const;
    ubint& mod_exp_eq(const ubint& b, const ubint& modulus) {
        return *this = this->ubint::mod_exp(b, modulus);
    }

    /**
     * Modulus inverse operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    ubint mod_inverse(const ubint& modulus) const;
    ubint& mod_inverse_eq(const ubint& modulus) {
        return *this = this->ubint::mod_inverse(modulus);
    }

    /**
     * Left shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    ubint l_shift(uint16_t shift) const;
    ubint& l_shift_eq(uint16_t shift);

    /**
     * Right shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    ubint r_shift(uint16_t shift) const;
    ubint& r_shift_eq(uint16_t shift);

    /**
     * Compares the current ubint to ubint a.
     *
     * @param a is the ubint to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
     * greater than conditons.
     */
    int Compare(const ubint& a) const noexcept {
        if (msb_ < a.msb_)
            return -1;
        if (msb_ > a.msb_)
            return 1;
        for (int i = value_.size() - 1; i >= 0; --i) {
            if (value_[i] < a.value_[i])
                return -1;
            if (value_[i] > a.value_[i])
                return 1;
        }
        return 0;
    }

    template <typename T = BasicInteger>
    T convert_to_int() const noexcept {
        constexpr uint32_t limblen{sizeof(T) * 8};
        if constexpr (limb_bit_length_ >= limblen) {
            return static_cast<T>(value_[0]);
        }
        if constexpr (limb_bit_length_ < limblen) {
            auto ceil_int = msb_to_limbs(limblen > msb_ ? msb_ : limblen);
            auto result = static_cast<T>(value_[0]);
            for (uint32_t i{1}; i < ceil_int; ++i)
                result |= static_cast<T>(value_[i]) << (i * limb_bit_length_);
            return result;
        }
    }

    /**
     * Converts the value to a float
     * if the ubint is uninitialized error is thrown
     * if the ubint is larger than the max value representable
     * or if conversion fails, and error is reported to cerr
     */
    float convert_to_float() const;
    double convert_to_double() const;

    /**
     * Convert a string representation of a binary number to a ubint.
     * @param bit_string the binary num in string.
     * @return the  number represented as a ubint.
     */
    static ubint from_binary_string(const std::string& bit_string);

    /**
     * Returns the MSB location of the value.
     * @return the index of the most significant bit.
     */
    uint32_t get_msb() const {
        return msb_;
    }

    /**
     * Returns the size of the underlying vector of Limbs
     * @return the size
     */
    size_t get_number_of_limbs() const {
        return value_.size();
    }

    /*
     * Tests whether the ubint is a power of 2.
     *
     * @param x is the value to check.
     * @return true if the input is a power of 2, false otherwise.
     */
    /*
    static bool isPowerOfTwo(const ubint& x) {
        if (x.msb_ == 0)
            return false;
        const size_t limbs{x.value_.size() - 1};
        for (size_t i = 0; i < limbs; ++i) {
            if (0 != x.value_[i])
                return false;
        }
        auto msb{cipher::get_msb(x.value_[limbs]) - 1};
        auto mask{(1 << msb) - 1};
        return (0 == (x.value_[limbs] & mask));
    }
*/

    /**
     * Get the number of digits using a specific base - support for arbitrary base
     * may be needed.
     *
     * @param base is the base with which to determine length in.
     * @return the length of the representation in a specific base.
     */

    // TODO hardcoded for base 2?
    uint32_t get_length_for_base(uint32_t base) const {
        return msb_;
    }

    /**
     * Get a specific digit at "digit" index; big integer is seen as an array of
     * digits, where a 0 <= digit < base.
     * Warning: only power-of-2 bases are currently supported.
     * Example: for number 83, index 2 and base 4 we have:
     *
     *                         index:0,1,2,3
     * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
     *
     * The return number is 1.
     *
     * @param index is the location to return value from in the specific base.
     * @param base is the base with which to determine length in.
     * @return is the requested digit.
     */
    uint32_t get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    /**
     * Gets the bit at the specified index.
     *
     * @param index is the index of the bit to get.
     * @return resulting bit.
     */
    uint8_t get_bit_at_index(uint32_t index) const;

    /**
     * A zero allocator that is called by the Matrix class. It is used to
     * initialize a Matrix of ubint objects.
     */
    static ubint allocator() noexcept {
        return ubint();
    }

    // STRINGS & STREAMS

    /**
     * Stores the based 10 equivalent/Decimal value of the ubint in a string
     * object and returns it.
     *
     * @return value of this ubint in base 10 represented as a string.
     */
    const std::string to_string() const;

    static const std::string integer_type_name() {
        if constexpr (std::is_same_v<limb_t, uint32_t>)
            return "UBDYNINT_32";
        if constexpr (std::is_same_v<limb_t, uint64_t>)
            return "UBDYNINT_64";
        if constexpr (std::is_same_v<limb_t, uint128_t>)
            return "UBDYNINT_128";
        static_assert(true, "Configuration Error: ubintdyn.h");
    }

    /**
     * Delivers value of the internal limb storage
     * Used primarily for debugging
     * @return string with the space-separated limb values, least significant limb first
     */
    std::string get_internal_representation() const {
        std::string ret{};
        for (size_t i = 0; i < value_.size(); i++) {
            ret += std::to_string(value_[i]);
            if (i < (value_.size() - 1)) {
                ret += " ";
            }
        }
        return ret;
    }

    /**
     * ostream output << operator
     *
     * @param os is the std ostream object.
     * @param ptr_obj is ubint to be printed.
     * @return is the returned ostream object.
     */
    friend std::ostream& operator<<(std::ostream& os, const ubint& ptr_obj) {
        os << ptr_obj.to_string();
        return os;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", value_));
        ar(::cereal::make_nvp("m", msb_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", value_));
        ar(::cereal::make_nvp("m", msb_));
    }

    std::string serialized_object_name() const {
        return "DYNInteger";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    /**
     * Sets the MSB to the correct value as computed from the internal value.
     */
    void set_msb() {
        msb_ = limb_bit_length_ * static_cast<uint32_t>(value_.size() - 1);
        msb_ += cipher::get_msb(value_.back());
    }

    /**
     * Normalize limb storage of the ubint by making sure the most
     * significant limb is non-zero (all higher zero limbs are
     * removed).
     */
    void normalize_limbs() {
        auto size = value_.size() - 1;
        while (size > 0 && value_[size--] == 0)
            value_.pop_back();
        msb_ = limb_bit_length_ * static_cast<uint32_t>(value_.size() - 1);
        msb_ += cipher::get_msb(value_.back());
    }

    /**
     * helper function for Div; computes the quotient and remainder of u divided by v
     * @param[out] q is the quotient u/v.
     * @param[out] r is the remainder u mod v.
     * @param u is the dividend.
     * @param v is the divisor.
     */
    void divqr_vect(ubint& q, ubint& r, const ubint& u, const ubint& v) const noexcept;
    void divq_vect(ubint& q, const ubint& u, const ubint& v) const noexcept;
    void divr_vect(ubint& r, const ubint& u, const ubint& v) const noexcept;

    /**
     * function to return the ceiling of the input number divided by
     * the number of bits in the limb data type.  DBC this is to
     * determine how many limbs are needed for an input bitsize.
     * @param msb is the number of bits to be divided.
     * @return the ceiling of msb/(bits in the limb data type)
     */
    static constexpr uint32_t msb_to_limbs(uint32_t msb) noexcept {
        constexpr uint32_t mask{limb_bit_length_ - 1};
        if (msb == 0)
            return 1;
        return (msb >> log2_limb_bit_length_) + ((msb & mask) != 0);
    }
};

    #if 0
// stream helper function for vector of objects
template <typename limb_t>
std::ostream &operator<<(std::ostream& os, const std::vector<limb_t>& v) {
  os << "[";
  for (auto&& itr : v)
    os << " " << itr;
  os << " ]";
  return os;
}
    #endif

}  // namespace bigintdyn
#endif

#endif  // CIPHER_MATH_BACKEND_DYNAMIC_INTEGER_H_
