//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
 This file contains the main class for native integers. It implements the same methods as other mathematical backends.
*/

#ifndef CIPHER_MATH_BACKEND_NATIVE_INTEGER_H_
#define CIPHER_MATH_BACKEND_NATIVE_INTEGER_H_

#include <cstdint>
#include <limits>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend/big_int_backend.h"
#include "cipher/math/backend/integer.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/serializable.h"

// the default behavior of the native integer layer is
// to assume that the user does not need bounds/range checks
// in the native integer code
// if you want them, change this #define to true
// we use a #define to resolve which to use at compile time
// sadly, making the choice according to some setting that
// is checked at runtime has awful performance; using this
// #define in a simple expression causes the compiler to
// optimize away the test
#define NATIVEINT_DO_CHECKS false

namespace native_int {

// Forward declare class and give it an alias for the expected type
template <typename IntType>
class NativeIntegerT;
/// the native integer of the default word width of the build (CIPHER_NATIVE_INT bits)
using NativeInteger = NativeIntegerT<BasicInteger>;

template <typename IntType>
class NativeVectorT;

template <typename VecType>
class NumberTheoreticTransformNat;

/**
 * @brief Struct to determine other datatyps based on utype.
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DataTypes {
    /// signed integer of the same width as utype
    using SignedType = void;
    /// unsigned integer of twice the width of utype
    using DoubleType = void;
    /// signed integer of twice the width of utype
    using SignedDoubleType = void;
};
/// @brief Companion types of a 32-bit word: 32-bit signed, 64-bit double-width.
template <>
struct DataTypes<uint32_t> {
    /// signed integer of the same width
    using SignedType = int32_t;
    /// unsigned integer of twice the width
    using DoubleType = uint64_t;
    /// signed integer of twice the width
    using SignedDoubleType = int64_t;
};
/// @brief Companion types of a 64-bit word: 64-bit signed and, when a 128-bit type is
/// available (CIPHER_HAVE_INT128), 128-bit double-width; otherwise the double-width types fall back
/// to 64 bits and the kernels use portable two-word arithmetic.
template <>
struct DataTypes<uint64_t> {
    /// signed integer of the same width
    using SignedType = int64_t;
#if defined(CIPHER_HAVE_INT128)
    /// unsigned integer of twice the width
    using DoubleType = uint128_t;
    /// signed integer of twice the width
    using SignedDoubleType = int128_t;
#else
    /// no wider type available: falls back to the same width
    using DoubleType = uint64_t;
    /// no wider type available: falls back to the same width
    using SignedDoubleType = int64_t;
#endif
};
#if defined(CIPHER_HAVE_INT128)
/// @brief Companion types of a 128-bit word; no wider type exists, so double-width is 128 bits.
template <>
struct DataTypes<uint128_t> {
    /// signed integer of the same width
    using SignedType = int128_t;
    /// no wider type available: falls back to the same width
    using DoubleType = uint128_t;
    /// no wider type available: falls back to the same width
    using SignedDoubleType = int128_t;
};
#endif

/**
 * @brief Largest modulus bit-width the generalized-Barrett kernels are exact for, keyed on
 * the word type rather than on the build.
 * @tparam NativeInt native unsigned integer type
 */
template <typename NativeInt>
struct MaxModulusBits;
/// @brief Modulus cap for 32-bit words (MAX_MODULUS_SIZE32).
template <>
struct MaxModulusBits<uint32_t> {
    /// the modulus cap in bits
    static constexpr uint32_t value{MAX_MODULUS_SIZE32};
};
/// @brief Modulus cap for 64-bit words (MAX_MODULUS_SIZE64).
template <>
struct MaxModulusBits<uint64_t> {
    /// the modulus cap in bits
    static constexpr uint32_t value{MAX_MODULUS_SIZE64};
};
#if defined(CIPHER_HAVE_INT128) || CIPHER_NATIVE_INT == 128
/// @brief Modulus cap for 128-bit words (MAX_MODULUS_SIZE128).
template <>
struct MaxModulusBits<uint128_t> {
    /// the modulus cap in bits
    static constexpr uint32_t value{MAX_MODULUS_SIZE128};
};
#endif

/**
 * @brief Main class for big integers represented as an array of native
 * (primitive) unsigned integers
 * @tparam NativeInt native unsigned integer type
 */
template <typename NativeInt>
class NativeIntegerT final : public cipher::BigIntegerInterface<NativeIntegerT<NativeInt>> {
  private:
    NativeInt value_{0};

    // bit width of the integral data type
    static constexpr uint32_t uint_bit_length_{std::numeric_limits<NativeInt>::digits};

    friend class NativeVectorT<NativeIntegerT<NativeInt>>;
    friend class NumberTheoreticTransformNat<NativeVectorT<NativeIntegerT<NativeInt>>>;

  public:
    /// the underlying native word type
    using Integer = NativeInt;

    /**
     * Width conversion between native integer widths. Explicit; the caller guarantees that the
     * value fits the target width (no check is performed).
     *
     * @param val is the native integer of another width to convert.
     */
    template <typename OtherInt, typename = std::enable_if_t<!std::is_same_v<OtherInt, NativeInt>>>
    explicit NativeIntegerT(const NativeIntegerT<OtherInt>& val) noexcept
        : value_(static_cast<NativeInt>(val.template convert_to_int<OtherInt>())) {}
    /// signed integer of the same width as NativeInt
    using SignedNativeInt = typename DataTypes<NativeInt>::SignedType;
    /// unsigned integer of twice the width of NativeInt (NativeInt itself when none exists)
    using DNativeInt = typename DataTypes<NativeInt>::DoubleType;
    /// signed integer of twice the width of NativeInt (SignedNativeInt when none exists)
    using SdNativeInt = typename DataTypes<NativeInt>::SignedDoubleType;

    /**
     * @brief Double-word integer represented as two single-word integers.
     */
    struct TypeD {
        /// most significant word
        NativeInt hi{0};
        /// least significant word
        NativeInt lo{0};

        /**
         * Formats both words in base 10 for debugging output.
         *
         * @return the string "hi [<hi>], lo [<lo>]".
         */
        inline std::string convert_to_string() const {
            return std::string("hi [" + to_string_impl(hi) + "], lo [" + to_string_impl(lo) + "]");
        }
    };

    /**
     * Explicit conversion to the underlying native word.
     *
     * @return the stored value.
     */
    explicit operator NativeInt() const {
        return value_;
    }

    /**
     * Explicit conversion to bool.
     *
     * @return true if the value is nonzero.
     */
    explicit operator bool() const {
        return value_ != 0;
    }

    constexpr NativeIntegerT() = default;
    constexpr NativeIntegerT(const NativeIntegerT& val) noexcept : value_{val.value_} {}
    constexpr NativeIntegerT(NativeIntegerT&& val) noexcept : value_{std::move(val.value_)} {}

    /**
     * Constructor from a decimal string; throws if the string contains a non-digit or the
     * value does not fit in NativeInt.
     *
     * @param val is the decimal representation of the value.
     */
    NativeIntegerT(const std::string& val) {
        this->NativeIntegerT::set_value(val);
    }

    /**
     * Constructor from a decimal C string; throws if the string contains a non-digit or the
     * value does not fit in NativeInt.
     *
     * @param strval is the decimal representation of the value.
     */
    explicit NativeIntegerT(const char* strval) {
        this->NativeIntegerT::set_value(std::string(strval));
    }

    /**
     * Constructor from a built-in integer type (including the 128-bit types); the value is
     * converted to NativeInt without a range check.
     *
     * @param val is the integer value.
     */
    template <typename T,
              std::enable_if_t<std::is_integral_v<T> || std::is_same_v<T, int128_t> || std::is_same_v<T, uint128_t>,
                               bool> = true>
    constexpr NativeIntegerT(T val) noexcept : value_(val) {}

    /**
     * Constructor from a multiprecision integer of one of the big-integer backends; the caller
     * guarantees that the value fits in NativeInt.
     *
     * @param val is the multiprecision integer.
     */
    template <typename T, std::enable_if_t<std::is_same_v<T, M2Integer> || std::is_same_v<T, M4Integer> ||
                                                   std::is_same_v<T, M6Integer>,
                                           bool> = true>
    constexpr NativeIntegerT(T val) noexcept : value_{val.template convert_to_int<NativeInt>()} {}

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    NativeIntegerT(T val) = delete;

    constexpr NativeIntegerT& operator=(const NativeIntegerT& val) noexcept {
        value_ = val.value_;
        return *this;
    }

    constexpr NativeIntegerT& operator=(NativeIntegerT&& val) noexcept {
        value_ = std::move(val.value_);
        return *this;
    }

    /**
     * Assignment from a decimal string; throws if the string contains a non-digit or the value
     * does not fit in NativeInt.
     *
     * @param val is the decimal representation of the value.
     * @return *this.
     */
    NativeIntegerT& operator=(const std::string& val) {
        this->NativeIntegerT::set_value(val);
        return *this;
    }

    /**
     * Assignment from a decimal C string; throws if the string contains a non-digit or the
     * value does not fit in NativeInt.
     *
     * @param strval is the decimal representation of the value.
     * @return *this.
     */
    NativeIntegerT& operator=(const char* strval) {
        this->NativeIntegerT::set_value(std::string(strval));
        return *this;
    }

    /**
     * Assignment from a built-in integer type (including the 128-bit types); the value is
     * converted to NativeInt without a range check.
     *
     * @param val is the integer value.
     * @return *this.
     */
    template <typename T,
              std::enable_if_t<std::is_integral_v<T> || std::is_same_v<T, int128_t> || std::is_same_v<T, uint128_t>,
                               bool> = true>
    constexpr NativeIntegerT& operator=(T val) noexcept {
        value_ = val;
        return *this;
    }

    /**
     * Assignment from a multiprecision integer of one of the big-integer backends; the caller
     * guarantees that the value fits in NativeInt.
     *
     * @param val is the multiprecision integer.
     * @return *this.
     */
    template <typename T, std::enable_if_t<std::is_same_v<T, M2Integer> || std::is_same_v<T, M4Integer> ||
                                                   std::is_same_v<T, M6Integer>,
                                           bool> = true>
    constexpr NativeIntegerT& operator=(T val) noexcept {
        value_ = val.template convert_to_int<NativeInt>();
        return *this;
    }

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    NativeIntegerT& operator=(T val) = delete;

    /**
     * Basic set method for setting the value of a native integer
     *
     * @param str is the string representation of the native integer to be
     * copied.
     */
    void set_value(const std::string& str) {
        NativeInt acc{0}, tst{0};
        for (auto c : str) {
            if ((c - '0') > 9)
                CIPHER_THROW("String contains a non-digit");
            if ((acc = (10 * acc) + static_cast<NativeInt>(c - '0')) < tst)
                CIPHER_THROW(str + " is too large to fit in this native integer object");
            tst = acc;
        }
        value_ = acc;
    }

    /**
     * Basic set method for setting the value of a native integer
     *
     * @param val is the big binary integer representation of the native
     * integer to be assigned.
     */
    void set_value(const NativeIntegerT& val) {
        value_ = val.value_;
    }

    /**
     *  Set this int to 1.
     */
    void set_identity() {
        value_ = static_cast<NativeInt>(1);
    }

    /**
     * Addition operation.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    NativeIntegerT add(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? add_check(b) : add_fast(b);
    }

    /**
     * add_check is the addition operation with bounds checking.
     *
     * @param b is the value to add to this.
     * @return result of the addition operation.
     */
    NativeIntegerT add_check(const NativeIntegerT& b) const {
        auto r{value_ + b.value_};
        if (r < value_ || r < b.value_)
            CIPHER_THROW("NativeIntegerT add_check: Overflow");
        return {r};
    }

    /**
     * add_fast is the addition operation without bounds checking.
     *
     * @param b is the value to add to this.
     * @return result of the addition operation.
     */
    NativeIntegerT add_fast(const NativeIntegerT& b) const {
        return {b.value_ + value_};
    }

    /**
     * Addition operation. In-place variant.
     *
     * @param b is the value to add.
     * @return result of the addition operation.
     */
    NativeIntegerT& add_eq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? add_eq_check(b) : add_eq_fast(b);
    }

    /**
     * add_eq_check is the addition in place operation with bounds checking.
     * In-place variant.
     *
     * @param b is the value to add to this.
     * @return result of the addition operation.
     */
    NativeIntegerT& add_eq_check(const NativeIntegerT& b) {
        auto oldv{value_};
        if ((value_ += b.value_) < oldv)
            CIPHER_THROW("NativeIntegerT add_eq_check: Overflow");
        return *this;
    }

    /**
     * add_eq_fast is the addition in place operation without bounds checking.
     * In-place variant.
     *
     * @param b is the value to add to this.
     * @return result of the addition operation.
     */
    NativeIntegerT& add_eq_fast(const NativeIntegerT& b) {
        return *this = b.value_ + value_;
    }

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    NativeIntegerT sub(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? sub_check(b) : sub_fast(b);
    }

    /**
     * sub_check is the subtraction operation with bounds checking.
     *
     * @param b is the value to subtract from this.
     * @return result of the subtraction operation.
     */
    NativeIntegerT sub_check(const NativeIntegerT& b) const {
        return {value_ <= b.value_ ? 0 : value_ - b.value_};
    }

    /**
     * sub_fast is the subtraction operation without bounds checking.
     *
     * @param b is the value to subtract from this.
     * @return result of the subtraction operation.
     */
    // no saturated subtraction? functionality differs from BigInteger Backends
    NativeIntegerT sub_fast(const NativeIntegerT& b) const {
        return {value_ - b.value_};
    }

    /**
     * Subtraction operation. In-place variant.
     *
     * @param b is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    NativeIntegerT& sub_eq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? sub_eq_check(b) : sub_eq_fast(b);
    }

    /**
     * sub_eq_check is the subtraction in place operation with bounds checking.
     * In-place variant.
     *
     * @param b is the value to subtract from this.
     * @return result of the subtraction operation.
     */
    NativeIntegerT& sub_eq_check(const NativeIntegerT& b) {
        if (value_ < b.value_)
            CIPHER_THROW("NativeIntegerT sub_eq_check: neg value");
        return *this = value_ - b.value_;
    }

    /**
     * sub_eq_fast is the subtraction in place operation without bounds checking.
     * In-place variant.
     *
     * @param b is the value to subtract from this.
     * @return result of the subtraction operation.
     */
    NativeIntegerT& sub_eq_fast(const NativeIntegerT& b) {
        return *this = value_ - b.value_;
    }

    /**
     * Unary minus: computes 0 - *this with the checking behavior of Sub (saturates to 0 when
     * bounds checking is enabled, wraps modulo 2^max_bits() otherwise).
     *
     * @return the negated value.
     */
    NativeIntegerT operator-() const {
        return NativeIntegerT().sub(*this);
    }

    /**
     * Multiplication operation.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    NativeIntegerT mul(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? mul_check(b) : mul_fast(b);
    }

    /**
     * mul_check is the multiplication operation with bounds checking.
     *
     * @param b is the value to multiply with
     * @return result of the multiplication operation
     */
    NativeIntegerT mul_check(const NativeIntegerT& b) const {
        auto p{b.value_ * value_};
        if (p < value_ || p < b.value_)
            CIPHER_THROW("NativeIntegerT mul_check: Overflow");
        return {p};
    }

    /**
     * mul_fast is the multiplication operation without bounds checking.
     *
     * @param b is the value to multiply with.
     * @return result of the multiplication operation.
     */
    NativeIntegerT mul_fast(const NativeIntegerT& b) const {
        return {b.value_ * value_};
    }

    /**
     * Multiplication operation. In-place variant.
     *
     * @param b is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    NativeIntegerT& mul_eq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? mul_eq_check(b) : mul_eq_fast(b);
    }

    /**
     * mul_eq_check is the multiplication in place operation with bounds checking.
     * In-place variant.
     *
     * @param b is the value to multiply with
     * @return result of the multiplication operation
     */
    NativeIntegerT& mul_eq_check(const NativeIntegerT& b) {
        auto oldv{value_};
        if ((value_ *= b.value_) < oldv)
            CIPHER_THROW("NativeIntegerT mul_eq_check: Overflow");
        return *this;
    }

    /**
     * mul_eq_fast is the multiplication in place operation without bounds
     * checking. In-place variant.
     *
     * @param b is the value to multiply with
     * @return result of the multiplication operation
     */
    NativeIntegerT& mul_eq_fast(const NativeIntegerT& b) {
        return *this = b.value_ * value_;
    }

    /**
     * Division operation.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    NativeIntegerT divided_by(const NativeIntegerT& b) const {
        if (b.value_ == 0)
            CIPHER_THROW("NativeIntegerT divided_by: zero");
        return {value_ / b.value_};
    }

    /**
     * Division operation. In-place variant.
     *
     * @param b is the value to divide by.
     * @return is the result of the division operation.
     */
    NativeIntegerT& divided_by_eq(const NativeIntegerT& b) {
        if (b.value_ == 0)
            CIPHER_THROW("NativeIntegerT divided_by_eq: zero");
        return *this = value_ / b.value_;
    }

    /**
     * Exponentiation operation. Returns x^p.
     *
     * @param p the exponent.
     * @return is the result of the exponentiation operation.
     */
    NativeIntegerT raise_to(uint32_t p) const {
        NativeInt r{1};
        for (auto x = value_; p > 0; p >>= 1, x *= x)
            r *= (p & 0x1) ? x : 1;
        return {r};
    }

    /**
     * Exponentiation operation. Returns x^p. In-place variant.
     *
     * @param p the exponent.
     * @return is the result of the exponentiation operation.
     */
    NativeIntegerT& exp_eq(uint32_t p) {
        auto x{value_};
        value_ = 1;
        for (; p > 0; p >>= 1, x *= x)
            value_ *= (p & 0x1) ? x : 1;
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
    NativeIntegerT multiply_and_round(const NativeIntegerT& p, const NativeIntegerT& q) const {
        if (q.value_ == 0)
            CIPHER_THROW("NativeIntegerT multiply_and_round: Divide by zero");
        return static_cast<NativeInt>(p.convert_to_double() * (this->convert_to_double() / q.convert_to_double()) +
                                      0.5);
    }

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    NativeIntegerT& multiply_and_round_eq(const NativeIntegerT& p, const NativeIntegerT& q) {
        if (q.value_ == 0)
            CIPHER_THROW("NativeIntegerT multiply_and_round_eq: Divide by zero");
        return *this = static_cast<NativeInt>(
                       p.convert_to_double() * (this->convert_to_double() / q.convert_to_double()) + 0.5);
    }

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    NativeIntegerT divide_and_round(const NativeIntegerT& q) const {
        if (q.value_ == 0)
            CIPHER_THROW("NativeIntegerT divide_and_round: zero");
        auto ans{value_ / q.value_};
        auto rem{value_ % q.value_};
        auto half_q{q.value_ >> 1};
        if (rem > half_q)
            return {ans + 1};
        return {ans};
    }

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    NativeIntegerT& divide_and_round_eq(const NativeIntegerT& q) {
        if (q.value_ == 0)
            CIPHER_THROW("NativeIntegerT divide_and_round_eq: zero");
        auto ans{value_ / q.value_};
        auto rem{value_ % q.value_};
        auto half_q{q.value_ >> 1};
        if (rem > half_q)
            return *this = ans + 1;
        return *this = ans;
    }

    /**
     * Naive modulus operation.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    NativeIntegerT mod(const NativeIntegerT& modulus) const {
        return {value_ % modulus.value_};
    }

    /**
     * Naive modulus operation. In-place variant.
     *
     * @param modulus is the modulus to perform.
     * @return is the result of the modulus operation.
     */
    NativeIntegerT& mod_eq(const NativeIntegerT& modulus) {
        return *this = value_ % modulus.value_;
    }

    /**
     * Precomputes a parameter mu for Barrett modular reduction.
     *
     * @return the precomputed parameter mu.
     */
    NativeIntegerT compute_mu() const {
        if (value_ == 0)
            CIPHER_THROW("NativeIntegerT compute_mu: Divide by zero");
        constexpr int64_t W{NativeIntegerT::max_bits()};
        int64_t shift{2 * static_cast<int64_t>(cipher::get_msb(value_)) + 3};
        if (shift >= W)
            return {div_d(NativeInt(1) << (shift - W), 0, value_)};
        return {(NativeInt(1) << shift) / value_};
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
    NativeIntegerT mod(const NativeIntegerT& modulus, const NativeIntegerT& mu) const {
        TypeD tmp;
        NativeIntegerT ans{*this};
        mod_mu(tmp, ans, modulus.value_, mu.value_, modulus.get_msb() - 2);
        return ans;
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
    NativeIntegerT& mod_eq(const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        TypeD tmp;
        mod_mu(tmp, *this, modulus.value_, mu.value_, modulus.get_msb() - 2);
        return *this;
    }

    /**
     * Modulus addition operation.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NativeIntegerT mod_add(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto av{value_};
        auto bv{b.value_};
        auto& mv{modulus.value_};
        if (av >= mv)
            av %= mv;
        if (bv >= mv)
            bv %= mv;
        av += bv;
        if (av >= mv)
            av -= mv;
        return {av};
    }

    /**
     * Modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NativeIntegerT& mod_add_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto bv{b.value_};
        auto& mv{modulus.value_};
        if (value_ >= mv)
            value_ = value_ % mv;
        if (bv >= mv)
            bv = bv % mv;
        value_ += bv;
        if (value_ >= mv)
            value_ -= mv;
        return *this;
    }

    /**
     * Modulus addition where operands are < modulus.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NativeIntegerT mod_add_fast(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto& mv{modulus.value_};
        auto r{value_ + b.value_};
        if (r >= mv)
            r -= mv;
        return {r};
    }
    /**
     * Modulus addition where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus addition operation.
     */
    NativeIntegerT& mod_add_fast_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto& mv{modulus.value_};
        value_ += b.value_;
        if (value_ >= mv)
            value_ -= mv;
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
    NativeIntegerT mod_add(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) const {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.value_};
        if (av.value_ >= mv)
            av.mod_eq(modulus, mu);
        if (bv.value_ >= mv)
            bv.mod_eq(modulus, mu);
        av.value_ += bv.value_;
        if (av.value_ >= mv)
            av.value_ -= mv;
        return av;
    }

    /**
     * Barrett modulus addition operation. In-place variant.
     *
     * @param b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus addition operation.
     */
    NativeIntegerT& mod_add_eq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.value_};
        if (av.value_ >= mv)
            av.mod_eq(modulus, mu);
        if (bv.value_ >= mv)
            bv.mod_eq(modulus, mu);
        value_ = av.value_ + bv.value_;
        if (value_ >= mv)
            value_ -= mv;
        return *this;
    }

    /**
     * Modulus subtraction operation.
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT mod_sub(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto av{value_};
        auto bv{b.value_};
        auto& mv{modulus.value_};
        if (av >= mv)
            av %= mv;
        if (bv >= mv)
            bv %= mv;
        if (av < bv)
            return {av + mv - bv};
        return {av - bv};
    }

    /**
     * Modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT& mod_sub_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto av{value_};
        auto bv{b.value_};
        auto& mv{modulus.value_};
        if (av >= mv)
            av = av % mv;
        if (bv >= mv)
            bv = bv % mv;
        if (av < bv)
            return *this = av + mv - bv;
        return *this = av - bv;
    }

    /**
     * Modulus subtraction where operands are < modulus.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT mod_sub_fast(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto mask{static_cast<NativeInt>(0) - static_cast<NativeInt>(value_ < b.value_)};
        return {value_ - b.value_ + (modulus.value_ & mask)};
    }

    /**
     * Modulus subtraction where operands are < modulus. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT& mod_sub_fast_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto mask{static_cast<NativeInt>(0) - static_cast<NativeInt>(value_ < b.value_)};
        value_ = value_ - b.value_ + (modulus.value_ & mask);
        return *this;
    }

    /**
     * Barrett modulus subtraction operation.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT mod_sub(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) const {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.value_};
        if (av.value_ >= mv)
            av.mod_eq(modulus, mu);
        if (bv.value_ >= mv)
            bv.mod_eq(modulus, mu);
        if (av.value_ < bv.value_)
            return {av.value_ + mv - bv.value_};
        return {av.value_ - bv.value_};
    }

    /**
     * Barrett modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    NativeIntegerT& mod_sub_eq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.value_};
        if (av.value_ >= mv)
            av.mod_eq(modulus, mu);
        if (bv.value_ >= mv)
            bv.mod_eq(modulus, mu);
        if (av.value_ < bv.value_)
            return *this = av.value_ + mv - bv.value_;
        return *this = av.value_ - bv.value_;
    }

    /**
     * Modulus multiplication operation.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT mod_mul(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        if constexpr (std::is_same_v<NativeInt, DNativeInt>) {
            if (modulus.get_msb() <= MAX_MODULUS_SIZE)
                return mod_mul(b, modulus, modulus.compute_mu());
            auto& mv{modulus.value_};
            return {mod_mul_d(value_ % mv, b.value_ % mv, mv)};
        } else {
            auto av{value_};
            auto bv{b.value_};
            auto& mv{modulus.value_};
            if (av >= mv)
                av = av % mv;
            if (bv >= mv)
                bv = bv % mv;
            DNativeInt rv{static_cast<DNativeInt>(av) * bv};
            DNativeInt dmv{mv};
            if (rv >= dmv)
                rv %= dmv;
            return {rv};
        }
    }

    /**
     * Modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT& mod_mul_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        if constexpr (std::is_same_v<NativeInt, DNativeInt>) {
            if (modulus.get_msb() <= MAX_MODULUS_SIZE)
                return mod_mul_eq(b, modulus, modulus.compute_mu());
            auto& mv{modulus.value_};
            value_ = mod_mul_d(value_ % mv, b.value_ % mv, mv);
            return *this;
        } else {
            auto av{value_};
            auto bv{b.value_};
            auto& mv{modulus.value_};
            if (av >= mv)
                av = av % mv;
            if (bv >= mv)
                bv = bv % mv;
            DNativeInt rv{static_cast<DNativeInt>(av) * bv};
            DNativeInt dmv{mv};
            if (rv >= dmv)
                rv %= dmv;
            return *this = static_cast<NativeInt>(rv);
        }
    }

    /**
     * Barrett modulus multiplication.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT mod_mul(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) const {
        auto av{*this};
        auto& mv{modulus.value_};
        TypeD tmp;
        int64_t n{modulus.get_msb() - 2};
        if (av.value_ >= mv)
            mod_mu(tmp, av, mv, mu.value_, n);
        auto bv{b};
        if (bv.value_ >= mv)
            mod_mu(tmp, bv, mv, mu.value_, n);
        mult_d(av.value_, bv.value_, tmp);
        NativeInt r{tmp.lo};
        mult_d(r_shift_d(tmp, n), mu.value_, tmp);
        r -= r_shift_d(tmp, n + 7) * mv;
        if (r >= mv)
            r -= mv;
        return {r};
    }

    /**
     * Barrett modulus multiplication. In-place variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT& mod_mul_eq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        int64_t n{modulus.get_msb() - 2};
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.value_};
        TypeD tmp;
        if (av.value_ >= mv)
            mod_mu(tmp, av, mv, mu.value_, n);
        if (bv.value_ >= mv)
            mod_mu(tmp, bv, mv, mu.value_, n);
        mult_d(av.value_, bv.value_, tmp);
        NativeInt r{tmp.lo};
        mult_d(r_shift_d(tmp, n), mu.value_, tmp);
        r -= r_shift_d(tmp, n + 7) * mv;
        value_ = r;
        if (r >= mv)
            value_ -= mv;
        return *this;
    }

    /**
     * Modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT mod_mul_fast(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        if constexpr (std::is_same_v<NativeInt, DNativeInt>) {
            if (modulus.get_msb() <= MAX_MODULUS_SIZE)
                return mod_mul_fast(b, modulus, modulus.compute_mu());
            return {mod_mul_d(value_, b.value_, modulus.value_)};
        } else {
            DNativeInt rv{static_cast<DNativeInt>(value_) * b.value_};
            DNativeInt dmv{modulus.value_};
            if (rv >= dmv)
                rv %= dmv;
            return {rv};
        }
    }

    /**
     * Modulus multiplication that assumes the operands are < modulus. In-place
     * variant.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT& mod_mul_fast_eq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        if constexpr (std::is_same_v<NativeInt, DNativeInt>) {
            if (modulus.get_msb() <= MAX_MODULUS_SIZE)
                return mod_mul_fast_eq(b, modulus, modulus.compute_mu());
            value_ = mod_mul_d(value_, b.value_, modulus.value_);
            return *this;
        } else {
            DNativeInt rv{static_cast<DNativeInt>(value_) * b.value_};
            DNativeInt dmv{modulus.value_};
            if (rv >= dmv)
                rv %= dmv;
            return *this = static_cast<NativeInt>(rv);
        }
    }

    /**
     * Barrett modulus multiplication that assumes the operands are < modulus.
     *
     * @param b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus multiplication operation.
     */
    /* Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
    @article{knezevicspeeding,
    title={Speeding Up Barrett and Montgomery Modular Multiplications},
    author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede,
    Ingrid}
    }
    We use the Generalized Barrett modular reduction algorithm described in
    Algorithm 2 of the Source. The algorithm was originally proposed in J.-F.
    Dhem. Modified version of the Barrett algorithm. Technical report, 1994
    and described in more detail in the PhD thesis of the author published at
    http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
    We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) =
    2^(2*n + 3). Generally speaking, the value of \alpha should be \ge \gamma
    + 1, where \gamma + n is the number of digits in the dividend. We use the
    upper bound of dividend assuming that none of the dividends will be larger
    than 2^(2*n + 3). The value of \mu is computed by NativeVector::compute_mu.
    */
    NativeIntegerT mod_mul_fast(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                const NativeIntegerT& mu) const {
        int64_t n = modulus.get_msb() - 2;
        auto& mv{modulus.value_};
        TypeD prod;
        mult_d(value_, b.value_, prod);
        NativeInt r{prod.lo};
        mult_d(r_shift_d(prod, n), mu.value_, prod);
        r -= r_shift_d(prod, n + 7) * mv;
        if (r >= mv)
            r -= mv;
        return {r};
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
    NativeIntegerT& mod_mul_fast_eq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        int64_t n{modulus.get_msb() - 2};
        auto& mv{modulus.value_};
        TypeD prod;
        mult_d(value_, b.value_, prod);
        NativeInt r{prod.lo};
        mult_d(r_shift_d(prod, n), mu.value_, prod);
        r -= r_shift_d(prod, n + 7) * mv;
        value_ = r;
        if (r >= mv)
            value_ -= mv;
        return *this;
    }

    /*  The next three subroutines implement the modular multiplication
    algorithm for the case when the multiplicand is used multiple times (known
    in advance), as in NTT. The algorithm is described in
    https://arxiv.org/pdf/1205.2926.pdf (Dave Harvey, FASTER ARITHMETIC FOR
    NUMBER-THEORETIC TRANSFORMS). The algorithm is described in lines 5-7 of
    Algorithm 2. The algorithm was originally proposed and implemented in NTL
    (https://www.shoup.net/ntl/) by Victor Shoup.
    */

    /**
     * Precomputation for a multiplicand.
     *
     * @param modulus is the modulus to perform operations with.
     * @return the precomputed factor.
     */
    NativeIntegerT prep_mod_mul_const(const NativeIntegerT& modulus) const {
        if (modulus.value_ == 0)
            CIPHER_THROW("Divide by zero");
        return {div_d(value_, 0, modulus.value_)};
    }

    /**
     * Modular multiplication using a precomputation for the multiplicand.
     *
     * @param b is the NativeIntegerT to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param b_inv precomputation for b.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT mod_mul_fast_const(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                      const NativeIntegerT& b_inv) const {
        NativeInt q = mult_d_hi(value_, b_inv.value_) + 1;
        auto yprime = static_cast<SignedNativeInt>(value_ * b.value_ - q * modulus.value_);
        return {yprime >= 0 ? yprime : yprime + modulus.value_};
    }

    /**
     * Modular multiplication using a precomputation for the multiplicand.
     * In-place variant.
     *
     * @param b is the NativeIntegerT to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param b_inv precomputation for b.
     * @return is the result of the modulus multiplication operation.
     */
    NativeIntegerT& mod_mul_fast_const_eq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                          const NativeIntegerT& b_inv) {
        NativeInt q = mult_d_hi(value_, b_inv.value_) + 1;
        auto yprime = static_cast<SignedNativeInt>(value_ * b.value_ - q * modulus.value_);
        value_ = static_cast<NativeInt>(yprime >= 0 ? yprime : yprime + modulus.value_);
        return *this;
    }

    /**
     * Modulus exponentiation operation.
     *
     * @param b is the exponent.
     * @param mod is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    NativeIntegerT mod_exp(const NativeIntegerT& b, const NativeIntegerT& mod_value) const {
        if (mod_value.get_msb() <= MaxModulusBits<NativeInt>::value) {
            NativeIntegerT t{value_ % mod_value.value_};
            NativeIntegerT p{b.value_};
            NativeIntegerT mu{mod_value.compute_mu()};
            NativeIntegerT r{1};
            if (p.value_ & 0x1)
                r.mod_mul_fast_eq(t, mod_value, mu);
            while (p.value_ >>= 1) {
                t.mod_mul_fast_eq(t, mod_value, mu);
                if (p.value_ & 0x1)
                    r.mod_mul_fast_eq(t, mod_value, mu);
            }
            return {r};
        }
        // above the Barrett domain (Miller-Rabin on first_prime/next_prime candidates)
        auto& mv{mod_value.value_};
        NativeInt t{value_ % mv};
        NativeInt p{b.value_};
        NativeInt r{1};
        if (p & 0x1)
            r = mod_mul_d(r, t, mv);
        while (p >>= 1) {
            t = mod_mul_d(t, t, mv);
            if (p & 0x1)
                r = mod_mul_d(r, t, mv);
        }
        return {r};
    }

    /**
     * Modulus exponentiation operation. In-place variant.
     *
     * @param b is the exponent.
     * @param mod is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    NativeIntegerT& mod_exp_eq(const NativeIntegerT& b, const NativeIntegerT& mod_value) {
        return *this = this->NativeIntegerT::mod_exp(b, mod_value);
    }

    /**
     * Modulus inverse operation.
     *
     * @param mod is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    NativeIntegerT mod_inverse(const NativeIntegerT& mod_value) const {
        SignedNativeInt modulus(mod_value.value_);
        SignedNativeInt a(value_ % mod_value.value_);
        if (a == 0) {
            std::string msg = NativeIntegerT::to_string_impl(value_) + " does not have a mod_inverse using " +
                              NativeIntegerT::to_string_impl(mod_value.value_);
            CIPHER_THROW(msg);
        }
        if (modulus == 1)
            return NativeIntegerT();

        SignedNativeInt y{0};
        SignedNativeInt x{1};
        while (a > 1) {
            auto t = modulus;
            auto q = a / t;
            modulus = a % t;
            a = t;
            t = y;
            y = x - q * y;
            x = t;
        }
        if (x < 0)
            x += mod_value.value_;
        return {x};
    }

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @param mod is the modulus to perform.
     * @return is the result of the modulus inverse operation.
     */
    NativeIntegerT& mod_inverse_eq(const NativeIntegerT& mod_value) {
        return *this = this->NativeIntegerT::mod_inverse(mod_value);
    }

    /**
     * Left shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NativeIntegerT l_shift(uint16_t shift) const {
        return {value_ << shift};
    }

    /**
     * Left shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NativeIntegerT& l_shift_eq(uint16_t shift) {
        return *this = value_ << shift;
    }

    /**
     * Right shift operation.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NativeIntegerT r_shift(uint16_t shift) const {
        return {value_ >> shift};
    }

    /**
     * Right shift operation. In-place variant.
     *
     * @param shift # of bits.
     * @return result of the shift operation.
     */
    NativeIntegerT& r_shift_eq(uint16_t shift) {
        return *this = value_ >> shift;
    }

    /**
     * Compares the current NativeIntegerT to NativeIntegerT a.
     *
     * @param a is the NativeIntegerT to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
     * greater than conditions.
     */
    int compare_with(const NativeIntegerT& a) const {
        return (value_ < a.value_) ? -1 : (value_ > a.value_) ? 1 : 0;
    }

    /**
     * Converts the value to an int.
     *
     * @return the value converted to the integer type T (defaults to the native type).
     */
    template <typename T = NativeInt,
              std::enable_if_t<std::is_integral_v<T> || std::is_same_v<T, int128_t> || std::is_same_v<T, uint128_t>,
                               bool> = true>
    constexpr T convert_to_int() const noexcept {
        return static_cast<T>(value_);
    }

    /**
     * Converts the value to an double.
     *
     * @return double representation of the value.
     */
    constexpr double convert_to_double() const noexcept {
        return static_cast<double>(value_);
    }

    /**
     * Convert a string representation of a binary number to a NativeIntegerT.
     *
     * @param bit_string the binary num in string.
     * @return the binary number represented as a big binary int.
     */
    static NativeIntegerT from_binary_string(const std::string& bit_string) {
        if (bit_string.length() > NativeIntegerT::max_bits())
            CIPHER_THROW("Bit string is too long to fit in an intnat");
        NativeInt v{0};
        for (size_t i = 0; i < bit_string.length(); ++i) {
            auto n = bit_string[i] - '0';
            if (n < 0 || n > 1)
                CIPHER_THROW("Bit string must contain only 0 or 1");
            v = (v << 1) | static_cast<NativeInt>(n);
        }
        return {v};
    }

    /**
     * Returns the MSB location of the value.
     *
     * @return the index of the most significant bit.
     */
    uint32_t get_msb() const {
        return cipher::get_msb(value_);
    }

    /**
     * Get the number of digits using a specific base - support for arbitrary
     * base may be needed.
     *
     * @param base is the base with which to determine length in.
     * @return the length of the representation in a specific base.
     */
    // the base argument is ignored: returns the bit count, which is the length only for base 2
    uint32_t get_length_for_base(uint32_t base) const {
        return NativeIntegerT::get_msb();
    }

    /**
     * Get a specific digit at "digit" index; big integer is seen as an array of
     * digits, where a 0 <= digit < base Warning: only power-of-2 bases are
     * currently supported. Example: for number 83, index 2 and base 4 we have:
     *
     *                         index:0,1,2,3
     * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
     *
     * The return number is 1.
     *
     * @param index is the "digit" index of the requested digit
     * @param base is the base with which to determine length in.
     * @return is the requested digit
     */

    uint32_t get_digit_at_index_for_base(uint32_t index, uint32_t base) const {
        auto digit_len = cipher::get_msb(base - 1);  // == ceil(log2(base))
        uint32_t shift{(index - 1) * digit_len};
        if (shift >= uint_bit_length_)
            return 0;
        return static_cast<uint32_t>((value_ >> shift) & ((uint64_t{1} << digit_len) - 1));
    }

    /**
     * Gets the bit at the specified index.
     *
     * @param index is the index of the bit to get.
     * @return resulting bit.
     */
    uint8_t get_bit_at_index(uint32_t index) const {
        if (index == 0)
            CIPHER_THROW("Zero index in GetBitAtIndex");
        return static_cast<uint8_t>((value_ >> (index - 1)) & 0x1);
    }

    /**
     * A zero allocator that is called by the Matrix class.
     * It is used to initialize a Matrix of NativeIntegerT objects.
     *
     * @return a NativeIntegerT holding zero.
     */
    static constexpr NativeIntegerT allocator() noexcept {
        return NativeIntegerT();
    }

    // STRINGS & STREAMS

    /**
     * Stores the based 10 equivalent/Decimal value of the NativeIntegerT in a
     * string object and returns it.
     *
     * @return value of this NativeIntegerT in base 10 represented as a string.
     */
    std::string to_string() const {
        return to_string_impl(value_);
    }

    /**
     * Name identifying this integer backend.
     *
     * @return the string "UBNATINT".
     */
    static const std::string integer_type_name() {
        return "UBNATINT";
    }

    /**
     * Console output operation.
     *
     * @param os is the std ostream object.
     * @param ptr_obj is NativeIntegerT to be printed.
     * @return is the ostream object.
     */
    friend std::ostream& operator<<(std::ostream& os, const NativeIntegerT& ptr_obj) {
        os << ptr_obj.to_string();
        return os;
    }

    template <class Archive, typename T = void>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint64_t> || std::is_same_v<NativeInt, uint32_t>, T> load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", value_));
    }

#if defined(CIPHER_HAVE_INT128)
    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint128_t> && !cereal::traits::is_text_archive<Archive>::value,
                              void> load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        // get an array with 2 uint64_t values for value_
        uint64_t vec[2];
        ar(::cereal::binary_data(vec, sizeof(vec)));  // 2*8 - size in bytes
        value_ = vec[1];                              // most significant word
        value_ <<= 64;
        value_ += vec[0];  // least significant word
    }

    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint128_t> && cereal::traits::is_text_archive<Archive>::value,
                              void>
    load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        // get an array with 2 uint64_t values for value_
        uint64_t vec[2];
        ar(::cereal::make_nvp("i", vec));
        value_ = vec[1];  // most significant word
        value_ <<= 64;
        value_ += vec[0];  // least significant word
    }
#endif

    template <class Archive, typename T = void>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint64_t> || std::is_same_v<NativeInt, uint32_t>, T> save(
            Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", value_));
    }

#if defined(CIPHER_HAVE_INT128)
    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint128_t> && !cereal::traits::is_text_archive<Archive>::value,
                              void> save(Archive& ar, std::uint32_t const version) const {
        // save 2 uint64_t values instead of uint128_t
        constexpr uint128_t mask = (static_cast<uint128_t>(1) << 64) - 1;
        uint64_t vec[2];
        vec[0] = value_ & mask;  // least significant word
        vec[1] = value_ >> 64;   // most significant word
        ar(::cereal::binary_data(vec, sizeof(vec)));
    }

    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, uint128_t> && cereal::traits::is_text_archive<Archive>::value,
                              void>
    save(Archive& ar, std::uint32_t const version) const {
        // save 2 uint64_t values instead of uint128_t
        constexpr uint128_t mask = (static_cast<uint128_t>(1) << 64) - 1;
        uint64_t vec[2];
        vec[0] = value_ & mask;  // least significant word
        vec[1] = value_ >> 64;   // most significant word
        ar(::cereal::make_nvp("i", vec));
    }
#endif

    std::string serialized_object_name() const {
        return "NATInteger";
    }

    static uint32_t serialized_version() {
        return 1;
    }

    /**
     * Bit width of the native word.
     *
     * @return the number of bits in NativeInt.
     */
    static constexpr uint32_t max_bits() noexcept {
        return uint_bit_length_;
    }

    /**
     * Tells whether this integer type is a native (single-word) integer.
     *
     * @return always true for this class.
     */
    static constexpr bool is_native_int() noexcept {
        return true;
    }

  private:
    /**
     * Right shifts a TypeD integer by a specific number of bits
     * and stores the result as a single-word integer.
     *
     * @param x double-word input
     * @param shift the number of bits to shift by
     * @return the result of right-shifting
     */
    static NativeInt r_shift_d(const TypeD& x, int64_t shift) {
        // shift may reach MSB+5 (see mod_mu/mod_mul_fast), which exceeds the word size for
        // moduli above max_bits()-6 bits; both single-word shifts below are UB there
        constexpr int64_t W{NativeIntegerT::max_bits()};
        if (shift >= W)
            return x.hi >> (shift - W);
        if (shift == 0)
            return x.lo;
        return (x.lo >> shift) | (x.hi << (W - shift));
    }

    // Quotient of a two-word dividend by a one-word divisor. The caller guarantees
    // hi < divisor, so the quotient fits one word (holds for the mu and Shoup
    // precomputations under MAX_MODULUS_SIZE). Without a double-width type this is a
    // W-round restoring division: the remainder stays < divisor before each shift, so
    // the shifted remainder fits W+1 bits and its top bit is the captured carry.
    static NativeInt div_d(NativeInt hi, NativeInt lo, NativeInt divisor) {
        if constexpr (!std::is_same_v<NativeInt, DNativeInt>) {
            return static_cast<NativeInt>(((static_cast<DNativeInt>(hi) << max_bits()) | lo) / divisor);
        } else {
            constexpr int64_t W{NativeIntegerT::max_bits()};
            NativeInt q{0};
            NativeInt r{hi};
            for (int64_t i = W - 1; i >= 0; --i) {
                NativeInt carry{r >> (W - 1)};
                r = (r << 1) | ((lo >> i) & 1);
                if (carry || r >= divisor) {
                    r -= divisor;
                    q |= NativeInt(1) << i;
                }
            }
            return q;
        }
    }

    /**
     * Full double-word product built from half-word partial products, for use where no
     * double-width integer type exists. Compilers do NOT fold this back into a single
     * high-multiply instruction (measured: ~24 instructions on aarch64 and powerpc64
     * versus one umulh/mulhdu), so it serves only the widest lane on any given target:
     * uint128_t always, and uint64_t only when __int128 is unavailable -- every 64-bit
     * target gcc and clang support provides __int128, so there only when the 128-bit
     * type is deliberately disabled.
     *
     * @param a multiplier
     * @param b multiplicand
     * @param res result of multiplication
     */
    static void mult_d_portable(NativeInt a, NativeInt b, TypeD& res) {
        constexpr uint32_t half{max_bits() / 2};
        const NativeInt mask{static_cast<NativeInt>((static_cast<NativeInt>(1) << half) - 1)};
        const NativeInt a1{static_cast<NativeInt>(a >> half)}, a2{static_cast<NativeInt>(a & mask)};
        const NativeInt b1{static_cast<NativeInt>(b >> half)}, b2{static_cast<NativeInt>(b & mask)};
        const NativeInt p1{static_cast<NativeInt>(a2 * b1)}, p2{static_cast<NativeInt>(a1 * b2)};
        const NativeInt mid{static_cast<NativeInt>(p1 + p2)};

        res.hi = static_cast<NativeInt>(a1 * b1);
        res.lo = static_cast<NativeInt>(a2 * b2);

        // fold the middle term in, propagating both carries: out of the low word, and
        // out of (p1 + p2) itself, which lands a half-word up in the high word
        const NativeInt low_before{res.lo};
        res.hi += mid >> half;
        res.lo += static_cast<NativeInt>(mid & mask) << half;
        if (res.lo < low_before)
            ++res.hi;
        // (p1 + p2) wrapped iff the sum is below either addend, so one comparison suffices
        if (mid < p1)
            res.hi += static_cast<NativeInt>(1) << half;
    }

    /**
     * Multiplies two single-word integers and stores the result in a
     * TypeD data structure.
     *
     * @param a multiplier
     * @param b multiplicand
     * @param res result of multiplication
     */
    static void mult_d(NativeInt a, NativeInt b, TypeD& res) {
        if constexpr (std::is_same_v<NativeInt, uint32_t>) {
            uint64_t c{static_cast<uint64_t>(a) * b};
            res.hi = static_cast<uint32_t>(c >> 32);
            res.lo = static_cast<uint32_t>(c);
        }

        if constexpr (std::is_same_v<NativeInt, uint64_t>) {
#if defined(CIPHER_HAVE_INT128)
            uint128_t c{static_cast<uint128_t>(a) * b};
            res.hi = static_cast<uint64_t>(c >> 64);
            res.lo = static_cast<uint64_t>(c);
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
            // clang-format off
            __asm__("mulq %[b]"
                : [ lo ] "=a"(res.lo), [ hi ] "=d"(res.hi)
                : [ a ] "%[lo]"(a), [ b ] "rm"(b)
                : "cc");
                // clang-format on
#else
            mult_d_portable(a, b, res);
#endif
        }

#if defined(CIPHER_HAVE_INT128)
        if constexpr (std::is_same_v<NativeInt, uint128_t>)
            mult_d_portable(a, b, res);
#endif
    }

    /**
     * Multiplies two single-word integers and stores the high word of the
     * result
     *
     * @param a multiplier
     * @param b multiplicand
     * @return the high word of the result
     */
    static NativeInt mult_d_hi(NativeInt a, NativeInt b) {
        TypeD x;
        mult_d(a, b, x);
        return x.hi;
    }

    static std::string to_string_impl(uint32_t value) noexcept {
        return std::to_string(value);
    }

    static std::string to_string_impl(uint64_t value) noexcept {
        return std::to_string(value);
    }

#if defined(CIPHER_HAVE_INT128)
    static std::string to_string_impl(uint128_t value) noexcept {
        constexpr size_t max_chars = 15;
        constexpr uint128_t divisor{0x38d7ea4c68000};  // 10**15
        std::string tmp(46, '0');
        auto msd_it = tmp.end() - 1;
        auto it = tmp.end();
        for (auto i = 3; i != 0; --i, it -= max_chars) {
            auto part = static_cast<uint64_t>(value % divisor);
            value /= divisor;
            if (part) {
                auto s{std::to_string(part)};
                msd_it = it - s.size();
                tmp.replace(it - s.size(), it, s.begin(), s.end());
            }
        }
        return std::string(msd_it, tmp.end());
    }
#endif

    // Exact modular multiplication by division, valid for ANY modulus width (the
    // generalized-Barrett kernels require msb(modulus) <= MAX_MODULUS_SIZE, but
    // first_prime/next_prime run Miller-Rabin on candidates one bit above the cap).
    // div_d's contract holds for any a, b < mv: hi(a*b) < mv^2 / 2^W < mv.
    static NativeInt mod_mul_d(NativeInt a, NativeInt b, NativeInt mv) {
        TypeD x;
        mult_d(a, b, x);
        return x.lo - div_d(x.hi, x.lo, mv) * mv;
    }

    static void mod_mu(TypeD& prod, NativeIntegerT& a, const NativeInt& mv, const NativeInt& mu, int64_t n) {
        prod = {0, a.value_};
        mult_d(r_shift_d(prod, n), mu, prod);
        a.value_ -= r_shift_d(prod, n + 7) * mv;
        if (a.value_ >= mv)
            a.value_ -= mv;
    }
};

/**
 * Streams the contents of a std::vector as "[ v0 v1 ... ]", provided T has a stream
 * operator<<.
 *
 * @param os is the output stream.
 * @param v is the vector to print.
 * @return the output stream.
 */
template <typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v) {
    os << "[";
    for (auto&& i : v)
        os << " " << i;
    os << " ]";
    return os;
}
/**
 * Explicit instantiation used to stream the internal representation of a vector of words.
 *
 * @param os is the output stream.
 * @param v is the vector to print.
 * @return the output stream.
 */
template std::ostream& operator<< <uint64_t>(std::ostream& os, const std::vector<uint64_t>& v);

}  // namespace native_int

#endif  // CIPHER_MATH_BACKEND_NATIVE_INTEGER_H_
