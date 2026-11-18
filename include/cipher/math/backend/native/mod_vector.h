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
 * This file contains the vector manipulation functionality for native integers
 */

#ifndef CIPHER_MATH_BACKEND_NATIVE_MOD_VECTOR_H_
#define CIPHER_MATH_BACKEND_NATIVE_MOD_VECTOR_H_

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend/native/integer.h"
#include "cipher/math/backend/vector.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/serializable.h"

/**
 * @namespace intnat
 * The namespace of intnat
 */
namespace native_int {

template <typename IntType>
class NativeVectorT;
/// vector of native integers of the default word width of the build
using NativeVector = NativeVectorT<NativeInteger>;
/// native integer with a 32-bit word
using NativeInteger32 = NativeIntegerT<uint32_t>;
/// vector of 32-bit native integers
using NativeVector32 = NativeVectorT<NativeInteger32>;

/**
 * @brief The class for representing vectors of native integers.
 */
template <class IntegerType>
class NativeVectorT final : public cipher::BigVectorInterface<NativeVectorT<IntegerType>, IntegerType>,
                            public cipher::Serializable {
  private:
    IntegerType modulus_{0};
    std::vector<IntegerType> data_{};

    bool index_check(size_t length) const {
        return length < data_.size();
    }

  public:
    /// the native word type underlying IntegerType
    using BasicInt = typename IntegerType::Integer;

    constexpr NativeVectorT() = default;

    /**
     * Creates a vector of length 1 holding val reduced modulo modulus.
     *
     * @param val is the single entry.
     * @param modulus is the modulus of the vector.
     * @return the one-entry vector.
     */
    static constexpr NativeVectorT single(const IntegerType& val, const IntegerType& modulus) noexcept {
        return NativeVectorT(1, modulus, val);
    }

    /**
     * Basic constructor for specifying the length of the vector.
     *
     * @param length is the length of the native vector, in terms of the number of
     * entries.
     */
    explicit constexpr NativeVectorT(uint32_t length) noexcept : data_(length) {}

    /**
     * Basic constructor for specifying the length of the vector and the modulus.
     *
     * @param length is the length of the native vector, in terms of the number of
     * entries.
     * @param modulus is the modulus of the ring.
     */
    constexpr NativeVectorT(uint32_t length, const IntegerType& modulus) noexcept
        : modulus_{modulus}, data_(length) {}

    /**
     * Constructor for specifying the length, the modulus, and one value for every entry.
     *
     * @param length is the length of the native vector, in terms of the number of
     * entries.
     * @param modulus is the modulus of the ring.
     * @param val is the value assigned to every entry, reduced modulo modulus.
     */
    constexpr NativeVectorT(uint32_t length, const IntegerType& modulus, const IntegerType& val) noexcept
        : modulus_{modulus}, data_(length, val.mod(modulus)) {}

    /**
     * Basic constructor for copying a vector
     *
     * @param v is the native vector to be copied.
     */
    constexpr NativeVectorT(const NativeVectorT& v) noexcept : modulus_{v.modulus_}, data_{v.data_} {}

    /**
     * Constructor from a vector under a different modulus: the values of v switched to the
     * new modulus, equivalent to a copy followed by switch_modulus(modulus) but fused into
     * one pass over the data.
     *
     * @param v is the source vector.
     * @param modulus is the modulus to switch the copied values to.
     */
    NativeVectorT(const NativeVectorT& v, const IntegerType& modulus) noexcept;

    /**
     * Basic move constructor for moving a vector
     *
     * @param v is the native vector to be moved.
     */
    constexpr NativeVectorT(NativeVectorT&& v) noexcept
        : modulus_{std::move(v.modulus_)}, data_{std::move(v.data_)} {}

    /**
     * Basic constructor for specifying the length of the vector
     * the modulus and an initializer list.
     *
     * @param length is the length of the native vector, in terms of the number of
     * entries.
     * @param modulus is the modulus of the ring.
     * @param rhs is an initializer list of strings
     */

    NativeVectorT(uint32_t length, const IntegerType& modulus, std::initializer_list<std::string> rhs) noexcept;

    /**
     * Basic constructor for specifying the length of the vector
     * the modulus and an initializer list.
     *
     * @param length is the length of the native vector, in terms of the number of
     * entries.
     * @param modulus is the modulus of the ring.
     * @param rhs is an initializer list of uint64_t
     */
    NativeVectorT(uint32_t length, const IntegerType& modulus, std::initializer_list<uint64_t> rhs) noexcept;

    /**
     * Assignment operator to assign value from rhs
     *
     * @param rhs is the native vector to be assigned from.
     * @return Assigned NativeVectorT.
     */
    NativeVectorT& operator=(const NativeVectorT& rhs) noexcept {
        modulus_ = rhs.modulus_;
        if (data_.size() >= rhs.data_.size()) {
            std::copy(rhs.data_.begin(), rhs.data_.end(), data_.begin());
            if (data_.size() > rhs.data_.size())
                data_.resize(rhs.data_.size());
            return *this;
        }
        data_ = rhs.data_;
        return *this;
    }

    /**
     * Move assignment operator
     *
     * @param rhs is the native vector to be moved.
     * @return moved NativeVectorT object
     */
    NativeVectorT& operator=(NativeVectorT&& rhs) noexcept {
        modulus_ = std::move(rhs.modulus_);
        data_ = std::move(rhs.data_);
        return *this;
    }

    /**
     * Initializer list for NativeVectorT.
     *
     * @param rhs is the list of strings containing integers to be assigned to
     * the BBV.
     * @return NativeVectorT object
     */
    NativeVectorT& operator=(std::initializer_list<std::string> rhs) noexcept;

    /**
     * Initializer list for NativeVectorT.
     *
     * @param rhs is the list of integers to be assigned to the BBV.
     * @return NativeVectorT object
     */
    NativeVectorT& operator=(std::initializer_list<uint64_t> rhs) noexcept;

    /**
     * Assignment operator to assign value val to first entry, 0 for the rest of
     * entries.
     *
     * @param val is the value to be assigned at the first entry.
     * @return Assigned NativeVectorT.
     */
    constexpr NativeVectorT& operator=(uint64_t val) {
        std::fill(data_.begin(), data_.end(), 0);
        data_.at(0) = val;
        return *this;
    }

    /**
     * Sets/gets a value at an index.
     * This method is slower than operator[] as it checks if index out of range
     *
     * @param i is the index to set a value at.
     * @return is the reference to the value at the index.
     */
    IntegerType& at(size_t i) {
        if (!NativeVectorT::index_check(i))
            CIPHER_THROW("NativeVectorT index out of range");
        return data_[i];
    }

    /**
     * operators to get a value at an index.
     * @param i is the index to get a value at.
     * @return is the value at the index; throws if i is out of range.
     */
    const IntegerType& at(size_t i) const {
        if (!NativeVectorT::index_check(i))
            CIPHER_THROW("NativeVectorT index out of range");
        return data_[i];
    }

    /**
     * operators to get a value at an index.
     * @param idx is the index to get a value at.
     * @return is the value at the index; no range check is performed.
     */
    IntegerType& operator[](size_t idx) {
        return data_[idx];
    }

    /**
     * operators to get a value at an index.
     * @param idx is the index to get a value at.
     * @return is the value at the index; no range check is performed.
     */
    const IntegerType& operator[](size_t idx) const {
        return data_[idx];
    }

    /**
     * Sets the vector modulus.
     *
     * @param value is the modulus value to set.
     */
    void set_modulus(const IntegerType& value) {
        constexpr uint32_t max_bits_value{MaxModulusBits<typename IntegerType::Integer>::value};
        if (value.get_msb() > max_bits_value)
            CIPHER_THROW("Modulus too large for requested IntegerType");
        modulus_.value_ = value.value_;
    }

    /**
     * Sets the vector modulus and changes the values to match the new modulus.
     *
     * @param value is the modulus value to set.
     */
    void switch_modulus(const IntegerType& value);

    /**
     * Sets the vector modulus and reduces every entry modulo the new modulus as a non-negative
     * integer, without the centered (signed) adjustment performed by switch_modulus.
     *
     * @param value is the modulus value to set.
     */
    void lazy_switch_modulus(const IntegerType& value);

    /**
     * Gets the vector modulus.
     *
     * @return the vector modulus.
     */
    const IntegerType& get_modulus() const {
        return modulus_;
    }

    /**
     * Gets the vector length.
     *
     * @return vector length.
     */
    size_t get_length() const {
        return data_.size();
    }

    // MODULAR ARITHMETIC OPERATIONS

    /**
     * Vector Modulus operator.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result after the modulus operation on current vector.
     */
    NativeVectorT mod(const IntegerType& modulus) const;

    /**
     * Vector Modulus operator. In-place variant.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result after the modulus operation on current vector.
     */
    NativeVectorT& mod_eq(const IntegerType& modulus);

    /**
     * Scalar modulus addition.
     *
     * After addition modulus operation is performed with the current vector
     * modulus.
     * @param b is the scalar to add at all locations.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT mod_add(const IntegerType& b) const;

    /**
     * Scalar modulus addition. In-place variant.
     *
     * After addition modulus operation is performed with the current vector
     * modulus.
     * @param b is the scalar to add at all locations.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT& mod_add_eq(const IntegerType& b);

    /**
     * Scalar modulus addition at a particular index.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT mod_add_at_index(size_t i, const IntegerType& b) const;

    /**
     * Scalar modulus addition at a particular index. In-place variant.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT& mod_add_at_index_eq(size_t i, const IntegerType& b);

    /**
     * vector modulus addition.
     *
     * @param b is the vector to add at all locations.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT mod_add(const NativeVectorT& b) const;

    /**
     * vector modulus addition. In-place variant.
     *
     * @param b is the vector to add at all locations.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT& mod_add_eq(const NativeVectorT& b);

    /**
     * vector modulus addition. In-place variant that skips the length and modulus
     * compatibility check of mod_add_eq; b must have the same length and modulus, and the
     * entries of both vectors must be reduced (mod_add_fast per entry).
     *
     * @param b is the vector to add at all locations.
     * @return is the result of the modulus addition operation.
     */
    NativeVectorT& mod_add_no_check_eq(const NativeVectorT& b) {
        size_t size{data_.size()};
        auto mv{modulus_};
        for (size_t i = 0; i < size; ++i)
            data_[i].mod_add_fast_eq(b[i], mv);
        return *this;
    }

    /**
     * Scalar modulus subtraction.
     * After subtraction modulus operation is performed with the current vector
     * modulus.
     * @param b is the scalar to subtract from all locations.
     * @return is the result of the modulus subtraction operation.
     */
    NativeVectorT mod_sub(const IntegerType& b) const;

    /**
     * Scalar modulus subtraction. In-place variant.
     * After subtraction modulus operation is performed with the current vector
     * modulus.
     * @param b is the scalar to subtract from all locations.
     * @return is the result of the modulus subtraction operation.
     */
    NativeVectorT& mod_sub_eq(const IntegerType& b);

    /**
     * Vector Modulus subtraction.
     *
     * @param b is the vector to subtract.
     * @return is the result of the modulus subtraction operation.
     */
    NativeVectorT mod_sub(const NativeVectorT& b) const;

    /**
     * Vector Modulus subtraction. In-place variant.
     *
     * @param b is the vector to subtract.
     * @return is the result of the modulus subtraction operation.
     */
    NativeVectorT& mod_sub_eq(const NativeVectorT& b);

    /**
     * Scalar modular multiplication.
     * See the comments in the cpp files for details of the implementation.
     *
     * @param b is the scalar to multiply at all locations.
     * @return is the result of the modulus multiplication operation.
     */
    NativeVectorT mod_mul(const IntegerType& b) const;

    /**
     * Scalar modular multiplication. In-place variant.
     * See the comments in the cpp files for details of the implementation.
     *
     * @param b is the scalar to multiply at all locations.
     * @return is the result of the modulus multiplication operation.
     */
    NativeVectorT& mod_mul_eq(const IntegerType& b);

    /**
     * Vector modulus multiplication.
     *
     * @param b is the vector to multiply.
     * @return is the result of the modulus multiplication operation.
     */
    NativeVectorT mod_mul(const NativeVectorT& b) const;

    /**
     * Vector modulus multiplication. In-place variant.
     *
     * @param b is the vector to multiply.
     * @return is the result of the modulus multiplication operation.
     */
    NativeVectorT& mod_mul_eq(const NativeVectorT& b);

    /**
     * Vector modulus multiplication. In-place variant that skips the length and modulus
     * compatibility check of mod_mul_eq; b must have the same length and modulus, and the
     * entries of both vectors must be reduced (Barrett kernel with hoisted constants).
     *
     * @param b is the vector to multiply.
     * @return is the result of the modulus multiplication operation.
     */
    NativeVectorT& mod_mul_no_check_eq(const NativeVectorT& b);

    /**
     * Fused multiply-accumulate: *this += V * I (mod the vector modulus), without
     * size/modulus validation. Operand contract: the values of *this must be reduced;
     * the values of V need NOT be reduced (the Shoup multiplication is exact for any
     * unreduced multiplicand, which approx_switch_crt_basis relies on for its cross-basis
     * accumulation); I is reduced internally. Alternative backends implementing this
     * interface must honor the unreduced-V tolerance.
     *
     * @param V is the vector to multiply and accumulate.
     * @param I is the scalar multiplier.
     * @return *this after the accumulation.
     */
    NativeVectorT& mult_acc_eq_no_check(const NativeVectorT& V, const IntegerType& I);

    /**
     * Fused multiply-accumulate: *this += a * b (mod the vector modulus), without
     * size/modulus validation. Operand contract: STRICTER than the scalar overload —
     * *this, a, and b must ALL hold reduced values (Barrett kernel, no unreduced-operand
     * tolerance). Saves the full-vector temporary of *this += a * b.
     *
     * @param a is the vector of first operands.
     * @param b is the vector of second operands.
     * @return *this after the accumulation.
     */
    NativeVectorT& mult_acc_eq_no_check(const NativeVectorT& a, const NativeVectorT& b);

    /**
     * Reduces every element modulo the vector's own modulus.
     *
     * @return is the reduced vector.
     */
    NativeVectorT& mod_reduce_eq();

    /**
     * Vector multiplication without applying the modulus operation.
     *
     * @param b is the vector to multiply.
     * @return is the result of the multiplication operation.
     */
    NativeVectorT mult_with_out_mod(const NativeVectorT& b) const;

    /**
     * Scalar modulus exponentiation.
     *
     * @param b is the scalar exponent to apply at all locations.
     * @return a new vector which is the result of the modulus exponentiation
     * operation.
     */
    NativeVectorT mod_exp(const IntegerType& b) const;

    /**
     * Scalar modulus exponentiation. In-place variant.
     *
     * @param b is the scalar exponent to apply at all locations.
     * @return the resulting vector (same object) after the modulus exponentiation
     * operation.
     */
    NativeVectorT& mod_exp_eq(const IntegerType& b);

    /**
     * Modulus inverse.
     *
     * @return a new vector which is the result of the modulus inverse operation.
     */
    NativeVectorT mod_inverse() const {
        size_t size{data_.size()};
        auto mv{modulus_};
        NativeVectorT ans(size, mv);
        for (size_t i{0}; i < size; ++i)
            ans[i] = data_[i].mod_inverse(mv);
        return ans;
    }

    /**
     * Modulus inverse. In-place variant.
     *
     * @return the resulting vector (same object) after the modulus inverse operation.
     */
    NativeVectorT& mod_inverse_eq() {
        size_t size{data_.size()};
        auto mv{modulus_};
        for (size_t i{0}; i < size; ++i)
            data_[i] = data_[i].mod_inverse(mv);
        return *this;
    }

    /**
     * Perform a modulus by 2 operation.  Returns the least significant bit.
     *
     * @return a new vector which is the return value of the modulus by 2, also
     * the least significant bit.
     */
    NativeVectorT mod_by_two() const;

    /**
     * Perform a modulus by 2 operation.  Returns the least significant bit.
     * In-place variant.
     *
     * @return the resulting vector (same object) holding the modulus by 2, also
     * the least significant bit.
     */
    NativeVectorT& mod_by_two_eq();

    /**
     * Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where []
     * is the rounding operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return the result of multiply and round.
     */
    NativeVectorT multiply_and_round(const IntegerType& p, const IntegerType& q) const;

    /**
     * Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where []
     * is the rounding operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return the result of multiply and round.
     */
    NativeVectorT& multiply_and_round_eq(const IntegerType& p, const IntegerType& q);

    /**
     * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is
     * the rounding operation.
     *
     * @param q is the denominator to be divided.
     * @return the result of divide and round.
     */
    NativeVectorT divide_and_round(const IntegerType& q) const;

    /**
     * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is
     * the rounding operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return the result of divide and round.
     */
    NativeVectorT& divide_and_round_eq(const IntegerType& q);

    // OTHER FUNCTIONS

    /**
     * Digit vector at a specific index for all entries for a given number base.
     * Warning: only power-of-2 bases are currently supported.
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
    NativeVectorT get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    /**
     * Decomposes every entry into all of its base-2^digit_len digits at once. Digits are
     * balanced, i.e. in [-2^(digit_len-1), 2^(digit_len-1)) of the centered representative
     * and returned mod q, which halves the digit bound of BV key switching; the top digit
     * absorbs the remaining quotient so that the digits reconstruct the value exactly
     * (mod q). Falls back to plain unsigned digit windows when the bias does not fit the
     * native word (ceil(q_bits/digit_len)*digit_len + 1 > max_bits).
     *
     * @param digit_len is the bit width of one digit.
     * @return one vector per digit position, least significant first.
     */
    std::vector<NativeVectorT> base_decompose(uint32_t digit_len) const;

    // STRINGS & STREAMS

    /**
     * ostream operator to output vector values to console
     *
     * @param os is the std ostream object.
     * @param ptr_obj is the NativeVectorT object to be printed.
     * @return std ostream object which captures the vector values.
     */
    friend std::ostream& operator<<(std::ostream& os, const NativeVectorT& ptr_obj) {
        auto len = ptr_obj.data_.size();
        os << "[";
        for (uint32_t i = 0; i < len; i++) {
            os << ptr_obj.data_[i];
            os << ((i == (len - 1)) ? "]" : " ");
        }
        os << " modulus: " << ptr_obj.modulus_;
        return os;
    }

    template <class Archive>
    std::enable_if_t<!cereal::traits::is_text_archive<Archive>::value, void> save(Archive& ar,
                                                                                  std::uint32_t const version) const {
        ::cereal::size_type size = data_.size();
        ar(size);
        if (size > 0) {
            ar(::cereal::binary_data(data_.data(), size * sizeof(IntegerType)));
        }
        ar(modulus_);
    }

    template <class Archive>
    std::enable_if_t<cereal::traits::is_text_archive<Archive>::value, void> save(Archive& ar,
                                                                                 std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", data_));
        ar(::cereal::make_nvp("m", modulus_));
    }

    template <class Archive>
    std::enable_if_t<!cereal::traits::is_text_archive<Archive>::value, void> load(Archive& ar,
                                                                                  std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ::cereal::size_type size;
        ar(size);
        data_.resize(size);
        if (size > 0) {
            ar(::cereal::binary_data(data_.data(), size * sizeof(IntegerType)));
        }
        ar(modulus_);
    }

    template <class Archive>
    std::enable_if_t<cereal::traits::is_text_archive<Archive>::value, void> load(Archive& ar,
                                                                                 std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", data_));
        ar(::cereal::make_nvp("m", modulus_));
    }

    std::string serialized_object_name() const override {
        return "NativeVectorT";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    /**
     * Generalized-Barrett multiply loop with the reduction constants hoisted out of the
     * loop. Uses the same shift structure and validity domain (operands < modulus) as
     * NativeIntegerT::mod_mul_fast(b, modulus, mu); falls back to the per-element path when
     * no double-width integer type is available.
     *
     * In-place variant: a is both the array of first operands and the destination.
     *
     * @param a is the array of first operands, overwritten with the products.
     * @param b is the array of second operands.
     * @param size is the number of elements.
     * @param modulus is the modulus to perform operations with.
     */
    static void barrett_mod_mul_loop(IntegerType* a, const IntegerType* b, size_t size, const IntegerType& modulus);

    /**
     * Generalized-Barrett multiply loop writing to a separate destination; see the
     * in-place overload for the kernel and its validity domain.
     *
     * @param dst is the destination array (may alias a).
     * @param a is the array of first operands.
     * @param b is the array of second operands.
     * @param size is the number of elements.
     * @param modulus is the modulus to perform operations with.
     */
    static void barrett_mod_mul_loop(IntegerType* dst, const IntegerType* a, const IntegerType* b, size_t size,
                                  const IntegerType& modulus);

    /**
     * General-shrink loop shared by switch_modulus, mod_eq and the copy-with-switch ctor:
     * reduces every element modulo nv and applies the centered correction, whose subtrahend
     * only takes the values {diff_r, 0}.
     *
     * The reduction uses a reciprocal computed once for the whole loop instead of a divide
     * per element. Note this is NOT the compute_mu/mod_mu Barrett used elsewhere: that one is
     * scaled to the modulus (valid only for inputs below 2^(2*MSB(nv)+3)), whereas this one
     * is scaled to the word width, so it is valid for any input the vector can hold. That
     * matters because callers do not agree on a bound: the arbitrary-cyclotomic transform
     * reduces values that are residues of a much larger modulus.
     *
     * @param dst is the destination array (may alias src for the in-place callers).
     * @param src is the source array.
     * @param size is the number of elements.
     * @param ov is the old modulus, only used for the centered correction.
     * @param nv is the modulus to reduce by.
     */
    static void general_shrink_loop(IntegerType* dst, const IntegerType* src, size_t size, BasicInt ov, BasicInt nv);

    /**
     * Fused multiply-accumulate loop: acc += a * b (mod modulus), with the same Barrett
     * kernel and dispatch as barrett_mod_mul_loop and the modular addition fused into the
     * same pass. Validity domain: ALL of acc, a, and b must hold reduced values — unlike
     * the scalar mult_acc_eq_no_check, the Barrett kernel has no tolerance for unreduced
     * multiplicands.
     *
     * @param acc is the accumulator array.
     * @param a is the array of first operands.
     * @param b is the array of second operands.
     * @param size is the number of elements.
     * @param modulus is the modulus to perform operations with.
     */
    static void barrett_mult_acc_loop(IntegerType* acc, const IntegerType* a, const IntegerType* b, size_t size,
                                   const IntegerType& modulus);
};

}  // namespace intnat

namespace cereal {

//! Serialization for vector of NativeInteger

template <class Archive, class A>
inline void CEREAL_SAVE_FUNCTION_NAME(Archive& ar, std::vector<native_int::NativeIntegerT<uint64_t>, A> const& vec) {
    ar(make_size_tag(static_cast<cereal::size_type>(vec.size())));  // number of elements
    for (const auto& v : vec) {
        ar(v.convert_to_int());
    }
}

#if defined(CIPHER_HAVE_INT128)
template <class Archive, class A>
inline void CEREAL_SAVE_FUNCTION_NAME(Archive& ar, std::vector<native_int::NativeIntegerT<uint128_t>, A> const& vec) {
    ar(make_size_tag(static_cast<cereal::size_type>(vec.size())));  // number of elements
    constexpr uint128_t mask = (static_cast<uint128_t>(1) << 64) - 1;
    for (const auto& v : vec) {
        uint64_t vec[2];
        uint128_t v128 = v.convert_to_int();
        vec[0] = v128 & mask;  // least significant word
        vec[1] = v128 >> 64;   // most significant word
        ar(vec);
    }
}
#endif

//! Deserialization for vector of NativeInteger

template <class Archive, class A>
inline void CEREAL_LOAD_FUNCTION_NAME(Archive& ar, std::vector<native_int::NativeIntegerT<uint64_t>, A>& vec) {
    cereal::size_type size;
    ar(make_size_tag(size));
    vec.resize(static_cast<size_t>(size));
    for (auto& v : vec) {
        uint64_t b;
        ar(b);
        v = b;
    }
}

#if defined(CIPHER_HAVE_INT128)
template <class Archive, class A>
inline void CEREAL_LOAD_FUNCTION_NAME(Archive& ar, std::vector<native_int::NativeIntegerT<uint128_t>, A>& vec) {
    cereal::size_type size;
    ar(make_size_tag(size));
    vec.resize(static_cast<size_t>(size));
    for (auto& v : vec) {
        uint64_t vec[2];
        ar(vec);
        v = vec[1];  // most significant word
        v <<= 64;
        v += vec[0];  // least significant word
    }
}
#endif
}  // namespace cereal

#endif  // CIPHER_MATH_BACKEND_NATIVE_MOD_VECTOR_H_
