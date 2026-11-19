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
  This file contains the vector manipulation functionality
 */

#ifndef CIPHER_MATH_BACKEND_FIXED_MOD_VECTOR_H_
#define CIPHER_MATH_BACKEND_FIXED_MOD_VECTOR_H_

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE2

    #include <ostream>
    #include <string>

    #include "cipher/math/backend/fixed/integer.h"
    #include "cipher/math/backend/vector.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"

/**
 * @namespace bigintfxd
 * The namespace of bigintfxd
 */
namespace fixed_int {

// Forward declare this class for aliases
template <typename IntegerType>
class BigVectorFixedT;

using BigVector = BigVectorFixedT<BigInteger>;

/**
 * @brief The class for representing vectors of big binary integers.
 */
template <class IntegerType>
class BigVectorFixedT final : public cipher::BigVectorInterface<BigVectorFixedT<IntegerType>, IntegerType>,
                              public cipher::Serializable {
  public:
    ~BigVectorFixedT() {
        delete[] data_;
    }

    /**
     * Basic constructor.
     */
    BigVectorFixedT();

    static inline BigVectorFixedT single(const IntegerType& val, const IntegerType& modulus) {
        BigVectorFixedT vec(1, modulus);
        vec[0] = val;
        return vec;
    }

    /**
     * Basic constructor for specifying the length of the vector and the modulus.
     *
     * @param length is the length of the big binary vector, in terms of the
     * number of entries.
     * @param modulus is the modulus of the ring.
     */
    explicit BigVectorFixedT(uint32_t length, const IntegerType& modulus = 0);

    BigVectorFixedT(uint32_t length, const IntegerType& modulus, const IntegerType& value)
        : data_(new IntegerType[length]()), length_{length}, modulus_{modulus} {
        std::fill(data_, data_ + length_, value);
    }

    /**
     * Basic constructor for copying a vector
     *
     * @param big_vector is the big binary vector to be copied.
     */
    BigVectorFixedT(const BigVectorFixedT& big_vector);

    /**
     * Basic move constructor for moving a vector
     *
     * @param big_vector is the big binary vector to be moved.
     */
    BigVectorFixedT(BigVectorFixedT&& big_vector);  // move copy constructor

    /**
     * Basic constructor for specifying the length of the vector
     * the modulus and an initializer list.
     *
     * @param length is the length of the big binary vector, in terms of the
     * number of entries.
     * @param modulus is the modulus of the ring.
     * @param rhs is an initializer list of strings
     */

    BigVectorFixedT(uint32_t length, const IntegerType& modulus, std::initializer_list<std::string> rhs);

    /**
     * Basic constructor for specifying the length of the vector
     * the modulus and an initializer list.
     *
     * @param length is the length of the big binary vector, in terms of the
     * number of entries.
     * @param modulus is the modulus of the ring.
     * @param rhs is an initializer list of uint64_t
     */
    BigVectorFixedT(uint32_t length, const IntegerType& modulus, std::initializer_list<uint64_t> rhs);

    /**
     * Assignment operator to assign value from rhs
     *
     * @param rhs is the big binary vector to be assigned from.
     * @return Assigned BigVectorFixedT.
     */
    BigVectorFixedT& operator=(const BigVectorFixedT& rhs);

    /**
     * Move assignment operator
     *
     * @param rhs is the big binary vector to be moved.
     * @return moved BigVectorFixedT object
     */
    BigVectorFixedT& operator=(BigVectorFixedT&& rhs);

    /**
     * Initializer list for BigVectorFixedT.
     *
     * @param rhs is the list of strings containing integers to be assigned to
     * the BBV.
     * @return BigVectorFixedT object
     */
    BigVectorFixedT& operator=(std::initializer_list<std::string> rhs);

    /**
     * Initializer list for BigVectorFixedT.
     *
     * @param rhs is the list of integers to be assigned to the BBV.
     * @return BigVectorFixedT object
     */
    BigVectorFixedT& operator=(std::initializer_list<uint64_t> rhs);

    /**
     * Assignment operator to assign value val to first entry, 0 for the rest of
     * entries.
     *
     * @param val is the value to be assigned at the first entry.
     * @return Assigned BigVectorFixedT.
     */
    BigVectorFixedT& operator=(uint64_t val) {
        data_[0] = val;
        if (modulus_ != 0) {
            data_[0] %= modulus_;
        }
        for (size_t i = 1; i < length_; ++i) {
            data_[i] = 0;
        }
        return *this;
    }

    // ACCESSORS

    /**
     * Sets/gets a value at an index.
     * This method is slower than operator[] as it checks if index out of range
     *
     * @param i is the index of the entry to access.
     * @return is a reference to the entry at the index.
     */
    IntegerType& at(size_t i) {
        if (!index_check(i)) {
            CIPHER_THROW("BigVector index out of range");
        }
        return data_[i];
    }

    const IntegerType& at(size_t i) const {
        if (!index_check(i)) {
            CIPHER_THROW("BigVector index out of range");
        }
        return data_[i];
    }

    /**
     * operators to get a value at an index.
     * @param idx is the index to get a value at.
     * @return is the value at the index.
     */
    IntegerType& operator[](size_t idx) {
        return data_[idx];
    }

    const IntegerType& operator[](size_t idx) const {
        return data_[idx];
    }

    /**
     * Sets the vector modulus.
     *
     * @param value is the modulus value to set.
     */
    void set_modulus(const IntegerType& value) {
        modulus_ = value;
    }

    /**
     * Sets the vector modulus and changes the values to match the new modulus.
     *
     * @param value is the value to set.
     */
    void switch_modulus(const IntegerType& value);
    void lazy_switch_modulus(const IntegerType& value);

    BigVectorFixedT& mult_acc_eq_no_check(const BigVectorFixedT& a, const BigVectorFixedT& b) {
        CIPHER_THROW("mult_acc_eq_no_check() not implemented for mubintvecfxd");
    }
    BigVectorFixedT& mult_acc_eq_no_check(const BigVectorFixedT& v, const IntegerType& i) {
        CIPHER_THROW("mult_acc_eq_no_check() not implemented for mubintvecfxd");
    }

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
        return length_;
    }

    // MODULAR ARITHMETIC OPERATIONS

    /**
     * Vector modulus operator.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    BigVectorFixedT mod(const IntegerType& modulus) const;

    /**
     * Vector modulus operator. In-place variant.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    BigVectorFixedT& mod_eq(const IntegerType& modulus);

    /**
     * Scalar-to-vector modulus addition operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    BigVectorFixedT mod_add(const IntegerType& b) const;

    /**
     * Scalar-to-vector modulus addition operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    BigVectorFixedT& mod_add_eq(const IntegerType& b);

    /**
     * Scalar modulus addition at a particular index.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    BigVectorFixedT mod_add_at_index(uint32_t i, const IntegerType& b) const;

    /**
     * Scalar modulus addition at a particular index. In-place variant.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    BigVectorFixedT& mod_add_at_index_eq(uint32_t i, const IntegerType& b);

    /**
     * Vector component wise modulus addition.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    BigVectorFixedT mod_add(const BigVectorFixedT& b) const;

    /**
     * Vector component wise modulus addition. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    BigVectorFixedT& mod_add_eq(const BigVectorFixedT& b);
    BigVectorFixedT& mod_add_no_check_eq(const BigVectorFixedT& b);

    /**
     * Scalar-from-vector modulus subtraction operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    BigVectorFixedT mod_sub(const IntegerType& b) const;

    /**
     * Scalar-from-vector modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    BigVectorFixedT& mod_sub_eq(const IntegerType& b);

    /**
     * Vector component wise modulus subtraction.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    BigVectorFixedT mod_sub(const BigVectorFixedT& b) const;

    /**
     * Vector component wise modulus subtraction. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    BigVectorFixedT& mod_sub_eq(const BigVectorFixedT& b);

    /**
     * Scalar-to-vector modulus multiplication operation.
     * Generalized Barrett modulo reduction algorithm.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    BigVectorFixedT mod_mul(const IntegerType& b) const;

    /**
     * Scalar-to-vector modulus multiplication operation. In-place variant.
     * Generalized Barrett modulo reduction algorithm.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    BigVectorFixedT& mod_mul_eq(const IntegerType& b);

    /**
     * Vector component wise modulus multiplication.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    BigVectorFixedT mod_mul(const BigVectorFixedT& b) const;

    /**
     * Vector component wise modulus multiplication. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    BigVectorFixedT& mod_mul_eq(const BigVectorFixedT& b);
    BigVectorFixedT& mod_mul_no_check_eq(const BigVectorFixedT& b);

    /**
     * Scalar modulus exponentiation operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    BigVectorFixedT mod_exp(const IntegerType& b) const;

    /**
     * Scalar modulus exponentiation operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    BigVectorFixedT& mod_exp_eq(const IntegerType& b);

    /**
     * Modulus inverse operation.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    BigVectorFixedT mod_inverse() const;

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    BigVectorFixedT& mod_inverse_eq();

    /**
     * Modulus 2 operation, also a least significant bit.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    BigVectorFixedT mod_by_two() const;

    /**
     * Modulus 2 operation, also a least significant bit. In-place variant.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    BigVectorFixedT& mod_by_two_eq();

    /**
     * Vector multiplication without applying the modulus operation.
     *
     * @param b is the vector to multiply.
     * @return is the result of the multiplication operation.
     */
    BigVectorFixedT mult_with_out_mod(const BigVectorFixedT& b) const;

    /**
     * Vector multiplication without applying the modulus operation. In-place
     * variant.
     *
     * @param b is the vector to multiply.
     * @return is the result of the multiplication operation.
     */
    BigVectorFixedT& mult_with_out_mod_eq(const BigVectorFixedT& b);

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    BigVectorFixedT multiply_and_round(const IntegerType& p, const IntegerType& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    BigVectorFixedT& multiply_and_round_eq(const IntegerType& p, const IntegerType& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    BigVectorFixedT divide_and_round(const IntegerType& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    BigVectorFixedT& divide_and_round_eq(const IntegerType& q);

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
    BigVectorFixedT get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    // STRINGS & STREAMS

    /**
     * ostream operator to output vector values to console
     *
     * @param os is the std ostream object.
     * @param ptr_obj is the BigVectorFixedT object to be printed.
     * @return std ostream object which captures the vector values.
     */
    template <class IntegerTypeC>
    friend std::ostream& operator<<(std::ostream& os, const BigVectorFixedT<IntegerTypeC>& ptr_obj) {
        auto len = ptr_obj.length_;
        os << "[";
        for (uint32_t i = 0; i < len; i++) {
            os << ptr_obj.data_[i];
            os << ((i == (len - 1)) ? "]" : " ");
        }
        os << " modulus: " << ptr_obj.modulus_;
        return os;
    }

    // SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("l", length_));
        ar(::cereal::binary_data(data_, sizeof(IntegerType) * length_));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("l", length_));
        for (size_t i = 0; i < length_; i++) {
            ar(data_[i]);
        }
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("l", length_));
        data_ = new IntegerType[length_]();
        ar(::cereal::binary_data(data_, sizeof(IntegerType) * length_));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("l", length_));
        data_ = new IntegerType[length_]();
        for (size_t i = 0; i < length_; i++) {
            ar(data_[i]);
        }
    }

    std::string serialized_object_name() const {
        return "FXDInteger";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // data_ is a pointer to the vector
    IntegerType* data_;
    // length_ stores the length of the vector
    uint32_t length_;
    // modulus_ stores the internal modulus of the vector.
    IntegerType modulus_ = 0;

    // function to check if the index is a valid index.
    bool index_check(uint32_t length) const {
        return length < length_;
    }
};

}  // namespace fixed_int

#endif

#endif  // CIPHER_MATH_BACKEND_FIXED_MOD_VECTOR_H_
