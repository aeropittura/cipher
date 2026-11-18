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
  This file contains mubintvecdyn, a <vector> of buintdyn, with associated modulus and modulo math operators
 */

#ifndef CIPHER_MATH_BACKEND_DYNAMIC_MOD_VECTOR_H_
#define CIPHER_MATH_BACKEND_DYNAMIC_MOD_VECTOR_H_

#include <cstdint>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include <initializer_list>
    #include <ostream>
    #include <string>
    #include <utility>
    #include <vector>

    #include "cipher/math/backend/dynamic/integer.h"
    #include "cipher/math/backend/vector.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"

/**
 * @namespace bigintdyn
 * The namespace of bigintdyn
 */
namespace dynamic_int {

template <class ubint_el_t>
class mubintvec;

/** Define the mapping for modulo Big Integer Vector */
using xmubintvec = mubintvec<BigInteger>;
using BigVector = xmubintvec;

/**
 * @brief The class for representing vectors of ubint with associated modulo
 * math
 */

template <class ubint_el_t>
class mubintvec final : public cipher::BigVectorInterface<mubintvec<ubint_el_t>, ubint_el_t>,
                        public cipher::Serializable {
  public:
    mubintvec() = default;

    static mubintvec single(const ubint_el_t& val, const ubint_el_t& modulus) {
        mubintvec vec(1, modulus);
        vec.data_[0] = val;
        return vec;
    }

    /**
     * Basic constructor for specifying the length of the vector.
     *
     * @param length initial size in terms of the number of entries.
     */
    explicit mubintvec(uint32_t length) noexcept : data_(length) {}

    /**
     * Basic constructor for specifying the length and modulus of the vector.
     *
     * @param length initial size in terms of the number of entries.
     * @param modulus uint32_t associated with entries in the vector.
     */
    // TODO: what practical purpose with uint32_t modulus??
    //    explicit mubintvec(uint32_t length, uint32_t modulus) noexcept
    //        : modulus_(modulus), modulus_state_(State::INITIALIZED), data_(length) {}

    /**
     * Basic constructor for specifying the length of the vector with modulus
     *
     * @param length initial size in terms of the number of entries.
     * @param modulus ubint associated with entries in the vector.
     */
    mubintvec(uint32_t length, const ubint_el_t& modulus) noexcept
        : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(length) {}

    mubintvec(uint32_t length, const ubint_el_t& modulus, const ubint_el_t& val) noexcept
        : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(length, val) {}

    /**
     * Basic constructor for specifying the length and modulus of the vector.
     *
     * @param length initial size in terms of the number of entries.
     * @param modulus string associated with entries in the vector.
     */
    explicit mubintvec(uint32_t length, const std::string& modulus)
        : modulus_(modulus), modulus_state_{State::INITIALIZED}, data_(length) {}

    /**
     * Copy constructor for copying a vector
     *
     * @param rhs is the mubintvec to be copied.
     */
    mubintvec(const mubintvec& rhs) noexcept
        : modulus_{rhs.modulus_}, modulus_state_{rhs.modulus_state_}, data_(rhs.data_) {}

    /**
     * Move constructor for moving a vector
     *
     * @param rhs is the mubintvec to be moved.
     */
    mubintvec(mubintvec&& rhs) noexcept
        : modulus_{std::move(rhs.modulus_)}, modulus_state_{rhs.modulus_state_}, data_(std::move(rhs.data_)) {}

    /**
     * Basic constructor for specifying the length of the vector with
     * modulus with initializer lists
     *
     * @param length initial size in terms of the number of entries.
     * @param modulus ubint associated with entries in the vector.
     * @param rhs initializer list of strings
     */
    explicit mubintvec(uint32_t length, const ubint_el_t& modulus, std::initializer_list<std::string> rhs) noexcept;

    /**
     * Basic constructor for specifying the length of the vector with
     * modulus with initializer lists
     *
     * @param length initial size in terms of the number of entries.
     * @param modulus ubint associated with entries in the vector.
     * @param rhs initializer list of uint64_t
     */
    explicit mubintvec(uint32_t length, const ubint_el_t& modulus, std::initializer_list<uint64_t> rhs) noexcept;

    // constructor specifying the mubintvec as a vector of strings and modulus
    explicit mubintvec(const std::vector<std::string>& s, const ubint_el_t& modulus) noexcept;

    // constructor specifying the mubintvec as a vector of strings and modulus
    explicit mubintvec(const std::vector<std::string>& s, const std::string& modulus) noexcept;

    /**
     * Assignment operator
     *
     * @param rhs is the mubintvec to be assigned from.
     * @return assigned mubintvec ref.
     */
    mubintvec& operator=(const mubintvec& rhs) noexcept;

    /**
     * move assignment contructor
     *
     * @param rhs is the mubintvec to move
     * @return the return value.
     */
    mubintvec& operator=(mubintvec&& rhs) noexcept {
        modulus_ = std::move(rhs.modulus_);
        modulus_state_ = rhs.modulus_state_;
        data_ = std::move(rhs.data_);
        return *this;
    }

    /**
     * Initializer list for mubintvec.
     *
     * @param rhs is the list of strings to be assigned to the mubintvec.
     * @return mubintvec object
     * note if  modulus is set then mod_value(input) is stored
     * note modulus remains unchanged.
     */
    mubintvec& operator=(std::initializer_list<std::string> rhs) noexcept;

    /**
     * Initializer list for mubintvec.
     *
     * @param rhs is the list of uint64_t to be assigned to the mubintvec.
     * @return mubintvec object
     * note if  modulus is set then mod_value(input) is stored
     * note modulus remains unchanged.
     */
    mubintvec& operator=(std::initializer_list<uint64_t> rhs) noexcept;

    /**
     * @param val is the uint64_t value to assign to the zeroth entry
     * @return resulting mubintvec
     * note that modulus remains untouched.
     */
    mubintvec& operator=(uint64_t val) {
        data_.at(0) = ubint_el_t(val);
        for (size_t i = 1; i < data_.size(); ++i)
            data_[i] = ubint_el_t();
        return *this;
    }

    /**
     * @param val is the ubint value to assign to the zeroth entry
     * @return resulting mubintvec
     */
    mubintvec& operator=(const ubint_el_t& val) {
        data_.at(0) = val;
        for (size_t i = 1; i < data_.size(); ++i)
            data_[i] = ubint_el_t();
        return *this;
    }

    size_t get_length() const {
        return data_.size();
    }

    /**
     * Sets/gets a value at an index.
     * This method is slower than operator[] as it checks if index out of range
     *
     * @param i is the index of the entry to access.
     * @return is a reference to the entry at the index.
     */
    ubint_el_t& at(size_t i) {
        if (!mubintvec::index_check(i))
            CIPHER_THROW("index out of range");
        return data_[i];
    }

    const ubint_el_t& at(size_t i) const {
        if (!mubintvec::index_check(i))
            CIPHER_THROW("index out of range");
        return data_[i];
    }

    ubint_el_t& operator[](size_t i) {
        return data_[i];
    }

    const ubint_el_t& operator[](size_t i) const {
        return data_[i];
    }

    /**
     * Checks the vector modulus state.
     * @return true if the modulus has been set.
     */
    bool is_modulus_set() const {
        return modulus_state_ == State::INITIALIZED;
    }

    /**
     * Sets the vector modulus.
     *
     * @param value is the value to set.
     */
    //    void set_modulus(uint32_t value) noexcept {
    //        modulus_       = ubint_el_t(value);
    //        modulus_state_ = State::INITIALIZED;
    //    }

    /**
     * Sets the vector modulus.
     *
     * @param value is the value to set.
     */
    void set_modulus(const ubint_el_t& value) noexcept {
        modulus_ = value;
        modulus_state_ = State::INITIALIZED;
    }

    void set_modulus(ubint_el_t&& value) noexcept {
        modulus_ = std::move(value);
        modulus_state_ = State::INITIALIZED;
    }

    /**
     * Sets the vector modulus.
     *
     * @param value is the value to set.
     */
    void set_modulus(const std::string& value) {
        modulus_ = ubint_el_t(value);
        modulus_state_ = State::INITIALIZED;
    }

    /**
     * Sets the vector modulus to the same as another mubintvec
     *
     * @param value is the vector whose modulus to use.
     */
    void set_modulus(const mubintvec& value) {
        modulus_ = value.get_modulus();
        modulus_state_ = State::INITIALIZED;
    }

    /**
     * Sets the vector modulus and changes the values to match the new modulus.
     *
     * @param value is the value to set.
     */
    void switch_modulus(const ubint_el_t& value);
    void lazy_switch_modulus(const ubint_el_t& value);

    mubintvec& mult_acc_eq_no_check(const mubintvec& a, const mubintvec& b) {
        CIPHER_THROW("MultAccEqNoCheck() not implemented for mubintvecdyn");
    }
    mubintvec& mult_acc_eq_no_check(const mubintvec& v, const ubint_el_t& i) {
        CIPHER_THROW("MultAccEqNoCheck() not implemented for mubintvecdyn");
    }

    /**
     * Gets the vector modulus.
     *
     * @return the vector modulus.
     */
    const ubint_el_t& get_modulus() const {
        if (modulus_state_ != State::INITIALIZED)
            CIPHER_THROW("GetModulus() on uninitialized mubintvec");
        return modulus_;
    }

    /**
     * Vector modulus operator. The vector modulus itself is left unchanged.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    mubintvec mod(const ubint_el_t& modulus) const;

    /**
     * Vector modulus operator. In-place variant. The vector modulus itself is left unchanged.
     *
     * @param modulus is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    mubintvec& mod_eq(const ubint_el_t& modulus);

    /**
     * Scalar-to-vector modulus addition operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    mubintvec mod_add(const ubint_el_t& b) const;

    /**
     * Scalar-to-vector modulus addition operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    mubintvec& mod_add_eq(const ubint_el_t& b);

    /**
     * Scalar modulus addition at a particular index.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    mubintvec mod_add_at_index(size_t i, const ubint_el_t& b) const;

    /**
     * Scalar modulus addition at a particular index. In-place variant.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    mubintvec& mod_add_at_index_eq(size_t i, const ubint_el_t& b);

    /**
     * Vector component wise modulus addition.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    mubintvec mod_add(const mubintvec& b) const;

    /**
     * Vector component wise modulus addition. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    mubintvec& mod_add_eq(const mubintvec& b);
    mubintvec& mod_add_no_check_eq(const mubintvec& b);

    /**
     * Scalar-from-vector modulus subtraction operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    mubintvec mod_sub(const ubint_el_t& b) const;

    /**
     * Scalar-from-vector modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    mubintvec& mod_sub_eq(const ubint_el_t& b);

    /**
     * Vector component wise modulus subtraction.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    mubintvec mod_sub(const mubintvec& b) const;

    /**
     * Vector component wise modulus subtraction. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    mubintvec& mod_sub_eq(const mubintvec& b);

    /**
     * Scalar-to-vector modulus multiplication operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    mubintvec mod_mul(const ubint_el_t& b) const;

    /**
     * Scalar-to-vector modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    mubintvec& mod_mul_eq(const ubint_el_t& b);

    /**
     * Vector component wise modulus multiplication.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    mubintvec mod_mul(const mubintvec& b) const;

    /**
     * Vector component wise modulus multiplication. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    mubintvec& mod_mul_eq(const mubintvec& b);
    mubintvec& mod_mul_no_check_eq(const mubintvec& b);

    /**
     * Scalar modulus exponentiation operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    mubintvec mod_exp(const ubint_el_t& b) const;

    /**
     * Scalar modulus exponentiation operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    mubintvec& mod_exp_eq(const ubint_el_t& b);

    /**
     * Modulus inverse operation.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    mubintvec mod_inverse() const;

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    mubintvec& mod_inverse_eq();

    /**
     * Modulus 2 operation, also a least significant bit.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    mubintvec mod_by_two() const;

    /**
     * Modulus 2 operation, also a least significant bit. In-place variant.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    mubintvec& mod_by_two_eq();

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    mubintvec multiply_and_round(const ubint_el_t& p, const ubint_el_t& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    mubintvec& multiply_and_round_eq(const ubint_el_t& p, const ubint_el_t& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    mubintvec divide_and_round(const ubint_el_t& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    mubintvec& divide_and_round_eq(const ubint_el_t& q);

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
    mubintvec get_digit_at_index_for_base(uint32_t index, uint32_t base) const;

    // STRINGS & STREAMS

    /**
     * ostream output << operator.
     *
     * @param os is the std ostream object.
     * @param ptr_obj is mubintvec to be printed.
     * @return is the ostream object.
     */
    friend std::ostream& operator<<(std::ostream& os, const mubintvec& ptr_obj) {
    #if 0  // old way
    os << std::endl;
    for (uint32_t i = 0; i < ptr_obj.data_.size(); i++) {
      os << ptr_obj.data_[i] << std::endl;
    }
    os << "modulus: " << ptr_obj.modulus_;
    os << std::endl;
    #else
        auto len = ptr_obj.data_.size();
        os << "[";
        for (uint32_t i = 0; i < len; i++) {
            os << ptr_obj.data_[i];
            os << ((i == (len - 1)) ? "]" : " ");
        }
        os << " modulus: " << ptr_obj.modulus_;
    #endif
        return os;
    }

    // SERIALIZATION

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("d", data_));
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("ms", modulus_state_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("d", data_));
        ar(::cereal::make_nvp("m", modulus_));
        ar(::cereal::make_nvp("ms", modulus_state_));
    }

    std::string serialized_object_name() const override {
        return "ExpVector";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    enum State { GARBAGE, INITIALIZED };

    ubint_el_t modulus_{};

    // enum to store the state of the
    State modulus_state_{State::GARBAGE};

    std::vector<ubint_el_t> data_{};

    bool index_check(size_t length) const {
        return length < data_.size();
    }
};

}  // namespace bigintdyn
#endif

#endif  // CIPHER_MATH_BACKEND_DYNAMIC_MOD_VECTOR_H_
