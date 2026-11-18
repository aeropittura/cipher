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
  This file contains mgmpintvec, a <vector> of gmpint, with associated math operators.
  NOTE: this has been refactored so that implied modulo (ring) aritmetic is in mbintvec
 */

//==================================================================================
// This file is included only if CIPHER_WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================
#ifndef CIPHER_MATH_BACKEND_NTL_MOD_VECTOR_H_
#define CIPHER_MATH_BACKEND_NTL_MOD_VECTOR_H_

#include <cstdint>
#include <type_traits>

#include "cipher/config.h"
#ifdef CIPHER_WITH_NTL

    #include <NTL/SmartPtr.h>
    #include <NTL/vec_ZZ.h>
    #include <NTL/vector.h>

    #include <initializer_list>
    #include <ostream>
    #include <string>
    #include <vector>

    #include "cipher/math/backend/ntl/integer.h"
    #include "cipher/math/backend/vector.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"

// defining this forces modulo when you write to the vector (except with at())
// this is becuase NTL required inputs to modmath to be < modulus but BU does
// not play with this and you will see different tests in pke pass and fail.
// I think this will go away soon
// #define FORCE_NORMALIZATION

// defining this enables a run time warning when a vector with uninitialized
// modulus is used in math operations (A very bad thing)
// #define WARN_BAD_MODULUS

/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {

// Forward declare this class for aliases
template <typename IntegerType>
class myVecP;

// Create default type for the CIPHER_MATH_BACKEND 6 Vector
using BigVector = myVecP<BigInteger>;

/**
 * @brief The class for representing vectors of ubint with associated modulo
 * math
 */

template <typename myT>
class myVecP : public NTL::Vec<myT>, public cipher::BigVectorInterface<myVecP<myT>, myT>, public cipher::Serializable {
  public:
    // CONSTRUCTORS

    myVecP() : Vec<myT>() {
        modulus_state_ = GARBAGE;
    }

    static inline myVecP single(const myT& val, const myT& modulus) {
        myVecP vec(1);
        vec.set_modulus(modulus);
        vec[0] = val;
        return vec;
    }

    explicit myVecP(const size_t length) : Vec<myT>(INIT_SIZE, length) {
        modulus_state_ = GARBAGE;
    }

    myVecP(INIT_SIZE_TYPE, const long length) : Vec<myT>(INIT_SIZE, length) {  // NOLINT
        modulus_state_ = GARBAGE;
    }

    explicit myVecP(const myVecP<myT>& a);

    myVecP(myVecP<myT>&& a);

    myVecP(const long n, const myT& q);  // NOLINT
    myVecP(uint32_t n, const myT& q, const myT& v) : Vec<myT>(INIT_SIZE, n) {
        this->set_modulus(q);
        for (uint32_t i{0}; i < n; ++i)
            (*this)[i] = v;
    }

    myVecP(const long n, const myT& q, std::initializer_list<std::string> rhs);  // NOLINT
    myVecP(const long n, const myT& q, std::initializer_list<uint64_t> rhs);     // NOLINT

    myVecP(const myVecP<myT>& a, const myT& q);

    myVecP(size_t n, const std::string& sq);

    myVecP(const myVecP<myT>& a, const std::string& sq);

    myVecP(size_t n, uint64_t q);

    myVecP(const myVecP<myT>& a, const uint64_t q);

    explicit myVecP(std::vector<std::string>& s);           // without modulus
    myVecP(std::vector<std::string>& s, const myT& q);      // with modulus
    myVecP(std::vector<std::string>& s, const char* sq);    // with modulus
    myVecP(std::vector<std::string>& s, const uint64_t q);  // with modulusu

    void clear(myVecP& x);  // why isn't this inhereted?

    ~myVecP() {}

    // ASSIGNMENT OPERATORS

    myVecP& operator=(const myVecP& a);
    myVecP& operator=(myVecP&& a);

    myVecP& operator=(std::initializer_list<uint64_t> rhs);
    myVecP& operator=(std::initializer_list<int32_t> rhs);
    myVecP& operator=(std::initializer_list<std::string> rhs);
    myVecP& operator=(uint64_t rhs);

    // ACCESSORS

    // NOTE the underlying Vec does not have a no-bounds-checking operator[]
    myT& at(size_t i) {
        return this->NTL::Vec<myT>::at(i);
    }

    const myT& at(size_t i) const {
        return this->NTL::Vec<myT>::at(i);
    }

    myT& operator[](size_t idx) {
        return this->at(idx);
    }

    const myT& operator[](size_t idx) const {
        return this->at(idx);
    }

    inline void push_back(const myT& a) {
        this->append(a);
    }

    void switch_modulus(const myT& new_modulus);
    void lazy_switch_modulus(const myT& new_modulus);

    myVecP& mult_acc_eq_no_check(const myVecP& a, const myVecP& b) {
        CIPHER_THROW("MultAccEqNoCheck() not implemented for mubintvecntl");
    }
    myT& mult_acc_eq_no_check(const myVecP& v, const myT& i) {
        CIPHER_THROW("MultAccEqNoCheck() not implemented for mubintvecntl");
    }

    // public modulus accessors
    inline bool is_modulus_set(void) const {
        return (this->modulus_state_ == INITIALIZED);
    }

    // return true if both myVecP have same modulus
    inline bool SameModulus(const myVecP& a) const {
        return ((this->modulus_state_ == a.modulus_state_) && (this->modulus_ == a.modulus_));
    }

    // sets modulus and the NTL init function uint64_t argument
    inline void set_modulus(uint64_t value) {
        if (value == 0) {
            CIPHER_THROW("SetModulus(uint64_t) cannot be zero");
        }
        this->modulus_ = myT(value);
        this->modulus_state_ = INITIALIZED;
    }

    // sets modulus and the NTL init function myT argument
    void set_modulus(const myT& value) {
        if (value == myT(0)) {
            CIPHER_THROW("SetModulus(myT) cannot be zero");
        }
        this->modulus_ = value;
        this->modulus_state_ = INITIALIZED;
    }

    // sets modulus and the NTL init function string argument
    inline void set_modulus(const std::string& value) {
        this->modulus_ = myT(value);
        if (this->modulus_ == myT(0)) {
            CIPHER_THROW("SetModulus(string) cannot be zero");
        }
        this->modulus_state_ = INITIALIZED;
    }

    // sets modulus and the NTL init function uses same modulus
    inline void set_modulus(const myVecP& value) {
        this->modulus_ = value.get_modulus();
        if (this->modulus_ == myT(0)) {
            CIPHER_THROW("SetModulus(myVecP) cannot be zero");
        }
        this->modulus_state_ = INITIALIZED;
    }

    const myT& get_modulus() const {
        if (this->is_modulus_set()) {
            return (this->modulus_);
        } else {
            CIPHER_THROW("modulus not set");
        }
    }

    inline int CopyModulus(const myVecP& rhs) {
        this->modulus_ = rhs.modulus_;
        this->modulus_state_ = rhs.modulus_state_;
        if (is_modulus_set()) {
            return (0);
        } else {
            this->modulus_state_ = GARBAGE;
            return (-1);
        }
    }

    size_t get_length(void) const {
        return this->length();
    }

    void resize(size_t n) {
        // resize is the STL::vector standard call for this functionality
        this->SetLength(n);  // SetLength() is the NTL::Vec member
    }

    // the library-wide vector interface; forwards to NTL::Vec::SetLength()
    void set_length(size_t n) {
        this->SetLength(n);
    }

    // MODULUS ARITHMETIC OPERATIONS

    /**
     * Vector modulus operator.
     *
     * @param b is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    myVecP mod(const myT& b) const;

    /**
     * Vector modulus operator. In-place variant.
     *
     * @param b is the modulus to perform on the current vector entries.
     * @return is the result of the modulus operation on current vector.
     */
    myVecP& mod_eq(const myT& b);

    /**
     * Scalar-to-vector modulus addition operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    myVecP mod_add(const myT& b) const {
        ModulusCheck("Warning: myVecP::ModAdd");
        myVecP ans(*this);
        ans.mod_add_eq(b);
        return ans;
    }

    /**
     * Scalar-to-vector modulus addition operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus addition operation.
     */
    myVecP& mod_add_eq(const myT& b) {
        ModulusCheck("Warning: myVecP::ModAdd");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_add_eq(b, this->modulus_);
        }
        return *this;
    }

    /**
     * Scalar modulus addition at a particular index.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    myVecP mod_add_at_index(size_t i, const myT& b) const;

    /**
     * Scalar modulus addition at a particular index. In-place variant.
     *
     * @param i is the index of the entry to add.
     * @param b is the scalar to add.
     * @return is the result of the modulus addition operation.
     */
    myVecP& mod_add_at_index_eq(size_t i, const myT& b);

    /**
     * Vector component wise modulus addition.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    myVecP mod_add(const myVecP& b) const {
        ArgCheckVector(b, "myVecP ModAdd()");
        myVecP ans(*this);
        ans.mod_add_eq(b);
        return ans;
    }

    /**
     * Vector component wise modulus addition. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus addition operation.
     */
    myVecP& mod_add_eq(const myVecP& b) {
        ArgCheckVector(b, "myVecP ModAddEq()");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_add_eq(b[i], this->modulus_);
        }
        return *this;
    }

    myVecP& mod_add_no_check_eq(const myVecP& b) {
        for (uint32_t i = 0; i < this->get_length(); i++)
            this->operator[](i).mod_add_eq(b[i], this->modulus_);
        return *this;
    }

    /// procedural version for the vector component wise modulus addition
    /// operation.
    void modadd_p(myVecP& x, const myVecP& a, const myVecP& b) const;

    /**
     * Scalar-from-vector modulus subtraction operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    myVecP mod_sub(const myT& b) const {
        ModulusCheck("Warning: myVecP::ModSub");
        myVecP ans(*this);
        ans.mod_sub_eq(b);
        return ans;
    }

    /**
     * Scalar-from-vector modulus subtraction operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus subtraction operation.
     */
    myVecP& mod_sub_eq(const myT& b) {
        ModulusCheck("Warning: myVecP::ModSubEq");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_sub_eq(b, this->modulus_);
        }
        return (*this);
    }

    /**
     * Vector component wise modulus subtraction.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    myVecP mod_sub(const myVecP& b) const {
        ArgCheckVector(b, "myVecP ModSub()");
        myVecP ans(*this);
        ans.mod_sub_eq(b);
        return ans;
    }

    /**
     * Vector component wise modulus subtraction. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus subtraction operation.
     */
    myVecP& mod_sub_eq(const myVecP& b) {
        ArgCheckVector(b, "myVecP ModSubEq()");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_sub_eq(b[i], this->modulus_);
        }
        return (*this);
    }

    /// procedural version for the vector component wise modulus subtraction
    /// operation.
    void modsub_p(myVecP& x, const myVecP& a, const myVecP& b) const;

    /**
     * Scalar-to-vector modulus multiplication operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    myVecP mod_mul(const myT& b) const {
        ModulusCheck("Warning: myVecP::ModMul");
        myVecP ans(*this);
        ans.mod_mul_eq(b);
        return ans;
    }

    /**
     * Scalar-to-vector modulus multiplication operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus multiplication operation.
     */
    myVecP& mod_mul_eq(const myT& b) {
        ModulusCheck("Warning: myVecP::ModMul");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_mul_eq(b, this->modulus_);
        }
        return (*this);
    }

    /**
     * Vector component wise modulus multiplication.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    myVecP mod_mul(const myVecP& b) const {
        ArgCheckVector(b, "myVecP Mul()");
        myVecP ans(*this);
        ans.mod_mul_eq(b);
        return ans;
    }

    /**
     * Vector component wise modulus multiplication. In-place variant.
     *
     * @param b is the vector to perform operation with.
     * @return is the result of the component wise modulus multiplication
     * operation.
     */
    myVecP& mod_mul_eq(const myVecP& b) {
        ArgCheckVector(b, "myVecP Mul()");
        for (uint32_t i = 0; i < this->get_length(); i++) {
            this->operator[](i).mod_mul_eq(b[i], this->modulus_);
        }
        return (*this);
    }

    myVecP& mod_mul_no_check_eq(const myVecP& b) {
        for (uint32_t i = 0; i < this->get_length(); i++)
            this->operator[](i).mod_mul_eq(b[i], this->modulus_);
        return (*this);
    }

    /// procedural version for the vector component wise modulus multiplication
    /// operation.
    void modmul_p(myVecP& x, const myVecP& a, const myVecP& b) const;

    /**
     * Scalar modulus exponentiation operation.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    myVecP mod_exp(const myT& b) const;

    /**
     * Scalar modulus exponentiation operation. In-place variant.
     *
     * @param b is the scalar to perform operation with.
     * @return is the result of the modulus exponentiation operation.
     */
    myVecP& mod_exp_eq(const myT& b);

    /**
     * Modulus inverse operation.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    myVecP mod_inverse() const;

    /**
     * Modulus inverse operation. In-place variant.
     *
     * @return is the result of the component wise modulus inverse operation.
     */
    myVecP& mod_inverse_eq();

    /**
     * Modulus 2 operation, also a least significant bit.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    myVecP mod_by_two() const;

    /**
     * Modulus 2 operation, also a least significant bit. In-place variant.
     *
     * @return is the result of the component wise modulus 2 operation, also a
     * least significant bit.
     */
    myVecP& mod_by_two_eq();

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    myVecP multiply_and_round(const myT& p, const myT& q) const;

    /**
     * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param p is the numerator to be multiplied.
     * @param q is the denominator to be divided.
     * @return is the result of multiply and round operation.
     */
    myVecP& multiply_and_round_eq(const myT& p, const myT& q);

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    myVecP divide_and_round(const myT& q) const;

    /**
     * Divide and Rounding operation. Returns [x/q] where [] is the rounding
     * operation. In-place variant.
     *
     * @param q is the denominator to be divided.
     * @return is the result of divide and round operation.
     */
    myVecP& divide_and_round_eq(const myT& q);

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
    myVecP get_digit_at_index_for_base(size_t index, uint32_t base) const;

    // STRINGS & STREAMS

    /**
     * ostream operator to output vector values to console
     *
     * @param os is the std ostream object.
     * @param ptr_obj is the myVecP object to be printed.
     * @return std ostream object which captures the vector values.
     */
    friend std::ostream& operator<<(std::ostream& os, const myVecP<myT>& ptr_obj) {
        auto len = ptr_obj.get_length();
        os << "[";
        for (size_t i = 0; i < len; i++) {
            os << ptr_obj.at(i);
            os << ((i == (len - 1)) ? "]" : " ");
        }
        os << " modulus: " << ptr_obj.modulus_;
        return os;
    }

    // SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        // YSP. This was seg-faulting in MINGW
        // ar( modulus_.to_string() );
        // ar( modulus_state_ );
        // ar( this->get_length() );
        // for(size_t i=0; i<this->get_length(); i++ )
        //  ar( (*this)[i] );
        ar(::cereal::make_nvp("m", modulus_.to_string()));
        ar(::cereal::make_nvp("ms", modulus_state_));
        ar(::cereal::make_nvp("l", this->get_length()));
        for (size_t i = 0; i < this->get_length(); i++) {
            ar(::cereal::make_nvp("v", (*this)[i].to_string()));
        }
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
            Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", modulus_.to_string()));
        ar(::cereal::make_nvp("ms", modulus_state_));
        ar(::cereal::make_nvp("l", this->get_length()));
        for (size_t i = 0; i < this->get_length(); i++) {
            ar(::cereal::make_nvp("v", (*this)[i].to_string()));
        }
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        // YSP. This was seg-faulting in MINGW
        // std::string m;
        // ar( m );
        // modulus_ = m;
        // ar( modulus_state_ );
        // cereal::size_type len;
        // ar( len );
        // this->set_length(len);
        // for(size_t i=0; i<len; i++ )
        //  ar( (*this)[i] );

        std::string m;
        ar(::cereal::make_nvp("m", m));
        modulus_ = m;
        ar(::cereal::make_nvp("ms", modulus_state_));
        cereal::size_type len;
        ar(::cereal::make_nvp("l", len));
        this->resize(len);
        for (size_t i = 0; i < len; i++) {
            std::string s;
            ar(::cereal::make_nvp("v", s));
            (*this)[i] = s;
        }
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
            Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        std::string m;
        ar(::cereal::make_nvp("m", m));
        modulus_ = m;
        ar(::cereal::make_nvp("ms", modulus_state_));
        cereal::size_type len;
        ar(::cereal::make_nvp("l", len));
        this->resize(len);
        for (size_t i = 0; i < len; i++) {
            std::string s;
            ar(::cereal::make_nvp("v", s));
            (*this)[i] = s;
        }
    }

    std::string serialized_object_name() const {
        return "NTLVector";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // utility function to warn if modulus is no good
    // use when argument to function is myT
    void ModulusCheck(std::string msg) const {
        if (!is_modulus_set()) {
            CIPHER_THROW(msg + " uninitialized this->modulus");
        }
    }

    // utility function to check argument consistency for vector vector fns
    // use when argument to function is myVecP
    void ArgCheckVector(const myVecP& b, std::string fname) const {
        if (this->modulus_ != b.modulus_) {
            CIPHER_THROW(fname + " modulus vector modulus vector op of different moduli");
        } else if (!is_modulus_set()) {
            CIPHER_THROW(fname + " modulus vector modulus vector op  GARBAGE  moduli");
        } else if (this->get_length() != b.get_length()) {
            CIPHER_THROW(fname + " vectors of different lengths");
        }
    }

    // used to make sure all entries in this are <=current modulus
    void Renormalize(void) {
        for (size_t i = 0; i < this->get_length(); ++i) {
            (*this)[i] %= modulus_;
        }
    }

    myT modulus_;
    // TODO: BE 2 has gotten rid of this, we may too.
    enum ModulusState {
        GARBAGE,
        INITIALIZED  // note different order,  GARBAGE is the default
                     // state
    };
    // enum to store the state of the
    ModulusState modulus_state_;

  protected:
    bool index_check(size_t index) const {
        return index < this->get_length();
    }
};
// template class ends

}  // namespace NTL

#endif  // CIPHER_WITH_NTL

#endif  // CIPHER_MATH_BACKEND_NTL_MOD_VECTOR_H_
