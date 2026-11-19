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
  This file contains the cpp implementation of mgmpintvec, a <vector> of gmpint, with associated math operators
 */

//==================================================================================
// This file is included only if CIPHER_WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================

#include <cstdint>
#include <initializer_list>
#include <string>

#include "cipher/config.h"
#ifdef CIPHER_WITH_NTL

    #define FASTNLOOSE
    #define FORCE_NORMALIZATION

    #include <chrono>

    #include "cipher/math/backend/ntl/mod_vector.h"
    #include "cipher/math/backend.h"
    #include "time.h"
    #include "cipher/util/debug.h"
    #include "cipher/util/diagnostic_output.h"
    #include "cipher/util/serializable.h"

namespace NTL {

// CONSTRUCTORS

// constructors without moduli
//&&&
// copy ctor with vector inputs
// creation ctors without moduli are marked GARBAGE
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const NtlModVector<ElemT>& a) : Vec<ElemT>(INIT_SIZE, a.length()) {
    int rv = this->copy_modulus(a);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        CIPHER_DIAGNOSTIC_ERR << "in NtlModVector(NtlModVector) Bad copy_modulus" << std::endl;
    #endif
    }
    *this = a;
}

// movecopy ctor
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(NtlModVector<ElemT>&& a) : Vec<ElemT>(INIT_SIZE, a.length()) {
    int rv = this->copy_modulus(a);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        CIPHER_DIAGNOSTIC_ERR << "in NtlModVector(NtlModVector &&) Bad copy_modulus" << std::endl;
    #endif
    }
    this->move(a);
}

// constructors with moduli
// ctor ElemT moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const long n, const ElemT& q) : Vec<ElemT>(INIT_SIZE, n) {  // NOLINT
    this->set_modulus(q);
}

// constructors with moduli and initializer list
// ctor ElemT moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const long n, const ElemT& q, std::initializer_list<uint64_t> rhs)  // NOLINT
    : Vec<ElemT>(INIT_SIZE, n) {                                                                      // NOLINT
    this->set_modulus(q);
    uint32_t len = rhs.size();
    for (size_t i = 0; i < size_t(n); i++) {  // this loops over each entry
        if (i < len) {
            (*this)[i] = ElemT(*(rhs.begin() + i)) % modulus_;
        } else {
            (*this)[i] = ElemT(0);
        }
    }
}

template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const long n, const ElemT& q, std::initializer_list<std::string> rhs)  // NOLINT
    : Vec<ElemT>(INIT_SIZE, n) {                                                                         // NOLINT
    this->set_modulus(q);
    uint32_t len = rhs.size();
    for (size_t i = 0; i < size_t(n); i++) {  // this loops over each entry
        if (i < len) {
            (*this)[i] = ElemT(*(rhs.begin() + i)) % modulus_;
        } else {
            (*this)[i] = ElemT(0);
        }
    }
}

template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const NtlModVector<ElemT>& a, const ElemT& q) : Vec<ElemT>(a) {
    this->set_modulus(q);
    (*this) %= q;
}

// ctor with string moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(size_t n, const std::string& sq) : Vec<ElemT>(INIT_SIZE, n) {
    this->set_modulus(ElemT(sq));
}

// copy with char * moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const NtlModVector<ElemT>& a, const std::string& sq) : Vec<ElemT>(a) {
    this->set_modulus(ElemT(sq));
}

// ctor with uint64_t moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(size_t n, uint64_t q) : Vec<ElemT>(INIT_SIZE, n) {
    this->set_modulus(q);
}

// copy with unsigned int moduli
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(const NtlModVector<ElemT>& a, const uint64_t q) : Vec<ElemT>(a) {
    this->set_modulus(q);
    for (size_t i = 0; i < this->get_length(); i++) {
        (*this)[i] %= ElemT(q);
    }
}

// constructor specifying the myvec as a vector of strings
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(std::vector<std::string>& s) {
    uint32_t len = s.size();
    this->resize(len);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = ElemT(s[i]);
    }
    this->modulus_state_ = GARBAGE;
}

// constructor specifying the myvec as a vector of strings with modulus
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(std::vector<std::string>& s, const ElemT& q) {
    uint32_t len = s.size();
    this->resize(len);
    this->set_modulus(q);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = ElemT(s[i]) % q;
    }
}

// constructor specifying the myvec as a vector of strings with modulus
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(std::vector<std::string>& s, const char* sq) {
    uint32_t len = s.size();
    this->resize(len);
    ElemT zzq(sq);
    this->set_modulus(zzq);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = ElemT(s[i]) % zzq;
    }
}

// constructor specifying the myvec as a vector of strings with modulus
template <class ElemT>
NtlModVector<ElemT>::NtlModVector(std::vector<std::string>& s, const uint64_t q) {
    uint32_t len = s.size();
    this->resize(len);
    ElemT zzq(q);
    this->set_modulus(zzq);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = ElemT(s[i]) % zzq;
    }
}

// ASSIGNMENT OPERATORS

// Assignment with initializer list of uint64_ts
// keeps current modulus

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(std::initializer_list<uint64_t> rhs) {
    size_t len = rhs.size();
    if (this->get_length() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->get_length(); i++) {  // this loops over each entry
        if (i < len) {
    #ifdef FORCE_NORMALIZATION
            if (is_modulus_set())
                (*this)[i] = ElemT(*(rhs.begin() + i)) % modulus_;
            else
                // must be set directly
    #endif
                (*this)[i] = ElemT(*(rhs.begin() + i));
        } else {
            (*this)[i] = ElemT(0);
        }
    }
    return *this;
}

// for some dumb reason they coded this., it is dangerous
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(std::initializer_list<int32_t> rhs) {
    size_t len = rhs.size();
    if (this->get_length() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->get_length(); i++) {  // this loops over each entry
        if (i < len) {
            int tmp = *(rhs.begin() + i);
            if (tmp < 0) {
                CIPHER_DIAGNOSTIC_OUT << "warning trying to assign negative integer value" << std::endl;
            }
    #ifdef FORCE_NORMALIZATION
            if (is_modulus_set())
                (*this)[i] = ElemT(tmp) % modulus_;
            else
                // must be set directly
    #endif
                (*this)[i] = ElemT(tmp);
        } else {
            (*this)[i] = ElemT(0);
        }
    }
    return *this;
}

// Assignment with initializer list of strings
// keeps current modulus
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(std::initializer_list<std::string> rhs) {
    size_t len = rhs.size();
    if (this->get_length() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->get_length(); i++) {  // this loops over each entry
        if (i < len) {
    #ifdef FORCE_NORMALIZATION
            if (is_modulus_set())
                (*this)[i] = ElemT(*(rhs.begin() + i)) % modulus_;
            else
                // must be set directly
    #endif
                (*this)[i] = ElemT(*(rhs.begin() + i));
        } else {
            (*this)[i] = ElemT(0);
        }
    }
    return *this;
}

// keeps current modulus
// note this only assigns to the first element!!
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(uint64_t val) {
    (*this)[0] = ElemT(val);
    #ifdef FORCE_NORMALIZATION
    if (is_modulus_set())
        (*this)[0] %= modulus_;
    #endif

    for (size_t i = 1; i < get_length(); ++i) {
        (*this)[i] = ElemT(0);
    }
    return *this;
}

// do not keep current modulus but copies from rhs.
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(const NtlModVector<ElemT>& rhs) {
    this->resize(rhs.get_length());
    int rv = this->copy_modulus(rhs);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        CIPHER_DIAGNOSTIC_ERR << "in operator=(NtlModVector) Bad copy_modulus" << std::endl;
    #endif
    }
    for (size_t i = 0; i < rhs.get_length(); i++) {
        (*this)[i] = rhs[i];
    }
    return *this;
}

// move copy do not keep current modulus but copies from rhs.
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::operator=(NtlModVector<ElemT>&& rhs) {
    if (this != &rhs) {
        this->resize(rhs.get_length());
        int rv = this->copy_modulus(rhs);
        if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
            CIPHER_DIAGNOSTIC_ERR << "in operator=(NtlModVector) Bad copy_modulus" << std::endl;
    #endif
        }
        this->move(rhs);
    }
    return *this;
}

template <class ElemT>
void NtlModVector<ElemT>::clear(NtlModVector<ElemT>& x) {
    size_t n = x.get_length();
    for (size_t i = 0; i < n; i++) {
        NTL_NAMESPACE::clear(x[i]);
    }
    NTL_NAMESPACE::clear(x.modulus_);
}

// not enabled yet

// ACCESSORS

// Switches the integers in the vector to values corresponding to the new
// modulus
//*  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
// *  Case 1: om < nm
// *  if i > i > om/2
// *  i' = i + delta
// *  Case 2: om > nm
// *  i > om/2
// *  i' = i-delta
//
template <class ElemT>
void NtlModVector<ElemT>::switch_modulus(const ElemT& new_modulus) {
    ElemT old_modulus(this->modulus_);
    ElemT n;
    ElemT old_modulus_by_two(old_modulus >> 1);
    ElemT diff((old_modulus > new_modulus) ? (old_modulus - new_modulus) : (new_modulus - old_modulus));
    for (size_t i = 0; i < this->get_length(); i++) {
        n = this->at(i);
        if (old_modulus < new_modulus) {
            if (n > old_modulus_by_two) {
                this->at(i) = n.mod_add(diff, new_modulus);
            } else {
                this->at(i) = n.mod(new_modulus);
            }
        } else {
            if (n > old_modulus_by_two) {
                this->at(i) = n.mod_sub(diff, new_modulus);
            } else {
                this->at(i) = n.mod(new_modulus);
            }
        }
    }
    this->set_modulus(new_modulus);
}

template <class ElemT>
void NtlModVector<ElemT>::lazy_switch_modulus(const ElemT& modulus) {
    for (uint32_t i = 0; i < this->get_length(); ++i)
        this->operator[](i).mod_eq(modulus);
    this->set_modulus(modulus);
}

// MODULAR ARITHMETIC FUNCTIONS

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::mod(const ElemT& modulus) const {
    if (modulus == ElemT(2)) {
        return this->mod_by_two();
    } else {
        ElemT this_mod(this->get_modulus());
        NtlModVector ans(this->get_length(), this_mod);  // zeroed out
        ElemT half_q(this_mod >> 1);
        for (size_t i = 0; i < this->get_length(); i++) {
            if ((*this)[i] > half_q) {
                ans[i] = (*this)[i].mod_sub(this_mod, modulus);
            } else {
                ans[i] = (*this)[i].mod(modulus);
            }
        }
        return ans;
    }
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::mod_eq(const ElemT& modulus) {
    if (modulus == ElemT(2)) {
        return this->mod_by_two_eq();
    } else {
        ElemT this_mod(this->get_modulus());
        ElemT half_q(this_mod >> 1);
        for (size_t i = 0; i < this->get_length(); i++) {
            if (this->operator[](i) > half_q) {
                this->operator[](i).mod_sub_eq(this_mod, modulus);
            } else {
                this->operator[](i).mod_eq(modulus);
            }
        }
        return *this;
    }
}

// method to add scalar to vector element at index i
template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::mod_add_at_index(size_t i, const ElemT& b) const {
    if (i > this->get_length() - 1) {
        CIPHER_THROW("Index is out of range. i = " + std::to_string(i));
    }
    NtlModVector ans(*this);  // copy vector
    modulus_check("NtlModVector::mod_add_at_index");
    ans[i] = ans[i].mod_add(b, this->modulus_);
    return ans;
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::mod_add_at_index_eq(size_t i, const ElemT& b) {
    if (i > this->get_length() - 1) {
        CIPHER_THROW("Index is out of range. i = " + std::to_string(i));
    }
    modulus_check("NtlModVector::mod_add_at_index");
    (*this)[i] = (*this)[i].mod_add(b, this->modulus_);
    return *this;
}

// procedural addition
// todo make modulus explicit.
template <class ElemT>
inline void NtlModVector<ElemT>::modadd_p(NtlModVector<ElemT>& x, NtlModVector<ElemT> const& a,
                                          NtlModVector<ElemT> const& b) const {
    a.arg_check_vector(b, "NtlModVector::modadd()");
    size_t n = a.get_length();
    if (b.get_length() != n)
        LogicError("NtlModVector<>vector add: dimension mismatch");

    x.resize(n);
    for (size_t i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].mod_add(b[i], modulus_);  // modulo add
    #else
        x[i] = a[i].mod_add_fast(b[i], modulus_);  // modulo add
    #endif
    }
}

// procedural subtraction
// todo make modulus explicit.

template <class ElemT>
void NtlModVector<ElemT>::modsub_p(NtlModVector<ElemT>& x, NtlModVector<ElemT> const& a,
                                   NtlModVector<ElemT> const& b) const {
    a.arg_check_vector(b, "NtlModVector::sub()");
    size_t n = a.get_length();
    if (b.get_length() != n)
        LogicError("NtlModVector<>vector sub: dimension mismatch");
    x.resize(n);
    for (size_t i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].mod_sub(b[i], modulus_);  // inmplicit modulo sub
    #else
        x[i] = a[i].mod_sub_fast(b[i], modulus_);  // inmplicit modulo sub
    #endif
    }
}

// todo make modulus explicit.
template <class ElemT>
inline void NtlModVector<ElemT>::modmul_p(NtlModVector<ElemT>& x, NtlModVector<ElemT> const& a,
                                          NtlModVector<ElemT> const& b) const {
    a.arg_check_vector(b, "NtlModVector::mul()");
    unsigned int n = a.get_length();
    if (b.get_length() != n)
        LogicError("NtlModVector<>vector sub: dimension mismatch");

    x.resize(n);
    unsigned int i;
    for (i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].mod_mul(b[i], modulus_);  // inmplicit modulo mul
    #else
        x[i] = a[i].mod_mul_fast(b[i], modulus_);  // inmplicit modulo mul
    #endif
    }
}

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::mod_exp(const ElemT& b) const {
    NtlModVector ans(*this);
    modulus_check("NtlModVector::mod_exp");
    ElemT b_local(b);
    for (size_t i = 0; i < this->get_length(); i++) {
        ans[i] = ans[i].mod_exp(b_local, ans.modulus_);
    }
    return ans;
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::mod_exp_eq(const ElemT& b) {
    modulus_check("NtlModVector::mod_exp");
    ElemT b_local(b);
    for (size_t i = 0; i < this->get_length(); i++) {
        (*this)[i] = (*this)[i].mod_exp(b_local, this->modulus_);
    }
    return *this;
}

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::mod_inverse(void) const {
    modulus_check("NtlModVector::mod_inverse");
    NtlModVector ans(*this);
    for (size_t i = 0; i < this->get_length(); i++) {
        ans[i] = ans[i].mod_inverse(this->modulus_);
    }
    return ans;
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::mod_inverse_eq(void) {
    modulus_check("NtlModVector::mod_inverse");
    for (size_t i = 0; i < this->get_length(); i++) {
        (*this)[i] = (*this)[i].mod_inverse(this->modulus_);
    }
    return *this;
}

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::mod_by_two() const {
    NtlModVector ans(*this);
    ans.mod_by_two_eq();
    return ans;
}

// method to mod by two
template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::mod_by_two_eq() {
    ElemT half_q(this->get_modulus() >> 1);
    for (size_t i = 0; i < this->get_length(); i++) {
        if (this->operator[](i) > half_q) {
            if (this->operator[](i).mod(ElemT(2)) == ElemT(1)) {
                this->operator[](i) = 0;
            } else {
                this->operator[](i) = 1;
            }
        } else {
            if (this->operator[](i).mod(ElemT(2)) == ElemT(1)) {
                this->operator[](i) = 1;
            } else {
                this->operator[](i) = 0;
            }
        }
    }
    return *this;
}

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::multiply_and_round(const ElemT& p, const ElemT& q) const {
    modulus_check("NtlModVector::multiply_and_round");
    NtlModVector ans(*this);
    ElemT half_q(this->modulus_ >> 1);
    for (size_t i = 0; i < this->get_length(); i++) {
        if (ans[i] > half_q) {
            ElemT temp = this->modulus_ - ans[i];
            ans[i] = this->modulus_ - temp.multiply_and_round(p, q);
        } else {
            ans[i] = ans[i].multiply_and_round(p, q).mod(this->modulus_);
        }
    }
    return ans;
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::multiply_and_round_eq(const ElemT& p, const ElemT& q) {
    modulus_check("NtlModVector::multiply_and_round");
    ElemT half_q(this->modulus_ >> 1);
    for (size_t i = 0; i < this->get_length(); i++) {
        if ((*this)[i] > half_q) {
            ElemT temp = this->modulus_ - (*this)[i];
            (*this)[i] = this->modulus_ - temp.multiply_and_round(p, q);
        } else {
            (*this)[i] = (*this)[i].multiply_and_round(p, q).mod(this->modulus_);
        }
    }
    return *this;
}

template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::divide_and_round(const ElemT& q) const {
    modulus_check("NtlModVector::divide_and_round");
    NtlModVector ans(*this);
    ElemT half_q(this->modulus_ >> 1);
    for (size_t i = 0; i < this->get_length(); i++) {
        if (ans[i] > half_q) {
            ElemT temp = this->modulus_ - ans[i];
            ans[i] = this->modulus_ - temp.divide_and_round(q);
        } else {
            ans[i] = ans[i].divide_and_round(q);
        }
    }
    return ans;
}

template <class ElemT>
NtlModVector<ElemT>& NtlModVector<ElemT>::divide_and_round_eq(const ElemT& q) {
    modulus_check("NtlModVector::divide_and_round");
    ElemT half_q(this->modulus_ >> 1);
    for (size_t i = 0; i < this->get_length(); i++) {
        if ((*this)[i] > half_q) {
            ElemT temp = this->modulus_ - (*this)[i];
            (*this)[i] = this->modulus_ - temp.divide_and_round(q);
        } else {
            (*this)[i] = (*this)[i].divide_and_round(q);
        }
    }
    return *this;
}

// OTHER FUNCTIONS

// not sure what this does..
template <class ElemT>
NtlModVector<ElemT> NtlModVector<ElemT>::get_digit_at_index_for_base(size_t index, uint32_t base) const {
    NtlModVector ans(*this);
    for (size_t i = 0; i < this->get_length(); i++) {
        ans[i] = ans[i].get_digit_at_index_for_base(index, base);
    }
    return ans;
}

template class NtlModVector<NtlInteger>;

}  // namespace NTL

#endif
