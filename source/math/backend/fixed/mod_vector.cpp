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

#include <cstdint>
#include <initializer_list>
#include <string>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE2

    #include "cipher/math/backend/fixed/mod_vector.h"
    #include "cipher/math/backend.h"
    #include "cipher/math/number_theory.h"
    #include "cipher/util/debug.h"
    #include "cipher/util/serializable.h"

namespace fixed_int {

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT() {
    this->length_ = 0;
    this->modulus_ = 0;
    data_ = nullptr;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(uint32_t length, const IntegerType& modulus) {
    this->length_ = length;
    this->modulus_ = modulus;
    this->data_ = new IntegerType[length_]();
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(const BigVectorFixedT& big_vector) {
    length_ = big_vector.length_;
    modulus_ = big_vector.modulus_;
    data_ = new IntegerType[length_];
    for (uint32_t i = 0; i < length_; i++) {
        data_[i] = big_vector.data_[i];
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(BigVectorFixedT&& big_vector) {
    if (this != &big_vector) {
        data_ = big_vector.data_;
        length_ = big_vector.length_;
        modulus_ = big_vector.modulus_;
        big_vector.data_ = nullptr;
        big_vector.length_ = 0;
        big_vector.modulus_ = 0;
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(uint32_t length, const IntegerType& modulus,
                                              std::initializer_list<std::string> rhs) {
    this->length_ = length;
    this->modulus_ = modulus;
    this->data_ = new IntegerType[length_]();
    uint32_t len = rhs.size();
    for (uint32_t i = 0; i < length_; i++) {  // this loops over each entry
        if (i < len) {
            data_[i] = IntegerType(*(rhs.begin() + i)) % modulus_;
        } else {
            data_[i] = 0;
        }
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(uint32_t length, const IntegerType& modulus,
                                              std::initializer_list<uint64_t> rhs) {
    this->length_ = length;
    this->modulus_ = modulus;
    this->data_ = new IntegerType[length_]();
    uint32_t len = rhs.size();
    for (uint32_t i = 0; i < length_; i++) {  // this loops over each entry
        if (i < len) {
            data_[i] = IntegerType(*(rhs.begin() + i)) % modulus_;
        } else {
            data_[i] = 0;
        }
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(const BigVectorFixedT& rhs) {
    if (this != &rhs) {
        if (this->length_ == rhs.length_) {
            for (size_t i = 0; i < length_; i++) {
                this->data_[i] = rhs.data_[i];
            }
        } else {
            delete[] data_;
            length_ = rhs.length_;
            modulus_ = rhs.modulus_;
            data_ = new IntegerType[length_];
            for (size_t i = 0; i < length_; i++) {
                data_[i] = rhs.data_[i];
            }
        }
        this->modulus_ = rhs.modulus_;
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(BigVectorFixedT&& rhs) {
    if (this != &rhs) {
        delete[] data_;
        data_ = rhs.data_;
        length_ = rhs.length_;
        modulus_ = rhs.modulus_;
        rhs.data_ = nullptr;
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(std::initializer_list<std::string> rhs) {
    size_t len = rhs.size();
    for (size_t i = 0; i < length_; i++) {
        if (i < len) {
            if (modulus_ != 0) {
                data_[i] = IntegerType(*(rhs.begin() + i)) % modulus_;
            } else {
                data_[i] = IntegerType(*(rhs.begin() + i));
            }
        } else {
            data_[i] = 0;
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) {
    size_t len = rhs.size();
    for (size_t i = 0; i < length_; i++) {
        if (i < len) {
            if (modulus_ != 0) {
                data_[i] = IntegerType(*(rhs.begin() + i)) % modulus_;
            } else {
                data_[i] = IntegerType(*(rhs.begin() + i));
            }
        } else {
            data_[i] = 0;
        }
    }
    return *this;
}

// ACCESSORS

/**Switches the integers in the vector to values corresponding to the new
 * modulus Algorithm: Integer i, Old Modulus om, New Modulus nm, delta =
 * abs(om-nm): Case 1: om < nm if i > i > om/2 i' = i + delta Case 2: om > nm i
 * > om/2 i' = i-delta
 */
template <class IntegerType>
void BigVectorFixedT<IntegerType>::switch_modulus(const IntegerType& new_modulus) {
    IntegerType old_modulus(this->modulus_);
    IntegerType n;
    IntegerType old_modulus_by_two(old_modulus >> 1);
    IntegerType diff((old_modulus > new_modulus) ? (old_modulus - new_modulus) : (new_modulus - old_modulus));
    for (uint32_t i = 0; i < this->length_; i++) {
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
    modulus_ = new_modulus;
}

template <class IntegerType>
void BigVectorFixedT<IntegerType>::lazy_switch_modulus(const IntegerType& modulus) {
    for (uint32_t i = 0; i < length_; ++i)
        this->data_[i].mod_eq(modulus);
    modulus_ = modulus;
}

// MODULAR ARITHMETIC OPERATIONS

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod(const IntegerType& modulus) const {
    BigVectorFixedT ans(*this);
    ans.mod_eq(modulus);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_eq(const IntegerType& modulus) {
    if (modulus == 2) {
        return this->mod_by_two_eq();
    } else {
        IntegerType half_q(modulus_ >> 1);
        for (uint32_t i = 0; i < length_; i++) {
            if (this->data_[i] > half_q) {
                this->data_[i].mod_sub_eq(modulus_, modulus);
            } else {
                this->data_[i].mod_eq(modulus);
            }
        }
        return *this;
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_add(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_add_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_add_eq(const IntegerType& b) {
    IntegerType bb = b.mod(this->modulus_);
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_add_fast_eq(bb, this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_add_at_index(uint32_t i, const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_add_at_index_eq(i, b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_add_at_index_eq(uint32_t i, const IntegerType& b) {
    if (i > length_ - 1) {
        CIPHER_THROW("mubintvecfxd::ModAddAtIndex. Index is out of range. i = " + std::to_string(i));
    }
    this->data_[i].mod_add_eq(b, this->modulus_);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_add(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_add_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_add_eq(const BigVectorFixedT& b) {
    if ((this->length_ != b.length_) || this->modulus_ != b.modulus_) {
        CIPHER_THROW("ModAddEq called on BigVectorFixedT's with different parameters.");
    }
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_add_fast_eq(b.data_[i], this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_add_no_check_eq(const BigVectorFixedT& b) {
    for (uint32_t i = 0; i < length_; ++i)
        data_[i].mod_add_fast_eq(b.data_[i], modulus_);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_sub(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_sub_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_sub_eq(const IntegerType& b) {
    IntegerType bb = b.mod(this->modulus_);
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_sub_fast_eq(bb, this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_sub(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_sub_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_sub_eq(const BigVectorFixedT& b) {
    if ((this->length_ != b.length_) || this->modulus_ != b.modulus_) {
        CIPHER_THROW("ModSubEq called on BigVectorFixedT's with different parameters.");
    }
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_sub_fast_eq(b.data_[i], this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_mul(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_mul_eq(b);
    return ans;
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_mul_eq(const IntegerType& b) {
    IntegerType bb = b.mod(this->modulus_);
    IntegerType mu = this->modulus_.compute_mu();  // Precompute the Barrett mu parameter
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_mul_eq(bb, this->modulus_, mu);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_mul(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_mul_eq(b);
    return ans;
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_mul_eq(const BigVectorFixedT& b) {
    if ((this->length_ != b.length_) || this->modulus_ != b.modulus_) {
        CIPHER_THROW("ModMulEq called on BigVectorFixedT's with different parameters.");
    }
    IntegerType mu = this->modulus_.compute_mu();
    // Precompute the Barrett mu parameter
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_mul_eq(b.data_[i], this->modulus_, mu);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_mul_no_check_eq(const BigVectorFixedT& b) {
    auto mu{modulus_.compute_mu()};
    for (uint32_t i = 0; i < length_; ++i)
        data_[i].mod_mul_eq(b[i], modulus_, mu);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_exp(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.mod_exp_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_exp_eq(const IntegerType& b) {
    IntegerType b_local(b);
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_exp_eq(b_local, this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_inverse() const {
    BigVectorFixedT ans(*this);
    ans.mod_inverse_eq();
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_inverse_eq() {
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mod_inverse_eq(this->modulus_);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mod_by_two() const {
    BigVectorFixedT ans(*this);
    ans.mod_by_two_eq();
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mod_by_two_eq() {
    IntegerType half_q(modulus_ >> 1);
    for (uint32_t i = 0; i < length_; i++) {
        if (this->data_[i] > half_q) {
            if (this->data_[i].mod(2) == 1) {
                this->data_[i] = IntegerType(0);
            } else {
                this->data_[i] = 1;
            }
        } else {
            if (this->data_[i].mod(2) == 1) {
                this->data_[i] = 1;
            } else {
                this->data_[i] = IntegerType(0);
            }
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::mult_with_out_mod(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.mult_with_out_mod_eq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::mult_with_out_mod_eq(const BigVectorFixedT& b) {
    if ((this->length_ != b.length_) || this->modulus_ != b.modulus_) {
        CIPHER_THROW("MultWithOutMod called on BigVectorFixedT's with different parameters.");
    }
    for (uint32_t i = 0; i < this->length_; i++) {
        this->data_[i].mul_eq(b.data_[i]);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::multiply_and_round(const IntegerType& p,
                                                                              const IntegerType& q) const {
    BigVectorFixedT ans(*this);
    ans.multiply_and_round_eq(p, q);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::multiply_and_round_eq(const IntegerType& p,
                                                                                  const IntegerType& q) {
    IntegerType half_q(this->modulus_ >> 1);
    IntegerType temp;
    for (uint32_t i = 0; i < this->length_; i++) {
        if (this->data_[i] > half_q) {
            temp = this->modulus_ - this->data_[i];
            this->data_[i] = this->modulus_ - temp.multiply_and_round(p, q);
        } else {
            this->data_[i].multiply_and_round_eq(p, q);
            this->data_[i].mod_eq(this->modulus_);
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::divide_and_round(const IntegerType& q) const {
    BigVectorFixedT ans(*this);
    ans.divide_and_round_eq(q);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::divide_and_round_eq(const IntegerType& q) {
    IntegerType half_q(this->modulus_ >> 1);
    IntegerType temp;
    for (uint32_t i = 0; i < this->length_; i++) {
        if (this->data_[i] > half_q) {
            temp = this->modulus_ - this->data_[i];
            this->data_[i] = this->modulus_ - temp.divide_and_round(q);
        } else {
            this->data_[i].divide_and_round_eq(q);
        }
    }
    return *this;
}

// OTHER OPERATIONS

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::get_digit_at_index_for_base(uint32_t index,
                                                                                       uint32_t base) const {
    BigVectorFixedT ans(*this);
    for (uint32_t i = 0; i < this->length_; i++) {
        ans.data_[i] = IntegerType(ans.data_[i].get_digit_at_index_for_base(index, base));
    }
    return ans;
}

template class BigVectorFixedT<BigIntegerFixedT<integral_dtype, BigIntegerBitLength>>;

}  // namespace fixed_int

#endif
