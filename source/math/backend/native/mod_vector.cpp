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
  This code provides basic arithmetic functionality for vectors of native integers
 */

#include "cipher/math/backend/native/mod_vector.h"

#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "cipher/math/backend.h"
#include "cipher/math/number_theory_impl.h"
#include "cipher/util/exception.h"

namespace native_int {

#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 12
    #define CIPHER_COMPARE_SELECT_LANES 1
#endif

template <typename T>
static inline T top_bit_mask(T x) {
    return static_cast<T>(0) - static_cast<T>(x >> (sizeof(T) * 8 - 1));
}

template <typename T>
static inline T mod_add_lane(T a, T b, T m) {
#if defined(CIPHER_COMPARE_SELECT_LANES) || defined(__clang__)
    T t = a + b;
    return t >= m ? t - m : t;
#else
    T t = a + b - m;
    return t + (m & top_bit_mask(t));
#endif
}

template <typename T>
static inline T mod_sub_lane(T a, T b, T m) {
#ifdef CIPHER_COMPARE_SELECT_LANES
    T t = a - b;
    return a < b ? t + m : t;
#else
    T t = a - b;
    return t + (m & top_bit_mask(t));
#endif
}

template <typename T>
static inline T centered_correction_lane(T v, T half_q, T diff) {
#ifdef CIPHER_COMPARE_SELECT_LANES
    return v > half_q ? diff : static_cast<T>(0);
#else
    return diff & top_bit_mask(half_q - v);
#endif
}

template <class IntegerType>
void NativeVectorT<IntegerType>::general_shrink_loop(IntegerType* dst, const IntegerType* src, size_t size, BasicInt ov,
                                                     BasicInt nv) {
    using DInt = typename IntegerType::DNativeInt;
    const BasicInt half_q{ov >> 1};
    const BasicInt diff_r{static_cast<BasicInt>((ov - nv) % nv)};
    if constexpr (sizeof(DInt) > sizeof(BasicInt)) {
        // e >= 1 is what bounds the quotient estimate to a single correction below
        const int64_t e{static_cast<int64_t>(cipher::get_msb(nv)) - 2};
        if (e >= 1) {
            // mu = floor(2^(W+e) / nv) fits a word because nv >= 2^(e+1), which is also
            // div_d's hi < divisor precondition; the estimate never exceeds the true
            // quotient and falls short of it by at most one
            const BasicInt mu{IntegerType::div_d(BasicInt(1) << e, 0, nv)};
            for (size_t i = 0; i < size; ++i) {
                const BasicInt v{src[i].value_};
                BasicInt av{v};
                // kept as a branch, not folded into the reduction: callers are uniform in
                // which way it goes (a near-equal shrink skips every element, a deep one
                // reduces every element), so it predicts and the near-equal case pays nothing
                if (av >= nv) {
                    av -= static_cast<BasicInt>(IntegerType::mult_d_hi(v, mu) >> e) * nv;
                    if (av >= nv)
                        av -= nv;
                }
                dst[i].value_ = mod_sub_lane(av, centered_correction_lane(v, half_q, diff_r), nv);
            }
            return;
        }
    }
    for (size_t i = 0; i < size; ++i) {
        const BasicInt v{src[i].value_};
        BasicInt av{v};
        if (av >= nv)
            av %= nv;
        dst[i].value_ = mod_sub_lane(av, centered_correction_lane(v, half_q, diff_r), nv);
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(uint32_t length, const IntegerType& modulus,
                                          std::initializer_list<std::string> rhs) noexcept
    : modulus_{modulus}, data_(length) {
    const uint32_t vlen = (rhs.size() < data_.size()) ? rhs.size() : data_.size();
    for (uint32_t i = 0; i < vlen; ++i)
        data_[i] = *(rhs.begin() + i) % modulus_;
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(uint32_t length, const IntegerType& modulus,
                                          std::initializer_list<uint64_t> rhs) noexcept
    : modulus_{modulus}, data_(length) {
    const uint32_t vlen = (rhs.size() < data_.size()) ? rhs.size() : data_.size();
    for (uint32_t i = 0; i < vlen; ++i)
        data_[i].value_ = BasicInt(*(rhs.begin() + i)) % modulus_.value_;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<std::string> rhs) noexcept {
    const size_t vlen = rhs.size();
    if (data_.size() < vlen)
        data_.resize(vlen);
    for (size_t i = 0; i < data_.size(); ++i) {
        if (i < vlen) {
            data_[i] = *(rhs.begin() + i);
            if (modulus_.value_ != 0)
                data_[i].value_ = data_[i].value_ % modulus_.value_;
        } else {
            data_[i].value_ = 0;
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    const size_t vlen = rhs.size();
    if (data_.size() < vlen)
        data_.resize(vlen);
    for (size_t i = 0; i < data_.size(); ++i) {
        if (i < vlen) {
            data_[i].value_ = BasicInt(*(rhs.begin() + i));
            if (modulus_.value_ != 0)
                data_[i].value_ = data_[i].value_ % modulus_.value_;
        } else {
            data_[i].value_ = 0;
        }
    }
    return *this;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus.
 * Algorithm: Integer i, Old Modulus om, New Modulus nm,
 * delta = abs(om-nm):
 *  Case 1: om < nm
 *    if i > om/2
 *      i' = i + delta
 *  Case 2: om > nm
 *    i > om/2 i' = i-delta
 */
template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(const NativeVectorT& v, const IntegerType& modulus) noexcept
    : data_(v.data_.size()) {
    // same three branches as switch_modulus below, reading from v instead of in place
    this->set_modulus(modulus);
    const auto ov{v.modulus_.value_};
    const auto nv{modulus.value_};
    const auto half_q{ov >> 1};
    const size_t size{data_.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i) {
            const auto x{v.data_[i].value_};
            data_[i].value_ = x + centered_correction_lane(x, half_q, diff);
        }
    } else if (nv > half_q) {
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i) {
            const auto x{v.data_[i].value_};
            data_[i].value_ = x - centered_correction_lane(x, half_q, diff);
        }
    } else {
        general_shrink_loop(data_.data(), v.data_.data(), size, ov, nv);
    }
}

template <class IntegerType>
void NativeVectorT<IntegerType>::switch_modulus(const IntegerType& modulus) {
    const auto ov{modulus_.value_};
    const auto nv{modulus.value_};
    const auto half_q{ov >> 1};
    const size_t size{data_.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i)
            data_[i].value_ += centered_correction_lane(data_[i].value_, half_q, diff);
    } else if (nv > half_q) {
        // new modulus within 2x of the old one: a single conditional subtract fully
        // reduces every value (v <= half_q < nv, and v > half_q maps into [0, nv))
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i)
            data_[i].value_ -= centered_correction_lane(data_[i].value_, half_q, diff);
    } else {
        general_shrink_loop(data_.data(), data_.data(), size, ov, nv);
    }
    this->set_modulus(modulus);
}

template <class IntegerType>
void NativeVectorT<IntegerType>::lazy_switch_modulus(const IntegerType& modulus) {
    for (auto& v : data_)
        v.mod_eq(modulus);
    this->set_modulus(modulus);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mult_acc_eq_no_check(const NativeVectorT& V,
                                                                             const IntegerType& I) {
    auto iv{I};
    auto mv{modulus_};
    if (iv.value_ >= mv.value_)
        iv.mod_eq(mv);
    auto iinv{iv.prep_mod_mul_const(mv)};
    const uint32_t ringdm = data_.size();
    for (uint32_t i = 0; i < ringdm; ++i)
        data_[i].mod_add_fast_eq(V.data_[i].mod_mul_fast_const(iv, mv, iinv), mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod(const IntegerType& modulus) const {
    auto ans(*this);
    ans.mod_eq(modulus);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_eq(const IntegerType& modulus) {
    if (modulus.value_ == 2)
        return this->NativeVectorT::mod_by_two_eq();
    const auto ov{modulus_.value_};
    const auto nv{modulus.value_};
    const auto half_q{ov >> 1};
    const size_t size{data_.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i)
            data_[i].value_ += centered_correction_lane(data_[i].value_, half_q, diff);
    } else if (nv > half_q) {
        // new modulus within 2x of the old one: every value is below ov by the class
        // invariant, so a single conditional subtract fully reduces it
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i)
            data_[i].value_ -= centered_correction_lane(data_[i].value_, half_q, diff);
    } else {
        general_shrink_loop(data_.data(), data_.data(), size, ov, nv);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_reduce_eq() {
    const auto mv{modulus_.value_};
    const size_t size{data_.size()};
    using DInt = typename IntegerType::DNativeInt;
    if constexpr (sizeof(DInt) > sizeof(BasicInt)) {
        const int64_t e{static_cast<int64_t>(cipher::get_msb(mv)) - 2};
        if (e >= 1) {
            const BasicInt mu{IntegerType::div_d(BasicInt(1) << e, 0, mv)};
            for (size_t i = 0; i < size; ++i) {
                const BasicInt v{data_[i].value_};
                if (v < mv)
                    continue;
                BasicInt av{v - static_cast<BasicInt>(IntegerType::mult_d_hi(v, mu) >> e) * mv};
                data_[i].value_ = (av >= mv) ? av - mv : av;
            }
            return *this;
        }
    }
    for (size_t i = 0; i < size; ++i) {
        if (data_[i].value_ >= mv)
            data_[i].value_ %= mv;
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_add(const IntegerType& b) const {
    auto mv{modulus_.value_};
    auto bv{b};
    if (bv.value_ >= mv)
        bv.mod_eq(modulus_);
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = mod_add_lane(data_[i].value_, bv.value_, mv);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_add_eq(const IntegerType& b) {
    auto mv{modulus_.value_};
    auto bv{b};
    if (bv.value_ >= mv)
        bv.mod_eq(modulus_);
    const size_t size{data_.size()};
    for (size_t i = 0; i < size; ++i)
        data_[i].value_ = mod_add_lane(data_[i].value_, bv.value_, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_add_at_index(size_t i, const IntegerType& b) const {
    auto ans(*this);
    ans.at(i).mod_add_eq(b, modulus_);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_add_at_index_eq(size_t i, const IntegerType& b) {
    this->NativeVectorT::at(i).mod_add_eq(b, modulus_);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_add(const NativeVectorT& b) const {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
#if defined(__clang__)
    // clang fuses the copy into the op loop; the single-pass form pays the result's
    // zero-init as a separate pass and loses 4-6% (gcc does not fuse and wins single-pass)
    auto ans(*this);
    ans.mod_add_eq(b);
    return ans;
#else
    const auto mv{modulus_.value_};
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = mod_add_lane(data_[i].value_, b.data_[i].value_, mv);
    return ans;
#endif
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_add_eq(const NativeVectorT& b) {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
    const auto mv{modulus_.value_};
    const size_t size{data_.size()};
    for (size_t i = 0; i < size; ++i)
        data_[i].value_ = mod_add_lane(data_[i].value_, b.data_[i].value_, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_sub(const IntegerType& b) const {
    auto mv{modulus_.value_};
    auto bv{b};
    if (bv.value_ >= mv)
        bv.mod_eq(modulus_);
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = mod_sub_lane(data_[i].value_, bv.value_, mv);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_sub_eq(const IntegerType& b) {
    auto mv{modulus_.value_};
    auto bv{b};
    if (bv.value_ >= mv)
        bv.mod_eq(modulus_);
    const size_t size{data_.size()};
    for (size_t i = 0; i < size; ++i)
        data_[i].value_ = mod_sub_lane(data_[i].value_, bv.value_, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_sub(const NativeVectorT& b) const {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
#if defined(__clang__)
    auto ans(*this);
    ans.mod_sub_eq(b);
    return ans;
#else
    const auto mv{modulus_.value_};
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = mod_sub_lane(data_[i].value_, b.data_[i].value_, mv);
    return ans;
#endif
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_sub_eq(const NativeVectorT& b) {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
    const auto mv{modulus_.value_};
    const size_t size{data_.size()};
    for (size_t i = 0; i < size; ++i)
        data_[i].value_ = mod_sub_lane(data_[i].value_, b.data_[i].value_, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_mul(const IntegerType& b) const {
    auto mv{modulus_};
    auto bv{b};
    if (bv.value_ >= mv.value_)
        bv.mod_eq(mv);
    auto bconst{bv.prep_mod_mul_const(mv)};
#if defined(__clang__)
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans.data_[i].mod_mul_fast_const_eq(bv, mv, bconst);
    return ans;
#else
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i] = data_[i].mod_mul_fast_const(bv, mv, bconst);
    return ans;
#endif
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_mul_eq(const IntegerType& b) {
    auto mv{modulus_};
    auto bv{b};
    if (bv.value_ >= mv.value_)
        bv.mod_eq(mv);
    auto bconst{bv.prep_mod_mul_const(mv)};
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_const_eq(bv, mv, bconst);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_mul(const NativeVectorT& b) const {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    barrett_mod_mul_loop(ans.data_.data(), data_.data(), b.data_.data(), size, modulus_);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_mul_eq(const NativeVectorT& b) {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
    barrett_mod_mul_loop(data_.data(), b.data_.data(), data_.size(), modulus_);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_by_two() const {
    auto half_q{modulus_.value_ >> 1};
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = 0x1 & (data_[i].value_ ^ (data_[i].value_ > half_q));
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_by_two_eq() {
    auto half_q{modulus_.value_ >> 1};
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].value_ = 0x1 & (data_[i].value_ ^ (data_[i].value_ > half_q));
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mod_exp(const IntegerType& b) const {
    auto mv{modulus_};
    auto bv{b};
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i] = ans[i].mod_exp(bv, mv);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_exp_eq(const IntegerType& b) {
    auto mv{modulus_};
    auto bv{b};
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i] = data_[i].mod_exp(bv, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::mult_with_out_mod(const NativeVectorT& b) const {
    if (data_.size() != b.data_.size() || modulus_ != b.modulus_)
        CIPHER_THROW("Called on NativeVectorT's with different parameters.");
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = data_[i].value_ * b.data_[i].value_;
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::multiply_and_round(const IntegerType& p,
                                                                          const IntegerType& q) const {
    auto half_q{modulus_.value_ >> 1};
    auto mv{modulus_};
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i) {
        if (ans[i].value_ > half_q) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.multiply_and_round(p, q);
        } else {
            ans[i] = ans[i].multiply_and_round(p, q).mod(mv);
        }
    }
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::multiply_and_round_eq(const IntegerType& p,
                                                                              const IntegerType& q) {
    auto half_q{modulus_.value_ >> 1};
    auto mv{modulus_};
    for (size_t i = 0; i < data_.size(); ++i) {
        if (data_[i].value_ > half_q) {
            auto&& tmp{mv - data_[i]};
            data_[i] = mv - tmp.multiply_and_round(p, q);
        } else {
            data_[i] = data_[i].multiply_and_round(p, q).mod(mv);
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::divide_and_round(const IntegerType& q) const {
    auto half_q{modulus_.value_ >> 1};
    auto mv{modulus_};
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i) {
        if (ans[i].value_ > half_q) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.divide_and_round(q);
        } else {
            ans[i] = ans[i].divide_and_round(q);
        }
    }
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::divide_and_round_eq(const IntegerType& q) {
    auto half_q{modulus_.value_ >> 1};
    auto mv{modulus_};
    for (size_t i = 0; i < data_.size(); ++i) {
        if (data_[i].value_ > half_q) {
            auto&& tmp{mv - data_[i]};
            data_[i] = mv - tmp.divide_and_round(q);
        } else {
            data_[i] = data_[i].divide_and_round(q);
        }
    }
    return *this;
}

template <class IntegerType>
std::vector<NativeVectorT<IntegerType>> NativeVectorT<IntegerType>::base_decompose(uint32_t digit_len) const {
    const BasicInt q = modulus_.value_;
    const uint32_t n_w = (modulus_.get_msb() + digit_len - 1) / digit_len;
    const auto mask = static_cast<BasicInt>((uint64_t{1} << digit_len) - 1);
    const uint32_t n = data_.size();
    std::vector<NativeVectorT> result;
    result.reserve(n_w);

    if (n_w * digit_len + 1 > IntegerType::max_bits() || q <= 1) {
        // not enough headroom for the bias: plain unsigned digit windows
        for (uint32_t w = 0; w < n_w; ++w) {
            NativeVectorT d(n, modulus_);
            const uint32_t shift = w * digit_len;
            for (uint32_t i = 0; i < n; ++i)
                d[i].value_ = (data_[i].value_ >> shift) & mask;
            result.push_back(std::move(d));
        }
        return result;
    }

    // bias by H (g_half in every digit position) once; every balanced digit is then an
    // independent window: digit_w = (((x~ + H) >> w*digit_len) & mask) - h, x~ centered.
    const BasicInt h = BasicInt{1} << (digit_len - 1);
    const BasicInt q_half = q >> 1;
    BasicInt H{0};
    for (uint32_t i = 0; i < n_w; ++i)
        H += h << (i * digit_len);
    std::vector<BasicInt> biased(n);
    for (uint32_t i = 0; i < n; ++i) {
        // borrow of (q_half - x) is 1 exactly when x > q_half, i.e. x is negative centered
        const BasicInt borrow = (q_half - data_[i].value_) >> (IntegerType::max_bits() - 1);
        biased[i] = data_[i].value_ + H - (q & (0 - borrow));
    }

    for (uint32_t w = 0; w < n_w; ++w) {
        NativeVectorT d(n, modulus_);
        const uint32_t shift = w * digit_len;
        if (w + 1 < n_w) {
            for (uint32_t i = 0; i < n; ++i) {
                const BasicInt v = (biased[i] >> shift) & mask;
                const BasicInt addq = q & ((v >> (digit_len - 1)) - 1);  // q exactly when v < h
                d[i].value_ = v - h + addq;
            }
        } else {  // the top window is unmasked so it absorbs the remaining quotient (v < 3h)
            for (uint32_t i = 0; i < n; ++i) {
                const BasicInt v = biased[i] >> shift;
                BasicInt s = v >> (digit_len - 1);  // in {0, 1, 2}
                s = (s | (s >> 1)) & 0x1;
                const BasicInt addq = q & (s - 1);
                d[i].value_ = v - h + addq;
            }
        }
        result.push_back(std::move(d));
    }
    return result;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::get_digit_at_index_for_base(uint32_t index,
                                                                                   uint32_t base) const {
    auto digit_len = cipher::get_msb(base - 1);  // == ceil(log2(base))
    uint32_t shift{(index - 1) * digit_len};
    if (shift >= IntegerType::max_bits())
        return NativeVectorT(data_.size(), modulus_);
    const auto mask = static_cast<BasicInt>((uint64_t{1} << digit_len) - 1);
    const size_t size{data_.size()};
    NativeVectorT ans(size, modulus_);
    for (size_t i = 0; i < size; ++i)
        ans.data_[i].value_ = (data_[i].value_ >> shift) & mask;
    return ans;
}

template <class IntegerType>
void NativeVectorT<IntegerType>::barrett_mod_mul_loop(IntegerType* a, const IntegerType* b, size_t size,
                                                      const IntegerType& modulus) {
    using NInt = decltype(modulus.value_);
    using DInt = typename IntegerType::DNativeInt;
    if constexpr (sizeof(DInt) > sizeof(NInt)) {
        const NInt mv{modulus.value_};
        const int64_t n{static_cast<int64_t>(modulus.get_msb()) - 2};
        const NInt mu{modulus.compute_mu().value_};
        for (size_t i = 0; i < size; ++i) {
#if defined(__clang__) && defined(__x86_64__) && defined(__AVX2__)
            DInt prod{static_cast<DInt>(a[i].value_) * b[i].value_};
            NInt qhat{static_cast<NInt>((static_cast<DInt>(static_cast<NInt>(prod >> n)) * mu) >> (n + 7))};
            NInt r{static_cast<NInt>(prod) - qhat * mv};
#else
            typename IntegerType::TypeD prod;
            IntegerType::mult_d(a[i].value_, b[i].value_, prod);
            NInt r{prod.lo};
            IntegerType::mult_d(IntegerType::r_shift_d(prod, n), mu, prod);
            r -= IntegerType::r_shift_d(prod, n + 7) * mv;
#endif
            if (r >= mv)
                r -= mv;
            a[i].value_ = r;
        }
    } else {
        const auto mu{modulus.compute_mu()};
        for (size_t i = 0; i < size; ++i)
            a[i].mod_mul_fast_eq(b[i], modulus, mu);
    }
}

template <class IntegerType>
void NativeVectorT<IntegerType>::barrett_mod_mul_loop(IntegerType* dst, const IntegerType* a, const IntegerType* b,
                                                      size_t size, const IntegerType& modulus) {
    using NInt = decltype(modulus.value_);
    using DInt = typename IntegerType::DNativeInt;
    if constexpr (sizeof(DInt) > sizeof(NInt)) {
        const NInt mv{modulus.value_};
        const int64_t n{static_cast<int64_t>(modulus.get_msb()) - 2};
        const NInt mu{modulus.compute_mu().value_};
        for (size_t i = 0; i < size; ++i) {
#if defined(__clang__) && defined(__x86_64__) && defined(__AVX2__)
            DInt prod{static_cast<DInt>(a[i].value_) * b[i].value_};
            NInt qhat{static_cast<NInt>((static_cast<DInt>(static_cast<NInt>(prod >> n)) * mu) >> (n + 7))};
            NInt r{static_cast<NInt>(prod) - qhat * mv};
#else
            typename IntegerType::TypeD prod;
            IntegerType::mult_d(a[i].value_, b[i].value_, prod);
            NInt r{prod.lo};
            IntegerType::mult_d(IntegerType::r_shift_d(prod, n), mu, prod);
            r -= IntegerType::r_shift_d(prod, n + 7) * mv;
#endif
            if (r >= mv)
                r -= mv;
            dst[i].value_ = r;
        }
    } else {
        const auto mu{modulus.compute_mu()};
        for (size_t i = 0; i < size; ++i)
            dst[i] = a[i].mod_mul_fast(b[i], modulus, mu);
    }
}

template <class IntegerType>
void NativeVectorT<IntegerType>::barrett_mult_acc_loop(IntegerType* acc, const IntegerType* a, const IntegerType* b,
                                                       size_t size, const IntegerType& modulus) {
    using NInt = decltype(modulus.value_);
    using DInt = typename IntegerType::DNativeInt;
    if constexpr (sizeof(DInt) > sizeof(NInt)) {
        const NInt mv{modulus.value_};
        const int64_t n{static_cast<int64_t>(modulus.get_msb()) - 2};
        const NInt mu{modulus.compute_mu().value_};
        for (size_t i = 0; i < size; ++i) {
#if defined(__clang__) && defined(__x86_64__) && defined(__AVX2__)
            DInt prod{static_cast<DInt>(a[i].value_) * b[i].value_};
            NInt qhat{static_cast<NInt>((static_cast<DInt>(static_cast<NInt>(prod >> n)) * mu) >> (n + 7))};
            NInt r{static_cast<NInt>(prod) - qhat * mv};
#else
            typename IntegerType::TypeD prod;
            IntegerType::mult_d(a[i].value_, b[i].value_, prod);
            NInt r{prod.lo};
            IntegerType::mult_d(IntegerType::r_shift_d(prod, n), mu, prod);
            r -= IntegerType::r_shift_d(prod, n + 7) * mv;
#endif
            if (r >= mv)
                r -= mv;
            NInt t{acc[i].value_ + r};
            if (t >= mv)
                t -= mv;
            acc[i].value_ = t;
        }
    } else {
        const auto mu{modulus.compute_mu()};
        for (size_t i = 0; i < size; ++i)
            acc[i].mod_add_fast_eq(a[i].mod_mul_fast(b[i], modulus, mu), modulus);
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mod_mul_no_check_eq(const NativeVectorT& b) {
    barrett_mod_mul_loop(data_.data(), b.data_.data(), data_.size(), modulus_);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::mult_acc_eq_no_check(const NativeVectorT& a,
                                                                             const NativeVectorT& b) {
    barrett_mult_acc_loop(data_.data(), a.data_.data(), b.data_.data(), data_.size(), modulus_);
    return *this;
}

template class NativeVectorT<NativeInteger>;
#if CIPHER_NATIVE_INT != 32
template class NativeVectorT<NativeInteger32>;
#endif

}  // namespace native_int
