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
  This file contains the cpp implementation of  mubintvec, a <vector> of ubint, with associated math operators
 */

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include "cipher/math/backend/dynamic/mod_vector.h"
    #include "cipher/math/backend.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"

//    #include "time.h"
//    #include <chrono>

namespace dynamic_int {

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(uint32_t length, const ubint_el_t& modulus,
                                 std::initializer_list<std::string> rhs) noexcept
    : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(length) {
    const size_t len = (rhs.size() < data_.size()) ? rhs.size() : data_.size();
    for (size_t i = 0; i < len; ++i)
        data_[i] = ubint_el_t(*(rhs.begin() + i)) % modulus_;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(uint32_t length, const ubint_el_t& modulus,
                                 std::initializer_list<uint64_t> rhs) noexcept
    : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(length) {
    const size_t len = (rhs.size() < data_.size()) ? rhs.size() : data_.size();
    for (size_t i = 0; i < len; ++i)
        data_[i] = ubint_el_t(*(rhs.begin() + i)) % modulus_;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string>& s, const ubint_el_t& modulus) noexcept
    : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(s.size()) {
    for (size_t i = 0; i < s.size(); ++i)
        data_[i] = ubint_el_t(s[i]) % modulus_;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string>& s, const std::string& modulus) noexcept
    : modulus_{modulus}, modulus_state_{State::INITIALIZED}, data_(s.size()) {
    for (size_t i = 0; i < s.size(); ++i)
        data_[i] = ubint_el_t(s[i]) % modulus_;
}

// if two vectors are different sized, then it will resize target vector
// will overwrite target modulus
template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(const mubintvec& rhs) noexcept {
    modulus_ = rhs.modulus_;
    modulus_state_ = rhs.modulus_state_;
    if (rhs.data_.size() > data_.size()) {
        data_ = rhs.data_;
        return *this;
    }
    std::copy(rhs.data_.begin(), rhs.data_.end(), data_.begin());
    if (data_.size() > rhs.data_.size())
        data_.resize(rhs.data_.size());
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<std::string> rhs) noexcept {
    const size_t len = rhs.size();
    if (data_.size() < len)
        data_.resize(len);
    const auto reduce = (modulus_state_ == State::INITIALIZED && modulus_);
    for (size_t i = 0; i < data_.size(); ++i) {
        if (i < len) {
            data_[i] = ubint_el_t(*(rhs.begin() + i));
            if (reduce)
                data_[i].mod_eq(modulus_);
        } else {
            data_[i] = 0;
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    const size_t len = rhs.size();
    if (data_.size() < len)
        data_.resize(len);
    const auto reduce = (modulus_state_ == State::INITIALIZED && modulus_);
    for (size_t i = 0; i < data_.size(); ++i) {
        if (i < len) {
            data_[i] = ubint_el_t(*(rhs.begin() + i));
            if (reduce)
                data_[i].mod_eq(modulus_);
        } else {
            data_[i] = 0;
        }
    }
    return *this;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus Algorithm: Integer i, Old Modulus om, New Modulus nm, delta =
 * abs(om-nm): Case 1: om < nm if i > i > om/2 i' = i + delta Case 2: om > nm i
 * > om/2 i' = i-delta
 */
template <class ubint_el_t>
void mubintvec<ubint_el_t>::switch_modulus(const ubint_el_t& modulus) {
    auto size{data_.size()};
    auto half_q{modulus_ >> 1};
    if (modulus > modulus_) {
        auto diff{modulus - modulus_};
        for (size_t i = 0; i < size; ++i) {
            if (data_[i] > half_q)
                data_[i] += diff;
        }
    } else {
        auto diff{modulus - (modulus_ % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (data_[i] > half_q)
                data_[i] += diff;
            if (data_[i] >= modulus)
                data_[i] %= modulus;
        }
    }
    this->set_modulus(modulus);
}

template <class ubint_el_t>
void mubintvec<ubint_el_t>::lazy_switch_modulus(const ubint_el_t& modulus) {
    for (auto& v : data_)
        v.mod_eq(modulus);
    this->set_modulus(modulus);
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod(const ubint_el_t& modulus) const {
    auto ans(*this);
    if (modulus == 2)
        return ans.mod_by_two_eq();
    auto size{data_.size()};
    auto half_q{modulus_ >> 1};
    if (modulus > modulus_) {
        auto diff{modulus - modulus_};
        for (size_t i = 0; i < size; ++i) {
            if (ans.data_[i] > half_q)
                ans.data_[i] += diff;
        }
    } else {
        auto diff{modulus - (modulus_ % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (ans.data_[i] > half_q)
                ans.data_[i] += diff;
            if (ans.data_[i] >= modulus)
                ans.data_[i] %= modulus;
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_eq(const ubint_el_t& modulus) {
    if (modulus == 2)
        return this->mod_by_two_eq();
    auto size{data_.size()};
    auto half_q{modulus_ >> 1};
    if (modulus > modulus_) {
        auto diff{modulus - modulus_};
        for (size_t i = 0; i < size; ++i) {
            if (data_[i] > half_q)
                data_[i] += diff;
        }
    } else {
        auto diff{modulus - (modulus_ % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (data_[i] > half_q)
                data_[i] += diff;
            if (data_[i] >= modulus)
                data_[i] %= modulus;
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_add(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus(modulus_);
    auto b_local(b);
    if (b_local >= modulus)
        b_local.mod_eq(modulus);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_add_fast_eq(b_local, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_add_eq(const ubint_el_t& b) {
    auto modulus{modulus_};
    auto b_local{b};
    if (b_local >= modulus)
        b_local.mod_eq(modulus);
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_add_fast_eq(b_local, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_add_at_index(size_t i, const ubint_el_t& b) const {
    auto ans(*this);
    ans.at(i).mod_add_eq(b, modulus_);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_add_at_index_eq(size_t i, const ubint_el_t& b) {
    this->mubintvec::at(i).mod_add_eq(b, modulus_);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_add(const mubintvec& b) const {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec adding vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec adding vectors of different lengths");
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_add_eq(b.data_[i], ans.modulus_);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_add_eq(const mubintvec& b) {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec adding vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec adding vectors of different lengths");
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_add_eq(b.data_[i], modulus_);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_add_no_check_eq(const mubintvec& b) {
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_add_eq(b.data_[i], modulus_);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_sub(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus{modulus_};
    auto b_local{b};
    if (b_local >= modulus)
        b_local.mod_eq(modulus);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_sub_fast_eq(b_local, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_sub_eq(const ubint_el_t& b) {
    auto modulus{modulus_};
    auto b_local{b};
    if (b_local >= modulus)
        b_local.mod_eq(modulus);
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_sub_fast_eq(b_local, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_sub(const mubintvec& b) const {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec subtractiong vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec subtractiong vectors of different lengths");
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_sub_eq(b.data_[i], ans.modulus_);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_sub_eq(const mubintvec& b) {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec subtractiong vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec subtractiong vectors of different lengths");
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_sub_eq(b.data_[i], modulus_);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_mul(const ubint_el_t& b) const {
    auto ans(*this);
    auto b_local{b};
    if (b_local >= ans.modulus_)
        b_local.mod_eq(ans.modulus_);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_mul_fast_eq(b_local, ans.modulus_);
    #else
    auto mu(ans.modulus_.compute_mu());
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_mul_fast_eq(b_local, ans.modulus_, mu);
    #endif
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_mul_eq(const ubint_el_t& b) {
    auto b_local(b);
    if (b_local >= modulus_)
        b_local.mod_eq(modulus_);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b_local, modulus_);
    #else
    auto mu(modulus_.compute_mu());
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b_local, modulus_, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_mul(const mubintvec& b) const {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec multiplying vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec multiplying vectors of different lengths");
    auto ans(*this);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < data_.size(); ++i)
        ans[i].mod_mul_fast_eq(b[i], ans.modulus_);
    #else
    auto mu(ans.modulus_.compute_mu());
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_mul_fast_eq(b[i], ans.modulus_, mu);
    #endif
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_mul_eq(const mubintvec& b) {
    if (modulus_ != b.modulus_)
        CIPHER_THROW("mubintvec multiplying vectors of different moduli");
    if (data_.size() != b.data_.size())
        CIPHER_THROW("mubintvec multiplying vectors of different lengths");
    #ifdef NO_BARRETT
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b[i], modulus_);
    #else
    auto mu(modulus_.compute_mu());
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b[i], modulus_, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_mul_no_check_eq(const mubintvec& b) {
    #ifdef NO_BARRETT
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b[i], modulus_);
    #else
    auto mu(modulus_.compute_mu());
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_mul_fast_eq(b[i], modulus_, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_exp(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus{modulus_};
    auto b_local{b};
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_exp_eq(b_local, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_exp_eq(const ubint_el_t& b) {
    auto modulus{modulus_};
    auto b_local{b};
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_exp_eq(b_local, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_inverse() const {
    auto ans(*this);
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i].mod_inverse_eq(ans.modulus_);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_inverse_eq() {
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i].mod_inverse_eq(modulus_);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::mod_by_two() const {
    auto ans(*this);
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < ans.data_.size(); ++i)
        ans[i] = ubint_el_t((ans[i].value_[0] & 0x1) ^ (ans[i] > half_q));
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::mod_by_two_eq() {
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < data_.size(); ++i)
        data_[i] = ubint_el_t((data_[i].value_[0] & 0x1) ^ (data_[i] > half_q));
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::multiply_and_round(const ubint_el_t& p, const ubint_el_t& q) const {
    auto ans(*this);
    auto mv(modulus_);
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < ans.data_.size(); ++i) {
        if (ans.data_[i] > half_q) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.multiply_and_round(p, q);
        } else {
            ans[i] = ans[i].multiply_and_round(p, q).mod(mv);
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::multiply_and_round_eq(const ubint_el_t& p, const ubint_el_t& q) {
    auto mv{modulus_};
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < data_.size(); ++i) {
        if (data_[i] > half_q) {
            auto&& tmp{mv - data_[i]};
            data_[i] = mv - tmp.multiply_and_round(p, q);
        } else {
            data_[i] = data_[i].multiply_and_round(p, q).mod(mv);
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::divide_and_round(const ubint_el_t& q) const {
    auto ans(*this);
    auto mv{modulus_};
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < ans.data_.size(); ++i) {
        if (ans[i] > half_q) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.divide_and_round(q);
        } else {
            ans[i] = ans[i].divide_and_round_eq(q);
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::divide_and_round_eq(const ubint_el_t& q) {
    auto mv{modulus_};
    auto half_q{modulus_ >> 1};
    for (size_t i = 0; i < data_.size(); ++i) {
        if (data_[i] > half_q) {
            auto&& tmp{mv - data_[i]};
            data_[i] = mv - tmp.divide_and_round(q);
        } else {
            data_[i] = data_[i].divide_and_round(q);
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::get_digit_at_index_for_base(uint32_t index, uint32_t base) const {
    auto ans(*this);
    for (size_t i = 0; i < data_.size(); ++i)
        ans[i] = static_cast<ubint_el_t>(ans[i].get_digit_at_index_for_base(index, base));
    return ans;
}

template class mubintvec<BigInteger>;

}  // namespace dynamic_int

#endif
