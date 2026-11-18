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
  This file contains the main class for unsigned big integers: ubint. Big integers are represented as arrays of
  machine native unsigned integers. The native integer type is supplied as a template parameter.
  Currently implementation based on uint32_t and uint64_t is supported. a native double the base integer size is also needed.
 */

#include <cmath>
#include <cstdint>
#include <utility>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include <iostream>
    #include <string>
    #include <vector>

    #include "cipher/math/backend.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/inttypes.h"
    #include "cipher/util/serializable.h"

namespace dynamic_int {

// Sum and Carry algorithm with radix 2^m_bitLength.
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::add(const ubint& b) const {
    const ubint* A = this;
    auto size_a = value_.size();
    const ubint* B = &b;
    auto size_b = b.value_.size();
    if (size_a < size_b) {
        std::swap(A, B);
        std::swap(size_a, size_b);
    }

    if (B->msb_ == 0)
        return *A;

    std::vector<limb_t> r(size_a + 1);
    Dlimb_t c{0};
    for (size_t i = 0; i < size_a; ++i, c >>= limb_bit_length_) {
        auto av = static_cast<Dlimb_t>(A->value_[i]);
        auto bv = static_cast<Dlimb_t>(i < size_b ? B->value_[i] : 0);
        r[i] = static_cast<limb_t>(c += av + bv);
    }
    r[size_a] = static_cast<limb_t>(c);
    return ubint(std::move(r));
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::add_eq(const ubint& b) {
    const ubint* A = this;
    auto size_a = value_.size();
    const ubint* B = &b;
    auto size_b = B->value_.size();
    if (size_a < size_b) {
        std::swap(A, B);
        std::swap(size_a, size_b);
    }

    if (B->msb_ == 0)
        return *this = *A;

    std::vector<limb_t> r(size_a + 1);
    Dlimb_t c{0};
    for (size_t i = 0; i < size_a; ++i, c >>= limb_bit_length_) {
        auto av = static_cast<Dlimb_t>(A->value_[i]);
        auto bv = static_cast<Dlimb_t>(i < size_b ? B->value_[i] : 0);
        r[i] = static_cast<limb_t>(c += av + bv);
    }
    r[size_a] = static_cast<limb_t>(c);
    value_ = std::move(r);
    ubint<limb_t>::normalize_limbs();
    return *this;
}

// TODO: convert to vector constructor method
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::sub(const ubint& b) const {
    // return 0 if b is higher than *this as there is no support for negative numbers
    if (*this <= b)
        return ubint();
    ubint result(*this);
    for (size_t i = 0; i < b.value_.size(); ++i) {
        if (result.value_[i] < b.value_[i]) {  // carryover condition need to
                                                 // borrow from higher limbs.
            size_t cntr{i};
            result.value_[cntr] += (max_limb_ - b.value_[cntr]) + 1;
            // set all the zero limbs to all FFs (propagate the 1)
            while (0 == result.value_[++cntr])
                result.value_[cntr] = max_limb_;
            // and eventually borrow 1 from the first nonzero limb we find
            result.value_[cntr]--;
        } else {  // usual subtraction condition
            result.value_[i] -= b.value_[i];
        }
    }
    result.normalize_limbs();
    return result;
}

// TODO: convert to vector constructor method
template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::sub_eq(const ubint& b) {
    if (*this <= b) {
        msb_ = 0;
        value_[0] = 0;
        value_.resize(1);
        return *this;
    }
    for (size_t i = 0; i < b.value_.size(); ++i) {
        if (value_[i] < b.value_[i]) {
            size_t cntr{i};
            value_[cntr] += (max_limb_ - b.value_[cntr]) + 1;
            while (0 == value_[++cntr])
                value_[cntr] = max_limb_;
            value_[cntr]--;
        } else {
            value_[i] -= b.value_[i];
        }
    }
    ubint<limb_t>::normalize_limbs();
    return *this;
}

// Multiply operation: usual school book shift and add after multiplication
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mul(const ubint& b) const {
    if (msb_ == 0 || b.msb_ == 0)
        return ubint();
    if (b.msb_ == 1)
        return *this;
    if (msb_ == 1)
        return b;

    const ubint* A = this;
    auto a_size = value_.size();
    const ubint* B = &b;
    auto b_size_value = b.value_.size();
    if (a_size < b_size_value) {
        std::swap(A, B);
        std::swap(a_size, b_size_value);
    }

    ubint ans;
    for (size_t i = 0; i < b_size_value; ++i) {
        std::vector<limb_t> c(i + a_size + 1);
        Dlimb_t limbb = static_cast<Dlimb_t>(B->value_[i]);
        Dlimb_t ofl{0};
        for (size_t j = 0; j < a_size; ++j, ofl >>= limb_bit_length_)
            c[i + j] = static_cast<limb_t>(ofl += limbb * A->value_[j]);
        c[i + a_size] = static_cast<limb_t>(ofl);

        ans = std::move(ans.add(ubint(std::move(c))));
    }
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::divided_by(const ubint& b) const {
    if (b.msb_ == 0)
        CIPHER_THROW("Divisor is zero");
    if (b.msb_ > msb_)
        return ubint();
    if ((b.msb_ == msb_) && (b.value_.back() == value_.back()))
        return ubint(1);
    ubint ans;
    divq_vect(ans, *this, b);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::divided_by_eq(const ubint& b) {
    if (b.msb_ == 0)
        CIPHER_THROW("Divisor is zero");
    if (b.msb_ > msb_) {
        msb_ = 0;
        value_.resize(1);
        value_[0] = 0;
        return *this;
    }
    if ((b.msb_ == msb_) && (b.value_.back() == value_.back())) {
        msb_ = 1;
        value_.resize(1);
        value_[0] = 1;
        return *this;
    }
    ubint ans;
    divq_vect(ans, *this, b);
    return *this = std::move(ans);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Exp(uint32_t p) const {
    if (p == 0)
        return ubint(1);
    if (p == 1)
        return *this;
    ubint tmp{ubint<limb_t>::Exp(p >> 1)};
    tmp = tmp.mul(tmp);
    if (p & 0x1)
        return tmp.mul(*this);
    return tmp;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::multiply_and_round(const ubint& p, const ubint& q) const {
    if (q.msb_ == 0)
        CIPHER_THROW("MultiplyAndRound() Divisor is zero");
    auto t{ubint<limb_t>::mul(p)};
    ubint half_q(q >> 1);
    if (t <= half_q)
        return ubint();
    if ((t.msb_ == half_q.msb_) || ((t.msb_ == q.msb_) && (t.value_.back() < q.value_.back())))
        return ubint(1);
    ubint ans, rv;
    divqr_vect(ans, rv, t, q);
    if (rv > half_q)
        return ans.add(ubint(1));
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::divide_and_round(const ubint& q) const {
    if (q.msb_ == 0)
        CIPHER_THROW("DivideAndRound() Divisor is zero");
    ubint half_q(q >> 1);
    if (*this <= half_q)
        return ubint();
    if ((msb_ == half_q.msb_) || ((msb_ == q.msb_) && (value_.back() < q.value_.back())))
        return ubint(1);
    ubint ans, rv;
    divqr_vect(ans, rv, *this, q);
    if (rv > half_q)
        return ans.add(ubint(1));
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod(const ubint& modulus) const {
    if (modulus.msb_ == 0)
        CIPHER_THROW("Mod() using zero modulus");
    if (*this < modulus)
        return *this;
    if (modulus.msb_ == 2 && modulus.value_[0] == 2)
        return ubint(value_[0] & 0x1);
    ubint ans;
    divr_vect(ans, *this, modulus);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::mod_eq(const ubint& modulus) {
    if (modulus.msb_ == 0)
        CIPHER_THROW("Mod() using zero modulus");
    if (*this < modulus)
        return *this;
    if (modulus.msb_ == 2 && modulus.value_[0] == 2) {
        value_.resize(1);
        value_[0] &= 0x1;
        msb_ = value_[0];
        return *this;
    }
    ubint ans;
    divr_vect(ans, *this, modulus);
    return *this = std::move(ans);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_add(const ubint& b, const ubint& modulus) const {
    ubint bv(b);
    if (bv >= modulus)
        bv.mod_eq(modulus);
    ubint av(*this);
    if (av >= modulus)
        av.mod_eq(modulus);
    av = av.add(bv);
    if (av >= modulus)
        return av.sub(modulus);
    return av;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::mod_add_eq(const ubint& b, const ubint& modulus) {
    ubint bv(b);
    if (bv >= modulus)
        bv.mod_eq(modulus);
    if (*this >= modulus)
        ubint<limb_t>::mod_eq(modulus);
    *this = bv.add(*this);
    if (*this >= modulus)
        return ubint<limb_t>::sub_eq(modulus);
    return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_add_fast(const ubint& b, const ubint& modulus) const {
    ubint ans(b.add(*this));
    if (ans >= modulus)
        return ans.sub(modulus);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::mod_add_fast_eq(const ubint& b, const ubint& modulus) {
    *this = b.add(*this);
    if (*this >= modulus)
        return ubint<limb_t>::sub_eq(modulus);
    return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_sub(const ubint& b, const ubint& modulus) const {
    auto av(*this);
    auto bv(b);
    if (bv >= modulus)
        bv.mod_eq(modulus);
    if (av >= modulus)
        av.mod_eq(modulus);
    if (av < bv)
        av = modulus.add(av);
    return av.sub(bv);
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::mod_sub_eq(const ubint& b, const ubint& modulus) {
    auto bv(b);
    if (bv >= modulus)
        bv.mod_eq(modulus);
    if (*this >= modulus)
        ubint<limb_t>::mod_eq(modulus);
    if (*this < bv)
        *this = modulus.add(*this);
    return ubint<limb_t>::sub_eq(bv);
}

template <typename limb_t>
inline ubint<limb_t> ubint<limb_t>::mod_sub_fast(const ubint& b, const ubint& modulus) const {
    if (*this < b)
        return modulus.add(*this).sub(b);
    return ubint<limb_t>::sub(b);
}

template <typename limb_t>
inline ubint<limb_t>& ubint<limb_t>::mod_sub_fast_eq(const ubint& b, const ubint& modulus) {
    if (*this < b)
        return *this = std::move(modulus.add(*this).sub(b));
    return ubint<limb_t>::sub_eq(b);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_mul_fast(const ubint& b, const ubint& modulus) const {
    if (msb_ == 0 || b.msb_ == 0)
        return ubint();
    if (b.msb_ == 1)
        return *this;
    if (msb_ == 1)
        return b;

    const ubint* A = this;
    auto a_size = value_.size();
    const ubint* B = &b;
    auto b_size_value = b.value_.size();
    if (a_size < b_size_value) {
        std::swap(A, B);
        std::swap(a_size, b_size_value);
    }

    ubint ans;
    for (size_t i = 0; i < b_size_value; ++i) {
        std::vector<limb_t> c(i + a_size + 1);
        Dlimb_t limbb = static_cast<Dlimb_t>(B->value_[i]);
        Dlimb_t ofl{0};
        for (size_t j = 0; j < a_size; ++j, ofl >>= limb_bit_length_)
            c[i + j] = static_cast<limb_t>(ofl += limbb * A->value_[j]);
        c[i + a_size] = static_cast<limb_t>(ofl);

        ans = std::move(ans.add(ubint(std::move(c))));
    }
    if (ans >= modulus)
        return ans.mod(modulus);
    return ans;
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_inverse(const ubint& modulus) const {
    if (msb_ == 0)
        CIPHER_THROW("Zero has no inverse");

    ubint second(*this);
    if (second >= modulus)
        second = second.mod(modulus);
    if (second.msb_ == 1)
        return second;

    // NORTH ALGORITHM
    ubint first(modulus);
    std::vector<ubint> quotient;
    quotient.reserve(8);  // TODO

    ubint q, mod_back;
    divqr_vect(q, mod_back, first, second);
    quotient.emplace_back(std::move(q));

    if (mod_back.msb_ == 0) {
        std::string msg = ubint<limb_t>::to_string() + " does not have a ModInverse using " + modulus.to_string();
        CIPHER_THROW(msg);
    }

    // max number of iterations should be < 2^k where k == min(bitsize(inputs))
    // TODO: consider breaking out of the loop if this limit exceeded.
    //       loop counter would need to be a ubint.
    while (mod_back.msb_ != 1) {
        first = second;
        second = mod_back;

        ubint q;
        divqr_vect(q, mod_back, first, second);
        quotient.emplace_back(std::move(q));
    }

    // SOUTH ALGORITHM
    first = ubint();
    second = ubint(1);
    for (auto it = quotient.rbegin(); it != quotient.rend(); ++it) {
        mod_back = *it * second + first;
        first = second;
        second = mod_back;
    }
    if (quotient.size() & 0x1)
        return modulus - mod_back;
    return mod_back;
}

// Modular Exponentiation using Square and Multiply Algorithm
// reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::mod_exp(const ubint& b, const ubint& modulus) const {
    ubint t(this->mod(modulus));
    ubint p(b);
    ubint r(1);
    if (p.value_[0] & 0x1)
        r = r.mod_mul_fast(t, modulus);
    while ((p >>= 1).msb_) {
        t = t.mod_mul_fast(t, modulus);
        if (p.value_[0] & 0x1)
            r = r.mod_mul_fast(t, modulus);
    }
    return r;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::l_shift(uint16_t shift) const {
    static constexpr uint16_t mask{limb_bit_length_ - 1};
    if (msb_ == 0)
        return ubint();
    auto ans(*this);
    ans.msb_ += shift;
    size_t shift_by_limb{static_cast<size_t>(shift) >> log2_limb_bit_length_};
    shift &= mask;
    if (shift) {
        Dlimb_t ofl{0};
        for (auto& v : ans.value_) {
            ofl |= static_cast<Dlimb_t>(v) << shift;
            v = static_cast<limb_t>(ofl);
            ofl >>= limb_bit_length_;
        }
        if (ofl)
            ans.value_.push_back(static_cast<limb_t>(ofl));
    }
    if (shift_by_limb) {
        size_t j = ans.value_.size();
        size_t i = j + shift_by_limb;
        ans.value_.resize(i);
        while (i > 0)
            ans.value_[--i] = (j > 0) ? ans.value_[--j] : 0;
    }
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::l_shift_eq(uint16_t shift) {
    static constexpr uint16_t mask{limb_bit_length_ - 1};
    if (msb_ == 0)
        return *this;
    msb_ += shift;
    size_t shift_by_limb{static_cast<size_t>(shift) >> log2_limb_bit_length_};
    shift &= mask;
    if (shift) {
        Dlimb_t ofl{0};
        for (auto& v : value_) {
            ofl |= static_cast<Dlimb_t>(v) << shift;
            v = static_cast<limb_t>(ofl);
            ofl >>= limb_bit_length_;
        }
        if (ofl)
            value_.push_back(static_cast<limb_t>(ofl));
    }
    if (shift_by_limb) {
        size_t j = value_.size();
        size_t i = j + shift_by_limb;
        value_.resize(i);
        while (i > 0)
            value_[--i] = (j > 0) ? value_[--j] : 0;
    }
    return *this;
}

/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::r_shift(uint16_t shift) const {
    static constexpr uint16_t mask{limb_bit_length_ - 1};
    if (msb_ <= shift)
        return ubint(0);
    ubint ans(*this);
    ans.msb_ -= shift;
    size_t shift_by_limb{static_cast<size_t>(shift) >> log2_limb_bit_length_};
    shift &= mask;
    Dlimb_t tmp{ans.value_[shift_by_limb++] >> shift};
    uint32_t lshift{limb_bit_length_ - shift};
    size_t size{ans.value_.size() - shift_by_limb};
    for (size_t i = 0; i < size; ++i, tmp >>= limb_bit_length_) {
        tmp |= static_cast<Dlimb_t>(ans.value_[i + shift_by_limb]) << lshift;
        ans.value_[i] = static_cast<limb_t>(tmp);
    }
    ans.value_.resize(size);
    if (tmp)
        ans.value_.push_back(static_cast<limb_t>(tmp));
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::r_shift_eq(uint16_t shift) {
    static constexpr uint16_t mask{limb_bit_length_ - 1};
    if (msb_ <= shift) {
        msb_ = 0;
        value_.resize(1);
        value_[0] = 0;
        return *this;
    }
    msb_ -= shift;
    size_t shift_by_limb{static_cast<size_t>(shift) >> log2_limb_bit_length_};
    shift &= mask;
    Dlimb_t tmp{value_[shift_by_limb++] >> shift};
    uint32_t lshift{limb_bit_length_ - shift};
    size_t size{value_.size() - shift_by_limb};
    for (size_t i = 0; i < size; ++i, tmp >>= limb_bit_length_) {
        tmp |= static_cast<Dlimb_t>(value_[i + shift_by_limb]) << lshift;
        value_[i] = static_cast<limb_t>(tmp);
    }
    value_.resize(size);
    if (tmp)
        value_.push_back(static_cast<limb_t>(tmp));
    return *this;
}

// Converts the ubint to float using the std library functions.
template <typename limb_t>
float ubint<limb_t>::convert_to_float() const {
    float ans{-1.0f};
    try {
        ans = std::stof(ubint<limb_t>::to_string());
    } catch (const std::exception& e) {
        CIPHER_THROW("ConvertToFloat() parse error converting to float");
    }
    return ans;
}

template <typename limb_t>
double ubint<limb_t>::convert_to_double() const {
    double ans{-1.0};
    try {
        // ans = std::stod(this->to_string());
        uint32_t ceil_int = msb_to_limbs(msb_);
        double factor = std::pow(2, limb_bit_length_);
        double power = 1.0;

        ans = 0.0;
        for (uint32_t i = 0; i < ceil_int; ++i, power *= factor)
            ans += power * value_[i];
    } catch (const std::exception& e) {
        CIPHER_THROW("ConvertToDouble() parse error converting to double");
    }
    return ans;
}

// TODO
// Splits binary string to equi sized chunks then populates internal array values
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::from_binary_string(const std::string& vin) {
    std::string v = vin;
    // v.erase(0, v.find_first_not_of(' '));
    v.erase(0, v.find_first_not_of('0'));
    if (v.size() == 0)
        return ubint();
    ubint value;
    value.value_.clear();
    uint32_t len = v.length();
    uint32_t cntr = msb_to_limbs(len);
    std::string val;
    Dlimb_t partial_value = 0;
    for (uint32_t i = 0; i < cntr; i++) {
        if (len > ((i + 1) * limb_bit_length_)) {
            val = v.substr((len - (i + 1) * limb_bit_length_), limb_bit_length_);
        } else {
            val = v.substr(0, len % limb_bit_length_);
        }
        for (uint32_t j = 0; j < val.length(); j++) {
            partial_value += std::stoi(val.substr(j, 1));
            partial_value <<= 1;
        }
        partial_value >>= 1;
        value.value_.push_back((limb_t)partial_value);
        partial_value = 0;
    }
    value.set_msb();
    return value;
}

// TODO: * i to << i
template <typename limb_t>
uint32_t ubint<limb_t>::get_digit_at_index_for_base(uint32_t index, uint32_t base) const {
    uint32_t digit_len_value = cipher::get_msb(base - 1);
    uint32_t digit = 0;
    uint32_t new_index = 1 + (index - 1) * digit_len_value;
    for (uint32_t i = 1; i < base; i <<= 1) {
        digit += get_bit_at_index(new_index++) * i;
    }
    return digit;
}

template <typename limb_t>
const std::string ubint<limb_t>::to_string() const {
    std::vector<uint8_t> val{0};
    val.reserve(msb_ >> 1);
    for (uint32_t i = msb_; i > 0; --i) {
        auto ofl = get_bit_at_index(i);  // TODO: needlessly expensive here
        for (auto& a : val) {
            a = (a << 1) + ofl;
            if ((ofl = (a > 9)))
                a -= 10;
        }
        if (ofl)
            val.push_back(1);
    }
    for (auto& a : val)
        a += '0';
    return std::string(val.rbegin(), val.rend());
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
 (The sequence is in little-endian order).

 This is a fairly precise implementation of Knuth's Algorithm D, for a
 binary computer with base b = 2**(32|64). The caller supplies:
 1. Space q for the quotient, m - n + 1 words (at least one).
 2. Space r for the remainder (optional), n words.
 3. The dividend u, m words, m >= 1.
 4. The divisor v, n words, n >= 2.
 The most significant digit of the divisor, v[n-1], must be nonzero.  The
 dividend u may have leading zeros; this just makes the algorithm take
 longer and makes the quotient contain more leading zeros.  A value of
 nullptr may be given for the address of the remainder to signify that the
 caller does not want the remainder.
 The program does not alter the input parameters u and v.
 The quotient and remainder returned may have leading zeros.  The
 function itself returns a value of 0 for success and 1 for invalid
 parameters (e.g., division by 0).
 For now, we must have m >= n.  Knuth's Algorithm D also requires
 that the dividend be at least as long as the divisor.  (In his terms,
 m >= 0 (unstated).  Therefore m+n >= n.) */

template <typename limb_t>
void ubint<limb_t>::divqr_vect(ubint& qin, ubint& rin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.value_;
    int m = u.size();
    auto& v = vin.value_;
    int n = v.size();
    auto& q = qin.value_;
    q.resize(m - n + 1);
    auto& r = rin.value_;
    Dlimb_t ofl{0};

    if (n == 1) {
        for (int i = m - 1; i >= 0; --i) {
            ofl = (ofl << limb_bit_length_) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        qin.normalize_limbs();

        r.resize(1);
        r[0] = static_cast<limb_t>(ofl);
        rin.msb_ = cipher::get_msb(r[0]);
        return;
    }

    // Normalize by shifting v left just enough so that its high-order
    // bit is set, and shift u left the same amount. We may have to append a
    // high-order digit on the dividend; we do that unconditionally.

    auto sl{limb_bit_length_ - cipher::get_msb(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl = (static_cast<Dlimb_t>(un[j + n]) << limb_bit_length_) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> limb_bit_length_) || ((qhat * vn[n - 2]) > ((rhat << limb_bit_length_) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> limb_bit_length_)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p = qhat * vn[i];
            t = un[i + j] - k - (p & max_limb_);
            un[i + j] = static_cast<limb_t>(t);
            k = (p >> limb_bit_length_) - (t >> limb_bit_length_);
        }
        t = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        q[j] = qhat;
        if (t < 0) {
            q[j] -= 1;
            k = 0;
            for (int i = 0; i < n; ++i) {
                t = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k = t >> limb_bit_length_;
            }
            un[j + n] += k;
        }
    }
    qin.normalize_limbs();

    ofl = un[0] >> sl;
    auto sr{limb_bit_length_ - sl};
    r.resize(n--);
    for (int i = 0; i < n; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(un[i + 1]) << sr;
        r[i] = static_cast<limb_t>(ofl);
    }
    r[n] = un[n] >> sl;
    rin.normalize_limbs();
}

template <typename limb_t>
void ubint<limb_t>::divq_vect(ubint& qin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.value_;
    int m = u.size();
    auto& v = vin.value_;
    int n = v.size();
    auto& q = qin.value_;
    q.resize(m - n + 1);
    Dlimb_t ofl{0};

    if (n == 1) {
        for (int i = m - 1; i >= 0; --i) {
            ofl = (ofl << limb_bit_length_) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        qin.normalize_limbs();
        return;
    }

    auto sl{limb_bit_length_ - cipher::get_msb(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl = (static_cast<Dlimb_t>(un[j + n]) << limb_bit_length_) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> limb_bit_length_) || ((qhat * vn[n - 2]) > ((rhat << limb_bit_length_) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> limb_bit_length_)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p = qhat * vn[i];
            t = un[i + j] - k - (p & max_limb_);
            un[i + j] = static_cast<limb_t>(t);
            k = (p >> limb_bit_length_) - (t >> limb_bit_length_);
        }
        t = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        q[j] = qhat;
        if (t < 0) {
            q[j] -= 1;
            k = 0;
            for (int i = 0; i < n; ++i) {
                t = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k = t >> limb_bit_length_;
            }
            un[j + n] += k;
        }
    }
    qin.normalize_limbs();
}

template <typename limb_t>
void ubint<limb_t>::divr_vect(ubint& rin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.value_;
    int m = u.size();
    auto& v = vin.value_;
    int n = v.size();
    auto& r = rin.value_;
    Dlimb_t ofl{0};

    if (n == 1) {
        std::vector<limb_t> q(m - n + 1);
        for (int i = m - 1; i >= 0; --i) {
            ofl = (ofl << limb_bit_length_) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        r[0] = static_cast<limb_t>(ofl);
        rin.msb_ = cipher::get_msb(r[0]);
        return;
    }

    auto sl{limb_bit_length_ - cipher::get_msb(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl = (static_cast<Dlimb_t>(un[j + n]) << limb_bit_length_) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> limb_bit_length_) || ((qhat * vn[n - 2]) > ((rhat << limb_bit_length_) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> limb_bit_length_)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p = qhat * vn[i];
            t = un[i + j] - k - (p & max_limb_);
            un[i + j] = static_cast<limb_t>(t);
            k = (p >> limb_bit_length_) - (t >> limb_bit_length_);
        }
        t = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        if (t < 0) {
            k = 0;
            for (int i = 0; i < n; ++i) {
                t = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k = t >> limb_bit_length_;
            }
            un[j + n] += k;
        }
    }

    r.resize(n--);
    ofl = un[0] >> sl;
    auto sr{limb_bit_length_ - sl};
    for (int i = 0; i < n; ++i, ofl >>= limb_bit_length_) {
        ofl |= static_cast<Dlimb_t>(un[i + 1]) << sr;
        r[i] = static_cast<limb_t>(ofl);
    }
    r[n] = un[n] >> sl;
    rin.normalize_limbs();
}

// Initializes the vector of limbs from the string equivalent of ubint
// Algorithm used is repeated division by 2
// Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template <typename limb_t>
void ubint<limb_t>::set_value(const std::string& vin) {
    std::string v{vin};
    // v.erase(0, v.find_first_not_of(' '));
    v.erase(0, v.find_first_not_of('0'));
    if (v.size() == 0)
        v = "0";

    size_t arr_size = v.length() - 1;
    for (size_t i = 0; i <= arr_size; ++i)
        v[i] -= '0';

    value_.clear();
    //    value_.reserve(msb_to_limbs(arr_size << 2));
    uint32_t cnt{0};
    limb_t val{0};
    size_t zptr{0};
    while (zptr <= arr_size) {
        val |= static_cast<limb_t>(v[arr_size] & 0x1) << cnt++;
        for (size_t i = zptr; i < arr_size; ++i) {
            v[i + 1] += (v[i] & 0x1) * 10;
            v[i] >>= 1;
        }
        v[arr_size] >>= 1;
        if (v[zptr] == 0)
            zptr++;

        if ((cnt == limb_bit_length_) || (zptr > arr_size)) {
            value_.push_back(val);
            cnt = val = 0;
        }
    }
    ubint<limb_t>::normalize_limbs();
}

template <typename limb_t>
uint8_t ubint<limb_t>::get_bit_at_index(uint32_t index) const {
    constexpr uint32_t mask{limb_bit_length_ - 1};
    if (index > msb_)
        return 0;
    size_t idx{msb_to_limbs(index) - 1};
    index &= mask;
    return static_cast<uint8_t>((value_[idx] >> (index ? index - 1 : mask)) & 0x1);
}

template class dynamic_int::ubint<expdtype>;

    #if 0
// to stream internal representation
template std::ostream& operator<<<expdtype>(std::ostream& os, const std::vector<expdtype>& v);
    #endif

}  // namespace bigintdyn
#endif
