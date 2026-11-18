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
  implementation of the integer lattice
 */

#ifndef CIPHER_RING_BACKEND_STANDARD_POLY_IMPL_H_
#define CIPHER_RING_BACKEND_STANDARD_POLY_IMPL_H_

#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cipher/ring/backend/standard/poly.h"
#include "cipher/util/debug.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

namespace cipher {

/**
 * @brief Constructs an element whose coefficients are sampled from a discrete Gaussian distribution and converted
 * to the requested format.
 *
 * @param dgg the discrete Gaussian generator.
 * @param params the element parameters.
 * @param format the format of the resulting element.
 */
template <typename VecType>
PolyImpl<VecType>::PolyImpl(const DggType& dgg, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : format_{Format::COEFFICIENT},
      params_{params},
      values_{std::make_unique<VecType>(dgg.generate_vector(params->get_ring_dimension(), params->get_modulus()))} {
    PolyImpl<VecType>::set_format(format);
}

/**
 * @brief Constructs an element with values sampled uniformly modulo the modulus, recorded as already being in the
 * requested format (no transform is applied).
 *
 * @param dug the discrete uniform generator.
 * @param params the element parameters.
 * @param format the format recorded for the resulting element.
 */
template <typename VecType>
PolyImpl<VecType>::PolyImpl(DugType& dug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : format_{format},
      params_{params},
      values_{std::make_unique<VecType>(dug.generate_vector(params->get_ring_dimension(), params->get_modulus()))} {}

/**
 * @brief Constructs an element whose coefficients are sampled from the binary uniform distribution and converted
 * to the requested format.
 *
 * @param bug the binary uniform generator.
 * @param params the element parameters.
 * @param format the format of the resulting element.
 */
template <typename VecType>
PolyImpl<VecType>::PolyImpl(const BugType& bug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : format_{Format::COEFFICIENT},
      params_{params},
      values_{std::make_unique<VecType>(bug.generate_vector(params->get_ring_dimension(), params->get_modulus()))} {
    PolyImpl<VecType>::set_format(format);
}

/**
 * @brief Constructs an element whose coefficients are sampled from the ternary uniform distribution and converted
 * to the requested format.
 *
 * @param tug the ternary uniform generator.
 * @param params the element parameters.
 * @param format the format of the resulting element.
 * @param h the Hamming weight (number of nonzero coefficients) for the sparse distribution; 0 samples every
 * coefficient uniformly.
 */
template <typename VecType>
PolyImpl<VecType>::PolyImpl(const TugType& tug, const std::shared_ptr<PolyImpl::Params>& params, Format format,
                            uint32_t h)
    : format_{Format::COEFFICIENT},
      params_{params},
      values_{std::make_unique<VecType>(tug.generate_vector(params->get_ring_dimension(), params->get_modulus(), h))} {
    PolyImpl<VecType>::set_format(format);
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const PolyImpl& rhs) noexcept {
    format_ = rhs.format_;
    params_ = rhs.params_;
    if (!rhs.values_) {
        values_ = nullptr;
        return *this;
    }
    if (values_) {
        *values_ = *rhs.values_;
        return *this;
    }
    values_ = std::make_unique<VecType>(*rhs.values_);
    return *this;
}

// assumes that elements in rhs less than modulus?
template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) {
    static const Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = params_->get_ring_dimension();
    if (!values_) {
        VecType temp(vlen);
        temp.set_modulus(params_->get_modulus());
        PolyImpl<VecType>::set_values(std::move(temp), format_);
    }
    for (size_t j = 0; j < vlen; ++j)
        (*values_)[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    return *this;
}

// TODO: template with enable_if int64_t/int32_t
template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int64_t>& rhs) {
    static const Integer ZERO(0);
    format_ = Format::COEFFICIENT;
    const size_t llen{rhs.size()};
    const size_t vlen{params_->get_ring_dimension()};
    const auto& m = params_->get_modulus();
    if (!values_) {
        VecType tmp(vlen);
        tmp.set_modulus(m);
        PolyImpl<VecType>::set_values(std::move(tmp), format_);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen)
            (*values_)[j] = signed_to_residue(rhs[j], m);
        else
            (*values_)[j] = ZERO;
    }
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int32_t>& rhs) {
    static const Integer ZERO(0);
    format_ = Format::COEFFICIENT;
    const size_t llen{rhs.size()};
    const size_t vlen{params_->get_ring_dimension()};
    const auto& m = params_->get_modulus();
    if (!values_) {
        VecType tmp(vlen);
        tmp.set_modulus(m);
        PolyImpl<VecType>::set_values(std::move(tmp), format_);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen)
            (*values_)[j] = signed_to_residue(rhs[j], m);
        else
            (*values_)[j] = ZERO;
    }
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs) {
    const size_t vlen = params_->get_ring_dimension();
    if (!values_) {
        VecType temp(vlen);
        temp.set_modulus(params_->get_modulus());
        PolyImpl<VecType>::set_values(std::move(temp), format_);
    }
    *values_ = rhs;
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(uint64_t val) {
    format_ = Format::EVALUATION;
    if (!values_) {
        auto d{params_->get_ring_dimension()};
        const auto& m{params_->get_modulus()};
        values_ = std::make_unique<VecType>(d, m);
    }
    size_t vlen{values_->get_length()};
    Integer ival{val};
    for (size_t i = 0; i < vlen; ++i)
        (*values_)[i] = ival;
    return *this;
}

template <typename VecType>
void PolyImpl<VecType>::set_values(const VecType& values, Format format) {
    if (params_->get_root_of_unity() == Integer(0))
        CIPHER_THROW("Polynomial has a 0 root of unity");
    if (params_->get_ring_dimension() != values.get_length() || params_->get_modulus() != values.get_modulus())
        CIPHER_THROW("Parameter mismatch on SetValues for Polynomial");
    format_ = format;
    values_ = std::make_unique<VecType>(values);
}

template <typename VecType>
void PolyImpl<VecType>::set_values(VecType&& values, Format format) {
    if (params_->get_root_of_unity() == Integer(0))
        CIPHER_THROW("Polynomial has a 0 root of unity");
    if (params_->get_ring_dimension() != values.get_length() || params_->get_modulus() != values.get_modulus())
        CIPHER_THROW("Parameter mismatch on SetValues for Polynomial");
    format_ = format;
    values_ = std::make_unique<VecType>(std::move(values));
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::plus_impl(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(params_, format_);
    if (format_ == Format::COEFFICIENT)
        tmp.set_values((*values_).mod_add_at_index(0, element), format_);
    else
        tmp.set_values((*values_).mod_add(element), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::minus_impl(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod_sub(element), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod_mul(element), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(NativeInteger::SignedNativeInt element) const {
    PolyImpl<VecType> tmp(params_, format_);
    Integer q{params_->get_modulus()};
    if (element < 0) {
        Integer element_reduced{NativeInteger::Integer(-element)};
        if (element_reduced > q)
            element_reduced.mod_eq(q);
        tmp.set_values((*values_).mod_mul(q - element_reduced), format_);
    } else {
        Integer element_reduced{NativeInteger::Integer(element)};
        if (element_reduced > q)
            element_reduced.mod_eq(q);
        tmp.set_values((*values_).mod_mul(element_reduced), format_);
    }
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::minus_impl(const PolyImpl& rhs) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod_sub(*rhs.values_), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::multiply_and_round(const typename VecType::Integer& p,
                                                        const typename VecType::Integer& q) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).multiply_and_round(p, q), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::divide_and_round(const typename VecType::Integer& q) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).divide_and_round(q), format_);
    return tmp;
}

// TODO: this will return vec of 0s for BigIntegers
template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::negate() const {
    //  UnitTestBFVrnsCRTOperations.cpp line 316 throws with this uncommented
    //    if (format_ != Format::EVALUATION)
    //        CIPHER_THROW("Negate for PolyImpl is supported only in Format::EVALUATION format.\n");
    return PolyImpl<VecType>(params_, format_, true) -= *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator+=(const PolyImpl& element) {
    if (!values_)
        values_ = std::make_unique<VecType>(params_->get_ring_dimension(), params_->get_modulus());
    values_->mod_add_eq(*element.values_);
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator-=(const PolyImpl& element) {
    if (!values_)
        values_ = std::make_unique<VecType>(params_->get_ring_dimension(), params_->get_modulus());
    values_->mod_sub_eq(*element.values_);
    return *this;
}

template <typename VecType>
void PolyImpl<VecType>::add_il_element_one() {
    static const Integer ONE(1);
    uint32_t vlen{params_->get_ring_dimension()};
    const auto& m{params_->get_modulus()};
    for (uint32_t i = 0; i < vlen; ++i)
        (*values_)[i].mod_add_fast_eq(ONE, m);
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::automorphism_transform(uint32_t k) const {
    uint32_t n{params_->get_ring_dimension()};
    uint32_t m{params_->get_cyclotomic_order()};
    bool bp{n == (m >> 1)};
    bool bf{format_ == Format::EVALUATION};

    // if (!bf && !bp)
    if (!bp)
        CIPHER_THROW("Automorphism Poly Format not EVALUATION or not power-of-two");
    /*
    // TODO: is this branch ever called?

    PolyImpl<VecType> result(params_, format_, true);
    if (bf && !bp) {
        // TODO: Add a test based on the inverse totient hash table?

        // All automorphism operations are performed for k coprime to m
        auto totientList = get_totient_list(m);

        // This step can be eliminated by using a hash table that looks up the
        // ring index (between 0 and n - 1) based on the totient index (between 0 and m - 1)
        VecType expanded(m, params_->get_modulus());
        for (uint32_t i = 0; i < n; ++i)
            expanded[totientList[i]] = (*values_)[i];

        for (uint32_t i = 0; i < n; ++i) {
            // determines which power of primitive root unity we should switch to
            (*result.values_)[i] = expanded[totientList[i] * k % m];
        }
        return result;
    }
*/
    if (k % 2 == 0)
        CIPHER_THROW("Automorphism index not odd\n");

    PolyImpl<VecType> result(params_, format_, true);
    uint32_t logm{cipher::get_msb(m) - 1};
    uint32_t logn{logm - 1};
    uint32_t mask{(uint32_t(1) << logn) - 1};

    if (bf) {
        for (uint32_t j{0}, jk{k}; j < n; ++j, jk += (2 * k)) {
            auto&& jrev{cipher::reverse_bits(j, logn)};
            auto&& idxrev{cipher::reverse_bits((jk >> 1) & mask, logn)};
            (*result.values_)[jrev] = (*values_)[idxrev];
        }
        return result;
    }

    auto q{params_->get_modulus()};
    for (uint32_t j{0}, jk{0}; j < n; ++j, jk += k)
        (*result.values_)[jk & mask] = ((jk >> logn) & 0x1) ? q - (*values_)[j] : (*values_)[j];
    return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::automorphism_transform(uint32_t k, const std::vector<uint32_t>& precomp) const {
    if ((format_ != Format::EVALUATION) || (params_->get_ring_dimension() != (params_->get_cyclotomic_order() >> 1)))
        CIPHER_THROW("Automorphism Poly Format not EVALUATION or not power-of-two");
    if (k % 2 == 0)
        CIPHER_THROW("Automorphism index not odd\n");
    PolyImpl<VecType> tmp(params_, format_, true);
    uint32_t n = params_->get_ring_dimension();
    for (uint32_t j = 0; j < n; ++j)
        (*tmp.values_)[j] = (*values_)[precomp[j]];
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::multiplicative_inverse() const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod_inverse(), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::mod_by_two() const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod_by_two(), format_);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::mod(const Integer& modulus) const {
    PolyImpl<VecType> tmp(params_, format_);
    tmp.set_values((*values_).mod(modulus), format_);
    return tmp;
}

template <typename VecType>
void PolyImpl<VecType>::switch_modulus(const Integer& modulus, const Integer& root_of_unity_value,
                                       const Integer& modulus_arb, const Integer& root_of_unity_arb) {
    if (values_ != nullptr) {
        values_->switch_modulus(modulus);
        auto c{params_->get_cyclotomic_order()};
        params_ = std::make_shared<PolyImpl::Params>(c, modulus, root_of_unity_value, modulus_arb, root_of_unity_arb);
    }
}

template <typename VecType>
void PolyImpl<VecType>::lazy_switch_modulus(const Integer& modulus, const Integer& root_of_unity_value,
                                            const Integer& modulus_arb, const Integer& root_of_unity_arb) {
    if (values_ != nullptr) {
        values_->lazy_switch_modulus(modulus);
        auto c{params_->get_cyclotomic_order()};
        params_ = std::make_shared<PolyImpl::Params>(c, modulus, root_of_unity_value, modulus_arb, root_of_unity_arb);
    }
}

template <typename VecType>
void PolyImpl<VecType>::switch_format(uint32_t thread_limit) {
    const auto& co{params_->get_cyclotomic_order()};
    const auto& rd{params_->get_ring_dimension()};
    const auto& ru{params_->get_root_of_unity()};

    if (rd != (co >> 1)) {
        PolyImpl<VecType>::arbitrary_switch_format();
        return;
    }

    if (!values_)
        CIPHER_THROW("Poly switch format to empty values");

    if (format_ != Format::COEFFICIENT) {
        format_ = Format::COEFFICIENT;
        ChineseRemainderTransformFtt<VecType>().inverse_transform_from_bit_reverse_in_place(ru, co, &(*values_));
        return;
    }
    format_ = Format::EVALUATION;
    ChineseRemainderTransformFtt<VecType>().forward_transform_to_bit_reverse_in_place(ru, co, &(*values_));
}

template <typename VecType>
void PolyImpl<VecType>::arbitrary_switch_format() {
    if (values_ == nullptr)
        CIPHER_THROW("Poly switch format to empty values");
    const auto& lr = params_->get_root_of_unity();
    const auto& bm = params_->get_big_modulus();
    const auto& br = params_->get_big_root_of_unity();
    const auto& co = params_->get_cyclotomic_order();
    if (format_ == Format::COEFFICIENT) {
        format_ = Format::EVALUATION;
        auto&& v = ChineseRemainderTransformArb<VecType>().forward_transform(*values_, lr, bm, br, co);
        values_ = std::make_unique<VecType>(v);
    } else {
        format_ = Format::COEFFICIENT;
        auto&& v = ChineseRemainderTransformArb<VecType>().inverse_transform(*values_, lr, bm, br, co);
        values_ = std::make_unique<VecType>(v);
    }
}

/**
 * @brief Writes the values and modulus of a polynomial, followed by its root of unity, to an output stream.
 *
 * @param os the output stream.
 * @param p the polynomial to print.
 * @return the output stream.
 */
template <typename VecType>
std::ostream& operator<<(std::ostream& os, const PolyImpl<VecType>& p) {
    if (p.values_ != nullptr) {
        os << *(p.values_);
        os << " mod:" << (p.values_)->get_modulus() << std::endl;
    }
    if (p.params_.get() != nullptr)
        os << " rootOfUnity: " << p.get_root_of_unity() << std::endl;
    else
        os << " something's odd: null m_params?!" << std::endl;
    os << std::endl;
    return os;
}

template <typename VecType>
void PolyImpl<VecType>::make_sparse(uint32_t w_factor) {
    static const Integer ZERO(0);
    if (values_ != nullptr) {
        uint32_t vlen{params_->get_ring_dimension()};
        for (uint32_t i = 0; i < vlen; ++i) {
            if (i % w_factor != 0)
                (*values_)[i] = ZERO;
        }
    }
}

template <typename VecType>
bool PolyImpl<VecType>::inverse_exists() const {
    static const Integer ZERO(0);
    uint32_t vlen{params_->get_ring_dimension()};
    for (uint32_t i = 0; i < vlen; ++i) {
        if ((*values_)[i] == ZERO)
            return false;
    }
    return true;
}

template <typename VecType>
double PolyImpl<VecType>::norm() const {
    uint32_t vlen{params_->get_ring_dimension()};
    const auto& q{params_->get_modulus()};
    const auto& half{q >> 1};
    Integer max_val{}, min_val{q};
    for (uint32_t i = 0; i < vlen; i++) {
        auto& val = (*values_)[i];
        if (val > half)
            min_val = val < min_val ? val : min_val;
        else
            max_val = val > max_val ? val : max_val;
    }
    min_val = q - min_val;
    return (min_val > max_val ? min_val : max_val).convert_to_double();
}

// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0
// }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and return the vector of{
// u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{
// \log q / base } \rceil }; used as a subroutine in the relinearization
// procedure base_bits is the number of bits in the base, i.e., base = 2^base_bits

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::base_decompose(uint32_t base_bits, bool eval_mode_answer) const {
    uint32_t n_bits = params_->get_modulus().get_length_for_base(2);

    uint32_t n_windows = n_bits / base_bits;
    if (n_bits % base_bits > 0)
        n_windows++;

    std::vector<PolyImpl<VecType>> result;
    result.reserve(n_windows);

    PolyImpl<VecType> xcopy;
    if (format_ != Format::COEFFICIENT) {
        xcopy = *this;
        xcopy.set_format(Format::COEFFICIENT);
    }
    const PolyImpl<VecType>& x = (format_ != Format::COEFFICIENT) ? xcopy : *this;

    if constexpr (std::is_same_v<VecType, NativeVector>) {
        for (auto&& dv : x.get_values().base_decompose(base_bits)) {
            PolyImpl<VecType> x_digit(params_);
            x_digit.set_values(std::move(dv), Format::COEFFICIENT);
            if (eval_mode_answer)
                x_digit.switch_format();
            result.push_back(std::move(x_digit));
        }
    } else {
        // TP: x is same for BACKEND 2 and 6
        for (uint32_t i = 0; i < n_windows; ++i) {
            PolyImpl<VecType> x_digit(params_);
            x_digit.set_values(x.get_values().get_digit_at_index_for_base(i + 1, uint32_t{1} << base_bits),
                               Format::COEFFICIENT);

            // TP: x_digit is all zeros for BACKEND=6, but not for BACKEND-2
            // *********************************************************
            if (eval_mode_answer)
                x_digit.switch_format();
            result.push_back(std::move(x_digit));
        }
    }
    return result;
}

// Generate a vector of PolyImpl's as {x, base*x, base^2*x, ..., base^{\lfloor
// {\log q/base} \rfloor}*x, where x is the current PolyImpl object; used as a
// subroutine in the relinearization procedure to get powers of a certain "base"
// for the secret key element base_bits is the number of bits in the base, i.e.,
// base = 2^base_bits

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::powers_of_base(uint32_t base_bits) const {
    static const Integer TWO(2);
    const auto& m{params_->get_modulus()};
    uint32_t n_bits{m.get_length_for_base(2)};
    uint32_t n_windows{n_bits / base_bits};
    if (n_bits % base_bits > 0)
        ++n_windows;
    std::vector<PolyImpl<VecType>> result(n_windows);
    Integer shift{0}, bbits{base_bits};
    for (uint32_t i = 0; i < n_windows; ++i, shift += bbits)
        result[i] = (*this) * TWO.mod_exp(shift, m);
    return result;
}

template <typename VecType>
typename PolyImpl<VecType>::PolyNative PolyImpl<VecType>::decryption_crt_interpolate(PlaintextModulus ptm) const {
    const PolyImpl<VecType> smaller(PolyImpl<VecType>::mod(ptm));
    uint32_t vlen{params_->get_ring_dimension()};
    auto c{params_->get_cyclotomic_order()};
    auto params{std::make_shared<NativePolyParams>(c, NativeInteger(ptm), 1)};
    typename PolyImpl<VecType>::PolyNative tmp(params, format_, true);
    for (uint32_t i = 0; i < vlen; ++i)
        tmp[i] = NativeInteger((*smaller.values_)[i]);
    return tmp;
}

template <>
inline PolyImpl<NativeVector> PolyImpl<NativeVector>::to_native_poly() const {
    return *this;
}

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_STANDARD_POLY_IMPL_H_
