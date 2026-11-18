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
  Implementation of the integer lattice using double-CRT representations
 */

#ifndef CIPHER_RING_BACKEND_STANDARD_RNS_POLY_IMPL_H_
#define CIPHER_RING_BACKEND_STANDARD_RNS_POLY_IMPL_H_

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "cipher/config.h"
#include "cipher/ring/backend/standard/rns_poly.h"
#include "cipher/ring/backend/standard/poly_impl.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/parallel.h"
#include "cipher/util/utilities_internal.h"
#include "cipher/util/utilities.h"

namespace cipher {

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const PolyLargeType& rhs, const std::shared_ptr<RnsPolyImpl::Params>& params) noexcept
    : RnsPolyImpl<VecType>::RnsPolyImpl(params, rhs.get_format(), true) {
    const uint32_t rdim = rhs.get_length();
    for (auto& v : vectors_) {
        const auto& m = v.get_params()->get_modulus();
        for (uint32_t i = 0; i < rdim; ++i)
            v[i] = rhs[i].mod(m);
    }
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(const PolyLargeType& rhs) noexcept {
    vectors_.clear();
    vectors_.reserve(params_->get_params().size());
    const uint32_t rdim = rhs.get_length();
    for (const auto& p : params_->get_params()) {
        vectors_.emplace_back(p, format_, true);
        const auto& m = p->get_modulus();
        auto& v = vectors_.back();
        for (uint32_t i = 0; i < rdim; ++i)
            v[i] = rhs[i].mod(m);
    }
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const PolyType& rhs, const std::shared_ptr<RnsPolyImpl::Params>& params) noexcept
    : params_{params}, format_{rhs.get_format()} {
    const auto& p = params->get_params();
    const uint32_t size = p.size();
    if (rhs.is_empty()) {
        vectors_.resize(size, rhs);
        return;
    }
    vectors_.reserve(size);
    vectors_.push_back(rhs);
    for (uint32_t i = 1; i < size; ++i) {
        PolyType tmp(p[i], format_);
        tmp.set_values(NativeVector(rhs.get_values(), p[i]->get_modulus()), format_);
        vectors_.push_back(std::move(tmp));
    }
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(const PolyType& rhs) noexcept {
    format_ = rhs.get_format();
    vectors_.clear();
    const auto& p = params_->get_params();
    const uint32_t size = p.size();
    if (rhs.is_empty()) {
        vectors_.resize(size, rhs);
        return *this;
    }
    vectors_.reserve(size);
    vectors_.push_back(rhs);
    for (uint32_t i = 1; i < size; ++i) {
        PolyType tmp(p[i], rhs.get_format());
        tmp.set_values(NativeVector(rhs.get_values(), p[i]->get_modulus()), rhs.get_format());
        vectors_.push_back(std::move(tmp));
    }
    return *this;
}

/* Construct using a tower of vectors.
 * The params and format for the RnsPolyImpl will be derived from the towers */
template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const std::vector<RnsPolyImpl::PolyType>& towers)
    : params_{nullptr}, format_{towers[0].get_format()}, vectors_(towers) {
    std::vector<std::shared_ptr<NativePolyParams>> parms;
    parms.reserve(vectors_.size());
    const auto cyclotomic_order = vectors_[0].get_cyclotomic_order();
    for (const auto& v : vectors_) {
        if (v.get_cyclotomic_order() != cyclotomic_order)
            CIPHER_THROW("Polys provided to constructor must have the same ring dimension");
        parms.emplace_back(v.get_params());
    }
    params_ = std::make_shared<RnsPolyImpl::Params>(cyclotomic_order, parms);
}

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const DggType& dgg, const std::shared_ptr<RnsPolyImpl::Params>& dcrt_params,
                                  Format format)
    : params_{dcrt_params}, format_{format} {
    const uint32_t rdim = params_->get_ring_dimension();
    const auto dgg_values = dgg.generate_int_vector(rdim);
    vectors_.reserve(params_->get_params().size());
    for (auto& p : params_->get_params()) {
        NativeVector ildv(rdim, p->get_modulus());
        if (dgg.get_std() > p->get_modulus().convert_to_double()) {
            auto modulus = (p->get_modulus()).template convert_to_int<int64_t>();
            for (uint32_t j = 0; j < rdim; ++j) {
                NativeInteger::SignedNativeInt k = (dgg_values[j] % modulus);
                ildv[j] = (k < 0) ? p->get_modulus() - static_cast<NativeInteger>(-k) : static_cast<NativeInteger>(k);
            }
        } else {
            for (uint32_t j = 0; j < rdim; ++j)
                ildv[j] = (dgg_values[j] < 0) ? p->get_modulus() - static_cast<NativeInteger>(-dgg_values[j]) :
                                                static_cast<NativeInteger>(dgg_values[j]);
        }
        vectors_.emplace_back(p);
        vectors_.back().set_values(std::move(ildv), Format::COEFFICIENT);
        vectors_.back().set_format(format_);
    }
}

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(DugType& dug, const std::shared_ptr<Params>& dcrt_params, Format format)
    : params_{dcrt_params}, format_{format} {
    vectors_.reserve(params_->get_params().size());
    for (auto& p : params_->get_params()) {
        vectors_.emplace_back(p);
        vectors_.back().set_values(NativeVector(dug.generate_vector(p->get_ring_dimension(), p->get_modulus())),
                                   format_);
    }
}

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const BugType& bug, const std::shared_ptr<Params>& dcrt_params, Format format)
    : params_{dcrt_params}, format_{format} {
    vectors_.reserve(params_->get_params().size());
    bool first = true;
    RnsPolyImpl<VecType>::PolyType ilvector(bug, params_->get_params()[0], Format::COEFFICIENT);
    for (auto& p : params_->get_params()) {
        if (!first)
            ilvector.switch_modulus(p->get_modulus(), p->get_root_of_unity(), 0, 0);
        vectors_.push_back(ilvector);
        vectors_.back().set_format(format_);
        first = false;
    }
}

template <typename VecType>
RnsPolyImpl<VecType>::RnsPolyImpl(const TugType& tug, const std::shared_ptr<Params>& dcrt_params, Format format,
                                  uint32_t h)
    : params_{dcrt_params}, format_{format} {
    const uint32_t rdim = params_->get_ring_dimension();
    const auto tug_values = tug.generate_int_vector(rdim, h);
    vectors_.reserve(params_->get_params().size());
    for (auto& p : params_->get_params()) {
        NativeVector iltvs(rdim, p->get_modulus());
        for (uint32_t j = 0; j < rdim; ++j)
            iltvs[j] = (tug_values[j] < 0) ? p->get_modulus() - static_cast<NativeInteger>(-tug_values[j]) :
                                             static_cast<NativeInteger>(tug_values[j]);
        vectors_.emplace_back(p);
        vectors_.back().set_values(std::move(iltvs), Format::COEFFICIENT);
        vectors_.back().set_format(format_);
    }
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::clone_with_noise(const DiscreteGaussianGeneratorImpl<VecType>& dgg,
                                                            Format format) const {
    auto c{params_->get_cyclotomic_order()};
    const auto& m{params_->get_modulus()};
    auto parm{std::make_shared<PolyParamsImpl<Integer>>(c, m, 1)};
    RnsPolyImpl<VecType>::PolyLargeType element(parm);
    // the samples are the coefficients of the noise polynomial, whatever format is requested
    element.set_values(dgg.generate_vector(c / 2, m), Format::COEFFICIENT);
    RnsPolyImpl<VecType> result(params_, Format::COEFFICIENT);
    result = element;
    result.set_format(format);
    return result;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::clone_towers(uint32_t start_tower, uint32_t end_tower) const {
    auto cycorder = params_->get_cyclotomic_order();
    auto params = std::make_shared<Params>(cycorder, params_->get_param_partition(start_tower, end_tower));
    auto res = RnsPolyImpl(params, format_, false);
    for (uint32_t i = start_tower; i <= end_tower; ++i)
        res.set_element_at_index(i - start_tower, this->get_element_at_index(i));
    return res;
}

template <typename VecType>
std::vector<RnsPolyImpl<VecType>> RnsPolyImpl<VecType>::base_decompose(uint32_t base_bits,
                                                                       bool eval_mode_answer) const {
    auto bd_v(crt_interpolate().base_decompose(base_bits, false));
    std::vector<RnsPolyImpl<VecType>> result;
    result.reserve(bd_v.size());
    for (auto& dv : bd_v) {
        result.emplace_back(dv, params_);
        if (eval_mode_answer)
            result.back().switch_format();
    }
    return result;
}

template <typename VecType>
std::vector<RnsPolyImpl<VecType>> RnsPolyImpl<VecType>::crt_decompose(uint32_t base_bits) const {
    RnsPolyImpl<VecType> cp(*this);
    cp.switch_format();
    const RnsPolyImpl<VecType>* coef = (format_ == Format::COEFFICIENT) ? this : &cp;
    const RnsPolyImpl<VecType>* eval = (format_ == Format::COEFFICIENT) ? &cp : this;
    uint32_t size(vectors_.size());

    if (base_bits == 0) {
        std::vector<RnsPolyType> result(size);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (uint32_t i = 0; i < size; ++i) {
            result[i] = RnsPolyType((*eval).params_, Format::EVALUATION, false);
            for (uint32_t k = 0; k < size; ++k) {
                if (i != k) {
                    RnsPolyImpl::PolyType tmp((*coef).vectors_[k].get_params(), Format::COEFFICIENT);
                    tmp.set_values(NativeVector((*coef).vectors_[i].get_values(), (*coef).vectors_[k].get_modulus()),
                                   Format::COEFFICIENT);
                    tmp.set_format(Format::EVALUATION);
                    result[i].vectors_[k] = std::move(tmp);
                }
            }
            result[i].vectors_[i] = (*eval).vectors_[i];
        }
        return result;
    }

    uint32_t n_windows{0};
    // used to store the number of digits for each small modulus
    std::vector<uint32_t> arr_windows(size);
    // creates an array of digits up to a certain tower
    for (uint32_t i = 0; i < size; ++i) {
        uint32_t n_bits{vectors_[i].get_modulus().get_length_for_base(2)};
        uint32_t cur_windows{n_bits / base_bits};
        if (n_bits % base_bits != 0)
            cur_windows++;
        arr_windows[i] = n_windows;
        n_windows += cur_windows;
    }
    std::vector<RnsPolyType> result(n_windows);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i) {
        auto decomposed = (*coef).vectors_[i].base_decompose(base_bits, false);
        const uint32_t decomposedsize = decomposed.size();
        for (uint32_t j = 0; j < decomposedsize; ++j) {
            RnsPolyImpl<VecType> current_rns_poly((*coef).params_, Format::COEFFICIENT, false);
            for (uint32_t k = 0; k < size; ++k) {
                if (i != k) {
                    RnsPolyImpl::PolyType tmp((*coef).vectors_[k].get_params(), Format::COEFFICIENT);
                    tmp.set_values(NativeVector(decomposed[j].get_values(), (*coef).vectors_[k].get_modulus()),
                                   Format::COEFFICIENT);
                    current_rns_poly.vectors_[k] = std::move(tmp);
                }
            }
            current_rns_poly.vectors_[i] = std::move(decomposed[j]);
            current_rns_poly.switch_format();
            result[j + arr_windows[i]] = std::move(current_rns_poly);
        }
    }
    return result;
}

template <typename VecType>
std::vector<RnsPolyImpl<VecType>> RnsPolyImpl<VecType>::powers_of_base(uint32_t base_bits) const {
    // prepare for the calculations by gathering a big integer version of each of the little moduli
    std::vector<Integer> mods;
    mods.reserve(params_->get_params().size());
    for (auto& p : params_->get_params())
        mods.emplace_back(p->get_modulus());

    uint32_t n_bits = params_->get_modulus().get_length_for_base(2);
    uint32_t n_windows = n_bits / base_bits;
    if (n_bits % base_bits != 0)
        ++n_windows;

    std::vector<RnsPolyImpl<VecType>> result;
    result.reserve(n_windows);
    Integer two_pow(1);
    uint32_t size(vectors_.size());
    for (uint32_t i = 0; i < n_windows; ++i) {
        RnsPolyImpl<VecType> x(params_, format_);
        two_pow.l_shift_eq(base_bits);
        for (uint32_t t = 0; t < size; ++t)
            x.vectors_[t] = vectors_[t] * two_pow.mod(mods[t]).convert_to_int();
        result.push_back(std::move(x));
    }
    return result;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::automorphism_transform(uint32_t idx) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].automorphism_transform(idx);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::automorphism_transform(uint32_t idx,
                                                                  const std::vector<uint32_t>& vec) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].automorphism_transform(idx, vec);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::multiplicative_inverse() const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
    // multiplicative_inverse throws on non-invertible elements, and an exception cannot leave
    // an OpenMP region (the runtime terminates instead -- the "segfault" this pragma was once
    // disabled over). Record the failure inside the region and throw after it, preserving the
    // throwing contract the unit tests pin.
    int fail = 0;
#pragma omp parallel for reduction(| : fail) num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i) {
        try {
            tmp.vectors_[i] = vectors_[i].multiplicative_inverse();
        } catch (...) {
            fail = 1;
        }
    }
    if (fail)
        CIPHER_THROW("MultiplicativeInverse: a tower has a non-invertible element");
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::negate() const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].negate();
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::operator-() const {
    return RnsPolyImpl<VecType>(params_, format_, true) -= *this;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::minus_impl(const RnsPolyImpl& rhs) const {
    if (vectors_.size() != rhs.vectors_.size())
        CIPHER_THROW("tower size mismatch; cannot subtract");
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].minus_impl(rhs.vectors_[i]);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator+=(const RnsPolyImpl& rhs) {
    uint32_t size(vectors_.size());
    if (size > rhs.vectors_.size())
        CIPHER_THROW("tower size mismatch; cannot add");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] += rhs.vectors_[i];
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator+=(const Integer& rhs) {
    NativeInteger val{rhs};
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] += val;
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator+=(const NativeInteger& rhs) {
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] += rhs;
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator-=(const RnsPolyImpl& rhs) {
    uint32_t size(vectors_.size());
    if (size > rhs.vectors_.size())
        CIPHER_THROW("tower size mismatch; cannot subtract");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] -= rhs.vectors_[i];
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator-=(const Integer& rhs) {
    NativeInteger val{rhs};
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] -= val;
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator-=(const NativeInteger& rhs) {
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] -= rhs;
    return *this;
}

template <typename VecType>
bool RnsPolyImpl<VecType>::operator==(const RnsPolyImpl& rhs) const {
    return ((format_ == rhs.format_) && (params_->get_cyclotomic_order() == rhs.params_->get_cyclotomic_order()) &&
            (params_->get_modulus() == rhs.params_->get_modulus()) && (vectors_.size() == rhs.vectors_.size()) &&
            (vectors_ == rhs.vectors_));
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    static constexpr RnsPolyImpl::PolyType::Integer ZERO(0);
    const uint32_t llen = rhs.size();
    const uint32_t vlen = params_->get_ring_dimension();
    for (auto& v : vectors_) {
        if (v.is_empty()) {
            NativeVector temp(vlen);
            temp.set_modulus(v.get_modulus());
            v.set_values(std::move(temp), format_);
        }
        for (uint32_t j = 0; j < vlen; ++j)
            v[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    }
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs) noexcept {
    static constexpr RnsPolyImpl::PolyType::Integer ZERO(0);
    const uint32_t llen = rhs.size();
    const uint32_t vlen = params_->get_ring_dimension();
    for (auto& v : vectors_) {
        if (v.is_empty()) {
            NativeVector temp(vlen);
            temp.set_modulus(v.get_modulus());
            v.set_values(std::move(temp), format_);
        }
        for (uint32_t j = 0; j < vlen; ++j)
            v[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    }
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(uint64_t val) noexcept {
    for (auto& v : vectors_)
        v = val;
    format_ = Format::EVALUATION;
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(const std::vector<int64_t>& val) noexcept {
    for (auto& v : vectors_) {
        if (v.is_empty()) {
            NativeVector temp(params_->get_ring_dimension());
            temp.set_modulus(v.get_modulus());
            v.set_values(std::move(temp), format_);
        }
        v = val;
    }
    format_ = Format::COEFFICIENT;
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator=(const std::vector<int32_t>& val) noexcept {
    for (auto& v : vectors_) {
        if (v.is_empty()) {
            NativeVector temp(params_->get_ring_dimension());
            temp.set_modulus(v.get_modulus());
            v.set_values(std::move(temp), format_);
        }
        v = val;
    }
    format_ = Format::COEFFICIENT;
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::plus_impl(const Integer& rhs) const {
    NativeInteger val{rhs};
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].plus_impl(val);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::plus_impl(const std::vector<Integer>& crt_element) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].plus_impl(NativeInteger(crt_element[i]));
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::minus_impl(const Integer& rhs) const {
    NativeInteger val{rhs};
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].minus_impl(val);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::minus_impl(const std::vector<Integer>& crt_element) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].minus_impl(NativeInteger(crt_element[i]));
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::Times(const Integer& rhs) const {
    NativeInteger val{rhs};
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].Times(val);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::Times(NativeInteger::SignedNativeInt rhs) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].Times(rhs);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::Times(const std::vector<Integer>& crt_element) const {
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].Times(NativeInteger(crt_element[i]));
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::Times(const std::vector<NativeInteger>& rhs) const {
    if (vectors_.size() != rhs.size())
        CIPHER_THROW("tower size mismatch; cannot multiply");
    RnsPolyImpl<VecType> tmp(params_, format_);
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        tmp.vectors_[i] = vectors_[i].Times(rhs[i]);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::times_no_check(const std::vector<NativeInteger>& rhs) const {
    uint32_t vec_size = vectors_.size() < rhs.size() ? vectors_.size() : rhs.size();
    RnsPolyImpl<VecType> tmp(params_, format_);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(vec_size))
    for (uint32_t i = 0; i < vec_size; ++i)
        tmp.vectors_[i] = vectors_[i].Times(rhs[i]);
    return tmp;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator*=(const Integer& rhs) {
    NativeInteger val{rhs};
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] *= val;
    return *this;
}

template <typename VecType>
RnsPolyImpl<VecType>& RnsPolyImpl<VecType>::operator*=(const NativeInteger& rhs) {
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i] *= rhs;
    return *this;
}

template <typename VecType>
void RnsPolyImpl<VecType>::set_values_to_zero() {
    uint32_t size(vectors_.size());
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i].set_values_to_zero();
}

template <typename VecType>
void RnsPolyImpl<VecType>::set_values_mod_switch(const RnsPolyImpl& element, const NativeInteger& modulus) {
    uint32_t N(params_->get_ring_dimension());
    if (N != element.get_ring_dimension())
        CIPHER_THROW("Ring dimension mismatch.");
    if (element.vectors_.size() != 1 || vectors_.size() != 1)
        CIPHER_THROW("Only implemented for DCRTPoly with one tower.");

    auto input{element.vectors_[0]};
    input.set_format(Format::COEFFICIENT);
    NativeVector tmp(N);
    tmp.set_modulus(modulus);
    auto qmod_double{modulus.convert_to_double() / element.get_modulus().convert_to_double()};
    for (uint32_t j = 0; j < N; ++j) {
        tmp[j] = NativeInteger(static_cast<BasicInteger>(std::floor(0.5 + input[j].convert_to_double() * qmod_double)))
                         .mod(modulus);
    }
    vectors_[0].set_values(std::move(tmp), Format::COEFFICIENT);
}

template <typename VecType>
void RnsPolyImpl<VecType>::add_il_element_one() {
    if (format_ != Format::EVALUATION)
        CIPHER_THROW("Only available in EVALUATION format.");
    uint32_t size(vectors_.size());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i].add_il_element_one();
}

template <typename VecType>
bool RnsPolyImpl<VecType>::is_empty() const {
    for (auto& v : vectors_) {
        if (!v.is_empty())
            return false;
    }
    return true;
}

template <typename VecType>
void RnsPolyImpl<VecType>::drop_last_element() {
    if (vectors_.size() == 0)
        CIPHER_THROW("Input has no elements to drop.");
    if (vectors_.size() == 1)
        CIPHER_THROW("Removing last element of DCRTPoly renders it invalid.");
    vectors_.resize(vectors_.size() - 1);
    RnsPolyImpl::Params* new_p = new RnsPolyImpl::Params(*params_);
    new_p->pop_last_param();
    params_.reset(new_p);
}

template <typename VecType>
void RnsPolyImpl<VecType>::drop_last_elements(size_t i) {
    if (vectors_.size() <= i)
        CIPHER_THROW("Too few towers in input.");
    vectors_.resize(vectors_.size() - i);
    RnsPolyImpl::Params* new_p = new RnsPolyImpl::Params(*params_);
    for (size_t j = 0; j < i; ++j)
        new_p->pop_last_param();
    params_.reset(new_p);
}

// used for CKKS rescaling
// Computes round(x/q_l) as (x - [x]_{q_l}) * [q_l^{-1}]_{q_i}, where [x]_{q_l} is the
// centered representative produced by switch_modulus (see RS(ct) in Sec. 3.2 of
// https://eprint.iacr.org/2018/931). The subtraction makes (x - [x]_{q_l}) exactly
// divisible by q_l, so one scalar multiplication per tower suffices.
template <typename VecType>
void RnsPolyImpl<VecType>::drop_last_element_and_scale(const std::vector<NativeInteger>& ql_inv_modq) {
    auto last_poly(std::move(vectors_.back()));
    last_poly.set_format(Format::COEFFICIENT);
    this->drop_last_element();
    uint32_t size(vectors_.size());

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i) {
        PolyType tmp(vectors_[i].get_params(), Format::COEFFICIENT);
        tmp.set_values(NativeVector(last_poly.get_values(), vectors_[i].get_modulus()), Format::COEFFICIENT);
        if (format_ == Format::EVALUATION)
            tmp.switch_format();
        vectors_[i] -= tmp;
        vectors_[i] *= ql_inv_modq[i];
        if (format_ == Format::COEFFICIENT)
            vectors_[i].switch_format();
    }
    this->override_format(Format::EVALUATION);
}

/**
* Used for BGVrns modulus switching
* This function performs mod_reduce on ciphertext element and private key
element. The algorithm computes ct' <- round( ct/qt ).

* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus
q/qt where qt is generally the last moduli of the tower.
* mod_reduce is written for RnsPolyImpl and it drops the last tower while
updating the necessary parameters.

* The rounding is actually computed as a flooring by computing delta such that
delta = -ct mod qt and delta = 0 [t]

* The steps taken here are as follows:
* 1. compute delta <- -ct/ptm mod qt
* 2. compute delta <- ptm*delta in Z. E.g., all of delta's integer coefficients
can be in the range [-ptm*qt/2, ptm*qt/2).
* 3. let d' = c + delta mod q/qt. By construction, d' is divisible by qt and
congruent to 0 mod ptm.
* 4. output (d'/q') in R(q/q').
*
* @param t the plaintext modulus.
* @param t_modq_precon NTL-specific precomputations for [t]_{q_i}; not used by this implementation.
* @param negt_inv_modq precomputed value for [-t^{-1}]_{q_l}.
* @param negt_inv_modq_precon NTL-specific precomputation for negt_inv_modq; not used by this implementation.
* @param ql_inv_modq precomputed values for [q_l^{-1}]_{q_i}.
* @param ql_inv_modq_precon NTL-specific precomputations for ql_inv_modq; not used by this implementation.
*/
template <typename VecType>
void RnsPolyImpl<VecType>::mod_reduce(const NativeInteger& t, const std::vector<NativeInteger>& t_modq_precon,
                                      const NativeInteger& negt_inv_modq, const NativeInteger& negt_inv_modq_precon,
                                      const std::vector<NativeInteger>& ql_inv_modq,
                                      const std::vector<NativeInteger>& ql_inv_modq_precon) {
    RnsPolyImpl::PolyType delta(vectors_.back());
    delta.set_format(Format::COEFFICIENT);
    delta *= negt_inv_modq;
    this->drop_last_element();
    uint32_t size(vectors_.size());

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i) {
        PolyType tmp(vectors_[i].get_params(), Format::COEFFICIENT);
        tmp.set_values(NativeVector(delta.get_values(), vectors_[i].get_modulus()), Format::COEFFICIENT);
        if (format_ == Format::EVALUATION)
            tmp.switch_format();
        vectors_[i].mult_acc_eq_no_check(tmp, t);
        vectors_[i] *= ql_inv_modq[i];
    }
}

/*
 * This method applies Chinese Remainder Interpolation on a RnsPoly
 * How the Algorithm works:
 * View the RnsPoly as a (t = Number of Towers) x (r = ring Dimension) Matrix M.
 * Let qt denote the big_modulus (product of each tower moduli), qi denote the
 * modulus of a particular tower, and V be a BigVector of length r.
 * For j = 0 --> r-1, calculate
 * V[j] = Sigma(i = 0 --> t-1) { M(i,j) * qt/qi * [(qt/qi)^(-1) mod qi] } mod qt
 */
template <typename VecType>
typename RnsPolyImpl<VecType>::PolyLargeType RnsPolyImpl<VecType>::crt_interpolate() const {
    if (format_ != Format::COEFFICIENT)
        CIPHER_THROW("Only available in COEFFICIENT format.");

    const uint32_t t(vectors_.size());
    const uint32_t r{params_->get_ring_dimension()};
    const Integer qt{params_->get_modulus()};
    Integer tmp1, tmp2;

    std::vector<Integer> multiplier;
    multiplier.reserve(t);
    for (uint32_t i = 0; i < t; ++i) {
        tmp1 = vectors_[i].get_modulus().convert_to_int();  // qi
        tmp2 = qt / tmp1;
        multiplier.emplace_back(tmp2.mod_inverse(tmp1) * tmp2);  // qt/qi * [(qt/qi)^(-1) mod qi]
    }

    VecType V(r, qt);

#pragma omp parallel for private(tmp1) num_threads(cipher_parallel_controls.get_thread_limit(THREADS_CRT_BASIS_SWITCH))
    for (uint32_t j = 0; j < r; ++j) {
        for (uint32_t i = 0; i < t; ++i)
            V[j] += (tmp1 = vectors_[i].get_values()[j].convert_to_int()) * multiplier[i];
        V[j].mod_eq(qt);
    }

    // Setting the root of unity to ONE as the calculation is expensive and not required.
    RnsPolyImpl<VecType>::PolyLargeType poly(std::make_shared<PolyParamsImpl<Integer>>(2 * r, qt, 1));
    poly.set_values(std::move(V), Format::COEFFICIENT);
    return poly;
}

/*
 * This method applies Chinese Remainder Interpolation on a
 * single element across all towers of a RnsPolyImpl and produces
 * an Poly with zeros except at that single element
 */
template <typename VecType>
typename RnsPolyImpl<VecType>::PolyLargeType RnsPolyImpl<VecType>::crt_interpolate_index(uint32_t i) const {
    if (format_ != Format::COEFFICIENT)
        CIPHER_THROW("Only available in COEFFICIENT format.");

    uint32_t r{params_->get_ring_dimension()};
    const Integer qt{params_->get_modulus()};
    Integer tmp1, tmp2;
    VecType V(r, qt, 0);
    for (const auto& npoly : vectors_) {
        tmp1 = npoly.get_modulus().convert_to_int();  // qi
        tmp2 = qt / tmp1;
        tmp1 = tmp2.mod_inverse(tmp1) * tmp2;  // qt/qi * [(qt/qi)^(-1) mod qi]
        const auto& mi = npoly.get_values();
        V[i] += tmp1 * (tmp2 = mi[i].convert_to_int());
    }

    V[i].mod_eq(qt, qt.compute_mu());

    // Setting the root of unity to ONE as the calculation is expensive and not required.
    RnsPolyImpl<VecType>::PolyLargeType poly(std::make_shared<PolyParamsImpl<Integer>>(2 * r, qt, 1));
    poly.set_values(std::move(V), Format::COEFFICIENT);
    return poly;
}

template <typename VecType>
typename RnsPolyImpl<VecType>::PolyType RnsPolyImpl<VecType>::decryption_crt_interpolate(PlaintextModulus ptm) const {
    return this->crt_interpolate().decryption_crt_interpolate(ptm);
}

template <typename VecType>
typename RnsPolyImpl<VecType>::PolyType RnsPolyImpl<VecType>::to_native_poly() const {
    return this->crt_interpolate().to_native_poly();
}

template <typename VecType>
typename VecType::Integer RnsPolyImpl<VecType>::get_working_modulus() const {
    typename VecType::Integer modulus_q = 1;
    for (const auto& p : params_->get_params())
        modulus_q.mul_eq(p->get_modulus());
    return modulus_q;
}

template <typename VecType>
std::shared_ptr<typename RnsPolyImpl<VecType>::Params> RnsPolyImpl<VecType>::get_extended_crt_basis(
        const std::shared_ptr<Params>& params_p) const {
    uint32_t size_q = vectors_.size();
    uint32_t size_qp = size_q + params_p->get_params().size();
    std::vector<NativeInteger> moduli_qp(size_qp);
    std::vector<NativeInteger> roots_qp(size_qp);
    const auto& parq = params_->get_params();
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli_qp[i] = parq[i]->get_modulus();
        roots_qp[i] = parq[i]->get_root_of_unity();
    }
    const auto& parp = params_p->get_params();
    for (uint32_t i = size_q, j = 0; i < size_qp; ++i, ++j) {
        moduli_qp[i] = parp[j]->get_modulus();
        roots_qp[i] = parp[j]->get_root_of_unity();
    }
    return std::make_shared<Params>(2 * params_->get_ring_dimension(), moduli_qp, roots_qp);
}

template <typename VecType>
void RnsPolyImpl<VecType>::times_qovert(const std::shared_ptr<Params>& params_q,
                                        const std::vector<NativeInteger>& t_inv_modq, const NativeInteger& t,
                                        const NativeInteger& neg_q_modt, const NativeInteger& neg_q_modt_precon) {
    if (t_inv_modq.size() < vectors_.size())
        CIPHER_THROW("Sizes of vectors do not match.");
    uint32_t size(vectors_.size());
    uint32_t ring_dim(params_->get_ring_dimension());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
    for (uint32_t i = 0; i < size; ++i) {
        auto q{vectors_[i].get_modulus()};
        auto mu{q.compute_mu()};
        for (uint32_t ri = 0; ri < ring_dim; ++ri) {
            NativeInteger& xi = vectors_[i][ri];
            xi.mod_mul_fast_const_eq(neg_q_modt, t, neg_q_modt_precon);
            xi.mod_mul_fast_eq(t_inv_modq[i], q, mu);
        }
    }
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::approx_switch_crt_basis(
        const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
        const std::vector<NativeInteger>& q_hat_inv_modq, const std::vector<NativeInteger>& q_hat_inv_modq_precon,
        const std::vector<std::vector<NativeInteger>>& q_hat_modp,
        const std::vector<DoubleNativeInt>& modp_barrett_mu) const {
    RnsPolyImpl<VecType> ans(params_p, format_, true);
    uint32_t size_q =
            (vectors_.size() > params_q->get_params().size()) ? params_q->get_params().size() : vectors_.size();
    uint32_t size_p = ans.vectors_.size();
#if defined(CIPHER_HAVE_INT128) && (CIPHER_NATIVE_INT == 64) && !defined(CIPHER_WITH_REDUCED_NOISE) && \
        (defined(CIPHER_WITH_OPENMP) || (defined(__clang__) && !defined(CIPHER_WITH_NATIVEOPT)))
    uint32_t ring_dim = params_->get_ring_dimension();
    std::vector<DoubleNativeInt> sum(size_p);
    #pragma omp parallel for firstprivate(sum) num_threads(cipher_parallel_controls.get_thread_limit( \
                    approx_switch_crt_basis_threads(ring_dim, size_q, size_p)))
    for (uint32_t ri = 0; ri < ring_dim; ++ri) {
        std::fill(sum.begin(), sum.end(), 0);
        for (uint32_t i = 0; i < size_q; ++i) {
            const auto& q_hat_modpi = q_hat_modp[i];
            const auto& qi = vectors_[i].get_modulus();
            const auto x_q_hat_inv_modqi = vectors_[i][ri]
                                                   .mod_mul_fast_const(q_hat_inv_modq[i], qi, q_hat_inv_modq_precon[i])
                                                   .template convert_to_int<uint64_t>();
            for (uint32_t j = 0; j < size_p; ++j)
                sum[j] += mul128(x_q_hat_inv_modqi, q_hat_modpi[j].convert_to_int<uint64_t>());
        }
        for (uint32_t j = 0; j < size_p; ++j) {
            auto&& pj = ans.vectors_[j].get_modulus().template convert_to_int<uint64_t>();
            ans.vectors_[j][ri] = barrett_uint128_mod_uint64(sum[j], pj, modp_barrett_mu[j]);
        }
    }
#else
    for (uint32_t i = 0; i < size_q; ++i) {
        auto x_q_hat_inv_modqi = vectors_[i] * q_hat_inv_modq[i];
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_p))
        for (uint32_t j = 0; j < size_p; ++j) {
    #if defined(CIPHER_WITH_REDUCED_NOISE)
            auto tmp = x_q_hat_inv_modqi;
            tmp.switch_modulus(ans.vectors_[j].get_modulus(), ans.vectors_[j].get_root_of_unity(), 0, 0);
            ans.vectors_[j].mult_acc_eq_no_check(tmp, q_hat_modp[i][j]);
    #else
            ans.vectors_[j].mult_acc_eq_no_check(x_q_hat_inv_modqi, q_hat_modp[i][j]);
    #endif
        }
    }
#endif
    return ans;
}

template <typename VecType>
void RnsPolyImpl<VecType>::approx_mod_up(const std::shared_ptr<Params>& params_q,
                                         const std::shared_ptr<Params>& params_p,
                                         const std::shared_ptr<Params>& params_qp,
                                         const std::vector<NativeInteger>& q_hat_inv_modq,
                                         const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                         const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                         const std::vector<DoubleNativeInt>& modp_barrett_mu) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<RnsPolyImpl::PolyType> poly_in_ntt;
    if (format_ == Format::EVALUATION) {
        poly_in_ntt = vectors_;
        const uint32_t size_q = std::min<uint32_t>(vectors_.size(), params_q->get_params().size());
        this->set_format(Format::COEFFICIENT, approx_switch_crt_basis_threads(params_->get_ring_dimension(), size_q,
                                                                              params_p->get_params().size()));
    }

    auto part_p = this->approx_switch_crt_basis(params_q, params_p, q_hat_inv_modq, q_hat_inv_modq_precon, q_hat_modp,
                                                modp_barrett_mu);

    if (poly_in_ntt.size() > 0)
        vectors_ = std::move(poly_in_ntt);

    uint32_t size_qp = params_qp->get_params().size();
    vectors_.reserve(size_qp);
    vectors_.insert(vectors_.end(), std::make_move_iterator(part_p.vectors_.begin()),
                    std::make_move_iterator(part_p.vectors_.end()));

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_qp))
    for (uint32_t i = 0; i < size_qp; ++i)
        vectors_[i].set_format(Format::EVALUATION);
    format_ = Format::EVALUATION;
    params_ = params_qp;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::approx_mod_down(
        const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
        const std::vector<NativeInteger>& P_inv_modq, const std::vector<NativeInteger>& p_inv_modq_precon,
        const std::vector<NativeInteger>& p_hat_inv_modp, const std::vector<NativeInteger>& p_hat_inv_modp_precon,
        const std::vector<std::vector<NativeInteger>>& p_hat_modq, const std::vector<DoubleNativeInt>& modq_barrett_mu,
        const std::vector<NativeInteger>& t_inv_modp, const std::vector<NativeInteger>& t_inv_modp_precon,
        const NativeInteger& t, const std::vector<NativeInteger>& t_modq_precon) const {
    RnsPolyImpl<VecType> part_p(params_p, format_);
    uint32_t size_p = params_p->get_params().size();
    uint32_t size_q = vectors_.size() - size_p;

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_p))
    for (uint32_t j = 0; j < size_p; ++j) {
        part_p.vectors_[j] = vectors_[size_q + j];
        part_p.vectors_[j].set_format(Format::COEFFICIENT);
        // Multiply everything by -t^(-1) mod P (BGVrns only)
        if (t > 0)
            part_p.vectors_[j] *= t_inv_modp[j];
    }
    part_p.override_format(Format::COEFFICIENT);
    part_p = part_p.approx_switch_crt_basis(params_p, params_q, p_hat_inv_modp, p_hat_inv_modp_precon, p_hat_modq,
                                            modq_barrett_mu);

    RnsPolyImpl<VecType> ans(params_q, Format::EVALUATION);
    if (uint32_t diff_q = params_q->get_params().size() - size_q; diff_q != 0)
        ans.drop_last_elements(diff_q);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_q))
    for (uint32_t i = 0; i < size_q; ++i) {
        // Multiply everything by t mod Q (BGVrns only)
        if (t > 0)
            part_p.vectors_[i] *= t;
        part_p.vectors_[i].set_format(Format::EVALUATION);
        ans.vectors_[i] = (vectors_[i] - part_p.vectors_[i]) * P_inv_modq[i];
    }
    return ans;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::switch_crt_basis(const std::shared_ptr<Params>& params_p,
                                                            const std::vector<NativeInteger>& q_hat_inv_modq,
                                                            const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                                            const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                                            const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                                            const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                                            const std::vector<double>& q_inv) const {
    uint32_t size_q = vectors_.size();
    uint32_t size_p = params_p->get_params().size();

    std::vector<NativeInteger> x_q_hat_inv_modq(size_q);
    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(size_p);
    for (const auto& p : params_p->get_params())
        mu.push_back(p->get_modulus().compute_mu());

    RnsPolyImpl<VecType> ans(params_p, format_, true);
    uint32_t ring_dim = params_->get_ring_dimension();

#pragma omp parallel for firstprivate(x_q_hat_inv_modq) \
        num_threads(cipher_parallel_controls.get_thread_limit(THREADS_CRT_BASIS_SWITCH))
    for (uint32_t ri = 0; ri < ring_dim; ++ri) {
        double nu{0.5};
        for (uint32_t i = 0; i < size_q; ++i) {
            const auto& qi = vectors_[i].get_modulus();
            // computes [x_i (Q/q_i)^{-1}]_{q_i}
            x_q_hat_inv_modq[i] = vectors_[i][ri].mod_mul_fast_const(q_hat_inv_modq[i], qi, q_hat_inv_modq_precon[i]);
            // to keep track of the number of q-overflows
            nu += x_q_hat_inv_modq[i].convert_to_double() * q_inv[i];
        }
        // alpha corresponds to the number of overflows, 0 <= static_cast<size_t>(nu) <= size_q
        const auto& alpha_q_modpri = alpha_q_modp[static_cast<size_t>(nu)];

        for (uint32_t j = 0; j < size_p; ++j) {
            const auto& pj = ans.vectors_[j].get_modulus();
            const auto& q_hat_modpj = q_hat_modp[j];
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
            DoubleNativeInt cur_value = 0;
            for (uint32_t i = 0; i < size_q; ++i)
                cur_value += mul128(x_q_hat_inv_modq[i].convert_to_int(), q_hat_modpj[i].convert_to_int());
            const auto& cur_native_value =
                    NativeInteger(barrett_uint128_mod_uint64(cur_value, pj.convert_to_int(), modp_barrett_mu[j]));
            ans.vectors_[j][ri] = cur_native_value.mod_sub_fast(alpha_q_modpri[j], pj);
#else
            for (uint32_t i = 0; i < size_q; ++i)
                ans.vectors_[j][ri].mod_add_fast_eq(x_q_hat_inv_modq[i].mod(pj).mod_mul_fast(q_hat_modpj[i], pj, mu[j]),
                                                    pj);
            ans.vectors_[j][ri].mod_sub_fast_eq(alpha_q_modpri[j], pj);
#endif
        }
    }
    return ans;
}

template <typename VecType>
void RnsPolyImpl<VecType>::expand_crt_basis(const std::shared_ptr<Params>& params_qp,
                                            const std::shared_ptr<Params>& params_p,
                                            const std::vector<NativeInteger>& q_hat_inv_modq,
                                            const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                            const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                            const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                            const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                            const std::vector<double>& q_inv, Format result_format) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<RnsPolyImpl::PolyType> poly_in_ntt;
    if (format_ == Format::EVALUATION) {
        poly_in_ntt = vectors_;
        this->set_format(Format::COEFFICIENT, THREADS_CRT_BASIS_SWITCH);
    }

    auto part_p = this->switch_crt_basis(params_p, q_hat_inv_modq, q_hat_inv_modq_precon, q_hat_modp, alpha_q_modp,
                                         modp_barrett_mu, q_inv);

    if ((result_format == Format::EVALUATION) && (poly_in_ntt.size() > 0))
        vectors_ = std::move(poly_in_ntt);

    uint32_t size_qp = params_qp->get_params().size();
    vectors_.reserve(size_qp);
    vectors_.insert(vectors_.end(), std::make_move_iterator(part_p.vectors_.begin()),
                    std::make_move_iterator(part_p.vectors_.end()));

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_qp))
    for (uint32_t i = 0; i < size_qp; ++i)
        vectors_[i].set_format(result_format);
    format_ = result_format;
    params_ = params_qp;
}

template <typename VecType>
void RnsPolyImpl<VecType>::expand_crt_basis_reverse_order(const std::shared_ptr<Params>& params_qp,
                                                          const std::shared_ptr<Params>& params_p,
                                                          const std::vector<NativeInteger>& q_hat_inv_modq,
                                                          const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                                          const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                                          const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                                          const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                                          const std::vector<double>& q_inv, Format result_format) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<RnsPolyImpl::PolyType> poly_in_ntt;
    if (format_ == Format::EVALUATION) {
        poly_in_ntt = vectors_;
        this->set_format(Format::COEFFICIENT, THREADS_CRT_BASIS_SWITCH);
    }

    auto part_p = this->switch_crt_basis(params_p, q_hat_inv_modq, q_hat_inv_modq_precon, q_hat_modp, alpha_q_modp,
                                         modp_barrett_mu, q_inv);

    if ((result_format == Format::EVALUATION) && (poly_in_ntt.size() > 0))
        vectors_ = std::move(poly_in_ntt);

    uint32_t size_qp = params_qp->get_params().size();
    part_p.vectors_.reserve(size_qp);
    part_p.vectors_.insert(part_p.vectors_.end(), std::make_move_iterator(vectors_.begin()),
                           std::make_move_iterator(vectors_.end()));
    vectors_ = std::move(part_p.vectors_);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_qp))
    for (uint32_t i = 0; i < size_qp; ++i)
        vectors_[i].set_format(result_format);
    format_ = result_format;
    params_ = params_qp;
}

template <typename VecType>
void RnsPolyImpl<VecType>::fast_expand_crt_basis_plover_q(const Precomputations& precomputed) {
    auto part_pl = this->approx_switch_crt_basis(params_, precomputed.params_pl, precomputed.m_pl_q_hat_inv_modq,
                                                 precomputed.m_pl_q_hat_inv_modq_precon, precomputed.q_inv_modp,
                                                 precomputed.modp_barrett_mu);
    auto part_ql = part_pl.switch_crt_basis(precomputed.params_ql, precomputed.pl_hat_inv_modp,
                                            precomputed.pl_hat_inv_modp_precon, precomputed.pl_hat_modq,
                                            precomputed.alpha_pl_modq, precomputed.modq_barrett_mu, precomputed.p_inv);

    vectors_ = std::move(part_ql.vectors_);
    vectors_.reserve(part_ql.vectors_.size() + part_pl.vectors_.size());
    vectors_.insert(vectors_.end(), std::make_move_iterator(part_pl.vectors_.begin()),
                    std::make_move_iterator(part_pl.vectors_.end()));
    params_ = precomputed.params_ql_pl;
}

template <typename VecType>
void RnsPolyImpl<VecType>::expand_crt_basis_ql_hat(const std::shared_ptr<Params>& params_q,
                                                   const std::vector<NativeInteger>& ql_hat_modq,
                                                   const std::vector<NativeInteger>& ql_hat_modq_precon,
                                                   const uint32_t size_q) {
    uint32_t size_ql(vectors_.size());
    uint32_t ring_dim(params_->get_ring_dimension());
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql))
    for (uint32_t i = 0; i < size_ql; ++i) {
        const NativeInteger& qi = vectors_[i].get_modulus();
        const NativeInteger& ql_hat_modqi = ql_hat_modq[i];
        const NativeInteger& ql_hat_modqi_precon = ql_hat_modq_precon[i];
        for (uint32_t ri = 0; ri < ring_dim; ++ri)
            vectors_[i][ri].mod_mul_fast_const_eq(ql_hat_modqi, qi, ql_hat_modqi_precon);
    }
    vectors_.resize(size_q);
    for (uint32_t i = size_ql; i < size_q; ++i) {
        typename RnsPolyImpl<VecType>::PolyType newvec(params_q->get_params()[i], format_, true);
        vectors_[i] = std::move(newvec);
    }
    params_ = params_q;
}

template <typename VecType>
typename RnsPolyImpl<VecType>::PolyType RnsPolyImpl<VecType>::scale_and_round(
        const NativeInteger& t, const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt,
        const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt_precon,
        const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt,
        const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt_precon,
        const std::vector<double>& t_q_hat_inv_modq_divq_frac,
        const std::vector<double>& t_q_hat_inv_modq_divq_b_frac) const {
    uint32_t ring_dim = params_->get_ring_dimension();
    uint32_t size_q = vectors_.size();
    // MSB of q_i
    auto qtmp = vectors_[0].get_modulus();
    for (uint32_t i = 1; i < size_q; ++i) {
        if (vectors_[i].get_modulus() > qtmp)
            qtmp = vectors_[i].get_modulus();
    }
    uint32_t q_msb = qtmp.get_msb();
    // MSB of t
    uint32_t t_msb = t.get_msb();
    // MSB of size_q
    uint32_t size_qmsb = get_msb(size_q);

    RnsPolyImpl::PolyType::Vector coefficients(ring_dim, t.convert_to_int());
    // For power of two t we can do modulo reduction easily
    if (is_power_of_two(t.convert_to_int())) {
        uint64_t t_minus1 = t.convert_to_int() - 1;
        // We try to keep floating point error of
        // \sum x_i*t_q_hat_inv_modq_divq_frac[i] small.
        if (q_msb + size_qmsb < 52) {
            // In our settings x_i <= q_i/2 and for double type floating point
            // error is bounded by 2^{-53}. Thus the floating point error is bounded
            // by size_q * q_i/2 * 2^{-53}. In case of q_msb + size_qmsb < 52 the error
            // is bounded by 1/4, and the rounding will be correct.
            if ((q_msb + size_qmsb + t_msb) < 63) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 63 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.5;
                    NativeInteger int_sum = 0, tmp;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp = vectors_[i][ri];

                        float_sum += tmp.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp.mul_eq_fast(t_q_hat_inv_modq_divq_modt[i]);
                        int_sum.add_eq_fast(tmp);
                    }
                    int_sum += static_cast<uint64_t>(float_sum);
                    // mod a power of two
                    coefficients[ri] = int_sum.convert_to_int() & t_minus1;
                }
            } else {
                // In case of q_msb + size_qmsb >= 52 we decompose x_i in the basis
                // B=2^{q_msb/2} And split the sum \sum x_i*t_q_hat_inv_modq_divq_frac[i] to
                // the sum \sum xLo_i*t_q_hat_inv_modq_divq_frac[i] +
                // xHi_i*t_q_hat_inv_modq_b_divq_frac[i] with also precomputed
                // t_q_hat_inv_modq_b_divq_frac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
                // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
                // is bounded by 2^{-53}. Thus the floating point error is bounded by
                // size_q * 2^30 * 2^{-53}. We always have size_q < 2^11, which means the
                // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.5;
                    NativeInteger int_sum = 0, tmp;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp = vectors_[i][ri];

                        float_sum += tmp.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];

                        tmp.mod_mul_fast_const_eq(t_q_hat_inv_modq_divq_modt[i], t,
                                                  t_q_hat_inv_modq_divq_modt_precon[i]);
                        int_sum.add_eq_fast(tmp);
                    }
                    int_sum += static_cast<uint64_t>(float_sum);
                    // mod a power of two
                    coefficients[ri] = int_sum.convert_to_int() & t_minus1;
                }
            }
        } else {
            uint32_t q_msb_hf = q_msb >> 1;
            if ((q_msb_hf + t_msb + size_qmsb) < 62) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 62 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.5;
                    NativeInteger int_sum = 0;
                    NativeInteger tmp_hi, tmp_lo;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp_lo = vectors_[i][ri];
                        tmp_hi = tmp_lo.r_shift(q_msb_hf);
                        tmp_lo.sub_eq_fast(tmp_hi.l_shift(q_msb_hf));

                        float_sum += tmp_lo.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];
                        float_sum += tmp_hi.convert_to_double() * t_q_hat_inv_modq_divq_b_frac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp_lo.mul_eq_fast(t_q_hat_inv_modq_divq_modt[i]);
                        tmp_hi.mul_eq_fast(t_q_hat_inv_modq_b_divq_modt[i]);
                        int_sum.add_eq_fast(tmp_lo);
                        int_sum.add_eq_fast(tmp_hi);
                    }
                    int_sum += static_cast<uint64_t>(float_sum);
                    // mod a power of two
                    coefficients[ri] = int_sum.convert_to_int() & t_minus1;
                }
            } else {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.5;
                    NativeInteger int_sum = 0;
                    NativeInteger tmp_hi, tmp_lo;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp_lo = vectors_[i][ri];
                        tmp_hi = tmp_lo.r_shift(q_msb_hf);
                        tmp_lo.sub_eq_fast(tmp_hi.l_shift(q_msb_hf));

                        float_sum += tmp_lo.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];
                        float_sum += tmp_hi.convert_to_double() * t_q_hat_inv_modq_divq_b_frac[i];

                        tmp_lo.mod_mul_fast_const_eq(t_q_hat_inv_modq_divq_modt[i], t,
                                                     t_q_hat_inv_modq_divq_modt_precon[i]);
                        tmp_hi.mod_mul_fast_const_eq(t_q_hat_inv_modq_b_divq_modt[i], t,
                                                     t_q_hat_inv_modq_b_divq_modt_precon[i]);
                        int_sum.add_eq_fast(tmp_lo);
                        int_sum.add_eq_fast(tmp_hi);
                    }
                    int_sum += static_cast<uint64_t>(float_sum);
                    // mod a power of two
                    coefficients[ri] = int_sum.convert_to_int() & t_minus1;
                }
            }
        }
    } else {
        // non-power of two: modular reduction is more expensive
        double td = t.convert_to_int();
        double t_inv = 1. / td;
        // We try to keep floating point error of
        // \sum x_i*t_q_hat_inv_modq_divq_frac[i] small.
        if (q_msb + size_qmsb < 52) {
            // In our settings x_i <= q_i/2 and for double type floating point
            // error is bounded by 2^{-53}. Thus the floating point error is bounded
            // by size_q * q_i/2 * 2^{-53}. In case of q_msb + size_qmsb < 52 the error
            // is bounded by 1/4, and the rounding will be correct.
            if ((q_msb + t_msb + size_qmsb) < 52) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 52 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once using floating point techniques
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.0;
                    NativeInteger int_sum = 0, tmp;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp = vectors_[i][ri];

                        float_sum += tmp.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp.mul_eq_fast(t_q_hat_inv_modq_divq_modt[i]);
                        int_sum.add_eq_fast(tmp);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    float_sum += int_sum.convert_to_int();
                    float_sum -= td * static_cast<uint64_t>(float_sum * t_inv);
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(float_sum + 0.5);
                }
            } else {
                // In case of q_msb + size_qmsb >= 52 we decompose x_i in the basis
                // B=2^{q_msb/2} And split the sum \sum x_i*t_q_hat_inv_modq_divq_frac[i] to
                // the sum \sum xLo_i*t_q_hat_inv_modq_divq_frac[i] +
                // xHi_i*t_q_hat_inv_modq_b_divq_frac[i] with also precomputed
                // t_q_hat_inv_modq_b_divq_frac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
                // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
                // is bounded by 2^{-53}. Thus the floating point error is bounded by
                // size_q * 2^30 * 2^{-53}. We always have size_q < 2^11, which means the
                // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum{0.0};
                    NativeInteger int_sum{0};
                    for (uint32_t i = 0; i < size_q; ++i) {
                        const auto& tmp = vectors_[i][ri];
                        float_sum += tmp.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];
                        int_sum.add_eq_fast(tmp.mod_mul_fast_const(t_q_hat_inv_modq_divq_modt[i], t,
                                                                   t_q_hat_inv_modq_divq_modt_precon[i]));
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    float_sum += int_sum.convert_to_double();
                    float_sum -= td * static_cast<uint64_t>(float_sum * t_inv);
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(float_sum + 0.5);
                }
            }
        } else {
            uint32_t q_msb_hf = q_msb >> 1;
            if ((q_msb_hf + t_msb + size_qmsb) < 52) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 52 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once using floating point techniques
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.0;
                    NativeInteger int_sum = 0;
                    NativeInteger tmp_hi, tmp_lo;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp_lo = vectors_[i][ri];
                        tmp_hi = tmp_lo.r_shift(q_msb_hf);
                        tmp_lo.sub_eq_fast(tmp_hi.l_shift(q_msb_hf));

                        float_sum += tmp_lo.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];
                        float_sum += tmp_hi.convert_to_double() * t_q_hat_inv_modq_divq_b_frac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp_lo.mul_eq_fast(t_q_hat_inv_modq_divq_modt[i]);
                        tmp_hi.mul_eq_fast(t_q_hat_inv_modq_b_divq_modt[i]);
                        int_sum.add_eq_fast(tmp_lo);
                        int_sum.add_eq_fast(tmp_hi);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    float_sum += int_sum.convert_to_int();
                    float_sum -= td * static_cast<uint64_t>(float_sum * t_inv);
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(float_sum + 0.5);
                }
            } else {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_SCALE_TO_POLY))
                for (uint32_t ri = 0; ri < ring_dim; ++ri) {
                    double float_sum = 0.0;
                    NativeInteger int_sum = 0;
                    NativeInteger tmp_hi, tmp_lo;
                    for (uint32_t i = 0; i < size_q; ++i) {
                        tmp_lo = vectors_[i][ri];
                        tmp_hi = tmp_lo.r_shift(q_msb_hf);
                        tmp_lo.sub_eq_fast(tmp_hi.l_shift(q_msb_hf));

                        float_sum += tmp_lo.convert_to_double() * t_q_hat_inv_modq_divq_frac[i];
                        float_sum += tmp_hi.convert_to_double() * t_q_hat_inv_modq_divq_b_frac[i];

                        tmp_lo.mod_mul_fast_const_eq(t_q_hat_inv_modq_divq_modt[i], t,
                                                     t_q_hat_inv_modq_divq_modt_precon[i]);
                        tmp_hi.mod_mul_fast_const_eq(t_q_hat_inv_modq_b_divq_modt[i], t,
                                                     t_q_hat_inv_modq_b_divq_modt_precon[i]);
                        int_sum.add_eq_fast(tmp_lo);
                        int_sum.add_eq_fast(tmp_hi);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    float_sum += int_sum.convert_to_int();
                    float_sum -= td * static_cast<uint64_t>(float_sum * t_inv);
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(float_sum + 0.5);
                }
            }
        }
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation
    // representation are performed after this
    RnsPolyImpl::PolyType result(
            std::make_shared<RnsPolyImpl::PolyType::Params>(params_->get_cyclotomic_order(), t.convert_to_int(), 1));
    result.set_values(std::move(coefficients), Format::COEFFICIENT);

    return result;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::approx_scale_and_round(
        const std::shared_ptr<Params>& params_p,
        const std::vector<std::vector<NativeInteger>>& t_ps_hat_inv_mods_divs_modp,
        const std::vector<DoubleNativeInt>& modp_barret_mu) const {
    RnsPolyImpl<VecType> ans(params_p, format_, true);
    uint32_t size_qp = vectors_.size();
    uint32_t size_p = ans.vectors_.size();
    uint32_t size_q = size_qp - size_p;

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(size_p);
    for (const auto& p : params_p->get_params())
        mu.push_back(p->get_modulus().compute_mu());

    uint32_t ring_dim = params_->get_ring_dimension();
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_CRT_BASIS_SWITCH))
    for (uint32_t ri = 0; ri < ring_dim; ++ri) {
        for (uint32_t j = 0; j < size_p; ++j) {
            const auto& pj = ans.vectors_[j].get_modulus();
            const auto& t_ps_hat_inv_mods_divs_modpj = t_ps_hat_inv_mods_divs_modp[j];
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
            DoubleNativeInt cur_value = 0;
            for (uint32_t i = 0; i < size_q; ++i) {
                const NativeInteger& xi = vectors_[i][ri];
                cur_value += mul128(xi.convert_to_int(), t_ps_hat_inv_mods_divs_modpj[i].convert_to_int());
            }
            const NativeInteger& xi = vectors_[size_q + j][ri];
            cur_value += mul128(xi.convert_to_int(), t_ps_hat_inv_mods_divs_modpj[size_q].convert_to_int());

            ans.vectors_[j][ri] = barrett_uint128_mod_uint64(cur_value, pj.convert_to_int(), modp_barret_mu[j]);
#else
            for (uint32_t i = 0; i < size_q; ++i) {
                const NativeInteger& xi = vectors_[i][ri];
                ans.vectors_[j][ri].mod_add_fast_eq(xi.mod_mul(t_ps_hat_inv_mods_divs_modpj[i], pj, mu[j]), pj);
            }
            const NativeInteger& xi = vectors_[size_q + j][ri];
            ans.vectors_[j][ri].mod_add_fast_eq(xi.mod_mul(t_ps_hat_inv_mods_divs_modpj[size_q], pj, mu[j]), pj);
#endif
        }
    }
    return ans;
}

template <typename VecType>
RnsPolyImpl<VecType> RnsPolyImpl<VecType>::scale_and_round(
        const std::shared_ptr<Params>& params_output,
        const std::vector<std::vector<NativeInteger>>& t_os_hat_inv_mods_divs_modo,
        const std::vector<double>& t_os_hat_inv_mods_divs_frac,
        const std::vector<DoubleNativeInt>& modo_barret_mu) const {
    if constexpr (CIPHER_NATIVE_INT == 32)
        CIPHER_THROW("Use of ScaleAndRound with NATIVEINT == 32 may lead to overflow");

    RnsPolyImpl<VecType> ans(params_output, format_, true);
    uint32_t ring_dim = params_->get_ring_dimension();
    uint32_t size_qp = vectors_.size();
    uint32_t size_o = ans.vectors_.size();
    uint32_t size_i = size_qp - size_o;
    uint32_t input_index = 0;
    uint32_t output_index = 0;

    if (params_output->get_params()[0]->get_modulus() == params_->get_params()[0]->get_modulus()) {
        // If the output modulus is Q, then the input index refers to the values (mod p_j), shifted by size_q.
        input_index = size_o;
    } else {
        // If the output modulus is P, then the output index refers to the values (mod p_j), shifted by size_q.
        output_index = size_i;
    }

    std::vector<NativeInteger> mu;
    mu.reserve(size_o);
    for (const auto& p : params_output->get_params())
        mu.push_back(p->get_modulus().compute_mu());

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_CRT_BASIS_SWITCH))
    for (uint32_t ri = 0; ri < ring_dim; ++ri) {
        double nu = 0.5;
        for (uint32_t i = 0; i < size_i; ++i) {
            // possible loss of precision if modulus greater than 2^53 + 1
            const NativeInteger& xi = vectors_[i + input_index][ri];
            nu += t_os_hat_inv_mods_divs_frac[i] * xi.convert_to_double();
        }
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
        if (is_convertable_to_native_int(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (uint32_t j = 0; j < size_o; ++j) {
                const auto& t_os_hat_inv_mods_divs_modoj = t_os_hat_inv_mods_divs_modo[j];
                DoubleNativeInt cur_value{0};
                for (uint32_t i = 0; i < size_i; ++i) {
                    const NativeInteger& xi = vectors_[i + input_index][ri];
                    cur_value += mul128(xi.convert_to_int(), t_os_hat_inv_mods_divs_modoj[i].convert_to_int());
                }
                const NativeInteger& xi = vectors_[output_index + j][ri];
                cur_value += mul128(xi.convert_to_int(), t_os_hat_inv_mods_divs_modoj[size_i].convert_to_int());

                const NativeInteger& oj = params_output->get_params()[j]->get_modulus();
                auto&& cur_native_value = barrett_uint128_mod_uint64(cur_value, oj.convert_to_int(), modo_barret_mu[j]);

                auto cur_alpha{alpha};
                if (alpha >= oj)
                    cur_alpha = alpha.mod(oj, mu[j]);
                ans.vectors_[j][ri] = NativeInteger(cur_native_value).mod_add_fast(cur_alpha, oj);
            }
        } else {
            auto alpha = static_cast<DoubleNativeInt>(nu);
            for (uint32_t j = 0; j < size_o; ++j) {
                const auto& t_os_hat_inv_mods_divs_modoj = t_os_hat_inv_mods_divs_modo[j];
                DoubleNativeInt cur_value{0};
                for (uint32_t i = 0; i < size_i; ++i) {
                    const NativeInteger& xi = vectors_[i + input_index][ri];
                    cur_value += mul128(xi.convert_to_int(), t_os_hat_inv_mods_divs_modoj[i].convert_to_int());
                }
                const NativeInteger& xi = vectors_[output_index + j][ri];
                cur_value += mul128(xi.convert_to_int(), t_os_hat_inv_mods_divs_modoj[size_i].convert_to_int());

                const NativeInteger& oj = params_output->get_params()[j]->get_modulus();
                auto&& cur_native_value = barrett_uint128_mod_uint64(cur_value, oj.convert_to_int(), modo_barret_mu[j]);

                ans.vectors_[j][ri] =
                        NativeInteger(cur_native_value)
                                .mod_add_fast(barrett_uint128_mod_uint64(alpha, oj.convert_to_int(), modo_barret_mu[j]),
                                              oj);
            }
        }
#else
        if (is_convertable_to_native_int(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (uint32_t j = 0; j < size_o; ++j) {
                const auto& t_os_hat_inv_mods_divs_modoj = t_os_hat_inv_mods_divs_modo[j];
                const auto& oj = ans.vectors_[j].get_modulus();
                auto& cur_value = ans.vectors_[j][ri];
                for (uint32_t i = 0; i < size_i; i++) {
                    const auto& xi = vectors_[i + input_index][ri];
                    cur_value.mod_add_fast_eq(xi.mod_mul(t_os_hat_inv_mods_divs_modoj[i], oj, mu[j]), oj);
                }
                const auto& xi = vectors_[output_index + j][ri];
                cur_value.mod_add_fast_eq(xi.mod_mul(t_os_hat_inv_mods_divs_modoj[size_i], oj, mu[j]), oj);
                cur_value.mod_add_fast_eq(alpha >= oj ? alpha.mod(oj, mu[j]) : alpha, oj);
            }
        } else {
            int exp;
            double mant = std::frexp(nu, &exp);
            NativeInteger mantissa = static_cast<BasicInteger>(mant * (1ULL << 53));
            NativeInteger exponent = static_cast<BasicInteger>(1ULL << (exp - 53));
            for (uint32_t j = 0; j < size_o; j++) {
                const auto& t_os_hat_inv_mods_divs_modoj = t_os_hat_inv_mods_divs_modo[j];
                const auto& oj = ans.vectors_[j].get_modulus();
                auto& cur_value = ans.vectors_[j][ri];
                for (uint32_t i = 0; i < size_i; i++) {
                    const auto& xi = vectors_[i + input_index][ri];
                    cur_value.mod_add_fast_eq(xi.mod_mul(t_os_hat_inv_mods_divs_modoj[i], oj, mu[j]), oj);
                }
                const auto& xi = vectors_[output_index + j][ri];
                cur_value.mod_add_fast_eq(xi.mod_mul(t_os_hat_inv_mods_divs_modoj[size_i], oj, mu[j]), oj);
                cur_value.mod_add_fast_eq(exponent.mod_mul(mantissa, oj, mu[j]), oj);
            }
        }
#endif
    }
    return ans;
}

template <typename VecType>
typename RnsPolyImpl<VecType>::PolyType RnsPolyImpl<VecType>::scale_and_round(
        const std::vector<NativeInteger>& moduli_q, const NativeInteger& t, const NativeInteger& tgamma,
        const std::vector<NativeInteger>& tgamma_q_hat_modq, const std::vector<NativeInteger>& tgamma_q_hat_modq_precon,
        const std::vector<NativeInteger>& neg_invq_modtgamma,
        const std::vector<NativeInteger>& neg_invq_modtgamma_precon) const {
    constexpr uint64_t gamma_minus1 = (1 << 26) - 1;

    uint32_t ring_dim = params_->get_ring_dimension();
    uint32_t size_q = vectors_.size();
    RnsPolyImpl::PolyType::Vector coefficients(ring_dim, t.convert_to_int());

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(THREADS_CRT_BASIS_SWITCH))
    for (uint32_t k = 0; k < ring_dim; ++k) {
        // TODO: this accumulation is only correct when NativeInteger holds >= 64 bits:
        // it works mod tgamma = t*2^26 (intermediates < 2^58 per the note below), which does
        // not fit a 32-bit word for any t > 3 -- under NATIVE_SIZE=32 the NativeInteger
        // construction of tgamma truncates SILENTLY. Fix is to accumulate in uint64_t
        // regardless of the native word size, or to reject NATIVE_SIZE=32 here explicitly.
        NativeInteger s = 0;
        for (uint32_t i = 0; i < size_q; ++i) {
            // xi*t*gamma*(q/qi)^-1 mod qi
            // -tmp/qi mod gamma*t < 2^58
            const NativeInteger& qi = moduli_q[i];
            s.mod_add_fast_eq(vectors_[i][k]
                                      .mod_mul_fast_const(tgamma_q_hat_modq[i], qi, tgamma_q_hat_modq_precon[i])
                                      .mod_mul_fast_const(neg_invq_modtgamma[i], tgamma, neg_invq_modtgamma_precon[i]),
                              tgamma);
        }

        // Compute s + s & (gamma-1)
        s += NativeInteger(s.convert_to_int() & gamma_minus1);

        // shift by log(gamma) to get the result
        coefficients[k] = s >> 26;
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation
    // representation are performed after this
    RnsPolyImpl::PolyType result(
            std::make_shared<RnsPolyImpl::PolyType::Params>(params_->get_cyclotomic_order(), t.convert_to_int(), 1));
    result.set_values(std::move(coefficients), Format::COEFFICIENT);

    return result;
}

template <typename VecType>
void RnsPolyImpl<VecType>::scale_and_round_p_over_q(const std::shared_ptr<Params>& params_q,
                                                    const std::vector<NativeInteger>& p_inv_modq) {
    params_ = params_q;

    const uint32_t size_q = vectors_.size() - 1;
    const auto& last_poly = vectors_.back();

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_q))
    for (uint32_t i = 0; i < size_q; ++i) {
        auto tmp = last_poly;
        tmp.switch_modulus(vectors_[i].get_modulus(), vectors_[i].get_root_of_unity(), 0, 0);
        vectors_[i] -= tmp;
        vectors_[i] *= p_inv_modq[i];
    }
    vectors_.resize(size_q);
}

// Input: dcrtpoly in basis Q
// Output: dcrtpoly in base QBsk = {B U msk}
template <typename VecType>
void RnsPolyImpl<VecType>::fast_base_convq_to_bsk_montgomery(
        const std::shared_ptr<Params>& params_q_bsk, const std::vector<NativeInteger>& moduli_q,
        const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
        const std::vector<NativeInteger>& mtilde_q_hat_inv_modq,
        const std::vector<NativeInteger>& mtilde_q_hat_inv_modq_precon,
        const std::vector<std::vector<NativeInteger>>& q_hat_modbsk, const std::vector<uint64_t>& q_hat_modmtilde,
        const std::vector<NativeInteger>& q_modbsk, const std::vector<NativeInteger>& q_modbsk_precon,
        uint64_t neg_q_inv_modmtilde, const std::vector<NativeInteger>& mtilde_inv_modbsk,
        const std::vector<NativeInteger>& mtilde_inv_modbsk_precon) {
    constexpr uint64_t mtilde = (uint64_t)1 << 16;
    constexpr uint64_t mtilde_half = mtilde >> 1;
    constexpr uint64_t mtilde_minus_1 = mtilde - 1;

    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<RnsPolyImpl::PolyType> poly_in_ntt;
    if (format_ == Format::EVALUATION) {
        poly_in_ntt = vectors_;
        this->set_format(Format::COEFFICIENT);
    }

    params_ = params_q_bsk;
    uint32_t num_q(moduli_q.size());
    uint32_t num_bsk(moduli_bsk.size());
    uint32_t num_q_bsk(params_->get_params().size());
    uint32_t n(params_->get_ring_dimension());

    vectors_.reserve(num_q_bsk);
    for (uint32_t j = 0; j < num_bsk; ++j)
        vectors_.emplace_back(params_->get_params()[num_q + j], format_, true);

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(num_bsk);
    for (const auto& q : moduli_bsk)
        mu.push_back(q.compute_mu());

    // first we twist xi by mtilde*(q/qi)^-1 mod qi
    std::vector<NativeInteger> ximtilde_q_hat_modqi(n * num_q);
    std::vector<uint64_t> result_mtilde(n, 0);
    for (uint32_t i = 0; i < num_q; ++i) {
        const auto& mtilde_q_hat_inv_modqi = mtilde_q_hat_inv_modq[i];
        const auto& mtilde_q_hat_inv_modq_preconi = mtilde_q_hat_inv_modq_precon[i];
        const auto& q_hat_modmtildei = q_hat_modmtilde[i];
        for (uint32_t k = 0; k < n; ++k) {
            ximtilde_q_hat_modqi[i * n + k] = vectors_[i][k].mod_mul_fast_const(mtilde_q_hat_inv_modqi, moduli_q[i],
                                                                                mtilde_q_hat_inv_modq_preconi);
            result_mtilde[k] += ximtilde_q_hat_modqi[i * n + k].convert_to_int<uint64_t>() * q_hat_modmtildei;
        }
    }
    for (uint32_t k = 0; k < n; ++k) {
        result_mtilde[k] &= mtilde_minus_1;
        result_mtilde[k] *= neg_q_inv_modmtilde;
        result_mtilde[k] &= mtilde_minus_1;
    }

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_bsk))
    for (uint32_t j = 0; j < num_bsk; ++j) {
        const auto& moduli_bskj = moduli_bsk[j];
        const auto& mtilde_inv_modbskj = mtilde_inv_modbsk[j];
        const auto& mtilde_inv_modbsk_preconj = mtilde_inv_modbsk_precon[j];
        const auto& q_mod_bskj = q_modbsk[j];
        const auto& q_mod_bskj_precon = q_modbsk_precon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < num_q; ++i)
                result += mul128(ximtilde_q_hat_modqi[i * n + k].convert_to_int<uint64_t>(),
                                 q_hat_modbsk[i][j].convert_to_int<uint64_t>());
            vectors_[num_q + j][k] =
                    barrett_uint128_mod_uint64(result, moduli_bskj.convert_to_int(), modbsk_barrett_mu[j]);
#else
            for (uint32_t i = 0; i < num_q; ++i)
                vectors_[num_q + j][k].mod_add_fast_eq(
                        ximtilde_q_hat_modqi[i * n + k].mod_mul(q_hat_modbsk[i][j], moduli_bskj, mu[j]), moduli_bskj);
#endif
            NativeInteger r_m_tilde(result_mtilde[k]);  // mtilde = 2^16 < all moduli of Bsk
            if (result_mtilde[k] >= mtilde_half)
                r_m_tilde += moduli_bskj - mtilde;                                        // centred remainder
            r_m_tilde.mod_mul_fast_const_eq(q_mod_bskj, moduli_bskj, q_mod_bskj_precon);  // (r_mtilde) * q mod Bski
            r_m_tilde.mod_add_fast_eq(vectors_[num_q + j][k], moduli_bskj);  // (c``_m + (r_mtilde* q)) mod Bski
            vectors_[num_q + j][k] =
                    r_m_tilde.mod_mul_fast_const(mtilde_inv_modbskj, moduli_bskj, mtilde_inv_modbsk_preconj);
        }
        vectors_[num_q + j].set_format(Format::EVALUATION);
    }

    format_ = Format::EVALUATION;
    if (poly_in_ntt.size() > 0) {
        // if input polynomial was in evaluation representation, use towers for Q from it
        std::move(poly_in_ntt.begin(), poly_in_ntt.end(), vectors_.begin());
    } else {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_q))
        for (uint32_t i = 0; i < num_q; ++i)
            vectors_[i].set_format(Format::EVALUATION);
    }
}

// Input: poly in basis {q U Bsk}
// Output: approximateFloor(t/q*poly) in basis Bsk
template <typename VecType>
void RnsPolyImpl<VecType>::fast_rns_floorq(const NativeInteger& t, const std::vector<NativeInteger>& moduli_q,
                                           const std::vector<NativeInteger>& moduli_bsk,
                                           const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
                                           const std::vector<NativeInteger>& t_q_hat_inv_modq,
                                           const std::vector<NativeInteger>& t_q_hat_inv_modq_precon,
                                           const std::vector<std::vector<NativeInteger>>& q_hat_modbsk,
                                           const std::vector<std::vector<NativeInteger>>& q_inv_modbsk,
                                           const std::vector<NativeInteger>& t_q_inv_modbsk,
                                           const std::vector<NativeInteger>& t_q_inv_modbsk_precon) {
    uint32_t num_q(moduli_q.size());
    uint32_t num_bsk(moduli_bsk.size());
    uint32_t n(params_->get_ring_dimension());

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(num_bsk);
    for (const auto& q : moduli_bsk)
        mu.push_back(q.compute_mu());

    // Twist xi by t*(q/qi)^-1 mod qi
    for (uint32_t i = 0; i < num_q; ++i) {
        const auto& tq_divqi_modqi = t_q_hat_inv_modq[i];
        const auto& tq_divqi_modqi_precon = t_q_hat_inv_modq_precon[i];
        const auto& moduli_qi = moduli_q[i];
        for (uint32_t k = 0; k < n; ++k)
            vectors_[i][k].mod_mul_fast_const_eq(tq_divqi_modqi, moduli_qi, tq_divqi_modqi_precon);
    }

    std::vector<NativeInteger> txiqi_divq_modqi(n * num_bsk);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_bsk))
    for (uint32_t j = 0; j < num_bsk; ++j) {
        const auto& moduli_bskj = moduli_bsk[j];
        const auto& t_divq_mod_bskj = t_q_inv_modbsk[j];
        const auto& t_divq_mod_bskj_precon = t_q_inv_modbsk_precon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
            DoubleNativeInt aq = 0;
            for (uint32_t i = 0; i < num_q; ++i) {
                const auto& xi = vectors_[i][k];
                aq += mul128(xi.template convert_to_int<uint64_t>(), q_inv_modbsk[i][j].convert_to_int<uint64_t>());
            }
            txiqi_divq_modqi[j * n + k] =
                    barrett_uint128_mod_uint64(aq, moduli_bskj.convert_to_int(), modbsk_barrett_mu[j]);
#else
            for (uint32_t i = 0; i < num_q; ++i) {
                const auto& xi = vectors_[i][k];
                txiqi_divq_modqi[j * n + k].mod_add_fast_eq(xi.mod_mul(q_inv_modbsk[i][j], moduli_bskj, mu[j]),
                                                            moduli_bskj);
            }
#endif
            // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqi_divq_modqi
            vectors_[num_q + j][k].mod_mul_fast_const_eq(t_divq_mod_bskj, moduli_bskj, t_divq_mod_bskj_precon);
            vectors_[num_q + j][k].mod_sub_fast_eq(txiqi_divq_modqi[j * n + k], moduli_bskj);
        }
    }
}

// Input: poly in basis Bsk
// Output: poly in basis q
template <typename VecType>
void RnsPolyImpl<VecType>::fast_base_conv_sk(
        const std::shared_ptr<Params>& params_q, const std::vector<DoubleNativeInt>& modq_barrett_mu,
        const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
        const std::vector<NativeInteger>& b_hat_inv_modb, const std::vector<NativeInteger>& b_hat_inv_modb_precon,
        const std::vector<NativeInteger>& b_hat_modmsk, const NativeInteger& b_inv_modmsk,
        const NativeInteger& b_inv_modmsk_precon, const std::vector<std::vector<NativeInteger>>& b_hat_modq,
        const std::vector<NativeInteger>& b_modq, const std::vector<NativeInteger>& b_modq_precon) {
    uint32_t size_q(params_q->get_params().size());

    std::vector<NativeInteger> moduli_q;
    moduli_q.reserve(size_q);

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(size_q);

    for (const auto& p : params_q->get_params()) {
        moduli_q.push_back(p->get_modulus());
        mu.push_back(p->get_modulus().compute_mu());
    }

    uint32_t size_bsk(moduli_bsk.size());
    uint32_t size_bskm1(size_bsk - 1);
    uint32_t n(params_->get_ring_dimension());

    std::vector<NativeInteger> alphaskx_vector(n, 0);
    [[maybe_unused]] NativeInteger mu_bsk(moduli_bsk[size_bskm1].compute_mu());
    NativeInteger msk_div_two(moduli_bsk[size_bskm1] >> 1);

    for (uint32_t i = 0; i < size_bskm1; i++) {  // exclude msk residue
        const auto& moduli_bski = moduli_bsk[i];
        const auto& b_hat_modmski = b_hat_modmsk[i];
        const auto& b_div_bi_mod_bi = b_hat_inv_modb[i];
        const auto& b_div_bi_mod_bi_precon = b_hat_inv_modb_precon[i];
        for (uint32_t k = 0; k < n; ++k) {
            vectors_[size_q + i][k].mod_mul_fast_const_eq(b_div_bi_mod_bi, moduli_bski, b_div_bi_mod_bi_precon);
            alphaskx_vector[k].mod_add_fast_eq(
                    vectors_[size_q + i][k].mod_mul(b_hat_modmski, moduli_bsk[size_bskm1], mu_bsk),
                    moduli_bsk[size_bskm1]);
        }
    }
    for (uint32_t k = 0; k < n; ++k) {
        alphaskx_vector[k] = alphaskx_vector[k].mod_sub_fast(vectors_[size_q + size_bskm1][k], moduli_bsk[size_bskm1]);
        alphaskx_vector[k].mod_mul_fast_const_eq(b_inv_modmsk, moduli_bsk[size_bskm1], b_inv_modmsk_precon);
    }

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_q))
    for (uint32_t j = 0; j < size_q; ++j) {
        const auto& moduli_qj = moduli_q[j];
        const auto& b_modqj = b_modq[j];
        const auto& b_modqj_precon = b_modq_precon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < size_bskm1; ++i) {  // exclude msk residue
                const auto& xi = vectors_[size_q + i][k];
                result += mul128(xi.template convert_to_int<uint64_t>(), b_hat_modq[i][j].convert_to_int<uint64_t>());
            }
            vectors_[j][k] = barrett_uint128_mod_uint64(result, moduli_qj.convert_to_int(), modq_barrett_mu[j]);
#else
            NativeInteger result(0);
            for (uint32_t i = 0; i < size_bskm1; ++i) {  // exclude msk residue
                const auto& xi = vectors_[size_q + i][k];
                result.mod_add_fast_eq(xi.mod_mul(b_hat_modq[i][j], moduli_qj, mu[j]), moduli_q[j]);
            }
            vectors_[j][k] = result;
#endif
            // do (m_vector - alphaskx*M) mod q
            NativeInteger alphask_b_modqj = alphaskx_vector[k];
            if (alphask_b_modqj > msk_div_two)
                alphask_b_modqj = alphask_b_modqj.mod_sub_fast(moduli_bsk[size_bskm1], moduli_q[j]);
            alphask_b_modqj.mod_mul_fast_const_eq(b_modqj, moduli_q[j], b_modqj_precon);
            vectors_[j][k] = vectors_[j][k].mod_sub_fast(alphask_b_modqj, moduli_q[j]);
        }
    }

    params_ = params_q;

    // drop extra vectors
    if (size_q < vectors_.size()) {
        auto starti = vectors_.begin() + size_q;
        if (starti + size_bsk >= vectors_.end())
            vectors_.erase(starti, vectors_.end());
        else
            vectors_.erase(starti, starti + size_bsk);
    }
}

template <typename VecType>
void RnsPolyImpl<VecType>::switch_format(uint32_t thread_limit) {
    format_ = (format_ == Format::COEFFICIENT) ? Format::EVALUATION : Format::COEFFICIENT;

    const uint32_t size = vectors_.size();
    if (ParallelControls::in_parallel_region()) {
        for (uint32_t i = 0; i < size; ++i)
            vectors_[i].switch_format();
        return;
    }
    [[maybe_unused]] const uint32_t limit = thread_limit ? thread_limit : size;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
    for (uint32_t i = 0; i < size; ++i)
        vectors_[i].switch_format();
}

template <typename VecType>
void RnsPolyImpl<VecType>::switch_modulus_at_index(size_t index, const Integer& modulus,
                                                   const Integer& root_of_unity_value) {
    if (index >= vectors_.size())
        CIPHER_THROW("Index out of range");
    vectors_[index].switch_modulus(PolyType::Integer(modulus.convert_to_int()),
                                   PolyType::Integer(root_of_unity_value.convert_to_int()), 0, 0);
    // params_ may be shared with other elements, so the updated tower goes into a copy
    auto new_p = std::make_shared<Params>(*params_);
    (*new_p)[index] = vectors_[index].get_params();
    new_p->recalculate_modulus();
    params_ = std::move(new_p);
}

template <typename VecType>
bool RnsPolyImpl<VecType>::inverse_exists() const {
    for (const auto& v : vectors_) {
        if (!v.inverse_exists())
            return false;
    }
    return true;
}

/**
 * @brief Writes every tower of a double-CRT polynomial to an output stream, one after another.
 *
 * @param os the output stream.
 * @param p the double-CRT polynomial to print.
 * @return the output stream.
 */
template <typename VecType>
std::ostream& operator<<(std::ostream& os, const RnsPolyImpl<VecType>& p) {
    // TODO(gryan): Standardize this printing so it is like other poly's
    os << "---START PRINT DOUBLE CRT-- WITH SIZE" << p.vectors_.size() << std::endl;
    for (uint32_t i = 0; i < p.vectors_.size(); i++) {
        os << "VECTOR " << i << std::endl;
        os << p.vectors_[i];
    }
    os << "---END PRINT DOUBLE CRT--" << std::endl;
    return os;
}

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_STANDARD_RNS_POLY_IMPL_H_
