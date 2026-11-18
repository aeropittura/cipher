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

#include "cipher/boolean/rgsw_acc_key32.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/util/exception.h"

namespace cipher {

#if CIPHER_NATIVE_INT != 32

bool RingGswAccKey32Impl::fits(const RingGswCryptoParams& params) {
    auto method = params.get_method();
    if (method != BINFHE_METHOD::GINX && method != BINFHE_METHOD::AP && method != BINFHE_METHOD::LMKCDEY)
        return false;
    if (params.get_Q().get_msb() > MAX_MODULUS_SIZE32)
        return false;
    uint64_t Q{params.get_Q().convert_to_int<uint64_t>()};
    auto ok = [Q](const RingGswCryptoParams::BaseGParams& bp) {
        // excess-H headroom: the biased value must stay inside a 32-bit word
        if (bp.digits_g * bp.g_bits + 1 > 32)
            return false;
        // uint64 headroom for the lazy inner product: digits_g2 * (Q-1)^2 < 2^64
        uint64_t d2{static_cast<uint64_t>((bp.digits_g - 1) << 1)};
        return d2 <= static_cast<uint64_t>(-1) / ((Q - 1) * (Q - 1));
    };
    const auto& by_index = params.get_base_g_by_index();
    if (by_index.empty())
        return ok(params.get_default_base_g_params());
    for (const auto& bp : by_index)
        if (!ok(bp))
            return false;
    // the LMKCDEY automorphism key switch uses the default base regardless of the per-index map
    if (method == BINFHE_METHOD::LMKCDEY && !ok(params.get_default_base_g_params()))
        return false;
    return true;
}

RingGswAccKey32Impl::RingGswAccKey32Impl(const std::shared_ptr<RingGswCryptoParams>& params,
                                         const RingGswAccKeyImpl& ek) {
    const auto& src = ek.get_elements();
    if (src.empty() || src[0].empty() || src[0][0].empty())
        CIPHER_THROW("RingGSWACCKey32Impl: empty accumulator key");
    init(params);
    key_.assign(src.size(),
                 std::vector<std::vector<EvalKey32>>(src[0].size(), std::vector<EvalKey32>(src[0][0].size())));
    for (size_t i = 0; i < src.size(); ++i)
        for (size_t j = 0; j < src[i].size(); ++j)
            for (size_t k = 0; k < src[i][j].size(); ++k)
                if (src[i][j][k] != nullptr)
                    set_eval_key(i, j, k, *src[i][j][k]);
}

RingGswAccKey32Impl::RingGswAccKey32Impl(const std::shared_ptr<RingGswCryptoParams>& params, uint32_t d1, uint32_t d2,
                                         uint32_t d3) {
    init(params);
    key_.assign(d1, std::vector<std::vector<EvalKey32>>(d2, std::vector<EvalKey32>(d3)));
}

// shared setup for both constructors
void RingGswAccKey32Impl::init(const std::shared_ptr<RingGswCryptoParams>& params) {
    if (!fits(*params))
        CIPHER_THROW("parameters do not qualify for the 32-bit internal path");

    N_ = params->get_N();
    poly_params_ = params->get_poly_params32();
    // force the lazy monomial build now: construction is single-threaded, gates may not be
    if (params->get_method() == BINFHE_METHOD::GINX)
        params->get_monomials_precon32();
}

void RingGswAccKey32Impl::set_eval_key(uint32_t i, uint32_t j, uint32_t k, const RingGswEvalKeyImpl& ek) {
    const auto& el = ek.get_elements();
    auto& dst = key_[i][j][k];
    dst.resize(el.size());
    for (size_t d = 0; d < el.size(); ++d) {
        dst[d].clear();
        dst[d].reserve(el[d].size());
        for (size_t col = 0; col < el[d].size(); ++col)
            dst[d].push_back(narrow_poly32(el[d][col], poly_params_));
    }
}

RingGswAccKey RingGswAccKey32Impl::widen(const std::shared_ptr<RingGswCryptoParams>& params) const {
    const auto& poly_params = params->get_poly_params();
    auto ek = std::make_shared<RingGswAccKeyImpl>(key_.size(), key_[0].size(), key_[0][0].size());
    for (size_t i = 0; i < key_.size(); ++i) {
        for (size_t j = 0; j < key_[i].size(); ++j) {
            for (size_t k = 0; k < key_[i][j].size(); ++k) {
                const auto& src = key_[i][j][k];
                if (src.empty())
                    continue;
                auto dst = std::make_shared<RingGswEvalKeyImpl>(static_cast<uint32_t>(src.size()), 2);
                for (size_t d = 0; d < src.size(); ++d) {
                    for (size_t col = 0; col < src[d].size(); ++col) {
                        NativePoly p(poly_params, src[d][col].get_format(), true);
                        widen_poly32_into(src[d][col], p);
                        (*dst)[d][col] = std::move(p);
                    }
                }
                (*ek)[i][j][k] = std::move(dst);
            }
        }
    }
    return ek;
}

uint64_t RingGswAccKey32Impl::key_bytes() const {
    uint64_t polys = 0;
    for (const auto& i : key_)
        for (const auto& j : i)
            for (const auto& k : j)
                for (const auto& d : k)
                    polys += d.size();
    return polys * static_cast<uint64_t>(N_) * sizeof(uint32_t);
}

#endif  // CIPHER_NATIVE_INT != 32

}  // namespace cipher
