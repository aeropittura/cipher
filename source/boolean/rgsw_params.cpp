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

#include "cipher/boolean/rgsw_params.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace cipher {

const std::vector<NativeInteger>& RingGswCryptoParams::precompute_g_power(uint32_t base_g) {
    auto it = gpower_map_.find(base_g);
    if (it != gpower_map_.end())
        return it->second;

    auto digits_g{digits_for_base(Q_, base_g)};
    NativeInteger v_temp{1};
    std::vector<NativeInteger> tempvec(digits_g);
    for (uint32_t i = 0; i < digits_g; ++i) {
        tempvec[i] = v_temp;
        v_temp = v_temp.mod_mul_fast(NativeInteger(base_g), Q_);
    }
    return gpower_map_.emplace(base_g, std::move(tempvec)).first->second;
}

void RingGswCryptoParams::pre_compute(bool sign_eval) {
    // Computes base_r^i (only for AP bootstrapping)
    if (method_ == BINFHE_METHOD::AP) {
        auto digit_count_r{get_digit_count(q_.convert_to_int(), base_r_)};
        digits_r_.clear();
        digits_r_.reserve(digit_count_r);
        BasicInteger value{1};
        for (size_t i = 0; i < digit_count_r; ++i, value *= base_r_)
            digits_r_.emplace_back(value);
    }

    // Computes base_g^i. The context's own base is always precomputed: sign evaluation adds
    // the three bases change_base_g switches between, it does not replace the base in use.
    precompute_g_power(base_g_);
    for (const auto& item : base_g_map_)
        precompute_g_power(item.first);
    if (sign_eval) {
        for (uint32_t base_g : {1 << 14, 1 << 18, 1 << 27})
            precompute_g_power(base_g);
    }
    gpower_ = gpower_map_.at(base_g_);

    // Sets the gate constants for supported binary operations
    gate_const_ = {
            NativeInteger(5) * (q_ >> 3),   // OR
            NativeInteger(7) * (q_ >> 3),   // AND
            NativeInteger(1) * (q_ >> 3),   // NOR
            NativeInteger(3) * (q_ >> 3),   // NAND
            NativeInteger(6) * (q_ >> 3),   // XOR
            NativeInteger(2) * (q_ >> 3),   // XNOR
            NativeInteger(7) * (q_ >> 3),   // MAJORITY
            NativeInteger(11) * (q_ / 12),  // AND3
            NativeInteger(7) * (q_ / 12),   // OR3
            NativeInteger(15) * (q_ >> 4),  // AND4
            NativeInteger(9) * (q_ >> 4),   // OR4
            NativeInteger(6) * (q_ >> 3),   // XOR_FAST
            NativeInteger(2) * (q_ >> 3)    // XNOR_FAST
    };

    // Computes polynomials X^m - 1 that are needed in the accumulator for the
    // CGGI bootstrapping
    if (method_ == BINFHE_METHOD::GINX)
        build_monomials();

    // expand the base map into one entry per LWE index. Digit counts are computed here,
    // once per distinct base, instead of per call in the accumulator.
    base_g_by_index_.clear();
    if (!base_g_map_.empty()) {
        uint32_t total{0};
        for (const auto& [base_g, count] : base_g_map_)
            total += count;
        base_g_by_index_.reserve(total);
        team_width_ = (digits_g_ - 1) << 1;
        for (const auto& [base_g, count] : base_g_map_)
            team_width_ = std::max(team_width_, (digits_for_base(Q_, base_g) - 1) << 1);
        for (const auto& [base_g, count] : base_g_map_) {
            auto it = gpower_map_.find(base_g);
            if (it == gpower_map_.end())
                CIPHER_THROW("No GPower found for the requested gadget base.");
            base_g_by_index_.insert(
                    base_g_by_index_.end(), count,
                    BaseGParams{base_g, digits_for_base(Q_, base_g), get_msb(base_g) - 1, &it->second, team_width_});
        }
    }

    if (method_ == LMKCDEY) {
        constexpr uint32_t gen{5};
        log_gen_.clear();
        uint32_t M{2 * N_};
        log_gen_.resize(M);
        uint32_t g_pow{1};
        log_gen_[M - g_pow] = M;  // for -1
        for (uint32_t i = 1; i < N_ / 2; ++i) {
            g_pow = (g_pow * gen) % M;
            log_gen_[g_pow] = i;
            log_gen_[M - g_pow] = -i;
        }

        // eval_acc only ever rotates by gen^k for k in [1, num_auto_keys] and by M - gen
        auto_map_.clear();
        auto add_map = [this](uint32_t idx) {
            auto& v = auto_map_[idx];
            v.resize(N_);
            precompute_auto_map(N_, idx, &v);
        };
        add_map(M - gen);
        uint32_t idx{1};
        for (uint32_t k = 1; k <= num_auto_keys_; ++k) {
            idx = (idx * gen) % M;
            add_map(idx);
        }
    }
}

#if CIPHER_NATIVE_INT != 32
const std::shared_ptr<NativePolyParams32>& RingGswCryptoParams::get_poly_params32() {
    if (poly_params32_ == nullptr) {
        poly_params32_ = std::make_shared<NativePolyParams32>(
                2 * N_, NativeInteger32(Q_.convert_to_int<uint32_t>()),
                NativeInteger32(poly_params_->get_root_of_unity().convert_to_int<uint32_t>()));
    }
    return poly_params32_;
}

const std::shared_ptr<const std::vector<NativePoly32>>& RingGswCryptoParams::get_monomials32() {
    if (monomials32_ == nullptr) {
        const auto& pp = get_poly_params32();
        // X^m - 1 built natively at 32 bits: the NTT mod Q is width-independent, so the table is
        // identical to narrowing the 64-bit one, which therefore need not exist
        NativeInteger32 Q32(Q_.convert_to_int<uint32_t>());
        constexpr NativeInteger32 one{1};
        auto monomials = std::make_shared<std::vector<NativePoly32>>();
        monomials->reserve(2 * N_);
        for (uint32_t i = 0; i < 2 * N_; ++i) {
            NativePoly32 a_poly(pp, Format::COEFFICIENT, true);
            a_poly[0].mod_sub_fast_eq(one, Q32);  // -1
            if (i < N_)
                a_poly[i].mod_add_fast_eq(one, Q32);  // X^m
            else
                a_poly[i - N_].mod_sub_fast_eq(one, Q32);  // -X^m
            a_poly.set_format(Format::EVALUATION);
            monomials->push_back(std::move(a_poly));
        }
        monomials32_ = std::move(monomials);
    }
    return monomials32_;
}

const std::shared_ptr<const std::vector<NativeVector32>>& RingGswCryptoParams::get_monomials_precon32() {
    if (monomials_precon32_ == nullptr) {
        const auto& monomials = *get_monomials32();
        NativeInteger32 Q32(Q_.convert_to_int<uint32_t>());
        auto precon = std::make_shared<std::vector<NativeVector32>>();
        precon->reserve(monomials.size());
        for (const auto& m : monomials) {
            const auto& mv = m.get_values();
            NativeVector32 p(mv.get_length(), Q32);
            for (size_t k = 0; k < mv.get_length(); ++k)
                p[k] = mv[k].prep_mod_mul_const(Q32);
            precon->push_back(std::move(p));
        }
        monomials_precon32_ = std::move(precon);
    }
    return monomials_precon32_;
}
#endif  // CIPHER_NATIVE_INT != 32

void RingGswCryptoParams::build_monomials() {
    constexpr NativeInteger one{1};
    monomials_.clear();
    monomials_.reserve(2 * N_);
    for (uint32_t i = 0; i < N_; ++i) {
        NativePoly a_poly(poly_params_, Format::COEFFICIENT, true);
        a_poly[0].mod_sub_fast_eq(one, Q_);  // -1
        a_poly[i].mod_add_fast_eq(one, Q_);  // X^m
        a_poly.set_format(Format::EVALUATION);
        monomials_.push_back(std::move(a_poly));
    }
    for (uint32_t i = 0; i < N_; ++i) {
        NativePoly a_poly(poly_params_, Format::COEFFICIENT, true);
        a_poly[0].mod_sub_fast_eq(one, Q_);  // -1
        a_poly[i].mod_sub_fast_eq(one, Q_);  // -X^m
        a_poly.set_format(Format::EVALUATION);
        monomials_.push_back(std::move(a_poly));
    }
}

};  // namespace cipher
