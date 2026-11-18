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

#include <algorithm>
#include <complex>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/config.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/math/hermite.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/utils.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/fhe/schemelet/rlwe_mp.h"

using namespace cipher;

struct fbt_config {
    SecretKeyDist skd;
    ScalingTechnique scal_tech;
    BigInteger qbfv_init;
    BigInteger p_input;
    BigInteger p_output;
    BigInteger Q;
    BigInteger bigq;
    double scale_thi;
    double scale_step_thi;
    size_t order;
    uint32_t num_slots;
    uint32_t ring_dim;
    uint32_t dnum;
    std::vector<uint32_t> lvlb;
};

[[maybe_unused]] const BigInteger Q1(BigInteger(1) << 1);
[[maybe_unused]] const BigInteger Q2(BigInteger(1) << 2);
[[maybe_unused]] const BigInteger Q4(BigInteger(1) << 4);
[[maybe_unused]] const BigInteger Q8(BigInteger(1) << 8);
[[maybe_unused]] const BigInteger Q12(BigInteger(1) << 12);
[[maybe_unused]] const BigInteger Q24(BigInteger(1) << 24);
[[maybe_unused]] const BigInteger Q27(BigInteger(1) << 27);
[[maybe_unused]] const BigInteger Q32(BigInteger(1) << 32);
[[maybe_unused]] const BigInteger Q33(BigInteger(1) << 33);
[[maybe_unused]] const BigInteger Q35(BigInteger(1) << 35);
[[maybe_unused]] const BigInteger Q38(BigInteger(1) << 38);
[[maybe_unused]] const BigInteger Q46(BigInteger(1) << 46);
[[maybe_unused]] const BigInteger Q47(BigInteger(1) << 47);
[[maybe_unused]] const BigInteger Q55(BigInteger(1) << 55);
[[maybe_unused]] const BigInteger Q60(BigInteger(1) << 60);
[[maybe_unused]] const BigInteger Q71(BigInteger(1) << 71);
[[maybe_unused]] const BigInteger Q80(BigInteger(1) << 80);

// clang-format off
[[maybe_unused]] constexpr SecretKeyDist    SE = SPARSE_ENCAPSULATED;
[[maybe_unused]] constexpr ScalingTechnique FM = FIXEDMANUAL;
[[maybe_unused]] constexpr ScalingTechnique FA = FLEXIBLEAUTO;

// Keyed by (log p, scaling technique). The order-1 rows for 1, 2, 4 and 8 bits use the smallest scaling factor (Q)
// whose FBT output error stays below Q/(2p) with probability 2^-40 per ciphertext, measured over all N coefficients
// on inputs covering every residue of p. Ring dimensions and dnum keep log(Q'_L P') within the 128-bit limits of
// AKP25 Table 1 for sparse secrets (767 / 1553 bits at N = 2^15 / 2^16).
// UNIFORM_TERNARY rows are left out until subring secret encapsulation (eprint 2025/1594) is implemented.
[[maybe_unused]] std::map<std::pair<uint32_t, ScalingTechnique>, fbt_config> arblut_configs = {
    // {log p, scal_tech}, {skd, scal_tech, qbfv_init, p_input, p_output, Q, Bigq, scale_thi, scale_step_thi, order,
    //                     num_slots, ring_dim, dnum, lvlBudget}
    {{1, FM},  {SE, FM, Q60,  Q1,  Q1, Q33, Q33,    1.0,  1.0, 1, 1 << 15, 1 << 15, 4, {3, 3}}},
    {{1, FA},  {SE, FA, Q60,  Q1,  Q1, Q24, Q24,    1.0,  1.0, 1, 1 << 15, 1 << 15, 2, {3, 3}}},
    {{2, FM},  {SE, FM, Q60,  Q2,  Q2, Q32, Q32,   16.0,  1.0, 1, 1 << 15, 1 << 15, 4, {2, 2}}},
    {{2, FA},  {SE, FA, Q60,  Q2,  Q2, Q24, Q24,   16.0,  1.0, 1, 1 << 15, 1 << 15, 3, {3, 3}}},
    {{4, FM},  {SE, FM, Q60,  Q4,  Q4, Q38, Q38,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {4, 4}}},
    {{4, FA},  {SE, FA, Q60,  Q4,  Q4, Q27, Q27,   32.0,  1.0, 1, 1 << 15, 1 << 15, 4, {3, 3}}},
    {{8, FM},  {SE, FM, Q60,  Q8,  Q8, Q46, Q46,   32.0,  1.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}},
    {{8, FA},  {SE, FA, Q60,  Q8,  Q8, Q35, Q35,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {3, 3}}},
    {{12, FM}, {SE, FM, Q80, Q12, Q12, Q55, Q55, 2000.0,  1.0, 1, 1 << 17, 1 << 17, 3, {4, 4}}},
    {{32, FM}, {SE, FM, Q80, Q32,  Q4, Q71, Q47,  256.0, 16.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}}
};
// clang-format on

[[maybe_unused]] static void arb_lut_bits_fm(benchmark::internal::Benchmark* b) {
    for (uint32_t bits : {12, 8, 4, 2, 1})
        b->ArgName("bits")->Arg(bits);
}

[[maybe_unused]] static void arb_lut_bits_fa(benchmark::internal::Benchmark* b) {
    for (uint32_t bits : {8, 4, 2, 1})
        b->ArgName("bits")->Arg(bits);
}

[[maybe_unused]] static void fbt_setup(benchmark::State& state) {
    auto t = arblut_configs[{12, FM}];

    bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing

    auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

    auto a = t.p_input.convert_to_int<int64_t>();
    auto b = t.p_output.convert_to_int<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.p_input.convert_to_int<int64_t>() / 2), (t.p_input.convert_to_int<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.p_input.convert_to_int<int64_t>() - 1)};
    if (x.size() < t.num_slots)
        x = Fill<int64_t>(x, t.num_slots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
    if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

    uint32_t dcrt_bits = t.bigq.get_msb() - 1;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(t.skd);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(t.scal_tech);
    parameters.set_first_mod_size(dcrt_bits);
    parameters.set_num_large_digits(t.dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(t.ring_dim);

    uint32_t depth = 0;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd);
    else
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    auto key_pair = cc->key_gen();

    while (state.KeepRunning()) {
        if (binary_lut)
            cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                               t.lvlb, 0, 0, t.order);
        else
            cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                               t.lvlb, 0, 0, t.order);
    }

    cc->clear_static_maps_and_vectors();
}

[[maybe_unused]] static void fbt_key_gen(benchmark::State& state) {
    auto t = arblut_configs[{12, FM}];

    bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing

    auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

    auto a = t.p_input.convert_to_int<int64_t>();
    auto b = t.p_output.convert_to_int<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.p_input.convert_to_int<int64_t>() / 2), (t.p_input.convert_to_int<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.p_input.convert_to_int<int64_t>() - 1)};
    if (x.size() < t.num_slots)
        x = Fill<int64_t>(x, t.num_slots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
    if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

    uint32_t dcrt_bits = t.bigq.get_msb() - 1;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(t.skd);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(t.scal_tech);
    parameters.set_first_mod_size(dcrt_bits);
    parameters.set_num_large_digits(t.dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(t.ring_dim);

    uint32_t depth = 0;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd);
    else
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    auto key_pair = cc->key_gen();

    if (binary_lut)
        cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                           0, 0, t.order);
    else
        cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                           t.lvlb, 0, 0, t.order);

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
        CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
        state.ResumeTiming();
        cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
        cc->eval_mult_key_gen(key_pair.secret_key);
    }

    cc->clear_static_maps_and_vectors();
}

[[maybe_unused]] static void fbt_arb_lut(benchmark::State& state, ScalingTechnique scal_tech) {
    auto t = arblut_configs[{static_cast<uint32_t>(state.range(0)), scal_tech}];

    bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing

    auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

    auto a = t.p_input.convert_to_int<int64_t>();
    auto b = t.p_output.convert_to_int<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.p_input.convert_to_int<int64_t>() / 2), (t.p_input.convert_to_int<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.p_input.convert_to_int<int64_t>() - 1)};
    if (x.size() < t.num_slots)
        x = Fill<int64_t>(x, t.num_slots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
    if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

    uint32_t dcrt_bits = t.bigq.get_msb() - 1;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(t.skd);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(t.scal_tech);
    parameters.set_first_mod_size(dcrt_bits);
    parameters.set_num_large_digits(t.dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(t.ring_dim);

    uint32_t depth = 0;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd);
    else
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    auto key_pair = cc->key_gen();

    if (binary_lut)
        cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                           0, 0, t.order);
    else
        cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                           t.lvlb, 0, 0, t.order);

    cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
    cc->eval_mult_key_gen(key_pair.secret_key);

    auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth);

    auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

    SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

    auto ctxt =
            SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks, depth);

    while (state.KeepRunning()) {
        Ciphertext<RnsPoly> ctxt_after_fbt;
        if (binary_lut)
            ctxt_after_fbt =
                    cc->eval_fbt(ctxt, coeffint, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0, t.order);
        else
            ctxt_after_fbt =
                    cc->eval_fbt(ctxt, coeffcomp, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0, t.order);
        ctxt_after_fbt.reset();
    }

    cc->clear_static_maps_and_vectors();
}

[[maybe_unused]] static void fbt_sign_digit32(benchmark::State& state) {
    auto t = arblut_configs[{32, FM}];

    bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing

    auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

    auto a = t.p_input.convert_to_int<int64_t>();
    auto b = t.p_output.convert_to_int<int64_t>();

    auto func_mod = [b](int64_t x) -> int64_t {
        return (x % b);
    };
    auto func_step = [a, b](int64_t x) -> int64_t {
        return (x % a) >= (b / 2);
    };

    std::vector<int64_t> x = {
            t.p_input.convert_to_int<int64_t>() / 2, t.p_input.convert_to_int<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
            t.p_input.convert_to_int<int64_t>() - 1};
    if (x.size() < t.num_slots)
        x = Fill<int64_t>(x, t.num_slots);

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(),
                   [&](int64_t elem) { return (elem >= t.p_input.convert_to_double() / 2.); });

    std::vector<int64_t> coeffint_mod;
    std::vector<std::complex<double>> coeffcomp_mod;
    std::vector<std::complex<double>> coeffcomp_step;
    bool binary_lut = (t.p_output.convert_to_int() == 2) && (t.order == 1);
    if (binary_lut) {
        coeffint_mod = {func_mod(1), func_mod(0) - func_mod(1)};  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
    } else {
        coeffcomp_mod = get_hermite_trig_coefficients(func_mod, t.p_output.convert_to_int(), t.order,
                                                      t.scale_thi);  // divided by 2
        coeffcomp_step = get_hermite_trig_coefficients(func_step, t.p_output.convert_to_int(), t.order,
                                                       t.scale_step_thi);  // divided by 2
    }

    uint32_t dcrt_bits = t.bigq.get_msb() - 1;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(t.skd);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(t.scal_tech);
    parameters.set_first_mod_size(dcrt_bits);
    parameters.set_num_large_digits(t.dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(t.ring_dim);

    uint32_t depth = 0;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint_mod, t.p_input, t.order, t.skd);
    else
        depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp_mod, t.p_input, t.order, t.skd);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    auto key_pair = cc->key_gen();

    if (binary_lut)
        cc->eval_fbt_setup(coeffint_mod, num_slots_ckks, t.p_output, t.p_input, t.bigq, key_pair.public_key, {0, 0},
                           t.lvlb, 0, 0, t.order);
    else
        cc->eval_fbt_setup(coeffcomp_mod, num_slots_ckks, t.p_output, t.p_input, t.bigq, key_pair.public_key, {0, 0},
                           t.lvlb, 0, 0, t.order);

    cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
    cc->eval_mult_key_gen(key_pair.secret_key);

    auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    if (binary_lut)
        coeffint = coeffint_mod;
    else
        coeffcomp = coeffcomp_mod;

    while (state.KeepRunning()) {
        auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

        SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

        uint32_t qbfv_bits = t.Q.get_msb() - 1;

        auto Q = t.Q;
        auto p_input = t.p_input;

        BigInteger Q_new;

        const bool checkgt2 = t.p_output.convert_to_int() > 2;
        const uint32_t p_digit_bits = t.p_output.get_msb() - 1;

        uint64_t scale_thi = t.scale_thi;
        bool step = false;
        bool go = qbfv_bits > dcrt_bits;
        size_t levels_to_drop = 0;
        uint32_t post_scaling_bits = 0;

        // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
        // Currently this only works when log(pNew) divides log(p).
        while (go) {
            auto encrypted_digit = ctxt_bfv;

            // Apply mod q
            encrypted_digit[0].switch_modulus(t.bigq, 1, 0, 0);
            encrypted_digit[1].switch_modulus(t.bigq, 1, 0, 0);

            auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, encrypted_digit, key_pair.public_key, t.bigq,
                                                              num_slots_ckks, depth);

            // Bootstrap the digit.
            Ciphertext<RnsPoly> ctxt_after_fbt;
            if (binary_lut)
                ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, p_digit_bits, ep->get_modulus(),
                                              scale_thi * (1 << post_scaling_bits), levels_to_drop, t.order);
            else
                ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, p_digit_bits, ep->get_modulus(),
                                              scale_thi * (1 << post_scaling_bits), levels_to_drop, t.order);

            auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, Q);

            if (!step) {
                Q_new = Q >> p_digit_bits;

                // Subtract digit and switch mod from Q to Q_new for BFV ciphertext
                ctxt_bfv[0] = (ctxt_bfv[0] - polys[0]).multiply_and_round(Q_new, Q);
                ctxt_bfv[0].switch_modulus(Q_new, 1, 0, 0);
                ctxt_bfv[1] = (ctxt_bfv[1] - polys[1]).multiply_and_round(Q_new, Q);
                ctxt_bfv[1].switch_modulus(Q_new, 1, 0, 0);
                Q >>= p_digit_bits;
                p_input >>= p_digit_bits;
                qbfv_bits -= p_digit_bits;
                post_scaling_bits += p_digit_bits;
            } else {
                ctxt_bfv[0] = std::move(polys[0]);
                ctxt_bfv[1] = std::move(polys[1]);
            }

            go = qbfv_bits > dcrt_bits;

            if (checkgt2 && !go && !step) {
                if (!binary_lut)
                    coeffcomp = coeffcomp_step;
                scale_thi = t.scale_step_thi;
                step = true;
                go = true;
                int64_t lvls_to_drop = get_multiplicative_depth_by_coeff_vector(coeffcomp_mod, true) -
                                       get_multiplicative_depth_by_coeff_vector(coeffcomp_step, true);
                if (coeffcomp_mod.size() > 4 && lvls_to_drop > 0)
                    levels_to_drop = lvls_to_drop;
            }
        }
    }

    cc->clear_static_maps_and_vectors();
}

BENCHMARK_CAPTURE(fbt_arb_lut, FM, FM)->Unit(benchmark::kSecond)->Iterations(4)->Apply(arb_lut_bits_fm);
BENCHMARK_CAPTURE(fbt_arb_lut, FA, FA)->Unit(benchmark::kSecond)->Iterations(4)->Apply(arb_lut_bits_fa);
BENCHMARK(fbt_sign_digit32)->Unit(benchmark::kSecond)->Iterations(4);
BENCHMARK(fbt_setup)->Unit(benchmark::kSecond)->Iterations(10);
BENCHMARK(fbt_key_gen)->Unit(benchmark::kSecond)->Iterations(4);

BENCHMARK_MAIN();
