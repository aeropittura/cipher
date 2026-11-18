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

#include <cstdint>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/config.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/utils.h"
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

struct boot_config {
    uint32_t ring_dim;
    uint32_t slots;
    uint32_t dcrt_bits;
    uint32_t first_mod;
    uint32_t num_digits;
    uint32_t lvls_after;
    uint32_t iters;
    std::vector<uint32_t> lvlb;
    SecretKeyDist skdst;
    ScalingTechnique stech;
    uint32_t precision;
};

// clang-format off
[[maybe_unused]] std::vector<boot_config> boot_configs_value = {
    // ringDm,   slots, dcrt_bits, first_mod, num_digits, lvls_after, iters,   lvlb,                skdst,                stech, precision
    // 2^16, full packing, sparse-encapsulated, one iteration: five levels after bootstrapping, then the most levels that fit the 128-bit bound
    { 1 << 16, 1 << 15,       56,       60,         5,         5,     1, {4, 3},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    { 1 << 16, 1 << 15,       54,       60,         7,        10,     1, {3, 3},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    // two iterations (the second refines the first round's precision, given in the last column), 9 and 10 levels
    { 1 << 16, 1 << 15,       50,       56,         6,         9,     2, {4, 3},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  7},
    { 1 << 16, 1 << 15,       50,       56,         8,        10,     2, {4, 3},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  7},
    // two iterations with FIXEDMANUAL scaling, 8 and 9 levels
    { 1 << 16, 1 << 15,       52,       58,         6,         8,     2, {4, 3},  SPARSE_ENCAPSULATED,          FIXEDMANUAL,  8},
    { 1 << 16, 1 << 15,       52,       58,         7,         9,     2, {4, 3},  SPARSE_ENCAPSULATED,          FIXEDMANUAL,  8},
    // sparse packing: 2^12 and 2^5 slots, each at the most levels that fit
    { 1 << 16, 1 << 12,       59,       60,         6,         7,     1, {3, 3},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    { 1 << 16,  1 << 5,       59,       60,         6,        11,     1, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    // uniform ternary secrets: Set II of the homomorphic encryption security guidelines (cic.iacr.org/p/1/4/26, Table 5.8)
    // with four levels after bootstrapping instead of five, which is what fits the library's bound
    { 1 << 16, 1 << 15,       58,       60,         9,         4,     1, {3, 3},      UNIFORM_TERNARY,         FLEXIBLEAUTO,  0},
    // the configurations used by the GPU comparisons
    { 1 << 16, 1 << 15,       55,       60,         3,         1,     1, {3, 3},      UNIFORM_TERNARY,         FLEXIBLEAUTO,  0},  // GPU0
    { 1 << 16, 1 << 14,       50,       53,         7,        10,     1, {3, 3},       SPARSE_TERNARY,         FLEXIBLEAUTO,  0},  // GPU1
    // 2^17, full packing, one iteration: five levels after bootstrapping, then fifteen
    { 1 << 17, 1 << 16,       59,       60,         0,         5,     1, {5, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    { 1 << 17, 1 << 16,       59,       60,         0,        15,     1, {5, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    // two iterations, 10 levels
    { 1 << 17, 1 << 16,       59,       60,         0,        10,     2, {4, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO, 14},
    // sparse packing: 2^5 slots
    { 1 << 17,  1 << 5,       59,       60,         0,         5,     1, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO,  0},
    // composite scaling, two iterations, 10 levels (the most that fit at 78-bit scaling)
    { 1 << 17, 1 << 16,       78,       96,         0,        10,     2, {4, 4},  SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO,  0},
};
// clang-format on

[[maybe_unused]] static void boot_configs(benchmark::internal::Benchmark* b) {
    for (uint32_t i = 0; i < boot_configs_value.size(); ++i)
        b->ArgName("Config")->Arg(i);
}

[[maybe_unused]] static void ckks_boot(benchmark::State& state) {
    auto t = boot_configs_value[state.range(0)];

    ContextParams<CkksRnsContext> parameters;
    parameters.set_security_level(HEStd_128_classic);
    parameters.set_ring_dim(t.ring_dim);
    parameters.set_scaling_mod_size(t.dcrt_bits);
    parameters.set_first_mod_size(t.first_mod);
    parameters.set_num_large_digits(t.num_digits);
    parameters.set_secret_key_dist(t.skdst);
    parameters.set_scaling_technique(t.stech);
    parameters.set_key_switch_technique(HYBRID);
    uint32_t depth = t.lvls_after + CkksRnsFhe::get_bootstrap_depth(t.lvlb, t.skdst) + (t.iters - 1);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    cc->eval_bootstrap_setup(t.lvlb, {0, 0}, t.slots);

    auto key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);
    cc->eval_bootstrap_key_gen(key_pair.secret_key, t.slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};

    auto ptxt = cc->make_ckks_packed_plaintext(x, 1, depth - 1, nullptr, t.slots);
    ptxt->set_length(t.slots);

    auto ctxt = cc->encrypt(key_pair.public_key, ptxt);

    while (state.KeepRunning())
        auto ctxt_after = cc->eval_bootstrap(ctxt, t.iters, t.precision);

    cc->clear_static_maps_and_vectors();
}

[[maybe_unused]] static void ckks_boot_st_c(benchmark::State& state) {
    auto t = boot_configs_value[state.range(0)];

    ContextParams<CkksRnsContext> parameters;
    parameters.set_security_level(HEStd_128_classic);
    parameters.set_ring_dim(t.ring_dim);
    parameters.set_scaling_mod_size(t.dcrt_bits);
    parameters.set_first_mod_size(t.first_mod);
    parameters.set_num_large_digits(t.num_digits);
    parameters.set_secret_key_dist(t.skdst);
    parameters.set_scaling_technique(t.stech);
    parameters.set_key_switch_technique(HYBRID);
    uint32_t depth = t.lvls_after + CkksRnsFhe::get_bootstrap_depth(t.lvlb, t.skdst) + (t.iters - 1);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    cc->eval_bootstrap_setup(t.lvlb, {0, 0}, t.slots, 0, true, true);

    auto key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);
    cc->eval_bootstrap_key_gen(key_pair.secret_key, t.slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};

    auto ptxt = cc->make_ckks_packed_plaintext(x, 1, depth - 1 - t.lvlb[1], nullptr, t.slots);
    ptxt->set_length(t.slots);

    auto ctxt = cc->encrypt(key_pair.public_key, ptxt);

    while (state.KeepRunning())
        auto ctxt_after = cc->eval_bootstrap(ctxt, t.iters, t.precision);

    cc->clear_static_maps_and_vectors();
}

BENCHMARK(ckks_boot)->Unit(benchmark::kSecond)->Iterations(4)->Apply(boot_configs);
BENCHMARK(ckks_boot_st_c)->Unit(benchmark::kSecond)->Iterations(4)->Apply(boot_configs);

BENCHMARK_MAIN();
