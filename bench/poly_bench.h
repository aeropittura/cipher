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

#ifndef CIPHER_BENCH_POLY_BENCH_H_
#define CIPHER_BENCH_POLY_BENCH_H_

#define _USE_MATH_DEFINES

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/ring/backend.h"
#include "cipher/math/discrete_uniform_gen.h"

using namespace cipher;

constexpr size_t POLY_NUM = 8;
constexpr size_t POLY_NUM_M1 = (POLY_NUM - 1);

std::vector<uint32_t> tow_args({1, 2, 4, 8, 16, 32});

uint32_t g_poly_order = 0;
uint32_t g_poly_bits = 0;

struct PolyBenchParams {
    PolyBenchParams(uint32_t order, uint32_t bits) {
        g_poly_order = order;
        g_poly_bits = bits;
    }
};

std::shared_ptr<std::vector<NativePoly>> g_nativepolys_eval;
std::shared_ptr<std::vector<NativePoly>> g_nativepolys_coef;
std::map<uint32_t, std::shared_ptr<std::vector<RnsPoly>>> g_dcrt_polys_eval;
std::map<uint32_t, std::shared_ptr<std::vector<RnsPoly>>> g_dcrt_polys_coef;

static void dcrt_arguments(benchmark::internal::Benchmark* b) {
    for (uint32_t t : tow_args) {
        b->ArgName("towers")->Arg(t);
    }
}

static void generate_polys(uint32_t order, uint32_t bits, std::shared_ptr<std::vector<NativePoly>>& poly_array_eval,
                           std::shared_ptr<std::vector<NativePoly>>& poly_array_coef) {
    auto p = std::make_shared<NativePolyParams>(order, bits);
    auto eval = std::make_shared<std::vector<NativePoly>>(POLY_NUM);
    auto coef = std::make_shared<std::vector<NativePoly>>(POLY_NUM);
#pragma omp parallel for collapse(2)
    for (size_t f = 0; f < 2; ++f) {
        for (size_t i = 0; i < POLY_NUM; ++i) {
            DiscreteUniformGeneratorImpl<NativeVector> dug;
            auto& dst = (f == 0) ? (*eval)[i] : (*coef)[i];
            dst = NativePoly(dug, p, (f == 0) ? Format::EVALUATION : Format::COEFFICIENT);
        }
    }
    poly_array_eval = std::move(eval);
    poly_array_coef = std::move(coef);
}

static void generate_rns_polys(uint32_t order, uint32_t bits, uint32_t towers,
                               std::shared_ptr<std::vector<RnsPoly>>& poly_array_eval,
                               std::shared_ptr<std::vector<RnsPoly>>& poly_array_coef) {
    auto p = std::make_shared<RnsParams<BigInteger>>(order, towers, bits);
    auto eval = std::make_shared<std::vector<RnsPoly>>(POLY_NUM);
    auto coef = std::make_shared<std::vector<RnsPoly>>(POLY_NUM);
#pragma omp parallel for collapse(2)
    for (size_t f = 0; f < 2; ++f) {
        for (size_t i = 0; i < POLY_NUM; ++i) {
            DiscreteUniformGeneratorImpl<NativeVector> tdug;
            auto& dst = (f == 0) ? (*eval)[i] : (*coef)[i];
            dst = RnsPoly(tdug, p, (f == 0) ? Format::EVALUATION : Format::COEFFICIENT);
        }
    }
    poly_array_eval = std::move(eval);
    poly_array_coef = std::move(coef);
}

static void ensure_native_polys() {
    static const bool generated = []() {
        generate_polys(g_poly_order, g_poly_bits, g_nativepolys_eval, g_nativepolys_coef);
        return true;
    }();
    (void)generated;
}

static void ensure_rns_polys(uint32_t towers) {
    static std::mutex gen_mutex;
    std::lock_guard<std::mutex> lock(gen_mutex);
    if (g_dcrt_polys_eval.find(towers) == g_dcrt_polys_eval.end())
        generate_rns_polys(g_poly_order, g_poly_bits, towers, g_dcrt_polys_eval[towers], g_dcrt_polys_coef[towers]);
}

static const std::shared_ptr<std::vector<NativePoly>>& nativepolys_eval() {
    ensure_native_polys();
    return g_nativepolys_eval;
}

static const std::shared_ptr<std::vector<NativePoly>>& nativepolys_coef() {
    ensure_native_polys();
    return g_nativepolys_coef;
}

static const std::shared_ptr<std::vector<RnsPoly>>& dcrt_polys_eval(uint32_t towers) {
    ensure_rns_polys(towers);
    return g_dcrt_polys_eval[towers];
}

static const std::shared_ptr<std::vector<RnsPoly>>& dcrt_polys_coef(uint32_t towers) {
    ensure_rns_polys(towers);
    return g_dcrt_polys_coef[towers];
}

// ************************************************************************************

[[maybe_unused]] static void native_add(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_add(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void native_add_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_add_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_sub(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_sub(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void native_sub_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_sub_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_mul(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_mul(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void native_mul_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void dcrt_mul_eq(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_copy(benchmark::State& state) {
    auto polys = nativepolys_eval();
    NativePoly p;
    size_t i{0};
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(p = (*polys)[(i = (i + 1) & POLY_NUM_M1)]);
    }
}

[[maybe_unused]] static void dcrt_copy(benchmark::State& state) {
    auto polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{0};
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(p = (*polys)[(i = (i + 1) & POLY_NUM_M1)]);
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_copy_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_coef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.switch_format();
    }
}

[[maybe_unused]] static void dcrt_copy_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_coef(state.range(0));
    RnsPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.switch_format();
    }
}

[[maybe_unused]] static void native_copy_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.switch_format();
    }
}

[[maybe_unused]] static void dcrt_copy_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.switch_format();
    }
}

[[maybe_unused]] static void native_avg_ntt_intt(benchmark::State& state) {
    auto polys = *nativepolys_coef();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &polys[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
    }
}

[[maybe_unused]] static void dcrt_avg_ntt_intt(benchmark::State& state) {
    auto polys = *dcrt_polys_coef(state.range(0));
    RnsPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &polys[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
    }
}

[[maybe_unused]] static void native_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_coef();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
        p->switch_format();
    }
}

[[maybe_unused]] static void dcrt_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_coef(state.range(0));
    RnsPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
        p->switch_format();
    }
}

[[maybe_unused]] static void native_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
        p->switch_format();
    }
}

[[maybe_unused]] static void dcrt_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->switch_format();
        p->switch_format();
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_crt_interpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_coef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].crt_interpolate();
    }
}

[[maybe_unused]] static void dcrt_crt_interpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_coef(state.range(0));
    RnsPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].crt_interpolate();
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_decryption_crt_interpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_coef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].decryption_crt_interpolate(ptm);
    }
}

[[maybe_unused]] static void dcrt_decryption_crt_interpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_coef(state.range(0));
    RnsPoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].decryption_crt_interpolate(ptm);
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_base_decompose(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_coef();
    std::vector<NativePoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].base_decompose(2, true);
    }
}

[[maybe_unused]] static void dcrt_base_decompose(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_coef(state.range(0));
    std::vector<RnsPoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].base_decompose(2, true);
    }
}

// ************************************************************************************

[[maybe_unused]] static void native_automorphism_transform(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = nativepolys_eval();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].automorphism_transform(5);
    }
}

[[maybe_unused]] static void dcrt_automorphism_transform(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    RnsPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].automorphism_transform(5);
    }
}

[[maybe_unused]] static void dcrt_drop_last_element_and_scale(benchmark::State& state) {
    std::shared_ptr<std::vector<RnsPoly>> polys = dcrt_polys_eval(state.range(0));
    const auto& towers = (*polys)[0].get_params()->get_params();
    const size_t last = towers.size() - 1;
    if (last == 0) {
        state.SkipWithError("drop_last_element_and_scale needs at least two towers");
        return;
    }
    const NativeInteger ql{towers[last]->get_modulus()};
    std::vector<NativeInteger> ql_inv_modq(last);
    for (size_t k = 0; k < last; ++k) {
        const NativeInteger qk{towers[k]->get_modulus()};
        ql_inv_modq[k] = ql.mod(qk).mod_inverse(qk);
    }
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        RnsPoly p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.drop_last_element_and_scale(ql_inv_modq);
    }
}

// ************************************************************************************

// BENCHMARK(native_add)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_add)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

BENCHMARK(native_add_eq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_add_eq)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

// BENCHMARK(native_sub)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_sub)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

BENCHMARK(native_sub_eq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_sub_eq)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

// BENCHMARK(native_mul)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_mul)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

BENCHMARK(native_mul_eq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_mul_eq)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

BENCHMARK(native_copy)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_copy)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

BENCHMARK(native_copy_ntt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_copy_ntt)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

BENCHMARK(native_copy_intt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_copy_intt)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

BENCHMARK(native_avg_ntt_intt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_avg_ntt_intt)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

// BENCHMARK(native_ntt_intt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_ntt_intt)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

// BENCHMARK(native_intt_ntt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_intt_ntt)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

// BENCHMARK(native_crt_interpolate)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
// BENCHMARK(dcrt_crt_interpolate)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

// BENCHMARK(native_decryption_crt_interpolate)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_decryption_crt_interpolate)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

// BENCHMARK(native_base_decompose)->Unit(benchmark::kMicrosecond);
// BENCHMARK(dcrt_base_decompose)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments);

BENCHMARK(native_automorphism_transform)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(dcrt_automorphism_transform)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

BENCHMARK(dcrt_drop_last_element_and_scale)->Unit(benchmark::kMicrosecond)->Apply(dcrt_arguments)->MinTime(5.0);

#endif  // CIPHER_BENCH_POLY_BENCH_H_
