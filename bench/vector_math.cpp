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
  This code benchmarks vector operations.
 */

#define _USE_MATH_DEFINES

#include <cstdint>
#include <iostream>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/discrete_uniform_gen.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/math/ternary_uniform_gen.h"

using namespace cipher;

constexpr size_t VEC_POOL = 8;
constexpr size_t VEC_POOL_M1 = VEC_POOL - 1;

template <typename V>
static std::vector<V> make_vec_pool(uint32_t n, const typename V::Integer& q) {
    DiscreteUniformGeneratorImpl<V> dug;
    std::vector<V> pool;
    pool.reserve(VEC_POOL);
    for (size_t k = 0; k < VEC_POOL; ++k)
        pool.push_back(dug.generate_vector(n, q));
    return pool;
}

template <typename V>
static void add_big_vec(const V& a, const V& b) {
    V c = a + b;
}

template <typename V>
static void bm_big_vec_add(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    auto a = make_vec_pool<V>(p, q);
    auto b = make_vec_pool<V>(p, q);
    size_t i{VEC_POOL_M1};
    while (state.KeepRunning()) {
        i = (i + 1) & VEC_POOL_M1;
        add_big_vec<V>(a[i], b[i]);
    }
}

template <typename V>
static void addeq_big_vec(V& a, const V& b) {
    a += b;
}

template <typename V>
static void bm_big_vec_addeq(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    auto a = make_vec_pool<V>(p, q);
    auto b = make_vec_pool<V>(p, q);
    size_t i{VEC_POOL_M1};
    V acc{a[0]};
    while (state.KeepRunning()) {
        addeq_big_vec<V>(acc, b[i = (i + 1) & VEC_POOL_M1]);
    }
}

template <typename V>
static void mult_big_vec(const V& a, const V& b) {
    V c = a * b;
}

template <typename V>
static void bm_big_vec_mult(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    auto a = make_vec_pool<V>(p, q);
    auto b = make_vec_pool<V>(p, q);
    size_t i{VEC_POOL_M1};
    while (state.KeepRunning()) {
        i = (i + 1) & VEC_POOL_M1;
        mult_big_vec<V>(a[i], b[i]);
    }
}

template <typename V>
static void multeq_big_vec(V& a, const V& b) {
    a *= b;
}

template <typename V>
static void bm_big_vec_multeq(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    auto a = make_vec_pool<V>(p, q);
    auto b = make_vec_pool<V>(p, q);
    size_t i{VEC_POOL_M1};
    V acc{a[0]};
    while (state.KeepRunning()) {
        multeq_big_vec<V>(acc, b[i = (i + 1) & VEC_POOL_M1]);
    }
}

template <typename V>
static void bm_sample_uniform(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    DiscreteUniformGeneratorImpl<V> dug;
    while (state.KeepRunning()) {
        V v = dug.generate_vector(p, q);
        benchmark::DoNotOptimize(v[0]);
    }
}

template <typename V>
static void bm_sample_ternary(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    TernaryUniformGeneratorImpl<V> tug;
    while (state.KeepRunning()) {
        V v = tug.generate_vector(p, q);
        benchmark::DoNotOptimize(v[0]);
    }
}

template <typename V>
static void bm_sample_gaussian(benchmark::State& state) {
    auto p = state.range(0);
    auto q = last_prime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    DiscreteGaussianGeneratorImpl<V> dgg(3.19);
    while (state.KeepRunning()) {
        V v = dgg.generate_vector(p, q);
        benchmark::DoNotOptimize(v[0]);
    }
}

#define DO_VECTOR_BENCHMARK(X, Y)                                                               \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(16);       \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1024);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2048);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(4096);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(8192);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(16384); \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(32768);

DO_VECTOR_BENCHMARK(bm_big_vec_add, NativeVector)
DO_VECTOR_BENCHMARK(bm_big_vec_addeq, NativeVector)
DO_VECTOR_BENCHMARK(bm_big_vec_mult, NativeVector)
DO_VECTOR_BENCHMARK(bm_big_vec_multeq, NativeVector)
DO_VECTOR_BENCHMARK(bm_sample_uniform, NativeVector)
DO_VECTOR_BENCHMARK(bm_sample_ternary, NativeVector)
DO_VECTOR_BENCHMARK(bm_sample_gaussian, NativeVector)

#ifdef CIPHER_WITH_BE2
DO_VECTOR_BENCHMARK(bm_big_vec_add, M2Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_addeq, M2Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_mult, M2Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_multeq, M2Vector)
#endif

#ifdef CIPHER_WITH_BE4
DO_VECTOR_BENCHMARK(bm_big_vec_add, M4Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_addeq, M4Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_mult, M4Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_multeq, M4Vector)
#endif

#ifdef CIPHER_WITH_NTL
DO_VECTOR_BENCHMARK(bm_big_vec_add, M6Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_addeq, M6Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_mult, M6Vector)
DO_VECTOR_BENCHMARK(bm_big_vec_multeq, M6Vector)
#endif

// execute the benchmarks
BENCHMARK_MAIN();
