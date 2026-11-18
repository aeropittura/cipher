//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
 * Main OpenFHE library benchmark that contains performance tests for standard operations in the following schemes:
 * BFVrns, CKKSrns, BGVrns. It also contains several performance tests for NTT and INTT transformations.
 */

#define _USE_MATH_DEFINES

#include <complex>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/fhe/bgv/context_gen.h"
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

/*
 * Context setup utility methods
 */

[[maybe_unused]] static void depth_args(benchmark::internal::Benchmark* b) {
    for (uint32_t d : {1, 2, 4, 6, 8, 10, 12})
        b->ArgName("depth")->Arg(d);
}

[[maybe_unused]] static CryptoContext<RnsPoly> generate_bfv_rns_context(uint32_t mdepth = 1) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_scaling_mod_size(60);
    parameters.set_multiplicative_depth(mdepth);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

[[maybe_unused]] static CryptoContext<RnsPoly> generate_ckks_context(uint32_t mdepth = 1) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_scaling_mod_size(48);
    parameters.set_batch_size(8);
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_multiplicative_depth(mdepth);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

[[maybe_unused]] static CryptoContext<RnsPoly> generate_bgv_rns_context(uint32_t mdepth = 1) {
    ContextParams<BgvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_max_relin_sk_deg(1);
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_multiplicative_depth(mdepth);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

/*
 * Native NTT benchmarks
 */

[[maybe_unused]] static void ring_args(benchmark::internal::Benchmark* b) {
    for (uint32_t r : {1024, 4096, 8192, 16384, 32768})
        b->ArgName("ringdm")->Arg(r);
}

static double bench_rand_real() {
    static std::mt19937_64 rng(20260818);
    static std::uniform_real_distribution<double> dist(-1.0, 1.0);
    return dist(rng);
}

static constexpr uint32_t NTT_POOL = 8;

static std::vector<NativeVector> make_ntt_pool(uint32_t n, const NativeInteger& modulus_q) {
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    std::vector<NativeVector> pool;
    pool.reserve(NTT_POOL);
    for (uint32_t k = 0; k < NTT_POOL; ++k)
        pool.push_back(dug.generate_vector(n, modulus_q));
    return pool;
}

[[maybe_unused]] static void native_ntt(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulus_q(last_prime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger root_of_unity_value = root_of_unity(m, modulus_q);

    auto pool = make_ntt_pool(n, modulus_q);
    NativeVector X(n);

    ChineseRemainderTransformFtt<NativeVector> crt_ftt;
    crt_ftt.pre_compute(root_of_unity_value, m, modulus_q);

    uint32_t i = 0;
    for (auto _ : state)
        crt_ftt.forward_transform_to_bit_reverse(pool[i = (i + 1) & (NTT_POOL - 1)], root_of_unity_value, m, &X);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void native_intt(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulus_q(last_prime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger root_of_unity_value = root_of_unity(m, modulus_q);

    auto pool = make_ntt_pool(n, modulus_q);
    NativeVector X(n);

    ChineseRemainderTransformFtt<NativeVector> crt_ftt;
    crt_ftt.pre_compute(root_of_unity_value, m, modulus_q);

    uint32_t i = 0;
    for (auto _ : state)
        crt_ftt.inverse_transform_from_bit_reverse(pool[i = (i + 1) & (NTT_POOL - 1)], root_of_unity_value, m, &X);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void native_ntt_in_place(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulus_q(last_prime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger root_of_unity_value = root_of_unity(m, modulus_q);

    auto pool = make_ntt_pool(n, modulus_q);

    ChineseRemainderTransformFtt<NativeVector> crt_ftt;
    crt_ftt.pre_compute(root_of_unity_value, m, modulus_q);

    uint32_t i = 0;
    for (auto _ : state)
        crt_ftt.forward_transform_to_bit_reverse_in_place(root_of_unity_value, m, &pool[i = (i + 1) & (NTT_POOL - 1)]);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void native_intt_in_place(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulus_q(last_prime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger root_of_unity_value = root_of_unity(m, modulus_q);

    auto pool = make_ntt_pool(n, modulus_q);

    ChineseRemainderTransformFtt<NativeVector> crt_ftt;
    crt_ftt.pre_compute(root_of_unity_value, m, modulus_q);

    uint32_t i = 0;
    for (auto _ : state)
        crt_ftt.inverse_transform_from_bit_reverse_in_place(root_of_unity_value, m, &pool[i = (i + 1) & (NTT_POOL - 1)]);

    state.SetComplexityN(state.range(0));
}

/*
 * BFVrns benchmarks
 */

[[maybe_unused]] void bfv_rns_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair;

    while (state.KeepRunning()) {
        key_pair = crypto_context->key_gen();
    }
}

[[maybe_unused]] void bfv_rns_mult_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
        state.ResumeTiming();
        cc->eval_mult_key_gen(key_pair.secret_key);
    }
}

[[maybe_unused]] void bfv_rns_eval_at_index_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
        state.ResumeTiming();
        cc->eval_at_index_key_gen(key_pair.secret_key, index_list);
    }
}

[[maybe_unused]] void bfv_rns_encryption(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    while (state.KeepRunning()) {
        auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    }
}

[[maybe_unused]] void bfv_rns_decryption(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    Plaintext plaintext_dec1;

    while (state.KeepRunning()) {
        crypto_context->decrypt(key_pair.secret_key, ciphertext1, &plaintext_dec1);
    }
}

[[maybe_unused]] void bfv_rns_add(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_add = cc->eval_add(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void bfv_rns_add_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        cc->eval_add_in_place(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void bfv_rns_mult_no_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bfv_rns_context(state.range(0));

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    std::vector<int64_t> vector_of_ints2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = crypto_context->eval_mult_no_relin(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void bfv_rns_mult_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bfv_rns_context(state.range(0));

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    std::vector<int64_t> vector_of_ints2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = crypto_context->eval_mult(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void bfv_rns_eval_at_index(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    cc->eval_at_index_key_gen(key_pair.secret_key, index_list);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->eval_at_index(ciphertext_mul, 1);
    }
}

[[maybe_unused]] void bfv_rns_eval_fast_rotation(benchmark::State& state) {
    auto cc = generate_bfv_rns_context(state.range(0));

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1});

    std::vector<int64_t> x{1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    auto ptxt = cc->make_packed_plaintext(x);

    auto c = cc->encrypt(keys.public_key, ptxt);

    auto c_precomp = cc->eval_fast_rotation_precompute(c);

    while (state.KeepRunning()) {
        auto res = cc->eval_fast_rotation(c, 1, 2 * cc->get_ring_dimension(), c_precomp);
    }
}

/*
 * CKKS benchmarks
 * */

[[maybe_unused]] void ckks_rns_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_ckks_context();

    KeyPair<RnsPoly> key_pair;

    while (state.KeepRunning()) {
        key_pair = crypto_context->key_gen();
    }
}

[[maybe_unused]] void ckks_rns_mult_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
        state.ResumeTiming();
        cc->eval_mult_key_gen(key_pair.secret_key);
    }
}

[[maybe_unused]] void ckks_rns_eval_at_index_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
        state.ResumeTiming();
        cc->eval_at_index_key_gen(key_pair.secret_key, index_list);
    }
}

[[maybe_unused]] void ckks_rns_encryption(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints[i] = bench_rand_real();
    }

    auto plaintext = cc->make_ckks_packed_plaintext(vector_of_ints);

    while (state.KeepRunning()) {
        auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
    }
}

[[maybe_unused]] void ckks_rns_decryption(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    ciphertext1 = cc->level_reduce(ciphertext1, nullptr, 1);

    Plaintext plaintext_dec1;

    while (state.KeepRunning()) {
        cc->decrypt(key_pair.secret_key, ciphertext1, &plaintext_dec1);
    }
}

[[maybe_unused]] void ckks_rns_add(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_add = cc->eval_add(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void ckks_rns_add_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        cc->eval_add_in_place(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void ckks_rns_mult_no_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context(state.range(0));

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void ckks_rns_mult_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context(state.range(0));

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void ckks_rns_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->relinearize(ciphertext_mul);
    }
}

[[maybe_unused]] void ckks_rns_relin_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
    auto ciphertext_mul_clone = ciphertext_mul->clone();

    while (state.KeepRunning()) {
        cc->relinearize_in_place(ciphertext_mul);
        state.PauseTiming();
        ciphertext_mul = ciphertext_mul_clone->clone();
        state.ResumeTiming();
    }
}

[[maybe_unused]] void ckks_rns_rescale(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->mod_reduce(ciphertext_mul);
    }
}

[[maybe_unused]] void ckks_rns_rescale_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints[i] = bench_rand_real();
    }

    auto plaintext = cc->make_ckks_packed_plaintext(vector_of_ints);
    auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
    auto ciphertext_mul = cc->eval_mult(ciphertext, ciphertext);
    auto ciphertext_mul_clone = ciphertext_mul->clone();

    while (state.KeepRunning()) {
        cc->mod_reduce_in_place(ciphertext_mul);
        state.PauseTiming();
        ciphertext_mul = ciphertext_mul_clone->clone();
        state.ResumeTiming();
    }
}

[[maybe_unused]] void ckks_rns_eval_at_index(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    cc->eval_at_index_key_gen(key_pair.secret_key, index_list);

    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vector_of_ints1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints1[i] = bench_rand_real();
    }
    std::vector<std::complex<double>> vector_of_ints2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        vector_of_ints2[i] = bench_rand_real();
    }

    auto plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->eval_at_index(ciphertext_mul, 1);
    }
}

[[maybe_unused]] void ckks_rns_eval_fast_rotation(benchmark::State& state) {
    auto cc = generate_ckks_context(state.range(0));

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1});

    std::vector<double> x{0, 0, 0, 0, 0, 0, 0, 1};
    auto ptxt = cc->make_ckks_packed_plaintext(x);

    auto c = cc->encrypt(keys.public_key, ptxt);

    auto c_precomp = cc->eval_fast_rotation_precompute(c);

    while (state.KeepRunning()) {
        auto res = cc->eval_fast_rotation(c, 1, 2 * cc->get_ring_dimension(), c_precomp);
    }
}

/*
 * BGVrns benchmarks
 * */

[[maybe_unused]] void bgv_rns_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair;

    while (state.KeepRunning()) {
        key_pair = crypto_context->key_gen();
    }
}

[[maybe_unused]] void bgv_rns_mult_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
        state.ResumeTiming();
        cc->eval_mult_key_gen(key_pair.secret_key);
    }
}

[[maybe_unused]] void bgv_rns_eval_at_index_key_gen(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair;
    key_pair = cc->key_gen();

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
        state.ResumeTiming();
        cc->eval_at_index_key_gen(key_pair.secret_key, index_list);
    }
}

[[maybe_unused]] void bgv_rns_encryption(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext = crypto_context->make_packed_plaintext(vector_of_ints);

    while (state.KeepRunning()) {
        auto ciphertext = crypto_context->encrypt(key_pair.public_key, plaintext);
    }
}

[[maybe_unused]] void bgv_rns_decryption(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);

    auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
    ciphertext = cc->mod_reduce(ciphertext);  // TODO level_reduce

    Plaintext plaintext_dec;

    while (state.KeepRunning()) {
        cc->decrypt(key_pair.secret_key, ciphertext, &plaintext_dec);
    }
}

[[maybe_unused]] void bgv_rns_add(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_add = cc->eval_add(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void bgv_rns_add_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        cc->eval_add_in_place(ciphertext1, ciphertext2);
    }
}

[[maybe_unused]] void bgv_rns_mult_no_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(state.range(0));

    KeyPair<RnsPoly> key_pair = cc->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void bgv_rns_mult_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(state.range(0));

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] void bgv_rns_relin(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->relinearize(ciphertext_mul);
    }
}

[[maybe_unused]] void bgv_rns_relin_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
    auto ciphertext_mul_clone = ciphertext_mul->clone();

    while (state.KeepRunning()) {
        cc->relinearize_in_place(ciphertext_mul);
        state.PauseTiming();
        ciphertext_mul = ciphertext_mul_clone->clone();
        state.ResumeTiming();
    }
}

[[maybe_unused]] void bgv_rns_mod_switch(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->mod_reduce(ciphertext_mul);
    }
}

[[maybe_unused]] void bgv_rns_mod_switch_in_place(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};

    auto plaintext = cc->make_packed_plaintext(vector_of_ints);
    auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
    auto ciphertext_mul = cc->eval_mult(ciphertext, ciphertext);
    auto ciphertext_mul_clone = ciphertext_mul->clone();

    while (state.KeepRunning()) {
        cc->mod_reduce_in_place(ciphertext_mul);
        state.PauseTiming();
        ciphertext_mul = ciphertext_mul_clone->clone();
        state.ResumeTiming();
    }
}

[[maybe_unused]] void bgv_rns_eval_at_index(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context();

    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int32_t> index_list(1);
    for (uint32_t i = 0; i < 1; i++) {
        index_list[i] = 1;
    }

    cc->eval_at_index_key_gen(key_pair.secret_key, index_list);

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->make_coef_packed_plaintext(vector_of_ints1);
    auto plaintext2 = cc->make_coef_packed_plaintext(vector_of_ints2);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

    auto ciphertext_mul = cc->eval_mult(ciphertext1, ciphertext2);

    while (state.KeepRunning()) {
        auto ciphertext3 = cc->eval_at_index(ciphertext_mul, 1);
    }
}

[[maybe_unused]] void bgv_rns_eval_fast_rotation(benchmark::State& state) {
    auto cc = generate_bgv_rns_context(state.range(0));

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1});

    std::vector<int64_t> x{1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    auto ptxt = cc->make_packed_plaintext(x);

    auto c = cc->encrypt(keys.public_key, ptxt);

    auto c_precomp = cc->eval_fast_rotation_precompute(c);

    while (state.KeepRunning()) {
        auto res = cc->eval_fast_rotation(c, 1, 2 * cc->get_ring_dimension(), c_precomp);
    }
}

// BENCHMARK(native_ntt)->Unit(benchmark::kMicrosecond)->RangeMultiplier(2)->Range(1<<10, 1<<16)->Complexity(benchmark::oAuto);

// ---------------------------------------------------------------------------------------

[[maybe_unused]] void ckks_rns_approx_switch_crt_basis(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context(state.range(0));
    KeyPair<RnsPoly> key_pair = cc->key_gen();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vals(slots);

    constexpr uint32_t KS_POOL = 4;
    std::vector<RnsPoly> parts;
    parts.reserve(KS_POOL);
    uint32_t size_ql = 0, size_part_ql = 0;
    for (uint32_t k = 0; k < KS_POOL; ++k) {
        for (uint32_t i = 0; i < slots; i++)
            vals[i] = bench_rand_real();
        auto c = cc->encrypt(key_pair.public_key, cc->make_ckks_packed_plaintext(vals))->get_elements()[0];
        size_ql = c.get_num_of_elements();
        RnsPoly parts_ct(crypto_params->get_params_part_q(0), Format::EVALUATION, false);
        size_part_ql = parts_ct.get_num_of_elements();
        if (size_part_ql > size_ql) {
            state.SkipWithError("digit part larger than the ciphertext at this depth");
            return;
        }
        for (uint32_t i = 0; i < size_part_ql; ++i)
            parts_ct.set_element_at_index(i, c.get_element_at_index(i));
        parts_ct.set_format(Format::COEFFICIENT);
        parts.push_back(std::move(parts_ct));
    }

    uint32_t i = 0;
    while (state.KeepRunning()) {
        i = (i + 1) & (KS_POOL - 1);
        auto out = parts[i].approx_switch_crt_basis(
                crypto_params->get_params_part_q(0), crypto_params->get_params_compl_part_q(size_ql - 1, 0),
                crypto_params->get_part_ql_hat_inv_modq(0, size_part_ql - 1),
                crypto_params->get_part_ql_hat_inv_modq_precon(0, size_part_ql - 1),
                crypto_params->get_part_ql_hat_modp(size_ql - 1, 0), crypto_params->get_mod_compl_partq_barrett_mu(size_ql - 1, 0));
        auto sink = out.get_element_at_index(0)[0];
        benchmark::DoNotOptimize(sink);
    }
}

[[maybe_unused]] void ckks_rns_approx_mod_down(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_ckks_context(state.range(0));
    KeyPair<RnsPoly> key_pair = cc->key_gen();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t slots = cc->get_encoding_params()->get_batch_size();
    std::vector<std::complex<double>> vals(slots);
    for (uint32_t k = 0; k < slots; k++)
        vals[k] = bench_rand_real();

    auto c = cc->encrypt(key_pair.public_key, cc->make_ckks_packed_plaintext(vals))->get_elements()[0];
    const auto params_ql = c.get_params();
    const auto params_ql_p = c.get_extended_crt_basis(crypto_params->get_params_p());

    constexpr uint32_t KS_POOL = 4;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    std::vector<RnsPoly> ext;
    ext.reserve(KS_POOL);
    for (uint32_t k = 0; k < KS_POOL; ++k)
        ext.emplace_back(dug, params_ql_p, Format::COEFFICIENT);

    const NativeInteger t(0);
    uint32_t i = 0;
    while (state.KeepRunning()) {
        i = (i + 1) & (KS_POOL - 1);
        auto out = ext[i].approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                                        crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                        crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                        crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                        crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
        auto sink = out.get_element_at_index(0)[0];
        benchmark::DoNotOptimize(sink);
    }
}

BENCHMARK(ckks_rns_approx_switch_crt_basis)->Unit(benchmark::kMicrosecond)->Apply(depth_args);
BENCHMARK(ckks_rns_approx_mod_down)->Unit(benchmark::kMicrosecond)->Apply(depth_args);

BENCHMARK(native_ntt)->Unit(benchmark::kMicrosecond)->Apply(ring_args);          // ->Complexity(benchmark::oAuto);
BENCHMARK(native_intt)->Unit(benchmark::kMicrosecond)->Apply(ring_args);         // ->Complexity(benchmark::oAuto);
BENCHMARK(native_ntt_in_place)->Unit(benchmark::kMicrosecond)->Apply(ring_args);   // ->Complexity(benchmark::oAuto);
BENCHMARK(native_intt_in_place)->Unit(benchmark::kMicrosecond)->Apply(ring_args);  // ->Complexity(benchmark::oAuto);

BENCHMARK(bfv_rns_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_mult_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_eval_at_index_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_encryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_decryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_add)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_add_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_mult_no_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);  // ->Complexity(benchmark::oAuto);
BENCHMARK(bfv_rns_mult_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);    // ->Complexity(benchmark::oAuto);
BENCHMARK(bfv_rns_eval_at_index)->Unit(benchmark::kMicrosecond);
BENCHMARK(bfv_rns_eval_fast_rotation)->Unit(benchmark::kMicrosecond)->Apply(depth_args);

BENCHMARK(ckks_rns_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_mult_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_eval_at_index_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_encryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_decryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_add)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_add_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_mult_no_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);  // ->Complexity(benchmark::oAuto);
BENCHMARK(ckks_rns_mult_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);    // ->Complexity(benchmark::oAuto);
BENCHMARK(ckks_rns_relin)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_relin_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_rescale)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_rescale_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_eval_at_index)->Unit(benchmark::kMicrosecond);
BENCHMARK(ckks_rns_eval_fast_rotation)->Unit(benchmark::kMicrosecond)->Apply(depth_args);

BENCHMARK(bgv_rns_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_mult_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_eval_at_index_key_gen)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_encryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_decryption)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_add)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_add_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_mult_no_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);  // ->Complexity(benchmark::oAuto);
BENCHMARK(bgv_rns_mult_relin)->Unit(benchmark::kMicrosecond)->Apply(depth_args);    // ->Complexity(benchmark::oAuto);
BENCHMARK(bgv_rns_relin)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_relin_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_mod_switch)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_mod_switch_in_place)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_eval_at_index)->Unit(benchmark::kMicrosecond);
BENCHMARK(bgv_rns_eval_fast_rotation)->Unit(benchmark::kMicrosecond)->Apply(depth_args);

BENCHMARK_MAIN();
