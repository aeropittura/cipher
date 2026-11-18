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
 * Compares the performance of BFV HPSPOVERQLEVELED with BFV BEHZ
 * using eval_mult_many operation.
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "cipher/fhe/bfv/context_gen.h"

using namespace cipher;

uint32_t mult_depth = 3;
static std::vector<uint32_t> ptm_args{2, 65537};
static std::vector<uint32_t> dcrtbit_args{30, 60};
static std::vector<uint32_t> logn_args{12, 14};

static void mult_bfv_arguments(benchmark::internal::Benchmark* b) {
    for (uint32_t ptm : ptm_args) {
        for (uint32_t dcrtbit : dcrtbit_args) {
            b->ArgNames({"ptm", "dcrtbit"})->Args({ptm, dcrtbit})->MinTime(10.0);
        }
    }
}

static void dec_bfv_arguments(benchmark::internal::Benchmark* b) {
    for (uint32_t ptm : ptm_args) {
        for (uint32_t dcrtbit : dcrtbit_args) {
            for (uint32_t logn : logn_args) {
                b->ArgNames({"ptm", "dcrtbit", "logn"})->Args({ptm, dcrtbit, logn});
            }
        }
    }
}

/*
 * Context setup utility methods
 */

CryptoContext<RnsPoly> generate_bfv_rns_context(uint32_t ptm, uint32_t dcrt_bits) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(mult_depth);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_multiplication_technique(HPSPOVERQLEVELED);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<RnsPoly> generate_behz_context(uint32_t ptm, uint32_t dcrt_bits) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(mult_depth);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_multiplication_technique(BEHZ);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<RnsPoly> generate_flat_bfv_rns_context(uint32_t ptm, uint32_t dcrt_bits, uint32_t n) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_max_relin_sk_deg(0);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_ring_dim(n);
    parameters.set_multiplication_technique(HPSPOVERQLEVELED);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

CryptoContext<RnsPoly> generate_flat_behz_context(uint32_t ptm, uint32_t dcrt_bits, uint32_t n) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_max_relin_sk_deg(0);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_ring_dim(n);
    parameters.set_multiplication_technique(BEHZ);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

/*
 * benchmarks
 */
void bfv_rns_eval_mult_many(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(state.range(0), state.range(1));

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    Plaintext plaintext;
    if (state.range(0) == 2)
        plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    else
        plaintext = cc->make_packed_plaintext(vector_of_ints);

    std::vector<Ciphertext<RnsPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->encrypt(key_pair.public_key, plaintext));

    Ciphertext<RnsPoly> ciphertext_mult;
    while (state.KeepRunning()) {
        ciphertext_mult = cc->eval_mult_many(ciphertexts);
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bfv_rns_eval_mult_many)->Unit(benchmark::kMicrosecond)->Apply(mult_bfv_arguments);

void behz_eval_mult_many(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_behz_context(state.range(0), state.range(1));

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext;
    if (state.range(0) == 2)
        plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    else
        plaintext = cc->make_packed_plaintext(vector_of_ints);

    std::vector<Ciphertext<RnsPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->encrypt(key_pair.public_key, plaintext));

    Ciphertext<RnsPoly> ciphertext_mult;
    while (state.KeepRunning()) {
        ciphertext_mult = cc->eval_mult_many(ciphertexts);
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(behz_eval_mult_many)->Unit(benchmark::kMicrosecond)->Apply(mult_bfv_arguments);

void bfv_rns_decrypt(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context =
            generate_flat_bfv_rns_context(state.range(0), state.range(1), 1 << state.range(2));

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1;
    if (state.range(0) == 2)
        plaintext1 = crypto_context->make_coef_packed_plaintext(vector_of_ints1);
    else
        plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    Plaintext plaintext_dec1;

    while (state.KeepRunning()) {
        crypto_context->decrypt(key_pair.secret_key, ciphertext1, &plaintext_dec1);
    }
}

BENCHMARK(bfv_rns_decrypt)->Unit(benchmark::kMicrosecond)->Apply(dec_bfv_arguments);

void behz_decrypt(benchmark::State& state) {
    CryptoContext<RnsPoly> crypto_context =
            generate_flat_behz_context(state.range(0), state.range(1), 1 << state.range(2));

    KeyPair<RnsPoly> key_pair = crypto_context->key_gen();

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1;
    if (state.range(0) == 2)
        plaintext1 = crypto_context->make_coef_packed_plaintext(vector_of_ints1);
    else
        plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    Plaintext plaintext_dec1;

    while (state.KeepRunning()) {
        crypto_context->decrypt(key_pair.secret_key, ciphertext1, &plaintext_dec1);
    }
}

BENCHMARK(behz_decrypt)->Unit(benchmark::kMicrosecond)->Apply(dec_bfv_arguments);

BENCHMARK_MAIN();
