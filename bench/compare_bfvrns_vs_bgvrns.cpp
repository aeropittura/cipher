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
 * Compares the performance of BFV and BFV (default modes)
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
#include "cipher/fhe/bgv/context_gen.h"

using namespace cipher;

uint32_t mult_depth = 3;

/*
 * Context setup utility methods
 */
CryptoContext<RnsPoly> generate_bfv_rns_context(uint32_t ptm) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(mult_depth);
    parameters.set_scaling_mod_size(60);
    parameters.set_key_switch_technique(BV);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<RnsPoly> generate_bgv_rns_context(uint32_t ptm) {
    ContextParams<BgvRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth);
    parameters.set_plaintext_modulus(ptm);
    parameters.set_key_switch_technique(BV);
    parameters.set_scaling_technique(FIXEDMANUAL);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    return cc;
}

/*
 * BFVrns benchmarks
 */
void bfv_rns_eval_mult_many_p2(benchmark::State& state) {
    uint32_t ptm = 2;

    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);

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

BENCHMARK(bfv_rns_eval_mult_many_p2)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

void bgv_rns_eval_mult_many_p2(benchmark::State& state) {
    uint32_t ptm = 2;

    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);

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

BENCHMARK(bgv_rns_eval_mult_many_p2)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

/*
 * BFVrns benchmarks
 */

void bfv_rns_eval_mult_many_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;

    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);

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

BENCHMARK(bfv_rns_eval_mult_many_p65537)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

void bgv_rns_eval_mult_many_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;

    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);

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

BENCHMARK(bgv_rns_eval_mult_many_p65537)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_MAIN();
