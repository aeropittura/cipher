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
 * Compares the performance of different multiplication methods in BFV
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

constexpr uint32_t RING_DIM = 16384;
constexpr uint32_t MULT_DEPTH = 7;
constexpr uint32_t PTM = 2;
constexpr uint32_t DCRT_BITS = 60;
constexpr KeySwitchTechnique KS_TECH = BV;

static std::vector<MultiplicationTechnique> MULT_METHOD_ARGS = {BEHZ, HPS, HPSPOVERQ, HPSPOVERQLEVELED};

static void mult_bfv_arguments(benchmark::internal::Benchmark* b) {
    for (MultiplicationTechnique mult_method : MULT_METHOD_ARGS) {
        b->ArgNames({"mult_method"})->Args({mult_method})->MinTime(10);
    }
}

/*
 * Context setup utility methods
 */

CryptoContext<RnsPoly> generate_bfv_rns_context(MultiplicationTechnique mult_method) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(PTM);
    parameters.set_multiplicative_depth(MULT_DEPTH);
    parameters.set_scaling_mod_size(DCRT_BITS);
    parameters.set_key_switch_technique(KS_TECH);
    parameters.set_ring_dim(RING_DIM);
    parameters.set_multiplication_technique(mult_method);
    parameters.set_security_level(HEStd_128_classic);
    parameters.set_max_relin_sk_deg(2);
    parameters.set_standard_deviation(3.19);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    return cc;
}

/*
 * benchmarks
 */
void bfv_rns_eval_mult(benchmark::State& state) {
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(MULT_METHOD_ARGS[state.range(0) - 1]);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    Plaintext plaintext;
    plaintext = cc->make_coef_packed_plaintext(vector_of_ints);

    std::vector<Ciphertext<RnsPoly>> ciphertexts;
    int tree_size = 1 << MULT_DEPTH;

    for (int i = 0; i < tree_size; i++)
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
BENCHMARK(bfv_rns_eval_mult)->Unit(benchmark::kMillisecond)->Apply(mult_bfv_arguments);

BENCHMARK_MAIN();
