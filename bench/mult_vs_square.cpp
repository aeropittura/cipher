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
 * Compares the performance of Mult and Square for BGV, BFV and CKKS
 * using eval_mult and eval_square operations.
 */

#include <cmath>
#include <complex>
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
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

static std::vector<uint32_t> depths({1, 2, 4, 8, 12});

/*
 * Context setup utility methods
 */
CryptoContext<RnsPoly> generate_bgv_rns_context(uint32_t ptm, uint32_t mult_depth_value) {
    ContextParams<BgvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_scaling_technique(FIXEDAUTO);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    return cc;
}

CryptoContext<RnsPoly> generate_bfv_rns_context(uint32_t ptm, uint32_t mult_depth_value) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(60);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_multiplication_technique(HPS);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    return cc;
}

CryptoContext<RnsPoly> generate_ckks_context(uint32_t mult_depth_value) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_scaling_mod_size(48);
    parameters.set_batch_size(8);
    parameters.set_multiplicative_depth(mult_depth_value);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    return cc;
}

static void depth_arguments(benchmark::internal::Benchmark* b) {
    for (uint32_t t : depths) {
        b->ArgName("depths")->Arg(t);
    }
}

/*
 * eval_mult benchmarks for Power of 2
 */
void bgv_rns_eval_po2_with_mult_p2(benchmark::State& state) {
    uint32_t ptm = 2;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_mult(ciphertext, ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_mult(ciphertext_po2, ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bgv_rns_eval_po2_with_mult_p2)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_square benchmarks for Power of 2
 */
void bgv_rns_eval_po2_with_square_p2(benchmark::State& state) {
    uint32_t ptm = 2;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_square(ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_square(ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bgv_rns_eval_po2_with_square_p2)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_mult benchmarks for Power of 2
 */
void bfv_rns_eval_po2_with_mult_p2(benchmark::State& state) {
    uint32_t ptm = 2;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_mult(ciphertext, ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_mult(ciphertext_po2, ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bfv_rns_eval_po2_with_mult_p2)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_square benchmarks for Power of 2
 */
void bfv_rns_eval_po2_with_square_p2(benchmark::State& state) {
    uint32_t ptm = 2;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_coef_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_square(ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_square(ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bfv_rns_eval_po2_with_square_p2)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_mult benchmarks for Power of 2
 */
void bgv_rns_eval_po2_with_mult_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 1, 0, 0, 1, 1};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_mult(ciphertext, ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_mult(ciphertext_po2, ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bgv_rns_eval_po2_with_mult_p65537)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_square benchmarks for Power of 2
 */
void bgv_rns_eval_po2_with_square_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bgv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 1, 0, 0, 1, 1};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_square(ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            cc->eval_square_in_place(ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bgv_rns_eval_po2_with_square_p65537)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_mult benchmarks for Power of 2
 */
void bfv_rns_eval_po2_with_mult_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_mult(ciphertext, ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_mult(ciphertext_po2, ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bfv_rns_eval_po2_with_mult_p65537)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_square benchmarks for Power of 2
 */
void bfv_rns_eval_po2_with_square_p65537(benchmark::State& state) {
    uint32_t ptm = 65537;
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_bfv_rns_context(ptm, depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<int64_t> vector_of_ints = {1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0};
    Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_square(ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_square(ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());

    if (plaintext != plaintext_dec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(bfv_rns_eval_po2_with_square_p65537)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_mult benchmarks for Power of 2
 */
void ckks_rns_eval_po2_with_mult(benchmark::State& state) {
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_ckks_context(depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<double> vector_of_doubles = {1., 0., 0., 1., 0., 0., 1., 1.};
    Plaintext plaintext = cc->make_ckks_packed_plaintext(vector_of_doubles);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_mult(ciphertext, ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_mult(ciphertext_po2, ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());
    bool equal = std::equal(plaintext->get_ckks_packed_value().begin(), plaintext->get_ckks_packed_value().end(),
                            plaintext_dec->get_ckks_packed_value().begin(),
                            [](std::complex<double> value1, std::complex<double> value2) {
                                constexpr double epsilon = 0.0001;
                                return std::fabs(value1.real() - value2.real()) < epsilon;
                            });
    if (!equal) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(ckks_rns_eval_po2_with_mult)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

/*
 * eval_square benchmarks for Power of 2
 */
void ckks_rns_eval_po2_with_square(benchmark::State& state) {
    uint32_t depth = state.range(0);
    CryptoContext<RnsPoly> cc = generate_ckks_context(depth);

    // key_gen
    KeyPair<RnsPoly> key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<double> vector_of_doubles = {1., 0., 0., 1., 0., 0., 1., 1.};
    Plaintext plaintext = cc->make_ckks_packed_plaintext(vector_of_doubles);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    Ciphertext<RnsPoly> ciphertext_po2;

    while (state.KeepRunning()) {
        ciphertext_po2 = cc->eval_square(ciphertext);
        for (uint32_t i = 2; i < depth; ++i) {
            ciphertext_po2 = cc->eval_square(ciphertext_po2);
        }
    }

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, ciphertext_po2, &plaintext_dec);
    plaintext_dec->set_length(plaintext->get_length());
    bool equal = std::equal(plaintext->get_ckks_packed_value().begin(), plaintext->get_ckks_packed_value().end(),
                            plaintext_dec->get_ckks_packed_value().begin(),
                            [](std::complex<double> value1, std::complex<double> value2) {
                                constexpr double epsilon = 0.0001;
                                return std::fabs(value1.real() - value2.real()) < epsilon;
                            });
    if (!equal) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintext_dec << std::endl;
    }
}

BENCHMARK(ckks_rns_eval_po2_with_square)->Unit(benchmark::kMicrosecond)->Apply(depth_arguments)->MinTime(10.0);

BENCHMARK_MAIN();
