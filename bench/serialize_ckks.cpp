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
 * This code benchmarks CKKS serialization.
 */

// #define PROFILE
#define _USE_MATH_DEFINES
#include <complex>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>
#include <sstream>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/context_gen.h"
#include "cipher/fhe/ckks/ser.h"
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

void ckks_serialize(benchmark::State& state) {
    // create a cryptocontext
    ContextParams<CkksRnsContext> parameters;
    parameters.set_ring_dim(512);
    parameters.set_multiplicative_depth(3);
    parameters.set_scaling_mod_size(50);
    parameters.set_digit_size(20);
    parameters.set_security_level(HEStd_NotSet);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(MULTIPARTY);

    // DEBUG("step 0");
    {
        std::stringstream s;
        CryptoContext<RnsPoly> cc_new;
        while (state.KeepRunning()) {
            serialization::to_stream(cc, s, SerType::BINARY);
            serialization::from_stream(cc, s, SerType::BINARY);
        }
    }

    KeyPair<RnsPoly> kp = cc->key_gen();
    KeyPair<RnsPoly> kpnew;

    // DEBUG("step 1");
    {
        std::stringstream s;
        while (state.KeepRunning()) {
            serialization::to_stream(kp.public_key, s, SerType::BINARY);
            serialization::from_stream(kpnew.public_key, s, SerType::BINARY);
        }
    }

    // DEBUG("step 2");
    {
        std::stringstream s;
        while (state.KeepRunning()) {
            serialization::to_stream(kp.secret_key, s, SerType::BINARY);
            serialization::from_stream(kpnew.secret_key, s, SerType::BINARY);
        }
    }

    // DEBUG("step 3");
    std::vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0, 2.0, 4.0, 6.0, 8.0, 11.0};
    Plaintext plaintext_short = cc->make_ckks_packed_plaintext(vals);
    Plaintext plaintext_short_l2_d2 = cc->make_ckks_packed_plaintext(vals, 2, 2);
    Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext_short);
    Ciphertext<RnsPoly> ciphertext_l2_d2 = cc->encrypt(kp.public_key, plaintext_short_l2_d2);

    Ciphertext<RnsPoly> new_c;
    Ciphertext<RnsPoly> new_cl2_d2;
    {
        std::stringstream s;
        std::stringstream s2;
        while (state.KeepRunning()) {
            serialization::to_stream(ciphertext, s, SerType::BINARY);
            serialization::from_stream(new_c, s, SerType::BINARY);
            serialization::to_stream(ciphertext_l2_d2, s2, SerType::BINARY);
            serialization::from_stream(new_cl2_d2, s2, SerType::BINARY);
        }
    }
}

BENCHMARK(ckks_serialize)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_MAIN();
