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
  Example of polynomial evaluation using CKKS.
 */

#define PROFILE  // turns on the reporting of timing results

#include <complex>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

int main(int argc, char* argv[]) {
    TimeVar t;

    double time_eval_linear_w_sum(0.0);

    std::cout << "\n======EXAMPLE FOR EVAL LINEAR WEIGHTED SUM========\n" << std::endl;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(8);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(2048);
    parameters.set_scaling_technique(FLEXIBLEAUTO);
    parameters.set_first_mod_size(60);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    std::vector<std::vector<std::complex<double>>> input;

    input.push_back({0.5, 0.7, 0.9, 0.95, 0.93, 1.3});
    input.push_back({1.2, 1.7, -0.9, 0.85, -0.63, 2});
    input.push_back({0.5, 0, 1.9, 2.95, -3.93, 3.3});
    input.push_back({1.5, 0.7, 1.9, 2.95, -3.78, 3.3});
    input.push_back({0.5, 2.7, 1.9, 0.0, -3.43, 1.3});
    input.push_back({0.5, 0.7, -1.9, 2.95, 1.96, 0.0});
    input.push_back({0.0, 0.0, 1.0, 0.0, 0.0, 0.0});

    size_t encoded_length = input.size();

    std::vector<double> coefficients({0.15, 0.75, 1.25, 1, 0, 0.5, 0.5});

    auto key_pair = cc->key_gen();

    std::cout << "Generating evaluation key for homomorphic multiplication...";
    cc->eval_mult_key_gen(key_pair.secret_key);
    std::cout << "Completed." << std::endl;

    std::vector<ReadOnlyCiphertext<RnsPoly>> ciphertext_vec;
    for (uint32_t i = 0; i < encoded_length; ++i) {
        Plaintext plaintext = cc->make_ckks_packed_plaintext(input[i]);
        ciphertext_vec.push_back(cc->encrypt(key_pair.public_key, plaintext));
    }

    TIC(t);

    auto result = cc->eval_linear_w_sum(ciphertext_vec, coefficients);

    time_eval_linear_w_sum = TOC(t);

    std::vector<std::complex<double>> unenc_ip;
    for (uint32_t i = 0; i < input[0].size(); ++i) {
        std::complex<double> x = 0;
        for (uint32_t j = 0; j < encoded_length; ++j) {
            x += input[j][i] * coefficients[j];
        }
        unenc_ip.push_back(x);
    }

    Plaintext plaintext_dec;

    cc->decrypt(key_pair.secret_key, result, &plaintext_dec);

    plaintext_dec->set_length(encoded_length);

    std::cout << std::setprecision(10) << std::endl;

    std::cout << "\n Result of evaluating a linear weighted sum with coefficients " << coefficients << " \n";
    std::cout << plaintext_dec << std::endl;

    std::cout << "\n Expected result: " << unenc_ip << std::endl;

    std::cout << "\n Evaluation time: " << time_eval_linear_w_sum << " ms" << std::endl;

    return 0;
}
