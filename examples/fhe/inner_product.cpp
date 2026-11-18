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

/**
 * Simple example for BFV and CKKS for inner product.
 */

#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

template <class T>
T plain_inner_product(std::vector<T> vec) {
    T res = 0.0;
    for (auto& el : vec) {
        res += (el * el);
    }
    return res;
}

bool inner_product_bfv(std::vector<int64_t>& incoming_vector) {
    int64_t expected_result = plain_inner_product(incoming_vector);
    /////////////////////////////////////////////////////////
    // Crypto CryptoParams
    /////////////////////////////////////////////////////////
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_multiplicative_depth(20);
    parameters.set_security_level(cipher::HEStd_NotSet);
    parameters.set_ring_dim(1 << 7);
    uint32_t batch_size = parameters.get_ring_dim() / 2;

    /////////////////////////////////////////////////////////
    // Set crypto params and create context
    /////////////////////////////////////////////////////////
    cipher::CryptoContext<cipher::RnsPoly> cc;
    cc = make_crypto_context(parameters);

    // Enable the features that you wish to use.
    cc->enable(PKE);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    KeyPair keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);
    cc->eval_sum_key_gen(keys.secret_key);

    Plaintext plaintext1 = cc->make_packed_plaintext(incoming_vector);
    auto ct1 = cc->encrypt(keys.public_key, plaintext1);
    auto final_result = cc->eval_inner_product(ct1, ct1, batch_size);
    cipher::Plaintext res;
    cc->decrypt(keys.secret_key, final_result, &res);
    auto final = res->get_packed_value()[0];

    std::cout << "Expected Result: " << expected_result << " Inner Product Result: " << final << std::endl;
    return expected_result == final;
}

bool inner_product_ckks(const std::vector<double>& incoming_vector) {
    double expected_result = plain_inner_product(incoming_vector);
    cipher::SecurityLevel security_level = cipher::HEStd_NotSet;
    uint32_t dcrt_bits = 59;
    uint32_t ring_dim = 1 << 8;
    uint32_t batch_size = ring_dim / 2;
    cipher::ContextParams<cipher::CkksRnsContext> parameters;
    uint32_t mult_depth_value = 10;

    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_batch_size(batch_size);
    parameters.set_security_level(security_level);
    parameters.set_ring_dim(ring_dim);

    cipher::CryptoContext<cipher::RnsPoly> cc;
    cc = make_crypto_context(parameters);

    cc->enable(PKE);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    KeyPair keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);
    cc->eval_sum_key_gen(keys.secret_key);

    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(incoming_vector);
    auto ct1 = cc->encrypt(keys.public_key, plaintext1);
    auto final_result = cc->eval_inner_product(ct1, ct1, batch_size);
    cipher::Plaintext res;
    cc->decrypt(keys.secret_key, final_result, &res);
    res->set_length(incoming_vector.size());
    auto final = res->get_ckks_packed_value()[0].real();
    std::cout << "Expected Result: " << expected_result << " Inner Product Result: " << final << std::endl;
    return std::abs(expected_result - final) <= 0.0001;
}

int main(int argc, char* argv[]) {
    std::vector<int64_t> vec = {1, 2, 3, 4, 5};
    bool bfv_res = inner_product_bfv(vec);
    std::cout << "BFV Inner Product Correct? " << (bfv_res ? "True" : "False") << std::endl;

    std::cout << "********************************************************************" << std::endl;
    std::vector<double> as_double(vec.begin(), vec.end());
    for (size_t i = 0; i < as_double.size(); i++) {
        as_double[i] += (as_double[i] / 100.0);
    }
    bool ckks_res = inner_product_ckks(as_double);
    std::cout << "CKKS Inner Product Correct? " << (ckks_res ? "True" : "False") << std::endl;

    return 0;
}
