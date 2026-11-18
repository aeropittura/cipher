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
  Example of vector rotation.
  This code shows how the eval_rotate and eval_merge operations work
 */

#include <complex>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

#include "cipher/math/backend.h"
#include "cipher/cipher.h"

using namespace cipher;

void bfv_rns_eval_rotate2n();
void ckks_eval_rotate2n();
void bfv_rns_eval_merge2n();

int main() {
    std::cout << "\nThis code shows how the EvalRotate and EvalMerge operations work "
                 "for different cyclotomic rings (both power-of-two and cyclic).\n"
              << std::endl;

    std::cout << "\n========== BFVrns.EvalRotate - Power-of-Two Cyclotomics "
                 "==========="
              << std::endl;

    bfv_rns_eval_rotate2n();

    std::cout << "\n========== CKKS.EvalRotate - Power-of-Two Cyclotomics ===========" << std::endl;

    ckks_eval_rotate2n();

    std::cout << "\n========== BFVrns.EvalMerge - Power-of-Two Cyclotomics ===========" << std::endl;

    bfv_rns_eval_merge2n();

    return 0;
}

void bfv_rns_eval_rotate2n() {
    ContextParams<BfvRnsContext> parameters;

    parameters.set_plaintext_modulus(65537);
    parameters.set_max_relin_sk_deg(3);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    int32_t n = cc->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2;

    // Initialize the public key containers.
    KeyPair<RnsPoly> kp = cc->key_gen();

    std::vector<int32_t> index_list = {2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5};

    cc->eval_rotate_key_gen(kp.secret_key, index_list);

    std::vector<int64_t> vector_of_ints = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    vector_of_ints.resize(n);
    vector_of_ints[n - 1] = n;
    vector_of_ints[n - 2] = n - 1;
    vector_of_ints[n - 3] = n - 2;

    Plaintext int_array = cc->make_packed_plaintext(vector_of_ints);

    auto ciphertext = cc->encrypt(kp.public_key, int_array);

    for (size_t i = 0; i < 18; i++) {
        auto permuted_ciphertext = cc->eval_rotate(ciphertext, index_list[i]);

        Plaintext int_array_new;

        cc->decrypt(kp.secret_key, permuted_ciphertext, &int_array_new);

        int_array_new->set_length(10);

        std::cout << "Automorphed array - at index " << index_list[i] << ": " << *int_array_new << std::endl;
    }
}

void ckks_eval_rotate2n() {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(2);
    parameters.set_scaling_mod_size(40);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    uint32_t cycl_order = cc->get_cyclotomic_order();

    // Initialize the public key containers.
    KeyPair<RnsPoly> kp = cc->key_gen();

    int32_t n = cycl_order / 4;
    std::vector<int32_t> index_list = {2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5};

    cc->eval_rotate_key_gen(kp.secret_key, index_list);

    std::vector<std::complex<double>> vector_of_ints = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    vector_of_ints.resize(n);
    vector_of_ints[n - 1] = n;
    vector_of_ints[n - 2] = n - 1;
    vector_of_ints[n - 3] = n - 2;

    Plaintext int_array = cc->make_ckks_packed_plaintext(vector_of_ints);

    auto ciphertext = cc->encrypt(kp.public_key, int_array);

    for (size_t i = 0; i < 18; i++) {
        auto permuted_ciphertext = cc->eval_rotate(ciphertext, index_list[i]);

        Plaintext int_array_new;

        cc->decrypt(kp.secret_key, permuted_ciphertext, &int_array_new);

        int_array_new->set_length(10);

        std::cout << "Automorphed array - at index " << index_list[i] << ": " << *int_array_new << std::endl;
    }
}

void bfv_rns_eval_merge2n() {
    ContextParams<BfvRnsContext> parameters;

    parameters.set_plaintext_modulus(65537);
    parameters.set_multiplicative_depth(2);
    parameters.set_max_relin_sk_deg(3);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    // Initialize the public key containers.
    KeyPair<RnsPoly> kp = cc->key_gen();

    std::vector<int32_t> index_list = {-1, -2, -3, -4, -5};

    cc->eval_rotate_key_gen(kp.secret_key, index_list);

    std::vector<Ciphertext<RnsPoly>> ciphertexts;

    std::vector<int64_t> vector_of_ints1 = {32, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);
    ciphertexts.push_back(cc->encrypt(kp.public_key, int_array1));

    std::vector<int64_t> vector_of_ints2 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext int_array2 = cc->make_packed_plaintext(vector_of_ints2);
    ciphertexts.push_back(cc->encrypt(kp.public_key, int_array2));

    std::vector<int64_t> vector_of_ints3 = {4, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext int_array3 = cc->make_packed_plaintext(vector_of_ints3);
    ciphertexts.push_back(cc->encrypt(kp.public_key, int_array3));

    std::vector<int64_t> vector_of_ints4 = {8, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext int_array4 = cc->make_packed_plaintext(vector_of_ints4);
    ciphertexts.push_back(cc->encrypt(kp.public_key, int_array4));

    std::vector<int64_t> vector_of_ints5 = {16, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext int_array5 = cc->make_packed_plaintext(vector_of_ints5);
    ciphertexts.push_back(cc->encrypt(kp.public_key, int_array5));

    std::cout << "Input ciphertext " << *int_array1 << std::endl;
    std::cout << "Input ciphertext " << *int_array2 << std::endl;
    std::cout << "Input ciphertext " << *int_array3 << std::endl;
    std::cout << "Input ciphertext " << *int_array4 << std::endl;
    std::cout << "Input ciphertext " << *int_array5 << std::endl;

    auto merged_ciphertext = cc->eval_merge(ciphertexts);

    Plaintext int_array_new;

    cc->decrypt(kp.secret_key, merged_ciphertext, &int_array_new);

    int_array_new->set_length(10);

    std::cout << "\nMerged ciphertext " << *int_array_new << std::endl;
}
