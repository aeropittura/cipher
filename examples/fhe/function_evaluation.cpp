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
  Example of evaluating arbitrary smooth functions with the Chebyshev approximation using CKKS.
 */

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/math/chebyshev.h"
#include "cipher/cipher.h"

using namespace cipher;

void eval_logistic_example();

void eval_function_example();

int main(int argc, char* argv[]) {
    eval_logistic_example();
    eval_function_example();
    return 0;
}

// In this example, we evaluate the logistic function 1 / (1 + exp(-x)) on an input of doubles
void eval_logistic_example() {
    std::cout << "--------------------------------- EVAL LOGISTIC FUNCTION ---------------------------------"
              << std::endl;
    ContextParams<CkksRnsContext> parameters;

    // We set a smaller ring dimension to improve performance for this example.
    // In production environments, the security level should be set to
    // HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    // or 256-bit security, respectively.
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 10);
#if CIPHER_NATIVE_INT == 128
    uint32_t scaling_mod_size = 78;
    uint32_t first_mod_size_value = 89;
#else
    uint32_t scaling_mod_size = 50;
    uint32_t first_mod_size_value = 60;
#endif
    parameters.set_scaling_mod_size(scaling_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);

    // Choosing a higher degree yields better precision, but a longer runtime.
    uint32_t poly_degree = 16;

    // The multiplicative depth depends on the polynomial degree.
    // See the FUNCTION_EVALUATION.md file for a table mapping polynomial degrees to multiplicative depths.
    uint32_t mult_depth_value = 6;

    parameters.set_multiplicative_depth(mult_depth_value);
    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    // We need to enable Advanced SHE to use the Chebyshev approximation.
    cc->enable(ADVANCEDSHE);

    auto key_pair = cc->key_gen();
    // We need to generate mult keys to run Chebyshev approximations.
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
    size_t encoded_length = input.size();
    Plaintext plaintext = cc->make_ckks_packed_plaintext(input);
    auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    double lower_bound = -5;
    double upper_bound = 5;
    auto result = cc->eval_logistic(ciphertext, lower_bound, upper_bound, poly_degree);

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, result, &plaintext_dec);
    plaintext_dec->set_length(encoded_length);

    std::vector<std::complex<double>> expected_output(
            {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});
    std::cout << "Expected output\n\t" << expected_output << std::endl;

    std::vector<std::complex<double>> final_result = plaintext_dec->get_ckks_packed_value();
    std::cout << "Actual output\n\t" << final_result << std::endl << std::endl;
}

void eval_function_example() {
    std::cout << "--------------------------------- EVAL SQUARE ROOT FUNCTION ---------------------------------"
              << std::endl;
    ContextParams<CkksRnsContext> parameters;

    // We set a smaller ring dimension to improve performance for this example.
    // In production environments, the security level should be set to
    // HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    // or 256-bit security, respectively.
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 10);
#if CIPHER_NATIVE_INT == 128
    uint32_t scaling_mod_size = 78;
    uint32_t first_mod_size_value = 89;
#else
    uint32_t scaling_mod_size = 50;
    uint32_t first_mod_size_value = 60;
#endif
    parameters.set_scaling_mod_size(scaling_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);

    // Choosing a higher degree yields better precision, but a longer runtime.
    uint32_t poly_degree = 50;

    // The multiplicative depth depends on the polynomial degree.
    // See the FUNCTION_EVALUATION.md file for a table mapping polynomial degrees to multiplicative depths.
    uint32_t mult_depth_value = 7;

    parameters.set_multiplicative_depth(mult_depth_value);
    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    // We need to enable Advanced SHE to use the Chebyshev approximation.
    cc->enable(ADVANCEDSHE);

    auto key_pair = cc->key_gen();
    // We need to generate mult keys to run Chebyshev approximations.
    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<std::complex<double>> input{1, 2, 3, 4, 5, 6, 7, 8, 9};
    size_t encoded_length = input.size();
    Plaintext plaintext = cc->make_ckks_packed_plaintext(input);
    auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);

    double lower_bound = 0;
    double upper_bound = 10;

    // We can input any lambda function, which inputs a double and returns a double.
    auto result = cc->eval_chebyshev_function([](double x) -> double { return std::sqrt(x); }, ciphertext, lower_bound,
                                              upper_bound, poly_degree);

    Plaintext plaintext_dec;
    cc->decrypt(key_pair.secret_key, result, &plaintext_dec);
    plaintext_dec->set_length(encoded_length);

    std::vector<std::complex<double>> expected_output(
            {1, 1.414213, 1.732050, 2, 2.236067, 2.449489, 2.645751, 2.828427, 3});
    std::cout << "Expected output\n\t" << expected_output << std::endl;

    // Compute the same approximation on cleartext data
    std::vector<double> input_double{1, 2, 3, 4, 5, 6, 7, 8, 9};
    auto ptxt_approx = eval_chebyshev_function_ptxt([](double x) -> double { return std::sqrt(x); }, input_double,
                                                    lower_bound, upper_bound, poly_degree);
    std::cout << "Cleartext output\n\t" << ptxt_approx << std::endl;

    std::vector<std::complex<double>> final_result = plaintext_dec->get_ckks_packed_value();
    std::cout << "Actual output\n\t" << final_result << std::endl << std::endl;
}
