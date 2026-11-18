//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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

#include <cmath>
#include <complex>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void print_prime_moduli_chain(const RnsPoly& poly) {
    int num_primes = poly.get_num_of_elements();
    double total_bit_len = 0.0;
    for (int i = 0; i < num_primes; i++) {
        auto qi = poly.get_params()->get_params()[i]->get_modulus();
        std::cout << "q_" << i << ": " << qi << ",  log q_" << i << ": " << std::log2(qi.convert_to_double())
                  << std::endl;
        total_bit_len += std::log2(qi.convert_to_double());
    }
    std::cout << "Total bit length: " << total_bit_len << std::endl;
}

double get_scale_approx_error(const RnsPoly& poly, uint32_t num_primes_value, uint32_t composite_degree,
                              uint32_t first_mod_size_value, uint32_t scaling_mod_size) {
    double delta0 = std::pow(2.0, static_cast<double>(first_mod_size_value));
    double delta = std::pow(2.0, static_cast<double>(scaling_mod_size));
    // uint32_t num_primes_value = poly.get_num_of_elements();
    auto q = poly.get_params()->get_params();

    std::cout << "numPrimes=" << num_primes_value << " compositeDegree=" << composite_degree
              << " firstModSize=" << first_mod_size_value << " scalingModSize=" << scaling_mod_size << std::endl;

    double prod = q[0]->get_modulus().convert_to_double();
    std::cout << "q0_0: " << prod;
    for (uint32_t d = 1; d < composite_degree; ++d) {
        std::cout << " q0_" << d << ": " << q[d]->get_modulus().convert_to_double();
        prod *= q[d]->get_modulus().convert_to_double();
    }
    std::cout << "\n";
    double cum_approx_error = std::abs(delta0 - prod);

    std::cout << "q0: " << prod << " delta0: " << delta0 << " approxErr=" << std::abs(delta0 - prod) << std::endl;

    for (uint32_t i = composite_degree; i < num_primes_value; i += composite_degree) {
        prod = q[i]->get_modulus().convert_to_double();
        std::cout << "q" << i / composite_degree << "_0: " << prod;
        for (uint32_t d = 1; d < composite_degree; ++d) {
            std::cout << " q" << i / composite_degree << "_" << d << ": "
                      << q[i + d]->get_modulus().convert_to_double();
            prod *= q[i + d]->get_modulus().convert_to_double();
        }
        std::cout << "\n";
        cum_approx_error += std::abs(delta - prod);
        std::cout << "q" << i / composite_degree << ": " << prod << " delta: " << delta
                  << " approxErr=" << std::abs(delta - prod) << std::endl;
    }

    std::cout << "Average distance to scaling factor: "
              << cum_approx_error / ((num_primes_value - composite_degree) / composite_degree) << std::endl;

    return cum_approx_error / ((num_primes_value - composite_degree) / composite_degree);
}

int main(int argc, char* argv[]) {
    TimeVar t;

    double time_eval_poly1(0.0), time_eval_poly2(0.0);
    // Parameters for d=4
    // uint32_t first_mod_size_value     = 106;
    // uint32_t scaling_mod_size   = 104;
    // uint32_t register_word_size = 32;
    // Parameters for d=3
    uint32_t first_mod_size_value = 96;
    uint32_t scaling_mod_size = 80;
    uint32_t register_word_size = 32;

    std::cout << "\n======EXAMPLE FOR EVALPOLY========\n" << std::endl;

    uint32_t mult_depth_value = 6;
    int argc_count = 1;
    if (argc > 1) {
        while (argc_count < argc) {
            uint32_t param_value = atoi(argv[argc_count]);
            switch (argc_count) {
                case 1:
                    first_mod_size_value = param_value;
                    std::cout << "Setting First Mod Size: " << first_mod_size_value << std::endl;
                    break;
                case 2:
                    scaling_mod_size = param_value;
                    std::cout << "Setting Scaling Mod Size: " << scaling_mod_size << std::endl;
                    break;
                case 3:
                    register_word_size = param_value;
                    std::cout << "Setting Register Word Size: " << register_word_size << std::endl;
                    break;
                case 4:
                    mult_depth_value = param_value;
                    std::cout << "Setting Multiplicative Depth: " << mult_depth_value << std::endl;
                    break;
                default:
                    std::cout << "Invalid option" << std::endl;
                    break;
            }
            argc_count += 1;
        }

        std::cout << "Completed reading input parameters!" << std::endl;
    } else {
        std::cout << "Using default parameters" << std::endl;
        std::cout << "First Mod Size: " << first_mod_size_value << std::endl;
        std::cout << "Scaling Mod Size: " << scaling_mod_size << std::endl;
        std::cout << "Register Word Size: " << register_word_size << std::endl;
        std::cout << "Multiplicative Depth: " << mult_depth_value << std::endl;
        std::cout << "Usage: " << argv[0] << " [firstModSize] [scalingModSize] [registerWordSize] [multDepth]"
                  << std::endl;
    }

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_mod_size(scaling_mod_size);

    parameters.set_register_word_size(register_word_size);
    parameters.set_scaling_technique(COMPOSITESCALINGAUTO);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    const auto crypto_params_ckksrns = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t composite_degree = crypto_params_ckksrns->get_composite_degree();

    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Composite Degree: " << composite_degree << "\nPrime Moduli Size: "
              << static_cast<float>(scaling_mod_size) / crypto_params_ckksrns->get_composite_degree()
              << "\nRegister Word Size: " << register_word_size << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;

    std::vector<std::complex<double>> input({0.5, 0.7, 0.9, 0.95, 0.93});

    size_t encoded_length = input.size();

    std::vector<double> coefficients1({0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1});
    std::vector<double> coefficients2({1,   2,   3,   4,   5,   -1,   -2,   -3,   -4,   -5,
                                       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5,
                                       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5});

    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input);

    auto key_pair = cc->key_gen();

    std::cout << "Generating evaluation key for homomorphic multiplication...";
    cc->eval_mult_key_gen(key_pair.secret_key);
    std::cout << "Completed." << std::endl;

    const std::vector<RnsPoly>& ckkspk = key_pair.public_key->get_public_elements();
    std::cout << "Moduli chain of pk: " << std::endl;
    print_prime_moduli_chain(ckkspk[0]);

    double avg_scale_error = get_scale_approx_error(ckkspk[0], (mult_depth_value + 1) * composite_degree,
                                                    composite_degree, first_mod_size_value, scaling_mod_size);
    std::cout << "Average Scale Error: " << avg_scale_error << std::endl;

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);

    TIC(t);

    auto result = cc->eval_poly(ciphertext1, coefficients1);

    time_eval_poly1 = TOC(t);

    TIC(t);

    auto result2 = cc->eval_poly(ciphertext1, coefficients2);

    time_eval_poly2 = TOC(t);

    Plaintext plaintext_dec;

    cc->decrypt(key_pair.secret_key, result, &plaintext_dec);

    plaintext_dec->set_length(encoded_length);

    Plaintext plaintext_dec2;

    cc->decrypt(key_pair.secret_key, result2, &plaintext_dec2);

    plaintext_dec2->set_length(encoded_length);

    std::cout << std::setprecision(15) << std::endl;

    std::cout << "\n Original Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\n Result of evaluating a polynomial with coefficients " << coefficients1 << " \n";
    std::cout << plaintext_dec << std::endl;

    std::cout << "\n Expected result: (0.70519107, 1.38285078, 3.97211180, "
                 "5.60215665, 4.86357575) "
              << std::endl;

    std::cout << "\n Evaluation time: " << time_eval_poly1 << " ms" << std::endl;

    std::cout << "\n Result of evaluating a polynomial with coefficients " << coefficients2 << " \n";
    std::cout << plaintext_dec2 << std::endl;

    std::cout << "\n Expected result: (3.4515092326, 5.3752765397, 4.8993108833, "
                 "3.2495023573, 4.0485229982) "
              << std::endl;

    std::cout << "\n Evaluation time: " << time_eval_poly2 << " ms" << std::endl;

    return 0;
}
