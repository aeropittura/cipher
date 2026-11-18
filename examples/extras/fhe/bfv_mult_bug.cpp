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
  Simple example for BFVrns (integer arithmetic)
 */

#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void eval_noise_bfv(PrivateKey<RnsPoly> private_key, ConstCiphertext<RnsPoly> ciphertext, Plaintext ptxt, uint32_t ptm,
                    double& noise, double& log_q);

int main() {
    ContextParams<BfvRnsContext> parameters;
    uint64_t ptm = 786433;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplication_technique(HPSPOVERQ);  // BEHZ, HPS, HPSPOVERQ, HPSPOVERQLEVELED
    parameters.set_multiplicative_depth(67);             // 50, 100, 150

    // For speed
    parameters.set_security_level(SecurityLevel::HEStd_NotSet);
    parameters.set_ring_dim(1024);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // Enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    // Generate a public/private key pair
    key_pair = crypto_context->key_gen();

    // Generate the relinearization key
    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    // First plaintext vector is encoded
    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

    // The encoded vectors are encrypted
    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

    // Homomorphic multiplications
    auto ciphertext_mul12 = crypto_context->eval_mult(ciphertext1, ciphertext2);

    // Decrypt the result of multiplications
    Plaintext plaintext_mult_result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12, &plaintext_mult_result);
    plaintext_mult_result->set_length(vector_of_ints1.size());
    std::vector<int64_t> decvec = plaintext_mult_result->get_packed_value();
    Plaintext d_res = crypto_context->make_packed_plaintext(decvec);

    // Decrypt the result of 1 and 2
    Plaintext plaintext1_result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext1, &plaintext1_result);
    plaintext1_result->set_length(vector_of_ints1.size());
    std::vector<int64_t> decvec1 = plaintext1_result->get_packed_value();
    Plaintext d_res1 = crypto_context->make_packed_plaintext(decvec1);

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1:      " << plaintext1_result << std::endl;
    std::cout << "#1 * #2: " << plaintext_mult_result << std::endl;

    double noise = 0, log_q = 0;
    eval_noise_bfv(key_pair.secret_key, ciphertext_mul12, d_res, ptm, noise, log_q);
    eval_noise_bfv(key_pair.secret_key, ciphertext1, d_res1, ptm, noise, log_q);
    return 0;
}

void eval_noise_bfv(PrivateKey<RnsPoly> private_key, ConstCiphertext<RnsPoly> ciphertext, Plaintext ptxt, uint32_t ptm,
                    double& noise, double& log_q) {
    const auto crypto_params = std::static_pointer_cast<BfvRnsCryptoParams>(private_key->get_crypto_parameters());

    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly s = private_key->get_private_element();

    size_t size_ql = cv[0].get_params()->get_params().size();
    size_t size_qs = s.get_params()->get_params().size();

    size_t diff_ql = size_qs - size_ql;

    auto scopy(s);
    scopy.drop_last_elements(diff_ql);

    RnsPoly s_power(scopy);

    RnsPoly b = cv[0];
    b.set_format(Format::EVALUATION);

    RnsPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.set_format(Format::EVALUATION);

        b += s_power * ci;
        s_power *= scopy;
    }

    const auto enc_params = crypto_params->get_element_params();
    NativeInteger neg_q_modt = crypto_params->get_neg_q_modt();
    NativeInteger neg_q_modt_precon = crypto_params->get_neg_q_modt_precon();
    const NativeInteger t = crypto_params->get_plaintext_modulus();
    std::vector<NativeInteger> t_inv_modq = crypto_params->get_t_inv_modq();

    RnsPoly plain = ptxt->get_element<RnsPoly>();
    plain.set_format(Format::COEFFICIENT);
    plain.times_qovert(enc_params, t_inv_modq, t, neg_q_modt, neg_q_modt_precon);
    plain.set_format(Format::EVALUATION);
    RnsPoly res;
    res = b - plain;

    // Converts back to coefficient representation
    res.set_format(Format::COEFFICIENT);
    size_t size_q = crypto_params->get_element_params()->get_params().size();
    noise = (std::log2(res.norm()));

    log_q = 0;
    for (uint32_t i = 0; i < size_q; i++) {
        double logqi = std::log2(crypto_params->get_element_params()->get_params()[i]->get_modulus().convert_to_int());
        log_q += logqi;
    }

    std::cout << "logQ: " << log_q << std::endl;
    std::cout << "noise: " << noise << std::endl;
}
