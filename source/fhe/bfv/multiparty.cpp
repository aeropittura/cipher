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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cipher/fhe/bfv/multiparty.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/bfv/crypto_params.h"

namespace cipher {

// make_sparse_value is not used by this scheme
KeyPair<RnsPoly> BfvRnsMultiparty::multiparty_key_gen(CryptoContext<RnsPoly> cc,
                                                      const std::vector<PrivateKey<RnsPoly>>& private_key_vec,
                                                      bool make_sparse_value) {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(cc->get_crypto_parameters());

    KeyPair<RnsPoly> key_pair(std::make_shared<PublicKeyImpl<RnsPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<RnsPoly>>(cc));

    auto element_params = crypto_params->get_element_params();
    if (crypto_params->get_encryption_technique() == EXTENDED) {
        element_params = crypto_params->get_params_qr();
    }
    const auto ns = crypto_params->get_noise_scale();

    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    DugType dug;

    // Private Key Generation

    RnsPoly s(element_params, Format::EVALUATION, true);

    for (auto& pk : private_key_vec) {
        const RnsPoly& si = pk->get_private_element();
        s += si;
    }

    // Public Key Generation
    RnsPoly a(dug, element_params, Format::EVALUATION);
    RnsPoly e(dgg, element_params, Format::EVALUATION);
    RnsPoly b(ns * e - a * s);

    key_pair.secret_key->set_private_element(std::move(s));
    std::vector<RnsPoly> pk_elems;
    pk_elems.reserve(2);
    pk_elems.push_back(std::move(b));
    pk_elems.push_back(std::move(a));
    key_pair.public_key->set_public_elements(std::move(pk_elems));

    return key_pair;
}

KeyPair<RnsPoly> BfvRnsMultiparty::multiparty_key_gen(CryptoContext<RnsPoly> cc, const PublicKey<RnsPoly> public_key,
                                                      bool make_sparse_value, bool fresh) {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(cc->get_crypto_parameters());

    KeyPair<RnsPoly> key_pair(std::make_shared<PublicKeyImpl<RnsPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<RnsPoly>>(cc));

    auto element_params = crypto_params->get_element_params();
    if (crypto_params->get_encryption_technique() == EXTENDED) {
        element_params = crypto_params->get_params_qr();
    }
    const auto params_pk = crypto_params->get_params_pk();

    const auto ns = crypto_params->get_noise_scale();

    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    TugType tug;

    RnsPoly s;
    switch (crypto_params->get_secret_key_dist()) {
        case GAUSSIAN:
            s = RnsPoly(dgg, params_pk, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = RnsPoly(tug, params_pk, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
            s = RnsPoly(tug, params_pk, Format::EVALUATION, 192);
            break;
        default:
            break;
    }

    const std::vector<RnsPoly>& pk = public_key->get_public_elements();

    RnsPoly a = pk[1];
    RnsPoly e(dgg, params_pk, Format::EVALUATION);

    // When PRE is not used, a joint key is computed
    RnsPoly b = fresh ? (ns * e - a * s) : (ns * e - a * s + pk[0]);

    uint32_t size_q = element_params->get_params().size();
    uint32_t size_pk = params_pk->get_params().size();
    if (size_pk > size_q) {
        s.drop_last_elements(size_pk - size_q);
    }

    key_pair.secret_key->set_private_element(std::move(s));
    std::vector<RnsPoly> pk_elems;
    pk_elems.reserve(2);
    pk_elems.push_back(std::move(b));
    pk_elems.push_back(std::move(a));
    key_pair.public_key->set_public_elements(std::move(pk_elems));

    return key_pair;
}

DecryptResult BfvRnsMultiparty::multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                                          NativePoly* plaintext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());

    const std::vector<RnsPoly>& cv0 = ciphertext_vec[0]->get_elements();

    RnsPoly b = cv0[0];
    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        const std::vector<RnsPoly>& cvi = ciphertext_vec[i]->get_elements();
        b += cvi[0];
    }

    size_t size_ql = b.get_num_of_elements();

    const auto element_params = crypto_params->get_element_params();
    size_t size_q = element_params->get_params().size();

    // use RNS procedures only if the number of RNS limbs is the same as for fresh ciphertexts
    if (size_ql == size_q) {
        b.set_format(Format::COEFFICIENT);
        if (crypto_params->get_multiplication_technique() == HPS ||
            crypto_params->get_multiplication_technique() == HPSPOVERQ ||
            crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) {
            *plaintext = b.scale_and_round(
                    crypto_params->get_plaintext_modulus(), crypto_params->get_t_q_hat_inv_modq_divq_modt(),
                    crypto_params->get_t_q_hat_inv_modq_divq_modt_precon(),
                    crypto_params->get_t_q_hat_inv_modq_b_divq_modt(),
                    crypto_params->get_t_q_hat_inv_modq_b_divq_modt_precon(),
                    crypto_params->get_t_q_hat_inv_modq_divq_frac(), crypto_params->get_t_q_hat_inv_modq_b_divq_frac());
        } else {
            *plaintext = b.scale_and_round(
                    crypto_params->get_moduli_q(), crypto_params->get_plaintext_modulus(), crypto_params->get_tgamma(),
                    crypto_params->get_tgamma_q_hat_inv_modq(), crypto_params->get_tgamma_q_hat_inv_modq_precon(),
                    crypto_params->get_neg_invq_modtgamma(), crypto_params->get_neg_invq_modtgamma_precon());
        }
    } else {
        // for the case when compress was called, we automatically reduce the polynomial to 1 RNS limb
        size_t diff_ql = size_q - size_ql;
        size_t levels = size_ql - 1;
        for (size_t l = 0; l < levels; ++l) {
            b.drop_last_element_and_scale(crypto_params->get_ql_inv_modq(diff_ql + l));
        }

        b.set_format(Format::COEFFICIENT);

        const NativeInteger t = crypto_params->get_plaintext_modulus();
        NativePoly element = b.get_element_at_index(0);
        const NativeInteger q = element.get_modulus();
        element = element.multiply_and_round(t, q);

        // Setting the root of unity to ONE as the calculation is expensive
        // It is assumed that no polynomial multiplications in evaluation
        // representation are performed after this
        element.switch_modulus(t, 1, 0, 0);

        *plaintext = element;
    }

    return DecryptResult(plaintext->get_length());
}

}  // namespace cipher
