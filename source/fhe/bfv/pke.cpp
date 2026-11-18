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

#include "cipher/fhe/bfv/pke.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/bfv/crypto_params.h"

namespace cipher {

KeyPair<RnsPoly> BfvRnsPke::key_gen_internal(CryptoContext<RnsPoly> cc, bool make_sparse_value) const {
    KeyPair<RnsPoly> key_pair(std::make_shared<PublicKeyImpl<RnsPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<RnsPoly>>(cc));

    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters());

    std::shared_ptr<ParmType> element_params = crypto_params->get_element_params();
    if (crypto_params->get_encryption_technique() == EXTENDED) {
        element_params = crypto_params->get_params_qr();
    }
    const std::shared_ptr<ParmType> params_pk = crypto_params->get_params_pk();

    const auto ns = crypto_params->get_noise_scale();
    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    DugType dug;
    TugType tug;

    // Private Key Generation

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

    // Public Key Generation

    RnsPoly a(dug, params_pk, Format::EVALUATION);
    RnsPoly e(dgg, params_pk, Format::EVALUATION);
    RnsPoly b(ns * e - a * s);

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
    key_pair.public_key->set_key_tag(key_pair.secret_key->get_key_tag());

    return key_pair;
}

Ciphertext<RnsPoly> BfvRnsPke::encrypt(RnsPoly ptxt, const PrivateKey<RnsPoly> private_key) const {
    Ciphertext<RnsPoly> ciphertext(std::make_shared<CiphertextImpl<RnsPoly>>(private_key));

    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(private_key->get_crypto_parameters());

    const auto element_params = crypto_params->get_element_params();
    size_t size_q = element_params->get_params().size();

    auto enc_params = ptxt.get_params();
    size_t size_p = enc_params->get_params().size();

    // enables encoding of plaintexts using a smaller number of RNS limbs
    size_t level = size_q - size_p;

    std::vector<NativeInteger> t_inv_modq = crypto_params->get_t_inv_modq();
    if (crypto_params->get_encryption_technique() == EXTENDED) {
        enc_params = crypto_params->get_params_qr();
        ptxt.set_format(Format::COEFFICIENT);
        Poly big_ptxt = ptxt.crt_interpolate();
        RnsPoly plain(big_ptxt, enc_params);
        ptxt = plain;
        t_inv_modq = crypto_params->get_t_inv_modqr();
    }
    ptxt.set_format(Format::COEFFICIENT);

    std::shared_ptr<std::vector<RnsPoly>> ba = encrypt_zero_core(private_key, enc_params);

    NativeInteger neg_q_modt = crypto_params->get_neg_q_modt(level);
    NativeInteger neg_q_modt_precon = crypto_params->get_neg_q_modt_precon(level);

    if (crypto_params->get_encryption_technique() == EXTENDED) {
        neg_q_modt = crypto_params->get_neg_qr_modt();
        neg_q_modt_precon = crypto_params->get_neg_qr_modt_precon();
    }

    const NativeInteger t = crypto_params->get_plaintext_modulus();

    ptxt.times_qovert(enc_params, t_inv_modq, t, neg_q_modt, neg_q_modt_precon);
    ptxt.set_format(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].set_format(Format::COEFFICIENT);
    (*ba)[1].set_format(Format::COEFFICIENT);

    if (crypto_params->get_encryption_technique() == EXTENDED) {
        (*ba)[0].scale_and_round_p_over_q(element_params, crypto_params->get_r_inv_modq());
        (*ba)[1].scale_and_round_p_over_q(element_params, crypto_params->get_r_inv_modq());
    }

    (*ba)[0].set_format(Format::EVALUATION);
    (*ba)[1].set_format(Format::EVALUATION);

    ciphertext->set_elements(std::move(*ba));
    ciphertext->set_noise_scale_deg(1);

    return ciphertext;
}

Ciphertext<RnsPoly> BfvRnsPke::encrypt(RnsPoly ptxt, const PublicKey<RnsPoly> public_key) const {
    Ciphertext<RnsPoly> ciphertext(std::make_shared<CiphertextImpl<RnsPoly>>(public_key));

    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(public_key->get_crypto_parameters());

    const auto element_params = crypto_params->get_element_params();
    size_t size_q = element_params->get_params().size();

    auto enc_params = ptxt.get_params();
    size_t size_p = enc_params->get_params().size();

    // enables encoding of plaintexts using a smaller number of RNS limbs
    size_t level = size_q - size_p;

    std::vector<NativeInteger> t_inv_modq = crypto_params->get_t_inv_modq();
    if (crypto_params->get_encryption_technique() == EXTENDED) {
        enc_params = crypto_params->get_params_qr();
        ptxt.set_format(Format::COEFFICIENT);
        Poly big_ptxt = ptxt.crt_interpolate();
        RnsPoly plain(big_ptxt, enc_params);
        ptxt = plain;
        t_inv_modq = crypto_params->get_t_inv_modqr();
    }
    ptxt.set_format(Format::COEFFICIENT);

    std::shared_ptr<std::vector<RnsPoly>> ba = encrypt_zero_core(public_key, enc_params);

    NativeInteger neg_q_modt = crypto_params->get_neg_q_modt(level);
    NativeInteger neg_q_modt_precon = crypto_params->get_neg_q_modt_precon(level);

    if (crypto_params->get_encryption_technique() == EXTENDED) {
        neg_q_modt = crypto_params->get_neg_qr_modt();
        neg_q_modt_precon = crypto_params->get_neg_qr_modt_precon();
    }

    const NativeInteger t = crypto_params->get_plaintext_modulus();

    ptxt.times_qovert(enc_params, t_inv_modq, t, neg_q_modt, neg_q_modt_precon);
    ptxt.set_format(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].set_format(Format::COEFFICIENT);
    (*ba)[1].set_format(Format::COEFFICIENT);

    if (crypto_params->get_encryption_technique() == EXTENDED) {
        (*ba)[0].scale_and_round_p_over_q(element_params, crypto_params->get_r_inv_modq());
        (*ba)[1].scale_and_round_p_over_q(element_params, crypto_params->get_r_inv_modq());
    }

    (*ba)[0].set_format(Format::EVALUATION);
    (*ba)[1].set_format(Format::EVALUATION);

    ciphertext->set_elements(std::move(*ba));
    ciphertext->set_noise_scale_deg(1);

    return ciphertext;
}

DecryptResult BfvRnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                                 NativePoly* plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(private_key->get_crypto_parameters());

    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly b = decrypt_core(cv, private_key);

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
