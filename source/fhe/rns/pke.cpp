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
#include "cipher/fhe/rns/pke.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/rns/crypto_params.h"

namespace cipher {

Ciphertext<RnsPoly> RnsPke::encrypt(RnsPoly plaintext, const PrivateKey<RnsPoly> private_key) const {
    Ciphertext<RnsPoly> ciphertext(std::make_shared<CiphertextImpl<RnsPoly>>(private_key));

    const std::shared_ptr<ParmType> ptxt_params = plaintext.get_params();
    std::shared_ptr<std::vector<RnsPoly>> ba = encrypt_zero_core(private_key, ptxt_params);

    plaintext.set_format(EVALUATION);

    (*ba)[0] += plaintext;

    ciphertext->set_elements(std::move(*ba));
    ciphertext->set_noise_scale_deg(1);

    return ciphertext;
}

Ciphertext<RnsPoly> RnsPke::encrypt(RnsPoly plaintext, const PublicKey<RnsPoly> public_key) const {
    Ciphertext<RnsPoly> ciphertext(std::make_shared<CiphertextImpl<RnsPoly>>(public_key));

    const std::shared_ptr<ParmType> ptxt_params = plaintext.get_params();
    std::shared_ptr<std::vector<RnsPoly>> ba = encrypt_zero_core(public_key, ptxt_params);

    plaintext.set_format(EVALUATION);

    (*ba)[0] += plaintext;

    ciphertext->set_elements(std::move(*ba));
    ciphertext->set_noise_scale_deg(1);

    return ciphertext;
}

DecryptResult RnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                              Poly* plaintext) const {
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly b = decrypt_core(cv, private_key);

    b.set_format(Format::COEFFICIENT);
    size_t size_ql = b.get_params()->get_params().size();

    if (size_ql == 0)
        CIPHER_THROW("Decryption failure: No towers left; consider increasing the depth.");

    if (size_ql == 1) {
        *plaintext = Poly(b.get_element_at_index(0), Format::COEFFICIENT);
    } else {
        *plaintext = b.crt_interpolate();
    }

    return DecryptResult(plaintext->get_length());
}

DecryptResult RnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                              NativePoly* plaintext) const {
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly b = decrypt_core(cv, private_key);

    b.set_format(Format::COEFFICIENT);
    const size_t size_ql = b.get_params()->get_params().size();
    if (size_ql != 1) {
        CIPHER_THROW(
                "sizeQl " + std::to_string(size_ql) +
                "!= 1. If sizeQl = 0, consider increasing the depth. If sizeQl > 1, check parameters (this is unsupported for NativePoly).");
    }

    *plaintext = b.get_element_at_index(0);

    return DecryptResult(plaintext->get_length());
}

std::shared_ptr<std::vector<RnsPoly>> RnsPke::encrypt_zero_core(const PrivateKey<RnsPoly> private_key,
                                                                const std::shared_ptr<ParmType> params) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(private_key->get_crypto_parameters());

    const RnsPoly& s = private_key->get_private_element();
    const auto ns = crypto_params->get_noise_scale();
    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    DugType dug;

    const std::shared_ptr<ParmType> element_params = (params == nullptr) ? crypto_params->get_element_params() : params;

    RnsPoly a(dug, element_params, Format::EVALUATION);
    RnsPoly e(dgg, element_params, Format::EVALUATION);

    uint32_t size_q = s.get_params()->get_params().size();
    uint32_t size_ql = element_params->get_params().size();

    RnsPoly c0, c1;
    if (size_ql != size_q) {
        // Clone only the towers of the secret key that are still needed.
        RnsPoly scopy = s.clone_towers(0, size_ql - 1);

        c0 = a * scopy + ns * e;
        c1 = -a;
    } else {
        // Use secret key as is
        c0 = a * s + ns * e;
        c1 = -a;
    }

    auto result = std::make_shared<std::vector<RnsPoly>>();
    result->reserve(2);
    result->push_back(std::move(c0));
    result->push_back(std::move(c1));
    return result;
}

std::shared_ptr<std::vector<RnsPoly>> RnsPke::encrypt_zero_core(const PublicKey<RnsPoly> public_key,
                                                                const std::shared_ptr<ParmType> params) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(public_key->get_crypto_parameters());

    const std::vector<RnsPoly>& pk = public_key->get_public_elements();
    const auto ns = crypto_params->get_noise_scale();
    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();

    TugType tug;

    const std::shared_ptr<ParmType> element_params = (params == nullptr) ? crypto_params->get_element_params() : params;
    // TODO (dsuponit): "tug" must be assigned with TernaryUniformGenerator. Otherwise the RnsPoly constructor crashes.
    // check other files if "tug" is properly assigned
    // if (crypto_params->get_secret_key_dist() != GAUSSIAN) {
    //    CIPHER_THROW("TugType tug must be assigned");
    //}
    RnsPoly v = crypto_params->get_secret_key_dist() == GAUSSIAN ? RnsPoly(dgg, element_params, Format::EVALUATION) :
                                                                   RnsPoly(tug, element_params, Format::EVALUATION);

    // noise generation with the discrete gaussian generator dgg
    RnsPoly e0(dgg, element_params, Format::EVALUATION);
    RnsPoly e1(dgg, element_params, Format::EVALUATION);

    uint32_t size_q = pk[0].get_params()->get_params().size();
    uint32_t size_ql = element_params->get_params().size();

    RnsPoly c0, c1;
    if (size_ql != size_q) {
        // Clone only the towers of the public keys that are still needed.
        RnsPoly p0 = pk[0].clone_towers(0, size_ql - 1);
        RnsPoly p1 = pk[1].clone_towers(0, size_ql - 1);

        c0 = p0 * v + ns * e0;
        c1 = p1 * v + ns * e1;
    } else {
        // Use public keys as they are
        const RnsPoly& p0 = pk[0];
        const RnsPoly& p1 = pk[1];

        c0 = p0 * v + ns * e0;
        c1 = p1 * v + ns * e1;
    }

    auto result = std::make_shared<std::vector<RnsPoly>>();
    result->reserve(2);
    result->push_back(std::move(c0));
    result->push_back(std::move(c1));
    return result;
}

RnsPoly RnsPke::decrypt_core(const std::vector<RnsPoly>& cv, const PrivateKey<RnsPoly> private_key) const {
    const RnsPoly& s = private_key->get_private_element();

    size_t size_ql = cv[0].get_params()->get_params().size();
    auto scopy = s.clone_towers(0, size_ql - 1);

    RnsPoly s_power(scopy);

    RnsPoly b(cv[0]);
    b.set_format(Format::EVALUATION);

    RnsPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.set_format(Format::EVALUATION);

        b.mult_acc_eq_no_check(s_power, ci);
        s_power *= scopy;
    }
    return b;
}

}  // namespace cipher
