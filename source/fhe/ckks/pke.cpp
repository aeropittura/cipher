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
CKKS implementation. If NOISE_FLOODING_DECRYPT is set, we flood the decryption bits with noise.
 */

#define PROFILE

#include "cipher/fhe/ckks/pke.h"

#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/ckks/crypto_params.h"

namespace cipher {

DecryptResult CkksRnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                                  NativePoly* plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly b = decrypt_core(cv, private_key);
    if (crypto_params->get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
        crypto_params->get_execution_mode() == EXEC_EVALUATION) {
        auto dgg = crypto_params->get_flooding_discrete_gaussian_generator();
        RnsPoly noise(dgg, cv[0].get_params(), Format::EVALUATION);
        b += noise;
    }

    b.set_format(Format::COEFFICIENT);
    const size_t size_ql = b.get_params()->get_params().size();

    if (size_ql != 1) {
        CIPHER_THROW(
                "size_ql " + std::to_string(size_ql) +
                "!= 1. If size_ql = 0, consider increasing the depth. If size_ql > 1, check parameters (this is unsupported for NativePoly).");
    }

    *plaintext = b.get_element_at_index(0);

    return DecryptResult(plaintext->get_length());
}

DecryptResult CkksRnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                                  Poly* plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    RnsPoly b = decrypt_core(cv, private_key);
    if (crypto_params->get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
        crypto_params->get_execution_mode() == EXEC_EVALUATION) {
        auto dgg = crypto_params->get_flooding_discrete_gaussian_generator();
        RnsPoly noise(dgg, cv[0].get_params(), Format::EVALUATION);
        b += noise;
    }

    b.set_format(Format::COEFFICIENT);
    const size_t size_ql = b.get_params()->get_params().size();

    if (size_ql == 0)
        CIPHER_THROW("No towers left; consider increasing the depth.");

    if (size_ql == 1) {
        *plaintext = Poly(b.get_element_at_index(0), Format::COEFFICIENT);
    } else {
        *plaintext = b.crt_interpolate();
    }

    return DecryptResult(plaintext->get_length());
}

}  // namespace cipher
