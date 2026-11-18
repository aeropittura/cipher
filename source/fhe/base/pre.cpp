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
#include "cipher/fhe/base/pre.h"

#include <memory>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/base/pke.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

template <class Element>
EvalKey<Element> BasePre<Element>::re_key_gen(const PrivateKey<Element> old_private_key,
                                            const PublicKey<Element> new_public_key) const {
    auto algo = old_private_key->get_crypto_context()->get_scheme();
    return algo->key_switch_gen(old_private_key, new_public_key);
}

template <class Element>
Ciphertext<Element> BasePre<Element>::re_encrypt(ConstCiphertext<Element> ciphertext, const EvalKey<Element> eval_key,
                                                const PublicKey<Element> public_key) const {
    auto algo = ciphertext->get_crypto_context()->get_scheme();
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    Ciphertext<Element> result = ciphertext->clone();
    std::vector<Element>& cv = result->get_elements();
    if (public_key != nullptr) {
        std::shared_ptr<std::vector<Element>> ba = algo->encrypt_zero_core(public_key);

        cv[0] += (*ba)[0];
        cv[1] += (*ba)[1];
    }

    if ((crypto_params->get_pre_mode() == FIXED_NOISE_HRA) || (crypto_params->get_pre_mode() == NOISE_FLOODING_HRA)) {
        // noiseflooding
        Element enf(crypto_params->get_flooding_discrete_gaussian_generator(), crypto_params->get_element_params(),
                    Format::EVALUATION);

        auto noise_scale = crypto_params->get_noise_scale();
        cv[0] += noise_scale * enf;
    }
    algo->key_switch_in_place(result, eval_key);

    return result;
}

}  // namespace cipher

// the code below is from base-pre-impl.cpp
namespace cipher {

template class BasePre<RnsPoly>;

}  // namespace cipher
