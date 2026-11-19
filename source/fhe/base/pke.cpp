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

#include "cipher/fhe/base/pke.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/base/rlwe_params.h"

namespace cipher {

// make_sparse_value is not used by this scheme
template <class Element>
KeyPair<Element> BasePke<Element>::key_gen_internal(CryptoContext<Element> cc, bool make_sparse_value) const {
    const auto crypto_params = std::dynamic_pointer_cast<RlweCryptoParams<Element>>(cc->get_crypto_parameters());
    const auto element_params = crypto_params->get_element_params();
    const auto params_pk = crypto_params->get_params_pk();
    if (!params_pk)
        CIPHER_THROW("precompute_crt_tables() must be called before using precomputed params.");

    // Private Key Generation

    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    TugType tug;

    Element s;
    switch (crypto_params->get_secret_key_dist()) {
        case GAUSSIAN:
            s = Element(dgg, params_pk, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = Element(tug, params_pk, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
        case SPARSE_ENCAPSULATED:
            // https://github.com/openfheorg/openfhe-development/issues/311
            s = Element(tug, params_pk, Format::EVALUATION, 192);
            break;
        default:
            CIPHER_THROW("Unknown SecretKeyDist.");
    }

    // Public Key Generation

    DugType dug;
    Element a(dug, params_pk, Format::EVALUATION);

    Element e(dgg, params_pk, Format::EVALUATION);
    NativeInteger ns = crypto_params->get_noise_scale();

    // b = ns * e - a * s
    Element b(std::move((e *= ns) -= (a * s)));

    auto size_q = element_params->get_params().size();
    auto size_pk = params_pk->get_params().size();
    if (size_pk > size_q)
        s.drop_last_elements(size_pk - size_q);

    KeyPair<Element> key_pair(std::make_shared<PublicKeyImpl<Element>>(cc),
                              std::make_shared<PrivateKeyImpl<Element>>(cc));
    key_pair.secret_key->set_private_element(std::move(s));
    std::vector<Element> pk_elems;
    pk_elems.reserve(2);
    pk_elems.push_back(std::move(b));
    pk_elems.push_back(std::move(a));
    key_pair.public_key->set_public_elements(std::move(pk_elems));
    key_pair.public_key->set_key_tag(key_pair.secret_key->get_key_tag());
    return key_pair;
}

template <class Element>
Ciphertext<Element> BasePke<Element>::encrypt(Element plaintext, const PrivateKey<Element> private_key) const {
    auto ba = encrypt_zero_core(private_key, nullptr);
    (*ba)[0] += plaintext;

    auto ctxt = std::make_shared<CiphertextImpl<Element>>(private_key);
    ctxt->set_elements(std::move(*ba));
    ctxt->set_noise_scale_deg(1);
    return ctxt;
}

template <class Element>
Ciphertext<Element> BasePke<Element>::encrypt(Element plaintext, const PublicKey<Element> public_key) const {
    auto ba = encrypt_zero_core(public_key, nullptr);
    (*ba)[0] += plaintext;

    auto ctxt = std::make_shared<CiphertextImpl<Element>>(public_key);
    ctxt->set_elements(std::move(*ba));
    ctxt->set_noise_scale_deg(1);
    return ctxt;
}

// make_sparse_value is not used by this scheme
template <class Element>
std::shared_ptr<std::vector<Element>> BasePke<Element>::encrypt_zero_core(
        const PrivateKey<Element> private_key, const std::shared_ptr<ParmType> params) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<Element>>(private_key->get_crypto_parameters());
    const auto element_params = (params == nullptr) ? crypto_params->get_element_params() : params;

    DugType dug;
    Element a(dug, element_params, Format::EVALUATION);

    Element e(crypto_params->get_discrete_gaussian_generator(), element_params, Format::EVALUATION);
    NativeInteger ns = crypto_params->get_noise_scale();

    // {b = ns * e - a * s, a}
    Element b(std::move((e *= ns) -= (a * private_key->get_private_element())));

    auto result = std::make_shared<std::vector<Element>>();
    result->reserve(2);
    result->push_back(std::move(b));
    result->push_back(std::move(a));
    return result;
}

// make_sparse_value is not used by this scheme
template <class Element>
std::shared_ptr<std::vector<Element>> BasePke<Element>::encrypt_zero_core(
        const PublicKey<Element> public_key, const std::shared_ptr<ParmType> params) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<Element>>(public_key->get_crypto_parameters());

    const auto ns = crypto_params->get_noise_scale();
    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    TugType tug;

    const std::shared_ptr<ParmType> element_params = (params == nullptr) ? crypto_params->get_element_params() : params;

    const std::vector<Element>& pk = public_key->get_public_elements();

    uint32_t size_q = element_params->get_params().size();
    uint32_t size_pk = pk[0].get_params()->get_params().size();

    // copy only the towers that are still needed, rather than the whole key followed by a drop
    Element p0 = (size_pk > size_q) ? pk[0].clone_towers(0, size_q - 1) : pk[0];
    Element p1 = (size_pk > size_q) ? pk[1].clone_towers(0, size_q - 1) : pk[1];

    Element v = crypto_params->get_secret_key_dist() == GAUSSIAN ? Element(dgg, element_params, Format::EVALUATION) :
                                                                   Element(tug, element_params, Format::EVALUATION);

    // noise generation with the discrete gaussian generator dgg
    Element e0(dgg, element_params, Format::EVALUATION);
    Element e1(dgg, element_params, Format::EVALUATION);

    auto result = std::make_shared<std::vector<Element>>();
    result->reserve(2);
    result->push_back(p0 * v + ns * e0);
    result->push_back(p1 * v + ns * e1);
    return result;
}

template <class Element>
Element BasePke<Element>::decrypt_core(const std::vector<Element>& cv, const PrivateKey<Element> private_key) const {
    const Element& s = private_key->get_private_element();

    Element s_power = s;
    Element b = cv[0];
    b.set_format(Format::EVALUATION);

    Element ci;
    for (size_t i = 1; i < cv.size(); ++i) {
        ci = cv[i];
        ci.set_format(Format::EVALUATION);
        b.mult_acc_eq_no_check(s_power, ci);
        s_power *= s;
    }

    return b;
}

}  // namespace cipher

// the code below is from base-pke-impl.cpp
namespace cipher {

template class BasePke<RnsPoly>;

}  // namespace cipher
