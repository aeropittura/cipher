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

#include "cipher/fhe/base/multiparty.h"

#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/eval_key.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/base/pke.h"
#include "cipher/fhe/base/scheme.h"
#include "cipher/fhe/base/rlwe_params.h"

namespace cipher {

// make_sparse_value is not used by this scheme
template <class Element>
KeyPair<Element> BaseMultiparty<Element>::multiparty_key_gen(CryptoContext<Element> cc,
                                                             const std::vector<PrivateKey<Element>>& private_key_vec,
                                                             bool make_sparse_value) {
    const auto crypto_params = std::dynamic_pointer_cast<RlweCryptoParams<Element>>(cc->get_crypto_parameters());
    const auto element_params = crypto_params->get_element_params();

    // Private Key Generation

    Element s(element_params, Format::EVALUATION, true);
    for (auto& pk : private_key_vec)
        s += pk->get_private_element();

    // Public Key Generation

    DugType dug;
    Element a(dug, element_params, Format::EVALUATION);

    Element e(crypto_params->get_discrete_gaussian_generator(), element_params, Format::EVALUATION);
    NativeInteger ns = crypto_params->get_noise_scale();

    // b = ns * e - a * s
    if (ns != 1)
        e *= ns;
    Element b(std::move(e -= a * s));

    KeyPair<Element> key_pair(std::make_shared<PublicKeyImpl<Element>>(cc),
                              std::make_shared<PrivateKeyImpl<Element>>(cc));
    key_pair.secret_key->set_private_element(std::move(s));
    std::vector<Element> pk_elems;
    pk_elems.reserve(2);
    pk_elems.push_back(std::move(b));
    pk_elems.push_back(std::move(a));
    key_pair.public_key->set_public_elements(std::move(pk_elems));
    return key_pair;
}

template <class Element>
KeyPair<Element> BaseMultiparty<Element>::multiparty_key_gen(CryptoContext<Element> cc,
                                                             const PublicKey<Element> public_key,
                                                             bool make_sparse_value, bool fresh) {
    const auto crypto_params = std::dynamic_pointer_cast<RlweCryptoParams<Element>>(cc->get_crypto_parameters());
    const auto element_params = crypto_params->get_element_params();
    const auto params_pk = crypto_params->get_params_pk();
    if (!params_pk)
        CIPHER_THROW("PrecomputeCRTTables() must be called before using precomputed params.");

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
            s = Element(tug, params_pk, Format::EVALUATION, 192);
            break;
        default:
            CIPHER_THROW("Unknown SecretKeyDist.");
    }

    const auto& pk = public_key->get_public_elements();
    Element a(pk[1]);
    Element e(dgg, params_pk, Format::EVALUATION);
    NativeInteger ns = crypto_params->get_noise_scale();

    // b = ns * e - a * s
    // When PRE is not used, a joint key is computed
    if (ns != 1)
        e *= ns;
    Element b(std::move(e -= a * s));
    if (!fresh)
        b += pk[0];

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
    return key_pair;
}

template <class Element>
EvalKey<Element> BaseMultiparty<Element>::multi_key_switch_gen(const PrivateKey<Element> old_private_key,
                                                               const PrivateKey<Element> new_private_key,
                                                               const EvalKey<Element> eval_key) const {
    return old_private_key->get_crypto_context()->get_scheme()->key_switch_gen(old_private_key, new_private_key,
                                                                               eval_key);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseMultiparty<Element>::multi_eval_automorphism_key_gen(
        const PrivateKey<Element> private_key, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
        const std::vector<uint32_t>& index_list) const {
    const Element& s = private_key->get_private_element();
    uint32_t N = s.get_ring_dimension();

    if (index_list.size() > N - 1)
        CIPHER_THROW("size exceeds the ring dimension");

    const auto cc = private_key->get_crypto_context();

    // deduplicated work list; the base keys are looked up (and missing ones reported) before
    // the parallel loop because an exception may not cross an OpenMP region boundary
    const std::set<uint32_t> index_set(index_list.begin(), index_list.end());
    const std::vector<uint32_t> indices(index_set.begin(), index_set.end());
    const uint32_t sz = indices.size();
    std::vector<EvalKey<Element>> base_keys(sz);
    for (uint32_t i = 0; i < sz; ++i) {
        auto eval_key_iterator = eval_key_map->find(indices[i]);
        if (eval_key_iterator == eval_key_map->end()) {
            CIPHER_THROW("EvalKey for index [" + std::to_string(indices[i]) + "] is not found.");
        }
        base_keys[i] = eval_key_iterator->second;
    }

    // pre-created map slots so the parallel loop assigns without a critical section
    auto result = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();
    for (auto indx : indices)
        (*result)[indx];

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(sz))
    for (uint32_t i = 0; i < sz; ++i) {
        uint32_t index = NativeInteger(indices[i]).mod_inverse(2 * N).convert_to_int();
        std::vector<uint32_t> vec(N);
        precompute_auto_map(N, index, &vec);

        auto private_key_permuted = std::make_shared<PrivateKeyImpl<Element>>(cc);
        private_key_permuted->set_private_element(s.automorphism_transform(index, vec));

        (*result)[indices[i]] = multi_key_switch_gen(private_key, private_key_permuted, base_keys[i]);
    }
    return result;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseMultiparty<Element>::multi_eval_at_index_key_gen(
        const PrivateKey<Element> private_key, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
        const std::vector<int32_t>& index_list) const {
    std::vector<uint32_t> auto_indices(index_list.size());
    const auto cc = private_key->get_crypto_context();
    const uint32_t M = private_key->get_crypto_parameters()->get_element_params()->get_cyclotomic_order();
    for (size_t i = 0; i < index_list.size(); i++)
        auto_indices[i] = cc->get_scheme()->find_automorphism_index(index_list[i], M);
    return multi_eval_automorphism_key_gen(private_key, eval_key_map, auto_indices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseMultiparty<Element>::multi_eval_sum_key_gen(
        const PrivateKey<Element> private_key,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map) const {
    const std::set<uint32_t> index_set{BaseAdvancedShe<Element>::generate_index_list_for_eval_sum(private_key)};
    std::vector<uint32_t> indices(index_set.begin(), index_set.end());
    return multi_eval_automorphism_key_gen(private_key, eval_key_map, indices);
}

template <class Element>
Ciphertext<Element> BaseMultiparty<Element>::multiparty_decrypt_lead(ConstCiphertext<Element> ciphertext,
                                                                     const PrivateKey<Element> private_key) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<Element>>(private_key->get_crypto_parameters());

    const std::shared_ptr<ParmType> element_params = crypto_params->get_element_params();
    const auto ns = crypto_params->get_noise_scale();

    const std::vector<Element>& cv = ciphertext->get_elements();
    const Element& s = private_key->get_private_element();

    DggType dgg(NoiseFlooding::MP_SD);
    Element e(dgg, element_params, Format::EVALUATION);
    if (ns != 1)
        e *= typename Element::Integer(ns);
    auto result = ciphertext->clone_empty();
    result->set_element(cv[0] + s * cv[1] + e);
    return result;
}

template <class Element>
Ciphertext<Element> BaseMultiparty<Element>::multiparty_decrypt_main(ConstCiphertext<Element> ciphertext,
                                                                     const PrivateKey<Element> private_key) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<Element>>(private_key->get_crypto_parameters());

    const std::shared_ptr<ParmType> element_params = crypto_params->get_element_params();
    const auto es = crypto_params->get_noise_scale();

    const std::vector<Element>& cv = ciphertext->get_elements();
    const Element& s = private_key->get_private_element();

    DggType dgg(NoiseFlooding::MP_SD);
    Element e(dgg, element_params, Format::EVALUATION);
    if (es != 1)
        e *= typename Element::Integer(es);
    auto result = ciphertext->clone_empty();
    result->set_element(s * cv[1] + e);
    return result;
}

template <class Element>
DecryptResult BaseMultiparty<Element>::multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                                 NativePoly* plaintext) const {
    Element b = (ciphertext_vec.size() > 1) ?
                        ciphertext_vec[0]->get_elements()[0] + ciphertext_vec[1]->get_elements()[0] :
                        ciphertext_vec[0]->get_elements()[0];
    for (size_t i = 2; i < ciphertext_vec.size(); i++)
        b += ciphertext_vec[i]->get_elements()[0];
    b.set_format(Format::COEFFICIENT);

    *plaintext = b.to_native_poly();

    return DecryptResult(plaintext->get_length());
}

template <class Element>
PublicKey<Element> BaseMultiparty<Element>::multi_add_pub_keys(PublicKey<Element> public_key1,
                                                               PublicKey<Element> public_key2) const {
    PublicKey<Element> public_key_sum = std::make_shared<PublicKeyImpl<Element>>(public_key1->get_crypto_context());

    const Element& b1 = public_key1->get_public_elements()[0];
    const Element& b2 = public_key2->get_public_elements()[0];
    const Element& a = public_key1->get_public_elements()[1];
    std::vector<Element> pk_elems;
    pk_elems.reserve(2);
    pk_elems.push_back(b1 + b2);
    pk_elems.push_back(a);
    public_key_sum->set_public_elements(std::move(pk_elems));

    return public_key_sum;
}

template <class Element>
EvalKey<Element> BaseMultiparty<Element>::multi_add_eval_keys(EvalKey<Element> eval_key1,
                                                              EvalKey<Element> eval_key2) const {
    const auto cc = eval_key1->get_crypto_context();

    EvalKey<Element> eval_key_sum = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a = eval_key1->get_a_vector();
    const std::vector<Element>& b1 = eval_key1->get_b_vector();
    const std::vector<Element>& b2 = eval_key2->get_b_vector();

    std::vector<Element> b;
    b.reserve(a.size());

    for (uint32_t i = 0; i < a.size(); i++) {
        b.push_back(b1[i] + b2[i]);
    }

    eval_key_sum->set_a_vector(a);
    eval_key_sum->set_b_vector(std::move(b));
    return eval_key_sum;
}

template <class Element>
EvalKey<Element> BaseMultiparty<Element>::multi_add_eval_mult_keys(EvalKey<Element> eval_key1,
                                                                   EvalKey<Element> eval_key2) const {
    const auto cc = eval_key1->get_crypto_context();

    EvalKey<Element> eval_key_sum = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a1 = eval_key1->get_a_vector();
    const std::vector<Element>& a2 = eval_key2->get_a_vector();
    const std::vector<Element>& b1 = eval_key1->get_b_vector();
    const std::vector<Element>& b2 = eval_key2->get_b_vector();

    std::vector<Element> a;
    a.reserve(a1.size());
    std::vector<Element> b;
    b.reserve(a1.size());

    for (uint32_t i = 0; i < a1.size(); i++) {
        a.push_back(a1[i] + a2[i]);
        b.push_back(b1[i] + b2[i]);
    }

    eval_key_sum->set_a_vector(std::move(a));
    eval_key_sum->set_b_vector(std::move(b));
    return eval_key_sum;
}

template <class Element>
EvalKey<Element> BaseMultiparty<Element>::multi_mult_eval_key(PrivateKey<Element> private_key,
                                                              EvalKey<Element> eval_key) const {
    const auto cc = eval_key->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<RlweCryptoParams<Element>>(cc->get_crypto_parameters());

    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    const auto element_params = crypto_params->get_element_params();

    EvalKey<Element> eval_key_result = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a0 = eval_key->get_a_vector();
    const std::vector<Element>& b0 = eval_key->get_b_vector();

    const Element& s = private_key->get_private_element();
    const auto ns = crypto_params->get_noise_scale();

    std::vector<Element> a;
    a.reserve(a0.size());
    std::vector<Element> b;
    b.reserve(a0.size());

    for (uint32_t i = 0; i < a0.size(); i++) {
        Element ea(dgg, element_params, Format::EVALUATION);
        if (ns != 1)
            ea *= typename Element::Integer(ns);
        a.push_back(std::move(ea += a0[i] * s));
        Element eb(dgg, element_params, Format::EVALUATION);
        if (ns != 1)
            eb *= typename Element::Integer(ns);
        b.push_back(std::move(eb += b0[i] * s));
    }

    eval_key_result->set_a_vector(std::move(a));
    eval_key_result->set_b_vector(std::move(b));
    return eval_key_result;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseMultiparty<Element>::multi_add_eval_automorphism_keys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2) const {
    auto eval_key_map_auto = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();

    for (auto it = eval_key_map1->begin(); it != eval_key_map1->end(); ++it) {
        auto it2 = eval_key_map2->find(it->first);
        if (it2 != eval_key_map2->end())
            (*eval_key_map_auto)[it->first] = multi_add_eval_keys(it->second, it2->second);
    }

    return eval_key_map_auto;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseMultiparty<Element>::multi_add_eval_sum_keys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2) const {
    return multi_add_eval_automorphism_keys(eval_key_map1, eval_key_map2);
}

}  // namespace cipher

// the code below is from base-multiparty-impl.cpp
namespace cipher {
template class BaseMultiparty<RnsPoly>;
}  // namespace cipher
