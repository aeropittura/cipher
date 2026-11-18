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

#include "cipher/fhe/base/leveled_she.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

/////////////////////////////////////////
// SHE NEGATION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_negate(ConstCiphertext<Element>& ciphertext) const {
    auto result = ciphertext->clone();
    eval_negate_in_place(result);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_negate_in_place(Ciphertext<Element>& ciphertext) const {
    for (auto& c : ciphertext->get_elements())
        c = c.negate();
}

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_add(ConstCiphertext<Element>& ciphertext1,
                                                      ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_add_in_place(result, ciphertext2);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_add_in_place(Ciphertext<Element>& ciphertext1,
                                                ConstCiphertext<Element>& ciphertext2) const {
    eval_add_core_in_place(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_add(ConstCiphertext<Element>& ciphertext,
                                                      ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_add_in_place(result, plaintext);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_add_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    auto& cv = ciphertext->get_elements();
    if (cv[0].get_format() == plaintext->get_element<Element>().get_format()) {
        cv[0] += plaintext->get_element<Element>();
    } else {
        auto pt = plaintext->get_element<Element>();
        pt.set_format(cv[0].get_format());
        cv[0] += pt;
    }
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_sub(ConstCiphertext<Element>& ciphertext1,
                                                      ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_sub_in_place(result, ciphertext2);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_sub_in_place(Ciphertext<Element>& ciphertext1,
                                                ConstCiphertext<Element>& ciphertext2) const {
    eval_sub_core_in_place(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_sub(ConstCiphertext<Element>& ciphertext,
                                                      ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_sub_in_place(result, plaintext);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_sub_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    auto& cv = ciphertext->get_elements();
    if (cv[0].get_format() == plaintext->get_element<Element>().get_format()) {
        cv[0] -= plaintext->get_element<Element>();
    } else {
        auto pt = plaintext->get_element<Element>();
        pt.set_format(cv[0].get_format());
        cv[0] -= pt;
    }
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

template <class Element>
EvalKey<Element> BaseLeveledShe<Element>::eval_mult_key_gen(const PrivateKey<Element> private_key) const {
    const auto cc = private_key->get_crypto_context();
    const auto& s = private_key->get_private_element();

    auto private_key_squared = std::make_shared<PrivateKeyImpl<Element>>(cc);
    private_key_squared->set_private_element(s * s);

    return cc->get_scheme()->key_switch_gen(private_key_squared, private_key);
}

template <class Element>
std::vector<EvalKey<Element>> BaseLeveledShe<Element>::eval_mult_keys_gen(const PrivateKey<Element> private_key) const {
    const auto cc = private_key->get_crypto_context();
    const auto& s = private_key->get_private_element();

    auto private_key_power = std::make_shared<PrivateKeyImpl<Element>>(cc);
    private_key_power->set_private_element(s);

    uint32_t max_relin_sk_deg = private_key->get_crypto_parameters()->get_max_relin_sk_deg() - 1;
    std::vector<EvalKey<Element>> eval_key_vec;
    eval_key_vec.reserve(max_relin_sk_deg);
    for (uint32_t i = 0; i < max_relin_sk_deg; ++i) {
        private_key_power->set_private_element(s * private_key_power->get_private_element());
        eval_key_vec.emplace_back(cc->get_scheme()->key_switch_gen(private_key_power, private_key));
    }

    return eval_key_vec;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult(ConstCiphertext<Element>& ciphertext,
                                                       ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_mult_in_place(result, plaintext);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_mult_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    if (plaintext->get_element<Element>().get_format() == Format::EVALUATION) {
        for (auto& c : ciphertext->get_elements()) {
            c.set_format(Format::EVALUATION);
            c *= plaintext->get_element<Element>();
        }
    } else {
        auto pt = plaintext->get_element<Element>();
        pt.set_format(Format::EVALUATION);
        for (auto& c : ciphertext->get_elements()) {
            c.set_format(Format::EVALUATION);
            c *= pt;
        }
    }
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult(ConstCiphertext<Element>& ciphertext1,
                                                       ConstCiphertext<Element>& ciphertext2,
                                                       const EvalKey<Element> eval_key) const {
    auto ciphertext = eval_mult(ciphertext1, ciphertext2);

    auto& cv = ciphertext->get_elements();

    auto ab = ciphertext->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
    return ciphertext;
}

template <class Element>
void BaseLeveledShe<Element>::eval_mult_in_place(Ciphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element>& ciphertext2,
                                                 const EvalKey<Element> eval_key) const {
    ciphertext1 = eval_mult(ciphertext1, ciphertext2);

    auto& cv = ciphertext1->get_elements();

    auto ab = ciphertext1->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult_mutable(Ciphertext<Element>& ciphertext1,
                                                               Ciphertext<Element>& ciphertext2,
                                                               const EvalKey<Element> eval_key) const {
    auto ciphertext = eval_mult_mutable(ciphertext1, ciphertext2);

    auto& cv = ciphertext->get_elements();

    auto ab = ciphertext->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
    return ciphertext;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_square(ConstCiphertext<Element>& ciphertext,
                                                         const EvalKey<Element> eval_key) const {
    auto csquare = eval_square(ciphertext);

    auto& cv = csquare->get_elements();

    auto ab = csquare->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
    return csquare;
}

template <class Element>
void BaseLeveledShe<Element>::eval_square_in_place(Ciphertext<Element>& ciphertext,
                                                   const EvalKey<Element> eval_key) const {
    ciphertext = eval_square(ciphertext);

    auto& cv = ciphertext->get_elements();

    auto ab = ciphertext->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_square_mutable(Ciphertext<Element>& ciphertext,
                                                                 const EvalKey<Element> eval_key) const {
    auto csquare = eval_square_mutable(ciphertext);

    auto& cv = csquare->get_elements();

    auto ab = csquare->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
    return csquare;
}

template <class Element>
void BaseLeveledShe<Element>::eval_mult_mutable_in_place(Ciphertext<Element>& ciphertext1,
                                                         Ciphertext<Element>& ciphertext2,
                                                         const EvalKey<Element> eval_key) const {
    ciphertext1 = eval_mult_mutable(ciphertext1, ciphertext2);

    auto& cv = ciphertext1->get_elements();

    auto ab = ciphertext1->get_crypto_context()->get_scheme()->key_switch_core(cv[2], eval_key);
    cv[0] += ab[0];
    cv[1] += ab[1];
    cv.resize(2);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult_and_relinearize(
        ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
        const std::vector<EvalKey<Element>>& eval_key_vec) const {
    auto result = eval_mult(ciphertext1, ciphertext2);
    relinearize_in_place(result, eval_key_vec);
    return result;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::relinearize(ConstCiphertext<Element>& ciphertext,
                                                         const std::vector<EvalKey<Element>>& eval_key_vec) const {
    auto result = ciphertext->clone();
    relinearize_in_place(result, eval_key_vec);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::relinearize_in_place(Ciphertext<Element>& ciphertext,
                                                   const std::vector<EvalKey<Element>>& eval_key_vec) const {
    auto& cv = ciphertext->get_elements();
    for (auto& c : cv)
        c.set_format(Format::EVALUATION);

    auto algo = ciphertext->get_crypto_context()->get_scheme();

    for (size_t j = 2; j < cv.size(); ++j) {
        auto ab = algo->key_switch_core(cv[j], eval_key_vec[j - 2]);
        cv[0] += ab[0];
        cv[1] += ab[1];
    }
    cv.resize(2);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseLeveledShe<Element>::eval_automorphism_key_gen(
        const PrivateKey<Element> private_key, const std::vector<uint32_t>& index_list) const {
    // Do not generate duplicate keys that have been already generated and added to the static storage (map)
    std::set<uint32_t> all_indices(index_list.begin(), index_list.end());
    std::set<uint32_t> indices_to_generate{
            CryptoContextImpl<Element>::get_eval_automorphism_no_key_indices(private_key->get_key_tag(), all_indices)};
    std::vector<uint32_t> new_indices(indices_to_generate.begin(), indices_to_generate.end());

    // we already have checks on higher level?
    //  auto it = std::find(new_indices.begin(), new_indices.end(), 2 * n - 1);
    //  if (it != new_indices.end())
    //    CIPHER_THROW("conjugation is disabled");

    const auto cc = private_key->get_crypto_context();
    const auto& s = private_key->get_private_element();

    const uint32_t N = s.get_ring_dimension();
    const uint32_t M = s.get_cyclotomic_order();

    // we already have checks on higher level?
    //  if (new_indices.size() > N - 1)
    //    CIPHER_THROW("size exceeds the ring dimension");

    // create and initialize the key map (key is a value from new_indices, EvalKey is nullptr). in this case
    // we should be able to assign values to the map without using "omp critical" as all eval_keys' elements would
    // have already been created
    auto eval_keys = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();
    for (auto indx : new_indices)
        (*eval_keys)[indx];

    const uint32_t sz = new_indices.size();
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(sz))
    for (uint32_t i = 0; i < sz; ++i) {
        auto index = NativeInteger(new_indices[i]).mod_inverse(M).convert_to_int<uint32_t>();
        std::vector<uint32_t> vec(N);
        precompute_auto_map(N, index, &vec);

        auto private_key_permuted = std::make_shared<PrivateKeyImpl<Element>>(cc);
        private_key_permuted->set_private_element(s.automorphism_transform(index, vec));
        (*eval_keys)[new_indices[i]] = cc->get_scheme()->key_switch_gen(private_key, private_key_permuted);
    }

    return eval_keys;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_automorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                                               const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                                               CALLER_INFO_ARGS_CPP) const {
    // this operation can be performed on 2-element ciphertexts only
    if (ciphertext->number_ciphertext_elements() != 2)
        CIPHER_THROW("Ciphertext should be relinearized before.");

    // verify if the key i exists in the eval_key_map
    auto eval_key_iterator = eval_key_map.find(i);
    if (eval_key_iterator == eval_key_map.end())
        CIPHER_THROW("EvalKey for index [" + std::to_string(i) + "] is not found." + CALLER_INFO);

    // Delegate to the shared automorphism core so that eval_automorphism/eval_at_index
    // produce ciphertexts bit-identical to eval_fast_rotation with fresh digits
    return eval_automorphism_core(ciphertext, i, eval_fast_rotation_precompute(ciphertext), eval_key_iterator->second);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_automorphism_core(ConstCiphertext<Element>& ciphertext,
                                                                    uint32_t auto_index,
                                                                    const std::shared_ptr<std::vector<Element>>& digits,
                                                                    const EvalKey<Element>& eval_key) const {
    const auto cc = ciphertext->get_crypto_context();
    const uint32_t N = cc->get_ring_dimension();
    std::vector<uint32_t> vec(N);
    precompute_auto_map(N, auto_index, &vec);

    const auto& cv0 = ciphertext->get_elements()[0];

    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(eval_key->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() == HYBRID) {
        //  This branch trades slightly higher complexity for significant performance boost on GPU backend

        const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

        auto ba = cc->get_scheme()->eval_fast_key_switch_core_ext(digits, eval_key, cv0.get_params());

        // ba[0] += cv[0] * P;
        uint32_t size_q = cv0.get_num_of_elements();
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_q))
        for (uint32_t i = 0; i < size_q; ++i)
            ba[0].get_all_elements()[i].mult_acc_eq_no_check(cv0.get_all_elements()[i], crypto_params->get_p_modq()[i]);

        ba[0] = ba[0].automorphism_transform(auto_index, vec)
                        .approx_mod_down(cv0.get_params(), crypto_params->get_params_p(),
                                         crypto_params->get_p_inv_modq(), crypto_params->get_p_inv_modq_precon(),
                                         crypto_params->get_p_hat_inv_modp(),
                                         crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                         crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                         crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
        ba[1] = ba[1].automorphism_transform(auto_index, vec)
                        .approx_mod_down(cv0.get_params(), crypto_params->get_params_p(),
                                         crypto_params->get_p_inv_modq(), crypto_params->get_p_inv_modq_precon(),
                                         crypto_params->get_p_hat_inv_modp(),
                                         crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                         crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                         crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());

        auto result = ciphertext->clone_empty();
        result->set_elements(std::move(ba));
        return result;
    } else {
        auto ba = cc->get_scheme()->eval_fast_key_switch_core(digits, eval_key, cv0.get_params());
        ba[0] += cv0;
        ba[0] = ba[0].automorphism_transform(auto_index, vec);
        ba[1] = ba[1].automorphism_transform(auto_index, vec);

        auto result = ciphertext->clone_empty();
        result->set_elements(std::move(ba));
        return result;
    }
}

template <class Element>
std::shared_ptr<std::vector<Element>> BaseLeveledShe<Element>::eval_fast_rotation_precompute(
        ConstCiphertext<Element>& ciphertext) const {
    const auto& cv = ciphertext->get_elements();
    auto& algo = ciphertext->get_crypto_context()->get_scheme();
    return algo->eval_key_switch_precompute_core(cv[1], ciphertext->get_crypto_parameters());
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_fast_rotation(
        ConstCiphertext<Element>& ciphertext, const uint32_t index, const uint32_t m,
        const std::shared_ptr<std::vector<Element>> digits) const {
    if (index == 0)
        return ciphertext->clone();

    uint32_t auto_index = find_automorphism_index(index, m);
    const auto cc = ciphertext->get_crypto_context();
    auto eval_key_map = cc->get_eval_automorphism_key_map(ciphertext->get_key_tag());
    auto eval_key_iterator = eval_key_map.find(auto_index);
    if (eval_key_iterator == eval_key_map.end())
        CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");
    return eval_automorphism_core(ciphertext, auto_index, digits, eval_key_iterator->second);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseLeveledShe<Element>::eval_at_index_key_gen(
        const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list) const {
    uint32_t M = private_key->get_crypto_parameters()->get_element_params()->get_cyclotomic_order();
    std::vector<uint32_t> auto_indices(index_list.size());
    for (size_t i = 0; i < index_list.size(); i++)
        auto_indices[i] = find_automorphism_index(index_list[i], M);
    return eval_automorphism_key_gen(private_key, auto_indices);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_at_index(
        ConstCiphertext<Element>& ciphertext, int32_t index,
        const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
    uint32_t M = ciphertext->get_crypto_parameters()->get_element_params()->get_cyclotomic_order();
    return eval_automorphism(ciphertext, find_automorphism_index(index, M), eval_key_map);
}

/////////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::composed_eval_mult(ConstCiphertext<Element>& ciphertext1,
                                                                ConstCiphertext<Element>& ciphertext2,
                                                                const EvalKey<Element> eval_key) const {
    auto ciphertext = eval_mult(ciphertext1, ciphertext2);
    ciphertext->get_crypto_context()->get_scheme()->key_switch_in_place(ciphertext, eval_key);
    mod_reduce_in_place(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    return ciphertext;
}

/////////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::level_reduce(ConstCiphertext<Element>& ciphertext,
                                                          const EvalKey<Element> eval_key, size_t levels) const {
    auto result = ciphertext->clone();
    level_reduce_in_place(result, eval_key, levels);
    return result;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::morph_plaintext(ConstPlaintext& plaintext,
                                                             ConstCiphertext<Element>& ciphertext) const {
    auto elem = plaintext->get_element<Element>();
    elem.set_format(EVALUATION);

    auto result = ciphertext->clone_empty();
    result->set_element(std::move(elem));
    result->set_slots(plaintext->get_slots());
    result->set_level(plaintext->get_level());
    result->set_noise_scale_deg(plaintext->get_noise_scale_deg());
    result->set_scaling_factor(plaintext->get_scaling_factor());
    result->set_scaling_factor_int(plaintext->get_scaling_factor_int());
    return result;
}

/////////////////////////////////////////
// CORE OPERATION
/////////////////////////////////////////

template <class Element>
void BaseLeveledShe<Element>::verify_num_of_towers(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2, CALLER_INFO_ARGS_CPP) const {
    uint32_t num_towers1 = ciphertext1->get_elements()[0].get_num_of_elements();
    uint32_t num_towers2 = ciphertext2->get_elements()[0].get_num_of_elements();
    if (num_towers1 != num_towers2) {
        std::string error_msg(std::string("Number of towers is not the same for ciphertext1 [") +
                              std::to_string(num_towers1) + "] and for ciphertext2 [" + std::to_string(num_towers2) +
                              "] " + CALLER_INFO);
        CIPHER_THROW(error_msg);
    }
}
template <class Element>
void BaseLeveledShe<Element>::verify_num_of_towers(ConstCiphertext<Element>& ciphertext, const Element& plaintext,
                                                   CALLER_INFO_ARGS_CPP) const {
    uint32_t num_towers_ctxt = ciphertext->get_elements()[0].get_num_of_elements();
    uint32_t num_towers_ptxt = plaintext.get_num_of_elements();
    if (num_towers_ctxt != num_towers_ptxt) {
        std::string error_msg(std::string("Number of towers is not the same for ciphertext[") +
                              std::to_string(num_towers_ctxt) + "] and for plaintext[" +
                              std::to_string(num_towers_ptxt) + "]" + CALLER_INFO);
        CIPHER_THROW(error_msg);
    }
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_add_core(ConstCiphertext<Element>& ciphertext1,
                                                           ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_add_core_in_place(result, ciphertext2);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_add_core_in_place(Ciphertext<Element>& ciphertext1,
                                                     ConstCiphertext<Element>& ciphertext2) const {
    verify_num_of_towers(ciphertext1, ciphertext2);
    auto& cv1 = ciphertext1->get_elements();
    auto& cv2 = ciphertext2->get_elements();

    uint32_t c1_size = cv1.size();
    uint32_t c2_size = cv2.size();
    uint32_t c_small_size = std::min(c1_size, c2_size);

    cv1.reserve(c2_size);
    uint32_t i = 0;
    for (; i < c_small_size; ++i)
        cv1[i] += cv2[i];
    for (; i < c2_size; ++i)
        cv1.emplace_back(cv2[i]);
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_sub_core(ConstCiphertext<Element>& ciphertext1,
                                                           ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_sub_core_in_place(result, ciphertext2);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_sub_core_in_place(Ciphertext<Element>& ciphertext1,
                                                     ConstCiphertext<Element>& ciphertext2) const {
    verify_num_of_towers(ciphertext1, ciphertext2);
    auto& cv1 = ciphertext1->get_elements();
    auto& cv2 = ciphertext2->get_elements();

    uint32_t c1_size = cv1.size();
    uint32_t c2_size = cv2.size();
    uint32_t c_small_size = std::min(c1_size, c2_size);

    cv1.reserve(c2_size);
    uint32_t i = 0;
    for (; i < c_small_size; ++i)
        cv1[i] -= cv2[i];
    for (; i < c2_size; ++i)
        cv1.emplace_back(cv2[i].negate());
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult_core(ConstCiphertext<Element>& ctxt1,
                                                            ConstCiphertext<Element>& ctxt2) const {
    verify_num_of_towers(ctxt1, ctxt2);
    auto& cv1 = ctxt1->get_elements();
    auto& cv2 = ctxt2->get_elements();

    uint32_t n1 = cv1.size();
    uint32_t n2 = cv2.size();
    uint32_t nr = n1 + n2 - 1;

    std::vector<RnsPoly> cvr;
    cvr.reserve(nr);
    if (n1 == 2 && n2 == 2) {
        cvr.emplace_back(cv1[0] * cv2[0]);
        cvr.emplace_back(cv1[0] * cv2[1]);
        cvr.back().mult_acc_eq_no_check(cv1[1], cv2[0]);
        cvr.emplace_back(cv1[1] * cv2[1]);
    } else {
        uint32_t m = 0;
        for (uint32_t i = 0; i < n1; ++i) {
            auto& cv1i = cv1[i];
            for (uint32_t j = 0, k = i; j < n2; ++j, ++k) {
                if (k == m) {
                    cvr.emplace_back(cv1i * cv2[j]);
                    ++m;
                } else {
                    cvr[k].mult_acc_eq_no_check(cv1i, cv2[j]);
                }
            }
        }
    }

    auto result = ctxt1->clone_empty();
    result->set_elements(std::move(cvr));
    result->set_noise_scale_deg(ctxt1->get_noise_scale_deg() + ctxt2->get_noise_scale_deg());
    result->set_scaling_factor(ctxt1->get_scaling_factor() * ctxt2->get_scaling_factor());
    result->set_scaling_factor_int(ctxt1->get_scaling_factor_int().mod_mul(
            ctxt2->get_scaling_factor_int(), ctxt1->get_crypto_parameters()->get_plaintext_modulus()));
    return result;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_square_core(ConstCiphertext<Element>& ctxt) const {
    const auto& cv = ctxt->get_elements();

    uint32_t n = cv.size();
    uint32_t nr = (n << 1) - 1;

    std::vector<RnsPoly> cvr;
    cvr.reserve(nr);
    if (n == 2) {
        cvr.emplace_back(cv[0] * cv[0]);
        cvr.emplace_back(cv[0] * cv[1]);
        cvr.back() += cvr.back();
        cvr.emplace_back(cv[1] * cv[1]);
    } else {
        RnsPoly cvt;
        uint32_t m = 0;
        for (uint32_t i = 0; i < n; ++i) {
            auto& cvi = cv[i];
            for (uint32_t j = i, k = 2 * i; j < n; ++j, ++k) {
                if (j == i) {
                    if (k == m) {
                        cvr.emplace_back(cvi * cvi);
                        ++m;
                    } else {
                        cvr[k].mult_acc_eq_no_check(cvi, cvi);
                    }
                } else {
                    if (k == m) {
                        cvr.emplace_back(cvi * cv[j]);
                        cvr.back() += cvr.back();
                        ++m;
                    } else {
                        cvt = (cvi * cv[j]);
                        cvr[k] += (cvt += cvt);
                    }
                }
            }
        }
    }

    auto result = ctxt->clone_empty();
    result->set_elements(std::move(cvr));
    result->set_noise_scale_deg(2 * ctxt->get_noise_scale_deg());
    result->set_scaling_factor(ctxt->get_scaling_factor() * ctxt->get_scaling_factor());
    result->set_scaling_factor_int(ctxt->get_scaling_factor_int().mod_mul(
            ctxt->get_scaling_factor_int(), ctxt->get_crypto_parameters()->get_plaintext_modulus()));
    return result;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_add_core(ConstCiphertext<Element>& ciphertext,
                                                           const Element& pt) const {
    auto result = ciphertext->clone();
    eval_add_core_in_place(result, pt);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_add_core_in_place(Ciphertext<Element>& ciphertext, const Element& pt) const {
    verify_num_of_towers(ciphertext, pt);
    ciphertext->get_elements()[0] += pt;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_sub_core(ConstCiphertext<Element>& ciphertext,
                                                           const Element& pt) const {
    auto result = ciphertext->clone();
    eval_sub_core_in_place(result, pt);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_sub_core_in_place(Ciphertext<Element>& ciphertext, const Element& pt) const {
    verify_num_of_towers(ciphertext, pt);
    ciphertext->get_elements()[0] -= pt;
}

template <class Element>
Ciphertext<Element> BaseLeveledShe<Element>::eval_mult_core(ConstCiphertext<Element>& ciphertext,
                                                            const Element& pt) const {
    auto result = ciphertext->clone();
    eval_mult_core_in_place(result, pt);
    return result;
}

template <class Element>
void BaseLeveledShe<Element>::eval_mult_core_in_place(Ciphertext<Element>& ciphertext, const Element& pt) const {
    verify_num_of_towers(ciphertext, pt);
    for (auto& c : ciphertext->get_elements())
        c *= pt;
}

}  // namespace cipher

// the code below is from base-leveledshe-impl.cpp
namespace cipher {

// template class BaseLeveledShe<Poly>;
// template class BaseLeveledShe<NativePoly>;
template class BaseLeveledShe<RnsPoly>;

}  // namespace cipher
