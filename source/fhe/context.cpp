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
  Control for encryption operations
 */

#include "cipher/fhe/context.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/math/chebyshev.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/rns/scheme.h"
#include "cipher/util/memory.h"

namespace cipher {

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>> CryptoContextImpl<Element>::eval_mult_key_map_{};
template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>
        CryptoContextImpl<Element>::eval_automorphism_key_map_{};

template <typename Element>
void CryptoContextImpl<Element>::clear_static_maps_and_vectors() {
    CryptoContextImpl<Element>::eval_automorphism_key_map_.clear();
    CryptoContextImpl<Element>::eval_mult_key_map_.clear();
    PackedEncoding::destroy();
    NatChineseRemainderTransformFtt<NativeVector>().reset();
#ifdef CIPHER_WITH_BE2
    fixed_int::ChineseRemainderTransformFttFxd<M2Vector>().reset();
#endif
#ifdef CIPHER_WITH_BE4
    dynamic_int::ChineseRemainderTransformFttDyn<M4Vector>().reset();
#endif
#ifdef CIPHER_WITH_NTL
    NTL::ChineseRemainderTransformFttNtl<M6Vector>().reset();
#endif
    alloc_trim();
}

template <typename Element>
void CryptoContextImpl<Element>::set_ks_technique_in_scheme() {
    // check if the scheme is an RNS scheme
    auto scheme_rns_ptr = std::dynamic_pointer_cast<RnsScheme>(scheme_);
    if (!scheme_rns_ptr)
        CIPHER_THROW("Invalid scheme: expected RnsScheme");

    // check if the parameter object is RNS-based
    auto el_ptr = std::dynamic_pointer_cast<const RnsCryptoParams>(params_);
    if (!el_ptr)
        CIPHER_THROW("Invalid crypto parameters: expected RnsCryptoParams");

    scheme_rns_ptr->set_key_switching_technique(el_ptr->get_key_switch_technique());
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////
template <typename Element>
void CryptoContextImpl<Element>::eval_mult_key_gen(const PrivateKey<Element>& key) {
    validate_key(key);
    if (CryptoContextImpl<Element>::eval_mult_key_map_.find(key->get_key_tag()) ==
        CryptoContextImpl<Element>::eval_mult_key_map_.end()) {
        // the key is not found in the map, so the key has to be generated
        CryptoContextImpl<Element>::eval_mult_key_map_[key->get_key_tag()] = {scheme_->eval_mult_key_gen(key)};
    }
}

template <typename Element>
void CryptoContextImpl<Element>::eval_mult_keys_gen(const PrivateKey<Element>& key) {
    validate_key(key);
    if (CryptoContextImpl<Element>::eval_mult_key_map_.find(key->get_key_tag()) ==
        CryptoContextImpl<Element>::eval_mult_key_map_.end()) {
        // the key is not found in the map, so the key has to be generated
        CryptoContextImpl<Element>::eval_mult_key_map_[key->get_key_tag()] = scheme_->eval_mult_keys_gen(key);
    }
}

template <typename Element>
void CryptoContextImpl<Element>::clear_eval_mult_keys() {
    CryptoContextImpl<Element>::eval_mult_key_map_.clear();
}

template <typename Element>
void CryptoContextImpl<Element>::clear_eval_mult_keys(const std::string& key_tag) {
    auto kd = CryptoContextImpl<Element>::eval_mult_key_map_.find(key_tag);
    if (kd != CryptoContextImpl<Element>::eval_mult_key_map_.end())
        CryptoContextImpl<Element>::eval_mult_key_map_.erase(kd);
}

template <typename Element>
void CryptoContextImpl<Element>::clear_eval_mult_keys(const CryptoContext<Element>& cc) {
    for (auto it = CryptoContextImpl<Element>::eval_mult_key_map_.begin();
         it != CryptoContextImpl<Element>::eval_mult_key_map_.end();) {
        if (it->second[0]->get_crypto_context() == cc) {
            it = CryptoContextImpl<Element>::eval_mult_key_map_.erase(it);
        } else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::insert_eval_mult_key(const std::vector<EvalKey<Element>>& vector_to_insert,
                                                      const std::string& key_tag) {
    const std::string& tag = (key_tag.empty()) ? vector_to_insert[0]->get_key_tag() : key_tag;
    if (CryptoContextImpl<Element>::eval_mult_key_map_.find(tag) !=
        CryptoContextImpl<Element>::eval_mult_key_map_.end()) {
        // we do not allow to override the existing key vector if its key_tag is identical to the key_tag of the new keys
        CIPHER_THROW("Can not save a eval_mult_keys vector as there is a key vector for the given key_tag");
    }
    CryptoContextImpl<Element>::eval_mult_key_map_[tag] = vector_to_insert;
}

/////////////////////////////////////////
// ADVANCED SHE
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::eval_sum_key_gen(const PrivateKey<Element> private_key) {
    validate_key(private_key);
    auto&& eval_keys = scheme_->eval_sum_key_gen(private_key);
    CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::eval_sum_rows_key_gen(
        const PrivateKey<Element> private_key, uint32_t row_size, uint32_t subring_dim) {
    validate_key(private_key);
    std::vector<uint32_t> indices;
    auto&& eval_keys = scheme_->eval_sum_rows_key_gen(private_key, row_size, subring_dim, indices);
    CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
    return CryptoContextImpl<Element>::get_partial_eval_automorphism_key_map_ptr(private_key->get_key_tag(), indices);
}

// TODO: this is here for backwards compatibility; should remove in v2.0
template <typename Element>
inline std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::eval_sum_rows_key_gen(
        const PrivateKey<Element> private_key, const PublicKey<Element> public_key, uint32_t row_size,
        uint32_t subring_dim) {
    return CryptoContextImpl<Element>::eval_sum_rows_key_gen(private_key, row_size, subring_dim);
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::eval_sum_cols_key_gen(
        const PrivateKey<Element> private_key) {
    validate_key(private_key);
    std::vector<uint32_t> indices;
    auto&& eval_keys = scheme_->eval_sum_cols_key_gen(private_key, indices);
    CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
    return CryptoContextImpl<Element>::get_partial_eval_automorphism_key_map_ptr(private_key->get_key_tag(), indices);
}

template <typename Element>
const std::map<uint32_t, EvalKey<Element>>& CryptoContextImpl<Element>::get_eval_sum_key_map(
        const std::string& key_tag) {
    return CryptoContextImpl<Element>::get_eval_automorphism_key_map(key_tag);
}

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>>& CryptoContextImpl<Element>::get_all_eval_mult_keys() {
    return CryptoContextImpl<Element>::eval_mult_key_map_;
}

template <typename Element>
const std::vector<EvalKey<Element>>& CryptoContextImpl<Element>::get_eval_mult_key_vector(const std::string& key_tag) {
    auto ekv = CryptoContextImpl<Element>::eval_mult_key_map_.find(key_tag);
    if (ekv == CryptoContextImpl<Element>::eval_mult_key_map_.end()) {
        std::string err_msg(std::string("Call eval_mult_key_gen() to have eval_mult_key available for ID [") + key_tag +
                            "].");
        CIPHER_THROW(err_msg);
    }
    return ekv->second;
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>&
CryptoContextImpl<Element>::get_all_eval_automorphism_keys() {
    return CryptoContextImpl<Element>::eval_automorphism_key_map_;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> CryptoContextImpl<Element>::get_eval_automorphism_key_map_ptr(
        const std::string& key_tag) {
    auto ekv = CryptoContextImpl<Element>::eval_automorphism_key_map_.find(key_tag);
    if (ekv == CryptoContextImpl<Element>::eval_automorphism_key_map_.end()) {
        CIPHER_THROW("eval_automorphism_keys are not generated for ID [" + key_tag + "].");
    }
    return ekv->second;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>
CryptoContextImpl<Element>::get_partial_eval_automorphism_key_map_ptr(const std::string& key_tag,
                                                                      const std::vector<uint32_t>& index_list) {
    if (!index_list.size())
        CIPHER_THROW("index_list is empty");

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> key_map =
            CryptoContextImpl<Element>::get_eval_automorphism_key_map_ptr(key_tag);

    // create a return map if specific indices are provided
    std::map<uint32_t, EvalKey<Element>> ret_map;
    for (uint32_t indx : index_list) {
        const auto it = key_map->find(indx);
        if (it == key_map->end()) {
            CIPHER_THROW("Key is not generated for index [" + std::to_string(indx) + "] and key_tag [" + key_tag + "]");
        }
        ret_map.emplace(indx, it->second);
    }
    return std::make_shared<std::map<uint32_t, EvalKey<Element>>>(ret_map);
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>&
CryptoContextImpl<Element>::get_all_eval_sum_keys() {
    return CryptoContextImpl<Element>::get_all_eval_automorphism_keys();
}

template <typename Element>
void CryptoContextImpl<Element>::clear_eval_sum_keys() {
    CryptoContextImpl<Element>::clear_eval_automorphism_keys();
}

/**
 * clear_eval_sum_keys - flush eval_key_sum cache for a given id
 * @param key_tag secret key tag
 */
template <typename Element>
void CryptoContextImpl<Element>::clear_eval_sum_keys(const std::string& key_tag) {
    CryptoContextImpl<Element>::clear_eval_automorphism_keys(key_tag);
}

/**
 * clear_eval_sum_keys - flush eval_key_sum cache for a given context
 * @param cc the context to clear all eval_sum_keys for
 */
template <typename Element>
void CryptoContextImpl<Element>::clear_eval_sum_keys(const CryptoContext<Element> cc) {
    CryptoContextImpl<Element>::clear_eval_automorphism_keys(cc);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::eval_at_index_key_gen(const PrivateKey<Element> private_key,
                                                       const std::vector<int32_t>& index_list) {
    validate_key(private_key);
    auto&& eval_keys = scheme_->eval_at_index_key_gen(private_key, index_list);
    CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
}

template <typename Element>
void CryptoContextImpl<Element>::clear_eval_automorphism_keys() {
    CryptoContextImpl<Element>::eval_automorphism_key_map_.clear();
}

/**
 * clear_eval_automorphism_keys - flush EvalAutomorphismKey cache for a given id
 * @param key_tag secret key tag
 */
template <typename Element>
void CryptoContextImpl<Element>::clear_eval_automorphism_keys(const std::string& key_tag) {
    auto kd = CryptoContextImpl<Element>::eval_automorphism_key_map_.find(key_tag);
    if (kd != CryptoContextImpl<Element>::eval_automorphism_key_map_.end())
        CryptoContextImpl<Element>::eval_automorphism_key_map_.erase(kd);
}

/**
 * clear_eval_automorphism_keys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc the context to clear all eval_automorphism_keys for
 */
template <typename Element>
void CryptoContextImpl<Element>::clear_eval_automorphism_keys(const CryptoContext<Element> cc) {
    for (auto it = CryptoContextImpl<Element>::eval_automorphism_key_map_.begin();
         it != CryptoContextImpl<Element>::eval_automorphism_key_map_.end();) {
        if (it->second->begin()->second->get_crypto_context() == cc) {
            it = CryptoContextImpl<Element>::eval_automorphism_key_map_.erase(it);
        } else {
            ++it;
        }
    }
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::get_existing_eval_automorphism_key_indices(const std::string& key_tag) {
    auto key_map_it = CryptoContextImpl<Element>::eval_automorphism_key_map_.find(key_tag);
    if (key_map_it == CryptoContextImpl<Element>::eval_automorphism_key_map_.end())
        // there is no keys for the given key_tag, return empty vector
        return std::set<uint32_t>();

    // get all inidices from the existing automorphism key map
    auto& key_map = *(key_map_it->second);
    std::set<uint32_t> indices;
    for (const auto& [key, _] : key_map) {
        indices.insert(key);
    }

    return indices;
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::get_unique_values(const std::set<uint32_t>& old_values,
                                                                 const std::set<uint32_t>& new_values) {
    std::set<uint32_t> new_unique_values;
    std::set_difference(new_values.begin(), new_values.end(), old_values.begin(), old_values.end(),
                        std::inserter(new_unique_values, new_unique_values.begin()));
    return new_unique_values;
}

template <typename Element>
void CryptoContextImpl<Element>::insert_eval_automorphism_key(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> map_to_insert, const std::string& key_tag) {
    // check if the map is empty
    if (map_to_insert->empty()) {
        return;
    }

    auto map_to_insert_it = map_to_insert->begin();
    const std::string& id = (key_tag.empty()) ? map_to_insert_it->second->get_key_tag() : key_tag;
    std::set<uint32_t> existing_indices{CryptoContextImpl<Element>::get_existing_eval_automorphism_key_indices(id)};
    if (existing_indices.empty()) {
        // there is no keys for the given id, so we insert full map_to_insert
        CryptoContextImpl<Element>::eval_automorphism_key_map_[id] = map_to_insert;
    } else {
        // get all indices from map_to_insert
        std::set<uint32_t> new_indices;
        for (const auto& [key, _] : *map_to_insert) {
            new_indices.insert(key);
        }

        // find all indices in map_to_insert that are not in the exising map and
        // insert those new indices and their corresponding keys to the existing map
        std::set<uint32_t> indices_to_insert{
                CryptoContextImpl<Element>::get_unique_values(existing_indices, new_indices)};
        auto key_map_it = CryptoContextImpl<Element>::eval_automorphism_key_map_.find(id);
        auto& key_map = *(key_map_it->second);
        for (uint32_t indx : indices_to_insert) {
            key_map[indx] = (*map_to_insert)[indx];
        }
    }
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_sum(ConstCiphertext<Element>& ciphertext,
                                                         uint32_t batch_size) const {
    validate_ciphertext(ciphertext);
    auto&& eval_sum_keys = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext->get_key_tag());
    return scheme_->eval_sum(ciphertext, batch_size, eval_sum_keys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_sum_rows(ConstCiphertext<Element>& ciphertext, uint32_t num_rows,
                                                              const std::map<uint32_t, EvalKey<Element>>& eval_sum_keys,
                                                              uint32_t subring_dim) const {
    validate_ciphertext(ciphertext);
    return scheme_->eval_sum_rows(ciphertext, num_rows, eval_sum_keys, subring_dim);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_sum_cols(
        ConstCiphertext<Element>& ciphertext, uint32_t num_cols,
        const std::map<uint32_t, EvalKey<Element>>& eval_sum_keys_right) const {
    validate_ciphertext(ciphertext);
    auto&& eval_sum_keys = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext->get_key_tag());
    return scheme_->eval_sum_cols(ciphertext, num_cols, eval_sum_keys, eval_sum_keys_right);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_at_index(ConstCiphertext<Element>& ciphertext,
                                                              int32_t index) const {
    validate_ciphertext(ciphertext);
    // If the index is zero, no rotation is needed, copy the ciphertext and return
    // This is done after the key_map so that it is protected if there's not a valid key.
    if (0 == index)
        return ciphertext->clone();
    auto&& eval_automorphism_keys =
            CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext->get_key_tag());
    return scheme_->eval_at_index(ciphertext, index, eval_automorphism_keys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_merge(
        const std::vector<Ciphertext<Element>>& ciphertext_vector) const {
    if (0 == ciphertext_vector.size())
        CIPHER_THROW("Input ciphertext vector is empty");
    validate_ciphertext(ciphertext_vector[0]);
    auto eval_automorphism_keys =
            CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext_vector[0]->get_key_tag());
    return scheme_->eval_merge(ciphertext_vector, eval_automorphism_keys);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_inner_product(ConstCiphertext<Element>& ct1,
                                                                   ConstCiphertext<Element>& ct2,
                                                                   uint32_t batch_size) const {
    validate_ciphertext(ct1);
    if (ct2 == nullptr || ct1->get_key_tag() != ct2->get_key_tag())
        CIPHER_THROW("Information was not generated with this crypto context");
    auto& eval_sum_keys = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ct1->get_key_tag());
    auto& ek = CryptoContextImpl<Element>::get_eval_mult_key_vector(ct1->get_key_tag());
    return scheme_->eval_inner_product(ct1, ct2, batch_size, eval_sum_keys, ek[0]);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_inner_product(ConstCiphertext<Element>& ct1, ConstPlaintext& ct2,
                                                                   uint32_t batch_size) const {
    validate_ciphertext(ct1);
    if (ct2 == nullptr)
        CIPHER_THROW("Information was not generated with this crypto context");
    auto& eval_sum_keys = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ct1->get_key_tag());
    return scheme_->eval_inner_product(ct1, ct2, batch_size, eval_sum_keys);
}

template <typename Element>
Plaintext CryptoContextImpl<Element>::get_plaintext_for_decrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                                EncodingParams ep, CkksDataType cdt) {
    auto vp =
            std::make_shared<typename NativePoly::Params>(evp->get_cyclotomic_order(), ep->get_plaintext_modulus(), 1);
    if (pte == CKKS_PACKED_ENCODING)
        return PlaintextFactory::make_plaintext(pte, evp, ep, INVALID_SCHEME, cdt);
    return PlaintextFactory::make_plaintext(pte, vp, ep);
}

template <typename Element>
DecryptResult CryptoContextImpl<Element>::decrypt(ConstCiphertext<Element>& ciphertext,
                                                  const PrivateKey<Element>& private_key, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        CIPHER_THROW("ciphertext is empty");
    if (plaintext == nullptr)
        CIPHER_THROW("plaintext is empty");
    validate_key(private_key);

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::get_plaintext_for_decrypt(ciphertext->get_encoding_type(),
    // this->get_element_params(), this->get_encoding_params());
    Plaintext decrypted = CryptoContextImpl<Element>::get_plaintext_for_decrypt(
            ciphertext->get_encoding_type(), ciphertext->get_elements()[0].get_params(), this->get_encoding_params(),
            this->get_ckks_data_type());

    DecryptResult result;

    if ((ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING) && (typeid(Element) != typeid(NativePoly))) {
        result = scheme_->decrypt(ciphertext, private_key, &decrypted->get_element<Poly>());
    } else {
        result = scheme_->decrypt(ciphertext, private_key, &decrypted->get_element<NativePoly>());
    }

    if (result.is_valid == false)  // TODO (dsuponit): why don't we throw an exception here?
        return result;

    decrypted->set_scaling_factor_int(result.scaling_factor_int);

    if (ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING) {
        auto decrypted_ckks = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        if (!decrypted_ckks)
            CIPHER_THROW("Invalid plaintext encoding type: expected CKKSPackedEncoding");
        decrypted_ckks->set_noise_scale_deg(ciphertext->get_noise_scale_deg());
        decrypted_ckks->set_level(ciphertext->get_level());
        decrypted_ckks->set_scaling_factor(ciphertext->get_scaling_factor());
        decrypted_ckks->set_slots(ciphertext->get_slots());

        const auto crypto_params_ckks = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (!crypto_params_ckks)
            CIPHER_THROW("Invalid crypto parameters: expected RnsCryptoParams");

        decrypted_ckks->decode(ciphertext->get_noise_scale_deg(), ciphertext->get_scaling_factor(),
                               crypto_params_ckks->get_scaling_technique(), crypto_params_ckks->get_execution_mode());
    } else {
        decrypted->decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

//------------------------------------------------------------------------------
// Advanced SHE CHEBYSHEV SERIES EXAMPLES
//------------------------------------------------------------------------------

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_chebyshev_function(std::function<double(double)> func,
                                                                        ConstCiphertext<Element>& ciphertext, double a,
                                                                        double b, uint32_t degree) const {
    std::vector<double> coefficients = eval_chebyshev_coefficients(func, a, b, degree);
    return eval_chebyshev_series(ciphertext, coefficients, a, b);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_sin(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                         uint32_t degree) const {
    return eval_chebyshev_function([](double x) -> double { return std::sin(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_cos(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                         uint32_t degree) const {
    return eval_chebyshev_function([](double x) -> double { return std::cos(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_logistic(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                              uint32_t degree) const {
    return eval_chebyshev_function([](double x) -> double { return 1 / (1 + std::exp(-x)); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::eval_divide(ConstCiphertext<Element>& ciphertext, double a, double b,
                                                            uint32_t degree) const {
    return eval_chebyshev_function([](double x) -> double { return 1 / x; }, ciphertext, a, b, degree);
}

}  // namespace cipher

// the code below is from cryptocontext-impl.cpp
namespace cipher {

template <>
Plaintext CryptoContextImpl<RnsPoly>::get_plaintext_for_decrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                                EncodingParams ep, CkksDataType cdt) {
    if ((pte == CKKS_PACKED_ENCODING) && (evp->get_params().size() > 1)) {
        auto vp = std::make_shared<typename Poly::Params>(evp->get_cyclotomic_order(), ep->get_plaintext_modulus(), 1);
        return PlaintextFactory::make_plaintext(pte, vp, ep, INVALID_SCHEME, cdt);
    } else {
        auto vp = std::make_shared<typename NativePoly::Params>(evp->get_cyclotomic_order(),
                                                                ep->get_plaintext_modulus(), 1);
        return PlaintextFactory::make_plaintext(pte, vp, ep, INVALID_SCHEME, cdt);
    }
}

template <>
DecryptResult CryptoContextImpl<RnsPoly>::decrypt(ConstCiphertext<RnsPoly>& ciphertext,
                                                  const PrivateKey<RnsPoly>& private_key, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        CIPHER_THROW("ciphertext is empty");
    if (plaintext == nullptr)
        CIPHER_THROW("plaintext is empty");
    if (private_key == nullptr || mismatched(private_key->get_crypto_context()))
        CIPHER_THROW("Information was not generated with this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::get_plaintext_for_decrypt(ciphertext->get_encoding_type(),
    // this->get_element_params(), this->get_encoding_params());
    Plaintext decrypted = CryptoContextImpl<RnsPoly>::get_plaintext_for_decrypt(
            ciphertext->get_encoding_type(), ciphertext->get_elements()[0].get_params(), this->get_encoding_params(),
            this->get_ckks_data_type());

    DecryptResult result;

    if ((ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING) &&
        (ciphertext->get_elements()[0].get_params()->get_params().size() > 1))  // more than one tower in RnsPoly
        result = scheme_->decrypt(ciphertext, private_key, &decrypted->get_element<Poly>());
    else
        result = scheme_->decrypt(ciphertext, private_key, &decrypted->get_element<NativePoly>());

    if (result.is_valid == false)
        return result;

    decrypted->set_scaling_factor_int(result.scaling_factor_int);

    if (ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING) {
        auto decrypted_ckks = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        if (!decrypted_ckks)
            CIPHER_THROW("Invalid plaintext encoding type: expected CKKSPackedEncoding");
        decrypted_ckks->set_noise_scale_deg(ciphertext->get_noise_scale_deg());
        decrypted_ckks->set_level(ciphertext->get_level());
        decrypted_ckks->set_scaling_factor(ciphertext->get_scaling_factor());
        decrypted_ckks->set_slots(ciphertext->get_slots());

        const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(params_);
        if (!crypto_params_ckks)
            CIPHER_THROW("Invalid crypto parameters: expected CkksRnsCryptoParams");

        decrypted_ckks->decode(ciphertext->get_noise_scale_deg(), ciphertext->get_scaling_factor(),
                               crypto_params_ckks->get_scaling_technique(), crypto_params_ckks->get_execution_mode());
    } else {
        decrypted->decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

template <>
DecryptResult CryptoContextImpl<RnsPoly>::multiparty_decrypt_fusion(
        const std::vector<Ciphertext<RnsPoly>>& partial_ciphertext_vec, Plaintext* plaintext) const {
    DecryptResult result;

    // Make sure we're processing ciphertexts.
    size_t last_ciphertext = partial_ciphertext_vec.size();
    if (last_ciphertext < 1)
        return result;

    for (size_t i = 0; i < last_ciphertext; i++) {
        validate_ciphertext(partial_ciphertext_vec[i]);
        if (partial_ciphertext_vec[i]->get_encoding_type() != partial_ciphertext_vec[0]->get_encoding_type())
            CIPHER_THROW("Ciphertexts have mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted = CryptoContextImpl<RnsPoly>::get_plaintext_for_decrypt(
            partial_ciphertext_vec[0]->get_encoding_type(), partial_ciphertext_vec[0]->get_elements()[0].get_params(),
            this->get_encoding_params(), this->get_ckks_data_type());

    if ((partial_ciphertext_vec[0]->get_encoding_type() == CKKS_PACKED_ENCODING) &&
        (partial_ciphertext_vec[0]->get_elements()[0].get_params()->get_params().size() > 1))
        result = scheme_->multiparty_decrypt_fusion(partial_ciphertext_vec, &decrypted->get_element<Poly>());
    else
        result = scheme_->multiparty_decrypt_fusion(partial_ciphertext_vec, &decrypted->get_element<NativePoly>());

    if (result.is_valid == false)
        return result;

    decrypted->set_scaling_factor_int(result.scaling_factor_int);

    if (partial_ciphertext_vec[0]->get_encoding_type() == CKKS_PACKED_ENCODING) {
        auto decrypted_ckks = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        if (!decrypted_ckks)
            CIPHER_THROW("Invalid plaintext encoding type: expected CKKSPackedEncoding");
        decrypted_ckks->set_slots(partial_ciphertext_vec[0]->get_slots());
        const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(params_);
        if (!crypto_params_ckks)
            CIPHER_THROW("Invalid crypto parameters: expected CkksRnsCryptoParams");
        decrypted_ckks->decode(partial_ciphertext_vec[0]->get_noise_scale_deg(),
                               partial_ciphertext_vec[0]->get_scaling_factor(),
                               crypto_params_ckks->get_scaling_technique(), crypto_params_ckks->get_execution_mode());
    } else {
        decrypted->decode();
    }

    *plaintext = std::move(decrypted);

    return result;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::int_mp_boot_adjust_scale(ConstCiphertext<Element>& ciphertext) const {
    return scheme_->int_mp_boot_adjust_scale(ciphertext);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::int_mp_boot_random_element_gen(
        const PublicKey<Element> public_key) const {
    const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(params_);
    if (!crypto_params_ckks)
        CIPHER_THROW("Invalid crypto parameters: expected CkksRnsCryptoParams");

    return scheme_->int_mp_boot_random_element_gen(crypto_params_ckks, public_key);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::int_mp_boot_random_element_gen(
        ConstCiphertext<Element>& ciphertext) const {
    const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    if (!crypto_params_ckks)
        CIPHER_THROW("Invalid crypto parameters: expected CkksRnsCryptoParams");

    return scheme_->int_mp_boot_random_element_gen(crypto_params_ckks, ciphertext);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::int_mp_boot_decrypt(const PrivateKey<Element> private_key,
                                                                                 ConstCiphertext<Element>& ciphertext,
                                                                                 ConstCiphertext<Element>& a) const {
    return scheme_->int_mp_boot_decrypt(private_key, ciphertext, a);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::int_mp_boot_add(
        std::vector<std::vector<Ciphertext<Element>>>& shares_pair_vec) const {
    return scheme_->int_mp_boot_add(shares_pair_vec);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::int_mp_boot_encrypt(const PublicKey<Element> public_key,
                                                                    const std::vector<Ciphertext<Element>>& shares_pair,
                                                                    ConstCiphertext<Element>& a,
                                                                    ConstCiphertext<Element>& ciphertext) const {
    return scheme_->int_mp_boot_encrypt(public_key, shares_pair, a, ciphertext);
}

// Function for sharing and recovery of secret for Threshold FHE with aborts
template <>
std::unordered_map<uint32_t, RnsPoly> CryptoContextImpl<RnsPoly>::share_keys(const PrivateKey<RnsPoly>& sk, uint32_t N,
                                                                             uint32_t threshold, uint32_t index,
                                                                             const std::string& share_type) const {
    // conditions on N and threshold for security with aborts
    if (N < 2)
        CIPHER_THROW("Number of parties needs to be at least 3 for aborts");

    if (threshold <= N / 2)
        CIPHER_THROW("Threshold required to be majority (more than N/2)");

    const auto crypto_params = sk->get_crypto_context()->get_crypto_parameters();
    auto element_params = crypto_params->get_element_params();
    auto vec_size = element_params->get_params().size();
    auto ring_dimension = element_params->get_ring_dimension();

    // condition for inverse in lagrange coeff to exist.
    for (size_t i = 0; i < vec_size; ++i) {
        auto modq_k = element_params->get_params()[i]->get_modulus();
        if (N >= modq_k)
            CIPHER_THROW("Number of parties N needs to be less than RnsPoly moduli");
    }

    // secret sharing
    std::unordered_map<uint32_t, RnsPoly> secret_shares;

    if (share_type == "additive") {
        // generate a random share of N-2 elements and create the last share as sk - (sk_1 + ... + sk_n-2)
        typename RnsPoly::DugType dug;
        RnsPoly rsum(dug, element_params, Format::EVALUATION);

        const uint32_t num_of_shares = N - 1;
        std::vector<RnsPoly> secret_shares_vec;
        secret_shares_vec.reserve(num_of_shares);
        secret_shares_vec.push_back(rsum);
        for (size_t i = 1; i < num_of_shares - 1; ++i) {
            RnsPoly r(dug, element_params, Format::EVALUATION);  // should re-generate uniform r for each share
            rsum += r;
            secret_shares_vec.push_back(std::move(r));
        }
        secret_shares_vec.push_back(sk->get_private_element() - rsum);

        for (size_t i = 1, ctr = 0; i <= N; ++i) {
            if (i != index) {
                secret_shares[i] = secret_shares_vec[ctr++];
            }
        }
    } else if (share_type == "shamir") {
        // vector to store columnwise randomly generated coefficients for polynomial f from Z_q for every secret key entry
        // set constant term of polynomial f_i to s_i
        std::vector<RnsPoly> fs{sk->get_private_element()};
        fs.back().set_format(Format::COEFFICIENT);

        // generate random coefficients
        fs.reserve(threshold);
        typename RnsPoly::DugType dug;
        for (size_t i = 1; i < threshold; ++i) {
            fs.emplace_back(dug, element_params, Format::COEFFICIENT);
        }

        // evaluate the polynomial at the index of the parties 1 to N
        for (size_t i = 1; i <= N; ++i) {
            if (i != index) {
                RnsPoly feval(element_params, Format::COEFFICIENT, true);
                for (size_t k = 0; k < vec_size; k++) {
                    auto modq_k = element_params->get_params()[k]->get_modulus();

                    NativePoly powtemppoly(element_params->get_params()[k], Format::COEFFICIENT);
                    NativePoly fevalpoly(element_params->get_params()[k], Format::COEFFICIENT, true);

                    NativeInteger powtemp(1);
                    for (size_t t = 1; t < threshold; t++) {
                        NativeVector powtempvec(ring_dimension, modq_k, (powtemp = powtemp.mod_mul(i, modq_k)));

                        powtemppoly.set_values(std::move(powtempvec), Format::COEFFICIENT);

                        auto& fst = fs[t].get_element_at_index(k);

                        for (size_t i = 0; i < ring_dimension; ++i) {
                            fevalpoly[i] += powtemppoly[i].mod_mul(fst[i], modq_k);
                        }
                    }
                    fevalpoly += fs[0].get_element_at_index(k);

                    fevalpoly.set_format(Format::COEFFICIENT);
                    feval.set_element_at_index(k, std::move(fevalpoly));
                }
                // assign fi
                secret_shares.emplace(i, std::move(feval));
            }
        }
    }
    return secret_shares;
}

template <>
void CryptoContextImpl<RnsPoly>::recover_shared_key(PrivateKey<RnsPoly>& sk,
                                                    std::unordered_map<uint32_t, RnsPoly>& sk_shares, uint32_t N,
                                                    uint32_t threshold, const std::string& share_type) const {
    if (sk_shares.size() < threshold)
        CIPHER_THROW("Number of shares available less than threshold of the sharing scheme");

    // conditions on N and threshold for security with aborts
    if (N < 2)
        CIPHER_THROW("Number of parties needs to be at least 3 for aborts");

    if (threshold <= N / 2)
        CIPHER_THROW("Threshold required to be majority (more than N/2)");

    const auto& crypto_params = sk->get_crypto_context()->get_crypto_parameters();
    const auto& element_params = crypto_params->get_element_params();
    size_t ring_dimension = element_params->get_ring_dimension();
    size_t vec_size = element_params->get_params().size();

    // condition for inverse in lagrange coeff to exist.
    for (size_t k = 0; k < vec_size; k++) {
        auto modq_k = element_params->get_params()[k]->get_modulus();
        if (N >= modq_k)
            CIPHER_THROW("Number of parties N needs to be less than RnsPoly moduli");
    }

    // vector of indexes of the clients
    std::vector<uint32_t> client_indexes;
    client_indexes.reserve(N);
    for (uint32_t i = 1; i <= N; ++i) {
        if (sk_shares.find(i) != sk_shares.end())
            client_indexes.push_back(i);
    }
    const uint32_t client_indexes_size = client_indexes.size();

    if (client_indexes_size < threshold)
        CIPHER_THROW("Not enough shares to recover the secret");

    if (share_type == "additive") {
        RnsPoly sum_of_elems(element_params, Format::EVALUATION, true);
        for (uint32_t i = 0; i < threshold; ++i) {
            sum_of_elems += sk_shares[client_indexes[i]];
        }
        sk->set_private_element(std::move(sum_of_elems));
    } else if (share_type == "shamir") {
        // use lagrange interpolation to recover the secret
        // vector of lagrange coefficients L_j = Pdt_i ne j (i (i-j)^-1)
        std::vector<RnsPoly> lagrange_coeffs(client_indexes_size, RnsPoly(element_params, Format::EVALUATION));

        // recovery of the secret with lagrange coefficients and the secret shares
        for (uint32_t j = 0; j < client_indexes_size; j++) {
            auto cj = client_indexes[j];
            for (size_t k = 0; k < vec_size; k++) {
                auto modq_k = element_params->get_params()[k]->get_modulus();
                NativePoly multpoly(element_params->get_params()[k], Format::COEFFICIENT, true);
                multpoly.add_il_element_one();
                for (uint32_t i = 0; i < client_indexes_size; i++) {
                    auto ci = client_indexes[i];
                    if (ci != cj) {
                        auto&& denominator = (cj < ci) ? NativeInteger(ci - cj) : modq_k - NativeInteger(cj - ci);
                        auto denom_inv{denominator.mod_inverse(modq_k)};
                        for (size_t d = 0; d < ring_dimension; ++d)
                            multpoly[d].mod_mul_fast_eq(NativeInteger(ci).mod_mul(denom_inv, modq_k), modq_k);
                    }
                }
                multpoly.set_format(Format::EVALUATION);
                lagrange_coeffs[j].set_element_at_index(k, std::move(multpoly));
            }
            lagrange_coeffs[j].set_format(Format::COEFFICIENT);
        }

        RnsPoly lagrange_sum_of_elems(element_params, Format::COEFFICIENT, true);
        for (size_t k = 0; k < vec_size; ++k) {
            NativePoly lagrange_sum_of_elems_poly(element_params->get_params()[k], Format::COEFFICIENT, true);
            for (uint32_t i = 0; i < client_indexes_size; ++i) {
                const auto& coeff = lagrange_coeffs[i].get_all_elements()[k];
                const auto& share = sk_shares[client_indexes[i]].get_all_elements()[k];
                lagrange_sum_of_elems_poly.mult_acc_eq_no_check(coeff, share);
            }
            lagrange_sum_of_elems.set_element_at_index(k, std::move(lagrange_sum_of_elems_poly));
        }
        lagrange_sum_of_elems.set_format(Format::EVALUATION);
        sk->set_private_element(std::move(lagrange_sum_of_elems));
    }
}

// explicit template instantiations (including the instantiations reqiured for pybind11 binding)
// clang-format off
template class CryptoContextImpl<RnsPoly>;

#define INSTANTIATE_FUNCTION_TEMPLATES(VECTOR_TYPE) \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_chebyshev_series<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_chebyshev_series_linear<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_chebyshev_series_ps<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&, double, double) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_linear_w_sum<VECTOR_TYPE>(std::vector<ReadOnlyCiphertext<RnsPoly>>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_linear_w_sum_mutable<VECTOR_TYPE>(const std::vector<VECTOR_TYPE>&, std::vector<Ciphertext<RnsPoly>>&) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_poly<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_poly_linear<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&) const; \
    template Ciphertext<RnsPoly> CryptoContextImpl<RnsPoly>::eval_poly_ps<VECTOR_TYPE>(ConstCiphertext<RnsPoly>&, const std::vector<VECTOR_TYPE>&) const;

INSTANTIATE_FUNCTION_TEMPLATES(int64_t)
INSTANTIATE_FUNCTION_TEMPLATES(double)
INSTANTIATE_FUNCTION_TEMPLATES(std::complex<double>)
// clang-format on

}  // namespace cipher
