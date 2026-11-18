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

#include "cipher/fhe/base/scheme.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/key/eval_key.h"
#include "cipher/fhe/key/key_pair.h"

// the code below is from base-scheme-impl.cpp
namespace cipher {

template <typename Element>
EvalKey<Element> SchemeBase<Element>::re_key_gen(const PrivateKey<Element> old_private_key,
                                               const PublicKey<Element> new_public_key) const {
    verify_pre_enabled(__func__);
    auto result = pre_->re_key_gen(old_private_key, new_public_key);
    result->set_key_tag(new_public_key->get_key_tag());
    return result;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::re_encrypt(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> eval_key,
                                                   const PublicKey<Element> public_key) const {
    verify_pre_enabled(__func__);
    auto result = pre_->re_encrypt(ciphertext, eval_key, public_key);
    result->set_key_tag(eval_key->get_key_tag());
    return result;
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::eval_mult_key_gen(const PrivateKey<Element> private_key) const {
    verify_leveled_she_enabled(__func__);
    auto eval_key = leveled_she_->eval_mult_key_gen(private_key);
    eval_key->set_key_tag(private_key->get_key_tag());
    return eval_key;
}

template <typename Element>
std::vector<EvalKey<Element>> SchemeBase<Element>::eval_mult_keys_gen(const PrivateKey<Element> private_key) const {
    verify_leveled_she_enabled(__func__);
    auto eval_key_vec = leveled_she_->eval_mult_keys_gen(private_key);
    for (auto& eval_key : eval_key_vec)
        eval_key->set_key_tag(private_key->get_key_tag());
    return eval_key_vec;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::eval_at_index_key_gen(
        const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list) const {
    verify_leveled_she_enabled(__func__);
    auto eval_key_map = leveled_she_->eval_at_index_key_gen(private_key, index_list);
    for (auto& key : *eval_key_map)
        key.second->set_key_tag(private_key->get_key_tag());
    return eval_key_map;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::composed_eval_mult(ConstCiphertext<Element>& ciphertext1,
                                                          ConstCiphertext<Element>& ciphertext2,
                                                          const EvalKey<Element> eval_key) const {
    verify_leveled_she_enabled(__func__);
    auto result = leveled_she_->composed_eval_mult(ciphertext1, ciphertext2, eval_key);
    result->set_key_tag(eval_key->get_key_tag());
    return result;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::mod_reduce(ConstCiphertext<Element>& ciphertext, size_t levels) const {
    verify_leveled_she_enabled(__func__);
    auto result = leveled_she_->mod_reduce(ciphertext, levels);
    result->set_key_tag(ciphertext->get_key_tag());
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::eval_sum_key_gen(
        const PrivateKey<Element> private_key) const {
    verify_advanced_she_enabled(__func__);
    auto eval_key_map = advanced_she_->eval_sum_key_gen(private_key);
    for (auto& key : *eval_key_map)
        key.second->set_key_tag(private_key->get_key_tag());
    return eval_key_map;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::eval_sum_rows_key_gen(
        const PrivateKey<Element> private_key, uint32_t row_size, uint32_t subring_dim,
        std::vector<uint32_t>& indices) const {
    verify_advanced_she_enabled(__func__);
    auto eval_key_map = advanced_she_->eval_sum_rows_key_gen(private_key, row_size, subring_dim, indices);
    for (auto& key : *eval_key_map)
        key.second->set_key_tag(private_key->get_key_tag());
    return eval_key_map;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::eval_sum_cols_key_gen(
        const PrivateKey<Element> private_key, std::vector<uint32_t>& indices) const {
    verify_advanced_she_enabled(__func__);
    auto eval_key_map = advanced_she_->eval_sum_cols_key_gen(private_key, indices);
    for (auto& key : *eval_key_map)
        key.second->set_key_tag(private_key->get_key_tag());
    return eval_key_map;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::eval_inner_product(ConstCiphertext<Element>& ciphertext1,
                                                          ConstCiphertext<Element>& ciphertext2, uint32_t batch_size,
                                                          const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map,
                                                          const EvalKey<Element> eval_mult_key) const {
    verify_advanced_she_enabled(__func__);
    if (!eval_sum_key_map.size())
        CIPHER_THROW("Input evaluation key map is empty");
    if (!eval_mult_key)
        CIPHER_THROW("Input evaluation key is nullptr");

    auto result = advanced_she_->eval_inner_product(ciphertext1, ciphertext2, batch_size, eval_sum_key_map, eval_mult_key);
    result->set_key_tag(eval_sum_key_map.begin()->second->get_key_tag());
    return result;
}

template <typename Element>
KeyPair<Element> SchemeBase<Element>::multiparty_key_gen(CryptoContext<Element> cc,
                                                       const std::vector<PrivateKey<Element>>& private_key_vec,
                                                       bool make_sparse_value) {
    verify_multiparty_enabled(__func__);
    if (!cc)
        CIPHER_THROW("Input crypto context is nullptr");
    if (!private_key_vec.size())
        CIPHER_THROW("Input private key vector is empty");

    auto key_pair = multiparty_->multiparty_key_gen(cc, private_key_vec, make_sparse_value);
    key_pair.public_key->set_key_tag(key_pair.secret_key->get_key_tag());
    return key_pair;
}

template <typename Element>
KeyPair<Element> SchemeBase<Element>::multiparty_key_gen(CryptoContext<Element> cc, const PublicKey<Element> public_key,
                                                       bool make_sparse_value, bool PRE) {
    verify_multiparty_enabled(__func__);
    if (!cc)
        CIPHER_THROW("Input crypto context is nullptr");
    if (!public_key)
        CIPHER_THROW("Input public key is empty");

    auto key_pair = multiparty_->multiparty_key_gen(cc, public_key, make_sparse_value, PRE);
    key_pair.public_key->set_key_tag(key_pair.secret_key->get_key_tag());
    return key_pair;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::multiparty_decrypt_main(ConstCiphertext<Element>& ciphertext,
                                                               const PrivateKey<Element> private_key) const {
    verify_multiparty_enabled(__func__);
    check_multiparty_decrypt_compatibility(ciphertext);

    auto result = multiparty_->multiparty_decrypt_main(ciphertext, private_key);
    return result;
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::multiparty_decrypt_lead(ConstCiphertext<Element>& ciphertext,
                                                               const PrivateKey<Element> private_key) const {
    verify_multiparty_enabled(__func__);
    check_multiparty_decrypt_compatibility(ciphertext);

    auto result = multiparty_->multiparty_decrypt_lead(ciphertext, private_key);
    return result;
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::multi_key_switch_gen(const PrivateKey<Element> old_private_key,
                                                        const PrivateKey<Element> new_private_key,
                                                        const EvalKey<Element> eval_key) const {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_key_switch_gen(old_private_key, new_private_key, eval_key);
    result->set_key_tag(new_private_key->get_key_tag());
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::multi_eval_automorphism_key_gen(
        const PrivateKey<Element> private_key,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_auto_key_map,
        const std::vector<uint32_t>& index_list, const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_eval_automorphism_key_gen(private_key, eval_auto_key_map, index_list);
    for (auto& key : *result) {
        if (key.second) {
            key.second->set_key_tag(key_id);
        }
    }
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::multi_eval_at_index_key_gen(
        const PrivateKey<Element> private_key,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_auto_key_map,
        const std::vector<int32_t>& index_list, const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_eval_at_index_key_gen(private_key, eval_auto_key_map, index_list);
    for (auto& key : *result) {
        if (key.second) {
            key.second->set_key_tag(key_id);
        }
    }
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::multi_eval_sum_key_gen(
        const PrivateKey<Element> private_key, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map,
        const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_eval_sum_key_gen(private_key, eval_sum_key_map);
    for (auto& key : *result) {
        if (key.second) {
            key.second->set_key_tag(key_id);
        }
    }
    return result;
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::multi_add_eval_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                                       const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto eval_key_sum = multiparty_->multi_add_eval_keys(eval_key1, eval_key2);
    eval_key_sum->set_key_tag(key_id);
    return eval_key_sum;
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::multi_mult_eval_key(PrivateKey<Element> private_key, EvalKey<Element> eval_key,
                                                       const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_mult_eval_key(private_key, eval_key);
    result->set_key_tag(key_id);
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::multi_add_eval_sum_keys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map2, const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_add_eval_sum_keys(eval_sum_key_map1, eval_sum_key_map2);
    for (auto& key : *result) {
        if (key.second) {
            key.second->set_key_tag(key_id);
        }
    }
    return result;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::multi_add_eval_automorphism_keys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map2, const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto result = multiparty_->multi_add_eval_automorphism_keys(eval_sum_key_map1, eval_sum_key_map2);
    for (auto& key : *result) {
        if (key.second) {
            key.second->set_key_tag(key_id);
        }
    }
    return result;
}

template <typename Element>
PublicKey<Element> SchemeBase<Element>::multi_add_pub_keys(PublicKey<Element> public_key1, PublicKey<Element> public_key2,
                                                        const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto public_key_sum = multiparty_->multi_add_pub_keys(public_key1, public_key2);
    public_key_sum->set_key_tag(key_id);
    return public_key_sum;
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::multi_add_eval_mult_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                                           const std::string& key_id) {
    verify_multiparty_enabled(__func__);
    auto eval_key_sum = multiparty_->multi_add_eval_mult_keys(eval_key1, eval_key2);
    eval_key_sum->set_key_tag(key_id);
    return eval_key_sum;
}

template <typename Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> SchemeBase<Element>::eval_automorphism_key_gen(
        const PrivateKey<Element> private_key, const std::vector<uint32_t>& index_list) const {
    verify_leveled_she_enabled(__func__);
    auto eval_key_map = leveled_she_->eval_automorphism_key_gen(private_key, index_list);
    for (auto& key : *eval_key_map)
        key.second->set_key_tag(private_key->get_key_tag());
    return eval_key_map;
}

template class SchemeBase<RnsPoly>;

}  // namespace cipher
