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

#include "cipher/fhe/base/advanced_she.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/math/number_theory.h"
#include "cipher/fhe/base/scheme.h"
#include "cipher/fhe/rns/crypto_params.h"
#include "cipher/util/parallel.h"

namespace cipher {

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_add_many(const std::vector<Ciphertext<Element>>& ciphertext_vec) const {
    const uint32_t size = ciphertext_vec.size();
    if (size == 0)
        CIPHER_THROW("Input ciphertext vector is empty.");

    uint32_t first = 0;
    while (first < size && ciphertext_vec[first] == nullptr)
        ++first;
    if (first == size)
        CIPHER_THROW("Input ciphertext vector has no non-null entries.");

    auto result = ciphertext_vec[first]->clone();
    auto algo = result->get_crypto_context()->get_scheme();
    for (uint32_t i = first + 1; i < size; ++i) {
        if (ciphertext_vec[i] != nullptr)
            algo->eval_add_in_place(result, ciphertext_vec[i]);
    }

    return result;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_add_many_in_place(
        std::vector<Ciphertext<Element>>& ciphertext_vec) const {
    const uint32_t size = ciphertext_vec.size();
    if (size == 0)
        CIPHER_THROW("Input ciphertext vector is empty.");

    uint32_t first = 0;
    while (first < size && ciphertext_vec[first] == nullptr)
        ++first;
    if (first == size)
        CIPHER_THROW("Input ciphertext vector has no non-null entries.");

    auto algo = ciphertext_vec[first]->get_crypto_context()->get_scheme();
    for (uint32_t i = first + 1; i < size; ++i) {
        if (ciphertext_vec[i] != nullptr)
            algo->eval_add_in_place(ciphertext_vec[first], ciphertext_vec[i]);
    }

    if (first != 0)
        ciphertext_vec[0] = ciphertext_vec[first];

    return ciphertext_vec[0];
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_mult_many(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                           const std::vector<EvalKey<Element>>& eval_keys) const {
    const uint32_t size = ciphertext_vec.size();
    if (size == 0)
        CIPHER_THROW("Input ciphertext vector is empty.");

    if (size == 1)
        return ciphertext_vec[0]->clone();

    const uint32_t lim = size * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertext_mult_vec(size - 1);

    // BASE_NUM_LEVELS_TO_DROP everywhere except composite-scaling CKKS.
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());
    const uint32_t levels_to_drop = crypto_params ? crypto_params->get_composite_degree() : BASE_NUM_LEVELS_TO_DROP;

    auto algo = ciphertext_vec[0]->get_crypto_context()->get_scheme();

    uint32_t i = 0, j = 0;
    // input x input
    for (; i < (size - 1); i += 2) {
        ciphertext_mult_vec[j] = algo->eval_mult_and_relinearize(ciphertext_vec[i], ciphertext_vec[i + 1], eval_keys);
        algo->mod_reduce_in_place(ciphertext_mult_vec[j++], levels_to_drop);
    }
    // odd size: the last input pairs with the first partial
    if (i < size) {
        ciphertext_mult_vec[j] =
                algo->eval_mult_and_relinearize(ciphertext_vec[i], ciphertext_mult_vec[i + 1 - size], eval_keys);
        algo->mod_reduce_in_place(ciphertext_mult_vec[j++], levels_to_drop);
        ciphertext_mult_vec[i + 1 - size].reset();
        i += 2;
    }
    // partial x partial
    for (; i < lim; i += 2) {
        ciphertext_mult_vec[j] =
                algo->eval_mult_and_relinearize(ciphertext_mult_vec[i - size], ciphertext_mult_vec[i + 1 - size], eval_keys);
        algo->mod_reduce_in_place(ciphertext_mult_vec[j++], levels_to_drop);
        ciphertext_mult_vec[i - size].reset();
        ciphertext_mult_vec[i + 1 - size].reset();
    }

    return ciphertext_mult_vec.back();
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::add_random_noise(ConstCiphertext<Element> ciphertext) const {
    if (!ciphertext)
        CIPHER_THROW("Input ciphertext is nullptr");

    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    std::string k_id = ciphertext->get_key_tag();
    const auto crypto_params = ciphertext->get_crypto_parameters();
    const auto encoding_params = crypto_params->get_encoding_params();
    const auto element_params = crypto_params->get_element_params();

    uint32_t n = element_params->get_ring_dimension();

    auto cc = ciphertext->get_crypto_context();

    Plaintext plaintext;

    if (ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> random_int_vector(n);

        // first plaintext slot does not need to change
        random_int_vector[0].real(0);

        for (uint32_t i = 0; i < n - 1; i++) {
            random_int_vector[i + 1].real(distribution(PseudoRandomNumberGenerator::get_prng()));
        }

        plaintext = cc->make_ckks_packed_plaintext(random_int_vector, ciphertext->get_noise_scale_deg(), 0, nullptr,
                                                ciphertext->get_slots());
    } else {
        DiscreteUniformGeneratorImpl<typename Element::Vector> dug;
        auto random_vector{dug.generate_vector(n - 1, encoding_params->get_plaintext_modulus())};

        std::vector<int64_t> random_int_vector(n);

        // first plaintext slot does not need to change
        random_int_vector[0] = 0;

        for (uint32_t i = 0; i < n - 1; i++) {
            random_int_vector[i + 1] = random_vector[i].convert_to_int();
        }

        plaintext = cc->make_packed_plaintext(random_int_vector);
    }

    plaintext->encode();
    plaintext->get_element<Element>().set_format(EVALUATION);
    auto algo = cc->get_scheme();
    return algo->eval_add(ciphertext, plaintext);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseAdvancedShe<Element>::eval_sum_key_gen(
        const PrivateKey<Element> private_key) const {
    if (!private_key)
        CIPHER_THROW("Input private key is nullptr");

    // get automorphism indices and convert them to a vector
    std::set<uint32_t> indx_set{generate_index_list_for_eval_sum(private_key)};
    std::vector<uint32_t> indices(indx_set.begin(), indx_set.end());

    auto algo = private_key->get_crypto_context()->get_scheme();
    return algo->eval_automorphism_key_gen(private_key, indices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseAdvancedShe<Element>::eval_sum_rows_key_gen(
        const PrivateKey<Element> private_key, uint32_t row_size, uint32_t subring_dim,
        std::vector<uint32_t>& indices) const {
    auto cc = private_key->get_crypto_context();

    if (!is_ckks(cc->get_scheme_id_impl()))
        CIPHER_THROW("Matrix summation of row-vectors is only supported for CKKSPackedEncoding.");

    uint32_t m = (subring_dim == 0) ? private_key->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() :
                                     subring_dim;

    if (!is_power_of_two(m))
        CIPHER_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    std::set<uint32_t> rows_indices{generate_indices2n_complex_rows(row_size, m)};
    indices.reserve(indices.size() + rows_indices.size());
    indices.insert(indices.end(), rows_indices.begin(), rows_indices.end());

    auto algo = cc->get_scheme();
    return algo->eval_automorphism_key_gen(private_key, indices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> BaseAdvancedShe<Element>::eval_sum_cols_key_gen(
        const PrivateKey<Element> private_key, std::vector<uint32_t>& indices) const {
    auto cc = private_key->get_crypto_context();

    if (!is_ckks(cc->get_scheme_id_impl()))
        CIPHER_THROW("Matrix summation of column-vectors is only supported for CKKSPackedEncoding.");

    const auto crypto_params = private_key->get_crypto_parameters();
    uint32_t M = crypto_params->get_element_params()->get_cyclotomic_order();
    if (!is_power_of_two(M))
        CIPHER_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    uint32_t batch_size = crypto_params->get_encoding_params()->get_batch_size();

    // get indices for eval_sum_cols() and merge them with the indices for eval_sum()
    std::set<uint32_t> eval_sum_cols_indices = generate_indices2n_complex_cols(batch_size, M);
    std::set<uint32_t> eval_sum_indices = generate_index_list_for_eval_sum(private_key);
    eval_sum_cols_indices.merge(eval_sum_indices);
    indices.reserve(indices.size() + eval_sum_cols_indices.size());
    indices.insert(indices.end(), eval_sum_cols_indices.begin(), eval_sum_cols_indices.end());

    auto algo = cc->get_scheme();
    return algo->eval_automorphism_key_gen(private_key, indices);
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum(ConstCiphertext<Element> ciphertext, uint32_t batch_size,
                                                      const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
    const auto crypto_params = ciphertext->get_crypto_parameters();
    const auto encoding_params = crypto_params->get_encoding_params();

    if ((encoding_params->get_batch_size() == 0))
        CIPHER_THROW(
                "Packed encoding parameters 'batch size' is not set; "
                "Please check the EncodingParams passed to the crypto context.");

    uint32_t m = crypto_params->get_element_params()->get_cyclotomic_order();

    Ciphertext<Element> new_ciphertext = ciphertext->clone();

    if (is_power_of_two(m)) {
        if (ciphertext->get_encoding_type() == CKKS_PACKED_ENCODING)
            new_ciphertext = eval_sum2n_complex(new_ciphertext, batch_size, m, eval_key_map);
        else
            new_ciphertext = eval_sum_2n(new_ciphertext, batch_size, m, eval_key_map);
    } else {  // Arbitrary cyclotomics
        if (encoding_params->get_plaintext_generator() == 0) {
            CIPHER_THROW(
                    "Packed encoding parameters 'plaintext "
                    "generator' is not set; Please check the "
                    "EncodingParams passed to the crypto context.");
        } else {
            auto algo = ciphertext->get_crypto_context()->get_scheme();

            uint32_t g = encoding_params->get_plaintext_generator();
            for (int i = 0; i < std::floor(std::log2(batch_size)); i++) {
                new_ciphertext = algo->eval_add(new_ciphertext, algo->eval_automorphism(new_ciphertext, g, eval_key_map));
                g = (g * g) % m;
            }
        }
    }

    return new_ciphertext;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum_rows(ConstCiphertext<Element> ciphertext, uint32_t num_rows,
                                                          const std::map<uint32_t, EvalKey<Element>>& eval_sum_keys,
                                                          uint32_t subring_dim) const {
    if (ciphertext->get_encoding_type() != CKKS_PACKED_ENCODING)
        CIPHER_THROW("Matrix summation of row-vectors is only supported for CKKS packed encoding.");

    const auto crypto_params = ciphertext->get_crypto_parameters();
    const auto encoding_params = crypto_params->get_encoding_params();
    if ((encoding_params->get_batch_size() == 0))
        CIPHER_THROW(
                "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    uint32_t m = (subring_dim == 0) ? crypto_params->get_element_params()->get_cyclotomic_order() : subring_dim;
    if (!is_power_of_two(m))
        CIPHER_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    return eval_sum2n_complex_rows(ciphertext->clone(), num_rows, m, eval_sum_keys);
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum_cols(
        ConstCiphertext<Element> ciphertext, uint32_t num_cols,
        const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map,
        const std::map<uint32_t, EvalKey<Element>>& eval_sum_cols_key_map) const {
    if (!ciphertext)
        CIPHER_THROW("Input ciphertext is nullptr");
    if (!eval_sum_key_map.size())
        CIPHER_THROW("Input evalKeys map is empty");
    if (!eval_sum_cols_key_map.size())
        CIPHER_THROW("Input rightEvalKeys map is empty");
    if (ciphertext->get_encoding_type() != CKKS_PACKED_ENCODING)
        CIPHER_THROW("Matrix summation of column-vectors is only supported for CKKS packed encoding.");

    const uint32_t slots = ciphertext->get_slots();
    if (slots < num_cols)
        CIPHER_THROW("The number of columns ca not be greater than the number of slots.");

    const auto crypto_params = ciphertext->get_crypto_parameters();
    const auto encoding_params = crypto_params->get_encoding_params();
    if ((encoding_params->get_batch_size() == 0))
        CIPHER_THROW(
                "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    const auto element_params = crypto_params->get_element_params();
    uint32_t m = element_params->get_cyclotomic_order();
    if (!is_power_of_two(m))
        CIPHER_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    std::vector<std::complex<double>> mask(slots, 0);  // create a mask vector and set all its elements to zero
    for (size_t i = 0; i < mask.size(); i++) {
        if (i % num_cols == 0)
            mask[i] = 1;
    }

    Ciphertext<Element> new_ciphertext = eval_sum2n_complex(ciphertext->clone(), num_cols, m, eval_sum_key_map);
    auto cc = ciphertext->get_crypto_context();
    auto algo = cc->get_scheme();
    Plaintext plaintext = cc->make_ckks_packed_plaintext(mask, 1, 0, nullptr, slots);
    algo->eval_mult_in_place(new_ciphertext, plaintext);

    return eval_sum2n_complex_cols(new_ciphertext, num_cols, m, eval_sum_cols_key_map);
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_inner_product(
        ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2, uint32_t batch_size,
        const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map, const EvalKey<Element> eval_mult_key) const {
    auto algo = ciphertext1->get_crypto_context()->get_scheme();

    Ciphertext<Element> result = algo->eval_mult(ciphertext1, ciphertext2, eval_mult_key);

    result = eval_sum(result, batch_size, eval_sum_key_map);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->get_encoding_type() != CKKS_PACKED_ENCODING)
    //   result = add_random_noise(result);
    return result;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_inner_product(
        ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext, uint32_t batch_size,
        const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map) const {
    auto algo = ciphertext->get_crypto_context()->get_scheme();

    Ciphertext<Element> result = algo->eval_mult(ciphertext, plaintext);

    result = eval_sum(result, batch_size, eval_sum_key_map);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->get_encoding_type() != CKKS_PACKED_ENCODING)
    //   result = add_random_noise(result);
    return result;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_merge(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                        const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
    if (ciphertext_vec.size() == 0)
        CIPHER_THROW("the vector of ciphertexts to be merged cannot be empty");

    const std::shared_ptr<BaseCryptoParams<Element>> crypto_params = ciphertext_vec[0]->get_crypto_parameters();
    Ciphertext<Element> ciphertext_merged(std::make_shared<CiphertextImpl<Element>>(*(ciphertext_vec[0])));

    auto cc = ciphertext_vec[0]->get_crypto_context();

    Plaintext plaintext;
    if (ciphertext_vec[0]->get_encoding_type() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> mask({{1, 0}, {0, 0}});
        plaintext = cc->make_ckks_packed_plaintext(mask, 1, 0, nullptr, ciphertext_vec[0]->get_slots());
    } else {
        std::vector<int64_t> mask = {1, 0};
        plaintext = cc->make_packed_plaintext(mask);
    }
    auto algo = ciphertext_vec[0]->get_crypto_context()->get_scheme();

    ciphertext_merged = algo->eval_mult(ciphertext_merged, plaintext);

    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        ciphertext_merged = algo->eval_add(
                ciphertext_merged,
                algo->eval_at_index(algo->eval_mult(ciphertext_vec[i], plaintext), -static_cast<int32_t>(i), eval_key_map));
    }

    return ciphertext_merged;
}

static_assert(CIPHER_PARTIAL_SUM_RADIX >= 2 && (CIPHER_PARTIAL_SUM_RADIX & (CIPHER_PARTIAL_SUM_RADIX - 1)) == 0,
              "PARTIAL_SUM_RADIX must be a power of two >= 2");

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_eval_sum_indices(uint32_t g0, uint32_t size, uint32_t m) {
    constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
    std::set<uint32_t> indices;
    uint64_t g = g0;
    for (uint32_t s = 1; s < size; s *= radix) {
        // Level automorphisms g^i = g0^(i * s) for the level's up to radix-1 rotations.
        uint64_t gi = g;
        for (uint32_t i = 1; i < radix && i * s < size; ++i) {
            indices.insert(static_cast<uint32_t>(gi));
            gi = gi * g % m;
        }
        for (uint32_t r = radix; r > 1; r >>= 1)
            g = g * g % m;
    }

    return indices;
}

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_indices_2n(uint32_t batch_size, uint32_t m) {
    std::set<uint32_t> indices;
    if (batch_size > 1) {
        if (2 * batch_size < m)
            return generate_eval_sum_indices(5, batch_size, m);

        indices = generate_eval_sum_indices(5, batch_size / 2, m);
        indices.insert(m - 1);
    }

    return indices;
}

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_indices2n_complex(uint32_t batch_size, uint32_t m) {
    return generate_eval_sum_indices(5, batch_size, m);
}

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_indices2n_complex_rows(uint32_t row_size, uint32_t m) {
    const uint32_t col_size = m / (4 * row_size);
    const uint32_t g0 = (NativeInteger(5).mod_exp(row_size, m)).convert_to_int<uint32_t>();
    return generate_eval_sum_indices(g0, col_size, m);
}

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_indices2n_complex_cols(uint32_t batch_size, uint32_t m) {
    const uint32_t g0 = NativeInteger(5).mod_inverse(m).convert_to_int<uint32_t>();
    return generate_eval_sum_indices(g0, batch_size, m);
}

template <class Element>
std::set<uint32_t> BaseAdvancedShe<Element>::generate_index_list_for_eval_sum(const PrivateKey<Element>& private_key) {
    const auto crypto_params = private_key->get_crypto_parameters();
    const auto encoding_params = crypto_params->get_encoding_params();
    const auto element_params = crypto_params->get_element_params();

    uint32_t batch_size = encoding_params->get_batch_size();
    uint32_t m = element_params->get_cyclotomic_order();

    std::set<uint32_t> indices;
    if (is_power_of_two(m)) {
        auto cc_inst = private_key->get_crypto_context();
        // CKKS Packing
        indices = is_ckks(cc_inst->get_scheme_id_impl()) ? generate_indices2n_complex(batch_size, m) :
                                                  generate_indices_2n(batch_size, m);
    } else {
        // Arbitrary cyclotomics
        auto isize = static_cast<size_t>(std::floor(std::log2(batch_size)));
        uint32_t g = encoding_params->get_plaintext_generator();
        for (size_t i = 0; i < isize; i++) {
            indices.insert(g);
            g = (g * g) % m;
        }
    }

    return indices;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum_radix_fold(
        ConstCiphertext<Element>& ciphertext, uint32_t g0, uint32_t size, uint32_t m,
        const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
    Ciphertext<Element> result = ciphertext->clone();
    if (size <= 1)
        return result;

    constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
    auto algo = ciphertext->get_crypto_context()->get_scheme();
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    if (!crypto_params || crypto_params->get_key_switch_technique() != HYBRID) {
        uint64_t g = g0;
        for (uint32_t s = 1; s < size; s *= radix) {
            Ciphertext<Element> base = result->clone();
            auto digits = algo->eval_fast_rotation_precompute(base);
            uint64_t gi = g;
            for (uint32_t i = 1; i < radix && i * s < size; ++i) {
                const auto auto_index = static_cast<uint32_t>(gi);
                auto eval_key_iterator = eval_key_map.find(auto_index);
                if (eval_key_iterator == eval_key_map.end())
                    CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");
                result = algo->eval_add(result,
                                       algo->eval_automorphism_core(base, auto_index, digits, eval_key_iterator->second));
                gi = gi * g % m;
            }
            for (uint32_t r = radix; r > 1; r >>= 1)
                g = g * g % m;
        }
        return result;
    }

    const uint32_t N = ciphertext->get_crypto_context()->get_ring_dimension();
    std::vector<Element>& cv = result->get_elements();
    const auto params_ql = cv[0].get_params();
    const auto params_p = crypto_params->get_params_p();
    const auto params_ql_p = cv[0].get_extended_crt_basis(params_p);
    const uint32_t size_ql = params_ql->get_params().size();
    const uint32_t size_ql_p = params_ql_p->get_params().size();

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    Element acc(params_ql_p, Format::EVALUATION, true);
    auto c_mult = cv[0].times_no_check(crypto_params->get_p_modq());
    for (uint32_t i = 0; i < size_ql; ++i)
        acc.set_element_at_index(i, std::move(c_mult.get_element_at_index(i)));

    std::vector<uint32_t> vec(N);
    uint64_t g = g0;
    for (uint32_t s = 1; s < size; s *= radix) {
        auto digits = algo->eval_key_switch_precompute_core(cv[1], crypto_params);

        Element lvl0(params_ql_p, Format::EVALUATION, true);
        Element lvl1(params_ql_p, Format::EVALUATION, true);

        uint64_t gi = g;
        for (uint32_t i = 1; i < radix && i * s < size; ++i) {
            const auto auto_index = static_cast<uint32_t>(gi);
            auto eval_key_iterator = eval_key_map.find(auto_index);
            if (eval_key_iterator == eval_key_map.end())
                CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");

            precompute_auto_map(N, auto_index, &vec);

            auto ba = algo->eval_fast_key_switch_core_ext(digits, eval_key_iterator->second, params_ql);

            // ba[0] += acc;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
            for (uint32_t j = 0; j < size_ql_p; ++j)
                ba[0].get_all_elements()[j] += acc.get_all_elements()[j];

            ba[0] = ba[0].automorphism_transform(auto_index, vec);
            ba[1] = ba[1].automorphism_transform(auto_index, vec);

            // lvl0 += ba[0]; lvl1 += ba[1];
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
            for (uint32_t j = 0; j < size_ql_p; ++j) {
                lvl0.get_all_elements()[j] += ba[0].get_all_elements()[j];
                lvl1.get_all_elements()[j] += ba[1].get_all_elements()[j];
            }

            gi = gi * g % m;
        }

        // acc += lvl0;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
        for (uint32_t j = 0; j < size_ql_p; ++j)
            acc.get_all_elements()[j] += lvl0.get_all_elements()[j];

        // Element 1 settles once per level from the level's extended sum: the next level's
        // rotations need its digit decomposition.
        cv[1] += lvl1.approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(), crypto_params->get_p_inv_modq_precon(),
                                    crypto_params->get_p_hat_inv_modp(), crypto_params->get_p_hat_inv_modp_precon(),
                                    crypto_params->get_p_hat_modq(), crypto_params->get_modq_barrett_mu(),
                                    crypto_params->get_t_inv_modp(), crypto_params->get_t_inv_modp_precon(), t,
                                    crypto_params->get_t_modq_precon());

        for (uint32_t r = radix; r > 1; r >>= 1)
            g = g * g % m;
    }

    cv[0] = acc.approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(), crypto_params->get_p_inv_modq_precon(),
                              crypto_params->get_p_hat_inv_modp(), crypto_params->get_p_hat_inv_modp_precon(),
                              crypto_params->get_p_hat_modq(), crypto_params->get_modq_barrett_mu(),
                              crypto_params->get_t_inv_modp(), crypto_params->get_t_inv_modp_precon(), t,
                              crypto_params->get_t_modq_precon());

    return result;
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum_2n(ConstCiphertext<Element> ciphertext, uint32_t batch_size,
                                                         uint32_t m,
                                                         const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
    if (batch_size <= 1)
        return ciphertext->clone();

    if (2 * batch_size < m)
        return eval_sum_radix_fold(ciphertext, 5, batch_size, m, eval_keys);

    auto result = eval_sum_radix_fold(ciphertext, 5, batch_size / 2, m, eval_keys);
    auto algo = ciphertext->get_crypto_context()->get_scheme();
    return algo->eval_add(result, algo->eval_automorphism(result, m - 1, eval_keys));
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum2n_complex(
        ConstCiphertext<Element> ciphertext, uint32_t batch_size, uint32_t m,
        const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
    return eval_sum_radix_fold(ciphertext, 5, batch_size, m, eval_keys);
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum2n_complex_rows(
        ConstCiphertext<Element> ciphertext, uint32_t row_size, uint32_t m,
        const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
    const uint32_t col_size = m / (4 * row_size);
    const uint32_t g0 = (NativeInteger(5).mod_exp(row_size, m)).convert_to_int<uint32_t>();
    return eval_sum_radix_fold(ciphertext, g0, col_size, m, eval_keys);
}

template <class Element>
Ciphertext<Element> BaseAdvancedShe<Element>::eval_sum2n_complex_cols(
        ConstCiphertext<Element> ciphertext, uint32_t batch_size, uint32_t m,
        const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
    const uint32_t g0 = NativeInteger(5).mod_inverse(m).convert_to_int<uint32_t>();
    return eval_sum_radix_fold(ciphertext, g0, batch_size, m, eval_keys);
}

}  // namespace cipher

// the code below is from base-advancedshe-impl.cpp
namespace cipher {

template class BaseAdvancedShe<RnsPoly>;

}  // namespace cipher
