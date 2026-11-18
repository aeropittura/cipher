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
  API to generate BGVRNS crypto context. MUST NOT (!) be used without a wrapper function
 */

#ifndef CIPHER_FHE_BGV_CONTEXT_GEN_INTERNAL_H_
#define CIPHER_FHE_BGV_CONTEXT_GEN_INTERNAL_H_

#include <memory>

#include "cipher/fhe/encoding/encoding_params.h"
#include "cipher/fhe/config/scheme_id.h"
#include "cipher/fhe/config/scheme_utils.h"

namespace cipher {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class ContextParams;

template <typename ContextGeneratorType, typename Element>
/**
 * Builds a BGV crypto context from the parameters: creates the crypto parameters object (with the noise
 * scale set to the plaintext modulus), computes the number of HYBRID digits, creates the scheme object
 * with the requested key switching technique, runs the BGV parameter generation for multiplicative_depth + 1
 * primes and registers the context with the factory. MUST NOT be used without the wrapper
 * BgvRnsContext::gen_crypto_context(), which validates the parameters first.
 *
 * @tparam ContextGeneratorType the context generator class (BgvRnsContext).
 * @tparam Element the ring element type (RnsPoly).
 * @param parameters the BGV parameters.
 * @return the generated crypto context.
 */
typename ContextGeneratorType::ContextType gen_crypto_context_bgvrns_internal(
        const ContextParams<ContextGeneratorType>& parameters) {
    using ParmType = typename Element::Params;
    constexpr float assurance_measure = 36.0f;

    auto ep = std::make_shared<ParmType>();
    EncodingParams encoding_params(
            std::make_shared<EncodingParamsImpl>(parameters.get_plaintext_modulus(), parameters.get_batch_size()));

    // clang-format off
    auto params = std::make_shared<typename ContextGeneratorType::CryptoParams>(
        ep,
        encoding_params,
        parameters.get_standard_deviation(),
        assurance_measure,
        parameters.get_security_level(),
        parameters.get_digit_size(),
        parameters.get_secret_key_dist(),
        parameters.get_max_relin_sk_deg(),
        parameters.get_key_switch_technique(),
        parameters.get_scaling_technique(),
        parameters.get_encryption_technique(),
        parameters.get_multiplication_technique(),
        parameters.get_pre_mode(),
        parameters.get_multiparty_mode(),
        parameters.get_execution_mode(),
        parameters.get_decryption_noise_mode(),
        parameters.get_plaintext_modulus(),
        parameters.get_statistical_security(),
        parameters.get_num_adversarial_queries(),
        parameters.get_threshold_num_of_parties());

    // for BGV scheme noise scale is always set to plaintext modulus
    params->set_noise_scale(parameters.get_plaintext_modulus());
    params->set_multiplicative_depth(parameters.get_multiplicative_depth());
    params->set_eval_add_count(parameters.get_eval_add_count());
    params->set_key_switch_count(parameters.get_key_switch_count());
    params->set_pre_num_hops(parameters.get_pre_num_hops());

    auto num_large_digits = (parameters.get_multiplicative_depth() == 0) ?
                              compute_num_large_digits_pre(parameters.get_num_large_digits(), parameters.get_pre_num_hops()) :
                              compute_num_large_digits(parameters.get_num_large_digits(), parameters.get_multiplicative_depth());

    auto scheme = std::make_shared<typename ContextGeneratorType::PublicKeyEncryptionScheme>();
    scheme->set_key_switching_technique(parameters.get_key_switch_technique());
    scheme->params_gen_bgvrns(
        params,
        parameters.get_eval_add_count(),
        parameters.get_key_switch_count(),
        2 * parameters.get_ring_dim(),
        parameters.get_multiplicative_depth() + 1,
        parameters.get_first_mod_size(),
        parameters.get_scaling_mod_size(),
        num_large_digits,
        parameters.get_pre_num_hops());
    // clang-format on

    auto cc = ContextGeneratorType::Factory::get_context(params, scheme);
    cc->set_scheme_id(SCHEME::BGVRNS_SCHEME);
    return cc;
}

}  // namespace cipher

#endif  // CIPHER_FHE_BGV_CONTEXT_GEN_INTERNAL_H_
