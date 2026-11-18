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
  API to generate CKKS crypto context. MUST NOT (!) be used without a wrapper function
 */

#ifndef CIPHER_FHE_CKKS_CONTEXT_GEN_INTERNAL_H_
#define CIPHER_FHE_CKKS_CONTEXT_GEN_INTERNAL_H_

#include <cmath>
#include <cstdint>
#include <memory>

#include "cipher/fhe/constants.h"
#include "cipher/fhe/context_fwd.h"
#include "cipher/fhe/encoding/encoding_params.h"
#include "cipher/fhe/config/scheme_id.h"
#include "cipher/fhe/config/scheme_utils.h"
#include "cipher/util/exception.h"

namespace cipher {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class ContextParams;

/**
 * Generates a CKKS cryptocontext from validated parameters: builds the encoding parameters (the scaling modulus
 * size acts as the plaintext modulus), the crypto parameters and the scheme, adjusts the scaling and first
 * modulus sizes for the NOISE_FLOODING_DECRYPT mode, runs the CKKS parameter generation and registers the context
 * with the factory. Must not be called directly; use make_crypto_context.
 *
 * @param parameters the CKKS parameters
 * @return the cryptocontext
 */
template <typename ContextGeneratorType, typename Element>
typename ContextGeneratorType::ContextType gen_crypto_context_ckksrns_internal(
        const ContextParams<ContextGeneratorType>& parameters) {
    using ParmType = typename Element::Params;
    constexpr float assurance_measure = 36.0f;

    auto ep = std::make_shared<ParmType>();

    uint32_t scaling_mod_size = parameters.get_scaling_mod_size();
    uint32_t first_mod_size_value = parameters.get_first_mod_size();
    double flooding_noise_std = 0;
    if (parameters.get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
        parameters.get_execution_mode() == EXEC_EVALUATION) {
        double logstd = parameters.get_statistical_security() / 2 +
                        std::log2(std::sqrt(12 * parameters.get_num_adversarial_queries()));
        flooding_noise_std = std::pow(2, logstd + parameters.get_noise_estimate());
#if CIPHER_NATIVE_INT == 128
        scaling_mod_size = parameters.get_desired_precision() + parameters.get_noise_estimate() + logstd +
                         0.5 * std::log2(parameters.get_ring_dim());
        first_mod_size_value = scaling_mod_size + 11;
#else
        scaling_mod_size = MAX_MODULUS_SIZE - 1;
        first_mod_size_value = MAX_MODULUS_SIZE;
        if (logstd + parameters.get_noise_estimate() > scaling_mod_size - 3) {
            CIPHER_THROW("Precision of less than 3 bits is not supported. logstd " + std::to_string(logstd) +
                          " + noiseEstimate " + std::to_string(parameters.get_noise_estimate()) + " must be 56 or less.");
        }
#endif
    }
    EncodingParams encoding_params(std::make_shared<EncodingParamsImpl>(scaling_mod_size, parameters.get_batch_size()));

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
        1,  // noise scale: TODO (dsuponit): this should be reviewed as we also call set_noise_scale(1) (see below)
        parameters.get_statistical_security(),
        parameters.get_num_adversarial_queries(),
        parameters.get_threshold_num_of_parties(),
        parameters.get_interactive_boot_compression_level(),
        parameters.get_composite_degree(),
        parameters.get_register_word_size(),
        parameters.get_ckks_data_type());

    // for CKKS scheme noise scale is always set to 1
    params->set_noise_scale(1);
    params->set_flooding_distribution_parameter(flooding_noise_std);
    params->set_multiplicative_depth(parameters.get_multiplicative_depth());
    params->set_noise_estimate(parameters.get_noise_estimate());

    uint32_t num_large_digits =
        compute_num_large_digits(parameters.get_num_large_digits(), parameters.get_multiplicative_depth());

    auto scheme = std::make_shared<typename ContextGeneratorType::PublicKeyEncryptionScheme>();
    scheme->set_key_switching_technique(parameters.get_key_switch_technique());
    scheme->params_gen_ckksrns(
        params,
        2 * parameters.get_ring_dim(),
        parameters.get_multiplicative_depth() + 1,
        scaling_mod_size,
        first_mod_size_value,
        num_large_digits,
        parameters.get_interactive_boot_compression_level());
    // clang-format on

    auto cc = ContextGeneratorType::Factory::get_context(params, scheme);
    cc->set_scheme_id(SCHEME::CKKSRNS_SCHEME);
    return cc;
}
}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_CONTEXT_GEN_INTERNAL_H_
