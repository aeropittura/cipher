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
  Definitions for scheme parameter default class
 */

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "cipher/fhe/config/params_defaults.h"
#include "cipher/fhe/config/params.h"
#include "cipher/util/exception.h"

namespace cipher {

//====================================================================================================================
#define SET_TO_SCHEME_DEFAULT(SCHEME, var) this->var = SCHEME##_DEFAULTS::var  // see cryptocontextparams-defaults.h
#define SET_TO_SCHEME_DEFAULTS(SCHEME)                                     \
    {                                                                      \
        SET_TO_SCHEME_DEFAULT(SCHEME, scheme);                             \
        SET_TO_SCHEME_DEFAULT(SCHEME, pt_modulus);                         \
        SET_TO_SCHEME_DEFAULT(SCHEME, digit_size);                         \
        SET_TO_SCHEME_DEFAULT(SCHEME, standard_deviation);                 \
        SET_TO_SCHEME_DEFAULT(SCHEME, secret_key_dist);                    \
        SET_TO_SCHEME_DEFAULT(SCHEME, max_relin_sk_deg);                   \
        SET_TO_SCHEME_DEFAULT(SCHEME, ks_tech);                            \
        SET_TO_SCHEME_DEFAULT(SCHEME, scal_tech);                          \
        SET_TO_SCHEME_DEFAULT(SCHEME, batch_size);                         \
        SET_TO_SCHEME_DEFAULT(SCHEME, first_mod_size_value);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, num_large_digits);                   \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiplicative_depth);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, scaling_mod_size);                   \
        SET_TO_SCHEME_DEFAULT(SCHEME, security_level);                     \
        SET_TO_SCHEME_DEFAULT(SCHEME, ring_dim);                           \
        SET_TO_SCHEME_DEFAULT(SCHEME, eval_add_count);                     \
        SET_TO_SCHEME_DEFAULT(SCHEME, key_switch_count);                   \
        SET_TO_SCHEME_DEFAULT(SCHEME, encryption_technique);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiplication_technique);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, pre_num_hops);                       \
        SET_TO_SCHEME_DEFAULT(SCHEME, pre_mode);                           \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiparty_mode);                    \
        SET_TO_SCHEME_DEFAULT(SCHEME, execution_mode);                     \
        SET_TO_SCHEME_DEFAULT(SCHEME, decryption_noise_mode);              \
        SET_TO_SCHEME_DEFAULT(SCHEME, noise_estimate);                     \
        SET_TO_SCHEME_DEFAULT(SCHEME, desired_precision);                  \
        SET_TO_SCHEME_DEFAULT(SCHEME, statistical_security);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, num_adversarial_queries);            \
        SET_TO_SCHEME_DEFAULT(SCHEME, threshold_num_of_parties);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, interactive_boot_compression_level); \
        SET_TO_SCHEME_DEFAULT(SCHEME, composite_degree);                   \
        SET_TO_SCHEME_DEFAULT(SCHEME, register_word_size);                 \
        SET_TO_SCHEME_DEFAULT(SCHEME, ckks_data_type);                     \
    }
void Params::set_to_defaults(SCHEME scheme) {
    switch (scheme) {
        case CKKSRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(CKKSRNS_SCHEME);
            break;
        case BFVRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(BFVRNS_SCHEME);
            break;
        case BGVRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(BGVRNS_SCHEME);
            break;
        default:
            std::string error_msg(std::string("Invalid scheme id: ") + std::to_string(scheme));
            CIPHER_THROW(error_msg);
            break;
    }
}
//====================================================================================================================
Params::Params(const std::vector<std::string>& vals) {
    if (get_all_params_data_members().size() != vals.size()) {
        std::string err_msg(std::string("The number of data members and the number of values do not match: ") +
                            std::to_string(get_all_params_data_members().size()) +
                            " != " + std::to_string(vals.size()));
        CIPHER_THROW(err_msg);
    }

    auto it = vals.begin();
    set_to_defaults(convert_to_scheme(*it));

    if (!(++it)->empty())
        pt_modulus = static_cast<PlaintextModulus>(std::stoul(*it));
    if (!(++it)->empty())
        digit_size = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        standard_deviation = static_cast<float>(std::stof(*it));
    if (!(++it)->empty())
        secret_key_dist = convert_to_secret_key_dist(*it);
    if (!(++it)->empty())
        max_relin_sk_deg = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        ks_tech = convert_to_key_switch_technique(*it);
    if (!(++it)->empty())
        scal_tech = convert_to_scaling_technique(*it);
    if (!(++it)->empty())
        first_mod_size_value = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        batch_size = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        num_large_digits = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        multiplicative_depth = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        scaling_mod_size = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        security_level = convert_to_security_level(*it);
    if (!(++it)->empty())
        ring_dim = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        eval_add_count = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        key_switch_count = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        encryption_technique = convert_to_encryption_technique(*it);
    if (!(++it)->empty())
        multiplication_technique = convert_to_multiplication_technique(*it);
    if (!(++it)->empty())
        pre_num_hops = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        pre_mode = convert_to_proxy_re_encryption_mode(*it);
    if (!(++it)->empty())
        multiparty_mode = convert_to_multiparty_mode(*it);
    if (!(++it)->empty())
        execution_mode = convert_to_execution_mode(*it);
    if (!(++it)->empty())
        decryption_noise_mode = convert_to_decryption_noise_mode(*it);
    if (!(++it)->empty())
        noise_estimate = std::stod(*it);
    if (!(++it)->empty())
        desired_precision = std::stod(*it);
    if (!(++it)->empty())
        statistical_security = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        num_adversarial_queries = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        threshold_num_of_parties = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        interactive_boot_compression_level = convert_to_compression_level(*it);
    if (!(++it)->empty())
        composite_degree = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        register_word_size = static_cast<uint32_t>(std::stoul(*it));
    if (!(++it)->empty())
        ckks_data_type = convert_to_ckks_data_type(*it);
}
//====================================================================================================================
// clang-format off
std::ostream& operator<<(std::ostream& os, const Params& obj) {
    os  << "scheme: " << obj.scheme
        << "; ptModulus: " << obj.pt_modulus
        << "; digitSize: " << obj.digit_size
        << "; standardDeviation: " << obj.standard_deviation
        << "; secretKeyDist: " << obj.secret_key_dist
        << "; maxRelinSkDeg: " << obj.max_relin_sk_deg
        << "; ksTech: " << obj.ks_tech
        << "; scalTech: " << obj.scal_tech
        << "; batchSize: " << obj.batch_size
        << "; firstModSize: " << obj.first_mod_size_value
        << "; numLargeDigits: " << obj.num_large_digits
        << "; multiplicativeDepth:" << obj.multiplicative_depth
        << "; scalingModSize: " << obj.scaling_mod_size
        << "; securityLevel: " << obj.security_level
        << "; ringDim: " << obj.ring_dim
        << "; evalAddCount: " << obj.eval_add_count
        << "; keySwitchCount: " << obj.key_switch_count
        << "; encryptionTechnique: " << obj.encryption_technique
        << "; multiplicationTechnique: " << obj.multiplication_technique
        << "; PRENumHops: " << obj.pre_num_hops
        << "; PREMode: " << obj.pre_mode
        << "; multipartyMode: " << obj.multiparty_mode
        << "; executionMode: " << obj.execution_mode
        << "; decryptionNoiseMode: " << obj.decryption_noise_mode
        << "; noiseEstimate: " << obj.noise_estimate
        << "; desiredPrecision: " << obj.desired_precision
        << "; statisticalSecurity: " << obj.statistical_security
        << "; numAdversarialQueries: " << obj.num_adversarial_queries
        << "; thresholdNumOfParties: " << obj.threshold_num_of_parties
        << "; interactiveBootCompressionLevel: " << obj.interactive_boot_compression_level
        << "; compositeDegree: " << obj.composite_degree
        << "; registerWordSize: " << obj.register_word_size
        << "; ckksDataType: " << obj.ckks_data_type;

    return os;
}
// clang-format on
//====================================================================================================================

}  // namespace cipher
