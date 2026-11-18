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
  Collection of parameter default values for different schemes
 */

#ifndef CIPHER_FHE_CONFIG_PARAMS_DEFAULTS_H_
#define CIPHER_FHE_CONFIG_PARAMS_DEFAULTS_H_

#include <cstdint>

#include "cipher/fhe/constants.h"
#include "cipher/ring/ring_constants.h"   // SecretKeyDist
#include "cipher/ring/standard_params.h"  // SecurityLevel
#include "cipher/fhe/config/scheme_id.h"  // SCHEME
#include "cipher/util/inttypes.h"

namespace cipher {

namespace CKKSRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme = CKKSRNS_SCHEME;
constexpr PlaintextModulus pt_modulus = 0;
constexpr uint32_t digit_size = 0;
constexpr float standard_deviation = 3.19f;
constexpr SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
constexpr uint32_t max_relin_sk_deg = 2;
constexpr KeySwitchTechnique ks_tech = HYBRID;
// Backend-specific settings for CKKS
#if CIPHER_NATIVE_INT == 128
constexpr ScalingTechnique scal_tech = FIXEDAUTO;
constexpr uint32_t first_mod_size_value = 89;
constexpr uint32_t scaling_mod_size = 78;
#else
constexpr ScalingTechnique scal_tech = FLEXIBLEAUTOEXT;
constexpr uint32_t first_mod_size_value = 60;
constexpr uint32_t scaling_mod_size = 50;
#endif
constexpr uint32_t batch_size = 0;
constexpr uint32_t num_large_digits = 0;
constexpr uint32_t multiplicative_depth = 1;
constexpr SecurityLevel security_level = HEStd_128_classic;
constexpr uint32_t ring_dim = 0;
constexpr uint32_t eval_add_count = 0;
constexpr uint32_t key_switch_count = 0;
constexpr EncryptionTechnique encryption_technique = STANDARD;
constexpr MultiplicationTechnique multiplication_technique = HPS;
constexpr uint32_t pre_num_hops = 0;
constexpr ProxyReEncryptionMode pre_mode = NOT_SET;
constexpr MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode execution_mode = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT;
constexpr double noise_estimate = 0.0;
constexpr double desired_precision = 25.0;
constexpr uint32_t statistical_security = 30;
constexpr uint32_t num_adversarial_queries = 1;
constexpr uint32_t threshold_num_of_parties = 1;
constexpr CompressionLevel interactive_boot_compression_level = SLACK;
constexpr uint32_t composite_degree = 1;
constexpr uint32_t register_word_size = CIPHER_NATIVE_INT;
constexpr CkksDataType ckks_data_type = REAL;
};  // namespace CKKSRNS_SCHEME_DEFAULTS

namespace BFVRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme = BFVRNS_SCHEME;
constexpr PlaintextModulus pt_modulus = 0;
constexpr uint32_t digit_size = 0;
constexpr float standard_deviation = 3.19f;
constexpr SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
constexpr uint32_t max_relin_sk_deg = 2;
constexpr KeySwitchTechnique ks_tech = BV;
constexpr ScalingTechnique scal_tech = NORESCALE;
constexpr uint32_t first_mod_size_value = 0;
constexpr uint32_t batch_size = 0;
constexpr uint32_t num_large_digits = 0;
constexpr uint32_t multiplicative_depth = 1;
constexpr uint32_t scaling_mod_size = 60;
constexpr SecurityLevel security_level = HEStd_128_classic;
constexpr uint32_t ring_dim = 0;
constexpr uint32_t eval_add_count = 0;
constexpr uint32_t key_switch_count = 0;
constexpr EncryptionTechnique encryption_technique = STANDARD;
constexpr MultiplicationTechnique multiplication_technique = HPSPOVERQLEVELED;
constexpr uint32_t pre_num_hops = 0;
constexpr ProxyReEncryptionMode pre_mode = NOT_SET;
constexpr MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode execution_mode = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT;
constexpr double noise_estimate = 0.0;
constexpr double desired_precision = 0.0;
constexpr uint32_t statistical_security = 0;
constexpr uint32_t num_adversarial_queries = 0;
constexpr uint32_t threshold_num_of_parties = 1;
constexpr CompressionLevel interactive_boot_compression_level = SLACK;
constexpr uint32_t composite_degree = 1;
constexpr uint32_t register_word_size = CIPHER_NATIVE_INT;
constexpr CkksDataType ckks_data_type = REAL;
};  // namespace BFVRNS_SCHEME_DEFAULTS

namespace BGVRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme = BGVRNS_SCHEME;
constexpr PlaintextModulus pt_modulus = 0;
constexpr uint32_t digit_size = 0;
constexpr float standard_deviation = 3.19f;
constexpr SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
constexpr uint32_t max_relin_sk_deg = 2;
constexpr KeySwitchTechnique ks_tech = HYBRID;
constexpr ScalingTechnique scal_tech = FLEXIBLEAUTOEXT;
constexpr uint32_t first_mod_size_value = 0;
constexpr uint32_t batch_size = 0;
constexpr uint32_t num_large_digits = 0;
constexpr uint32_t multiplicative_depth = 1;
constexpr uint32_t scaling_mod_size = 0;
constexpr SecurityLevel security_level = HEStd_128_classic;
constexpr uint32_t ring_dim = 0;
constexpr uint32_t eval_add_count = 5;
constexpr uint32_t key_switch_count = 3;
constexpr EncryptionTechnique encryption_technique = STANDARD;
constexpr MultiplicationTechnique multiplication_technique = HPS;
constexpr uint32_t pre_num_hops = 0;
constexpr ProxyReEncryptionMode pre_mode = NOT_SET;
constexpr MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode execution_mode = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT;
constexpr double noise_estimate = 0.0;
constexpr double desired_precision = 0.0;
constexpr uint32_t statistical_security = 30;
constexpr uint32_t num_adversarial_queries = 1;
constexpr uint32_t threshold_num_of_parties = 1;
constexpr CompressionLevel interactive_boot_compression_level = SLACK;
constexpr uint32_t composite_degree = 1;
constexpr uint32_t register_word_size = CIPHER_NATIVE_INT;
constexpr CkksDataType ckks_data_type = REAL;
};  // namespace BGVRNS_SCHEME_DEFAULTS

//====================================================================================================================

}  // namespace cipher

#endif  // CIPHER_FHE_CONFIG_PARAMS_DEFAULTS_H_
