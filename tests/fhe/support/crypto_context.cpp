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

#include "fhe/support/crypto_context.h"

#include <cmath>
#include <cstdint>
#include <type_traits>

#include "cipher/fhe/context_gen.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/fhe/bgv/context_gen.h"
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

template <typename U>
static void set_crypto_context_parameters_from_unit_test_cc_params(const TestContextParams& params, U& parameters) {
    if (!is_default_value(params.ring_dimension_value)) {
        parameters.set_ring_dim(static_cast<uint32_t>(std::round(params.ring_dimension_value)));
    }
    if (!is_default_value(params.multiplicative_depth)) {
        parameters.set_multiplicative_depth(static_cast<uint32_t>(std::round(params.multiplicative_depth)));
    }
    if constexpr (std::is_same_v<U, ContextParams<BgvRnsContext>> == false) {
        if (!is_default_value(params.scaling_mod_size)) {
            parameters.set_scaling_mod_size(static_cast<uint32_t>(std::round(params.scaling_mod_size)));
        }
    }
    if (!is_default_value(params.digit_size)) {
        parameters.set_digit_size(static_cast<uint32_t>(std::round(params.digit_size)));
    }
    if (!is_default_value(params.batch_size)) {
        parameters.set_batch_size(static_cast<uint32_t>(std::round(params.batch_size)));
    }
    if (!is_default_value(params.secret_key_dist)) {
        parameters.set_secret_key_dist(static_cast<SecretKeyDist>(std::round(params.secret_key_dist)));
    }
    if (!is_default_value(params.max_relin_sk_deg)) {
        parameters.set_max_relin_sk_deg(static_cast<int>(std::round(params.max_relin_sk_deg)));
    }
    if constexpr (std::is_same_v<U, ContextParams<BfvRnsContext>> == false) {
        if (!is_default_value(params.first_mod_size_value)) {
            parameters.set_first_mod_size(static_cast<uint32_t>(std::round(params.first_mod_size_value)));
        }
    }
    if (!is_default_value(params.security_level)) {
        parameters.set_security_level(static_cast<SecurityLevel>(std::round(params.security_level)));
    }
    if (!is_default_value(params.ks_tech)) {
        parameters.set_key_switch_technique(static_cast<KeySwitchTechnique>(std::round(params.ks_tech)));
    }
    if constexpr (std::is_same_v<U, ContextParams<BfvRnsContext>> == false) {
        if (!is_default_value(params.scal_tech)) {
            parameters.set_scaling_technique(static_cast<ScalingTechnique>(std::round(params.scal_tech)));
        }
    }
    if (!is_default_value(params.num_large_digits)) {
        parameters.set_num_large_digits(static_cast<uint32_t>(std::round(params.num_large_digits)));
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == false) {
        if (!is_default_value(params.plaintext_modulus)) {
            parameters.set_plaintext_modulus(static_cast<PlaintextModulus>(std::round(params.plaintext_modulus)));
        }
    }
    if (!is_default_value(params.standard_deviation)) {
        parameters.set_standard_deviation(params.standard_deviation);
    }
    if constexpr (std::is_same_v<U, ContextParams<BfvRnsContext>> == true) {
        if (!is_default_value(params.multiplication_technique)) {
            parameters.set_multiplication_technique(
                    static_cast<MultiplicationTechnique>(std::round(params.multiplication_technique)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<BfvRnsContext>> == true) {
        if (!is_default_value(params.encryption_technique)) {
            parameters.set_encryption_technique(static_cast<EncryptionTechnique>(std::round(params.encryption_technique)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == false) {
        if (!is_default_value(params.eval_add_count)) {
            parameters.set_eval_add_count(static_cast<uint32_t>(std::round(params.eval_add_count)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == false) {
        if (!is_default_value(params.key_switch_count)) {
            parameters.set_key_switch_count(static_cast<uint32_t>(std::round(params.key_switch_count)));
        }
    }
    if (!is_default_value(params.pre_mode)) {
        parameters.set_pre_mode(static_cast<ProxyReEncryptionMode>(std::round(params.pre_mode)));
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == false) {
        if (!is_default_value(params.multiparty_mode)) {
            parameters.set_multiparty_mode(static_cast<MultipartyMode>(std::round(params.multiparty_mode)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.decryption_noise_mode)) {
            parameters.set_decryption_noise_mode(static_cast<DecryptionNoiseMode>(std::round(params.decryption_noise_mode)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.execution_mode)) {
            parameters.set_execution_mode(static_cast<ExecutionMode>(std::round(params.execution_mode)));
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.noise_estimate)) {
            parameters.set_noise_estimate(params.noise_estimate);
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.register_word_size)) {
            parameters.set_register_word_size(params.register_word_size);
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.composite_degree)) {
            parameters.set_composite_degree(params.composite_degree);
        }
    }
    if constexpr (std::is_same_v<U, ContextParams<CkksRnsContext>> == true) {
        if (!is_default_value(params.ckks_data_type)) {
            parameters.set_ckks_data_type(static_cast<CkksDataType>(std::round(params.ckks_data_type)));
        }
    }
}
//===========================================================================================================
CryptoContext<Element> unit_test_generate_context(const TestContextParams& params) {
    CryptoContext<Element> cc(nullptr);
    if (CKKSRNS_SCHEME == params.scheme_id_value) {
        ContextParams<CkksRnsContext> parameters;
        set_crypto_context_parameters_from_unit_test_cc_params(params, parameters);

        cc = make_crypto_context(parameters);
    } else if (BFVRNS_SCHEME == params.scheme_id_value) {
        ContextParams<BfvRnsContext> parameters;
        set_crypto_context_parameters_from_unit_test_cc_params(params, parameters);

        cc = make_crypto_context(parameters);
    } else if (BGVRNS_SCHEME == params.scheme_id_value) {
        ContextParams<BgvRnsContext> parameters;
        set_crypto_context_parameters_from_unit_test_cc_params(params, parameters);

        cc = make_crypto_context(parameters);
    }

    if (!cc)
        CIPHER_THROW("Error generating crypto context.");

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(PRE);
    cc->enable(FHE);
    cc->enable(MULTIPARTY);

    return cc;
}

//===========================================================================================================
CryptoContext<Element> unit_test_generate_context(const BaseTestCase& test_case_value) {
    CryptoContext<Element> cc(nullptr);
    auto param_overrides = test_case_value.get_crypto_context_param_overrides();
    cipher::SCHEME scheme_id_value = cipher::convert_to_scheme(*param_overrides.begin());
    if (CKKSRNS_SCHEME == scheme_id_value) {
        ContextParams<CkksRnsContext> parameters(param_overrides);
        cc = make_crypto_context(parameters);
    } else if (BFVRNS_SCHEME == scheme_id_value) {
        ContextParams<BfvRnsContext> parameters(param_overrides);
        cc = make_crypto_context(parameters);
    } else if (BGVRNS_SCHEME == scheme_id_value) {
        ContextParams<BgvRnsContext> parameters(param_overrides);
        cc = make_crypto_context(parameters);
    }

    if (!cc)
        CIPHER_THROW("Error generating crypto context.");

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(PRE);
    cc->enable(FHE);
    cc->enable(MULTIPARTY);

    return cc;
}
