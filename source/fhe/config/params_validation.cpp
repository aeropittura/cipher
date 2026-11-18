//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
#include "cipher/fhe/config/params_validation.h"

#include <cmath>
#include <cstdint>
#include <string>

#include "cipher/fhe/rns/modulus_limits.h"
#include "cipher/util/exception.h"
#include "cipher/util/utilities.h"

namespace cipher {

void validate_parameters_for_cryptocontext(const Params& parameters) {
    SCHEME scheme = parameters.get_scheme();
    if (is_ckks(scheme)) {
#if CIPHER_NATIVE_INT == 128
        if (parameters.get_scaling_technique() == FLEXIBLEAUTO || parameters.get_scaling_technique() == FLEXIBLEAUTOEXT ||
            parameters.get_scaling_technique() == COMPOSITESCALINGAUTO ||
            parameters.get_scaling_technique() == COMPOSITESCALINGMANUAL) {
            CIPHER_THROW(
                    "128-bit CKKS is not supported with the FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO or COMPOSITESCALINGMANUAL scaling technique.");
        }
#endif
        if (NORESCALE == parameters.get_scaling_technique()) {
            CIPHER_THROW("NORESCALE is not supported in CKKSRNS");
        } else if (COMPOSITESCALINGAUTO == parameters.get_scaling_technique()) {
            if (1 != parameters.get_composite_degree()) {
                CIPHER_THROW("Composite degree can be set for COMPOSITESCALINGMANUAL only.");
            }
        } else if (COMPOSITESCALINGMANUAL == parameters.get_scaling_technique()) {
            if (parameters.get_composite_degree() < 1 || parameters.get_composite_degree() > 4) {
                CIPHER_THROW("Composite degree valid values: 1, 2, 3, and 4.");
            }
        }
        if (NOISE_FLOODING_HRA == parameters.get_pre_mode()) {
            CIPHER_THROW("NOISE_FLOODING_HRA is not supported in CKKSRNS");
        }
        if (NOISE_FLOODING_MULTIPARTY == parameters.get_multiparty_mode()) {
            CIPHER_THROW(
                    "NOISE_FLOODING_MULTIPARTY is not supported in CKKSRNS. Use NOISE_FLOODING_DECRYPT and EXEC_EVALUATION instead.");
        }
        if (COMPOSITESCALINGAUTO == parameters.get_scaling_technique() ||
            COMPOSITESCALINGMANUAL == parameters.get_scaling_technique()) {
            if (COMPOSITESCALING_MAX_MODULUS_SIZE <= parameters.get_scaling_mod_size() ||
                DCRT_MODULUS::MIN_SIZE > parameters.get_scaling_mod_size()) {
                CIPHER_THROW("scalingModSize should be at least " + std::to_string(DCRT_MODULUS::MIN_SIZE) +
                              " and less than " + std::to_string(COMPOSITESCALING_MAX_MODULUS_SIZE));
            }
            if (SPARSE_ENCAPSULATED == parameters.get_secret_key_dist() && parameters.get_first_mod_size() > 121) {
                CIPHER_THROW(
                        "SPARSE_ENCAPSULATED with COMPOSITESCALING* supports a first modulus of at most 121 bits");
            }
        } else {
            if (MAX_MODULUS_SIZE <= parameters.get_scaling_mod_size() ||
                DCRT_MODULUS::MIN_SIZE > parameters.get_scaling_mod_size()) {
                CIPHER_THROW("scalingModSize should be at least " + std::to_string(DCRT_MODULUS::MIN_SIZE) +
                              " and less than " + std::to_string(MAX_MODULUS_SIZE));
            }
        }
        if (30 != parameters.get_statistical_security()) {
            if (NOISE_FLOODING_MULTIPARTY != parameters.get_multiparty_mode()) {
                CIPHER_THROW("statisticalSecurity is allowed for multipartyMode == NOISE_FLOODING_MULTIPARTY only");
            }
        }
        if (1 != parameters.get_num_adversarial_queries()) {
            if (NOISE_FLOODING_MULTIPARTY != parameters.get_multiparty_mode()) {
                CIPHER_THROW("numAdversarialQueries is allowed for multipartyMode == NOISE_FLOODING_MULTIPARTY only");
            }
        }
        if (parameters.get_execution_mode() == EXEC_NOISE_ESTIMATION && parameters.get_ckks_data_type() == COMPLEX) {
            CIPHER_THROW("EXEC_NOISE_ESTIMATION mode is not compatible with complex data types.");
        }
        if (parameters.get_first_mod_size() < parameters.get_scaling_mod_size()) {
            CIPHER_THROW("firstModSize cannot be less than scalingModSize");
        }
        if (parameters.get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
            parameters.get_execution_mode() == EXEC_EVALUATION) {
            if (parameters.get_noise_estimate() == 0) {
                CIPHER_THROW(
                        "Noise estimate must be set for the combination of NOISE_FLOODING_DECRYPT and EXEC_EVALUATION modes.");
            }
        }
    } else if (is_bfvrns(scheme)) {
        if (0 == parameters.get_plaintext_modulus()) {
            CIPHER_THROW("PlaintextModulus is not set. It should be set to a non-zero value");
        }
        if (NOISE_FLOODING_HRA == parameters.get_pre_mode()) {
            CIPHER_THROW("NOISE_FLOODING_HRA is not supported in BFVRNS");
        }
        if (SPARSE_ENCAPSULATED == parameters.get_secret_key_dist()) {
            CIPHER_THROW("SPARSE_ENCAPSULATED not yet supported with BFVRNS");
        }
    } else if (is_bgvrns(scheme)) {
        if (0 == parameters.get_plaintext_modulus()) {
            CIPHER_THROW("PlaintextModulus is not set. It should be set to a non-zero value");
        }
        if (NORESCALE == parameters.get_scaling_technique()) {
            CIPHER_THROW("NORESCALE is not supported in BGVRNS");
        }
        if (NOISE_FLOODING_HRA == parameters.get_pre_mode()) {
            if (FIXEDMANUAL != parameters.get_scaling_technique()) {
                CIPHER_THROW("NOISE_FLOODING_HRA is allowed for scalingTechnique == FIXEDMANUAL only");
            }
            if (0 == parameters.get_pre_num_hops()) {
                CIPHER_THROW("PRENumHops should be set to a value > 0 for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.get_multiplicative_depth()) {
                CIPHER_THROW("multiplicativeDepth should be set to 0 for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.get_first_mod_size()) {
                CIPHER_THROW("firstModSize is not supported for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.get_scaling_mod_size()) {
                CIPHER_THROW("scalingModSize is not supported for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 == parameters.get_ring_dim()) {
                CIPHER_THROW("ringDim should be set to a value > 0 for PREMode == NOISE_FLOODING_HRA");
            }
        }
        if (0 != parameters.get_first_mod_size()) {
            if (FIXEDMANUAL != parameters.get_scaling_technique()) {
                CIPHER_THROW("firstModSize is allowed for scalingTechnique == FIXEDMANUAL only");
            }
        }
        if (0 != parameters.get_scaling_mod_size()) {
            if (FIXEDMANUAL != parameters.get_scaling_technique()) {
                CIPHER_THROW("scalingModSize is allowed for scalingTechnique == FIXEDMANUAL only");
            }
        }
        if (0 != parameters.get_pre_num_hops()) {
            if (NOISE_FLOODING_HRA != parameters.get_pre_mode()) {
                CIPHER_THROW("PRENumHops is allowed for PREMode == NOISE_FLOODING_HRA only");
            }
        }
        if (30 != parameters.get_statistical_security()) {
            if (NOISE_FLOODING_HRA != parameters.get_pre_mode()) {
                CIPHER_THROW("statisticalSecurity is allowed for PREMode == NOISE_FLOODING_HRA only");
            }
        }
        if (1 != parameters.get_num_adversarial_queries()) {
            if (NOISE_FLOODING_HRA != parameters.get_pre_mode()) {
                CIPHER_THROW("numAdversarialQueries is allowed for PREMode == NOISE_FLOODING_HRA only");
            }
        }
        if (SPARSE_ENCAPSULATED == parameters.get_secret_key_dist()) {
            CIPHER_THROW("SPARSE_ENCAPSULATED not yet supported with BGVRNS");
        }
    } else {
        std::string err_msg(std::string("Unknown schemeId: ") + std::to_string(scheme));
        CIPHER_THROW(err_msg);
    }

    //====================================================================================================================
    // general validations
    if (parameters.get_ring_dim() && !is_power_of_two(parameters.get_ring_dim())) {
        std::string error_msg(std::string("Invalid ringDim [") + std::to_string(parameters.get_ring_dim()) +
                             "]. Ring dimension must be a power of 2.");
        CIPHER_THROW(error_msg);
    }
    if (BV == parameters.get_key_switch_technique()) {
        const uint32_t max_digit_size = static_cast<uint32_t>(std::ceil(MAX_MODULUS_SIZE / 2));
        if (max_digit_size < parameters.get_digit_size()) {
            CIPHER_THROW("digitSize should not be greater than " + std::to_string(max_digit_size) +
                          " for keySwitchTechnique == BV");
        }
    }
    //====================================================================================================================
    constexpr uint32_t max_multiplicative_depth_value = 1000;
    if (parameters.get_multiplicative_depth() > max_multiplicative_depth_value) {
        std::string error_msg(std::string("The provided multiplicative depth [") +
                             std::to_string(parameters.get_multiplicative_depth()) +
                             "] is not computationally feasible. Use a smaller value.");
        CIPHER_THROW(error_msg);
    }
    //====================================================================================================================
}

}  // namespace cipher
