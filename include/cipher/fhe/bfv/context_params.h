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
  Parameter class to generate BFVRNS crypto context
 */

#ifndef CIPHER_FHE_BFV_CONTEXT_PARAMS_H_
#define CIPHER_FHE_BFV_CONTEXT_PARAMS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "cipher/fhe/config/params.h"

namespace cipher {

class BfvRnsContext;

// TODO (dsuponit): review class ContextParams<> as we may need to add a class template ContextParams<> (see the comments below)
// every ContextParams class should include the following forward declaration as there is
// no general ContextParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class ContextParams;
//====================================================================================================================
template <>
/**
 * @brief Parameters for generating a BFV crypto context. Initializes the BFV defaults and disables the
 * setters that do not apply to BFV (they throw when called).
 */
class ContextParams<BfvRnsContext> : public Params {
  public:
    ContextParams() : Params(BFVRNS_SCHEME) {}
    /**
     * Constructor from string values; to be used by unit tests only.
     *
     * @param vals vector with override values in the order given by Params::get_all_params_data_members().
     */
    explicit ContextParams(const std::vector<std::string>& vals) : Params(vals) {}
    ContextParams(const ContextParams& obj) = default;
    ContextParams(ContextParams&& obj) = default;
    ~ContextParams() = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to BFVRNS
    //================================================================================================================
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param scal_tech0 ignored.
     */
    void set_scaling_technique(ScalingTechnique scal_tech0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param first_mod_size0 ignored.
     */
    void set_first_mod_size(uint32_t first_mod_size0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param pre_num_hops0 ignored.
     */
    void set_pre_num_hops(uint32_t pre_num_hops0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param execution_mode0 ignored.
     */
    void set_execution_mode(ExecutionMode execution_mode0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param decryption_noise_mode0 ignored.
     */
    void set_decryption_noise_mode(DecryptionNoiseMode decryption_noise_mode0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param noise_estimate0 ignored.
     */
    void set_noise_estimate(double noise_estimate0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param desired_precision0 ignored.
     */
    void set_desired_precision(double desired_precision0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param statistical_security0 ignored.
     */
    void set_statistical_security(uint32_t statistical_security0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param num_adversarial_queries0 ignored.
     */
    void set_num_adversarial_queries(uint32_t num_adversarial_queries0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param interactive_boot_compression_level0 ignored.
     */
    void set_interactive_boot_compression_level(CompressionLevel interactive_boot_compression_level0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param composite_degree0 ignored.
     */
    void set_composite_degree(uint32_t composite_degree0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param register_word_size0 ignored.
     */
    void set_register_word_size(uint32_t register_word_size0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param ckks_data_type0 ignored.
     */
    void set_ckks_data_type(CkksDataType ckks_data_type0) override {
        DISABLED_FOR_BFVRNS;
    }
};
//====================================================================================================================

}  // namespace cipher

#endif  // CIPHER_FHE_BFV_CONTEXT_PARAMS_H_
