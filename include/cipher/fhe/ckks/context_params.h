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
  Parameter class to generate CKKSRNS crypto context
 */

#ifndef CIPHER_FHE_CKKS_CONTEXT_PARAMS_H_
#define CIPHER_FHE_CKKS_CONTEXT_PARAMS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "cipher/fhe/config/params.h"

namespace cipher {

class CkksRnsContext;

// every ContextParams class should include the following forward declaration as there is
// no general ContextParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class ContextParams;
//====================================================================================================================
/**
 * @brief Parameters for generating a CKKS cryptocontext. Disables the setters that do not apply to CKKS
 * (plaintext modulus, operation counts, encryption and multiplication techniques, PRE hops, multiparty mode and
 * threshold number of parties).
 */
template <>
class ContextParams<CkksRnsContext> : public Params {
  public:
    ContextParams() : Params(CKKSRNS_SCHEME) {}
    /**
     * Constructs the parameters from their string representation (one string per parameter, in the order of the
     * Params data members).
     *
     * @param vals the parameter values as strings
     */
    explicit ContextParams(const std::vector<std::string>& vals) : Params(vals) {}
    ContextParams(const ContextParams& obj) = default;
    ContextParams(ContextParams&& obj) noexcept = default;
    ~ContextParams() = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to CKKSRNS
    //================================================================================================================
    /**
     * Not applicable to CKKS (the plaintext modulus is the scaling modulus size); always throws.
     *
     * @param pt_modulus0 unused
     */
    void set_plaintext_modulus(PlaintextModulus pt_modulus0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param eval_add_count0 unused
     */
    void set_eval_add_count(uint32_t eval_add_count0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param key_switch_count0 unused
     */
    void set_key_switch_count(uint32_t key_switch_count0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param encryption_technique0 unused
     */
    void set_encryption_technique(EncryptionTechnique encryption_technique0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param multiplication_technique0 unused
     */
    void set_multiplication_technique(MultiplicationTechnique multiplication_technique0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param pre_num_hops0 unused
     */
    void set_pre_num_hops(uint32_t pre_num_hops0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param multiparty_mode0 unused
     */
    void set_multiparty_mode(MultipartyMode multiparty_mode0) override {
        DISABLED_FOR_CKKSRNS;
    }

    /**
     * Not applicable to CKKS; always throws.
     *
     * @param threshold_num_of_parties0 unused
     */
    void set_threshold_num_of_parties(uint32_t threshold_num_of_parties0) override {
        DISABLED_FOR_CKKSRNS;
    }
};
//====================================================================================================================

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_CONTEXT_PARAMS_H_
