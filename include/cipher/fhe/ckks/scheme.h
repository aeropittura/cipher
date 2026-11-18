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

#ifndef CIPHER_FHE_CKKS_SCHEME_H_
#define CIPHER_FHE_CKKS_SCHEME_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/ckks/advanced_she.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/leveled_she.h"
#include "cipher/fhe/ckks/multiparty.h"
#include "cipher/fhe/ckks/param_gen.h"
#include "cipher/fhe/ckks/pke.h"
#include "cipher/fhe/ckks/pre.h"
#include "cipher/fhe/ckks/scheme_switching.h"
#include "cipher/fhe/rns/scheme.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief The CKKS scheme in RNS form: assembles the CKKS parameter generation, PKE, key switching, PRE,
 * leveled SHE, advanced SHE, multiparty, FHE (bootstrapping) and scheme switching capabilities. Capabilities
 * other than parameter generation are instantiated on demand by Enable.
 */
class CkksRnsScheme : public RnsScheme {
  public:
    /**
     * Constructs the scheme with its parameter generation capability; the other capabilities are created by
     * Enable.
     */
    CkksRnsScheme() {
        this->params_gen_ = std::make_shared<CkksRnsParamGen>();
    }

    virtual ~CkksRnsScheme() = default;

    /**
     * Compares two schemes by type: any two CkksRnsScheme objects are equal.
     *
     * @param sch the scheme to compare to
     * @return true if sch is a CkksRnsScheme
     */
    bool operator==(const SchemeBase<RnsPoly>& sch) const override {
        return (typeid(sch) == typeid(CkksRnsScheme));
    }

    /**
     * Enables a feature by instantiating the corresponding CKKS capability object (PKE, KEYSWITCH, PRE,
     * LEVELEDSHE, ADVANCEDSHE, MULTIPARTY, FHE or SCHEMESWITCH) if it is not enabled yet.
     *
     * @param feature the feature to enable
     */
    void enable(PkeSchemeFeature feature) override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<RnsScheme>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::base_class<RnsScheme>(this));
    }

    std::string serialized_object_name() const override {
        return "SchemeCKKSRNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_SCHEME_H_
