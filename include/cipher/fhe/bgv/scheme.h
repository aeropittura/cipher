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

#ifndef CIPHER_FHE_BGV_SCHEME_H_
#define CIPHER_FHE_BGV_SCHEME_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/bgv/param_gen.h"
#include "cipher/fhe/rns/scheme.h"
#include "cipher/util/serializable.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief The BGV scheme in the RNS representation: instantiates the BGV parameter generation, PKE, PRE,
 * leveled SHE, advanced SHE, multiparty and FHE components.
 */
class BgvRnsScheme : public RnsScheme {
  public:
    BgvRnsScheme() {
        this->params_gen_ = std::make_shared<BgvRnsParamGen>();
    }

    virtual ~BgvRnsScheme() {}

    /**
     * Compares two schemes by type.
     *
     * @param sch the scheme to compare to.
     * @return true if sch is also a BgvRnsScheme.
     */
    bool operator==(const SchemeBase<RnsPoly>& sch) const override {
        return (typeid(sch) == typeid(BgvRnsScheme));
    }

    /**
     * Instantiates the BGV implementation of the given feature (PKE, PRE, LEVELEDSHE, MULTIPARTY, ADVANCEDSHE
     * or FHE) if it has not been instantiated yet. KEYSWITCH is set up separately by set_key_switching_technique().
     *
     * @param feature the feature to enable; unsupported features throw.
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
        return "SchemeBGVRNS";
    }
};
}  // namespace cipher

#endif  // CIPHER_FHE_BGV_SCHEME_H_
