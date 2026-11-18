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

#ifndef CIPHER_FHE_RNS_SCHEME_H_
#define CIPHER_FHE_RNS_SCHEME_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/constants.h"
#include "cipher/fhe/keyswitch/bv.h"
#include "cipher/fhe/keyswitch/hybrid.h"
#include "cipher/ring/backend.h"
#include "cipher/fhe/base/scheme.h"
#include "cipher/fhe/rns/advanced_she.h"
#include "cipher/fhe/rns/crypto_params.h"
#include "cipher/fhe/rns/leveled_she.h"
#include "cipher/fhe/rns/multiparty.h"
#include "cipher/fhe/rns/param_gen.h"
#include "cipher/fhe/rns/pke.h"
#include "cipher/fhe/rns/pre.h"
#include "cipher/util/exception.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief RNS implementation of the scheme interface (all crypto components for DCRTPoly)
 */
class SchemeRNS : public SchemeBase<DCRTPoly> {
  public:
    SchemeRNS() = default;

    virtual ~SchemeRNS() = default;

    /**
     * Instantiates the key switching component for the given technique (KeySwitchBV or KeySwitchHYBRID).
     * Must be called with the key switching technique from the crypto parameters before any key switching.
     *
     * @param ksTech the key switching technique (BV or HYBRID); any other value throws.
     */
    void SetKeySwitchingTechnique(KeySwitchTechnique ksTech) {
        if (ksTech == BV) {
            m_KeySwitch = std::make_shared<KeySwitchBV>();
        } else if (ksTech == HYBRID) {
            m_KeySwitch = std::make_shared<KeySwitchHYBRID>();
        } else
            OPENFHE_THROW("ksTech is invalid");
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<SchemeBase<DCRTPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::base_class<SchemeBase<DCRTPoly>>(this));
    }

    std::string SerializedObjectName() const override {
        return "SchemeRNS";
    }
};

}  // namespace lbcrypto

#endif  // CIPHER_FHE_RNS_SCHEME_H_
