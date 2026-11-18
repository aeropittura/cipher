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
  API to generate CKKSRNS crypto context
 */

#ifndef CIPHER_FHE_CKKS_CONTEXT_GEN_H_
#define CIPHER_FHE_CKKS_CONTEXT_GEN_H_

#include "cipher/fhe/context_factory.h"
#include "cipher/ring/backend.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/scheme.h"
#include "cipher/fhe/ckks/context_gen_internal.h"
#include "cipher/fhe/ckks/context_params.h"
#include "cipher/fhe/config/params_validation.h"

namespace cipher {

/**
 * @brief Generator of CKKS cryptocontexts; used as the template argument of ContextParams and make_crypto_context.
 */
class CkksRnsContext {
    using Element = RnsPoly;

  public:
    using ContextType = CryptoContext<Element>;       ///< the generated context type; required by make_crypto_context()
    using Factory = ContextFactory<Element>;          ///< the factory that creates and caches the contexts
    using PublicKeyEncryptionScheme = CkksRnsScheme;  ///< the scheme instantiated in the context
    using CryptoParams = CkksRnsCryptoParams;         ///< the crypto parameters instantiated in the context

    /**
     * Validates the parameters and generates a CKKS cryptocontext from them.
     *
     * @param parameters the CKKS parameters
     * @return the cryptocontext
     */
    static CryptoContext<Element> gen_crypto_context(const ContextParams<CkksRnsContext>& parameters) {
        validate_parameters_for_cryptocontext(parameters);
        return gen_crypto_context_ckksrns_internal<CkksRnsContext, Element>(parameters);
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_CONTEXT_GEN_H_
