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
  API to generate BGV crypto context
 */

#ifndef CIPHER_FHE_BGV_CONTEXT_GEN_H_
#define CIPHER_FHE_BGV_CONTEXT_GEN_H_

#include "cipher/fhe/context_fwd.h"
#include "cipher/ring/backend.h"
#include "cipher/fhe/bgv/crypto_params.h"
#include "cipher/fhe/bgv/scheme.h"
#include "cipher/fhe/bgv/context_gen_internal.h"
#include "cipher/fhe/bgv/context_params.h"
#include "cipher/fhe/config/params_validation.h"

namespace cipher {

template <typename Element>
class ContextFactory;

/**
 * @brief Context generator for the BGV scheme: binds the BGV scheme, crypto parameters and factory types
 * used by make_crypto_context() and builds a CryptoContext from ContextParams<BgvRnsContext>.
 */
class BgvRnsContext {
    using Element = RnsPoly;

  public:
    /**
     * The crypto context type produced by this generator (required by make_crypto_context()).
     */
    using ContextType = CryptoContext<Element>;  // required by make_crypto_context() in gen-cryptocontext.h
    /**
     * The factory that registers and returns the generated contexts.
     */
    using Factory = ContextFactory<Element>;
    /**
     * The scheme implementation class instantiated for the context.
     */
    using PublicKeyEncryptionScheme = BgvRnsScheme;
    /**
     * The crypto parameters class instantiated for the context.
     */
    using CryptoParams = BgvRnsCryptoParams;

    /**
     * Validates the parameters and generates a BGV crypto context from them.
     *
     * @param parameters the BGV parameters.
     * @return the generated crypto context.
     */
    static CryptoContext<Element> gen_crypto_context(const ContextParams<BgvRnsContext>& parameters) {
        validate_parameters_for_cryptocontext(parameters);
        return gen_crypto_context_bgvrns_internal<BgvRnsContext, Element>(parameters);
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BGV_CONTEXT_GEN_H_
