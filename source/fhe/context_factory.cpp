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
#include "cipher/fhe/context_factory.h"

#include <memory>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/config/scheme_id.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

template <>
std::vector<CryptoContext<RnsPoly>> ContextFactory<RnsPoly>::all_contexts = {};

template <typename Element>
CryptoContext<Element> ContextFactory<Element>::find_context(std::shared_ptr<BaseCryptoParams<Element>> params,
                                                                  std::shared_ptr<SchemeBase<Element>> scheme) {
    for (CryptoContext<Element> cc : ContextFactory<Element>::all_contexts) {
        if (*cc->get_scheme().get() == *scheme.get() && *cc->get_crypto_parameters().get() == *params.get()) {
            if (cc->get_encoding_params()->get_plaintext_root_of_unity() != 0) {
                PackedEncoding::set_params(cc->get_cyclotomic_order(), cc->get_encoding_params());
            }
            return cc;
        }
    }

    return nullptr;
}

template <typename Element>
void ContextFactory<Element>::add_context(CryptoContext<Element> cc) {
    ContextFactory<Element>::all_contexts.push_back(cc);

    if (cc->get_encoding_params()->get_plaintext_root_of_unity() != 0) {
        PackedEncoding::set_params(cc->get_cyclotomic_order(), cc->get_encoding_params());
    }
}

template <typename Element>
CryptoContext<Element> ContextFactory<Element>::get_context(std::shared_ptr<BaseCryptoParams<Element>> params,
                                                                 std::shared_ptr<SchemeBase<Element>> scheme,
                                                                 SCHEME scheme_id_value) {
    CryptoContext<Element> cc = find_context(params, scheme);
    // if the context is not found we should create one
    if (nullptr == cc) {
        cc = std::make_shared<CryptoContextImpl<Element>>(params, scheme, scheme_id_value);
        add_context(cc);
    }

    return cc;
}

template <typename Element>
CryptoContext<Element> ContextFactory<Element>::get_full_context_by_deserialized_context(
        const CryptoContext<Element> context) {
    return ContextFactory<Element>::get_context(context->get_crypto_parameters(), context->get_scheme(),
                                                     context->get_scheme_id_impl());
}

}  // namespace cipher

// the code below is from pke/lib/cryptocontextfactory-impl.cpp
namespace cipher {

template class ContextFactory<RnsPoly>;

}
