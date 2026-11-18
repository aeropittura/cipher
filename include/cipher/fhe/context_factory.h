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

#ifndef CIPHER_FHE_CONTEXT_FACTORY_H_
#define CIPHER_FHE_CONTEXT_FACTORY_H_

#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/context_fwd.h"
#include "cipher/ring/backend.h"
#include "cipher/fhe/config/scheme_id.h"
#include "cipher/util/memory.h"

namespace cipher {

template <typename Element>
class SchemeBase;
template <typename Element>
class BaseCryptoParams;

/**
 * @brief ContextFactory
 *
 * A class that contains all generated contexts and static methods to access/release them.
 * Contexts are deduplicated: get_context() returns the already registered context whose crypto parameters and
 * scheme compare equal to the requested ones, so keys and ciphertexts deserialized separately end up sharing
 * a single context instance.
 *
 * @tparam Element a ring element.
 */
template <typename Element>
class ContextFactory {
    static std::vector<CryptoContext<Element>> all_contexts;

  protected:
    /**
     * Looks up a registered context with equal crypto parameters and scheme.
     * If found and the context uses packed encoding, the PackedEncoding parameters are (re)initialized for it.
     *
     * @param params crypto parameters to match (compared by value)
     * @param scheme scheme object to match (compared by value)
     * @return the matching registered context, or nullptr if there is none
     */
    static CryptoContext<Element> find_context(std::shared_ptr<BaseCryptoParams<Element>> params,
                                              std::shared_ptr<SchemeBase<Element>> scheme);

    /**
     * Registers the given context and, if it uses packed encoding, initializes the PackedEncoding parameters
     * for it.
     */
    static void add_context(CryptoContext<Element>);

  public:
    /**
     * Releases all registered contexts: clears their CKKS caches and the static evaluation-key maps, empties the
     * registry and returns freed memory to the system.
     */
    static void release_all_contexts() {
        for (auto& cc : all_contexts) {
            if (cc)
                cc->clear_all_ckks_caches();
        }
        if (!all_contexts.empty())
            all_contexts[0]->clear_static_maps_and_vectors();
        all_contexts.clear();
        alloc_trim();
    }

    /**
     * Returns the number of registered contexts.
     *
     * @return the number of contexts currently held by the factory
     */
    static int get_context_count() {
        return all_contexts.size();
    }

    /**
     * Returns the registered context with equal crypto parameters and scheme, creating and registering a new one
     * if none exists yet.
     *
     * @param params crypto parameters of the context
     * @param scheme scheme object of the context
     * @param scheme_id_value scheme identifier stored in a newly created context (ignored if an existing one is found)
     * @return the shared context
     */
    static CryptoContext<Element> get_context(std::shared_ptr<BaseCryptoParams<Element>> params,
                                             std::shared_ptr<SchemeBase<Element>> scheme,
                                             SCHEME scheme_id_value = SCHEME::INVALID_SCHEME);

    /**
     * Returns the full registered context matching a (partial) context obtained by deserialization, registering
     * the deserialized context itself if no equal one exists. Callers that only include cryptocontext-fwd.h use
     * this instead of get_context() to avoid circular dependencies.
     *
     * @param context the deserialized context
     * @return the registered context with the same crypto parameters, scheme and scheme identifier
     */
    static CryptoContext<Element> get_full_context_by_deserialized_context(const CryptoContext<Element> context);

    /**
     * Returns all registered contexts.
     *
     * @return reference to the vector of registered contexts
     */
    static const std::vector<CryptoContext<Element>>& get_all_contexts() {
        return all_contexts;
    }
};

template <>
std::vector<CryptoContext<RnsPoly>> ContextFactory<RnsPoly>::all_contexts;

}  // namespace cipher

#endif  // CIPHER_FHE_CONTEXT_FACTORY_H_
