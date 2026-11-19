//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Example for checking CKKS bootstrap memory cleanup.

  eval_bootstrap_setup() caches precomputed data in the CKKS scheme. This example
  compares clear_bootstrap_precom() with release_all_contexts() while keeping the
  local CryptoContext handle alive.
*/

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#if defined(__GLIBC__)
    #include <malloc.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#endif

#include "cipher/cipher.h"
#include "cipher/util/memory.h"

using namespace cipher;

std::size_t heap_in_use_bytes() {
#if defined(__GLIBC__)
    auto info = mallinfo2();
    return info.uordblks;
#elif defined(__APPLE__)
    malloc_statistics_t s{};
    malloc_zone_statistics(malloc_default_zone(), &s);
    return s.size_in_use;
#else
    CIPHER_THROW("heap probe unavailable on this allocator");
#endif
}

static CryptoContext<RnsPoly> build_bootstrap_context() {
    ContextParams<CkksRnsContext> parameters;
    // SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128). UNIFORM_TERNARY,
    // used here, is the distribution of the homomorphic encryption security guidelines; its probability of failure is
    // 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    SecretKeyDist sk_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(sk_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

    parameters.set_scaling_mod_size(59);
    parameters.set_first_mod_size(60);
    parameters.set_scaling_technique(FLEXIBLEAUTO);

    std::vector<uint32_t> level_budget = {4, 4};
    uint32_t depth = 10 + CkksRnsFhe::get_bootstrap_depth(level_budget, sk_dist);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);
    return cc;
}

int main() {
    auto cc = build_bootstrap_context();
    uint32_t ring_dim = cc->get_ring_dimension();
    uint32_t num_slots = ring_dim / 2;

    std::cout << "ring dim = " << ring_dim << "\n";

    size_t before = heap_in_use_bytes();
    cc->eval_bootstrap_setup({4, 4}, {0, 0}, num_slots);
    size_t after = heap_in_use_bytes();
    cc->clear_bootstrap_precom();
    size_t after_cleanup = heap_in_use_bytes();
    std::cerr << "eval_bootstrap_setup(): before: " << before << "; after: " << after
              << "; after clear_bootstrap_precom(): " << after_cleanup << std::endl;

    before = heap_in_use_bytes();
    cc->eval_bootstrap_setup({4, 4}, {0, 0}, num_slots);
    after = heap_in_use_bytes();
    cc->clear_bootstrap_precom();
    after_cleanup = heap_in_use_bytes();
    ContextFactory<RnsPoly>::release_all_contexts();
    size_t final = heap_in_use_bytes();
    std::cerr << "eval_bootstrap_setup(): before: " << before << "; after: " << after
              << "; after clear_bootstrap_precom(): " << after_cleanup << "; after release_all_contexts(): " << final
              << std::endl;

    return 0;
}
