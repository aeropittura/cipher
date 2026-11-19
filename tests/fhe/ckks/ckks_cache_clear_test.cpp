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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/boolean/context.h"
#include "gtest/gtest.h"
#include "cipher/cipher.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/scheme_switching.h"
#include "cipher/fhe/config/switching_params.h"
#include "cipher/util/memory.h"

#if defined(__GLIBC__)
    #include <malloc.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#endif

#if defined(__GLIBC__) || defined(__APPLE__)
    #define CIPHER_HAS_HEAP_PROBE 1
#else
    #define CIPHER_HAS_HEAP_PROBE 0
#endif

using namespace cipher;

namespace {
std::size_t heap_in_use_bytes() {
#if CIPHER_HAS_HEAP_PROBE
    #if defined(__GLIBC__)
    auto info = mallinfo2();
    return info.uordblks;
    #else
    malloc_statistics_t s{};
    malloc_zone_statistics(malloc_default_zone(), &s);
    return s.size_in_use;
    #endif
#else
    CIPHER_THROW("heap probe unavailable on this allocator");
#endif
}

CryptoContext<RnsPoly> make_bootstrap_cc(uint32_t ring_dim = 1 << 8) {
    ContextParams<CkksRnsContext> params;
    SecretKeyDist sk_dist = UNIFORM_TERNARY;
    params.set_secret_key_dist(sk_dist);
    params.set_security_level(HEStd_NotSet);
    params.set_ring_dim(ring_dim);
#if CIPHER_NATIVE_INT == 128
    params.set_scaling_mod_size(78);
    params.set_first_mod_size(89);
    params.set_scaling_technique(FIXEDAUTO);
#else
    params.set_scaling_mod_size(59);
    params.set_first_mod_size(60);
    params.set_scaling_technique(FLEXIBLEAUTO);
#endif
    std::vector<uint32_t> level_budget = {1, 1};
    uint32_t depth = 2 + CkksRnsFhe::get_bootstrap_depth(level_budget, sk_dist);
    params.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(params);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);
    return cc;
}
CryptoContext<RnsPoly> make_scheme_switch_cc() {
    ContextParams<CkksRnsContext> params;
    params.set_multiplicative_depth(3);
#if CIPHER_NATIVE_INT == 128
    params.set_first_mod_size(89);
    params.set_scaling_mod_size(78);
    params.set_scaling_technique(FIXEDAUTO);
#else
    params.set_first_mod_size(60);
    params.set_scaling_mod_size(50);
    params.set_scaling_technique(FLEXIBLEAUTOEXT);
#endif
    params.set_security_level(HEStd_NotSet);
    params.set_ring_dim(1 << 12);
    params.set_batch_size(16);
    auto cc = make_crypto_context(params);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(SCHEMESWITCH);
    return cc;
}

}  // namespace

class CkksCacheClearTest : public ::testing::Test {
  protected:
#if defined(CIPHER_WITH_TCM) || !CIPHER_HAS_HEAP_PROBE
    void SetUp() override {
    #if defined(CIPHER_WITH_TCM)
        GTEST_SKIP() << "Heap usage checks are not stable with tcmalloc enabled";
    #elif defined(__EMSCRIPTEN__)
        GTEST_SKIP() << "Heap probe unavailable under Emscripten";
    #elif defined(_WIN32)
        GTEST_SKIP() << "Heap probe unavailable on Windows";
    #else
        GTEST_SKIP() << "Heap probe unavailable on this allocator";
    #endif
    }
#endif

    void TearDown() override {
        ContextFactory<RnsPoly>::release_all_contexts();
    }
};

// These checks do not depend on allocator statistics and also run with tcmalloc and on platforms
// without a supported heap probe.
class CkksReleaseAllContextsTest : public ::testing::Test {
  protected:
    void TearDown() override {
        ContextFactory<RnsPoly>::release_all_contexts();
    }
};

TEST_F(CkksReleaseAllContextsTest, ClearsBootstrapPrecomWithLiveContext) {
    auto cc = make_bootstrap_cc();
    const std::vector<uint32_t> slot_counts{cc->get_ring_dimension() / 4, cc->get_ring_dimension() / 2};
    for (auto slots : slot_counts) {
        cc->eval_bootstrap_setup({1, 1}, {0, 0}, slots);
        ASSERT_FALSE(cc->get_scheme()->eval_bootstrap_key_map_indices(cc, slots).empty());
    }

    // Keep cc alive: dropping the factory's references alone must not make this test pass.
    ContextFactory<RnsPoly>::release_all_contexts();

    EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 0);
    for (auto slots : slot_counts) {
        EXPECT_THROW(cc->get_scheme()->eval_bootstrap_key_map_indices(cc, slots), CipherException);
    }
}

TEST_F(CkksReleaseAllContextsTest, ClearsSchemeSwitchPrecomWithLiveContext) {
    auto cc = make_scheme_switch_cc();
    auto kp = cc->key_gen();

    SchSwchParams p;
    p.set_security_level_ckks(HEStd_NotSet);
    p.set_security_level_fhew(TOY);
    p.set_ctxt_mod_size_fhew_large_prec(25);
    p.set_num_slots_ckks(16);
    auto lwe_sk = cc->eval_ckks_to_fhew_setup(p);
    cc->eval_ckks_to_fhew_key_gen(kp, lwe_sk);
    std::weak_ptr<BooleanContext> bin_cc = cc->get_bin_cc_for_scheme_switch();
    ASSERT_FALSE(bin_cc.expired());

    // Neither cc nor its keys go out of scope before the cache lifetime is checked.
    ContextFactory<RnsPoly>::release_all_contexts();

    EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 0);
    EXPECT_EQ(cc->get_bin_cc_for_scheme_switch(), nullptr);
    EXPECT_TRUE(bin_cc.expired());
}

// Full clear drops every slot-keyed entry in CkksRnsFhe::boot_precom_map_.
TEST_F(CkksCacheClearTest, FullBootstrapClear) {
    auto cc = make_bootstrap_cc();
    uint32_t num_slots = cc->get_ring_dimension() / 2;

    // The first eval_bootstrap_setup() grows per-thread allocator structures in
    // proportion to the OpenMP thread count, and those are not returned to the
    // heap. Running one setup and clear before the baseline is taken keeps that
    // growth out of the comparison, so what is measured is the bootstrap
    // precomputation alone rather than the thread count of the host.
    cc->eval_bootstrap_setup({1, 1}, {0, 0}, num_slots);
    cc->clear_bootstrap_precom();

    size_t before = heap_in_use_bytes();
    cc->eval_bootstrap_setup({1, 1}, {0, 0}, num_slots);
    // size_t after = heap_in_use_bytes();
    cc->clear_bootstrap_precom();
    // size_t after_cleanup = heap_in_use_bytes();
    ContextFactory<RnsPoly>::release_all_contexts();
    size_t final = heap_in_use_bytes();

    std::string failmsg{"clear_bootstrap_precom() may not clean all allocated memory"};
    EXPECT_TRUE(final <= before) << failmsg;

    // std::cerr << "FullBootstrapClear(): before: " << before << "; after: " << after
    //           << "; after cleanup: " << after_cleanup << "; after release_all_contexts(): " << final << std::endl;
}

TEST_F(CkksCacheClearTest, SchemeSwitchPrecomClear) {
    auto cc = make_scheme_switch_cc();
    auto kp = cc->key_gen();

    SchSwchParams p;
    p.set_security_level_ckks(HEStd_NotSet);
    p.set_security_level_fhew(TOY);
    p.set_ctxt_mod_size_fhew_large_prec(25);
    p.set_num_slots_ckks(16);
    size_t before = heap_in_use_bytes();
    auto lwe_sk = cc->eval_ckks_to_fhew_setup(p);
    cc->eval_ckks_to_fhew_key_gen(kp, lwe_sk);
    // size_t after = heap_in_use_bytes();
    cc->clear_scheme_switch_precom();
    cc->clear_static_maps_and_vectors();
    // size_t after_cleanup = heap_in_use_bytes();
    ContextFactory<RnsPoly>::release_all_contexts();
    size_t final = heap_in_use_bytes();

    std::string failmsg{"clear_scheme_switch_precom() may not clean all allocated memory"};
    EXPECT_TRUE(final <= before) << failmsg;

    // std::cerr << "SchemeSwitchPrecomClear(): before: " << before << "; after: " << after
    //           << "; after cleanup: " << after_cleanup << "; after release_all_contexts(): " << final << std::endl;
}
