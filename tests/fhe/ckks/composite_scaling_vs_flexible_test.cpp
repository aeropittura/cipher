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
  Regression tests that COMPOSITESCALINGAUTO (CS) does not lose precision relative to
  FLEXIBLEAUTO (FA) for the bugs that were repaired on this branch. Each test runs the same
  computation under FA and under CS and asserts the CS precision is within a small tolerance
  of the FA precision. These configurations were verified to FAIL at the pre-fix commit
  452b94f (CS lagged FA by 4-18 bits) and to PASS after the fixes.

  Covered fixes:
    1. FullPackingBootstrap_HybridKeySwitch - the HYBRID key-switching fix (rns-cryptoparameters.cpp:
       widen the P/Q margin for composite). The roundoff only becomes visible once the modulus chain
       is deep enough to make the digit margin tight, so this test needs ring 2^14; sparse packing
       (1024 slots) keeps it cheap. Pre-fix gap ~4 bits.
    2. SparseBootstrapModRaiseHeadroom - the bootstrapping fix that applies the pre/post 1/(kN)
       scaling the same way as FA. The bug only triggers when first_mod_size_value > scaling_mod_size + 1
       (modraise headroom deg > 1); FA at 64 bits caps first_mod at 60, so we expose deg = 4 with
       scaling_mod_size = 56, first_mod_size_value = 60 at 8 slots / ring 2^12. Pre-fix gap ~7 bits.
    2b. SparseBootstrapLargeModRaiseHeadroom - same fix at the larger headroom deg = 6
       (scaling_mod_size = 54, first_mod_size_value = 60). This regime was only half-fixed by the original
       decomposition (it depended on the chosen primes - "good" at some ring dimensions, ~10 bits
       below FA at others). It is fully closed by folding the exact 2^-deg shrink into the
       CoeffsToSlots matrix so the CtS rotations stay on the full-magnitude message (their key-switch
       noise then scales down with the signal instead of being amplified by 2^deg). Pre-fix gap ~10 bits.
    3. DeepComputationWithFillers - the canonical-scaling-factor fix for plaintext multiplication.
       A deep filler chain followed by a sharp Chebyshev impulse makes CS diverge from FA by many
       orders of magnitude. Pre-fix gap ~18 bits at D = 20.

  The remaining two branch fixes (extend_ciphertext and composite prime modulation) do not need
  dedicated tests per the issue.

  Tolerances (k_gap_tol, one per test)
  ----------------------------------
  Each test compares one CS run against one FA run, both with unseeded randomness, so the gap
  (fa_bits - cs_bits) is a random variable, not a fixed quantity. Measured over 200 runs per test
  (52 for the two expensive scenarios) on x86_64 / GCC 13, NATIVE_SIZE = 64:

    FullPackingBootstrap_HybridKeySwitch          gap -1.50 +/- 0.22
    SparseBootstrapModRaiseHeadroom               gap -1.64 +/- 0.62
    SparseBootstrapLargeModRaiseHeadroom          gap  1.30 +/- 0.71
    StCFirstSparseBootstrap                       gap  1.06 +/- 0.72
    StCFirstSparseBootstrapLargeModRaiseHeadroom  gap  1.33 +/- 0.69
    StCFirstBootstrap1024Slots                    gap -0.56 +/- 0.33
    StCFirstSparseBootstrapWithExtraLevels        gap -0.09 +/- 0.63
    DeepComputationWithFillers                    gap -0.55 +/- 1.21

  Each k_gap_tol sits at least 5 standard deviations above its measured mean, so a false failure
  is under 1e-6 per run, and at most half of the pre-fix gap the test guards against, so it
  still separates noise from signal in both directions. The tolerance is deliberately per-test:
  the spread differs by 6x across scenarios, so a single shared value would be either flaky for
  the noisy tests or blind for the quiet ones. At the original uniform 3.0 the three tests with
  a positive mean gap sat only ~2.4 sd out and failed about one run in 200 (issue #1290) - the
  failures were not CS precision losses but FA reference runs that happened to land high.
*/

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/cipher.h"

using namespace cipher;

#if CIPHER_NATIVE_INT == 64
//===========================================================================================================
namespace {

constexpr uint32_t REGISTER_WORD = 32;  // composite degree 2 for the scaling-factor sizes used here
constexpr SecretKeyDist SK_DIST = UNIFORM_TERNARY;

// Builds a CKKS context for the requested scaling technique. COMPOSITESCALINGAUTO additionally sets
// the register word size; everything else is identical so FA and CS are a fair comparison.
CryptoContext<RnsPoly> build_context(ScalingTechnique scal_tech, uint32_t ring_dim, uint32_t mult_depth_value,
                                     uint32_t scaling_mod_size, uint32_t first_mod_size_value,
                                     uint32_t num_large_digits) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(SK_DIST);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(ring_dim);
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scaling_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_scaling_technique(scal_tech);
    if (num_large_digits > 0)
        parameters.set_num_large_digits(num_large_digits);
    if (scal_tech == COMPOSITESCALINGAUTO)
        parameters.set_register_word_size(REGISTER_WORD);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);
    return cc;
}

double MaxAbsError(const std::vector<double>& a, const std::vector<double>& b, size_t n) {
    double max_err = 0.0;
    for (size_t i = 0; i < n; ++i)
        max_err = std::max(max_err, std::abs(a[i] - b[i]));
    return max_err;
}

// Precision in bits (-log2 of the error); a tiny floor avoids +inf when the error is ~0.
double precision_bits(double max_err) {
    return -std::log2(std::max(max_err, 1e-18));
}

}  // namespace
//===========================================================================================================
class CkksCompositeVsFlexibleTest : public ::testing::Test {
  protected:
    void SetUp() override {
        cipher_parallel_controls.unit_test_start();
    }
    void TearDown() override {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    // Bootstraps a freshly-encrypted vector and returns the achieved precision in bits. With stc_first the
    // SlotsToCoeffs-first ("bt_slots_encoding") variant is used, whose input must keep level_budget[1] levels for
    // the initial SlotsToCoeffs; extra_levels additionally leaves the input that many levels above the
    // minimum, exercising the level adjustment performed before SlotsToCoeffs. Releases its own context
    // before returning: a test that takes two measurements would otherwise hold both bootstrapping key
    // sets at once, over 4 GB at ring 2^14.
    double bootstrap_precision_bits(ScalingTechnique scal_tech, uint32_t ring_dim, uint32_t scaling_mod_size,
                                    uint32_t first_mod_size_value, const std::vector<uint32_t>& level_budget,
                                    uint32_t num_slots, uint32_t levels_after_bootstrap, uint32_t num_large_digits,
                                    bool stc_first = false, uint32_t extra_levels = 0) {
        uint32_t depth = levels_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, SK_DIST);
        auto cc = build_context(scal_tech, ring_dim, depth, scaling_mod_size, first_mod_size_value, num_large_digits);
        auto cp = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
        uint32_t cd = cp->get_composite_degree();

        cc->eval_bootstrap_setup(level_budget, {0, 0}, num_slots, 0, true, stc_first);
        auto keys = cc->key_gen();
        cc->eval_mult_key_gen(keys.secret_key);
        cc->eval_bootstrap_key_gen(keys.secret_key, num_slots);

        // Deterministic input in (0,1) so FA and CS see the same signal.
        std::vector<double> x(num_slots);
        for (uint32_t i = 0; i < num_slots; ++i)
            x[i] = 0.25 + 0.5 * (0.5 * std::sin(0.3 * static_cast<double>(i) + 1.0) + 0.5);

        uint32_t input_level = depth - 1 - ((stc_first) ? level_budget[1] : 0) - extra_levels;
        Plaintext pt = cc->make_ckks_packed_plaintext(x, 1, cd * input_level, nullptr, num_slots);
        auto ct = cc->encrypt(keys.public_key, pt);
        auto ct_after = cc->eval_bootstrap(ct);

        Plaintext result;
        cc->decrypt(keys.secret_key, ct_after, &result);
        result->set_length(num_slots);
        double bits = precision_bits(MaxAbsError(result->get_real_packed_value(), x, num_slots));
        ContextFactory<RnsPoly>::release_all_contexts();
        return bits;
    }

    // Bootstraps a spike vector, applies `filler_levels` plaintext multiplications by 1 (each rescales),
    // then evaluates a sharp Gaussian impulse via a degree-119 Chebyshev approximation. Returns the
    // background-slot leakage precision in bits (how close the background slots stay to impulse(-1)).
    double deep_computation_bg_precision_bits(ScalingTechnique scal_tech, uint32_t ring_dim, uint32_t filler_levels) {
        constexpr double k_spike = -0.75;
        constexpr double k_background = -1.0;
        constexpr double k_sigma = 0.04;
        constexpr uint32_t k_cheb_deg = 119;

        uint32_t cheb_depth = static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(k_cheb_deg)))) + 1;
        uint32_t levels_after_bootstrap = filler_levels + cheb_depth + 6;
        uint32_t depth = levels_after_bootstrap + CkksRnsFhe::get_bootstrap_depth({3, 3}, SK_DIST);

        auto cc = build_context(scal_tech, ring_dim, depth, 59, 60, 0);
        auto cp = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
        uint32_t cd = cp->get_composite_degree();

        uint32_t num_slots = ring_dim / 2;
        cc->eval_bootstrap_setup({3, 3}, {0, 0}, num_slots);
        auto keys = cc->key_gen();
        cc->eval_mult_key_gen(keys.secret_key);
        cc->eval_bootstrap_key_gen(keys.secret_key, num_slots);

        std::vector<double> x(num_slots, k_background);
        x[0] = k_spike;

        Plaintext ptx = cc->make_ckks_packed_plaintext(x, 1, cd * (depth - 1), nullptr, num_slots);
        auto ct = cc->eval_bootstrap(cc->encrypt(keys.public_key, ptx));

        std::vector<double> ones_value(num_slots, 1.0);
        for (uint32_t i = 0; i < filler_levels; ++i) {
            auto pt1 = cc->make_ckks_packed_plaintext(ones_value, 1, ct->get_level(), nullptr, num_slots);
            ct = cc->eval_mult(ct, pt1);
        }

        auto impulse = [=](double v) {
            double z = (v - k_spike) / k_sigma;
            return std::exp(-z * z / 2);
        };
        auto ind = cc->eval_chebyshev_function(impulse, ct, -1.0, 1.0, k_cheb_deg);

        Plaintext result;
        cc->decrypt(keys.secret_key, ind, &result);
        auto vo = result->get_real_packed_value();

        double bg_leak = 0.0;
        for (uint32_t i = 1; i < num_slots; ++i)
            bg_leak = std::max(bg_leak, std::abs(vo[i] - impulse(k_background)));
        double bits = precision_bits(bg_leak);
        ContextFactory<RnsPoly>::release_all_contexts();
        return bits;
    }
};

//===========================================================================================================
// Scenario 1: bootstrapping with HYBRID key switching (num_large_digits = 3). Fixed by widening the P/Q
// margin for composite scaling. Needs ring 2^14 for the digit margin to become tight (verified to not
// reproduce at 2^12/2^13); sparse 1024-slot packing keeps the test cheap. Pre-fix: CS ~4 bits below FA.
TEST_F(CkksCompositeVsFlexibleTest, FullPackingBootstrap_HybridKeySwitch) {
    #if defined(__EMSCRIPTEN__)
    // Ring 2^14 at composite degree 2 keeps ~4.0 GB live across bootstrapping key generation, against
    // the 4 GB address space of wasm32. It does fit, but with ~1.5% to spare, which is not a margin to
    // run CI on. Every other case in this file stays under 0.5 GB.
    GTEST_SKIP() << "ring 2^14 composite-scaling bootstrap does not fit the 4 GB wasm32 address space";
    #endif
    constexpr double k_gap_tol = 1.0;  // measured gap -1.50 +/- 0.22; pre-fix gap ~4
    const uint32_t ring_dim = 1 << 14;
    const std::vector<uint32_t> level_budget = {4, 4};
    const uint32_t num_slots = 1024;
    const uint32_t levels_after_bootstrap = 10;
    const uint32_t num_large_digits = 3;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, num_large_digits);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, num_large_digits);

    EXPECT_GT(cs_bits, 6.0) << "CS bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - HYBRID key-switching regression";
}

//===========================================================================================================
// Scenario 2: sparse (8-slot) bootstrapping with modraise headroom deg = first_mod - scalingMod = 4.
// Fixed by applying the pre/post 1/(kN) scaling as an exact power-of-two, the same way as FA. The bug
// only triggers when first_mod_size_value > scaling_mod_size + 1. Pre-fix: CS ~7 bits below FA.
TEST_F(CkksCompositeVsFlexibleTest, SparseBootstrapModRaiseHeadroom) {
    constexpr double k_gap_tol = 3.0;  // measured gap -1.64 +/- 0.62; pre-fix gap ~7
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {3, 3};
    const uint32_t num_slots = 8;
    const uint32_t levels_after_bootstrap = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 56, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 56, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0);

    EXPECT_GT(cs_bits, 6.0) << "CS 8-slot bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol)
            << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits << ", FA=" << fa_bits
            << ") - bootstrap pre/post scaling (deg>1) regression";
}

//===========================================================================================================
// Scenario 2b: sparse (8-slot) bootstrapping with the larger modraise headroom deg = 6 (scaling_mod_size = 54,
// first_mod_size_value = 60) at ring 2^12 - the case from issue-1181. The original decomposition fix only half-closed
// this regime (prime-dependent: CS landed ~10 bits below FA at this ring); folding the exact 2^-deg shrink
// into the CoeffsToSlots matrix closes it (CS now within ~1.5 bits of FA, ~17 vs ~18.5). Pre-fix: CS ~8 bits
// (gap ~10).
TEST_F(CkksCompositeVsFlexibleTest, SparseBootstrapLargeModRaiseHeadroom) {
    constexpr double k_gap_tol = 5.0;  // measured gap 1.30 +/- 0.71; pre-fix gap ~10
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {3, 3};
    const uint32_t num_slots = 8;
    const uint32_t levels_after_bootstrap = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 54, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 54, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0);

    EXPECT_GT(cs_bits, 12.0) << "CS 8-slot deg=6 bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - large modraise headroom (deg=6) regression";
}

//===========================================================================================================
// Scenario 4: SlotsToCoeffs-first ("bt_slots_encoding") bootstrapping. Composite scaling support for this mode
// required (a) counting the towers consumed by the initial SlotsToCoeffs in units of composite_degree, so the
// input level matches the level at which the StC matrix is encoded (previously a modulus mismatch), and
// (b) using the level-adjustment formula of adjust_levels_and_depth_in_place when the input arrives with extra
// levels (the current and target levels were mixed up, which is invisible for FA but cost ~10 bits for CS).
// CS is expected to be within a few bits of FA in this mode, like in the ModRaise-first mode.
TEST_F(CkksCompositeVsFlexibleTest, StCFirstSparseBootstrap) {
    constexpr double k_gap_tol = 5.0;  // measured gap 1.06 +/- 0.72; pre-fix gap ~10
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {2, 2};
    const uint32_t num_slots = 8;
    const uint32_t levels_after_bootstrap = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);

    EXPECT_GT(cs_bits, 12.0) << "CS StC-first 8-slot bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - StC-first composite scaling regression";
}

TEST_F(CkksCompositeVsFlexibleTest, StCFirstSparseBootstrapLargeModRaiseHeadroom) {
    constexpr double k_gap_tol = 5.0;  // measured gap 1.33 +/- 0.69; pre-fix gap ~10
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {2, 2};
    const uint32_t num_slots = 8;
    const uint32_t levels_after_bootstrap = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 54, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 54, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);

    EXPECT_GT(cs_bits, 12.0) << "CS StC-first deg=6 bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - StC-first large modraise headroom regression";
}

TEST_F(CkksCompositeVsFlexibleTest, StCFirstBootstrap1024Slots) {
    constexpr double k_gap_tol = 3.0;  // measured gap -0.56 +/- 0.33; pre-fix gap ~10
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {3, 3};
    const uint32_t num_slots = 1024;
    const uint32_t levels_after_bootstrap = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true);

    EXPECT_GT(cs_bits, 12.0) << "CS StC-first 1024-slot bootstrap precision unexpectedly low (" << cs_bits << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - StC-first composite scaling regression";
}

// Input arrives with 2 more levels than the StC-first minimum, so the level adjustment before SlotsToCoeffs
// runs. Pre-fix: CS ~15 bits vs FA ~25 bits at ring 2^6.
TEST_F(CkksCompositeVsFlexibleTest, StCFirstSparseBootstrapWithExtraLevels) {
    constexpr double k_gap_tol = 5.0;  // measured gap -0.09 +/- 0.63; pre-fix gap ~10
    const uint32_t ring_dim = 1 << 12;
    const std::vector<uint32_t> level_budget = {2, 2};
    const uint32_t num_slots = 8;
    const uint32_t levels_after_bootstrap = 2;
    const uint32_t extra_levels = 2;

    double fa_bits = bootstrap_precision_bits(FLEXIBLEAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true, extra_levels);
    double cs_bits = bootstrap_precision_bits(COMPOSITESCALINGAUTO, ring_dim, 59, 60, level_budget, num_slots,
                                              levels_after_bootstrap, 0, true, extra_levels);

    EXPECT_GT(cs_bits, 12.0) << "CS StC-first bootstrap precision with extra input levels unexpectedly low (" << cs_bits
                             << " bits)";
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol) << "CS lags FA by >" << k_gap_tol << " bits (CS=" << cs_bits
                                            << ", FA=" << fa_bits << ") - StC-first level adjustment regression";
}

//===========================================================================================================
// Scenario 3: deep computation (filler plaintext mults + sharp Chebyshev impulse) at ring 2^12, full
// packing. Fixed by setting the post-mult scaling factor from the canonical table instead of tracked^2.
// CS used to diverge from FA by many orders of magnitude as the filler depth grows. Pre-fix: CS ~18 bits
// below FA at D = 20. (D = 30 is excluded - its residual is approximate-keyswitch noise, not this fix.)
TEST_F(CkksCompositeVsFlexibleTest, DeepComputationWithFillers) {
    if (CIPHER_MATH_BACKEND == 2)
        GTEST_SKIP() << "Disabled for MATHBACKEND 2: the coefficient modulus at filler depth D = 20 is too large "
                        "for the default BACKEND 2 configuration.";

    constexpr double k_gap_tol = 7.0;  // measured gap -0.55 +/- 1.21; pre-fix gap ~18
    const uint32_t ring_dim = 1 << 12;
    const uint32_t D = 20;

    double fa_bits = deep_computation_bg_precision_bits(FLEXIBLEAUTO, ring_dim, D);
    double cs_bits = deep_computation_bg_precision_bits(COMPOSITESCALINGAUTO, ring_dim, D);

    // This scenario has the widest run-to-run spread in the file (sd 1.25 bits, ~2x the sparse
    // bootstrap tests), so it needs the widest tolerance; the pre-fix gap of ~18 bits leaves room.
    EXPECT_GE(cs_bits, fa_bits - k_gap_tol)
            << "CS background leakage worse than FA by >" << k_gap_tol << " bits at filler depth D=" << D
            << " (CS=" << cs_bits << " bits, FA=" << fa_bits << " bits)";
}
//===========================================================================================================
#endif  // CIPHER_NATIVE_INT == 64
