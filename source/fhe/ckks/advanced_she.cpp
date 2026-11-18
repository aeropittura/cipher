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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#include "cipher/fhe/ckks/advanced_she.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/utils.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

//------------------------------------------------------------------------------
// LINEAR WEIGHTED SUM
//------------------------------------------------------------------------------

// streamed accumulation: one scaled term live at a time instead of `limit` clones
template <typename CtType, typename VectorDataType>
static Ciphertext<RnsPoly> eval_streamed_linear_w_sum(const std::vector<CtType>& ciphertexts,
                                                      const VectorDataType* constants, uint32_t limit) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertexts[0]->get_crypto_parameters());

    auto cc = ciphertexts[0]->get_crypto_context();

    if (crypto_params->get_scaling_technique() == FIXEDMANUAL) {
        auto acc = cc->eval_mult(ciphertexts[0], constants[0]);
        for (uint32_t i = 1; i < limit; ++i)
            cc->eval_add_in_place_no_check(acc, cc->eval_mult(ciphertexts[i], constants[i]));
        cc->mod_reduce_in_place(acc);
        return acc;
    }

    // Check to see if input ciphertexts are of same level
    // and adjust if needed to the max level among them
    uint32_t max_level = ciphertexts[0]->get_level();
    uint32_t max_idx = 0;
    for (uint32_t i = 1; i < limit; ++i) {
        if ((ciphertexts[i]->get_level() > max_level) ||
            ((ciphertexts[i]->get_level() == max_level) && (ciphertexts[i]->get_noise_scale_deg() == 2))) {
            max_level = ciphertexts[i]->get_level();
            max_idx = i;
        }
    }

    auto algo = cc->get_scheme();
    uint32_t composite_degree = crypto_params->get_composite_degree();
    auto ctm = ciphertexts[max_idx]->clone();
    const bool reduce_all = (ctm->get_noise_scale_deg() == 2);

    Ciphertext<RnsPoly> acc;
    for (uint32_t i = 0; i < limit; ++i) {
        auto term = ciphertexts[i]->clone();
        algo->adjust_levels_and_depth_in_place(term, ctm);
        if (reduce_all)
            algo->mod_reduce_internal_in_place(term, composite_degree);
        cc->eval_mult_in_place(term, constants[i]);
        if (i == 0)
            acc = std::move(term);
        else
            cc->eval_add_in_place_no_check(acc, term);
    }
    cc->mod_reduce_in_place(acc);
    return acc;
}

template <typename VectorDataType>
Ciphertext<RnsPoly> internal_eval_linear_w_sum(const std::vector<ReadOnlyCiphertext<RnsPoly>>& ciphertexts,
                                               const std::vector<VectorDataType>& constants) {
    return eval_streamed_linear_w_sum(ciphertexts, constants.data(), static_cast<uint32_t>(ciphertexts.size()));
}

template <typename VectorDataType>
Ciphertext<RnsPoly> internal_eval_linear_w_sum_mutable(std::vector<Ciphertext<RnsPoly>>& ciphertexts,
                                                       const std::vector<VectorDataType>& constants) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertexts[0]->get_crypto_parameters());

    auto cc = ciphertexts[0]->get_crypto_context();

    const uint32_t limit = ciphertexts.size();

    if (crypto_params->get_scaling_technique() != FIXEDMANUAL) {
        // Check to see if input ciphertexts are of same level
        // and adjust if needed to the max level among them
        uint32_t max_level = ciphertexts[0]->get_level();
        uint32_t max_idx = 0;
        for (uint32_t i = 1; i < limit; ++i) {
            if ((ciphertexts[i]->get_level() > max_level) ||
                ((ciphertexts[i]->get_level() == max_level) && (ciphertexts[i]->get_noise_scale_deg() == 2))) {
                max_level = ciphertexts[i]->get_level();
                max_idx = i;
            }
        }

        auto algo = cc->get_scheme();
        for (uint32_t i = 0; i < max_idx; ++i)
            algo->adjust_levels_and_depth_in_place(ciphertexts[i], ciphertexts[max_idx]);
        for (uint32_t i = max_idx + 1; i < limit; ++i)
            algo->adjust_levels_and_depth_in_place(ciphertexts[i], ciphertexts[max_idx]);

        uint32_t composite_degree = crypto_params->get_composite_degree();
        if (ciphertexts[max_idx]->get_noise_scale_deg() == 2) {
            for (uint32_t i = 0; i < limit; ++i)
                algo->mod_reduce_internal_in_place(ciphertexts[i], composite_degree);
        }
    }

    cc->eval_mult_in_place(ciphertexts[0], constants[0]);
    for (uint32_t i = 1; i < limit; ++i) {
        cc->eval_mult_in_place(ciphertexts[i], constants[i]);
        cc->eval_add_in_place_no_check(ciphertexts[0], ciphertexts[i]);
    }
    cc->mod_reduce_in_place(ciphertexts[0]);
    return ciphertexts[0];
}

template <typename VectorDataType>
Ciphertext<RnsPoly> eval_partial_linear_w_sum(const std::vector<Ciphertext<RnsPoly>>& ciphertexts,
                                              const std::vector<VectorDataType>& constants, uint32_t limit = 0) {
    if (0 == limit)
        limit = ciphertexts.size();
    return eval_streamed_linear_w_sum(ciphertexts, constants.data() + 1, limit);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum(std::vector<ReadOnlyCiphertext<RnsPoly>>& ciphertexts,
                                                          const std::vector<int64_t>& constants) const {
    return internal_eval_linear_w_sum(ciphertexts, constants);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum(std::vector<ReadOnlyCiphertext<RnsPoly>>& ciphertexts,
                                                          const std::vector<double>& constants) const {
    return internal_eval_linear_w_sum(ciphertexts, constants);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum(std::vector<ReadOnlyCiphertext<RnsPoly>>& ciphertexts,
                                                          const std::vector<std::complex<double>>& constants) const {
    return internal_eval_linear_w_sum(ciphertexts, constants);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum_mutable(std::vector<Ciphertext<RnsPoly>>& ciphertexts,
                                                                  const std::vector<int64_t>& constants) const {
    return internal_eval_linear_w_sum_mutable(ciphertexts, constants);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum_mutable(std::vector<Ciphertext<RnsPoly>>& ciphertexts,
                                                                  const std::vector<double>& constants) const {
    return internal_eval_linear_w_sum_mutable(ciphertexts, constants);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_linear_w_sum_mutable(
        std::vector<Ciphertext<RnsPoly>>& ciphertexts, const std::vector<std::complex<double>>& constants) const {
    return internal_eval_linear_w_sum_mutable(ciphertexts, constants);
}

//------------------------------------------------------------------------------
// EVAL POLYNOMIAL
//------------------------------------------------------------------------------

template <typename VectorDataType>
std::shared_ptr<SeriesPowers<RnsPoly>> internal_eval_powers_linear(ConstCiphertext<RnsPoly>& x,
                                                                   const std::vector<VectorDataType>& coefficients) {
    const uint32_t k = coefficients.size() - 1;
    std::vector<bool> indices(k);

    // find indices for powers of x that need to be computed
    for (uint32_t i = k; i > 0; --i) {
        if (0 == (i & (i - 1))) {  // if i is a power of 2
            indices[i - 1] = true;
        } else {  // non-power of 2
            if (is_not_equal_zero(coefficients[i])) {
                uint32_t rem = i;

                // while rem is not a power of 2
                // set indices required to compute rem to 1
                while (0 != (rem & (rem - 1))) {
                    indices[rem - 1] = true;
                    rem &= (uint64_t(1) << (get_msb(rem) - 1)) - 1;
                }
            }
        }
    }

    std::vector<Ciphertext<RnsPoly>> powers(k);
    powers[0] = x->clone();
    auto cc = x->get_crypto_context();

    auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(x->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();

    // computes all powers up to k for x
    for (uint32_t i = 2; i <= k; ++i) {
        if (0 == (i & (i - 1))) {
            powers[i - 1] = cc->eval_square(powers[i / 2 - 1]);
            cc->mod_reduce_in_place(powers[i - 1]);
        } else {
            if (indices[i - 1]) {
                uint64_t p = (uint64_t(1) << (get_msb(i) - 1)) - 1;
                uint64_t r = (i & p) - 1;
                uint32_t diff = powers[p]->get_level() - powers[r]->get_level();
                cc->level_reduce_in_place(powers[r], nullptr, diff / composite_degree);

                powers[i - 1] = cc->eval_mult(powers[p], powers[r]);
                cc->mod_reduce_in_place(powers[i - 1]);
            }
        }
    }

    // Bring all computed powers to the level and the noise-scale degree of the top power, so that the terms of
    // every series later evaluated from this basis add without any adjustment (under FIXEDMANUAL every power
    // has degree 1, so only the number of towers is aligned), as in the Paterson-Stockmeyer basis.
    auto algo = cc->get_scheme();
    for (uint32_t i = 1; i < k; ++i) {
        if (indices[i - 1])
            algo->adjust_levels_and_depth_in_place(powers[i - 1], powers[k - 1]);
    }

    return std::make_shared<SeriesPowers<RnsPoly>>(std::move(powers));
}

std::shared_ptr<SeriesPowers<RnsPoly>> internal_eval_powers_ps(ConstCiphertext<RnsPoly>& x, uint32_t degree) {
    auto degs = compute_degrees_ps(degree);
    uint32_t k = degs[0];
    uint32_t m = degs[1];

    std::vector<Ciphertext<RnsPoly>> powers(k);
    powers[0] = x->clone();

    auto cc = x->get_crypto_context();
    uint32_t composite_degree =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(x->get_crypto_parameters())->get_composite_degree();

    // computes all powers up to k for x
    uint32_t power_of2 = 2;
    uint32_t rem = 0;
    for (uint32_t i = 2; i <= k; ++i) {
        if (rem == 0) {
            powers[i - 1] = cc->eval_square(powers[(power_of2 >> 1) - 1]);
        } else {
            uint32_t diff = powers[power_of2 - 1]->get_level() - powers[rem - 1]->get_level();
            cc->level_reduce_in_place(powers[rem - 1], nullptr, diff / composite_degree);
            powers[i - 1] = cc->eval_mult(powers[power_of2 - 1], powers[rem - 1]);
        }

        if (++rem == power_of2) {
            power_of2 <<= 1;
            rem = 0;
        }
        cc->mod_reduce_in_place(powers[i - 1]);
    }

    // Bring all powers to the level and the noise-scale degree of the top power (under FIXEDMANUAL every power
    // has degree 1, so only the number of towers is aligned).
    for (uint32_t i = 1; i < k; ++i)
        cc->get_scheme()->adjust_levels_and_depth_in_place(powers[i - 1], powers[k - 1]);

    // computes powers of form k*2^i for x and the product of the powers in power2, that yield x^{k(2*m - 1)}
    std::vector<Ciphertext<RnsPoly>> powers2(m);
    powers2[0] = powers.back();

    auto power2km1 = powers.back();

    for (uint32_t i = 1; i < m; ++i) {
        powers2[i] = cc->eval_square(powers2[i - 1]);
        cc->mod_reduce_in_place(powers2[i]);
        power2km1 = cc->eval_mult(powers2[i], power2km1);
        cc->mod_reduce_in_place(power2km1);
    }

    return std::make_shared<SeriesPowers<RnsPoly>>(std::move(powers), std::move(powers2), std::move(power2km1), k, m);
}

std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_powers(ConstCiphertext<RnsPoly>& x,
                                                                       const std::vector<int64_t>& coefficients) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_powers_linear(x, coefficients) : internal_eval_powers_ps(x, d);
}
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_powers(ConstCiphertext<RnsPoly>& x,
                                                                       const std::vector<double>& coefficients) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_powers_linear(x, coefficients) : internal_eval_powers_ps(x, d);
}
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_powers(
        ConstCiphertext<RnsPoly>& x, const std::vector<std::complex<double>>& coefficients) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_powers_linear(x, coefficients) : internal_eval_powers_ps(x, d);
}

// The powers may be a precomputation shared across several polynomials (eval_poly_with_precomp), so every
// term is scaled into a fresh ciphertext and the powers are left untouched.
template <typename VectorDataType>
static inline Ciphertext<RnsPoly> internal_eval_poly_linear_with_precomp(
        const std::vector<Ciphertext<RnsPoly>>& powers, const std::vector<VectorDataType>& coefficients) {
    if (coefficients.size() < 2)
        CIPHER_THROW("The coefficients vector should contain at least 2 elements");

    const uint32_t k = coefficients.size() - 1;
    if (!is_not_equal_zero(coefficients[k]))
        CIPHER_THROW("The highest-order coefficient cannot be set to 0");

    auto cc = powers[0]->get_crypto_context();

    // perform scalar multiplication for the highest-order term
    auto result = cc->eval_mult(powers[k - 1], coefficients[k]);

    // perform scalar multiplication for all other terms and sum them up
    for (uint32_t i = 1; i < k; ++i) {
        if (is_not_equal_zero(coefficients[i])) {
            auto term = cc->eval_mult(powers[i - 1], coefficients[i]);
            cc->eval_add_mutable_in_place(result, term);
        }
    }

    // Do rescaling after scalar multiplication
    cc->mod_reduce_in_place(result);

    // adds the free term (at x^0)
    cc->eval_add_in_place(result, coefficients[0]);

    return result;
}

template <typename VectorDataType>
Ciphertext<RnsPoly> inner_eval_poly_ps(ConstCiphertext<RnsPoly>& x, const std::vector<VectorDataType>& coefficients,
                                       uint32_t k, uint32_t m, const std::vector<Ciphertext<RnsPoly>>& powers,
                                       const std::vector<Ciphertext<RnsPoly>>& powers2) {
    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by x^{k*2^{m-1}}
    std::vector<VectorDataType> xkm(k2m2k + k + 1);
    xkm.back() = 1;
    auto divqr = long_division_poly(coefficients, xkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto& r2 = divqr->r;
    if (auto n = Degree(r2); static_cast<int32_t>(k2m2k - n) <= 0) {
        r2.resize(n + 1);
        r2[k2m2k] -= 1;
    } else {
        r2.resize(k2m2k + 1);
        r2.back() = -1;
    }

    auto divcs = long_division_poly(r2, divqr->q);
    auto cc = x->get_crypto_context();

    Ciphertext<RnsPoly> cu, qu, su;

#pragma omp task shared(qu)
    {
        // Evaluate q and s2 at u.
        // If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.

        if (Degree(divqr->q) > k) {
            qu = inner_eval_poly_ps(x, divqr->q, k, m - 1, powers, powers2);
        } else {
            qu = cc->eval_add(powers[k - 1], divqr->q.front());
            divqr->q.resize(k);
            if (uint32_t n = Degree(divqr->q); n > 0)
                cc->eval_add_in_place(qu, eval_partial_linear_w_sum(powers, divqr->q, n));
        }
    }

#pragma omp task shared(su)
    {
        // Add x^{k(2^{m-1} - 1)} to s
        auto& s2 = divcs->r;
        s2.resize(k2m2k + 1);
        s2.back() = 1;

        if (Degree(s2) > k) {
            su = inner_eval_poly_ps(x, s2, k, m - 1, powers, powers2);
        } else {
            su = cc->eval_add(powers[k - 1], s2.front());
            s2.resize(k);
            if (uint32_t n = Degree(s2); n > 0)
                cc->eval_add_in_place(su, eval_partial_linear_w_sum(powers, s2, n));
        }
    }

    if (uint32_t n = Degree(divcs->q); n == 0) {
        cu = cc->eval_add(powers2[m - 1], divcs->q.front());
    } else if (n == 1) {
        if (is_not_equal_one(divcs->q[1])) {
            cu = cc->eval_mult(powers.front(), divcs->q[1]);
            cc->mod_reduce_in_place(cu);
            cc->eval_add_in_place(cu, powers2[m - 1]);
        } else {
            cu = cc->eval_add(powers2[m - 1], powers.front());
        }
        cc->eval_add_in_place(cu, divcs->q.front());
    } else {
        cu = cc->eval_add(powers2[m - 1], eval_partial_linear_w_sum(powers, divcs->q, n));
        cc->eval_add_in_place(cu, divcs->q.front());
    }

#pragma omp taskwait

    auto result = cc->eval_mult(cu, qu);
    cc->mod_reduce_in_place(result);
    cc->eval_add_in_place(result, su);
    return result;
}

template <typename VectorDataType>
Ciphertext<RnsPoly> internal_eval_poly_ps_with_precomp(const std::shared_ptr<SeriesPowers<RnsPoly>>& ctxt_powers,
                                                       const std::vector<VectorDataType>& coefficients) {
    auto& powers = ctxt_powers->powers_re;
    auto& powers2 = ctxt_powers->powers2_re;
    auto& power2km1 = ctxt_powers->power2km1_re;
    auto k = ctxt_powers->k;
    auto m = ctxt_powers->m;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add T^{k(2^m - 1)}(y) to the polynomial that has to be evaluated
    auto f2 = coefficients;
    f2.resize(Degree(f2) + 1);
    f2.resize(2 * k2m2k + k + 1);
    f2.back() = 1;

    // Serialize tree if k*2^{m-1} < 128
    if (k * (1U << (m - 1)) < 128)
        return powers[0]->get_crypto_context()->eval_sub(inner_eval_poly_ps(powers[0], f2, k, m, powers, powers2),
                                                         power2km1);

    Ciphertext<RnsPoly> result;
#pragma omp parallel num_threads(cipher_parallel_controls.get_thread_limit(6 * m + 2))
    {
#pragma omp single_value
        result = powers[0]->get_crypto_context()->eval_sub(inner_eval_poly_ps(powers[0], f2, k, m, powers, powers2),
                                                           power2km1);
    }
    return result;
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly(ConstCiphertext<RnsPoly>& x,
                                                  const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? eval_poly_linear(x, coeffs) : eval_poly_ps(x, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly(ConstCiphertext<RnsPoly>& x,
                                                  const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? eval_poly_linear(x, coeffs) : eval_poly_ps(x, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly(ConstCiphertext<RnsPoly>& x,
                                                  const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? eval_poly_linear(x, coeffs) : eval_poly_ps(x, coeffs);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_with_precomp(std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers,
                                                               const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_poly_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_poly_ps_with_precomp(ctxt_powers, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_with_precomp(std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers,
                                                               const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_poly_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_poly_ps_with_precomp(ctxt_powers, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_with_precomp(std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers,
                                                               const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_poly_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_poly_ps_with_precomp(ctxt_powers, coeffs);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_linear(ConstCiphertext<RnsPoly>& x,
                                                         const std::vector<int64_t>& coeffs) const {
    return internal_eval_poly_linear_with_precomp(internal_eval_powers_linear(x, coeffs)->powers_re, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_linear(ConstCiphertext<RnsPoly>& x,
                                                         const std::vector<double>& coeffs) const {
    return internal_eval_poly_linear_with_precomp(internal_eval_powers_linear(x, coeffs)->powers_re, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_linear(ConstCiphertext<RnsPoly>& x,
                                                         const std::vector<std::complex<double>>& coeffs) const {
    return internal_eval_poly_linear_with_precomp(internal_eval_powers_linear(x, coeffs)->powers_re, coeffs);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_ps(ConstCiphertext<RnsPoly>& x,
                                                     const std::vector<int64_t>& coeffs) const {
    return internal_eval_poly_ps_with_precomp(internal_eval_powers_ps(x, Degree(coeffs)), coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_ps(ConstCiphertext<RnsPoly>& x,
                                                     const std::vector<double>& coeffs) const {
    return internal_eval_poly_ps_with_precomp(internal_eval_powers_ps(x, Degree(coeffs)), coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_poly_ps(ConstCiphertext<RnsPoly>& x,
                                                     const std::vector<std::complex<double>>& coeffs) const {
    return internal_eval_poly_ps_with_precomp(internal_eval_powers_ps(x, Degree(coeffs)), coeffs);
}

//------------------------------------------------------------------------------
// EVAL CHEBYSHEV SERIES
//------------------------------------------------------------------------------

template <typename VectorDataType>
std::shared_ptr<SeriesPowers<RnsPoly>> internal_eval_cheby_polys_linear(ConstCiphertext<RnsPoly>& x,
                                                                        const std::vector<VectorDataType>& coefficients,
                                                                        double a, double b) {
    const uint32_t k = coefficients.size() - 1;
    std::vector<Ciphertext<RnsPoly>> T(k);

    auto cc = x->get_crypto_context();

    // computes linear transformation y = -1 + 2 (x-a)/(b-a)
    // consumes one level when a <> -1 && b <> 1
    if (!is_not_equal_neg_one(a) && !is_not_equal_one(b)) {
        T[0] = x->clone();
    } else {
        // linear transformation is needed
        double alpha = 2 / (b - a);
        double beta = a * alpha;

        T[0] = cc->eval_mult(x, alpha);
        cc->mod_reduce_in_place(T[0]);
        cc->eval_add_in_place(T[0], -1.0 - beta);
    }

    // Computes Chebyshev polynomials up to degree k
    // for y: T_1(y) = y, T_2(y), ... , T_k(y)
    // uses binary tree multiplication
    for (uint32_t i = 2; i <= k; ++i) {
        if (i & 0x1) {  // if i is odd
            // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
            T[i - 1] = cc->eval_mult(T[i / 2 - 1], T[i / 2]);
            cc->eval_add_in_place_no_check(T[i - 1], T[i - 1]);
            cc->mod_reduce_in_place(T[i - 1]);
            cc->eval_sub_in_place(T[i - 1], T[0]);
        } else {
            // compute T_{2i}(y) = 2*T_i(y)^2 - 1
            T[i - 1] = cc->eval_square(T[i / 2 - 1]);
            cc->eval_add_in_place_no_check(T[i - 1], T[i - 1]);
            cc->mod_reduce_in_place(T[i - 1]);
            cc->eval_add_in_place(T[i - 1], -1.0);
        }
    }

    // Bring all polynomials to the level and the noise-scale degree of the top one, so that the terms of every
    // series later evaluated from this basis add without any adjustment (see internal_eval_powers_linear).
    auto algo = cc->get_scheme();
    for (uint32_t i = 1; i < k; ++i)
        algo->adjust_levels_and_depth_in_place(T[i - 1], T[k - 1]);

    return std::make_shared<SeriesPowers<RnsPoly>>(std::move(T));
}

// The Chebyshev polynomials may be a precomputation shared across several series
// (eval_chebyshev_series_with_precomp), so every term is scaled into a fresh ciphertext and T is left untouched.
template <typename VectorDataType>
Ciphertext<RnsPoly> internal_eval_chebyshev_series_linear_with_precomp(
        const std::vector<Ciphertext<RnsPoly>>& T, const std::vector<VectorDataType>& coefficients) {
    const uint32_t k = coefficients.size() - 2;

    // perform scalar multiplication for the highest-order term
    auto cc = T[0]->get_crypto_context();
    auto result = cc->eval_mult(T[k], coefficients[k + 1]);

    // perform scalar multiplication for all other terms and sum them up
    for (uint32_t i = 0; i < k; ++i) {
        if (is_not_equal_zero(coefficients[i + 1])) {
            auto term = cc->eval_mult(T[i], coefficients[i + 1]);
            cc->eval_add_mutable_in_place(result, term);
        }
    }

    // Do rescaling after scalar multiplication
    cc->mod_reduce_in_place(result);

    // adds the free term (at x^0)
    cc->eval_add_in_place(result, coefficients[0] / 2.0);

    return result;
}

template <typename VectorDataType>
Ciphertext<RnsPoly> inner_eval_chebyshev_ps(ConstCiphertext<RnsPoly>& x,
                                            const std::vector<VectorDataType>& coefficients, uint32_t k, uint32_t m,
                                            const std::vector<Ciphertext<RnsPoly>>& T,
                                            const std::vector<Ciphertext<RnsPoly>>& T2) {
    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by T^{k*2^{m-1}}
    std::vector<VectorDataType> tkm(k2m2k + k + 1);
    tkm.back() = 1;
    auto divqr = long_division_chebyshev(coefficients, tkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto& r2 = divqr->r;
    if (uint32_t n = Degree(r2); static_cast<int32_t>(k2m2k - n) <= 0) {
        r2.resize(n + 1);
        r2[k2m2k] -= 1;
    } else {
        r2.resize(k2m2k + 1);
        r2.back() = -1;
    }

    auto divcs = long_division_chebyshev(r2, divqr->q);
    auto cc = x->get_crypto_context();

    Ciphertext<RnsPoly> cu, qu, su;

#pragma omp task shared(qu)
    {
        // Evaluate q and s2 at u.
        // If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
        if (Degree(divqr->q) > k) {
            qu = inner_eval_chebyshev_ps(x, divqr->q, k, m - 1, T, T2);
        } else {
            // dq = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients

            // the highest order coefficient will always be a power of two up to 2^{m-1} because q is "monic" but the Chebyshev rule adds a factor of 2
            // we don't need to increase the depth by multiplying the highest order coefficient, but instead checking and summing, since we work with m <= 4.
            qu = T[k - 1]->clone();
            const uint32_t limit = std::log2(to_real(divqr->q.back()));
            for (uint32_t i = 0; i < limit; ++i)
                cc->eval_add_in_place_no_check(qu, qu);

            // adds the free term (at x^0)
            cc->eval_add_in_place(qu, divqr->q.front() / 2.0);
            // The number of levels of qu is the same as the number of levels of T[k-1] + 1.
            // Will only get here when m = 2, so the number of levels of qu and T2[m-1] will be the same.

            divqr->q.resize(k);
            if (uint32_t n = Degree(divqr->q); n > 0)
                cc->eval_add_in_place(qu, eval_partial_linear_w_sum(T, divqr->q, n));
        }
    }

#pragma omp task shared(su)
    {
        // Add x^{k(2^{m-1} - 1)} to s
        auto& s2 = divcs->r;
        s2.resize(k2m2k + 1);
        s2.back() = 1;

        if (Degree(s2) > k) {
            su = inner_eval_chebyshev_ps(x, s2, k, m - 1, T, T2);
        } else {
            // the highest order coefficient will always be 1 because s2 is monic.
            su = T[k - 1]->clone();

            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            s2.resize(k);
            if (uint32_t n = Degree(s2); n > 0)
                cc->eval_add_in_place(su, eval_partial_linear_w_sum(T, s2, n));

            // adds the free term (at x^0)
            cc->eval_add_in_place(su, s2.front() / 2.0);

            // The number of levels of su is the same as the number of levels of T[k-1] or T[k-1] + 1. Need to reduce it to T2[m-1] + 1.
            cc->level_reduce_in_place(su, nullptr);
        }
    }

    if (uint32_t n = Degree(divcs->q); n >= 1) {
        if (n == 1) {
            if (is_not_equal_one(divcs->q[1])) {
                cu = cc->eval_mult(T.front(), divcs->q[1]);
                cc->mod_reduce_in_place(cu);
            } else {
                cu = T.front()->clone();
            }
        } else {
            cu = eval_partial_linear_w_sum(T, divcs->q, n);
        }

        // adds the free term (at x^0)
        cc->eval_add_in_place(cu, divcs->q.front() / 2.0);

        // Need to reduce levels up to the level of T2[m-1].
        uint32_t cd =
                std::dynamic_pointer_cast<CkksRnsCryptoParams>(x->get_crypto_parameters())->get_composite_degree();
        cc->level_reduce_in_place(cu, nullptr, (T2[m - 1]->get_level() - cu->get_level()) / cd);
    }

    cu = cu ? cc->eval_add(T2[m - 1], cu) : cc->eval_add(T2[m - 1], divcs->q.front() / 2.0);

#pragma omp taskwait

    auto result = cc->eval_mult(cu, qu);
    cc->mod_reduce_in_place(result);
    cc->eval_add_in_place(result, su);
    return result;
}

std::shared_ptr<SeriesPowers<RnsPoly>> internal_eval_cheby_polys_ps(ConstCiphertext<RnsPoly>& x, uint32_t degree,
                                                                    double a, double b) {
    auto degs = compute_degrees_ps(degree);
    uint32_t k = degs[0];
    uint32_t m = degs[1];

    // computes linear transformation y = -1 + 2 (x-a)/(b-a)
    // consumes one level when a <> -1 && b <> 1
    auto cc = x->get_crypto_context();
    std::vector<Ciphertext<RnsPoly>> T(k);
    if (!is_not_equal_neg_one(a) && !is_not_equal_one(b)) {
        // no linear transformation is needed if a = -1, b = 1
        // T_1(y) = y
        T[0] = x->clone();
    } else {
        // linear transformation is needed
        double alpha = 2 / (b - a);
        double beta = a * alpha;

        T[0] = cc->eval_mult(x, alpha);
        cc->mod_reduce_in_place(T[0]);
        cc->eval_add_in_place(T[0], -1.0 - beta);
    }

    // Computes Chebyshev polynomials up to degree k
    // for y: T_1(y) = y, T_2(y), ... , T_k(y)
    // uses binary tree multiplication
    for (uint32_t i = 2; i <= k; ++i) {
        if (i & 0x1) {  // if i is odd
            // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
            T[i - 1] = cc->eval_mult(T[i / 2 - 1], T[i / 2]);
            cc->eval_add_in_place_no_check(T[i - 1], T[i - 1]);
            cc->mod_reduce_in_place(T[i - 1]);
            cc->eval_sub_in_place(T[i - 1], T[0]);
        } else {
            // compute T_{2i}(y) = 2*T_i(y)^2 - 1
            T[i - 1] = cc->eval_square(T[i / 2 - 1]);
            cc->eval_add_in_place_no_check(T[i - 1], T[i - 1]);
            cc->mod_reduce_in_place(T[i - 1]);
            cc->eval_add_in_place(T[i - 1], -1.0);
        }
    }

    // Bring all polynomials to the level and the noise-scale degree of the top one (under FIXEDMANUAL every
    // polynomial has degree 1, so only the number of towers is aligned).
    for (uint32_t i = 1; i < k; ++i)
        cc->get_scheme()->adjust_levels_and_depth_in_place(T[i - 1], T[k - 1]);

    std::vector<Ciphertext<RnsPoly>> T2(m);
    // T2[0] is used as a placeholder
    T2[0] = T.back();

    // computes T_{k(2*m - 1)}(y)
    auto t2km1 = T.back();

    for (uint32_t i = 1; i < m; ++i) {
        // Compute the Chebyshev polynomials T_k(y), T_{2k}(y), T_{4k}(y), ... , T_{2^{m-1}k}(y)
        T2[i] = cc->eval_square(T2[i - 1]);
        cc->eval_add_in_place_no_check(T2[i], T2[i]);
        cc->mod_reduce_in_place(T2[i]);
        cc->eval_add_in_place(T2[i], -1.0);

        // compute T_{k(2*m - 1)} = 2*T_{k(2^{m-1}-1)}(y)*T_{k*2^{m-1}}(y) - T_k(y)
        t2km1 = cc->eval_mult(t2km1, T2[i]);
        cc->eval_add_in_place_no_check(t2km1, t2km1);
        cc->mod_reduce_in_place(t2km1);
        cc->eval_sub_in_place(t2km1, T2[0]);
    }

    return std::make_shared<SeriesPowers<RnsPoly>>(std::move(T), std::move(T2), std::move(t2km1), k, m);
}

template <typename VectorDataType>
Ciphertext<RnsPoly> internal_eval_chebyshev_series_ps_with_precomp(
        const std::shared_ptr<SeriesPowers<RnsPoly>>& ctxt_polys, const std::vector<VectorDataType>& coefficients) {
    auto& T = ctxt_polys->powers_re;
    auto& T2 = ctxt_polys->powers2_re;
    auto& t2km1 = ctxt_polys->power2km1_re;
    auto k = ctxt_polys->k;
    auto m = ctxt_polys->m;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add T^{k(2^m - 1)}(y) to the polynomial that has to be evaluated
    auto f2 = coefficients;
    f2.resize(Degree(f2) + 1);
    f2.resize(2 * k2m2k + k + 1);
    f2.back() = 1;

    // Serialize tree if k*2^{m-1} < 128
    if (k * (1U << (m - 1)) < 128)
        return T[0]->get_crypto_context()->eval_sub(inner_eval_chebyshev_ps(T[0], f2, k, m, T, T2), t2km1);

    Ciphertext<RnsPoly> result;
#pragma omp parallel num_threads(cipher_parallel_controls.get_thread_limit(6 * m + 2))
    {
#pragma omp single_value
        result = T[0]->get_crypto_context()->eval_sub(inner_eval_chebyshev_ps(T[0], f2, k, m, T, T2), t2km1);
    }
    return result;
}

std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_cheby_polys(ConstCiphertext<RnsPoly>& x,
                                                                            const std::vector<int64_t>& coefficients,
                                                                            double a, double b) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_cheby_polys_linear(x, coefficients, a, b) : internal_eval_cheby_polys_ps(x, d, a, b);
}
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_cheby_polys(ConstCiphertext<RnsPoly>& x,
                                                                            const std::vector<double>& coefficients,
                                                                            double a, double b) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_cheby_polys_linear(x, coefficients, a, b) : internal_eval_cheby_polys_ps(x, d, a, b);
}
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsAdvancedShe::eval_cheby_polys(
        ConstCiphertext<RnsPoly>& x, const std::vector<std::complex<double>>& coefficients, double a, double b) const {
    uint32_t d = Degree(coefficients);
    return (d < 5) ? internal_eval_cheby_polys_linear(x, coefficients, a, b) : internal_eval_cheby_polys_ps(x, d, a, b);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series(ConstCiphertext<RnsPoly>& x,
                                                              const std::vector<int64_t>& coeffs, double a,
                                                              double b) const {
    return (Degree(coeffs) < 5) ? eval_chebyshev_series_linear(x, coeffs, a, b) :
                                  eval_chebyshev_series_ps(x, coeffs, a, b);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series(ConstCiphertext<RnsPoly>& x,
                                                              const std::vector<double>& coeffs, double a,
                                                              double b) const {
    return (Degree(coeffs) < 5) ? eval_chebyshev_series_linear(x, coeffs, a, b) :
                                  eval_chebyshev_series_ps(x, coeffs, a, b);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series(ConstCiphertext<RnsPoly>& x,
                                                              const std::vector<std::complex<double>>& coeffs, double a,
                                                              double b) const {
    return (Degree(coeffs) < 5) ? eval_chebyshev_series_linear(x, coeffs, a, b) :
                                  eval_chebyshev_series_ps(x, coeffs, a, b);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_with_precomp(
        std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers, const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_chebyshev_series_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_chebyshev_series_ps_with_precomp(ctxt_powers, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_with_precomp(
        std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers, const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_chebyshev_series_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_chebyshev_series_ps_with_precomp(ctxt_powers, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_with_precomp(
        std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers, const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? internal_eval_chebyshev_series_linear_with_precomp(ctxt_powers->powers_re, coeffs) :
                                  internal_eval_chebyshev_series_ps_with_precomp(ctxt_powers, coeffs);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_linear(ConstCiphertext<RnsPoly>& x,
                                                                     const std::vector<int64_t>& coeffs, double a,
                                                                     double b) const {
    return internal_eval_chebyshev_series_linear_with_precomp(
            internal_eval_cheby_polys_linear(x, coeffs, a, b)->powers_re, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_linear(ConstCiphertext<RnsPoly>& x,
                                                                     const std::vector<double>& coeffs, double a,
                                                                     double b) const {
    return internal_eval_chebyshev_series_linear_with_precomp(
            internal_eval_cheby_polys_linear(x, coeffs, a, b)->powers_re, coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_linear(ConstCiphertext<RnsPoly>& x,
                                                                     const std::vector<std::complex<double>>& coeffs,
                                                                     double a, double b) const {
    return internal_eval_chebyshev_series_linear_with_precomp(
            internal_eval_cheby_polys_linear(x, coeffs, a, b)->powers_re, coeffs);
}

Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_ps(ConstCiphertext<RnsPoly>& x,
                                                                 const std::vector<int64_t>& coeffs, double a,
                                                                 double b) const {
    return internal_eval_chebyshev_series_ps_with_precomp(internal_eval_cheby_polys_ps(x, Degree(coeffs), a, b),
                                                          coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_ps(ConstCiphertext<RnsPoly>& x,
                                                                 const std::vector<double>& coeffs, double a,
                                                                 double b) const {
    return internal_eval_chebyshev_series_ps_with_precomp(internal_eval_cheby_polys_ps(x, Degree(coeffs), a, b),
                                                          coeffs);
}
Ciphertext<RnsPoly> CkksRnsAdvancedShe::eval_chebyshev_series_ps(ConstCiphertext<RnsPoly>& x,
                                                                 const std::vector<std::complex<double>>& coeffs,
                                                                 double a, double b) const {
    return internal_eval_chebyshev_series_ps_with_precomp(internal_eval_cheby_polys_ps(x, Degree(coeffs), a, b),
                                                          coeffs);
}

}  // namespace cipher
