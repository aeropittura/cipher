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

#ifndef CIPHER_BOOLEAN_RGSW_ACC_COMMON_H_
#define CIPHER_BOOLEAN_RGSW_ACC_COMMON_H_

#include <cstdint>
#include <memory>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "cipher/boolean/rgsw_params.h"
#include "cipher/util/parallel.h"

// Accumulator and key-generation bodies shared between the 64-bit accumulators and the 32-bit
// internal path, templated on the polynomial type so each algorithm exists exactly once. P's
// word type is P::Integer::Integer (BasicInteger for NativePoly, uint32_t for NativePoly32).

namespace cipher {

// NativeInteger at width of P::Integer: identity for NativePoly, narrowing copy for NativePoly32
template <typename Int>
Int at_width(const NativeInteger& x) {
    if constexpr (std::is_same_v<Int, NativeInteger>)
        return x;
    else
        return Int(x.template convert_to_int<typename Int::Integer>());
}

enum class GadgetTerm { NONE, ADD, SUB };

/**
 * @brief The plaintext of one RGSW encryption: term * X^position * G, where G is the gadget vector
 */
struct GadgetMonomial {
    uint32_t position{0};               ///< exponent of X, in [0, N)
    GadgetTerm term{GadgetTerm::NONE};  ///< sign of the monomial; NONE encrypts zero
};

// X^m for an exponent m given modulo q: scaled to the cyclotomic order 2N and folded past N into
// a sign, since X^N = -1
inline GadgetMonomial monomial_of(const std::shared_ptr<RingGswCryptoParams>& params, LwePlaintext m) {
    const int64_t q = params->get_q().convert_to_int<int64_t>();
    const int64_t N = params->get_N();
    const int64_t mm = (((m % q) + q) % q) * (2 * N / q);
    if (mm >= N)
        return {static_cast<uint32_t>(mm - N), GadgetTerm::SUB};
    return {static_cast<uint32_t>(mm), GadgetTerm::ADD};
}

// RGSW encryption of mono under sk_ntt at the width of P, with the gadget base assigned to LWE
// index `index`: 2(digits_g - 1) rows, the first digit being dropped by the approximate decomposition
template <typename P, typename PP>
std::vector<std::vector<P>> rgsw_encrypt(const std::shared_ptr<RingGswCryptoParams>& params, const PP& poly_params,
                                        const P& sk_ntt, const DiscreteGaussianGeneratorImpl<typename P::Vector>& dgg,
                                        uint32_t index, GadgetMonomial mono) {
    using Int = typename P::Integer;
    DiscreteUniformGeneratorImpl<typename P::Vector> dug;
    const Int Q{at_width<Int>(params->get_Q())};

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->get_base_g_params(index);
    uint32_t digits_g2{(bp.digits_g - 1) << 1};
    const auto& gpow_value{*bp.gpow};

    std::vector<std::vector<P>> result(digits_g2, std::vector<P>(2));
    P tmp;
    for (uint32_t i = 0; i < digits_g2; ++i) {
        result[i][0] = P(dug, poly_params, Format::COEFFICIENT);
        tmp = result[i][0];
        tmp.set_format(Format::EVALUATION);
        result[i][1] = P(dgg, poly_params, Format::COEFFICIENT);
        const Int g{at_width<Int>(gpow_value[(i >> 1) + 1])};
        if (mono.term == GadgetTerm::ADD)  // (i even) Add G Multiple, (i odd) [a,as+e] + X^m*G
            result[i][i & 0x1][mono.position].mod_add_fast_eq(g, Q);
        else if (mono.term == GadgetTerm::SUB)  // (i even) Sub G Multiple, (i odd) [a,as+e] - X^m*G
            result[i][i & 0x1][mono.position].mod_sub_fast_eq(g, Q);
        result[i][0].set_format(Format::EVALUATION);
        result[i][1].set_format(Format::EVALUATION);
        result[i][1] += (tmp *= sk_ntt);
    }
    return result;
}

// RGSW encryption of sk_ntt(X^k) * G under sk_ntt at the width of P, for the LMKCDEY automorphism
// keys: digits_g - 1 rows, sampled directly in evaluation form
template <typename P, typename PP>
std::vector<std::vector<P>> rgsw_encrypt_automorphism(const std::shared_ptr<RingGswCryptoParams>& params,
                                                    const PP& poly_params, const P& sk_ntt,
                                                    const DiscreteGaussianGeneratorImpl<typename P::Vector>& dgg,
                                                    LwePlaintext k) {
    using Int = typename P::Integer;
    const auto& gpow_value{params->get_g_power()};
    auto sk_auto{sk_ntt.automorphism_transform(k)};

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digits_g{params->get_digits_g() - 1};
    std::vector<std::vector<P>> result(digits_g, std::vector<P>(2));
    DiscreteUniformGeneratorImpl<typename P::Vector> dug;
    for (uint32_t i = 0; i < digits_g; ++i) {
        const Int g{at_width<Int>(gpow_value[i + 1])};
        result[i][0] = P(dug, poly_params, Format::EVALUATION);
        result[i][1] = P(dgg, poly_params, Format::EVALUATION) - sk_auto * g;
        result[i][1] += result[i][0] * sk_ntt;
    }
    return result;
}

// Excess-H signed digit decomposition of an RLWE ciphertext (both components) into digits_g2
// digits. Biasing by H (g_half in every digit position) turns balanced-digit extraction into
// independent unsigned windows: digit_k(x) = (((x + H) >> k*g_bits) & g_mask) - g_half.
// Requires digits_g*g_bits + 1 <= word bits, which holds for all supported parameter sets.
template <typename P>
void excess_h_digit_decompose(typename P::Integer::Integer Q, const RingGswCryptoParams::BaseGParams& bp,
                           const std::vector<P>& input, std::vector<P>& output) {
    using I = typename P::Integer::Integer;
    I Q_half{Q >> 1};
    uint32_t g_bits{bp.g_bits};
    I g_half{static_cast<I>(bp.base_g >> 1)};
    I g_mask{static_cast<I>(bp.base_g - 1)};
    I qm_half{Q - g_half};
    uint32_t digits_g{bp.digits_g};
    I H{0};
    for (uint32_t i{0}; i < digits_g; ++i)
        H += g_half << (i * g_bits);
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digits_g2{(digits_g - 1) << 1};
    uint32_t N{input[0].get_length()};

    std::vector<I> w0(N), w1(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[0][k].template convert_to_int<I>()};
        w0[k] = t0 + H - (t0 < Q_half ? 0 : Q);
        auto t1{input[1][k].template convert_to_int<I>()};
        w1[k] = t1 + H - (t1 < Q_half ? 0 : Q);
    }

    for (uint32_t d{0}; d < digits_g2; d += 2) {
        uint32_t shift{((d >> 1) + 1) * g_bits};
        // Q/2 + H can exceed base_g^digits_g, so the top window must keep the carry out of digits_g*g_bits.
        auto mask{(d + 2 < digits_g2) ? g_mask : static_cast<I>(-1)};
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w0[k] >> shift) & mask};
            out0[k] = (r0 < g_half) ? r0 + qm_half : r0 - g_half;
            auto r1{(w1[k] >> shift) & mask};
            out1[k] = (r1 < g_half) ? r1 + qm_half : r1 - g_half;
        }
    }
}

// Single-ring-element overload producing digits_g - 1 digits (for LMKCDEY automorphism key switch)
template <typename P>
void excess_h_digit_decompose(typename P::Integer::Integer Q, const RingGswCryptoParams::BaseGParams& bp, const P& input,
                           std::vector<P>& output) {
    using I = typename P::Integer::Integer;
    I Q_half{Q >> 1};
    uint32_t g_bits{bp.g_bits};
    I g_half{static_cast<I>(bp.base_g >> 1)};
    I g_mask{static_cast<I>(bp.base_g - 1)};
    I qm_half{Q - g_half};
    uint32_t digits_g{bp.digits_g};
    I H{0};
    for (uint32_t i{0}; i < digits_g; ++i)
        H += g_half << (i * g_bits);
    uint32_t N{input.get_length()};

    std::vector<I> w(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[k].template convert_to_int<I>()};
        w[k] = t0 + H - (t0 < Q_half ? 0 : Q);
    }

    // approximate gadget decomposition is used; the first digit is ignored
    for (uint32_t d{0}; d < digits_g - 1; ++d) {
        uint32_t shift{(d + 1) * g_bits};
        // Q/2 + H can exceed base_g^digits_g, so the top window must keep the carry out of digits_g*g_bits.
        auto mask{(d + 2 < digits_g) ? g_mask : static_cast<I>(-1)};
        auto& out{output[d]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w[k] >> shift) & mask};
            out[k] = (r0 < g_half) ? r0 + qm_half : r0 - g_half;
        }
    }
}

// acc = dct * ev (matrix product over the gadget digits);
template <typename P>
void gadget_matrix_product(std::vector<P>& acc, std::vector<P>& dct, const std::vector<std::vector<P>>& ev,
                         uint32_t rows) {
    acc[0] = (dct[0] * ev[0][0]);
    for (uint32_t d = 1; d < rows; ++d)
        acc[0].mult_acc_eq_no_check(dct[d], ev[d][0]);
    acc[1] = (dct[0] *= ev[0][1]);
    for (uint32_t d = 1; d < rows; ++d)
        acc[1].mult_acc_eq_no_check(dct[d], ev[d][1]);
}

// DM/LMKCDEY acc (no monomial): decompose, NTT the digits, external product with one RGSW key.
template <typename P, typename PP>
void add_to_acc_no_monomial(const PP& poly_params, typename P::Integer::Integer Q,
                        const RingGswCryptoParams::BaseGParams& bp, const std::vector<std::vector<P>>& ev,
                        std::vector<P>& acc) {
    using I = typename P::Integer::Integer;
    thread_local std::vector<P> ct_scratch, dct_scratch;
    thread_local std::vector<I> w0_scratch, w1_scratch;
    auto& ct = ct_scratch;
    auto& dct = dct_scratch;
    auto& w0 = w0_scratch;
    auto& w1 = w1_scratch;
    ct = acc;

    uint32_t N{acc[0].get_length()};
    if (w0.size() != N) {
        w0.resize(N);
        w1.resize(N);
    }

    uint32_t digits_g2{(bp.digits_g - 1) << 1};
    if (dct.size() < digits_g2 || dct[0].get_params() != poly_params) {
        dct.assign(digits_g2, P(poly_params, Format::COEFFICIENT, true));
    } else {
        for (auto& d : dct)
            d.override_format(Format::COEFFICIENT);
    }

    int nthreads = cipher_parallel_controls.get_thread_limit(bp.team_width > 4 ? bp.team_width : 4);
    if (nthreads < 2) {
        ct[0].set_format(Format::COEFFICIENT);
        ct[1].set_format(Format::COEFFICIENT);
        excess_h_digit_decompose(Q, bp, ct, dct);
        for (uint32_t d = 0; d < digits_g2; ++d)
            dct[d].set_format(Format::EVALUATION);
        gadget_matrix_product(acc, dct, ev, digits_g2);
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].set_format(Format::COEFFICIENT);

#pragma omp barrier
        // the shared form spreads the decomposition across the region at the price of one
        // more barrier, which only repays itself once the gadget is wide and the split deep
        if (digits_g2 >= 8 && nthreads >= 4) {
            excess_h_digit_decompose_shared(Q, bp, ct, dct, w0, w1);
        } else {
#pragma omp single_value
            excess_h_digit_decompose(Q, bp, ct, dct);
        }

#pragma omp for schedule(static)
        for (uint32_t d = 0; d < digits_g2; ++d)
            dct[d].set_format(Format::EVALUATION);

        // each column writes only its own acc element, so gadget_matrix_product's in-place
        // reuse of dct[0] for the second column cannot be used here. nowait: the region's
        // own closing barrier is the one the caller needs
#pragma omp for schedule(static) nowait
        for (uint32_t j = 0; j < 2; ++j) {
            acc[j] = dct[0];
            acc[j] *= ev[0][j];
            for (uint32_t d = 1; d < digits_g2; ++d)
                acc[j].mult_acc_eq_no_check(dct[d], ev[d][j]);
        }
    }
}

// As above, but the two loops are worksharing constructs that bind to the region the caller
// already opened, so the decomposition runs across that region's threads instead of on one.
// w0 and w1 are the caller's, and must be sized N before the region opens: every thread runs
// this body and each fills part of the one shared pair.
template <typename P>
void excess_h_digit_decompose_shared(typename P::Integer::Integer Q, const RingGswCryptoParams::BaseGParams& bp,
                                 const std::vector<P>& input, std::vector<P>& output,
                                 std::vector<typename P::Integer::Integer>& w0,
                                 std::vector<typename P::Integer::Integer>& w1) {
    using I = typename P::Integer::Integer;
    I Q_half{Q >> 1};
    uint32_t g_bits{bp.g_bits};
    I g_half{static_cast<I>(bp.base_g >> 1)};
    I g_mask{static_cast<I>(bp.base_g - 1)};
    I qm_half{Q - g_half};
    uint32_t digits_g{bp.digits_g};
    I H{0};
    for (uint32_t i{0}; i < digits_g; ++i)
        H += g_half << (i * g_bits);
    uint32_t digits_g2{(digits_g - 1) << 1};
    uint32_t N{input[0].get_length()};

#pragma omp for schedule(static)
    for (uint32_t k = 0; k < N; ++k) {
        auto t0{input[0][k].template convert_to_int<I>()};
        w0[k] = t0 + H - (t0 < Q_half ? 0 : Q);
        auto t1{input[1][k].template convert_to_int<I>()};
        w1[k] = t1 + H - (t1 < Q_half ? 0 : Q);
    }

#pragma omp for schedule(static)
    for (uint32_t d = 0; d < digits_g2; d += 2) {
        uint32_t shift{((d >> 1) + 1) * g_bits};
        auto mask{(d + 2 < digits_g2) ? g_mask : static_cast<I>(-1)};
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w0[k] >> shift) & mask};
            out0[k] = (r0 < g_half) ? r0 + qm_half : r0 - g_half;
            auto r1{(w1[k] >> shift) & mask};
            out1[k] = (r1 < g_half) ? r1 + qm_half : r1 - g_half;
        }
    }
}

// The LMKCDEY automorphism: permute both components by X -> X^a, then switch key of
// a-component back with automorphism key ak. Uses default gadget base and digits_g - 1 digits.
template <typename P, typename PP>
void automorphism_key_switch(uint32_t a, const std::vector<uint32_t>& auto_map, const PP& poly_params,
                           typename P::Integer::Integer Q, const RingGswCryptoParams::BaseGParams& bp,
                           const std::vector<std::vector<P>>& ev, std::vector<P>& acc) {
    acc[1] = acc[1].automorphism_transform(a, auto_map);

    P cta(acc[0].automorphism_transform(a, auto_map));
    acc[0].set_values_to_zero();
    cta.set_format(Format::COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digits_g{bp.digits_g - 1};
    thread_local std::vector<P> dcta_scratch;
    auto& dcta = dcta_scratch;
    if (dcta.size() != digits_g || dcta[0].get_params() != poly_params) {
        dcta.assign(digits_g, P(poly_params, Format::COEFFICIENT, true));
    } else {
        for (auto& d : dcta)
            d.override_format(Format::COEFFICIENT);
    }

    excess_h_digit_decompose(Q, bp, cta, dcta);

    int nthreads = cipher_parallel_controls.get_thread_limit(bp.team_width > 4 ? bp.team_width : 4);
    if (nthreads < 2) {
        for (uint32_t d = 0; d < digits_g; ++d)
            dcta[d].set_format(Format::EVALUATION);
        for (uint32_t d = 0; d < digits_g; ++d)
            acc[0].mult_acc_eq_no_check(dcta[d], ev[d][0]);
        for (uint32_t d = 0; d < digits_g; ++d)
            acc[1].mult_acc_eq_no_check(dcta[d], ev[d][1]);
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static)
        for (uint32_t d = 0; d < digits_g; ++d)
            dcta[d].set_format(Format::EVALUATION);

#pragma omp for schedule(static) nowait
        for (uint32_t j = 0; j < 2; ++j)
            for (uint32_t d = 0; d < digits_g; ++d)
                acc[j].mult_acc_eq_no_check(dcta[d], ev[d][j]);
    }
}

#if CIPHER_NATIVE_INT != 32
// a *= b (mod q) using b's Shoup constants: one high-word estimate per lane, vectorizable at
// every ISA where the Barrett form is not
inline void shoup_mul_eq32(NativePoly32& a, const NativePoly32& b, const NativeVector32& b_precon, uint32_t q) {
    uint32_t N{static_cast<uint32_t>(a.get_length())};
    for (size_t k = 0; k < N; ++k) {
        uint32_t x{static_cast<uint32_t>(a[k].convert_to_int())};
        uint32_t hi{static_cast<uint32_t>((static_cast<uint64_t>(x) * b_precon[k].convert_to_int()) >> 32)};
        uint32_t r{x * static_cast<uint32_t>(b[k].convert_to_int()) - hi * q};
        a[k] = NativeInteger32(r - (q & (uint32_t(0) - static_cast<uint32_t>(r >= q))));
    }
}

// Inner product over the gadget digits with ONE modular reduction instead of one per digit.
inline void lazy_inner_product32(NativePoly32& out, const std::vector<NativePoly32>& dct,
                               const std::vector<std::vector<NativePoly32>>& ev, uint32_t col, uint32_t rows,
                               uint32_t k_begin, uint32_t k_end, uint32_t N, uint32_t q, uint64_t mu) {
    thread_local std::vector<uint64_t> acc;
    if (acc.size() < N)
        acc.resize(N);
    {
        const auto& d0{dct[0].get_values()};
        const auto& e0{ev[0][col].get_values()};
        for (uint32_t k = k_begin; k < k_end; ++k)
            acc[k] = static_cast<uint64_t>(d0[k].convert_to_int()) * e0[k].convert_to_int();
    }
    for (uint32_t i = 1; i < rows; ++i) {
        const auto& di{dct[i].get_values()};
        const auto& ei{ev[i][col].get_values()};
        for (uint32_t k = k_begin; k < k_end; ++k)
            acc[k] += static_cast<uint64_t>(di[k].convert_to_int()) * ei[k].convert_to_int();
    }
    for (uint32_t k = k_begin; k < k_end; ++k) {
    #if defined(CIPHER_HAVE_INT128)
        uint64_t x{acc[k]};
        uint64_t hi{static_cast<uint64_t>((static_cast<uint128_t>(x) * mu) >> 64)};
        uint64_t r{x - hi * q};
        // mu = floor(2^64/q) underestimates the quotient by up to 2, so r is in [0, 3q):
        // the correction is repeated on purpose
        if (r >= q)
            r -= q;
        if (r >= q)
            r -= q;
    #else
        // no double-width type: the lazy accumulation still stands, only the single reduction
        // falls back to a hardware divide -- still far better than reducing once per digit.
        uint64_t r{acc[k] % q};
    #endif
        out[k] = NativeInteger32(static_cast<uint32_t>(r));
    }
}

// 32-bit overload of the accumulation body above: identical shape, with the lazy inner product
// replacing the per-digit reduction. Exact-match overload resolution routes the NativePoly32
// instantiations here; results are bit-identical to the generic body. The automorphism key
// switch stays on the generic poly-op body: its row count (digits_g - 1) is too small for the
// lazy kernel to pay.
inline void add_to_acc_no_monomial(const std::shared_ptr<NativePolyParams32>& poly_params, uint32_t Q,
                               const RingGswCryptoParams::BaseGParams& bp,
                               const std::vector<std::vector<NativePoly32>>& ev, std::vector<NativePoly32>& acc) {
    thread_local std::vector<NativePoly32> ct_scratch, dct_scratch;
    thread_local std::vector<uint32_t> w0_scratch, w1_scratch;
    auto& ct = ct_scratch;
    auto& dct = dct_scratch;
    ct = acc;

    uint32_t digits_g2{(bp.digits_g - 1) << 1};
    if (dct.size() < digits_g2 || dct[0].get_params() != poly_params) {
        dct.assign(digits_g2, NativePoly32(poly_params, Format::COEFFICIENT, true));
    } else {
        for (auto& d : dct)
            d.override_format(Format::COEFFICIENT);
    }

    uint32_t N{static_cast<uint32_t>(poly_params->get_ring_dimension())};
    auto& w0 = w0_scratch;
    auto& w1 = w1_scratch;
    if (w0.size() != N) {
        w0.resize(N);
        w1.resize(N);
    }
    uint64_t mu{static_cast<uint64_t>(-1) / Q};

    int nthreads = cipher_parallel_controls.get_thread_limit(bp.team_width > 4 ? bp.team_width : 4);
    if (nthreads < 2) {
        ct[0].set_format(Format::COEFFICIENT);
        ct[1].set_format(Format::COEFFICIENT);
        excess_h_digit_decompose(Q, bp, ct, dct);
        for (uint32_t d = 0; d < digits_g2; ++d)
            dct[d].set_format(Format::EVALUATION);
        lazy_inner_product32(acc[0], dct, ev, 0, digits_g2, 0, N, N, Q, mu);
        lazy_inner_product32(acc[1], dct, ev, 1, digits_g2, 0, N, N, Q, mu);
        return;
    }

    #pragma omp parallel num_threads(nthreads)
    {
    #pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].set_format(Format::COEFFICIENT);

    #pragma omp barrier
        if (digits_g2 >= 8 && nthreads >= 4) {
            excess_h_digit_decompose_shared(Q, bp, ct, dct, w0, w1);
        } else {
    #pragma omp single_value
            excess_h_digit_decompose(Q, bp, ct, dct);
        }

    #pragma omp for schedule(static)
        for (uint32_t d = 0; d < digits_g2; ++d)
            dct[d].set_format(Format::EVALUATION);

    #pragma omp for schedule(static) nowait
        for (uint32_t blk = 0; blk < static_cast<uint32_t>(nthreads); ++blk) {
            uint32_t kb{(N * blk) / static_cast<uint32_t>(nthreads)};
            uint32_t ke{(N * (blk + 1)) / static_cast<uint32_t>(nthreads)};
            lazy_inner_product32(acc[0], dct, ev, 0, digits_g2, kb, ke, N, Q, mu);
            lazy_inner_product32(acc[1], dct, ev, 1, digits_g2, kb, ke, N, Q, mu);
        }
    }
}

#endif  // CIPHER_NATIVE_INT != 32

// The DM digit schedule: one accumulation per nonzero base-R digit of each LWE coefficient.
template <typename AddFn>
void dm_acc_schedule(NativeInteger q, uint32_t base_r, size_t digits_r_count, const NativeVector& a, AddFn&& add_to_acc) {
    if (a.get_modulus() != q)
        CIPHER_THROW("Ciphertext modulus must equal the LWE modulus q");
    NativeInteger base_rn{base_r};
    uint32_t n{static_cast<uint32_t>(a.get_length())};
    for (uint32_t i = 0; i < n; ++i) {
        auto a_i = NativeInteger(0).mod_sub_fast(a[i], q);
        for (size_t k = 0; k < digits_r_count; ++k, a_i /= base_rn) {
            auto a0 = (a_i.mod(base_rn)).convert_to_int<uint32_t>();
            if (a0)
                add_to_acc(i, a0, k);
        }
    }
}

// The LMKCDEY rotation schedule over the generator's orbit, as described in
// https://eprint.iacr.org/2022/198: group the coefficients by discrete log, walk the orbit
// applying at most num_auto_keys-sized automorphism hops between accumulations. The caller applies
// the initial X -> X^{-gen} transform of the accumulator body before invoking this.
// add_to_acc(i) performs the external product for LWE coefficient i;
// automorphism_value(power, k) applies X -> X^power using automorphism key k.
template <typename AddFn, typename AutoFn>
void lmkcdey_acc_schedule(NativeInteger q, uint32_t N, uint32_t num_auto_keys, const std::vector<int32_t>& log_gen,
                        const NativeVector& a, AddFn&& add_to_acc, AutoFn&& automorphism_value) {
    if (a.get_modulus() != q)
        CIPHER_THROW("Ciphertext modulus must equal the LWE modulus q");
    // assume a is all-odd ciphertext (using round-to-odd technique)
    size_t n{a.get_length()};
    uint32_t nh_value{N / 2};
    uint32_t M{2 * N};
    NativeInteger m_native{M};

    std::unordered_map<int32_t, std::vector<int32_t>> permute_map;
    for (size_t i = 0; i < n; i++) {  // put all a_i in the permute_map
        // make it odd; round-to-odd(https://eprint.iacr.org/2022/198) will improve error.
        int32_t a_i_odd = NativeInteger(0).mod_sub_fast(a[i], m_native).convert_to_int<uint32_t>() | 0x1;
        permute_map[log_gen[a_i_odd]].push_back(i);
    }

    NativeInteger gen(5);
    uint32_t gen_int{5};
    uint32_t n_skips{0};

    // for a_j = -5^i
    for (uint32_t i = nh_value - 1; i > 0; i--) {
        auto it = permute_map.find(-static_cast<int32_t>(i));
        if (it != permute_map.end()) {
            if (n_skips != 0) {  // Rotation by 5^n_skips
                automorphism_value(gen.mod_exp(n_skips, M), n_skips);
                n_skips = 0;
            }
            for (auto idx : it->second)
                add_to_acc(idx);
        }
        n_skips++;

        if (n_skips == num_auto_keys || i == 1) {
            automorphism_value(gen.mod_exp(n_skips, M), n_skips);
            n_skips = 0;
        }
    }

    // for -1
    auto it_m = permute_map.find(M);
    if (it_m != permute_map.end()) {
        for (auto idx : it_m->second)
            add_to_acc(idx);
    }

    automorphism_value(NativeInteger(M - gen_int), 0);

    // for a_j = 5^i
    for (size_t i = nh_value - 1; i > 0; i--) {
        auto it = permute_map.find(i);
        if (it != permute_map.end()) {
            if (n_skips != 0) {  // Rotation by 5^n_skips
                automorphism_value(gen.mod_exp(n_skips, M), n_skips);
                n_skips = 0;
            }
            for (auto idx : it->second)
                add_to_acc(idx);
        }
        n_skips++;

        if (n_skips == num_auto_keys || i == 1) {
            automorphism_value(gen.mod_exp(n_skips, M), n_skips);
            n_skips = 0;
        }
    }

    // for 0
    auto it0 = permute_map.find(0);
    if (it0 != permute_map.end()) {
        for (auto idx : it0->second)
            add_to_acc(idx);
    }
}

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_ACC_COMMON_H_
