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

#ifndef CIPHER_MATH_BACKEND_NATIVE_TRANSFORM_IMPL_H_
#define CIPHER_MATH_BACKEND_NATIVE_TRANSFORM_IMPL_H_

// ATTENTION: this file contains implementations of the functions
//            declared in math/intnat/transformnat.h and
//            MUST be included in the end of math/intnat/transformnat.h ONLY
//            and nowhere else
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend/native/mod_vector.h"
#include "cipher/math/backend/native/transform.h"
#include "cipher/math/backend/native/integer.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/debug.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

namespace native_int {

using namespace cipher;

/**
 * Conditional subtraction v >= q ? v - q : v computed without a branch, for v < 2q.
 *
 * @param v is the value to reduce.
 * @param q is the modulus.
 * @return v reduced into [0, q).
 */
template <typename NInt>
static inline NInt cond_sub_no_cmp(NInt v, NInt q) {
#if defined(__clang__) && defined(__x86_64__) && !defined(__AVX2__)
    const NInt t{static_cast<NInt>(v - q)};
    return static_cast<NInt>(t + (q & (NInt(0) - static_cast<NInt>(t >> (8 * sizeof(NInt) - 1)))));
#else
    return static_cast<NInt>(v - (q & (NInt(0) - static_cast<NInt>(v >= q))));
#endif
}

// Shoup high-word multiply for the raw-lane butterflies. gcc's vectorizer takes the
// 32-bit-halves form with AVX2+ lanes and never takes the double-width form; clang vectorizes
// the double-width form on its own and is slower with the halves form, so the halves
// form is gcc-only. Scalar, the double-width form always wins, hence the fallbacks.
/**
 * High word of the 32x32-bit product, as used by the Shoup multiplication.
 *
 * @param a is the first factor.
 * @param b is the second factor.
 * @return the upper 32 bits of a * b.
 */
static inline uint32_t shoup_mul_hi(uint32_t a, uint32_t b) {
    return static_cast<uint32_t>((static_cast<uint64_t>(a) * b) >> 32);
}

/**
 * High word of the 64x64-bit product, as used by the Shoup multiplication; uses the
 * 128-bit type, the x86-64 mulq instruction, or 32-bit halves depending on the target.
 *
 * @param a is the first factor.
 * @param b is the second factor.
 * @return the upper 64 bits of a * b.
 */
static inline uint64_t shoup_mul_hi(uint64_t a, uint64_t b) {
#if defined(__AVX2__) && defined(__GNUC__) && !defined(__clang__)
    uint64_t al{a & 0xffffffffu}, ah{a >> 32}, bl{b & 0xffffffffu}, bh{b >> 32};
    uint64_t t0{al * bl};
    uint64_t t1{al * bh + (t0 >> 32)};
    uint64_t t2{ah * bl + (t1 & 0xffffffffu)};
    return ah * bh + (t1 >> 32) + (t2 >> 32);
#elif defined(CIPHER_HAVE_INT128)
    return static_cast<uint64_t>((static_cast<uint128_t>(a) * b) >> 64);
#elif defined(__x86_64__)
    uint64_t lo, hi;
    __asm__("mulq %[b]" : "=a"(lo), "=d"(hi) : "a"(a), [b] "rm"(b) : "cc");
    return hi;
#else
    uint64_t al{a & 0xffffffffu}, ah{a >> 32}, bl{b & 0xffffffffu}, bh{b >> 32};
    uint64_t t0{al * bl};
    uint64_t t1{al * bh + (t0 >> 32)};
    uint64_t t2{ah * bl + (t1 & 0xffffffffu)};
    return ah * bh + (t1 >> 32) + (t2 >> 32);
#endif
}
#if defined(CIPHER_HAVE_INT128)

/**
 * High word of the 128x128-bit product, as used by the Shoup multiplication, built from
 * 64-bit halves.
 *
 * @param a is the first factor.
 * @param b is the second factor.
 * @return the upper 128 bits of a * b.
 */
static inline uint128_t shoup_mul_hi(uint128_t a, uint128_t b) {
    constexpr uint128_t mask{(static_cast<uint128_t>(1) << 64) - 1};
    uint128_t al{a & mask}, ah{a >> 64}, bl{b & mask}, bh{b >> 64};
    uint128_t t0{al * bl};
    uint128_t t1{al * bh + (t0 >> 64)};
    uint128_t t2{ah * bl + (t1 & mask)};
    return ah * bh + (t1 >> 64) + (t2 >> 64);
}
#endif

/// pair loops (2i, 2i + 1) over words wider than 32 bits only vectorize with AVX2+ lanes; the
/// peeled butterfly stages fall back to the classic i += 2 scalar form without them
#if defined(__AVX2__)
inline constexpr bool k_pair_loop64 = true;
#else
inline constexpr bool k_pair_loop64 = false;
#endif

/**
 * Builds the Shoup constants for a root table, so the table-less transform overloads can
 * delegate to the vectorized precon kernels.
 *
 * @param table is the table of roots of unity.
 * @param modulus is the modulus of the transform.
 * @return the vector of prep_mod_mul_const() values of the table entries.
 */
template <typename VecType, typename IntType>
static VecType prep_shoup_consts(const VecType& table, const IntType& modulus) {
    const uint32_t n(table.get_length());
    VecType precon(n, modulus);
    for (size_t i = 0; i < n; ++i)
        precon[i] = table[i].prep_mod_mul_const(modulus);
    return precon;
}

template <typename VecType>
std::map<typename VecType::Integer, std::shared_ptr<const typename ChineseRemainderTransformFttNat<VecType>::Tables>>
        ChineseRemainderTransformFttNat<VecType>::tables_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::cyclotomic_poly_map_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::cyclotomic_poly_reverse_ntt_map_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::cyclotomic_poly_ntt_map_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftNat<VecType>::root_of_unity_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftNat<VecType>::root_of_unity_inverse_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFftNat<VecType>::powers_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRootPair<typename VecType::Integer>, VecType> BluesteinFftNat<VecType>::rb_table_by_modulus_root_pair_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftNat<VecType>::precon_root_of_unity_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftNat<VecType>::precon_root_of_unity_inverse_table_by_modulus_root_;

template <typename VecType>
std::map<typename VecType::Integer, ModulusRoot<typename VecType::Integer>>
        BluesteinFftNat<VecType>::default_ntt_modulus_root_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbNat<VecType>::root_of_unity_division_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbNat<VecType>::root_of_unity_division_inverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbNat<VecType>::root_of_unity_division_precon_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbNat<VecType>::root_of_unity_division_inverse_precon_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
        ChineseRemainderTransformArbNat<VecType>::division_ntt_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
        ChineseRemainderTransformArbNat<VecType>::division_ntt_root_of_unity_;

template <typename VecType>
std::map<uint32_t, uint32_t> ChineseRemainderTransformArbNat<VecType>::ntt_division_dim_;

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_iterative(const VecType& element,
                                                                       const VecType& root_of_unity_table, VecType* r) {
    uint32_t n = element.get_length();
    if (r->get_length() != n)
        CIPHER_THROW("size of input element and size of output element not of same size");
    forward_transform_iterative(element, root_of_unity_table,
                                prep_shoup_consts(root_of_unity_table, element.get_modulus()), r);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_iterative(const VecType& element,
                                                                       const VecType& root_inv_table, VecType* r) {
    inverse_transform_iterative(element, root_inv_table, prep_shoup_consts(root_inv_table, element.get_modulus()), r);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_iterative(const VecType& element,
                                                                       const VecType& root_of_unity_table,
                                                                       const VecType& precon_root_of_unity_table,
                                                                       VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n)
        CIPHER_THROW("size of input element and size of output element not of same size");
    const auto modulus = element.get_modulus();
    result->set_modulus(modulus);

    uint32_t logn = get_msb(n - 1);
    for (size_t i = 0; i < n; ++i) {
        (*result)[i] = element[reverse_bits(i, logn)];
    }

    // raw-lane Shoup butterflies in the same branchless shape as the power-of-two
    // butterfly, so the loop stays auto-vectorizable (clang lowers the element-level
    // mod_mul_fast_const select to a branch/scalar chain at this ISA)
    using NInt = decltype(modulus.value_);
    const NInt mv{modulus.value_};
    // the standard-order table is read at stride 2^shift, which no compiler vectorizes;
    // compacting each stage's twiddles into unit-stride scratch lets the butterfly loop vectorize
    std::vector<NInt> omega(n >> 1);
    std::vector<NInt> precon_omega(n >> 1);
    for (size_t logm = 1; logm <= logn; ++logm) {
        uint32_t m = 1u << (logm - 1);
        uint32_t shift = logn - logm;
        for (size_t i = 0; i < m; ++i) {
            omega[i] = root_of_unity_table[i << shift].value_;
            precon_omega[i] = precon_root_of_unity_table[i << shift].value_;
        }
        for (size_t j = 0; j < n; j += (m << 1)) {
            for (size_t i = 0; i < m; ++i) {
                size_t index_even = j + i;
                size_t index_odd = index_even + m;
                NInt odd{(*result)[index_odd].value_};
                NInt even{(*result)[index_even].value_};
                NInt of{static_cast<NInt>(odd * omega[i] - shoup_mul_hi(odd, precon_omega[i]) * mv)};
                of = cond_sub_no_cmp(of, mv);
                NInt sum{static_cast<NInt>(even + of)};
                (*result)[index_even].value_ = cond_sub_no_cmp(sum, mv);
                NInt dif{static_cast<NInt>(even - of + mv)};
                (*result)[index_odd].value_ = cond_sub_no_cmp(dif, mv);
            }
        }
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_iterative(
        const VecType& element, const VecType& root_of_unity_inverse_table,
        const VecType& precon_root_of_unity_inverse_table, VecType* result) {
    uint32_t n = element.get_length();
    const auto modulus = element.get_modulus();
    NumberTheoreticTransformNat<VecType>().forward_transform_iterative(element, root_of_unity_inverse_table,
                                                                       precon_root_of_unity_inverse_table, result);
    using NInt = decltype(modulus.value_);
    const NInt mv{modulus.value_};
    IntType cyclo_order_inv(IntType(n).mod_inverse(modulus));
    const NInt n_inv{cyclo_order_inv.value_};
    const NInt precon_n_inv{cyclo_order_inv.prep_mod_mul_const(modulus).value_};
    for (size_t i = 0; i < n; ++i) {
        NInt v{(*result)[i].value_};
        NInt r{static_cast<NInt>(v * n_inv - shoup_mul_hi(v, precon_n_inv) * mv)};
        (*result)[i].value_ = cond_sub_no_cmp(r, mv);
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_to_bit_reverse_in_place(const VecType& root_table,
                                                                                     VecType* element) {
    // compute the Shoup constants once and share the vectorized precon kernel
    forward_transform_to_bit_reverse_in_place(root_table, prep_shoup_consts(root_table, element->get_modulus()),
                                              element);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                            const VecType& root_of_unity_table,
                                                                            VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n)
        CIPHER_THROW("size of input element and size of output element not of same size");

    *result = element;
    forward_transform_to_bit_reverse_in_place(root_of_unity_table, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_to_bit_reverse_in_place(
        const VecType& root_of_unity_table, const VecType& precon_root_of_unity_table, VecType* element) {
    // NTT based on the Cooley-Tukey (CT) butterfly
    // Inputs: element (vector of size n in standard ordering)
    //         root_of_unity_table (precomputed roots of unity in bit-reversed ordering)
    // Output: NTT(element) in bit-reversed ordering
    //
    // for (m = 1, t = n, logt = log(t); m < n; m=2*m, t=t/2, --logt) do
    //     for (i = 0; i < m; ++i) do
    //         omega = root_of_unity_inverse_table[i + m]
    //         for (j1 = (i << logt), j2 = (j1 + t); j1 < j2; ++j1) do
    //             lo_val = element[j1 + 0]
    //             hi_val = element[j1 + t]*omega
    //             element[j1 + 0] = (lo_val + hi_val) mod modulus
    //             element[j1 + t] = (lo_val - hi_val) mod modulus
    //

    // Harvey lazy-reduction butterflies (https://arxiv.org/abs/1205.2926): values stay in
    // [0, 4*modulus) between stages (requires modulus < 2^(max_bits-2), which
    // MAX_MODULUS_SIZE guarantees); the full reduction to [0, modulus) is folded into the
    // peeled final stage. Loops work on the raw word values so they stay vectorizable.
    using NInt = typename IntType::Integer;
    const NInt mv{element->get_modulus().value_};
    const NInt mv2{static_cast<NInt>(mv + mv)};
    const uint32_t n(element->get_length() >> 1);
    // Deferred reduction: from [0, modulus) inputs the values grow by 2*modulus per stage, so
    // when (2*stages + 3)*modulus fits the word the per-butterfly conditional subtract can be
    // dropped from every stage and the peeled final stage folds the values back down with a
    // fixed chain.
    const uint32_t stages{get_msb(n)};
#if defined(__clang__) && defined(__x86_64__) && !defined(__AVX2__)
    constexpr bool k_lazy_wide{sizeof(NInt) == 4};
#else
    constexpr bool k_lazy_wide{true};
#endif
    const bool lazy{k_lazy_wide && mv <= static_cast<NInt>(-1) / static_cast<NInt>(2 * stages + 3)};
    if (lazy) {
        for (size_t m{1}, t{n}, logt{get_msb(t)}; m < n; m <<= 1, t >>= 1, --logt) {
            for (size_t i{0}; i < m; ++i) {
                const NInt omega{root_of_unity_table[i + m].value_};
                const NInt precon_omega{precon_root_of_unity_table[i + m].value_};
                // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer
                for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                    NInt hi{(*element)[j1 + t].value_};
                    NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
                    NInt lo{(*element)[j1 + 0].value_};
                    (*element)[j1 + 0].value_ = lo + of;
                    (*element)[j1 + t].value_ = lo - of + mv2;  // of < 2*modulus, so the offset holds
                }
            }
        }
    } else {
        for (size_t m{1}, t{n}, logt{get_msb(t)}; m < n; m <<= 1, t >>= 1, --logt) {
            for (size_t i{0}; i < m; ++i) {
                const NInt omega{root_of_unity_table[i + m].value_};
                const NInt precon_omega{precon_root_of_unity_table[i + m].value_};
                // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer (u32 indexing could wrap)
                for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                    NInt hi{(*element)[j1 + t].value_};
                    NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
                    NInt lo{(*element)[j1 + 0].value_};
                    lo = cond_sub_no_cmp(lo, mv2);
                    (*element)[j1 + 0].value_ = lo + of;
                    (*element)[j1 + t].value_ = lo - of + mv2;
                }
            }
        }
    }
    // peeled final stage, reducing the outputs to [0, modulus). When the stages ran lazily the
    // values sit in [0, (2*stages + 1)*modulus) and fold down through a fixed four-step chain
    // of halving multiples of the modulus (steps at or below the value are no-ops, and every
    // step is a multiple of the modulus, so residues are untouched).
    NInt c0{mv2}, c1{mv2}, c2{mv2}, c3{mv2};
    if (lazy) {
        // largest halving chain start below the value bound; comparing against bound/2 keeps
        // the doubling itself from overflowing (the bound fits the word by the lazy test)
        const NInt bound{static_cast<NInt>(mv * (2 * stages + 1))};
        while (c0 < static_cast<NInt>(bound >> 1))
            c0 <<= 1;
        c1 = (c0 >> 1 > mv2) ? c0 >> 1 : mv2;
        c2 = (c1 >> 1 > mv2) ? c1 >> 1 : mv2;
        c3 = (c2 >> 1 > mv2) ? c2 >> 1 : mv2;
    }
    if constexpr (sizeof(NInt) == 4 || k_pair_loop64) {
        // the index-doubled pair form (2i, 2i + 1) is the stride-2 shape gcc's vectorizer
        // accepts, i += 2 is not
        if (lazy) {
            for (size_t i{0}; i < n; ++i) {
                const NInt omega{root_of_unity_table[i + n].value_};
                const NInt precon_omega{precon_root_of_unity_table[i + n].value_};
                NInt hi{(*element)[2 * i + 1].value_};
                NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
                NInt lo{(*element)[2 * i + 0].value_};
                lo = cond_sub_no_cmp(lo, c0);
                lo = cond_sub_no_cmp(lo, c1);
                lo = cond_sub_no_cmp(lo, c2);
                lo = cond_sub_no_cmp(lo, c3);
                lo = cond_sub_no_cmp(lo, mv2);
                NInt s{static_cast<NInt>(lo + of)};
                s = cond_sub_no_cmp(s, mv2);
                s = cond_sub_no_cmp(s, mv);
                NInt d{static_cast<NInt>(lo - of + mv2)};
                d = cond_sub_no_cmp(d, mv2);
                d = cond_sub_no_cmp(d, mv);
                (*element)[2 * i + 0].value_ = s;
                (*element)[2 * i + 1].value_ = d;
            }
            return;
        }
        for (size_t i{0}; i < n; ++i) {
            const NInt omega{root_of_unity_table[i + n].value_};
            const NInt precon_omega{precon_root_of_unity_table[i + n].value_};
            NInt hi{(*element)[2 * i + 1].value_};
            NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
            NInt lo{(*element)[2 * i + 0].value_};
            lo = cond_sub_no_cmp(lo, mv2);
            NInt s{static_cast<NInt>(lo + of)};
            s = cond_sub_no_cmp(s, mv2);
            s = cond_sub_no_cmp(s, mv);
            NInt d{static_cast<NInt>(lo - of + mv2)};
            d = cond_sub_no_cmp(d, mv2);
            d = cond_sub_no_cmp(d, mv);
            (*element)[2 * i + 0].value_ = s;
            (*element)[2 * i + 1].value_ = d;
        }
    } else {
        // wide words without wide lanes: nothing vectorizes here and the classic i += 2 form
        // is the faster scalar
        if (lazy) {
            for (size_t i{0}; i < (static_cast<size_t>(n) << 1); i += 2) {
                const NInt omega{root_of_unity_table[(i >> 1) + n].value_};
                const NInt precon_omega{precon_root_of_unity_table[(i >> 1) + n].value_};
                NInt hi{(*element)[i + 1].value_};
                NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
                NInt lo{(*element)[i + 0].value_};
                lo = cond_sub_no_cmp(lo, c0);
                lo = cond_sub_no_cmp(lo, c1);
                lo = cond_sub_no_cmp(lo, c2);
                lo = cond_sub_no_cmp(lo, c3);
                lo = cond_sub_no_cmp(lo, mv2);
                NInt s{static_cast<NInt>(lo + of)};
                s = cond_sub_no_cmp(s, mv2);
                s = cond_sub_no_cmp(s, mv);
                NInt d{static_cast<NInt>(lo - of + mv2)};
                d = cond_sub_no_cmp(d, mv2);
                d = cond_sub_no_cmp(d, mv);
                (*element)[i + 0].value_ = s;
                (*element)[i + 1].value_ = d;
            }
            return;
        }
        for (size_t i{0}; i < (static_cast<size_t>(n) << 1); i += 2) {
            const NInt omega{root_of_unity_table[(i >> 1) + n].value_};
            const NInt precon_omega{precon_root_of_unity_table[(i >> 1) + n].value_};
            NInt hi{(*element)[i + 1].value_};
            NInt of{static_cast<NInt>(hi * omega - shoup_mul_hi(hi, precon_omega) * mv)};
            NInt lo{(*element)[i + 0].value_};
            lo = cond_sub_no_cmp(lo, mv2);
            NInt s{static_cast<NInt>(lo + of)};
            s = cond_sub_no_cmp(s, mv2);
            s = cond_sub_no_cmp(s, mv);
            NInt d{static_cast<NInt>(lo - of + mv2)};
            d = cond_sub_no_cmp(d, mv2);
            d = cond_sub_no_cmp(d, mv);
            (*element)[i + 0].value_ = s;
            (*element)[i + 1].value_ = d;
        }
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                            const VecType& root_of_unity_table,
                                                                            const VecType& precon_root_of_unity_table,
                                                                            VecType* result) {
    if (result->get_length() != element.get_length())
        CIPHER_THROW("size of input element and size of output element not of same size");
    *result = element;
    forward_transform_to_bit_reverse_in_place(root_of_unity_table, precon_root_of_unity_table, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_from_bit_reverse_in_place(const VecType& root_inv_table,
                                                                                       const IntType& co_inv,
                                                                                       VecType* element) {
    // compute the Shoup constants once and share the vectorized precon kernel
    const auto modulus = element->get_modulus();
    const auto precon = prep_shoup_consts(root_inv_table, modulus);
    inverse_transform_from_bit_reverse_in_place(root_inv_table, precon, co_inv, co_inv.prep_mod_mul_const(modulus),
                                                element);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_from_bit_reverse(
        const VecType& element, const VecType& root_of_unity_inverse_table, const IntType& cyclo_order_inv,
        VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n)
        CIPHER_THROW("size of input element and size of output element not of same size");
    *result = element;
    inverse_transform_from_bit_reverse_in_place(root_of_unity_inverse_table, cyclo_order_inv, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_from_bit_reverse_in_place(
        const VecType& root_of_unity_inverse_table, const VecType& precon_root_of_unity_inverse_table,
        const IntType& cyclo_order_inv, const IntType& precon_cyclo_order_inv, VecType* element) {
    //
    // INTT based on the Gentleman-Sande (GS) butterfly
    // Inputs: element (vector of size n in bit-reversed ordering)
    //         root_of_unity_inverse_table (precomputed roots of unity in bit-reversed ordering)
    //         cyclo_order_inv (n inverse)
    // Output: INTT(element) in standard ordering
    //
    // for (m = n/2, t = 1, logt = 1; m >= 1; m=m/2, t=2*t, ++logt) do
    //     for (i = 0; i < m; ++i) do
    //         omega = root_of_unity_inverse_table[i + m]
    //         for (j1 = (i << logt), j2 = (j1 + t); j1 < j2; ++j1) do
    //             lo_val = element[j1 + 0]
    //             hi_val = element[j1 + t]
    //             element[j1 + 0] = (lo_val + hi_val) mod modulus
    //             element[j1 + t] = (lo_val - hi_val)*omega mod modulus
    // for (i = 0; i < n; ++i) do
    //     element[i] = element[i]*cyclo_order_inv mod modulus
    //

    // Harvey lazy-reduction GS butterflies: values stay in [0, 2*modulus) between stages;
    // the full reduction to [0, modulus) is folded into the peeled final stage and the
    // trailing n/2 scalar multiplies by (n inverse). Loops work on the raw word values so
    // they stay vectorizable.
    using NInt = typename IntType::Integer;
    const auto modulus{element->get_modulus()};
    const NInt mv{modulus.value_};
    const NInt mv2{static_cast<NInt>(mv + mv)};
    const uint32_t n(element->get_length());

    // precomputed omega[bitreversed(1)] * (n inverse). used in final stage of intt.
    // Please see https://github.com/openfheorg/openfhe-development/issues/872 for details.
    const auto omega1_inv{
            root_of_unity_inverse_table[1].mod_mul_fast_const(cyclo_order_inv, modulus, precon_cyclo_order_inv)};
    const NInt o1{omega1_inv.value_};
    const NInt precon_o1{omega1_inv.prep_mod_mul_const(modulus).value_};

    if (n > 2) {
        // peeled off first stage for performance; the index-doubled pair form (2i, 2i + 1)
        // is the stride-2 shape gcc's vectorizer accepts, i += 2 is not
        const uint32_t nh{n >> 1};
        for (size_t i{0}; i < nh; ++i) {
            const NInt omega{root_of_unity_inverse_table[i + nh].value_};
            const NInt precon_omega{precon_root_of_unity_inverse_table[i + nh].value_};
            NInt lo{(*element)[2 * i + 0].value_};
            NInt hi{(*element)[2 * i + 1].value_};
            NInt s{static_cast<NInt>(lo + hi)};
            s = cond_sub_no_cmp(s, mv2);
            NInt d{static_cast<NInt>(lo - hi + mv2)};
            (*element)[2 * i + 0].value_ = s;
            (*element)[2 * i + 1].value_ = d * omega - shoup_mul_hi(d, precon_omega) * mv;
        }
    }
    // inner stages
    for (size_t m{n >> 2}, t{2}, logt{2}; m > 1; m >>= 1, t <<= 1, ++logt) {
        for (size_t i{0}; i < m; ++i) {
            const NInt omega{root_of_unity_inverse_table[i + m].value_};
            const NInt precon_omega{precon_root_of_unity_inverse_table[i + m].value_};
            // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer (u32 indexing could wrap)
            for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                NInt lo{(*element)[j1 + 0].value_};
                NInt hi{(*element)[j1 + t].value_};
                NInt s{static_cast<NInt>(lo + hi)};
                s = cond_sub_no_cmp(s, mv2);
                NInt d{static_cast<NInt>(lo - hi + mv2)};
                (*element)[j1 + 0].value_ = s;
                (*element)[j1 + t].value_ = d * omega - shoup_mul_hi(d, precon_omega) * mv;
            }
        }
    }

    // peeled off final stage where n/2 of the scalar multiplies by (n inverse) are
    // incorporated into the omega_factor calculation; outputs reduced to [0, modulus)
    const size_t j2{n >> 1};
    for (size_t j1{0}; j1 < j2; ++j1) {
        NInt lo{(*element)[j1 + 0].value_};
        NInt hi{(*element)[j1 + j2].value_};
        NInt s{static_cast<NInt>(lo + hi)};
        s = cond_sub_no_cmp(s, mv2);
        NInt d{static_cast<NInt>(lo - hi + mv2)};
        NInt y{static_cast<NInt>(d * o1 - shoup_mul_hi(d, precon_o1) * mv)};
        y = cond_sub_no_cmp(y, mv);
        (*element)[j1 + 0].value_ = s;
        (*element)[j1 + j2].value_ = y;
    }
    // perform remaining n/2 scalar multiplies by (n inverse), reducing to [0, modulus)
    const NInt n_inv{cyclo_order_inv.value_};
    const NInt precon_n_inv{precon_cyclo_order_inv.value_};
    for (size_t i{0}; i < j2; ++i) {
        NInt v{(*element)[i].value_};
        NInt r{static_cast<NInt>(v * n_inv - shoup_mul_hi(v, precon_n_inv) * mv)};
        r = cond_sub_no_cmp(r, mv);
        (*element)[i].value_ = r;
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::inverse_transform_from_bit_reverse(
        const VecType& element, const VecType& root_of_unity_inverse_table,
        const VecType& precon_root_of_unity_inverse_table, const IntType& cyclo_order_inv,
        const IntType& precon_cyclo_order_inv, VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n)
        CIPHER_THROW("size of input element and size of output element not of same size");

    result->set_modulus(element.get_modulus());

    for (size_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }
    inverse_transform_from_bit_reverse_in_place(root_of_unity_inverse_table, precon_root_of_unity_inverse_table,
                                                cyclo_order_inv, precon_cyclo_order_inv, result);

    return;
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::forward_transform_to_bit_reverse_in_place(
        const IntType& root_of_unity_value, const uint32_t cyclo_order, VecType* element) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0))
        return;
    auto tables = get_tables(root_of_unity_value, cyclo_order, element->get_modulus());
    NumberTheoreticTransformNat<VecType>().forward_transform_to_bit_reverse_in_place(
            tables->root_reverse, tables->precon_root_reverse, element);
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                                const IntType& root_of_unity_value,
                                                                                const uint32_t cyclo_order,
                                                                                VecType* result) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        *result = element;
        return;
    }
    auto tables = get_tables(root_of_unity_value, cyclo_order, element.get_modulus());
    NumberTheoreticTransformNat<VecType>().forward_transform_to_bit_reverse(element, tables->root_reverse,
                                                                            tables->precon_root_reverse, result);
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::inverse_transform_from_bit_reverse_in_place(
        const IntType& root_of_unity_value, const uint32_t cyclo_order, VecType* element) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0))
        return;
    auto tables = get_tables(root_of_unity_value, cyclo_order, element->get_modulus());
    uint32_t msb = get_msb((cyclo_order >> 1) - 1);
    NumberTheoreticTransformNat<VecType>().inverse_transform_from_bit_reverse_in_place(
            tables->root_inverse_reverse, tables->precon_root_inverse_reverse, tables->cyclo_order_inverse[msb],
            tables->precon_cyclo_order_inverse[msb], element);
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::inverse_transform_from_bit_reverse(const VecType& element,
                                                                                  const IntType& root_of_unity_value,
                                                                                  const uint32_t cyclo_order,
                                                                                  VecType* result) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        *result = element;
        return;
    }
    auto tables = get_tables(root_of_unity_value, cyclo_order, element.get_modulus());
    result->set_modulus(element.get_modulus());
    uint32_t n = element.get_length();
    for (size_t i = 0; i < n; ++i)
        (*result)[i] = element[i];
    uint32_t msb = get_msb(n - 1);
    NumberTheoreticTransformNat<VecType>().inverse_transform_from_bit_reverse_in_place(
            tables->root_inverse_reverse, tables->precon_root_inverse_reverse, tables->cyclo_order_inverse[msb],
            tables->precon_cyclo_order_inverse[msb], result);
}

template <typename VecType>
std::shared_ptr<const typename ChineseRemainderTransformFttNat<VecType>::Tables>
ChineseRemainderTransformFttNat<VecType>::get_tables(const IntType& root_of_unity_value, const uint32_t cyclo_order,
                                                     const IntType& modulus) {
    const uint32_t ring_dim = (cyclo_order >> 1);
    {
        std::shared_lock<std::shared_mutex> rlk(tables_mutex());
        auto it = tables_by_modulus_.find(modulus);
        if (it != tables_by_modulus_.end() && it->second->root_reverse.get_length() == ring_dim)
            return it->second;
    }
    std::unique_lock<std::shared_mutex> wlk(tables_mutex());
    auto it = tables_by_modulus_.find(modulus);
    if (it != tables_by_modulus_.end() && it->second->root_reverse.get_length() == ring_dim)
        return it->second;

    auto t = std::make_shared<Tables>();
    IntType x(1), xinv(1);
    uint32_t msb = get_msb(ring_dim - 1);
    IntType mu = modulus.compute_mu();
    IntType root_of_unity_inverse = root_of_unity_value.mod_inverse(modulus);
    const IntType& n_modulus{modulus};
    VecType table_value(ring_dim, modulus);
    VecType table_i(ring_dim, modulus);
    VecType precon_table(ring_dim, n_modulus);
    VecType precon_table_i(ring_dim, n_modulus);
    for (size_t i = 0; i < ring_dim; ++i) {
        auto iinv = reverse_bits(i, msb);
        table_value[iinv] = x;
        precon_table[iinv] = x.prep_mod_mul_const(n_modulus);
        x.mod_mul_eq(root_of_unity_value, modulus, mu);
        table_i[iinv] = xinv;
        precon_table_i[iinv] = xinv.prep_mod_mul_const(n_modulus);
        xinv.mod_mul_eq(root_of_unity_inverse, modulus, mu);
    }
    t->root_reverse = std::move(table_value);
    t->root_inverse_reverse = std::move(table_i);
    t->precon_root_reverse = std::move(precon_table);
    t->precon_root_inverse_reverse = std::move(precon_table_i);

    IntType co_inv(1);
    VecType table_coi(msb + 1, modulus);
    VecType precon_table_coi(msb + 1, n_modulus);
    for (size_t i = 0; i <= msb; ++i) {
        table_coi[i] = co_inv.mod_inverse(modulus);
        precon_table_coi[i] = table_coi[i].prep_mod_mul_const(n_modulus);
        co_inv <<= 1;
    }
    t->cyclo_order_inverse = std::move(table_coi);
    t->precon_cyclo_order_inverse = std::move(precon_table_coi);

    std::shared_ptr<const Tables> ct(std::move(t));
    tables_by_modulus_[modulus] = ct;
    return ct;
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::pre_compute(const IntType& root_of_unity_value,
                                                           const uint32_t cyclo_order, const IntType& modulus) {
    get_tables(root_of_unity_value, cyclo_order, modulus);
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::pre_compute(std::vector<IntType>& root_of_unity_value,
                                                           const uint32_t cyclo_order,
                                                           std::vector<IntType>& modulii_chain) {
    uint32_t num_of_root_u = root_of_unity_value.size();
    uint32_t num_modulii = modulii_chain.size();
    if (num_of_root_u != num_modulii)
        CIPHER_THROW("size of root of unity and size of moduli chain not of same size");
    for (size_t i = 0; i < num_of_root_u; ++i)
        pre_compute(root_of_unity_value[i], cyclo_order, modulii_chain[i]);
}

template <typename VecType>
void ChineseRemainderTransformFttNat<VecType>::reset() {
    std::unique_lock<std::shared_mutex> lk(tables_mutex());
    tables_by_modulus_.clear();
}

template <typename VecType>
void BluesteinFftNat<VecType>::pre_compute_default_ntt_modulus_root(uint32_t cyclo_order, const IntType& modulus) {
    std::lock_guard<std::recursive_mutex> lk(cache_mutex());
    uint32_t ntt_dim = 1u << get_msb(2 * cyclo_order - 2);
    const auto ntt_modulus = last_prime<IntType>(std::log2(ntt_dim) + 2 * modulus.get_msb(), ntt_dim);
    const auto ntt_root = root_of_unity<IntType>(ntt_dim, ntt_modulus);
    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    default_ntt_modulus_root_[modulus] = ntt_modulus_root;

    pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
}

template <typename VecType>
void BluesteinFftNat<VecType>::pre_compute_root_table_for_ntt(uint32_t cycloto_order,
                                                              const ModulusRoot<IntType>& ntt_modulus_root) {
    std::lock_guard<std::recursive_mutex> lk(cache_mutex());
    uint32_t ntt_dim = 1u << get_msb(2 * cycloto_order - 2);
    const auto& ntt_modulus = ntt_modulus_root.first;
    const auto& ntt_root = ntt_modulus_root.second;

    IntType root(ntt_root);
    auto root_inv = root.mod_inverse(ntt_modulus);

    uint32_t ntt_dim_hf = (ntt_dim >> 1);
    VecType root_table(ntt_dim_hf, ntt_modulus);
    VecType root_table_inverse(ntt_dim_hf, ntt_modulus);
    VecType precon_table(ntt_dim_hf, ntt_modulus);
    VecType precon_table_inverse(ntt_dim_hf, ntt_modulus);

    IntType x(1), y(1);
    for (size_t i = 0; i < ntt_dim_hf; ++i) {
        root_table[i] = x;
        precon_table[i] = x.prep_mod_mul_const(ntt_modulus);
        x.mod_mul_eq(root, ntt_modulus);
        root_table_inverse[i] = y;
        precon_table_inverse[i] = y.prep_mod_mul_const(ntt_modulus);
        y.mod_mul_eq(root_inv, ntt_modulus);
    }

    root_of_unity_table_by_modulus_root_[ntt_modulus_root] = std::move(root_table);
    root_of_unity_inverse_table_by_modulus_root_[ntt_modulus_root] = std::move(root_table_inverse);
    precon_root_of_unity_table_by_modulus_root_[ntt_modulus_root] = std::move(precon_table);
    precon_root_of_unity_inverse_table_by_modulus_root_[ntt_modulus_root] = std::move(precon_table_inverse);
}

template <typename VecType>
void BluesteinFftNat<VecType>::pre_compute_powers(uint32_t cyclo_order, const ModulusRoot<IntType>& modulus_root) {
    std::lock_guard<std::recursive_mutex> lk(cache_mutex());
    const auto& modulus = modulus_root.first;
    const auto& root = modulus_root.second;

    VecType powers(cyclo_order, modulus);
    powers[0] = 1;
    for (size_t i = 1; i < cyclo_order; i++) {
        auto i_sqr = (i * i) % (2 * cyclo_order);
        auto val = root.mod_exp(IntType(i_sqr), modulus);
        powers[i] = val;
    }
    powers_table_by_modulus_root_[modulus_root] = std::move(powers);
}

template <typename VecType>
void BluesteinFftNat<VecType>::pre_compute_rb_table(uint32_t cyclo_order,
                                                    const ModulusRootPair<IntType>& modulus_root_pair) {
    std::lock_guard<std::recursive_mutex> lk(cache_mutex());
    const auto& modulus_root = modulus_root_pair.first;
    const auto& modulus = modulus_root.first;
    const auto& root = modulus_root.second;
    const auto root_inv = root.mod_inverse(modulus);

    const auto& ntt_modulus_root = modulus_root_pair.second;
    const auto& ntt_modulus = ntt_modulus_root.first;
    const auto& root_table = root_of_unity_table_by_modulus_root_[ntt_modulus_root];
    const auto& precon_table = precon_root_of_unity_table_by_modulus_root_[ntt_modulus_root];
    uint32_t ntt_dim = 1u << get_msb(2 * cyclo_order - 2);

    VecType b(2 * cyclo_order - 1, modulus);
    b[cyclo_order - 1] = 1;
    for (size_t i = 1; i < cyclo_order; i++) {
        auto i_sqr = (i * i) % (2 * cyclo_order);
        auto val = root_inv.mod_exp(IntType(i_sqr), modulus);
        b[cyclo_order - 1 + i] = val;
        b[cyclo_order - 1 - i] = val;
    }

    auto rb = pad_zeros(b, ntt_dim);
    rb.set_modulus(ntt_modulus);

    VecType RB(ntt_dim);
    NumberTheoreticTransformNat<VecType>().forward_transform_iterative(rb, root_table, precon_table, &RB);
    rb_table_by_modulus_root_pair_[modulus_root_pair] = std::move(RB);
}

template <typename VecType>
VecType BluesteinFftNat<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                    const uint32_t cyclo_order) {
    const auto& modulus = element.get_modulus();
    std::unique_lock<std::recursive_mutex> lk(cache_mutex());
    const auto ntt_modulus_root = default_ntt_modulus_root_[modulus];
    lk.unlock();
    return forward_transform(element, root, cyclo_order, ntt_modulus_root);
}

template <typename VecType>
VecType BluesteinFftNat<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                    const uint32_t cyclo_order,
                                                    const ModulusRoot<IntType>& ntt_modulus_root) {
    if (element.get_length() != cyclo_order)
        CIPHER_THROW("expected size of element vector should be equal to cyclotomic order");

    const auto& modulus = element.get_modulus();
    const ModulusRoot<IntType> modulus_root = {modulus, root};
    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root, ntt_modulus_root};

    // all tables are precomputed by the callers; take stable references under the cache
    // lock (map nodes never move), then compute without it
    std::unique_lock<std::recursive_mutex> lk(cache_mutex());
    const VecType& powers = powers_table_by_modulus_root_.at(modulus_root);
    const VecType& root_table = root_of_unity_table_by_modulus_root_.at(ntt_modulus_root);
    const VecType& precon_table = precon_root_of_unity_table_by_modulus_root_.at(ntt_modulus_root);
    const VecType& root_table_inverse = root_of_unity_inverse_table_by_modulus_root_.at(ntt_modulus_root);
    const VecType& precon_table_inverse = precon_root_of_unity_inverse_table_by_modulus_root_.at(ntt_modulus_root);
    const VecType& RB = rb_table_by_modulus_root_pair_.at(modulus_root_pair);
    lk.unlock();

    const auto& ntt_modulus = ntt_modulus_root.first;
    VecType x = element.mod_mul(powers);

    uint32_t ntt_dim = 1u << get_msb(2 * cyclo_order - 2);
    auto ra = pad_zeros(x, ntt_dim);
    ra.set_modulus(ntt_modulus);
    VecType RA(ntt_dim);
    NumberTheoreticTransformNat<VecType>().forward_transform_iterative(ra, root_table, precon_table, &RA);

    auto RC = RA.mod_mul(RB);
    VecType rc(ntt_dim);
    NumberTheoreticTransformNat<VecType>().inverse_transform_iterative(RC, root_table_inverse, precon_table_inverse,
                                                                       &rc);
    auto resize_rc = resize_range(rc, cyclo_order - 1, 2 * (cyclo_order - 1));
    resize_rc.set_modulus(modulus);
    resize_rc.mod_reduce_eq();
    auto result = resize_rc.mod_mul(powers);

    return result;
}

template <typename VecType>
VecType BluesteinFftNat<VecType>::pad_zeros(const VecType& a, const uint32_t final_size) {
    uint32_t s = a.get_length();
    VecType result(final_size, a.get_modulus());
    for (size_t i = 0; i < s; i++)
        result[i] = a[i];
    for (size_t i = a.get_length(); i < final_size; i++)
        result[i] = IntType(0);
    return result;
}

template <typename VecType>
VecType BluesteinFftNat<VecType>::resize_range(const VecType& a, uint32_t lo, uint32_t hi) {
    VecType result(hi - lo + 1, a.get_modulus());
    for (size_t i = lo, j = 0; i <= hi; i++, j++)
        result[j] = a[i];
    return result;
}

template <typename VecType>
void BluesteinFftNat<VecType>::reset() {
    std::lock_guard<std::recursive_mutex> lk(cache_mutex());
    root_of_unity_table_by_modulus_root_.clear();
    root_of_unity_inverse_table_by_modulus_root_.clear();
    precon_root_of_unity_table_by_modulus_root_.clear();
    precon_root_of_unity_inverse_table_by_modulus_root_.clear();
    powers_table_by_modulus_root_.clear();
    rb_table_by_modulus_root_pair_.clear();
    default_ntt_modulus_root_.clear();
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::set_cylotomic_polynomial(const VecType& poly, const IntType& mod_value) {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
    cyclotomic_poly_map_[mod_value] = poly;
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::pre_compute(const uint32_t cycloto_order, const IntType& modulus) {
    BluesteinFftNat<VecType>().pre_compute_default_ntt_modulus_root(cycloto_order, modulus);
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::set_pre_computed_ntt_modulus(uint32_t cycloto_order,
                                                                            const IntType& modulus,
                                                                            const IntType& ntt_modulus,
                                                                            const IntType& ntt_root) {
    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
    BluesteinFftNat<VecType>().pre_compute_root_table_for_ntt(cycloto_order, ntt_modulus_root);
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::set_pre_computed_ntt_division_modulus(uint32_t cycloto_order,
                                                                                     const IntType& modulus,
                                                                                     const IntType& ntt_mod,
                                                                                     const IntType& ntt_root_big) {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
    CIPHER_DEBUG_FLAG(false);

    uint32_t n = get_totient(cycloto_order);
    CIPHER_DEBUG("get_totient(" << cycloto_order << ")= " << n);

    uint32_t power = cycloto_order - n;
    ntt_division_dim_[cycloto_order] = 2u << get_msb(power - 1);

    uint32_t ntt_dim_big = 1u << get_msb(2 * cycloto_order - 2);

    // Computes the root of unity for the division NTT based on the root of unity
    // for regular NTT
    IntType ntt_root = ntt_root_big.mod_exp(IntType(ntt_dim_big / ntt_division_dim_[cycloto_order]), ntt_mod);

    division_ntt_modulus_[modulus] = ntt_mod;
    division_ntt_root_of_unity_[modulus] = ntt_root;
    // part0 setting of root_table and inverse root_table
    uint32_t ntt_dim = ntt_division_dim_[cycloto_order];
    IntType root(ntt_root);
    auto root_inv = root.mod_inverse(ntt_mod);

    uint32_t ntt_dim_hf = (ntt_dim >> 1);
    VecType root_table(ntt_dim_hf, ntt_mod);
    VecType root_table_inverse(ntt_dim_hf, ntt_mod);
    VecType precon_table(ntt_dim_hf, ntt_mod);
    VecType precon_table_inverse(ntt_dim_hf, ntt_mod);

    IntType x(1);
    for (size_t i = 0; i < ntt_dim_hf; i++) {
        root_table[i] = x;
        precon_table[i] = x.prep_mod_mul_const(ntt_mod);
        x = x.mod_mul(root, ntt_mod);
    }

    x = 1;
    for (size_t i = 0; i < ntt_dim_hf; i++) {
        root_table_inverse[i] = x;
        precon_table_inverse[i] = x.prep_mod_mul_const(ntt_mod);
        x = x.mod_mul(root_inv, ntt_mod);
    }

    root_of_unity_division_table_by_modulus_[ntt_mod] = std::move(root_table);
    root_of_unity_division_inverse_table_by_modulus_[ntt_mod] = std::move(root_table_inverse);
    root_of_unity_division_precon_table_by_modulus_[ntt_mod] = std::move(precon_table);
    root_of_unity_division_inverse_precon_table_by_modulus_[ntt_mod] = std::move(precon_table_inverse);

    // end of part0
    // part1
    const auto& rev_cpm = inverse_poly_mod(cyclotomic_poly_map_[modulus], modulus, power);
    auto rev_cpm_padded = BluesteinFftNat<VecType>().pad_zeros(rev_cpm, ntt_dim);
    rev_cpm_padded.set_modulus(ntt_mod);
    // end of part1

    const auto& div_table = root_of_unity_division_table_by_modulus_[ntt_mod];
    const auto& div_precon = root_of_unity_division_precon_table_by_modulus_[ntt_mod];
    VecType RA(ntt_dim);
    NumberTheoreticTransformNat<VecType>().forward_transform_iterative(rev_cpm_padded, div_table, div_precon, &RA);
    cyclotomic_poly_reverse_ntt_map_[modulus] = std::move(RA);

    const auto& cyclo_poly = cyclotomic_poly_map_[modulus];

    VecType q_forward_transform(ntt_dim, ntt_mod);
    for (size_t i = 0; i < cyclo_poly.get_length(); i++)
        q_forward_transform[i] = cyclo_poly[i];

    VecType q_fwd_result(ntt_dim);
    NumberTheoreticTransformNat<VecType>().forward_transform_iterative(q_forward_transform, div_table, div_precon,
                                                                       &q_fwd_result);

    cyclotomic_poly_ntt_map_[modulus] = std::move(q_fwd_result);
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::inverse_poly_mod(const VecType& cyclo_poly, const IntType& modulus,
                                                                   uint32_t power) {
    VecType result(power, modulus);
    uint32_t r = (power > 1) ? get_msb(power - 1) : 0;
    VecType h(1, modulus);  // h is a unit polynomial
    h[0] = 1;

    // Precompute the Barrett mu parameter
    IntType mu = modulus.compute_mu();

    for (size_t i = 0; i < r; i++) {
        uint32_t q_degree = 1u << (i + 1);
        VecType q(q_degree + 1, modulus);  // q = x^(2^i+1)
        q[q_degree] = 1;
        auto h_square = polynomial_multiplication(h, h);

        auto a = h * IntType(2);
        auto b = polynomial_multiplication(h_square, cyclo_poly);
        // b = 2h - gh^2
        for (size_t j = 0; j < b.get_length(); j++) {
            if (j < a.get_length()) {
                b[j] = a[j].mod_sub(b[j], modulus, mu);
            } else {
                b[j] = modulus.mod_sub(b[j], modulus, mu);
            }
        }
        h = poly_mod(b, q, modulus);
    }
    // take modulo x^power
    for (size_t i = 0; i < power; i++) {
        result[i] = h[i];
    }

    return result;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                                    const IntType& ntt_modulus, const IntType& ntt_root,
                                                                    const uint32_t cyclo_order) {
    uint32_t phim = get_totient(cyclo_order);
    if (element.get_length() != phim)
        CIPHER_THROW("element size should be equal to phim");

    const auto& modulus = element.get_modulus();
    const ModulusRoot<IntType> modulus_root = {modulus, root};

    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root, ntt_modulus_root};

    {
        std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
        if (BluesteinFftNat<VecType>::root_of_unity_table_by_modulus_root_[ntt_modulus_root].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
        }

        if (BluesteinFftNat<VecType>::powers_table_by_modulus_root_[modulus_root].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_powers(cyclo_order, modulus_root);
        }

        if (BluesteinFftNat<VecType>::rb_table_by_modulus_root_pair_[modulus_root_pair].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_rb_table(cyclo_order, modulus_root_pair);
        }
    }

    VecType input_to_bluestein = pad(element, cyclo_order, true);
    auto output_bluestein =
            BluesteinFftNat<VecType>().forward_transform(input_to_bluestein, root, cyclo_order, ntt_modulus_root);
    VecType output = drop(output_bluestein, cyclo_order, true, ntt_modulus, ntt_root);

    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::inverse_transform(const VecType& element, const IntType& root,
                                                                    const IntType& ntt_modulus, const IntType& ntt_root,
                                                                    const uint32_t cyclo_order) {
    uint32_t phim = get_totient(cyclo_order);
    if (element.get_length() != phim)
        CIPHER_THROW("element size should be equal to phim");

    const auto& modulus = element.get_modulus();
    auto root_inverse(root.mod_inverse(modulus));
    const ModulusRoot<IntType> modulus_root_inverse = {modulus, root_inverse};

    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root_inverse, ntt_modulus_root};

    {
        std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
        if (BluesteinFftNat<VecType>::root_of_unity_table_by_modulus_root_[ntt_modulus_root].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
        }

        if (BluesteinFftNat<VecType>::powers_table_by_modulus_root_[modulus_root_inverse].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_powers(cyclo_order, modulus_root_inverse);
        }

        if (BluesteinFftNat<VecType>::rb_table_by_modulus_root_pair_[modulus_root_pair].get_length() == 0) {
            BluesteinFftNat<VecType>().pre_compute_rb_table(cyclo_order, modulus_root_pair);
        }
    }
    VecType input_to_bluestein = pad(element, cyclo_order, false);
    auto output_bluestein = BluesteinFftNat<VecType>().forward_transform(input_to_bluestein, root_inverse, cyclo_order,
                                                                         ntt_modulus_root);
    auto cyclotomic_inverse((IntType(cyclo_order)).mod_inverse(modulus));
    output_bluestein = output_bluestein * cyclotomic_inverse;
    VecType output = drop(output_bluestein, cyclo_order, false, ntt_modulus, ntt_root);
    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::pad(const VecType& element, const uint32_t cyclo_order,
                                                      bool forward) {
    uint32_t n = get_totient(cyclo_order);

    const auto& modulus = element.get_modulus();
    VecType input_to_bluestein(cyclo_order, modulus);

    if (forward) {  // Forward transform padding
        for (size_t i = 0; i < n; i++) {
            input_to_bluestein[i] = element[i];
        }
    } else {  // Inverse transform padding
        auto t_list = get_totient_list(cyclo_order);
        size_t i = 0;
        for (auto& coprime : t_list) {
            input_to_bluestein[coprime] = element[i++];
        }
    }

    return input_to_bluestein;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::drop(const VecType& element, const uint32_t cyclo_order, bool forward,
                                                       const IntType& big_mod, const IntType& big_root) {
    uint32_t n = get_totient(cyclo_order);

    const auto& modulus = element.get_modulus();
    VecType output(n, modulus);

    if (forward) {  // Forward transform drop
        auto t_list = get_totient_list(cyclo_order);
        for (size_t i = 0; i < n; i++) {
            output[i] = element[t_list[i]];
        }
    } else {  // Inverse transform drop
        if ((n + 1) == cyclo_order) {
            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter
            // cyclo_order is prime: Reduce mod Phi_{n+1}(x)
            // Reduction involves subtracting the coeff of x^n from all terms
            auto coeff_n = element[n];
            for (size_t i = 0; i < n; i++) {
                output[i] = element[i].mod_sub(coeff_n, modulus, mu);
            }
        } else if ((n + 1) * 2 == cyclo_order) {
            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter
            // cyclo_order is 2*prime: 2 Step reduction
            // First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
            // Subtract co-efficient of x^(i+n+1) from x^(i)
            for (size_t i = 0; i < n; i++) {
                auto coeff_i = element[i];
                auto coeff_ip = element[i + n + 1];
                output[i] = coeff_i.mod_sub(coeff_ip, modulus, mu);
            }
            auto coeff_n = element[n].mod_sub(element[2 * n + 1], modulus, mu);
            // Now reduce mod Phi_{2*(n+1)}(x)
            // Similar to the prime case but with alternating signs
            for (size_t i = 0; i < n; i++) {
                if (i % 2 == 0) {
                    output[i].mod_sub_eq(coeff_n, modulus, mu);
                } else {
                    output[i].mod_add_eq(coeff_n, modulus, mu);
                }
            }
        } else {
            // precompute root of unity tables for division NTT
            std::unique_lock<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
            if ((root_of_unity_division_table_by_modulus_[big_mod].get_length() == 0) ||
                (division_ntt_modulus_[modulus] != big_mod)) {
                set_pre_computed_ntt_division_modulus(cyclo_order, modulus, big_mod, big_root);
            }

            // cyclo_order is arbitrary
            const auto ntt_mod = division_ntt_modulus_[modulus];
            const VecType& root_table = root_of_unity_division_table_by_modulus_.at(ntt_mod);
            const VecType& precon_table = root_of_unity_division_precon_table_by_modulus_.at(ntt_mod);
            const VecType& root_table_inverse = root_of_unity_division_inverse_table_by_modulus_.at(ntt_mod);
            const VecType& precon_table_inverse = root_of_unity_division_inverse_precon_table_by_modulus_.at(ntt_mod);
            const VecType& cyclo_reverse_ntt = cyclotomic_poly_reverse_ntt_map_.at(modulus);
            const VecType& cyclo_ntt = cyclotomic_poly_ntt_map_.at(modulus);
            const uint32_t ntt_div_dim = ntt_division_dim_.at(cyclo_order);
            lk.unlock();

            VecType a_padded2(ntt_div_dim, ntt_mod);
            // perform mod operation
            uint32_t power = cyclo_order - n;
            for (size_t i = n; i < element.get_length(); i++) {
                a_padded2[power - (i - n) - 1] = element[i];
            }
            VecType A(ntt_div_dim);
            NumberTheoreticTransformNat<VecType>().forward_transform_iterative(a_padded2, root_table, precon_table, &A);
            auto AB = A * cyclo_reverse_ntt;
            VecType a(ntt_div_dim);
            NumberTheoreticTransformNat<VecType>().inverse_transform_iterative(AB, root_table_inverse,
                                                                               precon_table_inverse, &a);

            VecType quotient(ntt_div_dim, modulus);
            for (size_t i = 0; i < power; i++) {
                quotient[i] = a[i];
            }
            quotient.mod_reduce_eq();
            quotient.set_modulus(ntt_mod);

            VecType new_quotient(ntt_div_dim);
            NumberTheoreticTransformNat<VecType>().forward_transform_iterative(quotient, root_table, precon_table,
                                                                               &new_quotient);
            new_quotient *= cyclo_ntt;

            VecType new_quotient2(ntt_div_dim);
            NumberTheoreticTransformNat<VecType>().inverse_transform_iterative(new_quotient, root_table_inverse,
                                                                               precon_table_inverse, &new_quotient2);
            new_quotient2.set_modulus(modulus);
            new_quotient2.mod_reduce_eq();

            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter

            for (size_t i = 0; i < n; i++) {
                output[i] = element[i].mod_sub(new_quotient2[cyclo_order - 1 - i], modulus, mu);
            }
        }
    }
    return output;
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::reset() {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFftNat<VecType>::cache_mutex());
    cyclotomic_poly_map_.clear();
    cyclotomic_poly_reverse_ntt_map_.clear();
    cyclotomic_poly_ntt_map_.clear();
    root_of_unity_division_table_by_modulus_.clear();
    root_of_unity_division_inverse_table_by_modulus_.clear();
    root_of_unity_division_precon_table_by_modulus_.clear();
    root_of_unity_division_inverse_precon_table_by_modulus_.clear();
    division_ntt_modulus_.clear();
    division_ntt_root_of_unity_.clear();
    ntt_division_dim_.clear();
    BluesteinFftNat<VecType>().reset();
}

}  // namespace native_int

#endif  // CIPHER_MATH_BACKEND_NATIVE_TRANSFORM_IMPL_H_
