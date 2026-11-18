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

#include "cipher/boolean/rgsw_acc_cggi.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/boolean/rgsw_acc_common.h"

namespace cipher {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGswAccKey RingGswAccumulatorCggi::key_gen_acc(const std::shared_ptr<RingGswCryptoParams>& params,
                                                  const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv = LWE_sk->get_element();
    auto neg = sv.get_modulus().convert_to_int() - 1;
    uint32_t n = sv.get_length();
    params->verify_base_g_coverage(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].convert_to_int();
        if (s != 0 && s != 1 && s != neg)
            CIPHER_THROW("GINX/CGGI requires a ternary LWE secret key");
    }

    auto ek = std::make_shared<RingGswAccKeyImpl>(1, 2, n);
    auto& ek00 = (*ek)[0][0];
    auto& ek01 = (*ek)[0][1];

    // handles ternary secrets using signed mod 3 arithmetic
    // 0 -> {0,0}, 1 -> {1,0}, -1 -> {0,1}
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].convert_to_int();
        ek00[i] = key_gen_cggi(params, sk_ntt, s == 1 ? 1 : 0, i);
        ek01[i] = key_gen_cggi(params, sk_ntt, s == neg ? 1 : 0, i);
    }
    return ek;
}

#if CIPHER_NATIVE_INT != 32
RingGswAccKey32 RingGswAccumulatorCggi::key_gen_acc32(const std::shared_ptr<RingGswCryptoParams>& params,
                                                      const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv = LWE_sk->get_element();
    auto neg = sv.get_modulus().convert_to_int() - 1;
    uint32_t n = sv.get_length();
    params->verify_base_g_coverage(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].convert_to_int();
        if (s != 0 && s != 1 && s != neg)
            CIPHER_THROW("GINX/CGGI requires a ternary LWE secret key");
    }

    auto acc = std::make_shared<RingGswAccKey32Impl>(params, 1, 2, n);

    const auto& poly_params32 = params->get_poly_params32();
    const auto sk_ntt32 = narrow_poly32(sk_ntt, poly_params32);
    DiscreteGaussianGeneratorImpl<NativeVector32> dgg32(params->get_dgg_impl().get_std());

    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].convert_to_int();
        GadgetMonomial plus{0, s == 1 ? GadgetTerm::ADD : GadgetTerm::NONE};
        GadgetMonomial minus{0, s == neg ? GadgetTerm::ADD : GadgetTerm::NONE};
        acc->set_eval_key(0, 0, i, rgsw_encrypt(params, poly_params32, sk_ntt32, dgg32, i, plus));
        acc->set_eval_key(0, 1, i, rgsw_encrypt(params, poly_params32, sk_ntt32, dgg32, i, minus));
    }
    return acc;
}
#endif

#if CIPHER_NATIVE_INT != 32
namespace {

void add_to_acc_cggi32(const std::shared_ptr<NativePolyParams32>& poly_params, uint32_t Q, uint64_t mu, uint32_t M,
                       const RingGswCryptoParams::BaseGParams& bp, const RingGswAccKey32Impl::EvalKey32& ek1,
                       const RingGswAccKey32Impl::EvalKey32& ek2, const std::vector<NativePoly32>& monomials,
                       const std::vector<NativeVector32>& monomials_precon, const NativeInteger& a,
                       std::vector<NativePoly32>& acc) {
    thread_local std::vector<NativePoly32> ct_scratch, dct_scratch, tmp_scratch;
    auto& ct = ct_scratch;
    auto& dct = dct_scratch;
    auto& tmp = tmp_scratch;
    ct = acc;

    uint32_t digits_g2{(bp.digits_g - 1) << 1};
    if (dct.size() < digits_g2 || dct[0].get_params() != poly_params) {
        dct.assign(digits_g2, NativePoly32(poly_params, Format::COEFFICIENT, true));
        tmp.assign(4, NativePoly32(poly_params, Format::EVALUATION, true));
    } else {
        for (auto& d : dct)
            d.override_format(Format::COEFFICIENT);
    }

    uint32_t N{static_cast<uint32_t>(poly_params->get_ring_dimension())};
    uint32_t index_pos{a.convert_to_int<uint32_t>()};
    if (index_pos == M)
        index_pos = 0;
    uint32_t index_neg{NativeInteger(0).mod_sub_fast(a, NativeInteger(M)).convert_to_int<uint32_t>()};
    if (index_neg == M)
        index_neg = 0;
    const NativePoly32& monomial = monomials[index_pos];
    const NativePoly32& monomial_neg = monomials[index_neg];
    const NativeVector32& monomial_pre = monomials_precon[index_pos];
    const NativeVector32& monomial_pre_neg = monomials_precon[index_neg];

    int nthreads = cipher_parallel_controls.get_thread_limit(bp.team_width > 4 ? bp.team_width : 4);

    if (nthreads < 2) {
        ct[0].set_format(Format::COEFFICIENT);
        ct[1].set_format(Format::COEFFICIENT);
        excess_h_digit_decompose(Q, bp, ct, dct);
        for (uint32_t i = 0; i < digits_g2; ++i)
            dct[i].set_format(Format::EVALUATION);
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ek1 : ek2;
            uint32_t col{j & 0x1};
            lazy_inner_product32(tmp[j], dct, ev, col, digits_g2, 0, N, N, Q, mu);
            shoup_mul_eq32(tmp[j], (j < 2) ? monomial : monomial_neg, (j < 2) ? monomial_pre : monomial_pre_neg, Q);
            acc[col] += tmp[j];
        }
        return;
    }

    #pragma omp parallel num_threads(nthreads)
    {
    #pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].set_format(Format::COEFFICIENT);

    #pragma omp barrier
    #pragma omp single_value
        excess_h_digit_decompose(Q, bp, ct, dct);

    #pragma omp for schedule(static)
        for (uint32_t i = 0; i < digits_g2; ++i)
            dct[i].set_format(Format::EVALUATION);

    #pragma omp for schedule(static)
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ek1 : ek2;
            uint32_t col{j & 0x1};
            lazy_inner_product32(tmp[j], dct, ev, col, digits_g2, 0, N, N, Q, mu);
            shoup_mul_eq32(tmp[j], (j < 2) ? monomial : monomial_neg, (j < 2) ? monomial_pre : monomial_pre_neg, Q);
        }
    }

    acc[0] += tmp[0];
    acc[1] += tmp[1];
    acc[0] += tmp[2];
    acc[1] += tmp[3];
}

}  // namespace

void RingGswAccumulatorCggi::eval_acc32(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey32& ek,
                                        RlweCiphertext& acc, const NativeVector& a) const {
    const auto& poly_params = params->get_poly_params32();
    const auto& monomials = *params->get_monomials32();
    const auto& monomials_precon = *params->get_monomials_precon32();
    uint32_t Q{static_cast<uint32_t>(params->get_Q().convert_to_int())};
    uint64_t mu{static_cast<uint64_t>(-1) / Q};  // == floor(2^64/Q); Q is odd so it never divides 2^64
    uint32_t M{2 * params->get_N()};

    auto acc32 = narrow_acc32(poly_params, acc->get_elements());

    uint32_t n{static_cast<uint32_t>(a.get_length())};
    auto mod_value{a.get_modulus()};
    auto mby_mod{NativeInteger(M) / mod_value};
    for (uint32_t i = 0; i < n; ++i) {
        add_to_acc_cggi32(poly_params, Q, mu, M, params->get_base_g_params(i), (*ek)[0][0][i], (*ek)[0][1][i],
                          monomials, monomials_precon, NativeInteger(0).mod_sub_fast(a[i], mod_value) * mby_mod, acc32);
    }

    widen_acc32_into(acc32, acc->get_elements());
}
#endif  // CIPHER_NATIVE_INT != 32

void RingGswAccumulatorCggi::eval_acc(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey& ek,
                                      RlweCiphertext& acc, const NativeVector& a) const {
    if (!params->has_monomials())
        CIPHER_THROW("the 64-bit monomials were released; regenerate keys or reload them through the context");
    uint32_t n(a.get_length());
    auto mod_value{a.get_modulus()};
    auto mby_mod{NativeInteger(2 * params->get_N()) / mod_value};
    for (uint32_t i = 0; i < n; ++i) {
        // handles -a*E(1) and handles -a*E(-1) = a*E(1)
        add_to_acc_cggi(params, (*ek)[0][0][i], (*ek)[0][1][i],
                        NativeInteger(0).mod_sub_fast(a[i], mod_value) * mby_mod, acc, i);
    }
}

// Encryption for the CGGI variant, as described in https://eprint.iacr.org/2020/086
RingGswEvalKey RingGswAccumulatorCggi::key_gen_cggi(const std::shared_ptr<RingGswCryptoParams>& params,
                                                    const NativePoly& sk_ntt, LwePlaintext m, uint32_t index) const {
    GadgetMonomial mono{0, m ? GadgetTerm::ADD : GadgetTerm::NONE};
    return std::make_shared<RingGswEvalKeyImpl>(
            rgsw_encrypt(params, params->get_poly_params(), sk_ntt, params->get_dgg_impl(), index, mono));
}

// CGGI Accumulation as described in https://eprint.iacr.org/2020/086
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGswAccumulatorCggi::add_to_acc_cggi(const std::shared_ptr<RingGswCryptoParams>& params,
                                             ConstRingGswEvalKey& ek1, ConstRingGswEvalKey& ek2, NativeInteger a,
                                             RlweCiphertext& acc, uint32_t index) const {
    thread_local std::vector<NativePoly> ct_scratch, dct_scratch, tmp_scratch;
    auto& ct = ct_scratch;
    auto& dct = dct_scratch;
    auto& tmp = tmp_scratch;
    ct = acc->get_elements();

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->get_base_g_params(index);
    uint32_t digits_g2{(bp.digits_g - 1) << 1};
    const auto& poly_params = params->get_poly_params();
    if (dct.size() < digits_g2 || dct[0].get_params() != poly_params) {
        dct.assign(digits_g2, NativePoly(poly_params, Format::COEFFICIENT, true));
    } else {
        for (auto& d : dct)
            d.override_format(Format::COEFFICIENT);
    }
    if (tmp.size() != 4)
        tmp.resize(4);

    // obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    // index is in range [0,m] - so we need to adjust the edge case when index == m to index = 0
    uint32_t m_int{2 * params->get_N()};
    NativeInteger M{m_int};
    uint32_t index_pos{a.convert_to_int<uint32_t>()};
    const NativePoly& monomial = params->get_monomial(index_pos == m_int ? 0 : index_pos);
    uint32_t index_neg{NativeInteger(0).mod_sub_fast(a, M).convert_to_int<uint32_t>()};
    const NativePoly& monomial_neg = params->get_monomial(index_neg == m_int ? 0 : index_neg);

    // acc = acc + dct * ek1 * monomial + dct * ek2 * negative_monomial
    const auto& ev1(ek1->get_elements());
    const auto& ev2(ek2->get_elements());

    int nthreads = cipher_parallel_controls.get_thread_limit(bp.team_width > 4 ? bp.team_width : 4);

    if (nthreads < 2) {
        ct[0].set_format(Format::COEFFICIENT);
        ct[1].set_format(Format::COEFFICIENT);
        signed_digit_decompose_impl(params, ct, dct, bp);
        for (uint32_t i = 0; i < digits_g2; ++i)
            dct[i].set_format(Format::EVALUATION);
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ev1 : ev2;
            uint32_t col{j & 0x1};
            NativePoly& t = tmp[j];
            t = dct[0];
            t *= ev[0][col];
            for (uint32_t i = 1; i < digits_g2; ++i)
                t.mult_acc_eq_no_check(dct[i], ev[i][col]);
            acc->get_elements()[col] += (t *= (j < 2) ? monomial : monomial_neg);
        }
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].set_format(Format::COEFFICIENT);

#pragma omp barrier
#pragma omp single_value
        signed_digit_decompose_impl(params, ct, dct, bp);

#pragma omp for schedule(static)
        for (uint32_t i = 0; i < digits_g2; ++i)
            dct[i].set_format(Format::EVALUATION);

#pragma omp for schedule(static)
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ev1 : ev2;
            uint32_t col{j & 0x1};
            tmp[j] = dct[0];
            tmp[j] *= ev[0][col];
            for (uint32_t i = 1; i < digits_g2; ++i)
                tmp[j].mult_acc_eq_no_check(dct[i], ev[i][col]);
            tmp[j] *= (j < 2) ? monomial : monomial_neg;
        }
    }

    acc->get_elements()[0] += tmp[0];
    acc->get_elements()[1] += tmp[1];
    acc->get_elements()[0] += tmp[2];
    acc->get_elements()[1] += tmp[3];
}

};  // namespace cipher
