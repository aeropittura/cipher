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

#include "cipher/boolean/rgsw_acc_lmkcdey.h"

#include <cstdint>
#include <memory>

#include "cipher/boolean/rgsw_acc_common.h"

namespace cipher {

// Key generation as described in https://eprint.iacr.org/2022/198
RingGswAccKey RingGswAccumulatorLmkcdey::key_gen_acc(const std::shared_ptr<RingGswCryptoParams>& params,
                                                   const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv{LWE_sk->get_element()};
    auto mod_value{sv.get_modulus().convert_to_int<int32_t>()};
    auto mod_half{mod_value >> 1};
    uint32_t N{params->get_N()};
    size_t n{sv.get_length()};
    params->verify_base_g_coverage(static_cast<uint32_t>(n));
    uint32_t num_auto_keys{params->get_num_auto_keys()};

    // dim2, 0: for RGSW(X^si), 1: for automorphism keys
    // only w automorphism keys required
    // allocates (n - w) more memory for pointer (not critical for performance)
    RingGswAccKey ek = std::make_shared<RingGswAccKeyImpl>(1, 2, n);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].convert_to_int<int32_t>()};
        (*ek)[0][0][i] = key_gen_lmkcdey(params, sk_ntt, s > mod_half ? s - mod_value : s, i);
    }

    NativeInteger gen = NativeInteger(5);

    (*ek)[0][1][0] = key_gen_auto(params, sk_ntt, 2 * N - gen.convert_to_int());

    // m_window: window size, consider parameterization in the future
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_auto_keys))
    for (uint32_t i = 1; i <= num_auto_keys; ++i)
        (*ek)[0][1][i] = key_gen_auto(params, sk_ntt, gen.mod_exp(i, 2 * N).convert_to_int<LwePlaintext>());
    return ek;
}

#if CIPHER_NATIVE_INT != 32
RingGswAccKey32 RingGswAccumulatorLmkcdey::key_gen_acc32(const std::shared_ptr<RingGswCryptoParams>& params,
                                                       const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv{LWE_sk->get_element()};
    auto mod_value{sv.get_modulus().convert_to_int<int32_t>()};
    auto mod_half{mod_value >> 1};
    uint32_t N{params->get_N()};
    size_t n{sv.get_length()};
    params->verify_base_g_coverage(static_cast<uint32_t>(n));
    uint32_t num_auto_keys{params->get_num_auto_keys()};

    auto acc = std::make_shared<RingGswAccKey32Impl>(params, 1, 2, static_cast<uint32_t>(n));

    const auto& poly_params32 = params->get_poly_params32();
    const auto sk_ntt32 = narrow_poly32(sk_ntt, poly_params32);
    DiscreteGaussianGeneratorImpl<NativeVector32> dgg32(params->get_dgg_impl().get_std());

    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].convert_to_int<int32_t>()};
        const auto mono = monomial_of(params, s > mod_half ? s - mod_value : s);
        acc->set_eval_key(0, 0, i, rgsw_encrypt(params, poly_params32, sk_ntt32, dgg32, i, mono));
    }

    NativeInteger gen = NativeInteger(5);

    acc->set_eval_key(0, 1, 0, rgsw_encrypt_automorphism(params, poly_params32, sk_ntt32, dgg32, 2 * N - gen.convert_to_int()));

    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_auto_keys))
    for (uint32_t i = 1; i <= num_auto_keys; ++i)
        acc->set_eval_key(0, 1, i,
                        rgsw_encrypt_automorphism(params, poly_params32, sk_ntt32, dgg32,
                                                gen.mod_exp(i, 2 * N).convert_to_int<LwePlaintext>()));
    return acc;
}

void RingGswAccumulatorLmkcdey::eval_acc32(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey32& ek,
                                          RlweCiphertext& acc, const NativeVector& a) const {
    const auto& poly_params = params->get_poly_params32();
    uint32_t Q{static_cast<uint32_t>(params->get_Q().convert_to_int())};
    uint32_t M{2 * params->get_N()};

    auto acc32 = narrow_acc32(poly_params, acc->get_elements());
    acc32[1] = acc32[1].automorphism_transform(M - 5);

    lmkcdey_acc_schedule(
            params->get_q(), params->get_N(), params->get_num_auto_keys(), params->get_log_gen(), a,
            [&](int32_t idx) {
                add_to_acc_no_monomial(poly_params, Q, params->get_base_g_params(idx), (*ek)[0][0][idx], acc32);
            },
            [&](NativeInteger power, uint32_t k) {
                uint32_t p{power.convert_to_int<uint32_t>()};
                automorphism_key_switch(p, params->get_auto_map(p), poly_params, Q, params->get_default_base_g_params(),
                                      (*ek)[0][1][k], acc32);
            });

    widen_acc32_into(acc32, acc->get_elements());
}
#endif

void RingGswAccumulatorLmkcdey::eval_acc(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey& ek,
                                        RlweCiphertext& acc, const NativeVector& a) const {
    uint32_t M = 2 * params->get_N();
    acc->get_elements()[1] = (acc->get_elements()[1]).automorphism_transform(M - 5);

    lmkcdey_acc_schedule(
            params->get_q(), params->get_N(), params->get_num_auto_keys(), params->get_log_gen(), a,
            [&](int32_t idx) { add_to_acc_lmkcdey(params, (*ek)[0][0][idx], acc, idx); },
            [&](NativeInteger power, uint32_t k) { automorphism(params, power, (*ek)[0][1][k], acc); });
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2022/198
// Same as KeyGenAP, but only for X^{s_i}
// sk_ntt corresponds to the secret key z
RingGswEvalKey RingGswAccumulatorLmkcdey::key_gen_lmkcdey(const std::shared_ptr<RingGswCryptoParams>& params,
                                                        const NativePoly& sk_ntt, LwePlaintext m, uint32_t index) const {
    return std::make_shared<RingGswEvalKeyImpl>(
            rgsw_encrypt(params, params->get_poly_params(), sk_ntt, params->get_dgg_impl(), index, monomial_of(params, m)));
}

// Generation of an autormorphism key
RingGswEvalKey RingGswAccumulatorLmkcdey::key_gen_auto(const std::shared_ptr<RingGswCryptoParams>& params,
                                                     const NativePoly& sk_ntt, LwePlaintext k) const {
    return std::make_shared<RingGswEvalKeyImpl>(
            rgsw_encrypt_automorphism(params, params->get_poly_params(), sk_ntt, params->get_dgg_impl(), k));
}

// LMKCDEY Accumulation as described in https://eprint.iacr.org/2022/198
// Same as AP, but multiplied once
void RingGswAccumulatorLmkcdey::add_to_acc_lmkcdey(const std::shared_ptr<RingGswCryptoParams>& params,
                                                ConstRingGswEvalKey& ek, RlweCiphertext& acc, uint32_t index) const {
    add_to_acc_no_monomial(params->get_poly_params(), params->get_Q().convert_to_int<BasicInteger>(),
                       params->get_base_g_params(index), ek->get_elements(), acc->get_elements());
}

void RingGswAccumulatorLmkcdey::automorphism(const std::shared_ptr<RingGswCryptoParams>& params, NativeInteger a,
                                             ConstRingGswEvalKey& ak, RlweCiphertext& acc) const {
    uint32_t a_int{a.convert_to_int<uint32_t>()};
    automorphism_key_switch(a_int, params->get_auto_map(a_int), params->get_poly_params(),
                          params->get_Q().convert_to_int<BasicInteger>(), params->get_default_base_g_params(),
                          ak->get_elements(), acc->get_elements());
}

};  // namespace cipher
