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

#include "cipher/boolean/rgsw_acc_dm.h"

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/boolean/rgsw_acc_common.h"

namespace cipher {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGswAccKey RingGswAccumulatorDm::key_gen_acc(const std::shared_ptr<RingGswCryptoParams>& params,
                                              const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv{LWE_sk->get_element()};
    auto mod_value{sv.get_modulus().convert_to_int<int32_t>()};
    auto mod_half{mod_value >> 1};
    uint32_t n(sv.get_length());
    params->verify_base_g_coverage(n);
    int32_t base_r(params->get_base_r());
    const auto& digits_r = params->get_digits_r();
    RingGswAccKey ek = std::make_shared<RingGswAccKeyImpl>(n, base_r, digits_r.size());

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (uint32_t i = 0; i < n; ++i) {
        for (size_t k = 0; k < digits_r.size(); ++k) {
            const int32_t extent = params->get_digit_extent_r(k);
            for (int32_t j = 1; j < extent; ++j) {
                auto s{sv[i].convert_to_int<int32_t>()};
                (*ek)[i][j][k] = key_gen_dm(params, sk_ntt,
                                          (s > mod_half ? s - mod_value : s) * j * digits_r[k].convert_to_int<int32_t>(), i);
            }
        }
    }
    return ek;
}

#if CIPHER_NATIVE_INT != 32
RingGswAccKey32 RingGswAccumulatorDm::key_gen_acc32(const std::shared_ptr<RingGswCryptoParams>& params,
                                                  const NativePoly& sk_ntt, ConstLwePrivateKey& LWE_sk) const {
    auto sv{LWE_sk->get_element()};
    auto mod_value{sv.get_modulus().convert_to_int<int32_t>()};
    auto mod_half{mod_value >> 1};
    uint32_t n(sv.get_length());
    params->verify_base_g_coverage(n);
    int32_t base_r(params->get_base_r());
    const auto& digits_r = params->get_digits_r();

    auto acc = std::make_shared<RingGswAccKey32Impl>(params, n, base_r, digits_r.size());

    const auto& poly_params32 = params->get_poly_params32();
    const auto sk_ntt32 = narrow_poly32(sk_ntt, poly_params32);
    DiscreteGaussianGeneratorImpl<NativeVector32> dgg32(params->get_dgg_impl().get_std());

    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (uint32_t i = 0; i < n; ++i) {
        for (size_t k = 0; k < digits_r.size(); ++k) {
            const int32_t extent = params->get_digit_extent_r(k);
            for (int32_t j = 1; j < extent; ++j) {
                auto s{sv[i].convert_to_int<int32_t>()};
                const auto mono =
                        monomial_of(params, (s > mod_half ? s - mod_value : s) * j * digits_r[k].convert_to_int<int32_t>());
                acc->set_eval_key(i, j, k, rgsw_encrypt(params, poly_params32, sk_ntt32, dgg32, i, mono));
            }
        }
    }
    return acc;
}

void RingGswAccumulatorDm::eval_acc32(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey32& ek,
                                     RlweCiphertext& acc, const NativeVector& a) const {
    const auto& poly_params = params->get_poly_params32();
    uint32_t Q{static_cast<uint32_t>(params->get_Q().convert_to_int())};

    auto acc32 = narrow_acc32(poly_params, acc->get_elements());

    dm_acc_schedule(params->get_q(), params->get_base_r(), params->get_digits_r().size(), a,
                  [&](uint32_t i, uint32_t a0, size_t k) {
                      add_to_acc_no_monomial(poly_params, Q, params->get_base_g_params(i), (*ek)[i][a0][k], acc32);
                  });

    widen_acc32_into(acc32, acc->get_elements());
}
#endif

void RingGswAccumulatorDm::eval_acc(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey& ek,
                                   RlweCiphertext& acc, const NativeVector& a) const {
    dm_acc_schedule(params->get_q(), params->get_base_r(), params->get_digits_r().size(), a,
                  [&](uint32_t i, uint32_t a0, size_t k) { add_to_acc_dm(params, (*ek)[i][a0][k], acc, i); });
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// sk_ntt corresponds to the secret key z
RingGswEvalKey RingGswAccumulatorDm::key_gen_dm(const std::shared_ptr<RingGswCryptoParams>& params,
                                              const NativePoly& sk_ntt, LwePlaintext m, uint32_t index) const {
    return std::make_shared<RingGswEvalKeyImpl>(
            rgsw_encrypt(params, params->get_poly_params(), sk_ntt, params->get_dgg_impl(), index, monomial_of(params, m)));
}

// AP Accumulation as described in https://eprint.iacr.org/2020/086
void RingGswAccumulatorDm::add_to_acc_dm(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswEvalKey& ek,
                                      RlweCiphertext& acc, uint32_t index) const {
    add_to_acc_no_monomial(params->get_poly_params(), params->get_Q().convert_to_int<BasicInteger>(),
                       params->get_base_g_params(index), ek->get_elements(), acc->get_elements());
}

};  // namespace cipher
