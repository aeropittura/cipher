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

#ifndef CIPHER_BOOLEAN_RGSW_ACC_DM_H_
#define CIPHER_BOOLEAN_RGSW_ACC_DM_H_

#include <cstdint>
#include <memory>

#include "cipher/boolean/rgsw_acc.h"

namespace cipher {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and https://eprint.iacr.org/2020/086
 */
class RingGswAccumulatorDm final : public RingGswAccumulator {
  public:
    RingGswAccumulatorDm() = default;

    /**
     * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param sk_ntt secret key polynomial in the EVALUATION representation
     * @param LWE_sk the secret key
     * @return a shared pointer to the resulting keys
     */
    RingGswAccKey key_gen_acc(const std::shared_ptr<RingGswCryptoParams>& params, const NativePoly& sk_ntt,
                            ConstLwePrivateKey& LWE_sk) const override;

#if CIPHER_NATIVE_INT != 32
    /**
     * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086, producing the refreshing
     * key directly in its 32-bit internal form: the RGSW encryptions are sampled on 32-bit words, so the 64-bit key
     * is never materialised. Used when Q fits a 32-bit word (RingGswAccKey32Impl::Fits)
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param sk_ntt secret key polynomial in the EVALUATION representation
     * @param LWE_sk the secret key
     * @return a shared pointer to the resulting 32-bit keys, laid out as [n][base_r][digits_r] like the 64-bit key
     */
    RingGswAccKey32 key_gen_acc32(const std::shared_ptr<RingGswCryptoParams>& params, const NativePoly& sk_ntt,
                                ConstLwePrivateKey& LWE_sk) const override;

    /**
     * Main accumulator function used in bootstrapping - AP variant on the 32-bit internal key. The accumulator is
     * narrowed to 32 bits, updated with 32-bit external products, and widened back; the result is bit-identical to
     * eval_acc on the 64-bit key
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek the 32-bit accumulator key
     * @param acc previous value of the accumulator
     * @param a value to update the accumulator with
     */
    void eval_acc32(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey32& ek, RlweCiphertext& acc,
                   const NativeVector& a) const override;
#endif

    /**
     * Main accumulator function used in bootstrapping - AP variant
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek the accumulator key
     * @param acc previous value of the accumulator
     * @param a value to update the accumulator with
     */
    void eval_acc(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey& ek, RlweCiphertext& acc,
                 const NativeVector& a) const override;

  private:
    /**
     * DM Key generation for internal Ring GSW as described in https://eprint.iacr.org/2014/816
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param sk_ntt secret key polynomial in the EVALUATION representation
     * @param m a plaintext
     * @param index LWE secret-key coefficient index
     * @return a shared pointer to the resulting keys
     */
    RingGswEvalKey key_gen_dm(const std::shared_ptr<RingGswCryptoParams>& params, const NativePoly& sk_ntt, LwePlaintext m,
                            uint32_t index) const;

    /**
     * DM Accumulation as described in https://eprint.iacr.org/2020/086
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek evaluation key for Ring GSW
     * @param acc previous value of the accumulator
     * @param index LWE secret-key coefficient index
     */
    void add_to_acc_dm(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswEvalKey& ek, RlweCiphertext& acc,
                    uint32_t index) const;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_ACC_DM_H_
