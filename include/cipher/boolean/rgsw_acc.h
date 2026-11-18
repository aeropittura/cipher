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

#ifndef CIPHER_BOOLEAN_RGSW_ACC_H_
#define CIPHER_BOOLEAN_RGSW_ACC_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/boolean/rgsw_acc_key.h"
#include "cipher/boolean/rgsw_acc_key32.h"
#include "cipher/boolean/rgsw_params.h"
#include "cipher/boolean/rlwe_ciphertext.h"

namespace cipher {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class RingGswAccumulator {
  public:
    RingGswAccumulator() = default;

#if CIPHER_NATIVE_INT != 32
    /**
     * Key generation for internal Ring GSW directly in the 32-bit internal key representation, used when the modulus Q
     * fits a 32-bit word. Takes the same arguments as key_gen_acc: the RingGSW scheme parameters, the secret key
     * polynomial in the EVALUATION representation, and the LWE secret key. The base implementation returns nullptr,
     * meaning the accumulator does not implement it, so callers fall back to key_gen_acc
     *
     * @return a shared pointer to the 32-bit refreshing key, or nullptr when not implemented
     */
    virtual RingGswAccKey32 key_gen_acc32(const std::shared_ptr<RingGswCryptoParams>&, const NativePoly&,
                                          ConstLwePrivateKey&) const {
        return nullptr;
    }

    /**
     * Main accumulator function (blind rotation) on the 32-bit internal key, bit-identical to eval_acc on the 64-bit
     * key. Takes the same arguments as eval_acc: the RingGSW scheme parameters, the 32-bit accumulator key, the
     * accumulator to update, and the value to update it with. Implemented by every accumulator that implements
     * key_gen_acc32; the base implementation throws
     */
    virtual void eval_acc32(const std::shared_ptr<RingGswCryptoParams>&, ConstRingGswAccKey32&, RlweCiphertext&,
                            const NativeVector&) const {
        CIPHER_THROW("32-bit internal evaluation is not supported by this accumulator");
    }
#endif

    /**
     * Key generation for internal Ring GSW
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param sk_ntt secret key polynomial in the EVALUATION representation
     * @param LWE_sk the secret key
     * @return a shared pointer to the resulting keys
     */
    virtual RingGswAccKey key_gen_acc(const std::shared_ptr<RingGswCryptoParams>& params, const NativePoly& sk_ntt,
                                      ConstLwePrivateKey& LWE_sk) const {
        CIPHER_THROW("Operation not supported");
    }

    /**
     * Main accumulator function used in bootstrapping
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek the accumulator key
     * @param acc previous value of the accumulator
     * @param a value to update the accumulator with
     */
    virtual void eval_acc(const std::shared_ptr<RingGswCryptoParams>& params, ConstRingGswAccKey& ek,
                          RlweCiphertext& acc, const NativeVector& a) const {
        CIPHER_THROW("Operation not supported");
    }

    /**
     * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
     * RLWE' ciphertext. The current gadget base is used when no coefficient index is provided.
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param input input RLWE ciphertext
     * @param output output RLWE' ciphertext
     */
    void signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params,
                                const std::vector<NativePoly>& input, std::vector<NativePoly>& output) const;

    /**
     * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
     * RLWE' ciphertext, using the gadget base associated with the given LWE secret-key coefficient index.
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param input input RLWE ciphertext
     * @param output output RLWE' ciphertext
     * @param index LWE secret-key coefficient index
     */
    void signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params,
                                const std::vector<NativePoly>& input, std::vector<NativePoly>& output,
                                uint32_t index) const;

    /**
     * The signed digit decomposition of an RLWE ciphertext into an RLWE' ciphertext with explicit gadget parameters.
     * Both overloads of signed_digit_decompose for RLWE ciphertexts forward here. The excess-H decomposition produces
     * 2(digits_g - 1) digit polynomials, the first digit being dropped by the approximate gadget decomposition
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param input input RLWE ciphertext
     * @param output output RLWE' ciphertext, sized by the caller to 2(digits_g - 1) polynomials
     * @param bp the gadget parameters (base, digit count, digit width) to decompose with
     */
    void signed_digit_decompose_impl(const std::shared_ptr<RingGswCryptoParams>& params,
                                     const std::vector<NativePoly>& input, std::vector<NativePoly>& output,
                                     const RingGswCryptoParams::BaseGParams& bp) const;

    /**
     * The signed digit decomposition which takes a ring element input and outputs a vector of its digits, i.e.,
     * decompose(a) = (a_0, ..., a_{d-1}) = R^d.
     * Only for automorphism key switching LMKCDEY
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param input input ring element
     * @param output decomposed value
     */
    void signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params, const NativePoly& input,
                                std::vector<NativePoly>& output) const;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_ACC_H_
