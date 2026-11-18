//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef CIPHER_FHE_SCHEMELET_RLWE_MP_H_
#define CIPHER_FHE_SCHEMELET_RLWE_MP_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/context_fwd.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/core.h"

namespace cipher {

/**
 * @brief Helper ("schemelet") for RLWE ciphertexts with a message in the coefficients, used together with the
 * CKKS functional bootstrapping (eval_fbt)
 *
 * An RLWE ciphertext is represented as a pair {b, a} of Poly modulo a ciphertext modulus Q such that
 * b + a*s = (Q/p)*m + e for the CKKS secret key s, a plaintext modulus p and an integer message vector m stored in
 * the polynomial coefficients (BFV-style scaling). The static methods encrypt and decrypt such ciphertexts under
 * the CKKS secret key with arbitrary Q and p, switch their modulus, and convert them to and from CKKS ciphertexts
 * so that eval_fbt can evaluate a function on the encrypted values and return an exact RLWE ciphertext.
 */
class SchemeletRlweMp {
    using DggType = typename RnsPoly::DggType;
    using DugType = typename RnsPoly::DugType;

  public:
    ~SchemeletRlweMp() = default;

    /**
     * Returns the RNS element parameters of the secret key's crypto context with the towers of the given number of
     * levels removed from the end. One level corresponds to one tower, except that under COMPOSITESCALINGAUTO and
     * COMPOSITESCALINGMANUAL every level consists of composite_degree towers and under FLEXIBLEAUTOEXT one extra
     * tower is removed. The modulus of the result is the modulus Q' that encrypt_coeff() samples its encryption of
     * zero over.
     *
     * @param private_key the CKKS secret key whose crypto context supplies the element parameters
     * @param level number of levels to remove from the full parameters (0 keeps all towers)
     * @return the reduced element parameters
     */
    static std::shared_ptr<RnsParams<RnsPoly::Integer>> get_element_params(const PrivateKey<RnsPoly>& private_key,
                                                                           uint32_t level = 0);

    /**
     * Encrypts a vector of integers as the coefficients of an RLWE ciphertext under the CKKS secret key.
     * An RLWE encryption of zero is sampled over the modulus of element_params, switched to Q, and the message scaled
     * by Q/p is added. With N the ring dimension, the entries are placed at a stride of N/(2*input.size()); when the
     * stride is greater than 1 the same values are repeated in the second half of the coefficient vector, and when
     * the input has more than N/2 entries they are placed consecutively (at most N of them are used).
     *
     * @param input the integer message; every entry is reduced modulo p as a signed value
     * @param Q ciphertext modulus of the returned RLWE ciphertext
     * @param p plaintext modulus
     * @param private_key the CKKS secret key
     * @param element_params RNS parameters whose modulus Q' the encryption of zero is generated over
     *        (see get_element_params())
     * @param bit_reverse if true, the input is permuted in bit-reversed order before encoding (each half separately
     *        when the input has more than N/2 entries); this matches the slot order of the CKKS conversions when
     *        rotations are applied in the CKKS domain
     * @return the RLWE ciphertext as the pair {b, a} of polynomials modulo Q
     */
    static std::vector<Poly> encrypt_coeff(std::vector<int64_t> input, const BigInteger& Q, const BigInteger& p,
                                           const PrivateKey<RnsPoly>& private_key,
                                           const std::shared_ptr<RnsParams<RnsPoly::Integer>>& element_params,
                                           bool bit_reverse = false);

    /**
     * Decrypts an RLWE ciphertext {b, a} modulo Q (as produced by encrypt_coeff() or convert_ckks_to_rlwe()) with the
     * CKKS secret key. The ciphertext is switched to the modulus of element_params, b + a*s is computed, switched
     * back to Q and rounded to the plaintext modulus p, and the message coefficients are read at a stride of
     * N/(2*num_slots) (N = ring dimension) as signed integers in (-p/2, p/2].
     *
     * @param input the RLWE ciphertext {b, a} modulo Q
     * @param Q ciphertext modulus of the input
     * @param p plaintext modulus
     * @param private_key the CKKS secret key
     * @param element_params RNS parameters used for the decryption (see get_element_params())
     * @param num_slots number of slots used in the CKKS computation; determines the stride between message
     *        coefficients
     * @param length number of values to return (0 means num_slots)
     * @param bit_reverse if true, the bit-reversal permutation applied at encryption is undone (each half separately
     *        when num_slots is less than length)
     * @return the decrypted integer values
     */
    static std::vector<int64_t> decrypt_coeff(const std::vector<Poly>& input, const BigInteger& Q, const BigInteger& p,
                                              const PrivateKey<RnsPoly>& private_key,
                                              const std::shared_ptr<RnsParams<RnsPoly::Integer>>& element_params,
                                              uint32_t num_slots, uint32_t length = 0, bool bit_reverse = false);

    /**
     * Switches an RLWE ciphertext {b, a} from modulus Q2 to modulus Q1 in place by scaling both polynomials by
     * Q1/Q2 with rounding.
     *
     * @param input the ciphertext polynomials, currently modulo Q2; replaced by the polynomials modulo Q1
     * @param Q1 the target modulus
     * @param Q2 the current modulus
     */
    static void mod_switch(std::vector<Poly>& input, const BigInteger& Q1, const BigInteger& Q2);

    /**
     * Embeds an RLWE ciphertext {b, a} modulo Bigq into a CKKS ciphertext so that eval_fbt can process it.
     * A CKKS ciphertext with the requested number of slots is created at the given level by encrypting zero under
     * the public key (this supplies the ciphertext metadata), and its two elements are replaced by the RLWE
     * polynomials scaled and switched from Bigq to the CKKS modulus at that level. The level is adjusted for the
     * scaling technique in the same way as in get_element_params().
     *
     * @param cc the CKKS crypto context
     * @param coeffs the RLWE ciphertext {b, a}
     * @param pub_key CKKS public key used for the encryption of zero
     * @param Bigq modulus of the RLWE ciphertext
     * @param slots number of slots recorded in the CKKS ciphertext
     * @param level level of the resulting CKKS ciphertext
     * @return a CKKS ciphertext whose elements are the modulus-switched RLWE polynomials
     */
    static Ciphertext<RnsPoly> convert_rlwe_to_ckks(const CryptoContextImpl<RnsPoly>& cc,
                                                    const std::vector<Poly>& coeffs, const PublicKey<RnsPoly>& pub_key,
                                                    const BigInteger& bigq, uint32_t slots, uint32_t level = 0);

    /**
     * Extracts an RLWE ciphertext {b, a} modulo Q from a CKKS ciphertext: both elements are brought to coefficient
     * representation, CRT-interpolated to polynomials over the CKKS modulus and scaled and switched to Q with
     * rounding.
     *
     * @param ctxt the CKKS ciphertext (two elements)
     * @param Q the target modulus of the RLWE ciphertext
     * @return the pair {b, a} of polynomials modulo Q
     */
    static std::vector<Poly> convert_ckks_to_rlwe(ConstCiphertext<RnsPoly>& ctxt, const BigInteger& Q);

    /**
     * Computes the product of the first lvls+1 RNS moduli q_0, ..., q_lvls of the public key's element parameters.
     *
     * @param pub_key a CKKS public key supplying the RNS moduli
     * @param lvls number of moduli after q_0 to include in the product
     * @return q_0 * q_1 * ... * q_lvls
     */
    static BigInteger get_q_prime(const PublicKey<RnsPoly>& pub_key, uint32_t lvls);
};

}  // namespace cipher

#endif  // CIPHER_FHE_SCHEMELET_RLWE_MP_H_
