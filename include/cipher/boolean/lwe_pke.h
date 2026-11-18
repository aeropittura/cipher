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

#ifndef CIPHER_BOOLEAN_LWE_PKE_H_
#define CIPHER_BOOLEAN_LWE_PKE_H_

#include <cstdint>
#include <memory>

#include "cipher/boolean/constants.h"
#include "cipher/boolean/lwe_ciphertext.h"
#include "cipher/boolean/lwe_params.h"
#include "cipher/boolean/lwe_key_pair.h"
#include "cipher/boolean/lwe_switch_key.h"
#include "cipher/boolean/lwe_switch_key32.h"
#include "cipher/boolean/lwe_private_key.h"
#include "cipher/boolean/lwe_public_key.h"

namespace cipher {

/**
 * @brief Additive public-key LWE scheme
 */
class LweEncryptionScheme {
  public:
    LweEncryptionScheme() = default;

    /**
     * Generates a secret key of dimension n using modulus q
     *
     * @param size lattice parameter for the additive LWE scheme
     * @param modulus the modulus for the secret key
     * @return a shared pointer to the secret key
     */
    LwePrivateKey key_gen(uint32_t size, NativeInteger modulus) const;

    /**
     * Generates a secret key of dimension n using modulus q with coefficients sampled from a
     * discrete Gaussian distribution
     *
     * @param size lattice parameter for the additive LWE scheme
     * @param modulus the modulus for the secret key
     * @return a shared pointer to the secret key
     */
    LwePrivateKey key_gen_gaussian(uint32_t size, NativeInteger modulus) const;

    /**
     * Generates a public key of dimension N and modulus Q, secret key of dimension n using modulus q pair
     * @param params a shared pointer to LWE scheme parameters
     * @return a shared pointer to the public key, secret key pair
     */
    LweKeyPair key_gen_pair(const std::shared_ptr<LweCryptoParams>& params) const;

    /**
     * Generates a public key corresponding to a secret key of dimension N using modulus Q
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param sk_n a secret key of dimension N
     * @return a shared pointer to the public key
     */
    LwePublicKey pub_key_gen(const std::shared_ptr<LweCryptoParams>& params, ConstLwePrivateKey& sk_n) const;

    /**
     * Encrypts a bit using a secret key (symmetric key encryption)
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param sk the secret key
     * @param m the plaintext
     * @param p the plaintext space
     * @param mod the ciphertext modulus to encrypt with; by default q_ in params
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext encrypt(const std::shared_ptr<LweCryptoParams>& params, ConstLwePrivateKey& sk, LwePlaintext m,
                          LwePlaintextModulus p = 4, NativeInteger mod_value = 0) const;

    /**
     * Encrypts a bit using a public key (asymmetric key encryption)
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param pk the public key
     * @param m the plaintext
     * @param p the plaintext space
     * @param mod the ciphertext modulus to encrypt with; by default q_ in params
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext encrypt_n(const std::shared_ptr<LweCryptoParams>& params, ConstLwePublicKey& pk, LwePlaintext m,
                            LwePlaintextModulus p = 4, NativeInteger mod_value = 0) const;

    /**
     * Converts a ciphertext (public key encryption) with modulus Q and dimension N to ciphertext with q and n
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param ksk the key switching key from secret key of dimension N to secret key of dimension n
     * @param ct the ciphertext to convert
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext switch_c_ttoqn(const std::shared_ptr<LweCryptoParams>& params, ConstLweSwitchingKey& ksk,
                                 ConstLweCiphertext& ct) const;

    /**
     * Decrypts the ciphertext using secret key sk
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param sk the secret key
     * @param ct the ciphertext
     * @param result plaintext result
     * @param p the plaintext space
     */
    void decrypt(const std::shared_ptr<LweCryptoParams>& params, ConstLwePrivateKey& sk, ConstLweCiphertext& ct,
                 LwePlaintext* result, LwePlaintextModulus p = 4) const;

    /**
     * Adds the second ciphertext to the first ciphertext
     *
     * @param ct1 the ciphertext which will hold the sum
     * @param ct2 the ciphertext to add
     */
    void eval_add_eq(LweCiphertext& ct1, ConstLweCiphertext& ct2) const;

    /**
     * Adds the a constant to the ciphertext
     *
     * @param ct the ciphertext which will hold the sum
     * @param cnst the constant to add
     */
    void eval_add_const_eq(LweCiphertext& ct, NativeInteger cnst) const;

    /**
     * Subtracts the second ciphertext from the first ciphertext, the result is held in the first ciphertext
     *
     * @param ct1 the ciphertext which will hold the difference
     * @param ct2 the ciphertext to subtract
     */
    void eval_sub_eq(LweCiphertext& ct1, ConstLweCiphertext& ct2) const;

    /**
     * Subtracts the second ciphertext from the first ciphertext, the result is held in the second ciphertext
     *
     * @param ct1 the ciphertext from which to subtract
     * @param ct2 the ciphertext to subtract, will hold the difference
     */
    void eval_sub_eq2(ConstLweCiphertext& ct1, LweCiphertext& ct2) const;

    /**
     * Subtracts the constant from the ciphertext
     *
     * @param ct the ciphertext which will hold the difference
     * @param cnst the constant to subtract
     */
    void eval_sub_const_eq(LweCiphertext& ct, NativeInteger cnst) const;

    /**
     * Multiplies a ciphertext by a constant
     *
     * @param ct the ciphertext which will hold the product
     * @param cnst the constant to multiply by
     */
    void eval_mult_const_eq(LweCiphertext& ct, NativeInteger cnst) const;

    /**
     * Changes an LWE ciphertext modulo Q into an LWE ciphertext modulo q
     *
     * @param q the target modulus
     * @param ct_q the input ciphertext
     * @return resulting ciphertext
     */
    LweCiphertext mod_switch(NativeInteger q, ConstLweCiphertext& ct_q) const;

    /**
     * Generates a switching key to go from a secret key with (Q,N) to a secret
     * key with (q,n)
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param sk new secret key
     * @param sk_n old secret key
     * @return a shared pointer to the switching key
     */
    LweSwitchingKey key_switch_gen(const std::shared_ptr<LweCryptoParams>& params, ConstLwePrivateKey& sk,
                                   ConstLwePrivateKey& sk_n) const;

    /**
     * Switches ciphertext from (Q,N) to (Q,n)
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param K switching key
     * @param ct_qn input ciphertext
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext key_switch(const std::shared_ptr<LweCryptoParams>& params, ConstLweSwitchingKey& K,
                             ConstLweCiphertext& ct_qn) const;

#if CIPHER_NATIVE_INT != 32
    /**
     * Generates the switching key from (Q,N) to (q,n) directly in its 32-bit internal form, used when the
     * key-switching modulus q_ks fits a 32-bit word (LweSwitchingKey32Impl::Fits). The whole key is sampled on 32-bit
     * words, so the 64-bit key is never materialised; the outputs follow the same distributions as key_switch_gen, but
     * the sampling sequence differs, so keys are not bit-comparable across widths
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param sk new secret key
     * @param sk_n old secret key
     * @return a shared pointer to the 32-bit switching key
     */
    LweSwitchingKey32 key_switch_gen32(const std::shared_ptr<LweCryptoParams>& params, ConstLwePrivateKey& sk,
                                       ConstLwePrivateKey& sk_n) const;

    /**
     * Switches ciphertext from (q_ks,N) to (q_ks,n) using the 32-bit internal switching key. Rows are accumulated
     * unreduced in 64-bit words and reduced once per output coefficient, so the result is bit-identical to the key
     * switch on the 64-bit key
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param K the 32-bit switching key
     * @param ct_qn input ciphertext of dimension N whose modulus does not exceed q_ks
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext key_switch(const std::shared_ptr<LweCryptoParams>& params, ConstLweSwitchingKey32& K,
                             ConstLweCiphertext& ct_qn) const;

    /**
     * Converts a ciphertext with modulus Q and dimension N to a ciphertext with q and n using the 32-bit internal
     * switching key: modulus switch to q_ks, key switch to dimension n, modulus switch to q
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param ksk the 32-bit key switching key from the secret key of dimension N to the secret key of dimension n
     * @param ct the ciphertext to convert
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext switch_c_ttoqn(const std::shared_ptr<LweCryptoParams>& params, ConstLweSwitchingKey32& ksk,
                                 ConstLweCiphertext& ct) const;
#endif

    /**
     * Embeds a plaintext bit without noise or encryption
     *
     * @param params a shared pointer to LWE scheme parameters
     * @param m - the plaintext
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext noiseless_embedding(const std::shared_ptr<LweCryptoParams>& params, LwePlaintext m) const;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_PKE_H_
