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

#ifndef CIPHER_FHE_RNS_PKE_H_
#define CIPHER_FHE_RNS_PKE_H_

#include <memory>
#include <string>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/fhe/base/pke.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Abstract interface for encryption algorithm
 */
class RnsPke : public BasePke<RnsPoly> {
    using ParmType = typename RnsPoly::Params;
    using IntType = typename RnsPoly::Integer;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    virtual ~RnsPke() = default;

    /**
     * Method for encrypting plaintext using LBC
     *
     * @param plaintext copy of the plaintext element. NOTE a copy is passed!
     * That is NOT an error!
     * @param public_key public key used for encryption.
     * @return ciphertext which results from encryption.
     */
    Ciphertext<RnsPoly> encrypt(RnsPoly plaintext, const PublicKey<RnsPoly> public_key) const override;

    /**
     * Method for encrypting plaintext using LBC
     *
     * @param plaintext copy of the plaintext input. NOTE a copy is passed! That
     * is NOT an error!
     * @param private_key private key used for encryption.
     * @return ciphertext which results from encryption.
     */
    Ciphertext<RnsPoly> encrypt(RnsPoly plaintext, const PrivateKey<RnsPoly> private_key) const override;

    /**
     * Method for decrypting plaintext using LBC
     *
     * @param ciphertext ciphertext to be decrypted.
     * @param private_key private key used for decryption.
     * @param plaintext the plaintext output.
     * @return the decoding result.
     */
    DecryptResult decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                          NativePoly* plaintext) const override;

    /**
     * Method for decrypting plaintext using LBC
     *
     * @param ciphertext ciphertext to be decrypted.
     * @param private_key private key used for decryption.
     * @param plaintext the plaintext output.
     * @return the decoding result.
     */
    DecryptResult decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                          Poly* plaintext) const override;

    /////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////

    /**
     * Generates a secret-key encryption of zero, i.e., the pair (a*s + ns*e, -a) for a uniformly random a and a
     * Gaussian error e, where ns is the noise scale of the scheme.
     *
     * @param private_key the secret key.
     * @param params the element parameters of the ciphertext; if fewer towers than the key has are requested,
     * only the needed towers of the key are used. nullptr selects the full modulus chain.
     * @return the two ciphertext polynomials.
     */
    std::shared_ptr<std::vector<RnsPoly>> encrypt_zero_core(const PrivateKey<RnsPoly> private_key,
                                                            const std::shared_ptr<ParmType> params) const override;

    /**
     * Generates a public-key encryption of zero, i.e., the pair (p0*v + ns*e0, p1*v + ns*e1) for a fresh
     * ephemeral key v drawn from the secret key distribution and Gaussian errors e0, e1, where ns is the noise
     * scale of the scheme.
     *
     * @param public_key the public key (p0, p1).
     * @param params the element parameters of the ciphertext; if fewer towers than the key has are requested,
     * only the needed towers of the public key are used. nullptr selects the full modulus chain.
     * @return the two ciphertext polynomials.
     */
    std::shared_ptr<std::vector<RnsPoly>> encrypt_zero_core(const PublicKey<RnsPoly> public_key,
                                                            const std::shared_ptr<ParmType> params) const override;

    /**
     * Computes the decryption polynomial c_0 + c_1*s + c_2*s^2 + ... in EVALUATION format, using only the
     * towers of the secret key that the ciphertext still has.
     *
     * @param cv the ciphertext polynomials.
     * @param private_key the secret key.
     * @return the noisy scaled plaintext polynomial.
     */
    RnsPoly decrypt_core(const std::vector<RnsPoly>& cv, const PrivateKey<RnsPoly> private_key) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<BasePke<RnsPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<BasePke<RnsPoly>>(this));
    }

    std::string serialized_object_name() const {
        return "PKERNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_RNS_PKE_H_
