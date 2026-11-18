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

#ifndef CIPHER_FHE_BFV_PKE_H_
#define CIPHER_FHE_BFV_PKE_H_

#include <string>

#include "cipher/fhe/rns/pke.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief BFV implementation of key generation, encryption and decryption in the RNS representation.
 */
class BfvRnsPke : public RnsPke {
    using ParmType = typename RnsPoly::Params;
    using IntType = typename RnsPoly::Integer;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    virtual ~BfvRnsPke() {}

    /**
     * Generates a BFV key pair. The keys are generated over the key basis returned by get_params_pk() (Q, Qr for
     * EXTENDED encryption, or QP for HYBRID key switching with PRE) and the secret key is then truncated to the
     * ciphertext basis.
     *
     * @param cc the crypto context the keys are generated for.
     * @param make_sparse_value set to true to generate a sparse (ring-reduction) key; no longer supported.
     * @return the generated key pair.
     */
    KeyPair<RnsPoly> key_gen_internal(CryptoContext<RnsPoly> cc, bool make_sparse_value) const override;

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
                          Poly* plaintext) const override {
        std::string err_msg =
                "PKEBFVRNS: Decryption to Poly from DCRTPoly is not supported as it "
                "may "
                "lead to incorrect results.";
        CIPHER_THROW(err_msg);
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<RnsPke>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<RnsPke>(this));
    }

    std::string serialized_object_name() const {
        return "PKEBFVRNS";
    }
};
}  // namespace cipher

#endif  // CIPHER_FHE_BFV_PKE_H_
