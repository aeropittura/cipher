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

#ifndef CIPHER_FHE_CKKS_PKE_H_
#define CIPHER_FHE_CKKS_PKE_H_

#include <string>

#include "cipher/fhe/rns/pke.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief CKKS implementation of the public key encryption capability; adds the noise flooding used by the
 * NOISE_FLOODING_DECRYPT mode to the RNS decryption.
 */
class CkksRnsPke : public RnsPke {
    using ParmType = typename RnsPoly::Params;
    using IntType = typename RnsPoly::Integer;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    virtual ~CkksRnsPke() = default;

    /**
     * Method for decrypting plaintext with noise flooding
     *
     * @param ciphertext ciphertext to be decrypted.
     * @param private_key private key used for decryption.
     * @param plaintext the plaintext output.
     * @return the decoding result.
     */
    DecryptResult decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                          NativePoly* plaintext) const override;

    /**
     * Method for decrypting plaintext with noise flooding
     *
     * @param ciphertext ciphertext to be decrypted.
     * @param private_key private key used for decryption.
     * @param plaintext the plaintext output.
     * @return the decoding result.
     */
    DecryptResult decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                          Poly* plaintext) const override;

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
        return "PKECKKSRNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_PKE_H_
