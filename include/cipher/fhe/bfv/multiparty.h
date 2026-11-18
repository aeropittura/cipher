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

#ifndef CIPHER_FHE_BFV_MULTIPARTY_H_
#define CIPHER_FHE_BFV_MULTIPARTY_H_

#include <cstdint>
#include <string>
#include <vector>

#include "cipher/fhe/rns/multiparty.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {
/**
 * @brief BFV implementation of the threshold-FHE (multiparty) operations in the RNS representation.
 */
class BfvRnsMultiparty : public RnsMultiparty {
    using ParmType = typename RnsPoly::Params;
    using IntType = typename RnsPoly::Integer;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    virtual ~BfvRnsMultiparty() {}

    /**
     * Threshold FHE: Generates a public key from a vector of secret shares (the joint secret key is the sum of
     * the shares). ONLY FOR DEBUGGING PURPOSES. SHOULD NOT BE USED IN PRODUCTION. The keys are generated over
     * the key basis of BFV (Qr for EXTENDED encryption).
     *
     * @param cc cryptocontext for the keys to be generated.
     * @param private_key_vec secret key shares.
     * @param make_sparse_value not used by this scheme.
     * @return key pair including the joint private key and the joint public key.
     */
    KeyPair<RnsPoly> multiparty_key_gen(CryptoContext<RnsPoly> cc,
                                        const std::vector<PrivateKey<RnsPoly>>& private_key_vec,
                                        bool make_sparse_value) override;

    /**
     * Threshold FHE: Generation of a public key derived from a previous joined public key (for prior secret
     * shares) and a fresh secret key share of the current party. The same public random polynomial a is reused
     * and the new b is added to the prior one unless fresh is set.
     *
     * @param cc cryptocontext for the keys to be generated.
     * @param public_key joined public key from prior parties.
     * @param make_sparse_value not used by this scheme.
     * @param fresh set to true if proxy re-encryption is used in the multi-party protocol or star topology is
     * used (the prior b is then not added).
     * @return key pair including the secret share for the current party and joined public key.
     */
    KeyPair<RnsPoly> multiparty_key_gen(CryptoContext<RnsPoly> cc, const PublicKey<RnsPoly> public_key,
                                        bool make_sparse_value, bool fresh) override;

    /**
     * Threshold FHE: Combines the partial decryptions and scales the result by t/Q with rounding using the RNS
     * procedures of the configured multiplication technique (or CRT interpolation if the ciphertext had been
     * compressed to fewer towers).
     *
     * @param ciphertext_vec vector of "partial" decryptions.
     * @param plaintext the plaintext output as a NativePoly.
     * @return the decoding result.
     */
    DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                            NativePoly* plaintext) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "MultipartyBFVRNS";
    }
};
}  // namespace cipher

#endif  // CIPHER_FHE_BFV_MULTIPARTY_H_
