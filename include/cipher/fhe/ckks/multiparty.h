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

#ifndef CIPHER_FHE_CKKS_MULTIPARTY_H_
#define CIPHER_FHE_CKKS_MULTIPARTY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/rns/multiparty.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {
/**
 * @brief CKKS implementation of the multiparty (threshold FHE) capability: fusion of the partial decryptions and
 * the interactive multi-party bootstrapping protocol (common random element, masked decryption shares and their
 * re-encryption, with the scale adjustments CKKS needs).
 */
class CkksRnsMultiparty : public RnsMultiparty {
  public:
    virtual ~CkksRnsMultiparty() = default;

    DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                            Poly* plaintext) const override;

    DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                            NativePoly* plaintext) const override;

    Ciphertext<RnsPoly> int_boot_adjust_scale(ConstCiphertext<RnsPoly> ciphertext) const override;

    Ciphertext<RnsPoly> int_mp_boot_adjust_scale(ConstCiphertext<RnsPoly> ciphertext) const override;

    Ciphertext<RnsPoly> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                       const PublicKey<RnsPoly> public_key) const override;

    /**
     * Threshold FHE: generates a common random polynomial for multi-party interactive bootstrapping with the element
     * parameters (modulus chain) of the given ciphertext, and wraps it in a ciphertext with the same metadata.
     *
     * @param params CKKS crypto parameters (unused; the parameters of the ciphertext are used instead)
     * @param ciphertext the ciphertext to be bootstrapped, which sets the modulus chain of the random element
     * @return a ciphertext holding the common random polynomial as its single element
     */
    Ciphertext<RnsPoly> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                       ConstCiphertext<RnsPoly>& ciphertext) const override;

    std::vector<Ciphertext<RnsPoly>> int_mp_boot_decrypt(const PrivateKey<RnsPoly> private_key,
                                                         ConstCiphertext<RnsPoly> ciphertext,
                                                         ConstCiphertext<RnsPoly> a) const override;

    std::vector<Ciphertext<RnsPoly>> int_mp_boot_add(
            std::vector<std::vector<Ciphertext<RnsPoly>>>& shares_pair_vec) const override;

    Ciphertext<RnsPoly> int_mp_boot_encrypt(const PublicKey<RnsPoly> public_key,
                                            const std::vector<Ciphertext<RnsPoly>>& shares_pair,
                                            ConstCiphertext<RnsPoly> a,
                                            ConstCiphertext<RnsPoly> ciphertext) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "MultipartyCKKSRNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_MULTIPARTY_H_
