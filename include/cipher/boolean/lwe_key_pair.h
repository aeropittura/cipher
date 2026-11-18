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

#ifndef CIPHER_BOOLEAN_LWE_KEY_PAIR_H_
#define CIPHER_BOOLEAN_LWE_KEY_PAIR_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/lwe_key_pair_fwd.h"
#include "cipher/boolean/lwe_switch_key.h"
#include "cipher/boolean/lwe_private_key.h"
#include "cipher/boolean/lwe_public_key.h"
#include "cipher/math/backend.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores the LWE scheme secret key, public key pair; ((A, b), s)
 */
class LweKeyPairImpl {
  public:
    LwePublicKey public_key{nullptr};   ///< the public key (A, v) with v = A s + e
    LwePrivateKey secret_key{nullptr};  ///< the secret key s the public key was generated from

    /**
     * Constructs a key pair from a public key and the matching secret key
     *
     * @param Av the public key (A, v)
     * @param s the secret key s that (A, v) was generated from
     */
    LweKeyPairImpl(const LwePublicKey& av_value, const LwePrivateKey& s) : public_key(av_value), secret_key(s) {}

    /**
     * Constructs a key pair from a public key and the matching secret key, moving both pointers
     *
     * @param Av the public key (A, v)
     * @param s the secret key s that (A, v) was generated from
     */
    LweKeyPairImpl(LwePublicKey&& av_value, LwePrivateKey&& s) noexcept : public_key(std::move(av_value)), secret_key(std::move(s)) {}

    /**
     * @return true if both the public key and the secret key are set (non-null)
     */
    bool good() {
        return public_key && secret_key;
    }
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_KEY_PAIR_H_
