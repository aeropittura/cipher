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

#ifndef CIPHER_BOOLEAN_LWE_PRIVATE_KEY_H_
#define CIPHER_BOOLEAN_LWE_PRIVATE_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/lwe_private_key_fwd.h"
#include "cipher/math/backend.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores the LWE scheme secret key; contains a vector
 */
class LwePrivateKeyImpl : public Serializable {
  public:
    LwePrivateKeyImpl() = default;

    /**
     * Constructs an LWE secret key from its vector
     *
     * @param s the secret key vector; its length is the LWE dimension and its entries (ternary or Gaussian
     * secrets) are stored as residues modulo the LWE modulus
     */
    explicit LwePrivateKeyImpl(const NativeVector& s) : s_(s) {}

    /**
     * Constructs an LWE secret key from its vector, moving it
     *
     * @param s the secret key vector; its length is the LWE dimension and its entries (ternary or Gaussian
     * secrets) are stored as residues modulo the LWE modulus
     */
    explicit LwePrivateKeyImpl(NativeVector&& s) noexcept : s_(std::move(s)) {}

    LwePrivateKeyImpl(const LwePrivateKeyImpl& rhs) : s_(rhs.s_) {}

    LwePrivateKeyImpl(LwePrivateKeyImpl&& rhs) noexcept : s_(std::move(rhs.s_)) {}

    LwePrivateKeyImpl& operator=(const LwePrivateKeyImpl& rhs) {
        s_ = rhs.s_;
        return *this;
    }

    LwePrivateKeyImpl& operator=(LwePrivateKeyImpl&& rhs) noexcept {
        s_ = std::move(rhs.s_);
        return *this;
    }

    const NativeVector& get_element() const {
        return s_;
    }

    void set_element(const NativeVector& s) {
        s_ = s;
    }

    void set_element(NativeVector&& s) noexcept {
        s_ = std::move(s);
    }

    /**
     * @return the LWE dimension (the length of the secret key vector)
     */
    uint32_t get_length() const {
        return s_.get_length();
    }

    /**
     * @return the modulus of the secret key vector
     */
    NativeInteger get_modulus() const {
        return s_.get_modulus();
    }

    /**
     * @param other the secret key to compare with
     * @return true if both keys have the same vector
     */
    bool operator==(const LwePrivateKeyImpl& other) const {
        return s_ == other.s_;
    }

    /**
     * @param other the secret key to compare with
     * @return true if the key vectors differ
     */
    bool operator!=(const LwePrivateKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("s", s_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("s", s_));
    }

    std::string serialized_object_name() const override {
        return "LWEPrivateKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    NativeVector s_;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_PRIVATE_KEY_H_
