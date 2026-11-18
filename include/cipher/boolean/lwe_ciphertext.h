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

#ifndef CIPHER_BOOLEAN_LWE_CIPHERTEXT_H_
#define CIPHER_BOOLEAN_LWE_CIPHERTEXT_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/lwe_ciphertext_fwd.h"
#include "cipher/math/backend.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores a LWE scheme ciphertext; composed of a vector "a"
 * and integer "b"
 */
class LweCiphertextImpl : public Serializable {
  public:
    LweCiphertextImpl() = default;

    /**
     * Constructs an LWE ciphertext (a, b) from its components
     *
     * @param a the vector "a"; its modulus is the ciphertext modulus q. For a fresh encryption of m under the
     * secret key s, b = <a, s> + e + m * (q / p) mod q
     * @param b the integer "b"
     * @param p the plaintext modulus the ciphertext encodes for (4 for binary gates)
     */
    LweCiphertextImpl(const NativeVector& a, NativeInteger b, NativeInteger p = 4) : a_(a), b_(b), p_(p) {}

    /**
     * Constructs an LWE ciphertext (a, b) from its components, moving the vector "a"
     *
     * @param a the vector "a"; its modulus is the ciphertext modulus q. For a fresh encryption of m under the
     * secret key s, b = <a, s> + e + m * (q / p) mod q
     * @param b the integer "b"
     * @param p the plaintext modulus the ciphertext encodes for (4 for binary gates)
     */
    LweCiphertextImpl(NativeVector&& a, NativeInteger b, NativeInteger p = 4) noexcept
        : a_(std::move(a)), b_(b), p_(p) {}

    // TODO: p_ deliberately not copied, and completing this copy breaks multi-input gates.
    /**
     * Copies "a" and "b" only; the plaintext modulus of the copy is left at its default of 4
     *
     * @param rhs the ciphertext to copy
     */
    LweCiphertextImpl(const LweCiphertextImpl& rhs) : a_(rhs.a_), b_(rhs.b_) {}

    LweCiphertextImpl(LweCiphertextImpl&& rhs) noexcept : a_(std::move(rhs.a_)), b_(rhs.b_) {}

    LweCiphertextImpl& operator=(const LweCiphertextImpl& rhs) {
        a_ = rhs.a_;
        b_ = rhs.b_;
        return *this;
    }

    LweCiphertextImpl& operator=(LweCiphertextImpl&& rhs) noexcept {
        a_ = std::move(rhs.a_);
        b_ = rhs.b_;
        return *this;
    }

    const NativeVector& get_A() const {
        return a_;
    }

    NativeVector& get_A() {
        return a_;
    }

    NativeInteger get_B() const {
        return b_;
    }

    /**
     * @return the ciphertext modulus q (the modulus of the vector "a")
     */
    NativeInteger get_modulus() const {
        return a_.get_modulus();
    }

    /**
     * @return the LWE dimension (the length of the vector "a")
     */
    uint32_t get_length() const {
        return a_.get_length();
    }

    NativeInteger get_pt_modulus() const {
        return p_;
    }

    void set_A(const NativeVector& a) {
        a_ = a;
    }

    void set_A(NativeVector&& a) noexcept {
        a_ = std::move(a);
    }

    void set_B(NativeInteger b) {
        b_ = b;
    }

    /**
     * Sets the ciphertext modulus and reduces "a" and "b" modulo it
     *
     * @param q the new ciphertext modulus
     */
    void set_modulus(NativeInteger q) {
        a_.set_modulus(q);
        a_.mod_reduce_eq();
        b_.mod_eq(q);
    }

    void set_pt_modulus(NativeInteger pmod) {
        p_ = pmod;
    }

    /**
     * Compares "a", "b" and the plaintext modulus
     *
     * @param other the ciphertext to compare with
     * @return true if both ciphertexts have the same "a", "b" and plaintext modulus
     */
    bool operator==(const LweCiphertextImpl& other) const {
        return a_ == other.a_ && b_ == other.b_ && p_ == other.p_;
    }

    /**
     * @param other the ciphertext to compare with
     * @return true if the ciphertexts differ in "a", "b" or the plaintext modulus
     */
    bool operator!=(const LweCiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", a_));
        ar(::cereal::make_nvp("b", b_));
        ar(::cereal::make_nvp("p", p_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("a", a_));
        ar(::cereal::make_nvp("b", b_));
        ar(::cereal::make_nvp("p", p_));
    }

    std::string serialized_object_name() const override {
        return "LWECiphertext";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    NativeVector a_;      ///< the vector "a"; its modulus is the ciphertext modulus q
    NativeInteger b_;     ///< the integer "b" = <a, s> + e + encoded message mod q
    NativeInteger p_{4};  ///< plaintext modulus; see the copy constructor for why copies reset it
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_CIPHERTEXT_H_
