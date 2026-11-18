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

#ifndef CIPHER_BOOLEAN_LWE_PUBLIC_KEY_H_
#define CIPHER_BOOLEAN_LWE_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/lwe_public_key_fwd.h"
#include "cipher/math/backend.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores the LWE scheme public key; contains a vector
 */
class LwePublicKeyImpl : public Serializable {
  public:
    LwePublicKeyImpl() = default;

    /**
     * Constructs an LWE public key (A, v) from its components
     *
     * @param A the uniformly random matrix, stored by rows: N vectors of dimension N with modulus Q
     * @param v the vector v = A s + e, i.e. v[j] = <A[j], s> + e_j mod Q, for the secret key s
     */
    LwePublicKeyImpl(const std::vector<NativeVector>& A, const NativeVector& v) : A_(A), v_(v) {}

    /**
     * Constructs an LWE public key (A, v) from its components, moving them
     *
     * @param A the uniformly random matrix, stored by rows: N vectors of dimension N with modulus Q
     * @param v the vector v = A s + e, i.e. v[j] = <A[j], s> + e_j mod Q, for the secret key s
     */
    LwePublicKeyImpl(std::vector<NativeVector>&& A, NativeVector&& v) noexcept : A_(std::move(A)), v_(std::move(v)) {}

    LwePublicKeyImpl(const LwePublicKeyImpl& rhs) : A_(rhs.A_), v_(rhs.v_) {}

    LwePublicKeyImpl(LwePublicKeyImpl&& rhs) noexcept : A_(std::move(rhs.A_)), v_(std::move(rhs.v_)) {}

    LwePublicKeyImpl& operator=(const LwePublicKeyImpl& rhs) {
        A_ = rhs.A_;
        v_ = rhs.v_;
        return *this;
    }

    LwePublicKeyImpl& operator=(LwePublicKeyImpl&& rhs) noexcept {
        A_ = std::move(rhs.A_);
        v_ = std::move(rhs.v_);
        return *this;
    }

    const std::vector<NativeVector>& get_A() const {
        return A_;
    }

    const NativeVector& get_v() const {
        return v_;
    }

    void set_A(const std::vector<NativeVector>& A) {
        A_ = A;
    }

    void set_A(std::vector<NativeVector>&& A) noexcept {
        A_ = std::move(A);
    }

    void set_v(const NativeVector& v) {
        v_ = v;
    }

    void set_v(NativeVector&& v) noexcept {
        v_ = std::move(v);
    }

    /**
     * @return the dimension of the key (the length of v)
     */
    uint32_t get_length() const {
        return v_.get_length();
    }

    /**
     * @return the modulus of the key (the modulus of v)
     */
    NativeInteger get_modulus() const {
        return v_.get_modulus();
    }

    /**
     * @param other the public key to compare with
     * @return true if both keys have the same A and v
     */
    bool operator==(const LwePublicKeyImpl& other) const {
        return (A_ == other.A_) && (v_ == other.v_);
    }

    /**
     * @param other the public key to compare with
     * @return true if the keys differ in A or v
     */
    bool operator!=(const LwePublicKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("A", A_));
        ar(::cereal::make_nvp("v", v_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("A", A_));
        ar(::cereal::make_nvp("v", v_));
    }

    std::string serialized_object_name() const override {
        return "LWEPublicKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    std::vector<NativeVector> A_;  ///< the uniformly random matrix A, stored by rows
    NativeVector v_;               ///< the vector v = A s + e
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_PUBLIC_KEY_H_
