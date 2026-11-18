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

#ifndef CIPHER_FHE_KEY_RELIN_KEY_H_
#define CIPHER_FHE_KEY_RELIN_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/key/eval_key.h"
#include "cipher/fhe/key/relin_key_fwd.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Concrete class for Relinearization keys of RLWE scheme
 * @tparam Element a ring element.
 */
template <class Element>
class EvalKeyRelinImpl : public EvalKeyImpl<Element> {
  private:
    std::vector<Element> a_key_;
    std::vector<Element> b_key_;

  public:
    /**
     * Basic constructor for setting the crypto context
     *
     * @param cc the crypto context the key belongs to
     */
    explicit EvalKeyRelinImpl(const CryptoContext<Element>& cc) : EvalKeyImpl<Element>(cc) {}

    EvalKeyRelinImpl() = default;

    virtual ~EvalKeyRelinImpl() = default;

    /**
     * Copy constructor
     *
     *@param rhs key to copy from
     */
    EvalKeyRelinImpl(const EvalKeyRelinImpl<Element>& rhs)
        : EvalKeyImpl<Element>(rhs), a_key_(rhs.a_key_), b_key_(rhs.b_key_) {}

    /**
     * Move constructor
     *
     *@param rhs key to move from
     */
    EvalKeyRelinImpl(EvalKeyRelinImpl<Element>&& rhs) noexcept
        : EvalKeyImpl<Element>(std::move(rhs)), a_key_(std::move(rhs.a_key_)), b_key_(std::move(rhs.b_key_)) {}

    /**
     * Checks whether the key is usable: it has a crypto context and both key vectors A and B are non-empty.
     *
     * @return true if the key has a crypto context and non-empty A and B vectors
     */
    operator bool() const {
        return (this->context != nullptr) && (a_key_.size() != 0) && (b_key_.size() != 0);
    }

    /**
     * Assignment Operator.
     *
     * @param rhs key to copy from
     * @return the resulting EvalKeyRelinImpl
     */
    EvalKeyRelinImpl<Element>& operator=(const EvalKeyRelinImpl<Element>& rhs) {
        EvalKeyImpl<Element>::operator=(rhs);
        a_key_ = rhs.a_key_;
        b_key_ = rhs.b_key_;
        return *this;
    }

    /**
     * Move Assignment Operator.
     *
     * @param rhs key to move from
     * @return the resulting EvalKeyRelinImpl
     */
    EvalKeyRelinImpl<Element>& operator=(EvalKeyRelinImpl<Element>&& rhs) noexcept {
        EvalKeyImpl<Element>::operator=(std::move(rhs));
        a_key_ = std::move(rhs.a_key_);
        b_key_ = std::move(rhs.b_key_);
        return *this;
    }

    /**
     * Setter function to store Relinearization Element Vector A.
     * Overrides base class implementation.
     *
     * @param a is the Element vector to be copied.
     */
    void set_a_vector(const std::vector<Element>& a) override {
        a_key_ = a;
    }

    /**
     * Setter function to store Relinearization Element Vector A.
     * Overrides base class implementation.
     *
     * @param a is the Element vector to be moved.
     */
    void set_a_vector(std::vector<Element>&& a) noexcept override {
        a_key_ = std::move(a);
    }

    /**
     * Getter function to access Relinearization Element Vector A.
     * Overrides base class implementation.
     *
     * @return Element vector A.
     */
    const std::vector<Element>& get_a_vector() const override {
        return a_key_;
    }

    /**
     * Setter function to store Relinearization Element Vector B.
     * Overrides base class implementation.
     *
     * @param b is the Element vector to be copied.
     */
    void set_b_vector(const std::vector<Element>& b) override {
        b_key_ = b;
    }

    /**
     * Setter function to store Relinearization Element Vector B.
     * Overrides base class implementation.
     *
     * @param b is the Element vector to be moved.
     */
    void set_b_vector(std::vector<Element>&& b) noexcept override {
        b_key_ = std::move(b);
    }

    /**
     * Getter function to access Relinearization Element Vector B.
     * Overrides base class implementation.
     *
     * @return Element vector B.
     */
    const std::vector<Element>& get_b_vector() const override {
        return b_key_;
    }

    /**
     * Releases the key material: clears both key vectors A and B.
     */
    void clear_keys() override {
        a_key_.clear();
        b_key_.clear();
    }

    /**
     * Compares this key with another evaluation key, which must be an EvalKeyRelinImpl.
     * Keys are equal if they share the crypto context (by pointer) and key tag and have equal A and B vectors.
     *
     * @param rhs the evaluation key to compare with
     * @return true if the keys are equal
     */
    bool key_compare(const EvalKeyImpl<Element>& rhs) const override {
        const auto& r = static_cast<const EvalKeyRelinImpl<Element>&>(rhs);
        return CryptoObject<Element>::operator==(rhs) && a_key_ == r.a_key_ && b_key_ == r.b_key_;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("ak", a_key_));
        ar(::cereal::make_nvp("bk", b_key_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("ak", a_key_));
        ar(::cereal::make_nvp("bk", b_key_));
    }

    std::string serialized_object_name() const override {
        return "EvalKeyRelin";
    }

    static uint32_t serialized_version() {
        return 1;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_KEY_RELIN_KEY_H_
