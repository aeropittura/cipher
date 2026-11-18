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

#ifndef CIPHER_BOOLEAN_LWE_PARAMS_H_
#define CIPHER_BOOLEAN_LWE_PARAMS_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/constants.h"
#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores all parameters for the LWE scheme
 */
class LweCryptoParams : public Serializable {
  public:
    LweCryptoParams() = default;

    /**
     * Main constructor for LweCryptoParams
     *
     * @param n lattice parameter for additive LWE scheme
     * @param N ring dimension for RingGSW/RLWE used in bootstrapping
     * @param q modulus for additive LWE
     * @param Q modulus for RingGSW/RLWE used in bootstrapping
     * @param q_ks_value modulus for key switching
     * @param std standard deviation
     * @param base_ks the base used for key switching
     * @param key_dist the key distribution
     */
    explicit LweCryptoParams(uint32_t n, uint32_t N, NativeInteger q, NativeInteger Q, NativeInteger q_ks_value, double std,
                             uint32_t base_ks, SecretKeyDist key_dist = UNIFORM_TERNARY)
        : q_(q), Q_(Q), q_ks_(q_ks_value), n_(n), N_(N), base_ks_(base_ks), key_dist_(key_dist) {
        if (n_ == 0)
            CIPHER_THROW("m_n (lattice parameter) can not be zero");
        if (N_ == 0)
            CIPHER_THROW("m_N (ring dimension) can not be zero");
        if (q_ == 0)
            CIPHER_THROW("m_q (modulus for additive LWE) can not be zero");
        if (Q_ == 0)
            CIPHER_THROW("m_Q (modulus for RingGSW/RLWE) can not be zero");
        if (q_ks_value == 0)
            CIPHER_THROW("q_KS (modulus for key switching) can not be zero");
        if (base_ks_ == 0)
            CIPHER_THROW("m_baseKS (the base used for key switching) can not be zero");
        if (Q_.get_msb() > MAX_MODULUS_SIZE)
            CIPHER_THROW("Q.GetMSB() > MAX_MODULUS_SIZE");
        dgg_.set_std(std);
        ks_dgg_.set_std(std);
    }

    LweCryptoParams(const LweCryptoParams& rhs)
        : q_(rhs.q_),
          Q_(rhs.Q_),
          q_ks_(rhs.q_ks_),
          n_(rhs.n_),
          N_(rhs.N_),
          base_ks_(rhs.base_ks_),
          key_dist_(rhs.key_dist_) {
        dgg_.set_std(rhs.dgg_.get_std());
        ks_dgg_.set_std(rhs.ks_dgg_.get_std());
    }

    LweCryptoParams& operator=(const LweCryptoParams& rhs) {
        q_ = rhs.q_;
        Q_ = rhs.Q_;
        q_ks_ = rhs.q_ks_;
        n_ = rhs.n_;
        N_ = rhs.N_;
        base_ks_ = rhs.base_ks_;
        key_dist_ = rhs.key_dist_;
        dgg_.set_std(rhs.dgg_.get_std());
        ks_dgg_.set_std(rhs.ks_dgg_.get_std());
        return *this;
    }

    uint32_t get_n() const {
        return n_;
    }

    uint32_t get_N() const {
        return N_;
    }

    NativeInteger get_q() const {
        return q_;
    }

    NativeInteger get_Q() const {
        return Q_;
    }

    NativeInteger get_q_ks() const {
        return q_ks_;
    }

    uint32_t get_base_ks() const {
        return base_ks_;
    }

    /**
     * Gets the number of base-base_ks digits needed to represent a value below the key-switching modulus q_ks
     *
     * @return the digit count
     */
    uint32_t get_digit_count_ks() const {
        return get_digit_count(q_ks_.convert_to_int(), base_ks_);
    }

    /**
     * Gets the number of values the digit at position pos can take when a value below q_ks is written in base base_ks:
     * every position spans the whole base except the top one
     *
     * @param pos digit position, 0 being the least significant
     * @return the number of values the digit can take
     */
    uint32_t get_digit_extent_ks(uint32_t pos) const {
        const uint32_t digits = get_digit_count_ks();
        if (pos + 1 < digits)
            return base_ks_;
        uint64_t top{q_ks_.convert_to_int<uint64_t>() - 1};
        for (uint32_t k = 1; k < digits; ++k)
            top /= base_ks_;
        return static_cast<uint32_t>(top) + 1;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& get_dgg_impl() const {
        return dgg_;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& get_dgg_ks() const {
        return ks_dgg_;
    }

    SecretKeyDist get_key_dist() const {
        return key_dist_;
    }

    bool operator==(const LweCryptoParams& other) const {
        return n_ == other.n_ && N_ == other.N_ && q_ == other.q_ && Q_ == other.Q_ && q_ks_ == other.q_ks_ &&
               base_ks_ == other.base_ks_ && key_dist_ == other.key_dist_ && dgg_.get_std() == other.dgg_.get_std() &&
               ks_dgg_.get_std() == other.ks_dgg_.get_std();
    }

    bool operator!=(const LweCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("n", n_));
        ar(::cereal::make_nvp("N", N_));
        ar(::cereal::make_nvp("q", q_));
        ar(::cereal::make_nvp("Q", Q_));
        ar(::cereal::make_nvp("qKS", q_ks_));
        ar(::cereal::make_nvp("sigma", dgg_.get_std()));
        ar(::cereal::make_nvp("sigmaKS", ks_dgg_.get_std()));
        ar(::cereal::make_nvp("bKS", base_ks_));
        ar(::cereal::make_nvp("keyDist", key_dist_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }

        ar(::cereal::make_nvp("n", n_));
        ar(::cereal::make_nvp("N", N_));
        ar(::cereal::make_nvp("q", q_));
        ar(::cereal::make_nvp("Q", Q_));
        ar(::cereal::make_nvp("qKS", q_ks_));
        double sigma = 0;
        ar(::cereal::make_nvp("sigma", sigma));
        dgg_.set_std(sigma);
        double sigma_ks = 0;
        ar(::cereal::make_nvp("sigmaKS", sigma_ks));
        ks_dgg_.set_std(sigma_ks);
        ar(::cereal::make_nvp("bKS", base_ks_));
        ar(::cereal::make_nvp("keyDist", key_dist_));
    }

    std::string serialized_object_name() const override {
        return "LWECryptoParams";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // modulus for the additive LWE scheme
    NativeInteger q_;
    // modulus for the RingGSW/RingLWE scheme
    NativeInteger Q_;
    // modulus for key-switching
    NativeInteger q_ks_;
    // lattice parameter for the additive LWE scheme
    uint32_t n_;
    // ring dimension for RingGSW/RingLWE scheme
    uint32_t N_;
    // Base used in key switching
    uint32_t base_ks_;
    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist key_dist_{SecretKeyDist::UNIFORM_TERNARY};
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> dgg_;
    // Error distribution generator for key switching
    DiscreteGaussianGeneratorImpl<NativeVector> ks_dgg_;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_PARAMS_H_
