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

#ifndef CIPHER_BOOLEAN_BASE_PARAMS_H_
#define CIPHER_BOOLEAN_BASE_PARAMS_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/constants.h"
#include "cipher/ring/backend.h"
#include "cipher/boolean/lwe_ciphertext.h"
#include "cipher/boolean/lwe_params.h"
#include "cipher/boolean/lwe_switch_key.h"
#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/number_theory.h"
#include "cipher/boolean/rgsw_params.h"
#include "cipher/util/serializable.h"
#include "cipher/util/utilities.h"

namespace cipher {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class BooleanCryptoParams : public Serializable {
  public:
    BooleanCryptoParams() = default;

    /**
     * Main constructor for BooleanCryptoParams
     *
     * @param lweparams a shared poiter to an instance of LweCryptoParams
     * @param rgswparams a shared poiter to an instance of RingGswCryptoParams
     */
    BooleanCryptoParams(const std::shared_ptr<LweCryptoParams>& lweparams,
                       const std::shared_ptr<RingGswCryptoParams>& rgswparams)
        : lwe_params_(lweparams), rgsw_params_(rgswparams) {
        auto key_dist = lwe_params_->get_key_dist();
        if (key_dist != rgsw_params_->get_key_dist())
            CIPHER_THROW("LWE and RingGSW parameters disagree on the secret key distribution");
        if (key_dist != UNIFORM_TERNARY && key_dist != GAUSSIAN)
            CIPHER_THROW("BinFHE implements UNIFORM_TERNARY and GAUSSIAN secret key distributions only");
        if (rgsw_params_->get_method() == GINX && key_dist == GAUSSIAN)
            CIPHER_THROW("GINX/CGGI requires a ternary LWE secret key; use AP or LMKCDEY for GAUSSIAN");
        if (rgsw_params_->get_method() == LMKCDEY && rgsw_params_->get_num_auto_keys() >= lwe_params_->get_n())
            CIPHER_THROW("numAutoKeys must be less than the LWE dimension n");
        if ((2 * static_cast<uint64_t>(lwe_params_->get_N())) % lwe_params_->get_q().convert_to_int<uint64_t>() != 0)
            CIPHER_THROW("the LWE modulus q must divide 2N");
    }

    /**
     * Getter for LWE params
     * @return a shared pointer to the LWE crypto parameters
     */
    const std::shared_ptr<LweCryptoParams>& get_lwe_params() const {
        return lwe_params_;
    }

    /**
     * Getter for RingGSW params
     * @return a shared pointer to the RingGSW crypto parameters
     */
    const std::shared_ptr<RingGswCryptoParams>& get_ring_gsw_params() const {
        return rgsw_params_;
    }

    /**
     * Compare two BinFHE sets of parameters
     * @param other the parameters to compare with
     * @return true if the LWE and RingGSW parameters are both equal
     */
    bool operator==(const BooleanCryptoParams& other) const {
        return *lwe_params_ == *other.lwe_params_ && *rgsw_params_ == *other.rgsw_params_;
    }

    bool operator!=(const BooleanCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("lweparams", lwe_params_));
        ar(::cereal::make_nvp("rgswparams", rgsw_params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("lweparams", lwe_params_));
        ar(::cereal::make_nvp("rgswparams", rgsw_params_));
    }

    std::string serialized_object_name() const override {
        return "BinFHECryptoParams";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // shared pointer to an instance of LweCryptoParams
    std::shared_ptr<LweCryptoParams> lwe_params_{nullptr};

    // shared pointer to an instance of RGSWCryptoParams
    std::shared_ptr<RingGswCryptoParams> rgsw_params_{nullptr};
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_BASE_PARAMS_H_
