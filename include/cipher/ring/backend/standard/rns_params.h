//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

/*
  Wraps parameters for integer lattice operations using double-CRT representation. Inherits from ElementParams
 */

#ifndef CIPHER_RING_BACKEND_STANDARD_RNS_PARAMS_H_
#define CIPHER_RING_BACKEND_STANDARD_RNS_PARAMS_H_

#include <cstdint>
#include <iomanip>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend/standard/poly_params.h"
#include "cipher/ring/backend/element_params.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory_impl.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * @brief Parameters for array of ideal lattices (used for Double-CRT).
 *
 * The double-CRT representation of polynomials is a common optimization for
 * lattice encryption operations. Basically, it allows large-modulus polynamials
 * to be represented as multiple smaller-modulus polynomials. The double-CRT
 * representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology -
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 */
template <typename IntType>
class RnsParams final : public ElementParams<IntType> {
  public:
    using Integer = IntType;
    using NativePolyParams = PolyParamsImpl<NativeInteger>;

    /**
     * @brief Constructor building the tower chain for a target composite modulus: native primes of MAX_MODULUS_SIZE
     * bits are selected for the order, starting from the last such prime and going downwards, until their product
     * reaches modulus; the composite modulus is set to that product. A zero order creates an empty parameter set to
     * be populated later.
     *
     * @param corder the cyclotomic order.
     * @param modulus the lower bound on the composite modulus.
     * @param root_of_unity_value not used; the root of unity of each tower is computed from its modulus.
     */
    RnsParams(uint32_t corder, const IntType& modulus, const IntType& root_of_unity_value = IntType(0))
        : ElementParams<IntType>(corder, modulus) {
        // NOTE params generation uses this constructor to make an empty params that
        // it will later populate during the gen process. For that special case...
        // we don't populate, and we just return
        if (corder == 0)
            return;

        auto q{last_prime<NativeInteger>(MAX_MODULUS_SIZE, corder)};
        params_.reserve(32);
        params_.push_back(std::make_shared<NativePolyParams>(corder, q));

        IntType composite_modulus(1);
        while ((composite_modulus *= IntType(q.template convert_to_int<BasicInteger>())) < modulus)
            params_.push_back(std::make_shared<NativePolyParams>(corder, (q = previous_prime(q, corder))));
        ElementParams<IntType>::ciphertext_modulus_ = composite_modulus;
    }

    /**
     * @brief Constructor with basic parameter set.
     * q is selected as last_prime(bits, order)
     * @param corder the order of the ciphertext.
     * @param depth is the size of the tower.
     * @param bits is the number of bits of each tower's moduli.
     */
    explicit RnsParams(uint32_t corder = 0, uint32_t depth = 1, uint32_t bits = MAX_MODULUS_SIZE)
        : ElementParams<IntType>(corder, 0) {
        if (corder == 0)
            return;
        if (bits > MAX_MODULUS_SIZE)
            CIPHER_THROW("Invalid bits for ILDCRTParams");

        auto q{last_prime<NativeInteger>(bits, corder)};
        params_.reserve(depth);
        params_.push_back(std::make_shared<NativePolyParams>(corder, q));

        IntType composite_modulus(q.template convert_to_int<BasicInteger>());
        for (uint32_t _ = 1; _ < depth; ++_) {
            params_.push_back(std::make_shared<NativePolyParams>(corder, (q = previous_prime(q, corder))));
            composite_modulus *= IntType(q.template convert_to_int<BasicInteger>());
        }
        ElementParams<IntType>::ciphertext_modulus_ = composite_modulus;
    }

    /**
     * @brief Constructor with some pre-computed parameters provided as input.
     * @param corder the order of the ciphertext
     * @param moduli the list of the smaller moduli of the component polynomials.
     * @param roots_of_unity_value the list of the smaller roots of unity of the component
     * polynomials.
     */
    RnsParams(uint32_t corder, const std::vector<NativeInteger>& moduli,
                 const std::vector<NativeInteger>& roots_of_unity_value)
        : ElementParams<IntType>(corder, 0) {
        size_t limbs{moduli.size()};
        if (limbs != roots_of_unity_value.size())
            CIPHER_THROW("sizes of moduli and roots of unity do not match 1");

        params_.reserve(limbs);
        IntType composite_modulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            params_.push_back(std::make_shared<NativePolyParams>(corder, moduli[i], roots_of_unity_value[i]));
            composite_modulus *= IntType(moduli[i].template convert_to_int<BasicInteger>());
        }
        ElementParams<IntType>::ciphertext_modulus_ = composite_modulus;
    }

    /**
     * @brief Constructor with the moduli, roots of unity, big moduli and big roots of unity of the component
     * parameters (the big values are used for arbitrary cyclotomics); the composite modulus is the product of the
     * moduli. Throws if the four vectors differ in size.
     *
     * @param corder the cyclotomic order.
     * @param moduli the moduli of the component polynomials.
     * @param roots_of_unity_value the roots of unity of the component polynomials.
     * @param moduli_big the big moduli of the component polynomials.
     * @param roots_of_unity_big the big roots of unity of the component polynomials.
     */
    RnsParams(uint32_t corder, const std::vector<NativeInteger>& moduli,
                 const std::vector<NativeInteger>& roots_of_unity_value, const std::vector<NativeInteger>& moduli_big,
                 const std::vector<NativeInteger>& roots_of_unity_big)
        : ElementParams<IntType>(corder, 0) {
        size_t limbs{moduli.size()};
        if (limbs != roots_of_unity_value.size() || limbs != moduli_big.size() || limbs != roots_of_unity_big.size())
            CIPHER_THROW("sizes of moduli and roots of unity do not match 2");

        params_.reserve(limbs);
        IntType composite_modulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            params_.push_back(std::make_shared<NativePolyParams>(corder, moduli[i], roots_of_unity_value[i], moduli_big[i],
                                                                roots_of_unity_big[i]));
            composite_modulus *= IntType(moduli[i].template convert_to_int<BasicInteger>());
        }
        ElementParams<IntType>::ciphertext_modulus_ = composite_modulus;
    }

    /**
     * @brief Constructor with only cylotomic order and chain of moduli.
     * Multiplied values of the chain of moduli is automatically calculated. Root
     * of unity of the modulus is also calculated.
     *
     * @param corder the order of the ciphertext
     * @param moduli is the tower of moduli
     */
    RnsParams(uint32_t corder, const std::vector<NativeInteger>& moduli) : ElementParams<IntType>(corder, 0) {
        size_t limbs{moduli.size()};
        params_.reserve(limbs);
        IntType composite_modulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            params_.push_back(std::make_shared<NativePolyParams>(corder, moduli[i]));
            composite_modulus *= IntType(moduli[i].template convert_to_int<BasicInteger>());
        }
        ElementParams<IntType>::ciphertext_modulus_ = composite_modulus;
    }

    /**
     * @brief Constructor that takes in the cyclotomic order and the component
     * parameters of the component moduli.
     * @param corder the primary cyclotomic order.  This is not checked
     * against the component moduli.
     * @param params the componet parameters.
     */
    RnsParams(uint32_t corder, const std::vector<std::shared_ptr<NativePolyParams>>& params)
        : ElementParams<IntType>(corder, 0), params_(params) {
        recalculate_modulus();
    }

    RnsParams(const RnsParams& rhs) : ElementParams<IntType>(rhs), params_(rhs.params_) {}

    RnsParams(RnsParams&& rhs) noexcept
        : ElementParams<IntType>(std::move(rhs)), params_(std::move(rhs.params_)) {}

    /**
     * Assignment Operator.
     *
     * @param rhs the copied RnsParams.
     * @return the resulting RnsParams.
     */
    RnsParams& operator=(const RnsParams& rhs) {
        ElementParams<IntType>::operator=(rhs);
        params_ = rhs.params_;
        return *this;
    }

    RnsParams& operator=(RnsParams&& rhs) noexcept {
        ElementParams<IntType>::operator=(std::move(rhs));
        params_ = std::move(rhs.params_);
        return *this;
    }

    // ACCESSORS
    /**
     * @brief Getter method for the component parameters.
     * @return A vector of the component polynomial parameters.
     */
    const std::vector<std::shared_ptr<NativePolyParams>>& get_params() const {
        return params_;
    }

    /**
     * @brief Getter method that returns a subset of the component parameters.
     *
     * @param start The index of the first tower to include in the result.
     * @param end The index of the last tower to include.
     * @return A vector of the component polynomial parameters.
     */
    std::vector<std::shared_ptr<NativePolyParams>> get_param_partition(uint32_t start, uint32_t end) const {
        if (end < start || end >= params_.size())
            CIPHER_THROW("Incorrect parameters for GetParamPartition - (start: " + std::to_string(start) +
                          ", end:" + std::to_string(end) + ")");
        return std::vector<std::shared_ptr<NativePolyParams>>(params_.begin() + start, params_.begin() + end + 1);
    }

    /**
     * @brief Getter method for the component parameters of a specific index.
     * @param i the index of the parameters to return.  Note this this call is
     * unguarded if the index is out of bounds.
     * @return the parameters at index i.
     */
    std::shared_ptr<NativePolyParams>& operator[](size_t i) {
        return params_[i];
    }
    /**
     * @brief Const version of operator[](): the component parameters at index i, unguarded.
     *
     * @param i the index of the parameters to return.
     * @return the parameters at index i.
     */
    const std::shared_ptr<NativePolyParams>& operator[](size_t i) const {
        return params_[i];
    }

    /**
     * @brief Removes the last parameter set and adjust the multiplied moduli.
     *
     */

    void pop_last_param() {
        ElementParams<IntType>::ciphertext_modulus_ /=
                IntType(params_.back()->get_modulus().template convert_to_int<BasicInteger>());
        params_.pop_back();
    }

    /**
     * @brief Removes the first parameter set and adjust the multiplied moduli.
     *
     */
    void pop_first_param() {
        ElementParams<IntType>::ciphertext_modulus_ /=
                IntType(params_[0]->get_modulus().template convert_to_int<BasicInteger>());
        params_.erase(params_.begin());
    }

    /**
     * Destructor.
     */
    ~RnsParams() override = default;

    /**
     * @brief Equality operator checks if the ElementParams are the same.
     *
     * @param other ElementParams to compare against.
     * @return the equality check results.
     */
    bool operator==(const ElementParams<IntType>& other) const override {
        // ATTENTION: the following changes was made to fix failures in openfhe-python tests linked with clang++-18
        // ========================================================================================================
        // make sure that "other" is of the RnsParams<IntType> datatype as we have to "static_cast" it.
        // dynamic_cast doesn't work. only after removing "final" from RnsParams, dynamic_cast starts working.
        // it suggests that clang handles "final" differently in templates. most likely, it optimizes some things
        // more aggressively, which affects RTTI and base class behavior (especially in templates).
        if (typeid(other) != typeid(RnsParams<IntType>))
            return false;
        const auto& dcrt_params = static_cast<const RnsParams<IntType>&>(other);

        if (ElementParams<IntType>::operator==(dcrt_params) == false)
            return false;
        if (params_.size() != dcrt_params.params_.size())
            return false;
        for (size_t i = 0; i < params_.size(); ++i) {
            if (*params_[i] != *(dcrt_params.params_[i]))
                return false;
        }
        return true;
    }

    /**
     * @brief Method to recalculate the composite modulus from the component
     * moduli.
     */
    void recalculate_modulus() {
        ElementParams<IntType>::ciphertext_modulus_ = 1;
        for (size_t i = 0; i < params_.size(); ++i)
            ElementParams<IntType>::ciphertext_modulus_ *=
                    IntType(params_[i]->get_modulus().template convert_to_int<BasicInteger>());
    }

    /**
     * @brief Method to recalculate the big composite modulus from the component
     * moduli.
     */
    void recalculate_big_modulus() {
        ElementParams<IntType>::big_ciphertext_modulus_ = 1;
        for (size_t i = 0; i < params_.size(); ++i)
            ElementParams<IntType>::big_ciphertext_modulus_ *=
                    IntType(params_[i]->get_big_modulus().template convert_to_int<BasicInteger>());
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<ElementParams<IntType>>(this));
        ar(::cereal::make_nvp("p", params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<ElementParams<IntType>>(this));
        ar(::cereal::make_nvp("p", params_));
    }

    std::string serialized_object_name() const override {
        return "DCRTParams";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  protected:
    std::ostream& doprint(std::ostream& out) const override {
        out << "ILDCRTParams ";
        ElementParams<IntType>::doprint(out);
        out << std::endl << "  m_params:" << std::endl;
        for (size_t i = 0; i < params_.size(); ++i)
            out << "    " << i << ": " << *params_[i];
        return out << std::endl;
    }

  private:
    // array of smaller PolyParams
    std::vector<std::shared_ptr<NativePolyParams>> params_;
};

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_STANDARD_RNS_PARAMS_H_
