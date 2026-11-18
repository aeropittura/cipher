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
  base class for parameters for a lattice element
 */

#ifndef CIPHER_RING_BACKEND_ELEMENT_PARAMS_H_
#define CIPHER_RING_BACKEND_ELEMENT_PARAMS_H_

#include <cstdint>
#include <ostream>
#include <string>
#include <utility>

#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @class ElementParams
 * @brief Wrapper class to hold the parameters for Element types and their
 * inheritors.
 */
template <typename IntegerType>
class ElementParams : public Serializable {
  public:
    constexpr ElementParams() = default;
    virtual ~ElementParams() = default;

    /**
     * @brief Constructor taking the cyclotomic order and the ciphertext modulus; the ring dimension is set to the
     * totient of the order and the roots of unity and big modulus are left at zero.
     * @param order the cyclotomic order wrapped by the parameter set.
     * @param ct_modulus the ciphertext modulus wrapped by the parameter set.
     */
    ElementParams(uint32_t order, const IntegerType& ct_modulus)
        : ring_dimension_(static_cast<uint32_t>(get_totient(order))),
          cyclotomic_order_(order),
          ciphertext_modulus_(ct_modulus) {}

    /**
     * @brief Constructor taking the cyclotomic order, the ciphertext modulus and its root of unity; the ring
     * dimension is set to the totient of the order and the big modulus and big root of unity are left at zero.
     * @param order the cyclotomic order wrapped by the parameter set.
     * @param ct_modulus the ciphertext modulus wrapped by the parameter set.
     * @param r_unity the root of unity.
     */
    ElementParams(uint32_t order, const IntegerType& ct_modulus, const IntegerType& r_unity)
        : ring_dimension_(static_cast<uint32_t>(get_totient(order))),
          cyclotomic_order_(order),
          ciphertext_modulus_(ct_modulus),
          root_of_unity_(r_unity) {}

    /**
     * @brief Constructor taking the cyclotomic order, the ciphertext modulus and
     * root of unity, and the big ciphertext modulus and big root of unity used
     * for bit-packing operations.
     * @param order the cyclotomic order wrapped by the parameter set.
     * @param ct_modulus the ciphertext modulus wrapped by the parameter set.
     * @param r_unity the root of unity.
     * @param big_ct_modulus the big ciphertext modulus used for bit packing
     * operations.
     * @param big_r_unity the big root of unity used for bit packing operations.
     */
    ElementParams(uint32_t order, const IntegerType& ct_modulus, const IntegerType& r_unity, const IntegerType& big_ct_modulus,
               const IntegerType& big_r_unity)
        : ring_dimension_(static_cast<uint32_t>(get_totient(order))),
          cyclotomic_order_(order),
          ciphertext_modulus_(ct_modulus),
          root_of_unity_(r_unity),
          big_ciphertext_modulus_(big_ct_modulus),
          big_root_of_unity_(big_r_unity) {}

    ElementParams(const ElementParams& rhs) = default;
    ElementParams(ElementParams&& rhs) noexcept = default;
    ElementParams& operator=(const ElementParams& rhs) = default;
    ElementParams& operator=(ElementParams&& rhs) noexcept = default;

    /**
     * @brief Simple getter method for cyclotomic order.
     * @return The cyclotomic order.
     */
    uint32_t get_cyclotomic_order() const {
        return cyclotomic_order_;
    }

    /**
     * @brief Simple ring dimension getter method.  The ring dimension is the
     * evaluation of the totient function of the cyclotomic order.
     * @return the ring dimension.
     */
    uint32_t get_ring_dimension() const {
        return ring_dimension_;
    }

    /**
     * @brief Simple getter method for the ciphertext modulus, not the big
     * ciphertext modulus.
     * @return The ciphertext modulus, not the big ciphertext modulus.
     */
    const IntegerType& get_modulus() const {
        return ciphertext_modulus_;
    }

    /**
     * @brief Simpler getter method for the big ciphertext modulus.
     * This is not relevant for all applications.
     * @return The big ciphertext modulus.
     */
    const IntegerType& get_big_modulus() const {
        return big_ciphertext_modulus_;
    }

    /**
     * @brief Simple getter method for the root of unity, not the big root of
     * unity.
     * @return The root of unity, not the big root of unity.
     */
    const IntegerType& get_root_of_unity() const {
        return root_of_unity_;
    }

    /**
     * @brief Simple getter method for the big root of unity.
     * @return The the big root of unity.
     */
    const IntegerType& get_big_root_of_unity() const {
        return big_root_of_unity_;
    }

    /**
     * @brief Output strem operator.
     * @param out the preceding output stream.
     * @param item what to add to the output stream.
     * @return the appended output stream.
     */
    friend std::ostream& operator<<(std::ostream& out, const ElementParams& item) {
        return item.doprint(out);
    }

    /**
     * @brief Equality operator that tests the equality of all wrapped values.
     * @param other the other ElemenParams to compare to.
     * @return True if all elements are equal, and False otherwise.
     */
    virtual bool operator==(const ElementParams<IntegerType>& other) const {
        return ring_dimension_ == other.ring_dimension_ && cyclotomic_order_ == other.cyclotomic_order_ &&
               ciphertext_modulus_ == other.ciphertext_modulus_ && root_of_unity_ == other.root_of_unity_ &&
               big_ciphertext_modulus_ == other.big_ciphertext_modulus_ && big_root_of_unity_ == other.big_root_of_unity_;
    }

    /**
     * @brief Inequality operator that tests the equality of all wrapped values.
     * @param other the other ElemenParams to compare to.
     * @return False if all elements are equal, and True otherwise.
     */
    bool operator!=(const ElementParams<IntegerType>& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("co", cyclotomic_order_));
        ar(::cereal::make_nvp("rd", ring_dimension_));
        ar(::cereal::make_nvp("cm", ciphertext_modulus_));
        ar(::cereal::make_nvp("ru", root_of_unity_));
        ar(::cereal::make_nvp("bm", big_ciphertext_modulus_));
        ar(::cereal::make_nvp("br", big_root_of_unity_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version())
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        ar(::cereal::make_nvp("co", cyclotomic_order_));
        ar(::cereal::make_nvp("rd", ring_dimension_));
        ar(::cereal::make_nvp("cm", ciphertext_modulus_));
        ar(::cereal::make_nvp("ru", root_of_unity_));
        ar(::cereal::make_nvp("bm", big_ciphertext_modulus_));
        ar(::cereal::make_nvp("br", big_root_of_unity_));
    }

    std::string serialized_object_name() const override {
        return "ElemParams";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  protected:
    uint32_t ring_dimension_{0};
    uint32_t cyclotomic_order_{0};
    IntegerType ciphertext_modulus_{0};
    IntegerType root_of_unity_{0};
    IntegerType big_ciphertext_modulus_{0};  // Used for only some applications.
    IntegerType big_root_of_unity_{0};        // Used for only some applications.

    /**
     * @brief Pretty print operator for the ElementParams type.
     * @param out the output stream to print to
     * @return the resulting output stream.
     */
    virtual std::ostream& doprint(std::ostream& out) const {
        out << "[m=" << cyclotomic_order_ << " n=" << ring_dimension_ << " q=" << ciphertext_modulus_
            << " ru=" << root_of_unity_ << " bigq=" << big_ciphertext_modulus_ << " bigru=" << big_root_of_unity_ << "]";
        return out;
    }
};

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_ELEMENT_PARAMS_H_
