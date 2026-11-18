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

/*
  Represents and defines packing integers of plaintext objects into polynomial coefficients in OpenFHE
 */

#ifndef CIPHER_FHE_ENCODING_COEF_PACKED_H_
#define CIPHER_FHE_ENCODING_COEF_PACKED_H_

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "cipher/fhe/encoding/plaintext.h"

namespace cipher {

/**
 * @class CoefPackedEncoding
 * @brief Plaintext encoding that stores a vector of integers directly in the coefficients of the polynomial
 * (no SIMD packing), so that homomorphic multiplication computes polynomial products of the encoded vectors.
 */
class CoefPackedEncoding : public PlaintextImpl {
  private:
    std::vector<int64_t> value;

  protected:
    /**
     * @brief print_value() is called by operator<<
     * @param out stream to print to
     */
    void print_value(std::ostream& out) const override {
        out << "(";

        // for sanity's sake: get rid of all trailing zeroes and print "..." instead
        size_t i = value.size();
        bool all_zeroes = true;
        while (i > 0) {
            --i;
            if (value[i] != 0) {
                all_zeroes = false;
                break;
            }
        }

        if (all_zeroes == false) {
            for (size_t j = 0; j <= i; ++j)
                out << value[j] << ", ";
        }
        out << "... )";
    }

    /**
     * Method to compare two plaintext to test for equivalence
     * Testing that the plaintexts are of the same type done in operator==
     *
     * @param rhs - the other plaintext to compare to.
     * @return whether the two plaintext are equivalent.
     */
    bool compare_to(const PlaintextImpl& rhs) const override {
        if (typeid(rhs) != typeid(CoefPackedEncoding))
            return false;

        const auto& el = static_cast<const CoefPackedEncoding&>(rhs);
        return value == el.value;
    }

  public:
    /**
     * @brief Constructs an empty coefficient-packed plaintext over the given element parameters.
     * @param vp element parameters of the polynomial (Poly, NativePoly or RnsPoly parameters)
     * @param ep encoding parameters
     * @param scheme_id_value scheme the plaintext is created for
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, RnsPoly::Params>::value,
                                                  bool>::type = true>
    CoefPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, SCHEME scheme_id_value = SCHEME::INVALID_SCHEME)
        : PlaintextImpl(vp, ep, COEF_PACKED_ENCODING, scheme_id_value) {}

    /**
     * @brief Constructs a coefficient-packed plaintext holding the given coefficients (not encoded yet; call
     * Encode).
     * @param vp element parameters of the polynomial (Poly, NativePoly or RnsPoly parameters)
     * @param ep encoding parameters
     * @param coeffs the integer coefficients
     * @param scheme_id_value scheme the plaintext is created for
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, RnsPoly::Params>::value,
                                                  bool>::type = true>
    CoefPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, const std::vector<int64_t>& coeffs,
                       SCHEME scheme_id_value = SCHEME::INVALID_SCHEME)
        : PlaintextImpl(vp, ep, COEF_PACKED_ENCODING, scheme_id_value), value(coeffs) {}

    ~CoefPackedEncoding() override = default;

    /**
     * get_coef_packed_value
     * @return the un-encoded integer vector
     */
    const std::vector<int64_t>& get_coef_packed_value() const override {
        return value;
    }

    /**
     * set_int_vector_value
     * @param val integer vector to initialize the plaintext
     */
    void set_int_vector_value(const std::vector<int64_t>& val) override {
        value = val;
    }

    /**
     * Encode the plaintext into the Poly
     * @return true on success
     */
    bool encode() override;

    /**
     * Decode the Poly into the string
     * @return true on success
     */
    bool decode() override;

    /**
     * Get length of the plaintext
     *
     * @return number of elements in this plaintext
     */
    size_t get_length() const override {
        return value.size();
    }

    /**
     * set_length of the plaintext to the given size
     * @param siz the new number of elements
     */
    void set_length(size_t siz) override {
        value.resize(siz);
    }
};

} /* namespace cipher */

#endif  // CIPHER_FHE_ENCODING_COEF_PACKED_H_
