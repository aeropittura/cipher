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
  Manufactures plaintext objects in OpenFHE
 */

#ifndef CIPHER_FHE_ENCODING_PLAINTEXT_FACTORY_H_
#define CIPHER_FHE_ENCODING_PLAINTEXT_FACTORY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "cipher/fhe/encoding/encodings.h"
#include "cipher/fhe/config/scheme_id.h"

// TODO: when the parms are polymorphic, reduce the tuple of methods to a
// single one

namespace cipher {

/**
 * @class PlaintextFactory
 * @brief Static factory that creates plaintexts of a given encoding type (coefficient-packed, packed, string or
 * CKKS packed) over given element and encoding parameters.
 */
class PlaintextFactory {
    PlaintextFactory() = delete;  // never construct one!

  public:
    /**
     * @brief Creates an empty plaintext of the given encoding type.
     * @param encoding the encoding type
     * @param vp element parameters of the polynomial (Poly, NativePoly or RnsPoly parameters)
     * @param ep encoding parameters
     * @param scheme_id scheme the plaintext is created for (used by the coefficient-packed encoding)
     * @param cdt CKKS data type (used by the CKKS packed encoding)
     * @return the plaintext
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, RnsPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext make_plaintext(PlaintextEncodings encoding, std::shared_ptr<T> vp, EncodingParams ep,
                                   SCHEME scheme_id = SCHEME::INVALID_SCHEME, CkksDataType cdt = REAL) {
        switch (encoding) {
            case COEF_PACKED_ENCODING:
                return std::make_shared<CoefPackedEncoding>(vp, ep, scheme_id);
            case PACKED_ENCODING:
                return std::make_shared<PackedEncoding>(vp, ep);
            case STRING_ENCODING:
                return std::make_shared<StringEncoding>(vp, ep);
            case CKKS_PACKED_ENCODING:
                return std::make_shared<CKKSPackedEncoding>(vp, ep, cdt);
            default:
                CIPHER_THROW("Unknown plaintext encoding type in MakePlaintext");
        }
    }

    /**
     * @brief Creates and encodes a plaintext from an integer vector (packed or coefficient-packed encoding). The
     * vector may hold at most ring_dim values (ring_dim/2 for CKKS).
     * @param value the integer values to encode
     * @param encoding the encoding type
     * @param vp element parameters of the polynomial (Poly, NativePoly or RnsPoly parameters)
     * @param ep encoding parameters
     * @param scheme_id scheme the plaintext is created for
     * @param noise_scale_deg noise scale degree of the plaintext (BGV)
     * @param level level of the plaintext
     * @param scaling_factor integer scaling factor of the plaintext (BGV)
     * @return the encoded plaintext
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, RnsPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext make_plaintext(const std::vector<int64_t>& value, PlaintextEncodings encoding,
                                   std::shared_ptr<T> vp, EncodingParams ep, SCHEME scheme_id = SCHEME::INVALID_SCHEME,
                                   size_t noise_scale_deg = 1, uint32_t level = 0, NativeInteger scaling_factor = 1) {
        // Check if plaintext has got enough slots for data (value)
        uint32_t ring_dim = vp->get_ring_dimension();
        size_t value_size = value.size();
        if (is_ckks(scheme_id) && value_size > ring_dim / 2) {
            CIPHER_THROW("The size [" + std::to_string(value_size) +
                          "] of the vector with values should not be greater than ringDim/2 [" +
                          std::to_string(ring_dim / 2) + "] if the scheme is CKKS");
        } else if (value_size > ring_dim) {
            CIPHER_THROW("The size [" + std::to_string(value_size) +
                          "] of the vector with values should not be greater than ringDim [" + std::to_string(ring_dim) +
                          "] if the scheme is NOT CKKS");
        }
        Plaintext pt = make_plaintext(encoding, vp, ep, scheme_id);
        pt->set_int_vector_value(value);
        pt->set_noise_scale_deg(noise_scale_deg);
        pt->set_level(level);
        pt->set_scaling_factor_int(scaling_factor);
        pt->encode();
        return pt;
    }

    /**
     * @brief Creates and encodes a plaintext from a string (string encoding). The string may hold at most ring_dim
     * characters (ring_dim/2 for CKKS).
     * @param value the string to encode
     * @param encoding the encoding type
     * @param vp element parameters of the polynomial (Poly, NativePoly or RnsPoly parameters)
     * @param ep encoding parameters
     * @param scheme_id scheme the plaintext is created for
     * @param noise_scale_deg noise scale degree of the plaintext (BGV)
     * @param level level of the plaintext
     * @param scaling_factor integer scaling factor of the plaintext (BGV)
     * @return the encoded plaintext
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, RnsPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext make_plaintext(const std::string& value, PlaintextEncodings encoding, std::shared_ptr<T> vp,
                                   EncodingParams ep, SCHEME scheme_id = SCHEME::INVALID_SCHEME,
                                   size_t noise_scale_deg = 1, uint32_t level = 0, NativeInteger scaling_factor = 1) {
        // Check if plaintext has got enough slots for data (value)
        uint32_t ring_dim = vp->get_ring_dimension();
        size_t value_size = value.size();
        if (is_ckks(scheme_id) && value_size > ring_dim / 2) {
            CIPHER_THROW("The size [" + std::to_string(value_size) +
                          "] of the vector with values should not be greater than ringDim/2 [" +
                          std::to_string(ring_dim / 2) + "] if the scheme is CKKS");
        } else if (value_size > ring_dim) {
            CIPHER_THROW("The size [" + std::to_string(value_size) +
                          "] of the vector with values should not be greater than ringDim [" + std::to_string(ring_dim) +
                          "] if the scheme is NOT CKKS");
        }
        Plaintext pt = make_plaintext(encoding, vp, ep, scheme_id);
        pt->set_string_value(value);
        pt->set_noise_scale_deg(noise_scale_deg);
        pt->set_level(level);
        pt->set_scaling_factor_int(scaling_factor);
        pt->encode();
        return pt;
    }
};

} /* namespace cipher */

#endif  // CIPHER_FHE_ENCODING_PLAINTEXT_FACTORY_H_
