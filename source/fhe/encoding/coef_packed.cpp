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
  Represents and defines packing integers of plaintext objects into polynomial coefficients in Cipher
 */

#include "cipher/fhe/encoding/coef_packed.h"

#include <cstdint>
#include <vector>

#include "cipher/fhe/constants.h"

namespace cipher {

template <typename P>
inline static void encode_vec(P& poly, const PlaintextModulus& mod_value, int64_t lb, int64_t ub,
                              const std::vector<int64_t>& value, SCHEME scheme_id) {
    if (ub > INT32_MAX || lb < INT32_MIN)
        CIPHER_THROW("Cannot encode a coefficient larger than 32 bits");

    poly.set_values_to_zero();
    for (size_t i = 0; i < value.size() && i < poly.get_length(); i++) {
        if (value[i] <= lb || value[i] > ub)
            CIPHER_THROW("Cannot encode integer " + std::to_string(value[i]) + " at position " + std::to_string(i) +
                         " because it is out of range of plaintext modulus " + std::to_string(mod_value));

        if (value[i] < 0) {
            if (is_bfvrns(scheme_id)) {
                // TODO: Investigate why this doesn't work with q instead of t.
                uint64_t adjusted_val{mod_value - static_cast<uint64_t>(llabs(value[i]))};
                poly[i] = typename P::Integer(adjusted_val);
            } else {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                poly[i] = poly.get_modulus() - typename P::Integer(static_cast<uint64_t>(llabs(value[i])));
            }
        } else
            poly[i] = value[i];
    }
}

bool CoefPackedEncoding::encode() {
    if (this->is_encoded_)
        return true;

    PlaintextModulus mod_value = this->encoding_params->get_plaintext_modulus();
    NativeInteger original_sf = scaling_factor_int;
    for (size_t j = 1; j < noise_scale_deg; j++) {
        scaling_factor_int = scaling_factor_int.mod_mul(original_sf, mod_value);
    }

    if (this->type_flag == IsNativePoly) {
        encode_vec(this->encoded_native_vector, mod_value, low_bound(), high_bound(), this->value,
                   this->get_scheme_id());
        encoded_native_vector = encoded_native_vector.Times(scaling_factor_int);
    } else {
        encode_vec(this->encoded_vector, mod_value, low_bound(), high_bound(), this->value, this->get_scheme_id());

        if (this->type_flag == IsRnsPoly) {
            this->encoded_vector_dcrt = this->encoded_vector;
            encoded_vector_dcrt = encoded_vector_dcrt.Times(scaling_factor_int);
            this->encoded_vector_dcrt.set_format(Format::EVALUATION);
        }
    }

    this->is_encoded_ = true;
    return true;
}

template <typename P>
inline static void fill_vec(const P& poly, const PlaintextModulus& mod_value, std::vector<int64_t>& value) {
    value.clear();
    value.reserve(poly.get_length());

    int64_t half = int64_t(mod_value) / 2;
    const typename P::Integer& q = poly.get_modulus();
    typename P::Integer q_half = q >> 1;

    for (size_t i = 0; i < poly.get_length(); i++) {
        int64_t val;
        if (poly[i] > q_half)
            val = (-(q - poly[i]).convert_to_int());
        else
            val = poly[i].convert_to_int();
        if (val > half)
            val -= mod_value;
        value.push_back(val);
    }
}

bool CoefPackedEncoding::decode() {
    PlaintextModulus mod_value = this->encoding_params->get_plaintext_modulus();

    if (this->type_flag == IsNativePoly) {
        NativeInteger scf_inv = scaling_factor_int.mod_inverse(mod_value);
        NativePoly temp = encoded_native_vector.Times(scf_inv).mod(mod_value);
        fill_vec(temp, mod_value, this->value);
        // clears the values containing information about the noise
        encoded_native_vector.set_values_to_zero();
    } else {
        fill_vec(this->encoded_vector, mod_value, this->value);
        // clears the values containing information about the noise
        this->encoded_vector.set_values_to_zero();
    }

    return true;
}

} /* namespace cipher */
