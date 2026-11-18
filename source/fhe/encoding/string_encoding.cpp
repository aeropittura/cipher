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
  Represents and defines string-encoded plaintext objects in OpenFHE
 */

#include "cipher/fhe/encoding/string_encoding.h"

#include <cstdint>
#include <string>

namespace cipher {

static const size_t char_ptm = (1 << 8);
static const uint32_t CHARMARKER = (1 << 7);

bool StringEncoding::encode() {
    if (this->is_encoded_)
        return true;
    auto mod_value = this->encoding_params->get_plaintext_modulus();

    if (mod_value != 256) {
        CIPHER_THROW("Plaintext modulus must be " + std::to_string(char_ptm) + " for string encoding");
    }

    if (this->type_flag == IsNativePoly) {
        this->encoded_native_vector.set_values_to_zero();
        size_t i = 0;
        for (; i < ptx.size() && i < this->encoded_native_vector.get_length(); i++) {
            this->encoded_native_vector[i] = static_cast<uint32_t>(ptx[i]);
        }
        for (; i < this->encoded_native_vector.get_length(); i++) {
            this->encoded_native_vector[i] = CHARMARKER;
        }
    } else {
        this->encoded_vector.set_values_to_zero();
        size_t i = 0;
        for (; i < ptx.size() && i < this->encoded_vector.get_length(); i++) {
            this->encoded_vector[i] = static_cast<uint32_t>(ptx[i]);
        }
        for (; i < this->encoded_vector.get_length(); i++) {
            this->encoded_vector[i] = CHARMARKER;
        }
    }

    if (this->type_flag == IsDCRTPoly) {
        this->encoded_vector_dcrt = this->encoded_vector;
        this->encoded_vector_dcrt.set_format(Format::EVALUATION);
    }

    this->is_encoded_ = true;
    return true;
}

template <typename P>
static void fill_plaintext(const P& poly, std::string& str, const PlaintextModulus& mod_value) {
    str.clear();
    for (size_t i = 0; i < poly.get_length(); i++) {
        uint32_t ch = (poly[i].convert_to_int() % mod_value) & 0xff;
        if (ch == CHARMARKER)
            break;
        str += static_cast<char>(ch);
    }
}

bool StringEncoding::decode() {
    auto mod_value = this->encoding_params->get_plaintext_modulus();

    if (this->type_flag == IsNativePoly) {
        fill_plaintext(this->encoded_native_vector, this->ptx, mod_value);
        // clears the values containing information about the noise
        this->encoded_native_vector.set_values_to_zero();
    } else {
        fill_plaintext(this->encoded_vector, this->ptx, mod_value);
        // clears the values containing information about the noise
        this->encoded_vector.set_values_to_zero();
    }

    return true;
}

} /* namespace cipher */
