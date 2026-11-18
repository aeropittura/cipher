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

#ifndef CIPHER_TESTS_FHE_SUPPORT_CC_PARAMS_H_
#define CIPHER_TESTS_FHE_SUPPORT_CC_PARAMS_H_

#include <cmath>
#include <iosfwd>
#include <string>

#include "cipher/fhe/config/scheme_id.h"

enum { DFLT = -999 };  // enum for test cases if you want to use the default value for the parameter

//===========================================================================================================
struct TestContextParams {
    cipher::SCHEME scheme_id_value = cipher::INVALID_SCHEME;  // mandatory field indicating what scheme is used

    // all double values are just data holders. Having them we can use parameters' default values
    double ring_dimension_value = DFLT;      // CKKSRNS, BFVRNS, BGVRNS
    double multiplicative_depth = DFLT;      // CKKSRNS, BGVRNS
    double scaling_mod_size = DFLT;          // CKKSRNS, BFVRNS, BGVRNS
    double digit_size = DFLT;                // CKKSRNS, BFVRNS, BGVRNS
    double batch_size = DFLT;                // CKKSRNS, BFVRNS, BGVRNS
    double secret_key_dist = DFLT;           // CKKSRNS, BFVRNS, BGVRNS
    double max_relin_sk_deg = DFLT;          // CKKSRNS, BFVRNS, BGVRNS
    double first_mod_size_value = DFLT;      // CKKSRNS, BGVRNS
    double security_level = DFLT;            // BFVRNS, BGVRNS
    double ks_tech = DFLT;                   // CKKSRNS, BGVRNS
    double scal_tech = DFLT;                 // CKKSRNS, BGVRNS
    double num_large_digits = DFLT;          // CKKSRNS, BGVRNS
    double plaintext_modulus = DFLT;         // BFVRNS, BGVRNS
    double standard_deviation = DFLT;        // BFVRNS, BGVRNS
    double eval_add_count = DFLT;            // BFVRNS,
    double key_switch_count = DFLT;          // BFVRNS,
    double multiplication_technique = DFLT;  // BFVRNS,
    double encryption_technique = DFLT;      // BFVRNS,
    double pre_mode = DFLT;                  // BGVRNS, BFVRNS, CKKSRNS
    double multiparty_mode = DFLT;           // BGVRNS, BFVRNS
    double decryption_noise_mode = DFLT;     // CKKSRNS
    double execution_mode = DFLT;            // CKKSRNS
    double noise_estimate = DFLT;            // CKKSRNS
    double register_word_size = DFLT;        // CKKSRNS
    double composite_degree = DFLT;          // CKKSRNS
    double ckks_data_type = DFLT;            // CKKSRNS

    std::string to_string_impl() const;
};
//===========================================================================================================
std::ostream& operator<<(std::ostream& os, const TestContextParams& params);
//===========================================================================================================
inline bool is_default_value(double val) {
    return (DFLT == std::round(val));
}
//===========================================================================================================

#endif  // CIPHER_TESTS_FHE_SUPPORT_CC_PARAMS_H_
