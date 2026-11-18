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

#include "fhe/support/cc_params.h"

#include <ostream>
#include <sstream>
#include <string>

std::string TestContextParams::to_string_impl() const {
    std::stringstream ss;
    ss << "schemeId [" << scheme_id_value << "], " << "ringDimension [" << ring_dimension_value << "], " << "multiplicativeDepth ["
       << multiplicative_depth << "], " << "scalingModSize [" << scaling_mod_size << "], " << "digitSize [" << digit_size
       << "], " << "batchSize [" << batch_size << "], " << "secretKeyDist [" << secret_key_dist << "], "
       << "maxRelinSkDeg [" << max_relin_sk_deg << "], " << "firstModSize [" << first_mod_size_value << "], " << "securityLevel ["
       << security_level << "], " << "ksTech [" << ks_tech << "], " << "scalTech [" << scal_tech << "], "
       << "numLargeDigits [" << num_large_digits << "], " << "plaintextModulus [" << plaintext_modulus << "], "
       << "standardDeviation [" << standard_deviation << "], " << "evalAddCount [" << eval_add_count << "], "
       << "keySwitchCount [" << key_switch_count << "], " << "multiplicationTechnique [" << multiplication_technique
       << "], " << "encryptionTechnique [" << encryption_technique << "], " << "PREMode [" << pre_mode << "], "
       << "multipartyMode [" << multiparty_mode << "], " << "decryptionNoiseMode [" << decryption_noise_mode << "], "
       << "executionMode [" << execution_mode << "], " << "noiseEstimate [" << noise_estimate << "], "
       << "registerWordSize [" << register_word_size << "], " << "compositeDegree [" << composite_degree << "] ";
    return ss.str();
}
//===========================================================================================================
std::ostream& operator<<(std::ostream& os, const TestContextParams& params) {
    return os << params.to_string_impl();
}
