//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include "cipher/fhe/config/switching_params.h"

#include <iostream>

namespace cipher {

// clang-format off
std::ostream& operator<<(std::ostream& os, const SchSwchParams& obj) {
    os  << "securityLevelCKKS: " << obj.security_level_ckks
        << "; securityLevelFHEW: " << obj.security_level_fhew
        << "; numSlotsCKKS: " << obj.num_slots_ckks
        << "; numValues: " << obj.num_values
        << "; ctxtModSizeFHEWLargePrec: " << obj.ctxt_mod_size_fhew_large_prec
        << "; ctxtModSizeFHEWIntermedSwch: " << obj.ctxt_mod_size_fhew_intermed_swch
        << "; bStepLTrCKKStoFHEW: " << obj.b_step_l_tr_ckks_to_fhew
        << "; bStepLTrFHEWtoCKKS: " << obj.b_step_l_tr_fhew_to_ckks
        << "; levelLTrCKKStoFHEW: " << obj.level_l_tr_ckks_to_fhew
        << "; levelLTrFHEWtoCKKS: " << obj.level_l_tr_fhew_to_ckks
        << "; arbitraryFunctionEvaluation: " << obj.arbitrary_function_evaluation
        << "; useDynamicModeFHEW:" << obj.use_dynamic_mode_fhew
        << "; computeArgmin: " << obj.compute_argmin
        << "; oneHotEncoding: " << obj.one_hot_encoding
        << "; useAltArgmin: " << obj.use_alt_argmin
        << "; PARAMS SET UP INTERNALLY FROM CRYPTOCONTEXT:"
        << "  initialCKKSModulus: " << obj.initial_ckks_modulus
        << "; ringDimension: " << obj.ring_dimension_value
        << "; scalingModSize: " << obj.scaling_mod_size
        << "; batchSize: " << obj.batch_size;

    return os;
}
// clang-format on

}  // namespace cipher
