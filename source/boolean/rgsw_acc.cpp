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
  FHEW scheme (RingGSW accumulator) implementation
  The scheme is described in https://eprint.iacr.org/2014/816 and in Daniele Micciancio and Yuriy Polyakov
  "Bootstrapping in FHEW-like Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
  https://eprint.iacr.org/2020/086.

  Full reference to https://eprint.iacr.org/2014/816:
  @misc{cryptoeprint:2014:816,
    author = {Leo Ducas and Daniele Micciancio},
    title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
    howpublished = {Cryptology ePrint Archive, Report 2014/816},
    year = {2014},
    note = {\url{https://eprint.iacr.org/2014/816}},
 */

#include "cipher/boolean/rgsw_acc.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/boolean/rgsw_acc_common.h"

namespace cipher {

void RingGswAccumulator::signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const {
    signed_digit_decompose_impl(params, input, output, params->get_default_base_g_params());
}

void RingGswAccumulator::signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params,
                                              const std::vector<NativePoly>& input, std::vector<NativePoly>& output,
                                              uint32_t index) const {
    signed_digit_decompose_impl(params, input, output, params->get_base_g_params(index));
}

void RingGswAccumulator::signed_digit_decompose_impl(const std::shared_ptr<RingGswCryptoParams>& params,
                                                  const std::vector<NativePoly>& input, std::vector<NativePoly>& output,
                                                  const RingGswCryptoParams::BaseGParams& bp) const {
    excess_h_digit_decompose(params->get_Q().convert_to_int<BasicInteger>(), bp, input, output);
}

void RingGswAccumulator::signed_digit_decompose(const std::shared_ptr<RingGswCryptoParams>& params,
                                              const NativePoly& input, std::vector<NativePoly>& output) const {
    excess_h_digit_decompose(params->get_Q().convert_to_int<BasicInteger>(), params->get_default_base_g_params(), input, output);
}

};  // namespace cipher
