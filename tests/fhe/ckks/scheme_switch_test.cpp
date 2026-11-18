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

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "gtest/gtest.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/ckks/ser.h"
#include "cipher/fhe/ckks/utils.h"
#include "fhe/support/scheme_switching_data.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    SCHEME_SWITCH_CKKS_FHEW,
    SCHEME_SWITCH_FHEW_CKKS,
    SCHEME_SWITCH_COMPARISON,
    SCHEME_SWITCH_FUNC,
    SCHEME_SWITCH_ARGMIN,
    SCHEME_SWITCH_ALT_ARGMIN,
    SCHEME_SWITCH_SERIALIZE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case SCHEME_SWITCH_CKKS_FHEW:
            typeName = "SCHEME_SWITCH_CKKS_FHEW";
            break;
        case SCHEME_SWITCH_FHEW_CKKS:
            typeName = "SCHEME_SWITCH_FHEW_CKKS";
            break;
        case SCHEME_SWITCH_COMPARISON:
            typeName = "SCHEME_SWITCH_COMPARISON";
            break;
        case SCHEME_SWITCH_ARGMIN:
            typeName = "SCHEME_SWITCH_ARGMIN";
            break;
        case SCHEME_SWITCH_ALT_ARGMIN:
            typeName = "SCHEME_SWITCH_ALT_ARGMIN";
            break;
        case SCHEME_SWITCH_SERIALIZE:
            typeName = "SCHEME_SWITCH_SERIALIZE";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_SCHEMESWITCH {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    // ........
    std::vector<uint32_t> dim1;  // dim1_CF, dim1_FC
    uint32_t log_q;
    uint32_t num_values;
    uint32_t slots;
    bool one_hot;

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }
    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "testCaseType [" << test_case_type << "], " << params.to_string_impl();
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_SCHEMESWITCH>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================

constexpr uint32_t MULT_DEPTH1 = 13;
[[maybe_unused]] constexpr uint32_t MULT_DEPTH2 = 16;
constexpr uint32_t RDIM = 64;
constexpr uint32_t NUM_LRG_DIGS = 3;

#if CIPHER_NATIVE_INT == 128
constexpr uint32_t SMODSIZE = 70;
constexpr uint32_t FMODSIZE = 80;
#else
constexpr uint32_t SMODSIZE = 50;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_SCHEMESWITCH> test_cases = {
    // TestType,              Descr, Scheme,          RDim, MultDepth,   SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1,     LogQ, NumValues, Slots
    { SCHEME_SWITCH_CKKS_FHEW, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_CKKS_FHEW, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },

#endif
    // ==========================================
    // TestType,              Descr, Scheme,          RDim, MultDepth,   SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1,     LogQ, NumValues, Slots
    { SCHEME_SWITCH_FHEW_CKKS, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },

#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_FHEW_CKKS, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,   DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 27, 8, RDIM/2 },

#endif
    // ==========================================
    // TestType,               Descr, Scheme,          RDim, MultDepth,   SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1,     LogQ, NumValues, Slots
    { SCHEME_SWITCH_COMPARISON, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_COMPARISON, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_COMPARISON, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_COMPARISON, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#endif

    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1, LogQ, NumValues, Slots, OneHot
    { SCHEME_SWITCH_ARGMIN, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ARGMIN, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ARGMIN, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    { SCHEME_SWITCH_ARGMIN, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_ARGMIN, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    // { SCHEME_SWITCH_ARGMIN, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ARGMIN, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ARGMIN, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    // { SCHEME_SWITCH_ARGMIN, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1, LogQ, NumValues, Slots, OneHot
    { SCHEME_SWITCH_ALT_ARGMIN, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_ALT_ARGMIN, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    // { SCHEME_SWITCH_ALT_ARGMIN, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ALT_ARGMIN, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ALT_ARGMIN, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    // { SCHEME_SWITCH_ALT_ARGMIN, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_SERIALIZE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8},
    { SCHEME_SWITCH_SERIALIZE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8},
    { SCHEME_SWITCH_SERIALIZE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2},
    { SCHEME_SWITCH_SERIALIZE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2},
#if CIPHER_NATIVE_INT != 128
    { SCHEME_SWITCH_SERIALIZE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8},
    { SCHEME_SWITCH_SERIALIZE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8},
#endif
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_SCHEMESWITCH : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_SCHEMESWITCH> {
    using Element = RnsPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    // When working with binary or small values
    const double eps1 = 0.0001;
    // When working with conversion to FHEW of larger values, since it implies multiplying by a large value and modular approximation around zero
    const double eps2 = 0.05;

    // calculate_approximation_error() calculates the precision number (or approximation error).
    // The higher the precision, the less the error.
    double calculate_approximation_error(const std::vector<std::complex<double>>& result,
                                       const std::vector<std::complex<double>>& expected_result) {
        if (result.size() != expected_result.size())
            CIPHER_THROW("Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double max_error = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i] - expected_result[i]);
            if (max_error < error)
                max_error = error;
        }

        return std::abs(std::log2(max_error));
    }

    double calculate_approximation_error_int(const std::vector<int32_t>& result,
                                          const std::vector<int32_t>& expected_result) {
        if (result.size() != expected_result.size())
            CIPHER_THROW("Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double max_error = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i] - expected_result[i]);
            if (max_error < error)
                max_error = error;
        }

        return std::abs(std::log2(max_error));
    }

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<Element>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_scheme_switch_ckks_fhew(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->enable(SCHEMESWITCH);

            auto key_pair = cc->key_gen();

            SchSwchParams params;
            params.set_security_level_ckks(HEStd_NotSet);
            params.set_security_level_fhew(TOY);
            params.set_ctxt_mod_size_fhew_large_prec(test_data.log_q);
            params.set_num_slots_ckks(test_data.slots);
            params.set_b_step_l_tr_ckks_to_fhew(test_data.dim1[0]);
            auto private_key_fhew = cc->eval_ckks_to_fhew_setup(params);
            auto cc_lwe = cc->get_bin_cc_for_scheme_switch();
            cc->eval_ckks_to_fhew_key_gen(key_pair, private_key_fhew);

            auto modulus_lwe = 1 << test_data.log_q;
            auto p_lwe = modulus_lwe / (2 * cc_lwe->get_beta().convert_to_int());
            double scale = 1.0 / p_lwe;
            cc->eval_ckks_to_fhew_precompute(scale);

            auto input(Fill<double>({0, 1, -2, -3, p_lwe / 8.0, p_lwe / 4.0, p_lwe / 2.0, p_lwe / 1.0}, test_data.slots));

            size_t encoded_length = input.size();
            std::vector<int32_t> input_int(encoded_length);
            std::transform(input.begin(), input.end(), input_int.begin(), [&](const std::complex<double>& elem) {
                return static_cast<int32_t>(static_cast<int32_t>(std::round(elem.real())) % p_lwe);
            });

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input, 1, 0, nullptr, test_data.slots);
            auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext_after = cc->eval_ckks_to_fhew(ciphertext1, test_data.num_values);

            std::string failed = " Scheme switching from CKKS to FHEW for sparsely packed ciphertexts fails.";

            LwePlaintext result;
            for (uint32_t i = 0; i < ciphertext_after.size(); ++i) {
                cc_lwe->decrypt(private_key_fhew, ciphertext_after[i], &result, p_lwe);
                EXPECT_EQ(result, input_int[i]) << failed;
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_scheme_switch_fhew_ckks(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->enable(SCHEMESWITCH);

            auto key_pair = cc->key_gen();

            auto cc_lwe = std::make_shared<BooleanContext>();
            cc_lwe->BooleanContext::generate_boolean_context(TOY, false, test_data.log_q, 0, GINX, false);
            LwePrivateKey lwesk = cc_lwe->key_gen();

            std::vector<int32_t> x1(test_data.slots);
            std::vector<int32_t> x1_values{0, 0, 1, 1, 0, 0, 1, 1};
            std::copy(x1_values.begin(), x1_values.end(), x1.begin());
            std::vector<LweCiphertext> ctxts_lwe1(test_data.slots);
            auto modulus_lwe = 1 << test_data.log_q;
            for (uint32_t i = 0; i < test_data.slots; i++) {
                // encrypted under small plantext modulus p = 4 and ciphertext modulus
                ctxts_lwe1[i] = cc_lwe->encrypt(lwesk, x1[i], LARGE_DIM, 4, modulus_lwe);
            }

            std::vector<int32_t> x2(test_data.slots);
            std::vector<int32_t> x2_values{0, -1, 2, -3, 4, -8, 16, -32};
            std::copy(x2_values.begin(), x2_values.end(), x2.begin());
            std::vector<LweCiphertext> ctxts_lwe2(test_data.slots);
            uint32_t p_lwe = 1 << (test_data.log_q - 12);
            for (uint32_t i = 0; i < test_data.slots; i++) {
                // encrypted under larger plaintext modulus and large ciphertext modulus
                ctxts_lwe2[i] = cc_lwe->encrypt(lwesk, x2[i], LARGE_DIM, p_lwe, modulus_lwe);
            }

            cc->eval_fhew_to_ckks_setup(cc_lwe, test_data.slots, test_data.log_q);
            cc->eval_fhew_to_ckks_key_gen(key_pair, lwesk, test_data.num_values, test_data.num_values, test_data.dim1[1]);

            auto c_temp = cc->eval_fhew_to_ckks(ctxts_lwe1, test_data.num_values, test_data.slots);

            Plaintext plaintext_dec;
            cc->decrypt(key_pair.secret_key, c_temp, &plaintext_dec);
            plaintext_dec->set_length(test_data.num_values);

            check_equality(plaintext_dec->get_ckks_packed_value(), to_complex_double_vec(x1_values), eps1,
                          failmsg + " FHEW to CKKS fails for binary messages.");

            c_temp = cc->eval_fhew_to_ckks(ctxts_lwe2, test_data.num_values, test_data.slots, p_lwe, 0, p_lwe);

            cc->decrypt(key_pair.secret_key, c_temp, &plaintext_dec);
            plaintext_dec->set_length(test_data.num_values);

            check_equality(plaintext_dec->get_ckks_packed_value(), to_complex_double_vec(x2_values), eps2,
                          failmsg + " FHEW to CKKS fails for larger messages.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_scheme_switch_comparison(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                          const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->enable(SCHEMESWITCH);

            auto key_pair = cc->key_gen();

            SchSwchParams params;
            params.set_security_level_ckks(HEStd_NotSet);
            params.set_security_level_fhew(TOY);
            params.set_ctxt_mod_size_fhew_large_prec(test_data.log_q);
            params.set_num_slots_ckks(test_data.slots);
            params.set_num_values(test_data.num_values);
            params.set_one_hot_encoding(test_data.one_hot);
            params.set_b_step_l_tr_ckks_to_fhew(test_data.dim1[0]);
            params.set_b_step_l_tr_fhew_to_ckks(test_data.dim1[1]);
            auto private_key_fhew = cc->eval_scheme_switching_setup(params);
            auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

            cc_lwe->bt_key_gen(private_key_fhew);

            cc->eval_scheme_switching_key_gen(key_pair, private_key_fhew);

            std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
            std::vector<double> x2(test_data.slots, 5.25);

            Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, test_data.slots);
            Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2, 1, 0, nullptr, test_data.slots);

            auto c1 = cc->encrypt(key_pair.public_key, ptxt1);
            auto c2 = cc->encrypt(key_pair.public_key, ptxt2);

            auto c_diff = cc->eval_sub(c1, c2);

            auto modulus_lwe = 1 << test_data.log_q;
            auto p_lwe = modulus_lwe / (2 * cc_lwe->get_beta().convert_to_int());
            double scale_sign_fhew = 8.0;
            cc->eval_compare_switch_precompute(p_lwe, scale_sign_fhew);

            Plaintext p_diff;
            cc->decrypt(key_pair.secret_key, c_diff, &p_diff);
            std::vector<std::complex<double>> input_sign(test_data.num_values);
            p_diff->set_length(test_data.num_values);
            std::vector<double> v_diff(p_diff->get_real_packed_value());
            std::transform(v_diff.begin(), v_diff.end(), input_sign.begin(), [&](const std::complex<double>& elem) {
                return std::complex<double>(static_cast<int32_t>(std::round(elem.real() / eps1) * eps1 < 0), 0);
            });

            auto c_result = cc->eval_compare_scheme_switching(c1, c2, test_data.num_values, test_data.slots);

            Plaintext plaintext_dec;
            cc->decrypt(key_pair.secret_key, c_result, &plaintext_dec);
            plaintext_dec->set_length(test_data.num_values);

            check_equality(plaintext_dec->get_ckks_packed_value(), input_sign, eps1, failmsg + " EvalCompare fails.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_scheme_switch_argmin(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                      const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->enable(SCHEMESWITCH);

            auto key_pair = cc->key_gen();

            SchSwchParams params;
            params.set_security_level_ckks(HEStd_NotSet);
            params.set_security_level_fhew(TOY);
            params.set_ctxt_mod_size_fhew_large_prec(test_data.log_q);
            params.set_num_slots_ckks(test_data.slots);
            params.set_num_values(test_data.num_values);
            params.set_compute_argmin(true);
            params.set_one_hot_encoding(test_data.one_hot);
            params.set_b_step_l_tr_ckks_to_fhew(test_data.dim1[0]);
            params.set_b_step_l_tr_fhew_to_ckks(test_data.dim1[1]);
            auto private_key_fhew = cc->eval_scheme_switching_setup(params);
            auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

            cc->eval_scheme_switching_key_gen(key_pair, private_key_fhew);

            double scale_sign = 128.0;

            auto modulus_lwe = 1 << test_data.log_q;
            auto p_lwe = modulus_lwe / (2 * cc_lwe->get_beta().convert_to_int());
            cc->eval_compare_switch_precompute(p_lwe, scale_sign);

            std::vector<double> x1 = {-1.1, -1.05, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0};
            auto xmin = *std::min_element(x1.begin(), x1.begin() + test_data.num_values);
            auto xargmin = std::min_element(x1.begin(), x1.begin() + test_data.num_values) - x1.begin();

            Plaintext p1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, test_data.slots);
            auto c1 = cc->encrypt(key_pair.public_key, p1);

            auto result = cc->eval_min_scheme_switching(c1, key_pair.public_key, test_data.num_values, test_data.slots);

            Plaintext ptxt_min;
            cc->decrypt(key_pair.secret_key, result[0], &ptxt_min);
            ptxt_min->set_length(1);

            check_equality(ptxt_min->get_real_packed_value()[0], xmin, eps1);

            cc->decrypt(key_pair.secret_key, result[1], &ptxt_min);
            if (test_data.one_hot) {
                ptxt_min->set_length(test_data.num_values);

                std::vector<std::complex<double>> xargmin_oh(test_data.num_values);
                xargmin_oh[xargmin] = 1;
                check_equality(ptxt_min->get_ckks_packed_value(), xargmin_oh, eps1,
                              failmsg + " EvalMinSchemeSwitching fails.");
            } else {
                ptxt_min->set_length(1);
                check_equality(ptxt_min->get_real_packed_value()[0], static_cast<double>(xargmin), eps1);
            }

            // Uncomment to test the max+argmax functionality
            /* auto xmax    = *std::max_element(x1.begin(), x1.begin() + test_data.num_values);
            auto xargmax = std::max_element(x1.begin(), x1.begin() + test_data.num_values) - x1.begin();

            result =
                cc->eval_max_scheme_switching(c1, key_pair.public_key, test_data.num_values, test_data.slots);

            Plaintext ptxt_max;
            cc->decrypt(key_pair.secret_key, result[0], &ptxt_max);
            ptxt_max->set_length(1);
            check_equality(ptxt_max->get_real_packed_value()[0], xmax, eps1);

            cc->decrypt(key_pair.secret_key, result[1], &ptxt_max);
            if (test_data.one_hot) {
                ptxt_max->set_length(test_data.num_values);
                std::vector<std::complex<double>> xargmaxOH(test_data.num_values);
                xargmaxOH[xargmax] = 1;
                check_equality(ptxt_max->get_ckks_packed_value(), xargmaxOH, eps1,
                              failmsg + "eval_min_scheme_switching fails.");
            }
            else {
                ptxt_max->set_length(1);
                check_equality(ptxt_max->get_real_packed_value()[0], static_cast<double>(xargmax), eps1);
            }
            */
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_scheme_switch_alt_argmin(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->enable(SCHEMESWITCH);

            auto key_pair = cc->key_gen();

            SchSwchParams params;
            params.set_security_level_ckks(HEStd_NotSet);
            params.set_security_level_fhew(TOY);
            params.set_ctxt_mod_size_fhew_large_prec(test_data.log_q);
            params.set_num_slots_ckks(test_data.slots);
            params.set_num_values(test_data.num_values);
            params.set_compute_argmin(true);
            params.set_one_hot_encoding(test_data.one_hot);
            params.set_use_alt_argmin(true);
            params.set_b_step_l_tr_ckks_to_fhew(test_data.dim1[0]);
            params.set_b_step_l_tr_fhew_to_ckks(test_data.dim1[1]);
            auto private_key_fhew = cc->eval_scheme_switching_setup(params);
            auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

            cc->eval_scheme_switching_key_gen(key_pair, private_key_fhew);

            double scale_sign = 128.0;

            auto modulus_lwe = 1 << test_data.log_q;
            auto p_lwe = modulus_lwe / (2 * cc_lwe->get_beta().convert_to_int());
            cc->eval_compare_switch_precompute(p_lwe, scale_sign);

            std::vector<double> x1 = {-1.1, -1.05, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0};
            auto xmin = *std::min_element(x1.begin(), x1.begin() + test_data.num_values);
            auto xargmin = std::min_element(x1.begin(), x1.begin() + test_data.num_values) - x1.begin();

            Plaintext p1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, test_data.slots);
            auto c1 = cc->encrypt(key_pair.public_key, p1);

            auto result = cc->eval_min_scheme_switching_alt(c1, key_pair.public_key, test_data.num_values, test_data.slots);

            Plaintext ptxt_min;
            cc->decrypt(key_pair.secret_key, result[0], &ptxt_min);
            ptxt_min->set_length(1);

            check_equality(ptxt_min->get_real_packed_value()[0], xmin, eps1);

            cc->decrypt(key_pair.secret_key, result[1], &ptxt_min);
            if (test_data.one_hot) {
                ptxt_min->set_length(test_data.num_values);
                std::vector<std::complex<double>> xargmin_oh(test_data.num_values);
                xargmin_oh[xargmin] = 1;
                check_equality(ptxt_min->get_ckks_packed_value(), xargmin_oh, eps1,
                              failmsg + " EvalMinSchemeSwitching fails.");
            } else {
                ptxt_min->set_length(1);
                check_equality(ptxt_min->get_real_packed_value()[0], static_cast<double>(xargmin), eps1);
            }

            // Uncomment to test the max+argmax functionality
            /* auto xmax    = *std::max_element(x1.begin(), x1.begin() + test_data.num_values);
            auto xargmax = std::max_element(x1.begin(), x1.begin() + test_data.num_values) - x1.begin();

            result = cc->eval_max_scheme_switching_alt(c1, key_pair.public_key, test_data.num_values, test_data.slots);

            Plaintext ptxt_max;
            cc->decrypt(key_pair.secret_key, result[0], &ptxt_max);
            ptxt_max->set_length(1);
            check_equality(ptxt_max->get_real_packed_value()[0], xmax, eps1);

            cc->decrypt(key_pair.secret_key, result[1], &ptxt_max);
            if (test_data.one_hot) {
                ptxt_max->set_length(test_data.num_values);
                std::vector<std::complex<double>> xargmaxOH(test_data.num_values);
                xargmaxOH[xargmax] = 1;
                check_equality(ptxt_max->get_ckks_packed_value(), xargmaxOH, eps1,
                              failmsg + "eval_min_scheme_switching fails.");
            }
            else {
                ptxt_max->set_length(1);
                check_equality(ptxt_max->get_real_packed_value()[0], static_cast<double>(xargmax), eps1);
            }
            */
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_scheme_switch_serialize(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContextImpl<Element>::clear_eval_mult_keys();
            CryptoContextImpl<Element>::clear_eval_sum_keys();
            CryptoContextImpl<Element>::clear_eval_automorphism_keys();
            ContextFactory<Element>::release_all_contexts();

            CryptoContext<Element> cc_init(unit_test_generate_context(test_data.params));

            cc_init->enable(SCHEMESWITCH);

            SchSwchParams params;
            params.set_security_level_ckks(HEStd_NotSet);
            params.set_security_level_fhew(TOY);
            params.set_ctxt_mod_size_fhew_large_prec(test_data.log_q);
            params.set_num_slots_ckks(test_data.slots);
            params.set_num_values(test_data.num_values);
            params.set_compute_argmin(true);
            params.set_b_step_l_tr_ckks_to_fhew(test_data.dim1[0]);
            params.set_b_step_l_tr_fhew_to_ckks(test_data.dim1[1]);
            auto private_key_fhew_init = cc_init->eval_scheme_switching_setup(params);
            auto cc_lwe_init = cc_init->get_bin_cc_for_scheme_switch();

            auto key_pair_init = cc_init->key_gen();

            cc_init->eval_scheme_switching_key_gen(key_pair_init, private_key_fhew_init);
            auto swk_fhew_to_ckks_init = cc_init->get_swk_fc();

            std::vector<double> x1 = {-1.1, -1.05, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0};
            auto xmin = *std::min_element(x1.begin(), x1.begin() + test_data.num_values);
            auto xargmin = std::min_element(x1.begin(), x1.begin() + test_data.num_values) - x1.begin();

            Plaintext p1 = cc_init->make_ckks_packed_plaintext(x1, 1, 0, nullptr, test_data.slots);
            auto c1 = cc_init->encrypt(key_pair_init.public_key, p1);

            // Serialize all necessary objects
            SchemeSwitchingDataSerializer serializer(cc_init, key_pair_init.public_key, c1);
            serializer.to_stream();

            // Serialize secret key to verify correctness
            std::stringstream secret_key_stream;
            serialization::to_stream(key_pair_init.secret_key, secret_key_stream, SerType::BINARY);

            //====================================================================================================
            // Removed the serialized objects from the memory
            CryptoContextImpl<Element>::clear_eval_mult_keys();
            CryptoContextImpl<Element>::clear_eval_sum_keys();
            CryptoContextImpl<Element>::clear_eval_automorphism_keys();
            ContextFactory<Element>::release_all_contexts();
            //====================================================================================================
            // Deserialize all necessary objects
            SchemeSwitchingDataDeserializer deserializer;
            deserializer.from_stream();

            CryptoContext<RnsPoly> cc{deserializer.get_crypto_context_impl()};
            PublicKey<RnsPoly> client_public_key{deserializer.get_public_key_impl()};
            std::shared_ptr<cipher::BooleanContext> cc_lwe{cc->get_bin_cc_for_scheme_switch()};
            Ciphertext<RnsPoly> client_c{deserializer.get_raw_ciphertext()};

            // Deserialize the secret key for verification
            PrivateKey<Element> secret_key_for_verification;
            serialization::from_stream(secret_key_for_verification, secret_key_stream, SerType::BINARY);

            double scale_sign = 128.0;
            auto modulus_lwe = 1 << test_data.log_q;
            auto p_lwe = modulus_lwe / (2 * cc_lwe->get_beta().convert_to_int());
            cc->eval_compare_switch_precompute(p_lwe, scale_sign);

            auto result = cc->eval_min_scheme_switching(client_c, client_public_key, test_data.num_values, test_data.slots);

            Plaintext ptxt_min;
            cc->decrypt(secret_key_for_verification, result[0], &ptxt_min);
            ptxt_min->set_length(1);

            check_equality(ptxt_min->get_real_packed_value()[0], xmin, eps1);

            cc->decrypt(secret_key_for_verification, result[1], &ptxt_min);
            ptxt_min->set_length(test_data.num_values);

            std::vector<std::complex<double>> xargmin_oh(test_data.num_values);
            xargmin_oh[xargmin] = 1;
            check_equality(ptxt_min->get_ckks_packed_value(), xargmin_oh, eps1,
                          failmsg + " Serialization for scheme switching fails.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

//===========================================================================================================
TEST_P(UTCKKSRNS_SCHEMESWITCH, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case SCHEME_SWITCH_CKKS_FHEW:
            unit_test_scheme_switch_ckks_fhew(test, test.build_test_name());
            break;
        case SCHEME_SWITCH_FHEW_CKKS:
            unit_test_scheme_switch_fhew_ckks(test, test.build_test_name());
            break;
        case SCHEME_SWITCH_COMPARISON:
            unit_test_scheme_switch_comparison(test, test.build_test_name());
            break;
        case SCHEME_SWITCH_ARGMIN:
            unit_test_scheme_switch_argmin(test, test.build_test_name());
            break;
        case SCHEME_SWITCH_ALT_ARGMIN:
            unit_test_scheme_switch_alt_argmin(test, test.build_test_name());
            break;
        case SCHEME_SWITCH_SERIALIZE:
            unit_test_scheme_switch_serialize(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_SCHEMESWITCH, ::testing::ValuesIn(test_cases), testName);
