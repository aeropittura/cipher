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

#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "include/gtest/gtest.h"
#include "cipher/util/exception.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    CKKSRNS_TEST = 0,
    BFVRNS_TEST,
    BGVRNS_TEST,
    BFVRNS_TEST_EXTRA,
    TEST_ABORTS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case CKKSRNS_TEST:
            typeName = "CKKSRNS_TEST";
            break;
        case BFVRNS_TEST:
            typeName = "BFVRNS_TEST";
            break;
        case BGVRNS_TEST:
            typeName = "BGVRNS_TEST";
            break;
        case BFVRNS_TEST_EXTRA:
            typeName = "BFVRNS_TEST_EXTRA";
            break;
        case TEST_ABORTS:
            typeName = "TEST_ABORTS";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_MULTIPARTY {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    bool star;
    uint32_t slots = 0;

    // specific parameters for threhold FHE aborts
    std::string sharing_scheme = "additive";

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_MULTIPARTY>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_MULTIPARTY& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t BATCH = 16;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_MULTIPARTY> test_cases = {
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode,  Star, Slots, sharing_scheme
    { CKKSRNS_TEST, "01", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "02", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "03", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "04", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "05", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "06", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "07", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "08", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
#if CIPHER_NATIVE_INT != 128
    { CKKSRNS_TEST, "09", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "10", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "11", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "12", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,    0, "NA"},
    { CKKSRNS_TEST, "13", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "14", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "15", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
    { CKKSRNS_TEST, "16", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,     0, "NA"},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode,  Star, Slots, sharing_scheme
    { CKKSRNS_TEST, "21", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "22", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "23", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "24", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "25", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "26", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "27", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "28", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
#if CIPHER_NATIVE_INT != 128
    { CKKSRNS_TEST, "29", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "30", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "31", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "32", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   16, "NA"},
    { CKKSRNS_TEST, "33", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "34", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "35", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
    { CKKSRNS_TEST, "36", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    16, "NA"},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode,  Star, Slots, sharing_scheme
    { CKKSRNS_TEST, "41", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "42", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "43", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "44", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "45", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "46", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "47", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "48", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
#if CIPHER_NATIVE_INT != 128
    { CKKSRNS_TEST, "49", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "50", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "51", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "52", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false,   32, "NA"},
    { CKKSRNS_TEST, "53", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "54", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "55", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
    { CKKSRNS_TEST, "56", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,    32, "NA"},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode,  Star, Slots, sharing_scheme
    { CKKSRNS_TEST, "61", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "62", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "63", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "64", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "65", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "66", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "67", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "68", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
#if CIPHER_NATIVE_INT != 128
    { CKKSRNS_TEST, "69", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "70", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "71", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "72", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "73", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "74", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "75", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    { CKKSRNS_TEST, "76", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    true,  1024, "NA"},
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode,  Star, Slots, sharing_scheme
    { CKKSRNS_TEST, "77", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},    false, 1024, "NA"},
    { CKKSRNS_TEST, "78", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT},     true, 1024, "NA"},
    { CKKSRNS_TEST, "79", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 2},    false, 1024, "NA"},
    { CKKSRNS_TEST, "80", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 2},     true, 1024, "NA"},
    { CKKSRNS_TEST, "81", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,            60,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32},    false, 1024, "NA"},
    { CKKSRNS_TEST, "82", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,            60,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32},     true, 1024, "NA"},
    { CKKSRNS_TEST, "83", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 2},    false, 512, "NA"},
    { CKKSRNS_TEST, "84", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 2},     true, 512, "NA"},
    { CKKSRNS_TEST, "85", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, 4},    false, 512, "NA"},
    { CKKSRNS_TEST, "86", {CKKSRNS_SCHEME, 2048, 2,        118,       3,    BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, 4},     true, 512, "NA"},
#endif
    // ==========================================
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,     LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech,         EncTech,  pre_mode, MultipartyMode,             Star, Slots, sharing_scheme
    { BFVRNS_TEST, "01", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "02", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "03", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "04", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "05", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "06", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "07", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "08", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "09", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "10", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "11", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "12", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "13", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "14", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "15", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "16", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "17", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "18", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "19", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "20", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "21", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "22", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "23", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "24", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BFVRNS_TEST, "25", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "26", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "27", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "28", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "29", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "30", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "31", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "32", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BFVRNS_TEST, "33", {BFVRNS_SCHEME,   1024, DFLT,      49,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "34", {BFVRNS_SCHEME,   1024, DFLT,      49,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "35", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "36", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "37", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "38", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "39", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "40", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "41", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "42", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "43", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "44", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "45", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "46", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "47", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "48", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "49", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "50", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "51", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "52", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "53", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "54", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "55", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "56", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BFVRNS_TEST, "57", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "58", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "59", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "60", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "61", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "62", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "63", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BFVRNS_TEST, "64", {BFVRNS_SCHEME,   1024, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT, HEStd_NotSet,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    // ==========================================
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode,             Star, Slots, sharing_scheme
    { BGVRNS_TEST, "01", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "02", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "03", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "04", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "05", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "06", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "07", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "08", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "09", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "10", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "11", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "12", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "13", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "14", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "15", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "16", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "17", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "18", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "19", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "20", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "21", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "22", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "23", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "24", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "25", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "26", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "27", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "28", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    false,    0, "NA"},
    { BGVRNS_TEST, "29", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "30", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "31", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "32", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    FIXED_NOISE_MULTIPARTY},    true,     0, "NA"},
    { BGVRNS_TEST, "33", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "34", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "35", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "36", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "37", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "38", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "39", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "40", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "41", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "42", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "43", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "44", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "45", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "46", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "47", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "48", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "49", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "50", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "51", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "52", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "53", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "54", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "55", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "56", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "57", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "58", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "59", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "60", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, false,    0, "NA"},
    { BGVRNS_TEST, "61", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "62", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "63", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    { BGVRNS_TEST, "64", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    NOISE_FLOODING_MULTIPARTY}, true,     0, "NA"},
    // ==========================================
    // TestType,         Descr, Scheme,        RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,     LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech,         EncTech,  pre_mode, Star, Slots, sharing_scheme
    { BFVRNS_TEST_EXTRA, "01", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "02", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "03", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "04", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "05", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "06", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "07", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "08", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "09", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "10", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "11", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "12", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "13", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "14", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "15", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT},   false,    0, "NA"},
    { BFVRNS_TEST_EXTRA, "16", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT},   false,    0, "NA"},
     // ==========================================
    // TestType,   Descr, Scheme,         RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,     LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech,        EncTech,  pre_mode, MultipartyMode, Star, Slots, sharing_scheme
    { TEST_ABORTS, "01", {BFVRNS_SCHEME,  1024, 2,         DFLT,     DFLT,  BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "02", {BFVRNS_SCHEME,  1024, 2,         DFLT,     DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     HEStd_NotSet, DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "03", {BFVRNS_SCHEME,  1024, 2,         DFLT,     DFLT,  BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    { TEST_ABORTS, "04", {BFVRNS_SCHEME,  1024, 2,         DFLT,     DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     HEStd_NotSet, DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    { TEST_ABORTS, "05", {BGVRNS_SCHEME,  1024, 2,         DFLT,     3,     BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "06", {BGVRNS_SCHEME,  1024, 2,         DFLT,     3,     BATCH,   UNIFORM_TERNARY, DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "07", {BGVRNS_SCHEME,  1024, 2,         DFLT,     3,     BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    { TEST_ABORTS, "08", {BGVRNS_SCHEME,  1024, 2,         DFLT,     3,     BATCH,   UNIFORM_TERNARY, DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    { TEST_ABORTS, "09", {CKKSRNS_SCHEME, 1024, 2,         50,       3,     BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     DFLT,         DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "10", {CKKSRNS_SCHEME, 1024, 2,         50,       3,     BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     HEStd_NotSet, BV,     DFLT,         DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "shamir"},
    { TEST_ABORTS, "11", {CKKSRNS_SCHEME, 1024, 2,         50,       3,     BATCH,   GAUSSIAN,        DFLT,          DFLT,     HEStd_NotSet, BV,     DFLT,         DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    { TEST_ABORTS, "12", {CKKSRNS_SCHEME, 1024, 2,         50,       3,     BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     HEStd_NotSet, BV,     DFLT,         DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,            DFLT,     DFLT,     DFLT},        false,    0, "additive"},
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTGENERAL_MULTIPARTY : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_MULTIPARTY> {
    using Element = RnsPoly;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }
    void TearDown() {
        ContextFactory<Element>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    // in order to avoid redundancy, unit_test_multi_party() uses 2 conditions:
    //  - test_data.star false/true
    //  - CKKSRNS_TEST false/true
    // runs for two parties only
    void unit_test_multi_party(const TEST_CASE_UTGENERAL_MULTIPARTY& test_data,
                               const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            const double eps = 0.000001;
            std::vector<int32_t> indices = {2};
            //====================================================================
            KeyPair<Element> kp1 = cc->key_gen();

            auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);
            cc->eval_sum_key_gen(kp1.secret_key);
            auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<Element>>>(
                    cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));
            cc->eval_at_index_key_gen(kp1.secret_key, indices);
            auto eval_at_index_keys = std::make_shared<std::map<uint32_t, EvalKey<Element>>>(
                    cc->get_eval_automorphism_key_map(kp1.secret_key->get_key_tag()));
            //====================================================================

            KeyPair<Element> kp2 = test_data.star ? cc->multiparty_key_gen(kp1.public_key) :
                                                    cc->multiparty_key_gen(kp1.public_key, false, true);

            auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);
            auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());
            auto eval_mult_bab = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
            auto eval_sum_keys_b =
                    cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());
            auto eval_sum_keys_join =
                    cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());
            cc->insert_eval_sum_key(eval_sum_keys_join);

            auto eval_at_index_keys_b = cc->multi_eval_at_index_key_gen(kp2.secret_key, eval_at_index_keys, indices,
                                                                        kp2.public_key->get_key_tag());
            auto eval_at_index_keys_join = cc->multi_add_eval_automorphism_keys(
                    eval_at_index_keys, eval_at_index_keys_b, kp2.public_key->get_key_tag());
            cc->insert_eval_automorphism_key(eval_at_index_keys_join);

            auto eval_mult_aab = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
            auto eval_mult_final = cc->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab,
                                                                (CKKSRNS_TEST == test_data.test_case_type) ?
                                                                        eval_mult_ab->get_key_tag() :
                                                                        kp2.public_key->get_key_tag());
            cc->insert_eval_mult_key({eval_mult_final});
            //====================================================================
            std::vector<PrivateKey<Element>> secret_keys{kp1.secret_key, kp2.secret_key};
            KeyPair<Element> kp_multiparty = cc->multiparty_key_gen(secret_keys);
            if (!kp_multiparty.good())
                CIPHER_THROW("Key generation failed");

            ////////////////////////////////////////////////////////////
            // Encode source data
            ////////////////////////////////////////////////////////////
            std::vector<int64_t> vector_of_ints1{1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
            std::vector<int64_t> vector_of_ints2{1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vector_of_ints3{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

            size_t encoded_length = vector_of_ints1.size();
            std::vector<int64_t> sum_input(encoded_length, 0);
            std::vector<int64_t> mult_input(encoded_length, 0);
            for (uint32_t i = 0; i < encoded_length; ++i) {
                sum_input[i] = vector_of_ints1[i] + vector_of_ints2[i] + vector_of_ints3[i];
                mult_input[i] = vector_of_ints1[i] * vector_of_ints3[i];
            }

            std::vector<int64_t> eval_sum_input(encoded_length, 0);
            std::vector<int64_t> rotate_input(encoded_length, 0);
            if (CKKSRNS_TEST == test_data.test_case_type) {
                // For CKKS there is different logic, depending on slots value
                uint32_t slots = (test_data.slots != 0) ? test_data.slots :
                                 (BATCH != 0)           ? BATCH :
                                                          cc->get_ring_dimension() / 2;
                for (uint32_t i = 0; i < encoded_length; ++i) {
                    eval_sum_input[i] = 0;
                    // we add to eval_sum_input[i] value vector_of_ints3[(i + j) % BATCH];
                    for (uint32_t j = 0; j < BATCH; ++j) {
                        if ((i + j) % slots < encoded_length) {
                            eval_sum_input[i] += vector_of_ints3[(i + j) % slots];
                        }
                    }
                }

                for (uint32_t i = 0; i < encoded_length; ++i) {
                    if ((slots + i + indices[0]) % slots < encoded_length) {
                        rotate_input[i] = vector_of_ints1[(slots + i + indices[0]) % slots];
                    }
                }
            } else {
                // For BGV and BFV no slots is given
                for (uint32_t i = 0, rev = (encoded_length - 1); i < encoded_length; ++i, --rev) {
                    if (i == 0)
                        eval_sum_input[rev] = vector_of_ints3[rev];
                    else
                        eval_sum_input[rev] = eval_sum_input[rev + 1] + vector_of_ints3[rev];
                    if (i + indices[0] > encoded_length - 1)
                        rotate_input[i] = 0;
                    else
                        rotate_input[i] = vector_of_ints1[i + indices[0]];
                }
            }

            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);
            Plaintext plaintext3(nullptr);
            Plaintext plaintext_sum_input(nullptr);
            Plaintext plaintext_mult_input(nullptr);
            Plaintext plaintext_eval_sum_input(nullptr);
            Plaintext plaintext_rotate_input(nullptr);
            if (CKKSRNS_TEST == test_data.test_case_type) {
                // TODO (dsuponit): we have to rename make_ckks_packed_plaintext() to make_packed_plaintext(). All of them have different input params
                // for CKKS we need to convert vectors of integers to vectors of complex numbers
                plaintext1 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints1), 1, 0, nullptr,
                                                            test_data.slots);
                plaintext2 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints2), 1, 0, nullptr,
                                                            test_data.slots);
                plaintext3 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints3), 1, 0, nullptr,
                                                            test_data.slots);
                plaintext_sum_input = cc->make_ckks_packed_plaintext(to_complex_double_vec(sum_input), 1, 0, nullptr,
                                                                     test_data.slots);
                plaintext_mult_input = cc->make_ckks_packed_plaintext(to_complex_double_vec(mult_input), 1, 0, nullptr,
                                                                      test_data.slots);
                plaintext_eval_sum_input = cc->make_ckks_packed_plaintext(to_complex_double_vec(eval_sum_input), 1, 0,
                                                                          nullptr, test_data.slots);
                plaintext_rotate_input = cc->make_ckks_packed_plaintext(to_complex_double_vec(rotate_input), 1, 0,
                                                                        nullptr, test_data.slots);
            } else {
                plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
                plaintext2 = cc->make_packed_plaintext(vector_of_ints2);
                plaintext3 = cc->make_packed_plaintext(vector_of_ints3);
                plaintext_sum_input = cc->make_packed_plaintext(sum_input);
                plaintext_mult_input = cc->make_packed_plaintext(mult_input);
                plaintext_eval_sum_input = cc->make_packed_plaintext(eval_sum_input);
                plaintext_rotate_input = cc->make_packed_plaintext(rotate_input);
            }
            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto pub_key_for_encryption = test_data.star ? kp2.public_key :
                                                           cc->multi_add_pub_keys(kp1.public_key, kp2.public_key,
                                                                                  kp2.public_key->get_key_tag());
            Ciphertext<Element> ciphertext1 = cc->encrypt(pub_key_for_encryption, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(pub_key_for_encryption, plaintext2);
            Ciphertext<Element> ciphertext3 = cc->encrypt(pub_key_for_encryption, plaintext3);

            ////////////////////////////////////////////////////////////
            // eval_add Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////
            Ciphertext<Element> ciphertext_add12 = cc->eval_add(ciphertext1, ciphertext2);
            Ciphertext<Element> ciphertext_add123 = cc->eval_add(ciphertext_add12, ciphertext3);

            auto ciphertext_mult = cc->eval_mult(ciphertext1, ciphertext3);
            if (CKKSRNS_TEST == test_data.test_case_type) {
                ciphertext_mult = cc->mod_reduce(ciphertext_mult);
                ciphertext1 = cc->eval_mult(ciphertext1, 1);
            }
            auto ciphertext_eval_sum = cc->eval_sum(ciphertext3, BATCH);
            auto ciphertext_rotate = cc->eval_at_index(ciphertext1, indices[0]);

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Encrypted Data
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_add_new;
            cc->decrypt(kp_multiparty.secret_key, ciphertext_add123, &plaintext_add_new);
            plaintext_add_new->set_length(plaintext1->get_length());

            // TODO (dsuponit): we have to rename get_ckks_packed_value() to get_packed_value(). it should be an override of the virtual function in plaintext.h
            std::string err_msg = failmsg + " accumulation failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_add_new->get_ckks_packed_value(), plaintext_sum_input->get_ckks_packed_value(),
                               eps, err_msg);
            } else {
                check_equality(plaintext_add_new->get_packed_value(), plaintext_sum_input->get_packed_value(), eps,
                               err_msg);
            }
            //====================================================================
            Plaintext plaintext_mult;
            cc->decrypt(kp_multiparty.secret_key, ciphertext_mult, &plaintext_mult);
            plaintext_mult->set_length(plaintext1->get_length());

            err_msg = failmsg + " multiplication failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_mult->get_ckks_packed_value(), plaintext_mult_input->get_ckks_packed_value(),
                               eps, err_msg);
            } else {
                check_equality(plaintext_mult->get_packed_value(), plaintext_mult_input->get_packed_value(), eps,
                               err_msg);
            }
            //====================================================================
            Plaintext plaintext_rotate;
            cc->decrypt(kp_multiparty.secret_key, ciphertext_rotate, &plaintext_rotate);
            plaintext_rotate->set_length(plaintext1->get_length());

            err_msg = failmsg + " rotation failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_rotate->get_ckks_packed_value(),
                               plaintext_rotate_input->get_ckks_packed_value(), eps, err_msg);
            } else {
                check_equality(plaintext_rotate->get_packed_value(), plaintext_rotate_input->get_packed_value(), eps,
                               err_msg);
            }

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Encrypted Data with Multiparty
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_multiparty_new;
            auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_add123}, kp1.secret_key);
            auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_add123}, kp2.secret_key);
            std::vector<Ciphertext<Element>> partial_ciphertext_vec{ciphertext_partial1[0], ciphertext_partial2[0]};
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty_new);
            plaintext_multiparty_new->set_length(plaintext1->get_length());

            err_msg = failmsg + " Multiparty accumulation failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                std::stringstream buffer;
                buffer << "should be: " << plaintext_multiparty_new->get_ckks_packed_value()
                       << " - we get: " << plaintext_sum_input->get_ckks_packed_value();

                check_equality(plaintext_multiparty_new->get_ckks_packed_value(),
                               plaintext_sum_input->get_ckks_packed_value(), eps, err_msg + buffer.str());
            } else {
                check_equality(plaintext_multiparty_new->get_packed_value(), plaintext_sum_input->get_packed_value(),
                               eps, err_msg);
            }
            //====================================================================
            if (BGVRNS_TEST == test_data.test_case_type && test_data.star) {  // TODO (dsuponit): is this necessary???
                uint32_t target_towers = (test_data.params.scal_tech == FIXEDMANUAL) ? 1 : 2;
                target_towers = (test_data.params.multiparty_mode == NOISE_FLOODING_MULTIPARTY) ? 3 : target_towers;
                ciphertext_mult = cc->compress(ciphertext_mult, target_towers);
            }
            Plaintext plaintext_multiparty_mult;
            ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_mult}, kp1.secret_key);
            ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_mult}, kp2.secret_key);
            std::vector<Ciphertext<Element>> partial_ciphertext_vec_mult{ciphertext_partial1[0],
                                                                         ciphertext_partial2[0]};
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec_mult, &plaintext_multiparty_mult);
            plaintext_multiparty_mult->set_length(plaintext1->get_length());

            err_msg = failmsg + " Multiparty multiplication failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_multiparty_mult->get_ckks_packed_value(),
                               plaintext_mult_input->get_ckks_packed_value(), eps, err_msg);
            } else {
                check_equality(plaintext_multiparty_mult->get_packed_value(), plaintext_mult_input->get_packed_value(),
                               eps, err_msg);
            }
            //====================================================================
            Plaintext plaintext_multiparty_eval_sum;
            ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_eval_sum}, kp1.secret_key);
            ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp2.secret_key);
            std::vector<Ciphertext<Element>> partial_ciphertext_vec_eval_sum{ciphertext_partial1[0],
                                                                             ciphertext_partial2[0]};
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec_eval_sum, &plaintext_multiparty_eval_sum);
            plaintext_multiparty_eval_sum->set_length(plaintext1->get_length());

            err_msg = failmsg + " Multiparty eval sum failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_multiparty_eval_sum->get_ckks_packed_value(),
                               plaintext_eval_sum_input->get_ckks_packed_value(), eps, err_msg);
            } else {
                check_equality(plaintext_multiparty_eval_sum->get_packed_value(),
                               plaintext_eval_sum_input->get_packed_value(), eps, err_msg);
            }
            //====================================================================
            Plaintext plaintext_multiparty_rotate;
            ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_rotate}, kp1.secret_key);
            ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_rotate}, kp2.secret_key);
            std::vector<Ciphertext<Element>> partial_ciphertext_vec_rotate{ciphertext_partial1[0],
                                                                           ciphertext_partial2[0]};
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec_rotate, &plaintext_multiparty_rotate);
            plaintext_multiparty_rotate->set_length(plaintext1->get_length());

            err_msg = failmsg + " Multiparty rotation failed";
            if (CKKSRNS_TEST == test_data.test_case_type) {
                check_equality(plaintext_multiparty_rotate->get_ckks_packed_value(),
                               plaintext_rotate_input->get_ckks_packed_value(), eps, err_msg);
            } else {
                check_equality(plaintext_multiparty_rotate->get_packed_value(),
                               plaintext_rotate_input->get_packed_value(), eps, err_msg);
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // runs for three parties only
    void unit_test_multiparty(const TEST_CASE_UTGENERAL_MULTIPARTY& test_data,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));
            ////////////////////////////////////////////////////////////
            // Perform Key Generation Operation
            ////////////////////////////////////////////////////////////
            KeyPair<Element> kp1 = cc->key_gen();
            ASSERT_TRUE(kp1.good()) << failmsg + "kp1 generation failed!";

            KeyPair<Element> kp2 = cc->multiparty_key_gen(kp1.public_key, false, true);
            ASSERT_TRUE(kp2.good()) << failmsg + "kp2 generation failed!";

            KeyPair<Element> kp3 = cc->multiparty_key_gen(kp1.public_key, false, true);
            ASSERT_TRUE(kp3.good()) << failmsg + "kp3 generation failed!";

            ////////////////////////////////////////////////////////////
            // Perform the second key generation operation.
            // This generates the keys which should be able to decrypt the ciphertext
            // after the re-encryption operation.
            ////////////////////////////////////////////////////////////

            std::vector<PrivateKey<Element>> secret_keys{kp1.secret_key, kp2.secret_key, kp3.secret_key};
            // This is the same core key generation operation.
            KeyPair<Element> kp_multiparty = cc->multiparty_key_gen(secret_keys);
            ASSERT_TRUE(kp_multiparty.good()) << "kpMultiparty generation failed!";

            ////////////////////////////////////////////////////////////
            // Perform the proxy re-encryption key generation operation.
            // This generates the keys which are used to perform the key switching.
            ////////////////////////////////////////////////////////////

            EvalKey<Element> eval_key1 = cc->re_key_gen(kp1.secret_key, kp_multiparty.public_key);
            EvalKey<Element> eval_key2 = cc->re_key_gen(kp2.secret_key, kp_multiparty.public_key);
            EvalKey<Element> eval_key3 = cc->re_key_gen(kp3.secret_key, kp_multiparty.public_key);

            ////////////////////////////////////////////////////////////
            // Encode source data
            ////////////////////////////////////////////////////////////
            std::vector<int64_t> vector_of_ints1 = {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0};
            std::vector<int64_t> vector_of_ints2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vector_of_ints3 = {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};

            auto plaintext_modulus = cc->get_crypto_parameters()->get_plaintext_modulus();

            int64_t half(plaintext_modulus >> 1);
            std::vector<int64_t> vector_of_ints_sum(vector_of_ints1.size());
            for (size_t i = 0; i < vector_of_ints1.size(); i++) {
                int64_t value = (vector_of_ints1[i] + vector_of_ints2[i] + vector_of_ints3[i]) % plaintext_modulus;
                if (value > half)
                    value -= plaintext_modulus;
                vector_of_ints_sum[i] = value;
            }

            auto plaintext1 = cc->make_coef_packed_plaintext(vector_of_ints1);
            auto plaintext2 = cc->make_coef_packed_plaintext(vector_of_ints2);
            auto plaintext3 = cc->make_coef_packed_plaintext(vector_of_ints3);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp1.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp2.public_key, plaintext2);
            Ciphertext<Element> ciphertext3 = cc->encrypt(kp3.public_key, plaintext3);

            ////////////////////////////////////////////////////////////
            // Re-Encryption
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertext1_new = cc->re_encrypt(ciphertext1, eval_key1);
            Ciphertext<Element> ciphertext2_new = cc->re_encrypt(ciphertext2, eval_key2);
            Ciphertext<Element> ciphertext3_new = cc->re_encrypt(ciphertext3, eval_key3);

            ////////////////////////////////////////////////////////////
            // eval_add Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertext_add_new12 = cc->eval_add(ciphertext1_new, ciphertext2_new);
            Ciphertext<Element> ciphertext_add_new = cc->eval_add(ciphertext_add_new12, ciphertext3_new);

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////

            Plaintext plaintext_add_new;
            cc->decrypt(kp_multiparty.secret_key, ciphertext_add_new, &plaintext_add_new);
            plaintext_add_new->set_length(plaintext1->get_length());

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Re-Encrypted Data with
            // Multiparty
            ////////////////////////////////////////////////////////////
            auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_add_new}, kp1.secret_key);
            auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_add_new}, kp2.secret_key);
            auto ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_add_new}, kp3.secret_key);

            std::vector<Ciphertext<Element>> partial_ciphertext_vec{ciphertext_partial1[0], ciphertext_partial2[0],
                                                                    ciphertext_partial3[0]};

            Plaintext plaintext_multiparty_new;
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty_new);
            plaintext_multiparty_new->set_length(plaintext1->get_length());

            const double eps = EPSILON;
            std::string err_msg = failmsg + " Multiparty: Does not match plaintext addition";
            check_equality(vector_of_ints_sum, plaintext_multiparty_new->get_coef_packed_value(), eps, err_msg);
            err_msg = failmsg + " Multiparty: Does not match the results of direction encryption";
            check_equality(plaintext_add_new->get_coef_packed_value(),
                           plaintext_multiparty_new->get_coef_packed_value(), eps, err_msg);
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // runs for three parties only
    void unit_test_multiparty_aborts(const TEST_CASE_UTGENERAL_MULTIPARTY& test_data,
                                     const std::string& failmsg = std::string()) {
        ////////////////////////////////////////////////////////////
        // Set-up of parameters
        ////////////////////////////////////////////////////////////
        CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

        const uint32_t N = 3;  // number of parties
        // threshold number of parties
        const uint32_t THRESH =
                (test_data.sharing_scheme == "shamir") ? static_cast<uint32_t>(std::floor(N / 2)) + 1 : N - 1;

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////
        // Round 1 (party A)
        KeyPair<RnsPoly> kp1 = cc->key_gen();
        auto kp1smap = cc->share_keys(kp1.secret_key, N, THRESH, 1, test_data.sharing_scheme);

        // Generate evalmult key part for A
        auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);

        // Generate evalsum key part for A
        cc->eval_sum_key_gen(kp1.secret_key);
        auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
                cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

        // Round 2 (party B)
        KeyPair<RnsPoly> kp2 = cc->multiparty_key_gen(kp1.public_key);

        auto kp2smap = cc->share_keys(kp2.secret_key, N, THRESH, 2, test_data.sharing_scheme);
        auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);
        auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());
        auto eval_sum_keys_b = cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());
        auto eval_sum_keys_ab =
                cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());

        KeyPair<RnsPoly> kp3 = cc->multiparty_key_gen(kp2.public_key);

        auto kp3smap = cc->share_keys(kp3.secret_key, N, THRESH, 3, test_data.sharing_scheme);
        auto eval_mult_key3 = cc->multi_key_switch_gen(kp3.secret_key, kp3.secret_key, eval_mult_ab);
        auto eval_mult_abc = cc->multi_add_eval_keys(eval_mult_ab, eval_mult_key3, kp3.public_key->get_key_tag());
        auto eval_mult_cabc = cc->multi_mult_eval_key(kp3.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
        auto eval_sum_keys_c =
                cc->multi_eval_sum_key_gen(kp3.secret_key, eval_sum_keys_b, kp3.public_key->get_key_tag());
        auto eval_sum_keys_join =
                cc->multi_add_eval_sum_keys(eval_sum_keys_c, eval_sum_keys_ab, kp3.public_key->get_key_tag());

        cc->insert_eval_sum_key(eval_sum_keys_join);

        auto eval_mult_babc = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
        auto eval_mult_bcabc =
                cc->multi_add_eval_mult_keys(eval_mult_cabc, eval_mult_babc, eval_mult_cabc->get_key_tag());
        auto eval_mult_aabc = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
        auto eval_mult_final =
                cc->multi_add_eval_mult_keys(eval_mult_aabc, eval_mult_bcabc, eval_mult_aabc->get_key_tag());

        cc->insert_eval_mult_key({eval_mult_final});

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////
        std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
        std::vector<int64_t> vector_of_ints2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
        std::vector<int64_t> vector_of_ints3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

        // compute expected results in plain
        size_t encoded_length = vector_of_ints1.size();
        std::vector<int64_t> sum_input(encoded_length);
        std::vector<int64_t> mult_input(encoded_length);
        std::vector<int64_t> eval_sum_input(encoded_length);

        for (size_t i = 0; i < encoded_length; i++) {
            sum_input[i] = vector_of_ints1[i] + vector_of_ints2[i] + vector_of_ints3[i];
            mult_input[i] = vector_of_ints1[i] * vector_of_ints3[i];
        }

        if (CKKSRNS_SCHEME == test_data.params.scheme_id_value) {
            // For CKKS there is different logic, depending on slots value
            uint32_t slots = (test_data.slots != 0) ? test_data.slots :
                             (BATCH != 0)           ? BATCH :
                                                      cc->get_ring_dimension() / 2;
            for (size_t i = 0; i < encoded_length; ++i) {
                eval_sum_input[i] = 0;
                // we add to eval_sum_input[i] value vector_of_ints3[(i + j) % BATCH];
                for (size_t j = 0; j < BATCH; ++j) {
                    if ((i + j) % slots < encoded_length) {
                        eval_sum_input[i] += vector_of_ints3[(i + j) % slots];
                    }
                }
            }
        } else {
            // For BGV and BFV no slots is given
            for (size_t i = 0, rev = (encoded_length - 1); i < encoded_length; ++i, --rev) {
                if (i == 0)
                    eval_sum_input[rev] = vector_of_ints3[rev];
                else
                    eval_sum_input[rev] = eval_sum_input[rev + 1] + vector_of_ints3[rev];
            }
        }

        Plaintext plaintext1;
        Plaintext plaintext2;
        Plaintext plaintext3;
        Plaintext plaintextevaladd;
        Plaintext plaintextevalmult;
        Plaintext plaintextevalsum;
        if (CKKSRNS_SCHEME == test_data.params.scheme_id_value) {
            plaintext1 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints1), 1, 0, nullptr,
                                                        test_data.slots);
            plaintext2 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints2), 1, 0, nullptr,
                                                        test_data.slots);
            plaintext3 = cc->make_ckks_packed_plaintext(to_complex_double_vec(vector_of_ints3), 1, 0, nullptr,
                                                        test_data.slots);
            plaintextevaladd =
                    cc->make_ckks_packed_plaintext(to_complex_double_vec(sum_input), 1, 0, nullptr, test_data.slots);
            plaintextevalmult =
                    cc->make_ckks_packed_plaintext(to_complex_double_vec(mult_input), 1, 0, nullptr, test_data.slots);
            plaintextevalsum = cc->make_ckks_packed_plaintext(to_complex_double_vec(eval_sum_input), 1, 0, nullptr,
                                                              test_data.slots);
        } else {
            plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
            plaintext2 = cc->make_packed_plaintext(vector_of_ints2);
            plaintext3 = cc->make_packed_plaintext(vector_of_ints3);
            plaintextevaladd = cc->make_packed_plaintext(sum_input);
            plaintextevalmult = cc->make_packed_plaintext(mult_input);
            plaintextevalsum = cc->make_packed_plaintext(eval_sum_input);
        }
        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////

        Ciphertext<RnsPoly> ciphertext1 = cc->encrypt(kp3.public_key, plaintext1);
        Ciphertext<RnsPoly> ciphertext2 = cc->encrypt(kp3.public_key, plaintext2);
        Ciphertext<RnsPoly> ciphertext3 = cc->encrypt(kp3.public_key, plaintext3);

        ////////////////////////////////////////////////////////////
        // Homomorphic Operations
        ////////////////////////////////////////////////////////////

        Ciphertext<RnsPoly> ciphertext_add12 = cc->eval_add(ciphertext1, ciphertext2);
        Ciphertext<RnsPoly> ciphertext_add123 = cc->eval_add(ciphertext_add12, ciphertext3);

        auto ciphertext_mult = cc->eval_mult(ciphertext1, ciphertext3);
        auto ciphertext_eval_sum = cc->eval_sum(ciphertext3, BATCH);

        ////////////////////////////////////////////////////////////
        // Decryption after Accumulation Operation on Encrypted Data with Multiparty
        ////////////////////////////////////////////////////////////

        auto crypto_params = kp1.secret_key->get_crypto_parameters();
        auto element_params = crypto_params->get_element_params();

        // Aborts - recovering kp1.secret key from the shares assuming party A dropped out
        PrivateKey<RnsPoly> kp1_recovered_sk = std::make_shared<PrivateKeyImpl<RnsPoly>>(cc);
        cc->recover_shared_key(kp1_recovered_sk, kp1smap, N, THRESH, test_data.sharing_scheme);

        // Distributed decryption

        // partial decryption by party A
        auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_add123}, kp1_recovered_sk);

        // partial decryption by party B
        auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_add123}, kp2.secret_key);

        // partial decryption by party C
        auto ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_add123}, kp3.secret_key);

        std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
        partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
        partial_ciphertext_vec.push_back(ciphertext_partial2[0]);
        partial_ciphertext_vec.push_back(ciphertext_partial3[0]);

        // Two partial decryptions are combined
        Plaintext plaintext_multiparty_new;
        cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty_new);

        plaintext_multiparty_new->set_length(plaintext1->get_length());

        Plaintext plaintext_multiparty_mult;
        ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_mult}, kp1_recovered_sk);
        ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_mult}, kp2.secret_key);
        ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_mult}, kp3.secret_key);

        std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec_mult;
        partial_ciphertext_vec_mult.push_back(ciphertext_partial1[0]);
        partial_ciphertext_vec_mult.push_back(ciphertext_partial2[0]);
        partial_ciphertext_vec_mult.push_back(ciphertext_partial3[0]);

        cc->multiparty_decrypt_fusion(partial_ciphertext_vec_mult, &plaintext_multiparty_mult);

        plaintext_multiparty_mult->set_length(plaintext1->get_length());

        Plaintext plaintext_multiparty_eval_sum;
        ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_eval_sum}, kp1_recovered_sk);
        ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp2.secret_key);
        ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp3.secret_key);

        std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec_eval_sum;
        partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial1[0]);
        partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial2[0]);
        partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial3[0]);

        cc->multiparty_decrypt_fusion(partial_ciphertext_vec_eval_sum, &plaintext_multiparty_eval_sum);

        plaintext_multiparty_eval_sum->set_length(plaintext1->get_length());

        const double eps = EPSILON_HIGH;
        std::string err_msg = failmsg + " Multiparty: Does not match plaintext computaion results";

        if ((test_data.test_case_type == TEST_ABORTS) && (test_data.params.scheme_id_value == CKKSRNS_SCHEME)) {
            check_equality(plaintextevaladd->get_ckks_packed_value(), plaintext_multiparty_new->get_ckks_packed_value(),
                           eps, err_msg);
            check_equality(plaintextevalmult->get_ckks_packed_value(),
                           plaintext_multiparty_mult->get_ckks_packed_value(), eps, err_msg);
            check_equality(plaintextevalsum->get_ckks_packed_value(),
                           plaintext_multiparty_eval_sum->get_ckks_packed_value(), eps, err_msg);
        } else {
            check_equality(plaintextevaladd->get_packed_value(), plaintext_multiparty_new->get_packed_value(), eps,
                           err_msg);
            check_equality(plaintextevalmult->get_packed_value(), plaintext_multiparty_mult->get_packed_value(), eps,
                           err_msg);
            check_equality(plaintextevalsum->get_packed_value(), plaintext_multiparty_eval_sum->get_packed_value(), eps,
                           err_msg);
        }
    }
};
//===========================================================================================================
TEST_P(UTGENERAL_MULTIPARTY, Multiparty) {
    setup_signals();
    auto test = GetParam();
    if (test.test_case_type == BFVRNS_TEST_EXTRA)
        unit_test_multiparty(test, test.build_test_name());
    else if (test.test_case_type == TEST_ABORTS)
        unit_test_multiparty_aborts(test, test.build_test_name());
    else
        unit_test_multi_party(test, test.build_test_name());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_MULTIPARTY, ::testing::ValuesIn(test_cases), testName);
