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
  unit tests for the SHE capabilities
 */

#include <complex>
#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/metadata_test.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"
#include "cipher/fhe/key/relin_key.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    ADD_PACKED = 0,
    MULT_COEF_PACKED,
    MULT_PACKED,
    EVALATINDEX,
    EVALMERGE,
    EVALSUM,
    METADATA,
    EVALSUM_ALL,
    KS_SINGLE_CRT,
    KS_MOD_REDUCE_DCRT,
    EVALSQUARE,
    RING_DIM_ERROR_HANDLING,
    EVAL_MUTABLE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case ADD_PACKED:
            type_name_of = "ADD_PACKED";
            break;
        case MULT_COEF_PACKED:
            type_name_of = "MULT_COEF_PACKED";
            break;
        case MULT_PACKED:
            type_name_of = "MULT_PACKED";
            break;
        case EVALATINDEX:
            type_name_of = "EVALATINDEX";
            break;
        case EVALMERGE:
            type_name_of = "EVALMERGE";
            break;
        case EVALSUM:
            type_name_of = "EVALSUM";
            break;
        case METADATA:
            type_name_of = "METADATA";
            break;
        case EVALSUM_ALL:
            type_name_of = "EVALSUM_ALL";
            break;
        case KS_SINGLE_CRT:
            type_name_of = "KS_SINGLE_CRT";
            break;
        case KS_MOD_REDUCE_DCRT:
            type_name_of = "KS_MOD_REDUCE_DCRT";
            break;
        case EVALSQUARE:
            type_name_of = "EVALSQUARE";
            break;
        case RING_DIM_ERROR_HANDLING:
            type_name_of = "RING_DIM_ERROR_HANDLING";
            break;
        case EVAL_MUTABLE:
            type_name_of = "EVAL_MUTABLE";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_SHE {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    // ........

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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_SHE>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_SHE& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
// NOTE the SHE tests are all based on these
constexpr uint32_t BATCH = 16;
constexpr uint32_t BATCH_LRG = 1 << 12;
constexpr uint32_t PTM = 64;
constexpr uint32_t PTM_LRG = 65537;
// checks BFV for a 46-bit plaintext modulus
constexpr uint64_t PTM_XTR_LRG = 35184372744193;
constexpr uint32_t BV_DSIZE = 4;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_SHE> test_cases = {
    // TestType,  Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { ADD_PACKED, "01", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "02", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "03", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "04", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "05", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "06", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "07", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "08", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "09", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "10", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "11", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "12", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "13", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "14", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "15", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "16", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "17", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "18", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "19", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "20", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "21", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "22", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "23", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "24", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "25", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "26", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "27", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "28", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "29", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "30", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "31", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "32", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "33", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "34", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "35", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "36", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "37", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "38", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "39", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "40", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,        Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { MULT_COEF_PACKED, "01", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "02", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "03", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "04", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "05", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "06", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "07", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "08", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "25", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "26", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "27", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "28", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "29", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "30", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "31", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "32", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "33", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "34", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "35", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "36", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "37", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "38", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "39", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "40", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { MULT_PACKED, "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "25", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "26", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "27", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "28", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "29", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "30", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "31", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "32", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "33", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "34", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "35", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "36", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "37", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "38", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "39", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "40", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "41", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "42", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "43", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "44", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "45", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "46", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "47", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "48", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "49", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "50", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "51", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "52", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "53", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "54", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "55", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "56", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "57", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "58", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "59", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "60", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "61", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "62", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "63", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "64", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { EVALATINDEX, "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "09", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "10", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "11", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "12", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "13", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "14", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "15", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "16", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "17", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "18", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "19", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "20", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "21", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "22", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "23", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "24", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "25", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "26", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "27", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "28", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "29", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "30", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "31", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "32", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "33", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "34", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "35", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "36", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "37", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "38", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "39", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "40", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "41", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "42", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "43", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "44", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "45", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "46", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "47", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "48", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "49", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "50", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "51", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "52", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "53", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "54", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "55", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "56", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "57", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "58", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "59", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "60", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "61", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "62", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "63", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "64", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_XTR_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech          enc_tech,   pre_mode
    { EVALMERGE,  "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALMERGE,  "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALMERGE,  "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALMERGE,  "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALMERGE,  "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALMERGE,  "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALMERGE,  "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALMERGE,  "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALMERGE,  "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALMERGE,  "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALMERGE,  "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALMERGE,  "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALMERGE,  "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALMERGE,  "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALMERGE,  "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALMERGE,  "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { EVALSUM,    "01", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSUM,    "02", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSUM,    "03", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSUM,    "04", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSUM,    "05", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSUM,    "06", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSUM,    "07", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSUM,    "08", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSUM,    "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSUM,    "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSUM,    "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSUM,    "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSUM,    "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSUM,    "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSUM,    "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALSUM,    "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { METADATA,   "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { METADATA,   "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { METADATA,   "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { METADATA,   "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { METADATA,   "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { METADATA,   "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { METADATA,   "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { METADATA,   "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { METADATA,   "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { METADATA,   "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { METADATA,   "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { METADATA,   "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { METADATA,   "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { METADATA,   "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { METADATA,   "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { METADATA,   "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,    Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, batch_sz,   SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech, enc_tech,   pre_mode
    { EVALSUM_ALL, "01", {BFVRNS_SCHEME, BATCH_LRG, 0,         DFLT,     20,    BATCH_LRG, DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      12,   DFLT,     STANDARD,  DFLT}, },
    { EVALSUM_ALL, "02", {BFVRNS_SCHEME, BATCH_LRG, 0,         DFLT,     20,    BATCH_LRG, DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      12,   DFLT,     EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,      Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech, enc_tech,   pre_mode
    { KS_SINGLE_CRT, "01", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "02", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDAUTO,       DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "03", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FLEXIBLEAUTO,    DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "04", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FLEXIBLEAUTOEXT, DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    // ==========================================
    // TestType,           Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech, enc_tech,   pre_mode
    { KS_MOD_REDUCE_DCRT, "01", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    // Calling mod_reduce in the AUTO modes doesn't do anything because we automatically mod reduce before multiplication,
    // so we don't need unit tests for KS_MOD_REDUCE_DCRT in the AUTO modes.
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    batch_sz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech,   pre_mode
    { EVALSQUARE,  "01", {BGVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "02", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "03", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "04", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "05", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "06", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "07", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "08", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "09", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "10", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "11", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "12", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "13", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSQUARE,  "14", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSQUARE,  "15", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSQUARE,  "16", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSQUARE,  "17", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSQUARE,  "18", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSQUARE,  "19", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSQUARE,  "20", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSQUARE,  "21", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSQUARE,  "22", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSQUARE,  "23", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALSQUARE,  "24", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
// ==========================================
    // TestType,               Descr, Scheme,        RDim,  MultDepth, SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, scal_tech, LDigits, PtMod,      std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode
    { RING_DIM_ERROR_HANDLING, "01", {BFVRNS_SCHEME, 1<<13, 3,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    4293918721, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,    Descr, Scheme,         RDim, MultDepth, SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,            KSTech, scal_tech,     LDigits, PtMod,   std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode
    { EVAL_MUTABLE, "01", {BGVRNS_SCHEME,  DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   DFLT,         DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MUTABLE, "02", {CKKSRNS_SCHEME, DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   DFLT,         DFLT,    DFLT,    DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MUTABLE, "03", {BGVRNS_SCHEME,  DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   FIXEDAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MUTABLE, "04", {BGVRNS_SCHEME,  DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   FLEXIBLEAUTO, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MUTABLE, "05", {CKKSRNS_SCHEME, DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   FIXEDAUTO,    DFLT,    DFLT,    DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { EVAL_MUTABLE, "06", {CKKSRNS_SCHEME, DFLT, 2,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     HEStd_128_classic, DFLT,   FLEXIBLEAUTO, DFLT,    DFLT,    DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#endif
};
// clang-format on
//===========================================================================================================
class UTGENERAL_SHE : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_SHE> {
    using Element = RnsPoly;
    const double eps = EPSILON;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_add_packed(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1 = cc->make_coef_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints2 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext2 = cc->make_coef_packed_plaintext(vector_of_ints2);

            std::vector<int64_t> vector_of_ints_add = {3, 1, 6, 3, 2, 2, 5, 1};
            Plaintext plaintext_add = cc->make_coef_packed_plaintext(vector_of_ints_add);

            std::vector<int64_t> vector_of_ints_sub = {-1, -1, 0, -1, -2, 0, -1, 1};
            Plaintext plaintext_sub = cc->make_coef_packed_plaintext(vector_of_ints_sub);

            KeyPair<Element> kp = cc->key_gen();
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);

            Ciphertext<Element> c_result;
            Plaintext results;

            c_result = cc->eval_add(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            EXPECT_EQ(plaintext_add->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_add fails";

            auto ct1_clone = ciphertext1->clone();
            cc->eval_add_in_place(ct1_clone, ciphertext2);
            cc->decrypt(kp.secret_key, ct1_clone, &results);
            results->set_length(plaintext_add->get_length());
            EXPECT_EQ(plaintext_add->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_add_in_place fails";

            c_result = ciphertext1 + ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            EXPECT_EQ(plaintext_add->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator+ fails";

            Ciphertext<Element> cadd_inplace = ciphertext1->clone();
            cadd_inplace += ciphertext2;
            cc->decrypt(kp.secret_key, cadd_inplace, &results);
            results->set_length(plaintext_add->get_length());
            EXPECT_EQ(plaintext_add->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator+= fails";

            c_result = cc->eval_sub(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            EXPECT_EQ(plaintext_sub->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_sub fails";

            c_result = ciphertext1 - ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            EXPECT_EQ(plaintext_sub->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator- fails";

            Ciphertext<Element> csub_inplace = ciphertext1->clone();
            csub_inplace -= ciphertext2;
            cc->decrypt(kp.secret_key, csub_inplace, &results);
            results->set_length(plaintext_sub->get_length());
            EXPECT_EQ(plaintext_sub->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator-= fails";

            c_result = cc->eval_add(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            EXPECT_EQ(plaintext_add->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_add Ct and Pt fails";

            c_result = cc->eval_sub(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            EXPECT_EQ(plaintext_sub->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_sub Ct and Pt fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_mult_coef_packed(const TEST_CASE_UTGENERAL_SHE& test_data,
                                    const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1 = cc->make_coef_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints2 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext2 = cc->make_coef_packed_plaintext(vector_of_ints2);

            // For cyclotomic order != 16, the expected result is the convolution of
            // vectorOfInt21 and vector_of_ints2
            std::vector<int64_t> vector_of_ints_mult_long = {2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3};
            std::vector<int64_t> vector_of_ints_mult = {-17, -11, 2, 0, 5, 9, 16, 12};

            Plaintext int_array1 = cc->make_coef_packed_plaintext(vector_of_ints1);

            Plaintext int_array2 = cc->make_coef_packed_plaintext(vector_of_ints2);

            Plaintext int_array_expected = cc->make_coef_packed_plaintext(
                    cc->get_cyclotomic_order() == 16 ? vector_of_ints_mult : vector_of_ints_mult_long);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, int_array1);

            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, int_array2);

            cc->eval_mult_key_gen(kp.secret_key);

            Ciphertext<Element> c_result;
            Plaintext results;

            c_result = cc->eval_mult(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " EvalMult fails";

            c_result = ciphertext1 * ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator* fails";

            Ciphertext<Element> cmul_inplace = ciphertext1->clone();
            cmul_inplace *= ciphertext2;
            cc->decrypt(kp.secret_key, cmul_inplace, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " operator*= fails";

            c_result = cc->eval_mult(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " EvalMult Ct and Pt fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_mult_packed(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints2 = {2, 1, 3, 2, 2, 1, 3, 1};
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

            // For cyclotomic order != 16, the expected result is the convolution of
            // vectorOfInt21 and vector_of_ints2
            std::vector<int64_t> vector_of_ints_mult = {2, 0, 9, 2, 0, 1, 6, 1};

            Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);

            Plaintext int_array2 = cc->make_packed_plaintext(vector_of_ints2);

            Plaintext int_array_expected = cc->make_packed_plaintext(vector_of_ints_mult);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, int_array1);

            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, int_array2);

            cc->eval_mult_key_gen(kp.secret_key);

            Ciphertext<Element> c_result;
            Plaintext results;

            c_result = cc->eval_mult(ciphertext1, ciphertext2);

            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                    << failmsg << " EvalMult fails";

            if (!((cc->get_scheme_id_impl() == SCHEME::BFVRNS_SCHEME) &&
                  ((std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_multiplication_technique() == BEHZ) ||
                   (std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_multiplication_technique() == HPS) ||
                   (std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_encryption_technique() == EXTENDED)))) {
                c_result = cc->compress(c_result, 1);
                cc->decrypt(kp.secret_key, c_result, &results);
                results->set_length(int_array_expected->get_length());
                EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                        << failmsg << " EvalMult fails after Compress";
            }

            c_result = ciphertext1 * ciphertext2;

            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                    << failmsg << " operator* fails";

            if (!((cc->get_scheme_id_impl() == SCHEME::BFVRNS_SCHEME) &&
                  ((std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_multiplication_technique() == BEHZ) ||
                   (std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_multiplication_technique() == HPS) ||
                   (std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters())
                            ->get_encryption_technique() == EXTENDED)))) {
                c_result = cc->compress(c_result, 1);
                cc->decrypt(kp.secret_key, c_result, &results);
                results->set_length(int_array_expected->get_length());
                EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                        << failmsg << " operator* fails after Compress";
            }

            Ciphertext<Element> cmul_inplace = ciphertext1->clone();
            cmul_inplace *= ciphertext2;
            cc->decrypt(kp.secret_key, cmul_inplace, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                    << failmsg << " operator*= fails";

            c_result = cc->eval_mult(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(int_array_expected->get_length());
            EXPECT_EQ(int_array_expected->get_packed_value(), results->get_packed_value())
                    << failmsg << " EvalMult Ct and Pt fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_at_index(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            // Expected results after evaluating eval_at_index(3) and eval_at_index(-3)
            std::vector<int64_t> vector_of_ints_plus3 = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0};
            std::vector<int64_t> vector_of_ints_minus3 = {0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

            Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);

            Plaintext int_array_plus3 = cc->make_packed_plaintext(vector_of_ints_plus3);
            Plaintext int_array_minus3 = cc->make_packed_plaintext(vector_of_ints_minus3);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, int_array1);

            cc->eval_at_index_key_gen(kp.secret_key, {3, -3});

            Ciphertext<Element> c_result1 = cc->eval_at_index(ciphertext1, 3);

            Ciphertext<Element> c_result2 = cc->eval_at_index(ciphertext1, -3);

            Plaintext results1;

            Plaintext results2;

            cc->decrypt(kp.secret_key, c_result1, &results1);

            cc->decrypt(kp.secret_key, c_result2, &results2);

            results1->set_length(int_array_plus3->get_length());
            EXPECT_EQ(int_array_plus3->get_packed_value(), results1->get_packed_value())
                    << failmsg << " eval_at_index(3) fails";

            results2->set_length(int_array_minus3->get_length());
            EXPECT_EQ(int_array_minus3->get_packed_value(), results2->get_packed_value())
                    << failmsg << " eval_at_index(-3) fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_merge(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            std::vector<Ciphertext<Element>> ciphertexts;

            std::vector<int64_t> vector_of_ints1 = {32, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);
            ciphertexts.push_back(cc->encrypt(kp.public_key, int_array1));

            std::vector<int64_t> vector_of_ints2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext int_array2 = cc->make_packed_plaintext(vector_of_ints2);
            ciphertexts.push_back(cc->encrypt(kp.public_key, int_array2));

            std::vector<int64_t> vector_of_ints3 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext int_array3 = cc->make_packed_plaintext(vector_of_ints3);
            ciphertexts.push_back(cc->encrypt(kp.public_key, int_array3));

            std::vector<int64_t> vector_of_ints4 = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext int_array4 = cc->make_packed_plaintext(vector_of_ints4);
            ciphertexts.push_back(cc->encrypt(kp.public_key, int_array4));

            std::vector<int64_t> vector_of_ints5 = {16, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext int_array5 = cc->make_packed_plaintext(vector_of_ints5);
            ciphertexts.push_back(cc->encrypt(kp.public_key, int_array5));

            // Expected results after evaluating eval_at_index(3) and eval_at_index(-3)
            std::vector<int64_t> vector_merged = {32, 2, 4, 8, 16, 0, 0, 0};
            Plaintext int_array_merged = cc->make_packed_plaintext(vector_merged);

            std::vector<int32_t> index_list = {-1, -2, -3, -4, -5};

            cc->eval_at_index_key_gen(kp.secret_key, index_list);

            auto merged_ciphertext = cc->eval_merge(ciphertexts);

            Plaintext results1;

            cc->decrypt(kp.secret_key, merged_ciphertext, &results1);

            results1->set_length(int_array_merged->get_length());
            EXPECT_EQ(int_array_merged->get_packed_value(), results1->get_packed_value())
                    << failmsg << " eval_merge fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_sum(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            std::vector<Ciphertext<Element>> ciphertexts;

            uint32_t n = cc->get_ring_dimension();

            std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8};
            uint32_t dim = vector_of_ints1.size();
            vector_of_ints1.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vector_of_ints1[i] = vector_of_ints1[i % dim];
            Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);
            auto ct1 = cc->encrypt(kp.public_key, int_array1);

            cc->eval_sum_key_gen(kp.secret_key);

            auto ctsum1 = cc->eval_sum(ct1, 1);
            auto ctsum2 = cc->eval_sum(ct1, 2);
            auto ctsum3 = cc->eval_sum(ct1, 8);

            std::vector<int64_t> vector_of_ints2 = {3, 5, 7, 9, 11, 13, 15, 9};
            vector_of_ints2.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vector_of_ints2[i] = vector_of_ints2[i % dim];
            Plaintext int_array2 = cc->make_packed_plaintext(vector_of_ints2);

            std::vector<int64_t> vector_of_ints_all = {36, 36, 36, 36, 36, 36, 36, 36};
            vector_of_ints_all.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vector_of_ints_all[i] = vector_of_ints_all[i % dim];
            Plaintext int_array_all = cc->make_packed_plaintext(vector_of_ints_all);

            Plaintext results1;
            cc->decrypt(kp.secret_key, ctsum1, &results1);
            Plaintext results2;
            cc->decrypt(kp.secret_key, ctsum2, &results2);
            Plaintext results3;
            cc->decrypt(kp.secret_key, ctsum3, &results3);

            int_array1->set_length(dim);
            int_array2->set_length(dim);
            int_array_all->set_length(dim);
            results1->set_length(dim);
            results2->set_length(dim);
            results3->set_length(dim);

            EXPECT_EQ(int_array1->get_packed_value(), results1->get_packed_value())
                    << failmsg << " eval_sum for batch size = 1 failed";
            EXPECT_EQ(int_array2->get_packed_value(), results2->get_packed_value())
                    << failmsg << " eval_sum for batch size = 2 failed";
            EXPECT_EQ(int_array_all->get_packed_value(), results3->get_packed_value())
                    << failmsg << " eval_sum for batch size = 8 failed";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_metadata(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> input1{0, 1, 2, 3, 4, 5, 6, 7};
            std::vector<int64_t> input2{0, -1, -2, -3, -4, -5, -6, -7};
            Plaintext plaintext1 = cc->make_packed_plaintext(input1);
            Plaintext plaintext2 = cc->make_packed_plaintext(input2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
            cc->eval_at_index_key_gen(kp.secret_key, {2, -2});
            // Generate keys for eval_sum
            cc->eval_sum_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);
            Plaintext results;

            // Populating metadata map in ciphertexts
            auto val1 = std::make_shared<MetadataTest>();
            val1->set_metadata("ciphertext1");
            MetadataTest::store_metadata<Element>(ciphertext1, val1);
            auto val2 = std::make_shared<MetadataTest>();
            val2->set_metadata("ciphertext2");
            MetadataTest::store_metadata<Element>(ciphertext2, val2);

            // Checking if metadata is carried over in eval_add(ctx,ctx)
            Ciphertext<Element> c_add_cc = cc->eval_add(ciphertext1, ciphertext2);
            auto add_cc_val_test = MetadataTest::get_metadata<Element>(c_add_cc);
            EXPECT_EQ(val1->get_metadata(), add_cc_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_add(ctx,ctx)";

            // Checking if metadata is carried over in eval_add_in_place(ctx,ctx)
            Ciphertext<Element> ciphertext1_clone = ciphertext1->clone();
            cc->eval_add_in_place(ciphertext1_clone, ciphertext2);
            auto add_cc_in_place_val_test = MetadataTest::get_metadata<Element>(ciphertext1_clone);
            EXPECT_EQ(val1->get_metadata(), add_cc_in_place_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_add_in_place(ctx,ctx)";

            // Checking if metadata is carried over in eval_add(ctx,ptx)
            Ciphertext<Element> c_add_cp = cc->eval_add(ciphertext1, plaintext1);
            auto add_cp_val_test = MetadataTest::get_metadata<Element>(c_add_cp);
            EXPECT_EQ(val1->get_metadata(), add_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_add(ctx,ptx)";

            // Checking if metadata is carried over in eval_sub(ctx,ctx)
            Ciphertext<Element> c_sub_cc = cc->eval_sub(ciphertext1, ciphertext2);
            auto sub_cc_val_test = MetadataTest::get_metadata<Element>(c_sub_cc);
            EXPECT_EQ(val1->get_metadata(), sub_cc_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_sub(ctx,ctx)";

            // Checking if metadata is carried over in eval_sub(ctx,ptx)
            Ciphertext<Element> c_sub_cp = cc->eval_sub(ciphertext1, plaintext1);
            auto sub_cp_val_test = MetadataTest::get_metadata<Element>(c_sub_cp);
            EXPECT_EQ(val1->get_metadata(), sub_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_sub(ctx,ptx)";

            // Checking if metadata is carried over in eval_mult(ctx,ctx)
            Ciphertext<Element> c_mult_cc = cc->eval_mult(ciphertext1, ciphertext2);
            auto mult_cc_val_test = MetadataTest::get_metadata<Element>(c_mult_cc);
            EXPECT_EQ(val1->get_metadata(), mult_cc_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalMult(ctx,ctx)";

            // Checking if metadata is carried over in eval_mult(ctx,ptx)
            Ciphertext<Element> c_mult_cp = cc->eval_mult(ciphertext1, plaintext1);
            auto mult_cp_val_test = MetadataTest::get_metadata<Element>(c_mult_cp);
            EXPECT_EQ(val1->get_metadata(), mult_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalMult(ctx,ptx)";

            // Checking if metadata is carried over in eval_at_index +2 (left rotate)
            auto c_at_index2 = cc->eval_at_index(ciphertext1, 2);
            auto at_index2_val_test = MetadataTest::get_metadata<Element>(c_at_index2);
            EXPECT_EQ(val1->get_metadata(), at_index2_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_at_index +2";

            // Checking if metadata is carried over in eval_at_index -2 (right rotate)
            auto c_at_index_minus2 = cc->eval_at_index(ciphertext1, -2);
            auto at_index_minus2_val_test = MetadataTest::get_metadata<Element>(c_at_index_minus2);
            EXPECT_EQ(val1->get_metadata(), at_index_minus2_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in eval_at_index -2";

            std::vector<double> weights(2);
            for (uint32_t i = 0; i < 2; i++)
                weights[i] = i;

            std::vector<Ciphertext<Element>> ciphertexts(2);
            ciphertexts[0] = ciphertext1;
            ciphertexts[1] = ciphertext2;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_sum_bfv_rns_all(const TEST_CASE_UTGENERAL_SHE& test_data,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<RnsPoly> kp = cc->key_gen();

            std::vector<Ciphertext<RnsPoly>> ciphertexts;

            uint32_t n = cc->get_ring_dimension();

            std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8};
            uint32_t dim = vector_of_ints1.size();
            vector_of_ints1.resize(n);
            for (uint32_t i = n - dim; i < n; i++)
                vector_of_ints1[i] = i;

            Plaintext int_array1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints_all = {32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768};
            Plaintext int_array_all = cc->make_packed_plaintext(vector_of_ints_all);

            auto ct1 = cc->encrypt(kp.public_key, int_array1);

            cc->eval_sum_key_gen(kp.secret_key);

            auto ctsum1 = cc->eval_sum(ct1, BATCH_LRG);

            Plaintext results1;
            cc->decrypt(kp.secret_key, ctsum1, &results1);

            int_array_all->set_length(dim);
            results1->set_length(dim);

            EXPECT_EQ(int_array_all->get_packed_value(), results1->get_packed_value())
                    << " BFVrns eval_sum for batch size = All failed";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_keyswitch_single_crt(const TEST_CASE_UTGENERAL_SHE& test_data,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext = cc->make_string_plaintext("I am good, what are you?! 32 ch");
            KeyPair<RnsPoly> kp = cc->key_gen();

            Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext);

            KeyPair<RnsPoly> kp2 = cc->key_gen();
            EvalKey<RnsPoly> key_switch_hint = cc->key_switch_gen(kp.secret_key, kp2.secret_key);

            Ciphertext<RnsPoly> new_ct = cc->key_switch(ciphertext, key_switch_hint);

            Plaintext plaintext_new;

            cc->decrypt(kp2.secret_key, new_ct, &plaintext_new);

            EXPECT_EQ(plaintext->get_string_value(), plaintext_new->get_string_value()) << "Key-Switched Decrypt fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_keyswitch_mod_reduce_dcrt(const TEST_CASE_UTGENERAL_SHE& test_data,
                                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext = cc->make_string_plaintext("I am good, what are you?! 32 ch");

            KeyPair<RnsPoly> kp = cc->key_gen();
            Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext);

            KeyPair<RnsPoly> kp2 = cc->key_gen();
            EvalKey<RnsPoly> key_switch_hint = cc->key_switch_gen(kp.secret_key, kp2.secret_key);

            Ciphertext<RnsPoly> new_ct = cc->key_switch(ciphertext, key_switch_hint);

            Plaintext plaintext_new_key_switch;

            cc->decrypt(kp2.secret_key, new_ct, &plaintext_new_key_switch);

            EXPECT_EQ(plaintext->get_string_value(), plaintext_new_key_switch->get_string_value())
                    << "Key-Switched Decrypt fails";

            /**************************KEYSWITCH TEST END******************************/
            /**************************MODREDUCE TEST BEGIN******************************/

            cc->mod_reduce_in_place(new_ct);
            RnsPoly sk2_private_element(kp2.secret_key->get_private_element());
            sk2_private_element.drop_last_element();
            kp2.secret_key->set_private_element(sk2_private_element);

            Plaintext plaintext_new_mod_reduce;

            cc->decrypt(kp2.secret_key, new_ct, &plaintext_new_mod_reduce);

            EXPECT_EQ(plaintext->get_string_value(), plaintext_new_mod_reduce->get_string_value())
                    << "Mod Reduced Decrypt fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_square(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints_square1 = {4, 1, 9, 4, 4, 1, 9, 0};
            Plaintext int_array_expected_square1 = cc->make_packed_plaintext(vector_of_ints_square1);

            std::vector<int64_t> vector_of_ints_sixth1 = {64, 1, 729, 64, 64, 1, 729, 0};
            Plaintext int_array_expected_sixth1 = cc->make_packed_plaintext(vector_of_ints_sixth1);

            std::vector<int64_t> vector_of_ints2 = {1, 1, -1, 1, 1, 1, 0, 0, 0, 0, 0, 0};
            Plaintext plaintext2 = cc->make_coef_packed_plaintext(vector_of_ints2);
            // These are the coefficients of the square polynomial of the polynomial with coefficients in vector_of_ints2.
            std::vector<int64_t> vector_of_ints_square2 = {1, 2, -1, 0, 5, 2, 1, 0, 3, 2, 1};
            Plaintext int_array_expected_square2 = cc->make_coef_packed_plaintext(vector_of_ints_square2);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);

            cc->eval_mult_key_gen(kp.secret_key);

            Plaintext results;

            Ciphertext<Element> ciphertext_sq1 = cc->eval_square(ciphertext1);
            cc->decrypt(kp.secret_key, ciphertext_sq1, &results);
            results->set_length(int_array_expected_square1->get_length());
            EXPECT_EQ(int_array_expected_square1->get_packed_value(), results->get_packed_value())
                    << failmsg << " eval_square (Packed) fails";

            Ciphertext<Element> ciphertext_third1 = cc->eval_mult(ciphertext_sq1, plaintext1);
            cc->decrypt(kp.secret_key, ciphertext_third1, &results);

            Ciphertext<Element> ciphertext_sixth1 = cc->eval_square(ciphertext_third1);
            cc->decrypt(kp.secret_key, ciphertext_sixth1, &results);
            results->set_length(int_array_expected_sixth1->get_length());
            EXPECT_EQ(int_array_expected_sixth1->get_packed_value(), results->get_packed_value())
                    << failmsg << " eval_square Sixth (Packed) fails";

            Ciphertext<Element> ciphertext_sq2 = cc->eval_square(ciphertext2);
            cc->decrypt(kp.secret_key, ciphertext_sq2, &results);
            results->set_length(int_array_expected_square2->get_length());
            EXPECT_EQ(int_array_expected_square2->get_coef_packed_value(), results->get_coef_packed_value())
                    << failmsg << " eval_square (CoefPacked) fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bfv_ringdimension_security_check(const TEST_CASE_UTGENERAL_SHE& test_data,
                                                    const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // make it fail if there is no exception thrown
            EXPECT_EQ(0, 1);
        } catch (std::exception& e) {
            // we expect to catch an exception for this test as ring dimension should not meet the security requirement
            // std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_EQ(1, 1);
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // clang-format off
    // helper function for unit_test_eval_mutable()
    template <typename Func1, typename Func2>
    void eval_mutable_operations(const CryptoContext<RnsPoly>& crypto_context,
                               const KeyPair<RnsPoly>& key_pair,
                               SCHEME scheme_id_value,
                               Func1 operation1,  // (ctxt, ctxt)
                               Func2 operation2,  // (ctxt, ptxt)
                               Plaintext& plaintext1,
                               Plaintext& plaintext2,
                               Plaintext& plaintext_result1,
                               Plaintext& plaintext_result2,
                               double tolerance,
                               const std::string& err_msg) {
        auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
        auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

        auto ciphertext12 = ((*crypto_context).*operation1)(ciphertext1, ciphertext2);
        Plaintext plaintext_result12{nullptr};
        crypto_context->decrypt(key_pair.secret_key, ciphertext12, &plaintext_result12);
        plaintext_result12->set_length(plaintext_result1->get_length());

        std::string err_msg1 = err_msg + " (1)";
        if (CKKSRNS_SCHEME == scheme_id_value)
            check_equality(plaintext_result12->get_ckks_packed_value(), plaintext_result1->get_ckks_packed_value(), tolerance,
                          err_msg1);
        else
            check_equality(plaintext_result12->get_packed_value(), plaintext_result1->get_packed_value(), eps, err_msg1);

        auto ciphertext_result122 = ((*crypto_context).*operation2)(ciphertext12, plaintext2);
        Plaintext plaintext_result122{nullptr};
        crypto_context->decrypt(key_pair.secret_key, ciphertext_result122, &plaintext_result122);
        plaintext_result122->set_length(plaintext_result2->get_length());

        std::string err_msg2 = err_msg + " (2)";
        if (CKKSRNS_SCHEME == scheme_id_value)
            check_equality(plaintext_result122->get_ckks_packed_value(), plaintext_result2->get_ckks_packed_value(), tolerance,
                          err_msg2);
        else
            check_equality(plaintext_result122->get_packed_value(), plaintext_result2->get_packed_value(), eps, err_msg2);
    }

    // helper function for unit_test_eval_mutable(): passing the same ciphertext object as both arguments must match
    // the result for two separate copies and leave the operand holding its original value
    void eval_mutable_aliased_operations(const CryptoContext<RnsPoly>& crypto_context,
                                      const KeyPair<RnsPoly>& key_pair,
                                      SCHEME scheme_id_value,
                                      ConstCiphertext<RnsPoly>& ciphertext,
                                      const Plaintext& plaintext_in,
                                      const Plaintext& plaintext_square,
                                      double tolerance,
                                      const std::string& err_msg) {
        auto check = [&](ConstCiphertext<RnsPoly>& result, const Plaintext& expected, const std::string& msg) {
            Plaintext plaintext_result{nullptr};
            crypto_context->decrypt(key_pair.secret_key, result, &plaintext_result);
            plaintext_result->set_length(expected->get_length());
            if (CKKSRNS_SCHEME == scheme_id_value)
                check_equality(plaintext_result->get_ckks_packed_value(), expected->get_ckks_packed_value(), tolerance,
                              err_msg + msg);
            else
                check_equality(plaintext_result->get_packed_value(), expected->get_packed_value(), tolerance, err_msg + msg);
        };

        const uint32_t square_level = crypto_context->eval_mult(ciphertext, ciphertext)->get_level();

        auto ct = ciphertext->clone();
        auto ct_square = crypto_context->eval_mult_mutable(ct, ct);
        check(ct_square, plaintext_square, " eval_mult_mutable(ct, ct) result");
        check(ct, plaintext_in, " eval_mult_mutable(ct, ct) operand");
        EXPECT_EQ(ct_square->get_level(), square_level) << err_msg << " eval_mult_mutable(ct, ct) level";

        ct = ciphertext->clone();
        crypto_context->eval_mult_mutable_in_place(ct, ct);
        check(ct, plaintext_square, " eval_mult_mutable_in_place(ct, ct) result");
        EXPECT_EQ(ct->get_level(), square_level) << err_msg << " eval_mult_mutable_in_place(ct, ct) level";

        ct = ciphertext->clone();
        auto ct1 = ciphertext->clone();
        auto ct2 = ciphertext->clone();
        crypto_context->get_scheme()->adjust_levels_and_depth_to_one_in_place(ct, ct);
        crypto_context->get_scheme()->adjust_levels_and_depth_to_one_in_place(ct1, ct2);
        check(ct, plaintext_in, " adjust_levels_and_depth_to_one_in_place(ct, ct) operand");
        EXPECT_EQ(ct->get_level(), ct1->get_level()) << err_msg << " adjust_levels_and_depth_to_one_in_place(ct, ct) level";
        EXPECT_EQ(ct->get_noise_scale_deg(), ct1->get_noise_scale_deg())
                << err_msg << " adjust_levels_and_depth_to_one_in_place(ct, ct) noise scale degree";
    }

    void unit_test_eval_mutable(const TEST_CASE_UTGENERAL_SHE& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<RnsPoly> crypto_context(unit_test_generate_context(test_data.params));

            auto key_pair = crypto_context->key_gen();
            ASSERT_TRUE(key_pair.good()) << "Key generation failed!";
            crypto_context->eval_mult_keys_gen(key_pair.secret_key);

            // test data for all cases
            std::vector<int64_t> vector_of_ints1 = {0, 1, 2, 3, 4, 5, 6, 7};
            std::vector<int64_t> vector_of_ints2 = {7, 6, 5, 4, 3, 2, 1, 0};

            std::vector<int64_t> vector_of_ints_mult_result1 = {0, 6, 10, 12, 12, 10, 6, 0};
            std::vector<int64_t> vector_of_ints_mult_result2 = {0, 36, 50, 48, 36, 20, 6, 0};

            std::vector<int64_t> vector_of_ints_add_result1 = {7, 7, 7, 7, 7, 7, 7, 7};
            std::vector<int64_t> vector_of_ints_add_result2 = {14, 13, 12, 11, 10, 9, 8, 7};

            std::vector<int64_t> vector_of_ints_sub_result1 = {-7, -5, -3, -1, 1, 3, 5, 7};
            std::vector<int64_t> vector_of_ints_sub_result2 = {-14, -11, -8, -5, -2, 1, 4, 7};

            std::vector<int64_t> vector_of_ints_square_result1 = {0, 1, 4, 9, 16, 25, 36, 49};
            std::vector<int64_t> vector_of_ints_square_result2 = {0, 36, 100, 144, 144, 100, 36, 0};

            // the CKKS approximation error of the squared product reaches ~3e-7 for FIXEDAUTO and ~1e-8 for
            // FLEXIBLEAUTO, above EPSILON; the failures checked here are exceptions or errors of order 1
            const double tolerance = (CKKSRNS_SCHEME == test_data.params.scheme_id_value) ? EPSILON_HIGH : eps;

            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);

            Plaintext plaintext_mult_result1(nullptr);
            Plaintext plaintext_mult_result2(nullptr);
            Plaintext plaintext_add_result1(nullptr);
            Plaintext plaintext_add_result2(nullptr);
            Plaintext plaintext_sub_result1(nullptr);
            Plaintext plaintext_sub_result2(nullptr);
            Plaintext plaintext_square_result1(nullptr);
            Plaintext plaintext_square_result2(nullptr);
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value) {
                std::vector<std::complex<double>> vector_of_dbls1(vector_of_ints1.begin(), vector_of_ints1.end());
                std::vector<std::complex<double>> vector_of_dbls2(vector_of_ints2.begin(), vector_of_ints2.end());
                plaintext1 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls1);
                plaintext2 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls2);

                std::vector<std::complex<double>> vector_of_dbls_mult_result1(vector_of_ints_mult_result1.begin(), vector_of_ints_mult_result1.end());
                std::vector<std::complex<double>> vector_of_dbls_mult_result2(vector_of_ints_mult_result2.begin(), vector_of_ints_mult_result2.end());
                plaintext_mult_result1 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_mult_result1);
                plaintext_mult_result2 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_mult_result2);

                std::vector<std::complex<double>> vector_of_dbls_add_result1(vector_of_ints_add_result1.begin(), vector_of_ints_add_result1.end());
                std::vector<std::complex<double>> vector_of_dbls_add_result2(vector_of_ints_add_result2.begin(), vector_of_ints_add_result2.end());
                plaintext_add_result1 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_add_result1);
                plaintext_add_result2 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_add_result2);

                std::vector<std::complex<double>> vector_of_dbls_sub_result1(vector_of_ints_sub_result1.begin(), vector_of_ints_sub_result1.end());
                std::vector<std::complex<double>> vector_of_dbls_sub_result2(vector_of_ints_sub_result2.begin(), vector_of_ints_sub_result2.end());
                plaintext_sub_result1 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_sub_result1);
                plaintext_sub_result2 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_sub_result2);

                std::vector<std::complex<double>> vector_of_dbls_square_result1(vector_of_ints_square_result1.begin(), vector_of_ints_square_result1.end());
                std::vector<std::complex<double>> vector_of_dbls_square_result2(vector_of_ints_square_result2.begin(), vector_of_ints_square_result2.end());
                plaintext_square_result1 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_square_result1);
                plaintext_square_result2 = crypto_context->make_ckks_packed_plaintext(vector_of_dbls_square_result2);
            }
            else {
                plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
                plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

                plaintext_mult_result1 = crypto_context->make_packed_plaintext(vector_of_ints_mult_result1);
                plaintext_mult_result2 = crypto_context->make_packed_plaintext(vector_of_ints_mult_result2);

                plaintext_add_result1 = crypto_context->make_packed_plaintext(vector_of_ints_add_result1);
                plaintext_add_result2 = crypto_context->make_packed_plaintext(vector_of_ints_add_result2);

                plaintext_sub_result1 = crypto_context->make_packed_plaintext(vector_of_ints_sub_result1);
                plaintext_sub_result2 = crypto_context->make_packed_plaintext(vector_of_ints_sub_result2);

                plaintext_square_result1 = crypto_context->make_packed_plaintext(vector_of_ints_square_result1);
                plaintext_square_result2 = crypto_context->make_packed_plaintext(vector_of_ints_square_result2);
            }

            eval_mutable_operations(crypto_context,
                                  key_pair,
                                  test_data.params.scheme_id_value,
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Ciphertext<RnsPoly>&) const>(&CryptoContextImpl<RnsPoly>::eval_mult_mutable),
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Plaintext&) const>(&CryptoContextImpl<RnsPoly>::eval_mult_mutable),
                                  plaintext1,
                                  plaintext2,
                                  plaintext_mult_result1,
                                  plaintext_mult_result2,
                                  tolerance,
                                  failmsg + " eval_mult_mutable() failed");

            eval_mutable_operations(crypto_context,
                                  key_pair,
                                  test_data.params.scheme_id_value,
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Ciphertext<RnsPoly>&) const>(&CryptoContextImpl<RnsPoly>::eval_add_mutable),
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Plaintext&) const>(&CryptoContextImpl<RnsPoly>::eval_add_mutable),
                                  plaintext1,
                                  plaintext2,
                                  plaintext_add_result1,
                                  plaintext_add_result2,
                                  tolerance,
                                  failmsg + " eval_add_mutable() failed");

            eval_mutable_operations(crypto_context,
                                  key_pair,
                                  test_data.params.scheme_id_value,
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Ciphertext<RnsPoly>&) const>(&CryptoContextImpl<RnsPoly>::eval_sub_mutable),
                                  static_cast<Ciphertext<RnsPoly> (CryptoContextImpl<RnsPoly>::*)(Ciphertext<RnsPoly>&, Plaintext&) const>(&CryptoContextImpl<RnsPoly>::eval_sub_mutable),
                                  plaintext1,
                                  plaintext2,
                                  plaintext_sub_result1,
                                  plaintext_sub_result2,
                                  tolerance,
                                  failmsg + " eval_sub_mutable() failed");

            // the same ciphertext object as both arguments, both fresh and after a multiplication (noise scale
            // degree 2), so that every automatic scaling technique rescales it before multiplying
            auto ciphertext = crypto_context->encrypt(key_pair.public_key, plaintext1);
            eval_mutable_aliased_operations(crypto_context, key_pair, test_data.params.scheme_id_value, ciphertext, plaintext1,
                                         plaintext_square_result1, tolerance, failmsg + " fresh:");
            auto ciphertext_product =
                    crypto_context->eval_mult(ciphertext, crypto_context->encrypt(key_pair.public_key, plaintext2));
            eval_mutable_aliased_operations(crypto_context, key_pair, test_data.params.scheme_id_value, ciphertext_product,
                                         plaintext_mult_result1, plaintext_square_result2, tolerance, failmsg + " product:");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};
// clang-format on
//===========================================================================================================
TEST_P(UTGENERAL_SHE, SHE) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case ADD_PACKED:
            unit_test_add_packed(test, test.build_test_name());
            break;
        case MULT_COEF_PACKED:
            unit_test_mult_coef_packed(test, test.build_test_name());
            break;
        case MULT_PACKED:
            unit_test_mult_packed(test, test.build_test_name());
            break;
        case EVALATINDEX:
            unit_test_eval_at_index(test, test.build_test_name());
            break;
        case EVALMERGE:
            unit_test_eval_merge(test, test.build_test_name());
            break;
        case EVALSUM:
            unit_test_eval_sum(test, test.build_test_name());
            break;
        case METADATA:
            unit_test_metadata(test, test.build_test_name());
            break;
        case EVALSUM_ALL:
            unit_test_eval_sum_bfv_rns_all(test, test.build_test_name());
            break;
        case KS_SINGLE_CRT:
            unit_test_keyswitch_single_crt(test, test.build_test_name());
            break;
        case KS_MOD_REDUCE_DCRT:
            unit_test_keyswitch_mod_reduce_dcrt(test, test.build_test_name());
            break;
        case EVALSQUARE:
            unit_test_eval_square(test, test.build_test_name());
            break;
        case RING_DIM_ERROR_HANDLING:
            unit_test_bfv_ringdimension_security_check(test, test.build_test_name());
            break;
        case EVAL_MUTABLE:
            unit_test_eval_mutable(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_SHE, ::testing::ValuesIn(test_cases), make_test_name);

TEST(UnitTestSHE, EvalKeyRelinPreservesKeyTag) {
    constexpr auto tag = "evaluation-key-tag";
    auto context = std::make_shared<CryptoContextImpl<RnsPoly>>();

    EvalKeyRelinImpl<RnsPoly> source(context);
    source.set_key_tag(tag);

    EvalKeyRelinImpl<RnsPoly> copy_constructed(source);
    EXPECT_EQ(tag, copy_constructed.get_key_tag());

    EvalKeyRelinImpl<RnsPoly> copy_assigned;
    copy_assigned = source;
    EXPECT_EQ(tag, copy_assigned.get_key_tag());

    EvalKeyRelinImpl<RnsPoly> move_source(context);
    move_source.set_key_tag(tag);
    EvalKeyRelinImpl<RnsPoly> move_constructed(std::move(move_source));
    EXPECT_EQ(tag, move_constructed.get_key_tag());
    EXPECT_EQ(nullptr, move_source.get_crypto_context());

    EvalKeyRelinImpl<RnsPoly> move_assign_source(context);
    move_assign_source.set_key_tag(tag);
    EvalKeyRelinImpl<RnsPoly> move_assigned;
    move_assigned = std::move(move_assign_source);
    EXPECT_EQ(tag, move_assigned.get_key_tag());
    EXPECT_EQ(nullptr, move_assign_source.get_crypto_context());
}

TEST(UnitTestSHE, GetMetadataByKeyClonesDynamicType) {
    CiphertextImpl<RnsPoly> ciphertext;
    auto stored = std::make_shared<MetadataTest>();
    stored->set_metadata("derived metadata");
    ciphertext.set_metadata_by_key("test", stored);

    auto cloned = std::dynamic_pointer_cast<MetadataTest>(ciphertext.get_metadata_by_key("test"));

    ASSERT_NE(nullptr, cloned);
    EXPECT_NE(stored.get(), cloned.get());
    EXPECT_EQ("derived metadata", cloned->get_metadata());
}
