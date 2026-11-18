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

#include <complex>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    EVAL_AT_INDX_PACKED_ARRAY = 0,
    EVAL_SUM_PACKED_ARRAY,
    EVAL_SUM_ROWS,
    EVAL_SUM_COLS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_AT_INDX_PACKED_ARRAY:
            typeName = "EVAL_AT_INDX_PACKED_ARRAY";
            break;
        case EVAL_SUM_PACKED_ARRAY:
            typeName = "EVAL_SUM_PACKED_ARRAY";
            break;
        case EVAL_SUM_ROWS:
            typeName = "EVAL_SUM_ROWS";
            break;
        case EVAL_SUM_COLS:
            typeName = "EVAL_SUM_COLS";
            break;
        default:
            typeName = "UNKNOWN_UTCKKSRNS_AUTOMORPHISM";
            break;
    }
    return os << typeName;
}

enum TEST_CASE_ERROR {
    SUCCESS = 0,
    CORNER_CASES,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL,
};

struct TEST_CASE_UTCKKSRNS_AUTOMORPHISM {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    TEST_CASE_ERROR error;
    const std::vector<int32_t> index_list;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_AUTOMORPHISM>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t SMODSIZE = 50;
constexpr uint32_t RING_DIM = 16;
constexpr uint32_t BATCH = 8;
constexpr uint32_t MULT_DEPTH = 1;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
static const std::vector<int32_t> init_index_list{3, 5, 7, 9, 11, 13, 15};
static const std::vector<int32_t> corner_case_index_list{0};

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_AUTOMORPHISM> test_cases_utckksrns_automorphism = {
    // TestType,                Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Error,               index_list
    { EVAL_AT_INDX_PACKED_ARRAY, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        corner_case_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       init_index_list },
    // ==========================================
    { EVAL_AT_INDX_PACKED_ARRAY, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        corner_case_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "16", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "17", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       init_index_list },
    // ==========================================
#if CIPHER_NATIVE_INT != 128
    { EVAL_AT_INDX_PACKED_ARRAY, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        corner_case_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "26", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "27", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       init_index_list },
    // ==========================================
    { EVAL_AT_INDX_PACKED_ARRAY, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        corner_case_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "36", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     init_index_list },
    { EVAL_AT_INDX_PACKED_ARRAY, "37", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       init_index_list },
#endif
    // ==========================================
    // TestType,            Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Error,               index_list
    { EVAL_SUM_PACKED_ARRAY, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
    // ==========================================
    { EVAL_SUM_PACKED_ARRAY, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
#if CIPHER_NATIVE_INT != 128
    { EVAL_SUM_PACKED_ARRAY, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
    // ==========================================
    { EVAL_SUM_PACKED_ARRAY, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
#endif
    // ==========================================
    // TestType,    Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz,    SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech, LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Error,               index_list
    { EVAL_SUM_ROWS, "01", {CKKSRNS_SCHEME, RING_DIM, DFLT,       DFLT,     DFLT, RING_DIM/2, DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    // ==========================================
    // TestType,    Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz,    SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech, LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, Error,               index_list
    { EVAL_SUM_COLS, "01", {CKKSRNS_SCHEME, RING_DIM, DFLT,       DFLT,     DFLT, RING_DIM/2, DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
};
// clang-format on
//===========================================================================================================

class UTCKKSRNS_AUTOMORPHISM : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_AUTOMORPHISM> {
    using Element = RnsPoly;
    const double eps = EPSILON;

    const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vector10{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const std::vector<int64_t> vector_failure{1, 2, 3, 4};
    const uint32_t invalid_index_automorphism = 4;
    const std::vector<std::complex<double>> vector_complex_failure{1.0, 2.0, 3.0, 4.0};
    const std::vector<std::complex<double>> vector8_complex{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    const std::complex<double> vector8_complex_sum =
            std::accumulate(vector8_complex.begin(), vector8_complex.end(), std::complex<double>(0));  // 36.0;
    const int64_t vector8_sum = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));          // 36

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_eval_at_index_packed_array(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test_data,
                                         const std::string& failmsg = std::string()) {
        for (auto index : test_data.index_list) {
            try {
                CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->key_gen();

                std::vector<std::complex<double>> input_vec =
                        (INVALID_INPUT_DATA == test_data.error) ? vector_complex_failure : vector8_complex;
                Plaintext int_array = cc->make_ckks_packed_plaintext(input_vec);

                std::vector<int32_t> indices{index, -index};
                if (NO_KEY_GEN_CALL != test_data.error) {
                    if (INVALID_PRIVATE_KEY == test_data.error) {
                        cc->eval_at_index_key_gen(nullptr, indices);
                    } else {
                        cc->eval_at_index_key_gen(kp.secret_key, indices);
                    }
                }

                Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == test_data.error) ?
                                                         cc->encrypt(PublicKey<Element>(nullptr), int_array) :
                                                         cc->encrypt(kp.public_key, int_array);

                if (INVALID_INDEX == test_data.error)
                    index = invalid_index_automorphism;
                Ciphertext<Element> p1 = cc->eval_at_index(ciphertext, index);
                Ciphertext<Element> p2 = cc->eval_at_index(p1, -index);

                Plaintext int_array_new;
                cc->decrypt(kp.secret_key, p2, &int_array_new);

                int_array_new->set_length(input_vec.size());

                std::string err_msg(" for index[" + std::to_string(index) + "]");
                switch (test_data.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                        // should not fail
                        check_equality(int_array_new->get_ckks_packed_value(), vector8_complex, eps, err_msg);
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(check_equality(int_array_new->get_ckks_packed_value(), vector8_complex)) << err_msg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << err_msg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            } catch (std::exception& e) {
                switch (test_data.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            } catch (...) {
                UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
            }
        }
    }

    void unit_test_eval_sum_packed_array(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test_data,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            std::vector<std::complex<double>> input_vec = vector8_complex;
            Plaintext int_array = cc->make_ckks_packed_plaintext(input_vec);

            if (NO_KEY_GEN_CALL != test_data.error) {
                if (INVALID_PRIVATE_KEY == test_data.error)
                    cc->eval_sum_key_gen(nullptr);
                else
                    cc->eval_sum_key_gen(kp.secret_key);
            }

            Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == test_data.error) ?
                                                     cc->encrypt(PublicKey<Element>(nullptr), int_array) :
                                                     cc->encrypt(kp.public_key, int_array);

            uint32_t batch_sz = (INVALID_BATCH_SIZE == test_data.error) ? (BATCH * 2) : BATCH;
            Ciphertext<Element> p1 = cc->eval_sum(ciphertext, batch_sz);

            Plaintext int_array_new;
            cc->decrypt(kp.secret_key, p1, &int_array_new);

            switch (test_data.error) {
                case SUCCESS:
                case CORNER_CASES:
                    // should not fail
                    EXPECT_TRUE(check_equality(int_array_new->get_ckks_packed_value()[0], vector8_complex_sum));
                    break;
                case INVALID_INPUT_DATA:
                    // should fail
                    EXPECT_FALSE(check_equality(int_array_new->get_ckks_packed_value()[0], vector8_complex_sum));
                    break;
                default:
                    // make it fail
                    EXPECT_EQ(0, 1);
                    break;
            }
        } catch (std::exception& e) {
            switch (test_data.error) {
                case SUCCESS:
                case CORNER_CASES:
                case INVALID_INPUT_DATA:
                    std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                    // make it fail
                    EXPECT_EQ(0, 1);
                    break;
                default:
                    EXPECT_EQ(1, 1);
                    break;
            }
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_sum_rows(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test_data,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            KeyPair<Element> kp = cc->key_gen();

            std::vector<double> mat{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
            uint32_t row_size = 4;
            uint32_t batch_size = cc->get_encoding_params()->get_batch_size();

            const std::vector<std::complex<double>> output_sum_rows{6.0, 8.0, 10.0, 12.0, 6.0, 8.0, 10.0, 12.0};

            // Encoding as plaintexts
            Plaintext ptxt_mat = cc->make_ckks_packed_plaintext(mat);

            // Encrypt the encoded vectors
            auto ct_mat = cc->encrypt(kp.public_key, ptxt_mat);

            auto eval_sum_row_keys = cc->eval_sum_rows_key_gen(kp.secret_key, row_size);

            // Evaluation
            auto ct_rows_sum = cc->eval_sum_rows(ct_mat, row_size, *eval_sum_row_keys);

            // Decrypt
            Plaintext result;
            cc->decrypt(kp.secret_key, ct_rows_sum, &result);
            result->set_length(batch_size);
            // std::cout << "sum Rows: " << result;
            check_equality(result->get_ckks_packed_value(), output_sum_rows, eps,
                          failmsg + " EvalSumRowsKeyGen()/EvalSumRows fails - result is incorrect");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_sum_cols(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test_data,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            KeyPair<Element> kp = cc->key_gen();

            std::vector<double> mat{8.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
            uint32_t col_size = 4;
            uint32_t batch_size = cc->get_encoding_params()->get_batch_size();

            const std::vector<std::complex<double>> output_sum_cols{14.0, 14.0, 14.0, 14.0, 22.0, 22.0, 22.0, 22.0};

            // Encoding as plaintexts
            Plaintext ptxt_mat = cc->make_ckks_packed_plaintext(mat);

            // Encrypt the encoded vectors
            auto ct_mat = cc->encrypt(kp.public_key, ptxt_mat);

            auto eval_sum_col_keys = cc->eval_sum_cols_key_gen(kp.secret_key);

            // Evaluation
            auto ct_cols_sum = cc->eval_sum_cols(ct_mat, col_size, *eval_sum_col_keys);

            // Decrypt
            Plaintext result;
            cc->decrypt(kp.secret_key, ct_cols_sum, &result);
            result->set_length(batch_size);
            // std::cout << "sum Cols: " << result;
            check_equality(result->get_ckks_packed_value(), output_sum_cols, eps,
                          failmsg + " EvalSumColsKeyGen()/EvalSumCols fails - result is incorrect");
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
TEST_P(UTCKKSRNS_AUTOMORPHISM, Automorphism) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case EVAL_AT_INDX_PACKED_ARRAY:
            unit_test_eval_at_index_packed_array(test, test.build_test_name());
            break;
        case EVAL_SUM_PACKED_ARRAY:
            unit_test_eval_sum_packed_array(test, test.build_test_name());
            break;
        case EVAL_SUM_ROWS:
            unit_test_eval_sum_rows(test, test.build_test_name());
            break;
        case EVAL_SUM_COLS:
            unit_test_eval_sum_cols(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_AUTOMORPHISM, ::testing::ValuesIn(test_cases_utckksrns_automorphism),
                         testName);
