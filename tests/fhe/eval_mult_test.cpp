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
    EVAL_MULT_ERROR_HANDLING = 0,
    EVAL_MULT_MANY_ERROR_HANDLING,
    RELIN_TEST,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case EVAL_MULT_ERROR_HANDLING:
            type_name_of = "EVAL_MULT_ERROR_HANDLING";
            break;
        case EVAL_MULT_MANY_ERROR_HANDLING:
            type_name_of = "EVAL_MULT_MANY_ERROR_HANDLING";
            break;
        case RELIN_TEST:
            type_name_of = "RELIN_TEST";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}

enum TEST_CASE_ERROR {
    SUCCESS = 0,
    INVALID_MAX_DEPTH,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_PLAINTEXT_ENCRYPT,
    INVALID_CIPHERTEXT_ERROR1,
    INVALID_CIPHERTEXT_ERROR2,
    INVALID_CIPHERTEXT_ERROR3,
    INVALID_CIPHERTEXT_ERROR_MANY,
    INVALID_CIPHERTEXT_DECRYPT,
    INVALID_PLAINTEXT_DECRYPT,
    INVALID_PRIVATE_KEY_DECRYPT,
    INVALID_CIPHER_TEXT_LIST_MANY
};

struct TEST_CASE_UTGENERAL_EVALMULT {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    TEST_CASE_ERROR error;

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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_EVALMULT>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_EVALMULT& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
#if CIPHER_NATIVE_INT == 128
constexpr uint32_t SCALE = 78;
#else
constexpr uint32_t SCALE = 50;
#endif
constexpr uint32_t RING_DIM = 16;
constexpr uint32_t BATCH = 8;
constexpr uint32_t MULT_DEPTH = 4;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
constexpr uint32_t PTM = 65537;

// clang-format off
static std::vector<TEST_CASE_UTGENERAL_EVALMULT> test_cases_utgeneral_evalmult = {
//    TestType,               Descr,   Scheme,         RDim,     MultDepth,  SModSize, DSize,batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode,  Error
    { EVAL_MULT_ERROR_HANDLING, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "09", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "10", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "16", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "17", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "18", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "19", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "20", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
#if CIPHER_NATIVE_INT != 128
    { EVAL_MULT_ERROR_HANDLING, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "26", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "27", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "28", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "29", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "30", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "36", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "37", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "38", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "39", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "40", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
#endif
    // ==========================================
    // TestType,               Descr,  Scheme,        RDim,     MultDepth,  SModSize, DSize,batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode,  Error
    { EVAL_MULT_ERROR_HANDLING, "41", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "42", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "43", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "44", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "45", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "46", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "47", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "48", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "49", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "50", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "51", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "52", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "53", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "54", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "55", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "56", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "57", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "58", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "59", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "60", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "61", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "62", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "63", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "64", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "65", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "66", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "67", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "68", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "69", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "70", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "71", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "72", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "73", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "74", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "75", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "76", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "77", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "78", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "79", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "80", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    // TestType,                    Descr,  Scheme,        RDim,     MultDepth,  SModSize, DSize,batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech, LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech, enc_tech,     pre_mode,  Error
    { EVAL_MULT_MANY_ERROR_HANDLING, "01", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    SUCCESS },
    { EVAL_MULT_MANY_ERROR_HANDLING, "02", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       3,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_MAX_DEPTH },
    { EVAL_MULT_MANY_ERROR_HANDLING, "03", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "04", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "05", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "06", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "07", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "08", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "09", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "10", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "11", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "12", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "13", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHER_TEXT_LIST_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "14", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    SUCCESS },
    { EVAL_MULT_MANY_ERROR_HANDLING, "15", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       3,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_MAX_DEPTH },
    { EVAL_MULT_MANY_ERROR_HANDLING, "16", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "17", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "18", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "19", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "20", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "21", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "22", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "23", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "24", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "25", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "26", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHER_TEXT_LIST_MANY },
    // ==========================================
    // TestType, Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode
    { RELIN_TEST, "01", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "02", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "03", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "04", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { RELIN_TEST, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================

class UTGENERAL_EVALMULT : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_EVALMULT> {
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

    void unit_test_eval_mult_many_error_handling(const TEST_CASE_UTGENERAL_EVALMULT& test_data,
                                                 const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> crypto_context(unit_test_generate_context(test_data.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto key_pair = crypto_context->key_gen();
            ASSERT_TRUE(key_pair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if (INVALID_PRIVATE_KEY == test_data.error)
                crypto_context->eval_mult_keys_gen(nullptr);
            else
                crypto_context->eval_mult_keys_gen(key_pair.secret_key);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<int64_t> vector_of_ints1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
            std::vector<int64_t> vector_of_ints2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vector_of_ints3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vector_of_ints4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            std::vector<int64_t> vector_of_ints5 = {10, 8, 6, 4, 2, 0, 10, 8, 6, 4, 2, 0};
            std::vector<int64_t> vector_of_ints6 = {30, 24, 18, 12, 6, 0, 30, 24, 18, 12, 6, 0};
            std::vector<int64_t> vector_of_ints7 = {120, 96, 72, 48, 24, 0, 120, 96, 72, 48, 24, 0};
            Plaintext plaintext1 = crypto_context->make_coef_packed_plaintext(vector_of_ints1);
            Plaintext plaintext2 = crypto_context->make_coef_packed_plaintext(vector_of_ints2);
            Plaintext plaintext3 = crypto_context->make_coef_packed_plaintext(vector_of_ints3);
            Plaintext plaintext4 = crypto_context->make_coef_packed_plaintext(vector_of_ints4);

            Plaintext plaintext_result1 = crypto_context->make_coef_packed_plaintext(vector_of_ints5);
            Plaintext plaintext_result2 = crypto_context->make_coef_packed_plaintext(vector_of_ints6);
            Plaintext plaintext_result3 = crypto_context->make_coef_packed_plaintext(vector_of_ints7);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 =
                    (INVALID_PUBLIC_KEY == test_data.error) ?
                            crypto_context->encrypt(static_cast<const PublicKey<Element>>(nullptr), plaintext1) :
                            crypto_context->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == test_data.error) ?
                                       crypto_context->encrypt(key_pair.public_key, nullptr) :
                                       crypto_context->encrypt(key_pair.public_key, plaintext2);
            auto ciphertext3 = crypto_context->encrypt(key_pair.public_key, plaintext3);
            auto ciphertext4 = crypto_context->encrypt(key_pair.public_key, plaintext4);

            ////////////////////////////////////////////////////////////
            // eval_mult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertext_mul12 = (INVALID_CIPHERTEXT_ERROR1 == test_data.error) ?
                                            crypto_context->eval_mult_no_relin(nullptr, ciphertext2) :
                                            crypto_context->eval_mult_no_relin(ciphertext1, ciphertext2);
            auto ciphertext_mul123 = (INVALID_CIPHERTEXT_ERROR2 == test_data.error) ?
                                             crypto_context->eval_mult_no_relin(ciphertext_mul12, nullptr) :
                                             crypto_context->eval_mult_no_relin(ciphertext_mul12, ciphertext3);
            Ciphertext<Element> ciphertext_mul1234 = nullptr;
            if (INVALID_CIPHERTEXT_ERROR3 == test_data.error)
                ciphertext_mul1234 = crypto_context->eval_mult_and_relinearize(nullptr, ciphertext4);
            else if (INVALID_CIPHERTEXT_ERROR_MANY == test_data.error)
                ciphertext_mul1234 = crypto_context->eval_mult_and_relinearize(ciphertext_mul123, nullptr);
            else
                ciphertext_mul1234 = crypto_context->eval_mult_and_relinearize(ciphertext_mul123, ciphertext4);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_mul1;
            Plaintext plaintext_mul2;
            Plaintext plaintext_mul3;
            if (INVALID_CIPHERTEXT_DECRYPT == test_data.error)
                crypto_context->decrypt(key_pair.secret_key, nullptr, &plaintext_mul1);
            else if (INVALID_PLAINTEXT_DECRYPT == test_data.error)
                crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12, nullptr);
            else if (INVALID_PRIVATE_KEY_DECRYPT == test_data.error)
                crypto_context->decrypt(nullptr, ciphertext_mul12, &plaintext_mul1);
            else
                crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12, &plaintext_mul1);

            crypto_context->decrypt(key_pair.secret_key, ciphertext_mul123, &plaintext_mul2);
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mul1234, &plaintext_mul3);
            ////////////////////////////////////////////////////////////
            // Prepare eval_mult_many
            ////////////////////////////////////////////////////////////
            std::vector<Ciphertext<Element>> cipher_text_list = {ciphertext1, ciphertext2, ciphertext3, ciphertext4};

            ////////////////////////////////////////////////////////////
            // Compute eval_mult_many
            ////////////////////////////////////////////////////////////
            auto ciphertext_mul12345 = (INVALID_CIPHER_TEXT_LIST_MANY == test_data.error) ?
                                               crypto_context->eval_mult_many(std::vector<Ciphertext<Element>>()) :
                                               crypto_context->eval_mult_many(cipher_text_list);

            ////////////////////////////////////////////////////////////
            // Decrypt eval_mult_many
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_mul_many;
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12345, &plaintext_mul_many);

            plaintext_result1->set_length(plaintext_mul1->get_length());
            plaintext_result2->set_length(plaintext_mul2->get_length());
            plaintext_result3->set_length(plaintext_mul3->get_length());

            std::string err_msg("EvalMult gives incorrect results");
            check_equality(plaintext_mul1->get_coef_packed_value(), plaintext_result1->get_coef_packed_value(), eps,
                           err_msg);

            err_msg = "eval_mult_and_relinearize gives incorrect results";
            check_equality(plaintext_mul2->get_coef_packed_value(), plaintext_result2->get_coef_packed_value(), eps,
                           err_msg);

            err_msg = "eval_mult_and_relinearize gives incorrect results";
            check_equality(plaintext_mul3->get_coef_packed_value(), plaintext_result3->get_coef_packed_value(), eps,
                           err_msg);

            err_msg = "eval_mult_and_relinearize gives incorrect results";
            check_equality(plaintext_mul_many->get_coef_packed_value(), plaintext_result3->get_coef_packed_value(), eps,
                           err_msg);

            if (SUCCESS != test_data.error) {
                // make it fail
                EXPECT_EQ(0, 1);
            }
        } catch (std::exception& e) {
            if (SUCCESS == test_data.error) {
                std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                // make it fail
                EXPECT_EQ(0, 1);
            } else
                EXPECT_EQ(1, 1);
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_mult_error_handling(const TEST_CASE_UTGENERAL_EVALMULT& test_data,
                                            const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> crypto_context(unit_test_generate_context(test_data.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto key_pair = crypto_context->key_gen();
            ASSERT_TRUE(key_pair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if (INVALID_PRIVATE_KEY == test_data.error)
                crypto_context->eval_mult_key_gen(nullptr);
            else
                crypto_context->eval_mult_key_gen(key_pair.secret_key);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////
            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);

            Plaintext plaintext_result(nullptr);
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value) {
                std::vector<std::complex<double>> vector_of_ints1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<std::complex<double>> vector_of_ints2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = crypto_context->make_ckks_packed_plaintext(vector_of_ints1);
                plaintext2 = crypto_context->make_ckks_packed_plaintext(vector_of_ints2);

                std::vector<std::complex<double>> vector_of_ints_result = {0, 6, 10, 12, 12, 10, 6, 0};

                plaintext_result = crypto_context->make_ckks_packed_plaintext(vector_of_ints_result);
            } else {
                std::vector<int64_t> vector_of_ints1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<int64_t> vector_of_ints2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
                plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

                std::vector<int64_t> vector_of_ints_result = {0, 6, 10, 12, 12, 10, 6, 0};

                plaintext_result = crypto_context->make_packed_plaintext(vector_of_ints_result);
            }

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 =
                    (INVALID_PUBLIC_KEY == test_data.error) ?
                            crypto_context->encrypt(static_cast<const PublicKey<Element>>(nullptr), plaintext1) :
                            crypto_context->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == test_data.error) ?
                                       crypto_context->encrypt(key_pair.public_key, nullptr) :
                                       crypto_context->encrypt(key_pair.public_key, plaintext2);

            ////////////////////////////////////////////////////////////
            // eval_mult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            Ciphertext<Element> ciphertext_mul12 = nullptr;
            if (INVALID_CIPHERTEXT_ERROR1 == test_data.error)
                ciphertext_mul12 = crypto_context->eval_mult_no_relin(nullptr, ciphertext2);
            else if (INVALID_CIPHERTEXT_ERROR2 == test_data.error)
                ciphertext_mul12 = crypto_context->eval_mult_no_relin(ciphertext1, nullptr);
            else
                ciphertext_mul12 = crypto_context->eval_mult_no_relin(ciphertext1, ciphertext2);

            Ciphertext<Element> ciphertext_mult = (INVALID_CIPHERTEXT_ERROR3 == test_data.error) ?
                                                          crypto_context->relinearize(nullptr) :
                                                          crypto_context->relinearize(ciphertext_mul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_mult;
            if (INVALID_CIPHERTEXT_DECRYPT == test_data.error)
                crypto_context->decrypt(key_pair.secret_key, nullptr, &plaintext_mult);
            else if (INVALID_PLAINTEXT_DECRYPT == test_data.error)
                crypto_context->decrypt(key_pair.secret_key, ciphertext_mult, nullptr);
            else if (INVALID_PRIVATE_KEY_DECRYPT == test_data.error)
                crypto_context->decrypt(nullptr, ciphertext_mult, &plaintext_mult);
            else
                crypto_context->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_mult);

            plaintext_result->set_length(plaintext_mult->get_length());

            std::string err_msg(failmsg);
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value)
                check_equality(plaintext_mult->get_ckks_packed_value(), plaintext_result->get_ckks_packed_value(), eps,
                               err_msg);
            else
                check_equality(plaintext_mult->get_packed_value(), plaintext_result->get_packed_value(), eps, err_msg);

            if (SUCCESS != test_data.error) {
                // make it fail
                EXPECT_EQ(0, 1);
            }
        } catch (std::exception& e) {
            if (SUCCESS == test_data.error) {
                std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                // make it fail
                EXPECT_EQ(0, 1);
            } else
                EXPECT_EQ(1, 1);
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_relinearization(const TEST_CASE_UTGENERAL_EVALMULT& test_data,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> crypto_context(unit_test_generate_context(test_data.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto key_pair = crypto_context->key_gen();
            ASSERT_TRUE(key_pair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            crypto_context->eval_mult_keys_gen(key_pair.secret_key);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////
            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);

            Plaintext plaintext_result(nullptr);
            Plaintext plaintext_result2(nullptr);
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value) {
                std::vector<std::complex<double>> vector_of_ints1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<std::complex<double>> vector_of_ints2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = crypto_context->make_ckks_packed_plaintext(vector_of_ints1);
                plaintext2 = crypto_context->make_ckks_packed_plaintext(vector_of_ints2);

                std::vector<std::complex<double>> vector_of_ints_result = {0, 6, 10, 12, 12, 10, 6, 0};
                std::vector<std::complex<double>> vector_of_ints_result2 = {0, 6, 20, 36, 48, 50, 36, 0};

                plaintext_result = crypto_context->make_ckks_packed_plaintext(vector_of_ints_result);
                plaintext_result2 = crypto_context->make_ckks_packed_plaintext(vector_of_ints_result2);
            } else {
                std::vector<int64_t> vector_of_ints1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<int64_t> vector_of_ints2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
                plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

                std::vector<int64_t> vector_of_ints_result = {0, 6, 10, 12, 12, 10, 6, 0};
                std::vector<int64_t> vector_of_ints_result2 = {0, 6, 20, 36, 48, 50, 36, 0};

                plaintext_result = crypto_context->make_packed_plaintext(vector_of_ints_result);
                plaintext_result2 = crypto_context->make_packed_plaintext(vector_of_ints_result2);
            }
            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

            ////////////////////////////////////////////////////////////
            // eval_mult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertext_mul12 = crypto_context->eval_mult_no_relin_no_check(ciphertext1, ciphertext2);
            auto ciphertext_mult = crypto_context->relinearize(ciphertext_mul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_mult;
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_mult);
            plaintext_mult->set_length(plaintext_result->get_length());

            std::string err_msg = failmsg + " Relinearization after one multiplication failed.";
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value)
                check_equality(plaintext_mult->get_ckks_packed_value(), plaintext_result->get_ckks_packed_value(), eps,
                               err_msg);
            else
                check_equality(plaintext_mult->get_packed_value(), plaintext_result->get_packed_value(), eps, err_msg);

            ciphertext_mult = ciphertext_mul12;
            crypto_context->relinearize(ciphertext_mult);
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_mult);
            plaintext_mult->set_length(plaintext_result->get_length());

            err_msg = failmsg + " In-place relinearization after one multiplication failed.";
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value)
                check_equality(plaintext_mult->get_ckks_packed_value(), plaintext_result->get_ckks_packed_value(), eps,
                               err_msg);
            else
                check_equality(plaintext_mult->get_packed_value(), plaintext_result->get_packed_value(), eps, err_msg);

            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertext_mul123 = crypto_context->eval_mult_no_relin(ciphertext1, ciphertext_mul12);
            auto ciphertext_mult2 = crypto_context->relinearize(ciphertext_mul123);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintext_mult2;
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mult2, &plaintext_mult2);
            plaintext_mult2->set_length(plaintext_result2->get_length());

            err_msg = failmsg + " Relinearization after two multiplications failed.";
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value)
                check_equality(plaintext_mult2->get_ckks_packed_value(), plaintext_result2->get_ckks_packed_value(),
                               eps, err_msg);
            else
                check_equality(plaintext_mult2->get_packed_value(), plaintext_result2->get_packed_value(), eps,
                               err_msg);

            ciphertext_mult2 = ciphertext_mul123;
            crypto_context->relinearize(ciphertext_mult2);
            crypto_context->decrypt(key_pair.secret_key, ciphertext_mult2, &plaintext_mult2);
            plaintext_mult2->set_length(plaintext_result2->get_length());

            err_msg = failmsg + " In-place relinearization after two multiplications failed.";
            if (CKKSRNS_SCHEME == test_data.params.scheme_id_value)
                check_equality(plaintext_mult2->get_ckks_packed_value(), plaintext_result2->get_ckks_packed_value(),
                               eps, err_msg);
            else
                check_equality(plaintext_mult2->get_packed_value(), plaintext_result2->get_packed_value(), eps,
                               err_msg);
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
TEST_P(UTGENERAL_EVALMULT, EvalMult) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case EVAL_MULT_ERROR_HANDLING:
            unit_test_eval_mult_error_handling(test, test.build_test_name());
            break;
        case EVAL_MULT_MANY_ERROR_HANDLING:
            unit_test_eval_mult_many_error_handling(test, test.build_test_name());
            break;
        case RELIN_TEST:
            unit_test_relinearization(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_EVALMULT, ::testing::ValuesIn(test_cases_utgeneral_evalmult),
                         make_test_name);
