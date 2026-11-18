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

#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/metadata_test.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    ADD_PACKED_UTBGVRNS = 0,
    MULT_PACKED_UTBGVRNS,
    EVALATINDEX_UTBGVRNS,
    EVALMERGE_UTBGVRNS,
    RE_ENCRYPTION_UTBGVRNS,
    AUTO_LEVEL_REDUCE_UTBGVRNS,
    COMPRESS_UTBGVRNS,
    EVAL_FAST_ROTATION_UTBGVRNS,
    METADATA_UTBGVRNS,
    CRYPTOPARAMS_VALIDATION_UTBGVRNS,
    MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case ADD_PACKED_UTBGVRNS:
            typeName = "ADD_PACKED_UTBGVRNS";
            break;
        case MULT_PACKED_UTBGVRNS:
            typeName = "MULT_PACKED_UTBGVRNS";
            break;
        case EVALATINDEX_UTBGVRNS:
            typeName = "EVALATINDEX_UTBGVRNS";
            break;
        case EVALMERGE_UTBGVRNS:
            typeName = "EVALMERGE_UTBGVRNS";
            break;
        case RE_ENCRYPTION_UTBGVRNS:
            typeName = "RE_ENCRYPTION_UTBGVRNS";
            break;
        case AUTO_LEVEL_REDUCE_UTBGVRNS:
            typeName = "AUTO_LEVEL_REDUCE_UTBGVRNS";
            break;
        case COMPRESS_UTBGVRNS:
            typeName = "COMPRESS_UTBGVRNS";
            break;
        case EVAL_FAST_ROTATION_UTBGVRNS:
            typeName = "EVAL_FAST_ROTATION_UTBGVRNS";
            break;
        case METADATA_UTBGVRNS:
            typeName = "METADATA_UTBGVRNS";
            break;
        case CRYPTOPARAMS_VALIDATION_UTBGVRNS:
            typeName = "CRYPTOPARAMS_VALIDATION_UTBGVRNS";
            break;
        case MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS:
            typeName = "MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS";
            break;
        default:
            typeName = "UNKNOWN_UTBGVRNS";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
/***
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus (or scaling factor bits).
 *             Should fit into a machine word, i.e., less than 64.
 * DSIZE:      The bit decomposition count used in BV relinearization.
 * PTM:        The plaintext modulus.
 * BATCH:      The length of the packed vectors to be used with CKKS.
 */
constexpr uint32_t RING_DIM = 512;
constexpr uint32_t MULT_DEPTH = 7;
constexpr uint32_t MAX_RELIN_DEG = 2;
constexpr uint32_t DSIZE = 0;
constexpr uint32_t BV_DSIZE = 4;
constexpr uint32_t PTM = 65537;
constexpr uint32_t BATCH = 16;
constexpr uint32_t FIRST_MOD_SIZE = 0;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS> test_cases_utbgvrns = {
    // TestType,          Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { ADD_PACKED_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    /// tests the scenario when plaintext modulus * cyclotomic order > 2^32
    { ADD_PACKED_UTBGVRNS, "09", {BGVRNS_SCHEME,    32768,          3, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "10", {BGVRNS_SCHEME,    32768,          3, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { MULT_PACKED_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { EVALATINDEX_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,         Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { EVALMERGE_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,             Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { RE_ENCRYPTION_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    // ==========================================
    // TestType,                 Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,        Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { COMPRESS_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,                  Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { EVAL_FAST_ROTATION_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,        Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { METADATA_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,                       Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "01", {BGVRNS_SCHEME, 3,        MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, 60,             SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     NORESCALE,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,                        Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
};
// clang-format on
//===========================================================================================================

class UTBGVRNS : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS> {
    using Element = RnsPoly;

    // the size for all vectors remains const - 8 elements
    const uint32_t VECTOR_SIZE = 8;

    // The precision after which we consider two values equal. Necessary for the check_equality() calls
    const double eps = EPSILON;

    const std::vector<int64_t> vector_of_ints0_7{0, 1, 2, 3, 4, 5, 6, 7};
    const std::vector<int64_t> vector_of_ints0_7neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<int64_t> vector_of_ints7_0{7, 6, 5, 4, 3, 2, 1, 0};

    const std::vector<int64_t> vector_of_ints1_8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vector_of_ints1_8neg{-1, -2, -3, -4, -5, -6, -7, -8};
    const std::vector<int64_t> vector_of_ints8_1{8, 7, 6, 5, 4, 3, 2, 1};

    const std::vector<int64_t> vector_of_ints1s{1, 1, 1, 1, 1, 1, 1, 1};  // all 1's

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_add_packed(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> negative_ints1(vector_of_ints0_7neg);
            Plaintext negatives1 = cc->make_packed_plaintext(negative_ints1);

            std::vector<int64_t> vector_of_ints2(vector_of_ints7_0);
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

            std::vector<int64_t> vector_of_ints_add{7, 7, 7, 7, 7, 7, 7, 7};  // all 7's
            Plaintext plaintext_add = cc->make_packed_plaintext(vector_of_ints_add);

            // std::vector<int64_t> vector_of_ints_sub = { -7,-5,-3,-1,1,3,5,7 };
            std::vector<int64_t> vector_of_ints_sub(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                vector_of_ints_sub[i] = static_cast<int64_t>(2 * i) - VECTOR_SIZE + 1;
            }
            Plaintext plaintext_sub = cc->make_packed_plaintext(vector_of_ints_sub);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);
            Ciphertext<Element> c_result;
            Plaintext results;

            // Testing eval_add
            c_result = cc->eval_add(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_packed_value(), results->get_packed_value(), eps, failmsg + " EvalAdd fails");

            // Testing eval_add_in_place
            Ciphertext<Element> ciphertext1_clone = ciphertext1->clone();
            cc->eval_add_in_place(ciphertext1_clone, ciphertext2);
            cc->decrypt(kp.secret_key, ciphertext1_clone, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAddInPlace fails");

            // Testing operator+
            c_result = ciphertext1 + ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_packed_value(), results->get_packed_value(), eps, failmsg + " operator+ fails");

            // Testing operator+=
            Ciphertext<Element> cadd_inplace(ciphertext1);
            cadd_inplace += ciphertext2;
            cc->decrypt(kp.secret_key, cadd_inplace, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " operator+= fails");

            // Testing eval_sub
            c_result = cc->eval_sub(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_packed_value(), results->get_packed_value(), eps, failmsg + " EvalSub fails");

            // Testing operator-
            c_result = ciphertext1 - ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_packed_value(), results->get_packed_value(), eps, failmsg + " operator- fails");

            // Testing operator-=
            Ciphertext<Element> csub_inplace(ciphertext1);
            csub_inplace -= ciphertext2;
            cc->decrypt(kp.secret_key, csub_inplace, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " operator-= fails");

            // Testing eval_add ciphertext + plaintext
            c_result = cc->eval_add(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAdd Ct and Pt fails");

            // Testing eval_sub ciphertext - plaintext
            c_result = cc->eval_sub(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalSub Ct and Pt fails");

            // Testing eval_negate
            c_result = cc->eval_negate(ciphertext1);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(negatives1->get_length());
            check_equality(negatives1->get_packed_value(), results->get_packed_value(), eps, failmsg + " EvalNegate fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Under FLEXIBLEAUTO* a plaintext multiply sets the result's scaling factor to the ciphertext's factor
    // squared, which is right only if the level adjustment gives the plaintext the ciphertext's factor. This
    // multiplies ciphertexts at several levels and noise-scale degrees by plaintexts encoded at other levels.
    void unit_test_mult_plaintext_at_level(const TEST_CASE_UTBGVRNS& test_data,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));
            KeyPair<Element> kp = cc->key_gen();
            cc->eval_mult_key_gen(kp.secret_key);

            const std::vector<int64_t>& x = vector_of_ints0_7;
            const std::vector<int64_t>& y = vector_of_ints7_0;
            std::vector<int64_t> xy(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; ++i)
                xy[i] = x[i] * y[i];

            // x at three levels (one higher under FLEXIBLEAUTOEXT) with noise-scale degree 1, 2, 2, 2: each
            // multiply by an encryption of ones leaves degree 2, and the next one rescales first
            auto ct_ones = cc->encrypt(kp.public_key, cc->make_packed_plaintext(std::vector<int64_t>(VECTOR_SIZE, 1)));
            std::vector<Ciphertext<Element>> cts{cc->encrypt(kp.public_key, cc->make_packed_plaintext(x))};
            for (int i = 0; i < 3; ++i)
                cts.push_back(cc->eval_mult(cts.back(), ct_ones));
            ASSERT_GE(cts.back()->get_level(), cts.front()->get_level() + 2)
                    << failmsg << " the ciphertexts do not span the intended levels";

            Plaintext result;
            for (uint32_t pt_level = 0; pt_level <= 3; ++pt_level) {
                for (size_t c = 0; c < cts.size(); ++c) {
                    const std::string msg = failmsg + " ciphertext at level " + std::to_string(cts[c]->get_level()) +
                                            " (degree " + std::to_string(cts[c]->get_noise_scale_deg()) +
                                            ") times plaintext at level " + std::to_string(pt_level);

                    cc->decrypt(kp.secret_key, cc->eval_mult(cts[c], cc->make_packed_plaintext(y, 1, pt_level)), &result);
                    result->set_length(VECTOR_SIZE);
                    check_equality(xy, result->get_packed_value(), eps, msg + ": EvalMult fails");

                    auto ct_mutable = cts[c]->clone();
                    Plaintext pt_mutable = cc->make_packed_plaintext(y, 1, pt_level);
                    cc->decrypt(kp.secret_key, cc->eval_mult_mutable(ct_mutable, pt_mutable), &result);
                    result->set_length(VECTOR_SIZE);
                    check_equality(xy, result->get_packed_value(), eps, msg + ": EvalMultMutable fails");
                }
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_mult_packed(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints2(vector_of_ints7_0);
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

            // vector_of_ints_mult = { 0,6,10,12,12,10,6,0 };
            std::vector<int64_t> vector_of_ints_mult(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                vector_of_ints_mult[i] = i * VECTOR_SIZE - i * i - i;
            }
            Plaintext plaintext_mult = cc->make_packed_plaintext(vector_of_ints_mult);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);
            Ciphertext<Element> c_result;
            Plaintext results;

            // Testing eval_mult
            cc->eval_mult(ciphertext1, plaintext1);
            cc->eval_mult(ciphertext2, plaintext2);
            c_result = cc->eval_mult(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_packed_value(), results->get_packed_value(), eps, failmsg + " EvalMult fails");

            // Testing operator*
            c_result = ciphertext1 * ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " operator* fails");

            // Testing operator*=
            Ciphertext<Element> cmult_inplace(ciphertext1);
            cmult_inplace *= ciphertext2;
            cc->decrypt(kp.secret_key, cmult_inplace, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " operator*= fails");

            // Testing eval_mult ciphertext * plaintext
            c_result = cc->eval_mult(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalMult Ct and Pt fails");

            // Testing eval_mult_no_relin ciphertext * ciphertext
            c_result = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalMultNoRelin Ct and Ct fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_at_index(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1(vector_of_ints1_8);
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> v_ones(vector_of_ints1s);
            Plaintext p_ones = cc->make_packed_plaintext(v_ones);

            // v_ints_right_shift2 = { 0,0,1,2,3,4,5,6 };
            std::vector<int64_t> v_ints_right_shift2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                v_ints_right_shift2[i] = (i >= 2) ? vector_of_ints1[i - 2] : 0;
            }
            Plaintext plaintext_right2 = cc->make_packed_plaintext(v_ints_right_shift2);

            // v_ints_left_shift2 = { 3,4,5,6,7,8,0,0 };
            std::vector<int64_t> v_ints_left_shift2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                v_ints_left_shift2[i] = (i < VECTOR_SIZE - 2) ? vector_of_ints1[i + 2] : 0;
            }
            Plaintext plaintext_left2 = cc->make_packed_plaintext(v_ints_left_shift2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->eval_at_index_key_gen(kp.secret_key, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);
            Ciphertext<Element> c_result;
            Plaintext results;

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            ciphertext1 *= c_ones;

            // Testing eval_at_index +2
            c_result = cc->eval_at_index(ciphertext1, 2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_left2->get_length());
            check_equality(plaintext_left2->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAtIndex(+2) fails");

            // Testing eval_at_index -2
            c_result = cc->eval_at_index(ciphertext1, -2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_right2->get_length());
            check_equality(plaintext_right2->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAtIndex(-2) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_merge(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // v* = { i,0,0,0,0,0,0,0 };
            std::vector<int64_t> v_one{1, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_two{2, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_three{3, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_four{4, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_five{5, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_six{6, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_seven{7, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> v_eight{8, 0, 0, 0, 0, 0, 0, 0};
            Plaintext p_one = cc->make_packed_plaintext(v_one);
            Plaintext p_two = cc->make_packed_plaintext(v_two);
            Plaintext p_three = cc->make_packed_plaintext(v_three);
            Plaintext p_four = cc->make_packed_plaintext(v_four);
            Plaintext p_five = cc->make_packed_plaintext(v_five);
            Plaintext p_six = cc->make_packed_plaintext(v_six);
            Plaintext p_seven = cc->make_packed_plaintext(v_seven);
            Plaintext p_eight = cc->make_packed_plaintext(v_eight);

            std::vector<int64_t> v_merged(vector_of_ints1_8);
            Plaintext p_merged = cc->make_packed_plaintext(v_merged);

            std::vector<int64_t> v_ones(vector_of_ints1s);
            Plaintext p_ones = cc->make_packed_plaintext(v_ones);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for all right rotations 1 to 8.
            std::vector<int32_t> index_list{-1, -2, -3, -4, -5, -6, -7, -8};
            cc->eval_at_index_key_gen(kp.secret_key, index_list);

            // Encrypt plaintexts
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);
            std::vector<Ciphertext<Element>> ciphertexts;

            // Here, we perform the same trick (mult with one) as in
            // UnitTest_EvalAtiIndex.
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_one) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_two) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_three) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_four) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_five) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_six) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_seven) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_eight) * c_ones);
            Plaintext results;

            // Testing eval_merge
            auto c_result = cc->eval_merge(ciphertexts);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(p_merged->get_length());
            check_equality(p_merged->get_packed_value(), results->get_packed_value(), eps, failmsg + " EvalMerge fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_re_encryption(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            auto ptm = 10;
            size_t re_encrypt_vec_size = 128;

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < re_encrypt_vec_size; ii++) {
                intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));  // NOLINT
            }
            Plaintext plaintext_int = cc->make_packed_plaintext(intvec);

            KeyPair<Element> kp = cc->key_gen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

            KeyPair<Element> new_kp = cc->key_gen();
            EXPECT_EQ(new_kp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

            // This generates the keys which are used to perform the key switching.
            EvalKey<Element> eval_key = cc->re_key_gen(kp.secret_key, new_kp.public_key);

            Ciphertext<Element> ciphertext = cc->encrypt(kp.public_key, plaintext_int);
            Ciphertext<Element> re_ciphertext = cc->re_encrypt(ciphertext, eval_key);
            Plaintext plaintext_int_new;
            cc->decrypt(new_kp.secret_key, re_ciphertext, &plaintext_int_new);
            plaintext_int_new->set_length(plaintext_int->get_length());
            auto tmp_a = plaintext_int_new->get_packed_value();
            auto tmp_b = plaintext_int->get_packed_value();
            std::stringstream buffer;
            buffer << tmp_b << " - we get: " << tmp_a << std::endl;
            check_equality(tmp_a, tmp_b, eps, failmsg + " ReEncrypt integer plaintext " + buffer.str());

            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext_int);
            Ciphertext<Element> re_ciphertext2 = cc->re_encrypt(ciphertext2, eval_key, kp.public_key);
            Plaintext plaintext_int_new2;
            cc->decrypt(new_kp.secret_key, re_ciphertext2, &plaintext_int_new2);
            plaintext_int_new2->set_length(plaintext_int->get_length());
            tmp_a = plaintext_int_new2->get_packed_value();
            tmp_b = plaintext_int->get_packed_value();
            std::stringstream buffer2;
            buffer2 << tmp_b << " - we get: " << tmp_a << std::endl;
            check_equality(tmp_a, tmp_b, eps, failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_auto_level_reduce(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> vector_of_ints2(vector_of_ints7_0);
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);

            std::vector<int64_t> p_ct_mult(VECTOR_SIZE);
            std::vector<int64_t> p_ct_mult3(VECTOR_SIZE);
            std::vector<int64_t> p_ct3(VECTOR_SIZE);
            std::vector<int64_t> p_ct3_b(VECTOR_SIZE);
            std::vector<int64_t> p_ct4(VECTOR_SIZE);
            std::vector<int64_t> p_ct5(VECTOR_SIZE);
            std::vector<int64_t> p_ct6(VECTOR_SIZE);
            std::vector<int64_t> p_ct7(VECTOR_SIZE);
            std::vector<int64_t> p_ct_5(VECTOR_SIZE);
            std::vector<int64_t> p_ct_6(VECTOR_SIZE);
            std::vector<int64_t> p_ct_7(VECTOR_SIZE);
            std::vector<int64_t> p_ct8(VECTOR_SIZE);
            std::vector<int64_t> p_ct9(VECTOR_SIZE);
            std::vector<int64_t> p_ct10(VECTOR_SIZE);
            std::vector<int64_t> p_ct11(VECTOR_SIZE);
            std::vector<int64_t> p_ct12(VECTOR_SIZE);
            std::vector<int64_t> p_ct13(VECTOR_SIZE);
            std::vector<int64_t> p_ct14(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                p_ct_mult[i] = vector_of_ints1[i] * vector_of_ints2[i];
                p_ct3[i] = p_ct_mult[i] + vector_of_ints1[i];
                p_ct4[i] = p_ct_mult[i] - vector_of_ints1[i];
                p_ct5[i] = p_ct_mult[i] * vector_of_ints1[i];
                p_ct6[i] = vector_of_ints1[i] + p_ct_mult[i];
                p_ct7[i] = vector_of_ints1[i] - p_ct_mult[i];
                auto tmp =
                        (vector_of_ints1[i] * vector_of_ints1[i] + vector_of_ints1[i] * vector_of_ints1[i]) * vector_of_ints1[i];
                p_ct_5[i] = tmp + vector_of_ints2[i];
                p_ct_6[i] = tmp - vector_of_ints2[i];
                p_ct_7[i] = tmp * vector_of_ints2[i];
                p_ct8[i] = vector_of_ints1[i] * p_ct_mult[i];
                p_ct_mult3[i] = p_ct_mult[i] * vector_of_ints1[i] * vector_of_ints1[i];
                p_ct9[i] = p_ct_mult3[i] + vector_of_ints1[i];
                p_ct10[i] = p_ct_mult3[i] - vector_of_ints1[i];
                p_ct11[i] = p_ct_mult3[i] * vector_of_ints1[i];
                p_ct12[i] = vector_of_ints1[i] + p_ct_mult3[i];
                p_ct13[i] = vector_of_ints1[i] - p_ct_mult3[i];
                p_ct14[i] = vector_of_ints1[i] * p_ct_mult3[i];
            }
            Plaintext plaintext_ct3 = cc->make_packed_plaintext(p_ct3);
            Plaintext plaintext_ct4 = cc->make_packed_plaintext(p_ct4);
            Plaintext plaintext_ct5 = cc->make_packed_plaintext(p_ct5);
            Plaintext plaintext_ct6 = cc->make_packed_plaintext(p_ct6);
            Plaintext plaintext_ct7 = cc->make_packed_plaintext(p_ct7);
            Plaintext plaintext_ct_5 = cc->make_packed_plaintext(p_ct_5);
            Plaintext plaintext_ct_6 = cc->make_packed_plaintext(p_ct_6);
            Plaintext plaintext_ct_7 = cc->make_packed_plaintext(p_ct_7);
            Plaintext plaintext_ct8 = cc->make_packed_plaintext(p_ct8);
            Plaintext plaintext_ct9 = cc->make_packed_plaintext(p_ct9);
            Plaintext plaintext_ct10 = cc->make_packed_plaintext(p_ct10);
            Plaintext plaintext_ct11 = cc->make_packed_plaintext(p_ct11);
            Plaintext plaintext_ct12 = cc->make_packed_plaintext(p_ct12);
            Plaintext plaintext_ct13 = cc->make_packed_plaintext(p_ct13);
            Plaintext plaintext_ct14 = cc->make_packed_plaintext(p_ct14);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ct2 = cc->encrypt(kp.public_key, plaintext2);
            Ciphertext<Element> c_result;
            Plaintext results;

            auto ct_mul = cc->eval_mult(ct, ct2);
            auto ct_red = cc->mod_reduce(ct_mul);
            Ciphertext<Element> ct_red_clone = ct_red->clone();

            auto ct3 = cc->eval_add(ct_red, ct);  // Addition with tower diff = 1
            cc->decrypt(kp.secret_key, ct3, &results);
            results->set_length(plaintext_ct3->get_length());
            check_equality(plaintext_ct3->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " addition with tower diff = 1 fails");

            cc->eval_add_in_place(ct_red_clone, ct);  // In-place addition with tower diff = 1
            cc->decrypt(kp.secret_key, ct_red_clone, &results);
            results->set_length(plaintext_ct3->get_length());
            check_equality(plaintext_ct3->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " in-place addition with tower diff = 1 fails");

            auto ct4 = cc->eval_sub(ct_red, ct);  // Subtraction with tower diff = 1
            cc->decrypt(kp.secret_key, ct4, &results);
            results->set_length(plaintext_ct4->get_length());
            check_equality(plaintext_ct4->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " subtraction with tower diff = 1 fails");

            auto ct5 = cc->eval_mult(ct_red, ct);  // Multiplication with tower diff = 1
            cc->decrypt(kp.secret_key, ct5, &results);
            results->set_length(plaintext_ct5->get_length());
            check_equality(plaintext_ct5->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " multiplication with tower diff = 1 fails");

            auto ct6 = cc->eval_add(ct, ct_red);  // Addition with tower diff = 1 (inputs reversed)
            cc->decrypt(kp.secret_key, ct6, &results);
            results->set_length(plaintext_ct6->get_length());
            check_equality(plaintext_ct6->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " addition (reverse) with tower diff = 1 fails");

            // In-place addition with tower diff = 1 (inputs reversed)
            auto ct_clone = ct->clone();
            cc->eval_add_in_place(ct_clone, ct_red);
            cc->decrypt(kp.secret_key, ct_clone, &results);
            results->set_length(plaintext_ct6->get_length());
            check_equality(plaintext_ct6->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " in-place addition (reverse) with tower diff = 1 fails");

            auto ct7 = cc->eval_sub(ct, ct_red);  // Subtraction with tower diff = 1 (inputs reversed)
            cc->decrypt(kp.secret_key, ct7, &results);
            results->set_length(plaintext_ct7->get_length());
            check_equality(plaintext_ct7->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " subtraction (reverse) with tower diff = 1 fails");

            auto ct8 = cc->eval_mult(ct, ct_red);  // Multiplication with tower diff = 1 (inputs reversed)
            cc->decrypt(kp.secret_key, ct8, &results);
            results->set_length(plaintext_ct8->get_length());
            check_equality(plaintext_ct8->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " multiplication (reverse) with tower diff = 1 fails");

            auto ct_mul2 = cc->eval_mult(ct_red, ct);
            auto ct_red2 = cc->mod_reduce(ct_mul2);
            auto ct_mul3 = cc->eval_mult(ct_red2, ct);
            auto ct_red3 = cc->mod_reduce(ct_mul3);
            auto ct_red3_clone_value = ct_red3->clone();

            auto ct9 = cc->eval_add(ct_red3, ct);  // Addition with more than 1 level difference
            cc->decrypt(kp.secret_key, ct9, &results);
            results->set_length(plaintext_ct9->get_length());
            check_equality(plaintext_ct9->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " addition with tower diff > 1 fails");

            // In-place Addition with more than 1 level difference
            cc->eval_add_in_place(ct_red3_clone_value, ct);
            cc->decrypt(kp.secret_key, ct_red3_clone_value, &results);
            results->set_length(plaintext_ct9->get_length());
            check_equality(plaintext_ct9->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " in-place addition with tower diff > 1 fails");

            auto ct10 = cc->eval_sub(ct_red3, ct);  // Subtraction with more than 1 level difference
            cc->decrypt(kp.secret_key, ct10, &results);
            results->set_length(plaintext_ct10->get_length());
            check_equality(plaintext_ct10->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " subtraction with tower diff > 1 fails");

            auto ct11 = cc->eval_mult(ct_red3, ct);  // Multiplication with more than 1 level difference
            cc->decrypt(kp.secret_key, ct11, &results);
            results->set_length(plaintext_ct11->get_length());
            check_equality(plaintext_ct11->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " multiplication with tower diff > 1 fails");

            // Addition with more than 1 level difference (inputs reversed)
            auto ct12 = cc->eval_add(ct, ct_red3);
            cc->decrypt(kp.secret_key, ct12, &results);
            results->set_length(plaintext_ct12->get_length());
            check_equality(plaintext_ct12->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " addition (reverse) with tower diff > 1 fails");

            // In-place addition with more than 1 level difference (inputs reversed)
            auto ct_clone_value = ct->clone();
            cc->eval_add_in_place(ct_clone_value, ct_red3);
            cc->decrypt(kp.secret_key, ct_clone_value, &results);
            results->set_length(plaintext_ct12->get_length());
            check_equality(plaintext_ct12->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " in-place addition (reverse) with tower diff > 1 fails");

            auto ct13 = cc->eval_sub(ct, ct_red3);  // Subtraction with more than 1 level difference (inputs reversed)
            cc->decrypt(kp.secret_key, ct13, &results);
            results->set_length(plaintext_ct13->get_length());
            check_equality(plaintext_ct13->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " subtraction (reverse) with tower diff > 1 fails");

            auto ct14 = cc->eval_mult(ct, ct_red3);  // Multiplication with more than 1 level difference (inputs reversed)
            cc->decrypt(kp.secret_key, ct14, &results);
            results->set_length(plaintext_ct14->get_length());
            check_equality(plaintext_ct14->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " multiplication (reverse) with tower diff > 1 fails");

            // This scenario tests for operations on
            // ciphertext and plaintext that differ on
            // both scaling factor and number of towers.
            auto ct_1 = cc->eval_mult(ct, plaintext1);
            auto ct_2 = cc->eval_add(ct_1, ct_1);
            auto ct_3 = cc->mod_reduce(ct_2);
            auto ct_4 = cc->eval_mult(ct_3, plaintext1);
            auto ct_5 = cc->eval_add(ct_4, plaintext2);   // Addition with plaintext and tower diff = 1
            auto ct_6 = cc->eval_sub(ct_4, plaintext2);   // Subtraction with plaintext and tower diff = 1
            auto ct_7 = cc->eval_mult(ct_4, plaintext2);  // Multiplication with plaintext and tower diff = 1
            cc->decrypt(kp.secret_key, ct_5, &results);
            results->set_length(plaintext_ct_5->get_length());
            check_equality(plaintext_ct_5->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " addition with plaintext and tower diff = 1 fails");

            cc->decrypt(kp.secret_key, ct_6, &results);
            results->set_length(plaintext_ct_6->get_length());
            check_equality(plaintext_ct_6->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " subtraction with plaintext and tower diff = 1 fails");

            cc->decrypt(kp.secret_key, ct_7, &results);
            results->set_length(plaintext_ct_7->get_length());
            check_equality(plaintext_ct_7->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " multiplication with plaintext and tower diff = 1 fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_compress(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints(vector_of_ints0_7);
            Plaintext plaintext = cc->make_packed_plaintext(vector_of_ints);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->encrypt(kp.public_key, plaintext);
            ct *= ct;
            Ciphertext<Element> c_result;
            Plaintext result;
            Plaintext result_compressed;
            auto algo = cc->get_scheme();
            size_t target_towers = (test_data.params.scal_tech == FLEXIBLEAUTOEXT) ? 2 : 1;
            auto ct_compressed = cc->compress(ct, target_towers);

            size_t towers_left = ct_compressed->get_elements()[0].get_num_of_elements();
            EXPECT_TRUE(towers_left == target_towers) << " compress fails";

            cc->decrypt(kp.secret_key, ct, &result);
            cc->decrypt(kp.secret_key, ct_compressed, &result_compressed);
            check_equality(result->get_packed_value(), result_compressed->get_packed_value(), eps,
                          failmsg + " compress fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_fast_rotation(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> vector_of_ints1(vector_of_ints1_8);
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);

            std::vector<int64_t> v_ones(vector_of_ints1s);
            Plaintext p_ones = cc->make_packed_plaintext(v_ones);

            // v_ints_right_shift2 = { 0,0,1,2,3,4,5,6 };
            std::vector<int64_t> v_ints_right_shift2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                v_ints_right_shift2[i] = (i >= 2) ? vector_of_ints1[i - 2] : 0;
            }
            Plaintext plaintext_right2 = cc->make_packed_plaintext(v_ints_right_shift2);

            // v_ints_left_shift2 = { 3,4,5,6,7,8,0,0 };
            std::vector<int64_t> v_ints_left_shift2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                v_ints_left_shift2[i] = (i < VECTOR_SIZE - 2) ? vector_of_ints1[i + 2] : 0;
            }
            Plaintext plaintext_left2 = cc->make_packed_plaintext(v_ints_left_shift2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->eval_at_index_key_gen(kp.secret_key, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);
            Ciphertext<Element> c_result;
            Plaintext results;

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            ciphertext1 *= c_ones;

            auto decompose = cc->eval_fast_rotation_precompute(ciphertext1);

            uint32_t m = cc->get_crypto_parameters()->get_element_params()->get_cyclotomic_order();
            // Testing eval_at_index +2
            c_result = cc->eval_fast_rotation(ciphertext1, 2, m, decompose);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_left2->get_length());
            check_equality(plaintext_left2->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAtIndex(+2) fails");

            // Testing eval_at_index -2
            c_result = cc->eval_fast_rotation(ciphertext1, -2, m, decompose);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_right2->get_length());
            check_equality(plaintext_right2->get_packed_value(), results->get_packed_value(), eps,
                          failmsg + " EvalAtIndex(-2) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_metadata(const TEST_CASE_UTBGVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<int64_t> input1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_packed_plaintext(input1);

            std::vector<int64_t> input2(vector_of_ints0_7neg);
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
                    << "Ciphertext metadata mismatch in EvalAdd(ctx,ctx)";

            // Checking if metadata is carried over in eval_add_in_place(ctx,ctx)
            Ciphertext<Element> ciphertext1_clone = ciphertext1->clone();
            cc->eval_add_in_place(ciphertext1_clone, ciphertext2);
            auto add_cc_in_place_val_test = MetadataTest::get_metadata<Element>(ciphertext1_clone);
            EXPECT_EQ(val1->get_metadata(), add_cc_in_place_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

            // Checking if metadata is carried over in eval_add(ctx,ptx)
            Ciphertext<Element> c_add_cp = cc->eval_add(ciphertext1, plaintext1);
            auto add_cp_val_test = MetadataTest::get_metadata<Element>(c_add_cp);
            EXPECT_EQ(val1->get_metadata(), add_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAdd(ctx,ptx)";

            // Checking if metadata is carried over in eval_sub(ctx,ctx)
            Ciphertext<Element> c_sub_cc = cc->eval_sub(ciphertext1, ciphertext2);
            auto sub_cc_val_test = MetadataTest::get_metadata<Element>(c_sub_cc);
            EXPECT_EQ(val1->get_metadata(), sub_cc_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalSub(ctx,ctx)";

            // Checking if metadata is carried over in eval_sub(ctx,ptx)
            Ciphertext<Element> c_sub_cp = cc->eval_sub(ciphertext1, plaintext1);
            auto sub_cp_val_test = MetadataTest::get_metadata<Element>(c_sub_cp);
            EXPECT_EQ(val1->get_metadata(), sub_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalSub(ctx,ptx)";

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
                    << "Ciphertext metadata mismatch in EvalAtIndex +2";

            // Checking if metadata is carried over in eval_at_index -2 (right rotate)
            auto c_at_index_minus2 = cc->eval_at_index(ciphertext1, -2);
            auto at_index_minus2_val_test = MetadataTest::get_metadata<Element>(c_at_index_minus2);
            EXPECT_EQ(val1->get_metadata(), at_index_minus2_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAtIndex -2";

            std::vector<double> weights(2);
            for (int i = 0; i < 2; i++)
                weights[i] = i;

            std::vector<Ciphertext<Element>> ciphertexts(2);
            ciphertexts[0] = ciphertext1;
            ciphertexts[1] = ciphertext2;

            // Checking if metadata is carried over in eval_sum
            auto c_sum = cc->eval_sum(ciphertext1, VECTOR_SIZE);
            auto sum_val_test = MetadataTest::get_metadata<Element>(c_sum);
            EXPECT_EQ(val1->get_metadata(), sum_val_test->get_metadata()) << "Ciphertext metadata mismatch in EvalSum";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_cryptoparams_validation(const TEST_CASE_UTBGVRNS& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // make it fail
            EXPECT_EQ(0, 1);
        } catch (CipherException& e) {
            // expected an exception
            EXPECT_TRUE(1 == 1) << failmsg;
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
TEST_P(UTBGVRNS, BGVRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case ADD_PACKED_UTBGVRNS:
            unit_test_add_packed(test, test.build_test_name());
            break;
        case MULT_PACKED_UTBGVRNS:
            unit_test_mult_packed(test, test.build_test_name());
            break;
        case EVALATINDEX_UTBGVRNS:
            unit_test_eval_at_index(test, test.build_test_name());
            break;
        case EVALMERGE_UTBGVRNS:
            unit_test_eval_merge(test, test.build_test_name());
            break;
        case RE_ENCRYPTION_UTBGVRNS:
            unit_test_re_encryption(test, test.build_test_name());
            break;
        case AUTO_LEVEL_REDUCE_UTBGVRNS:
            unit_test_auto_level_reduce(test, test.build_test_name());
            break;
        case COMPRESS_UTBGVRNS:
            unit_test_compress(test, test.build_test_name());
            break;
        case EVAL_FAST_ROTATION_UTBGVRNS:
            unit_test_eval_fast_rotation(test, test.build_test_name());
            break;
        case METADATA_UTBGVRNS:
            unit_test_metadata(test, test.build_test_name());
            break;
        case CRYPTOPARAMS_VALIDATION_UTBGVRNS:
            unit_test_cryptoparams_validation(test, test.build_test_name());
            break;
        case MULT_PLAINTEXT_AT_LEVEL_UTBGVRNS:
            unit_test_mult_plaintext_at_level(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS, ::testing::ValuesIn(test_cases_utbgvrns), testName);
