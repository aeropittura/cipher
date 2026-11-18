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
#include "fhe/support/metadata_test.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;

#if CIPHER_NATIVE_INT == 64
//===========================================================================================================
enum TEST_CASE_TYPE : int {
    ADD_PACKED = 0,
    MULT_PACKED,
    SCALE_FACTOR_ADJUSTMENTS,
    AUTO_LEVEL_REDUCE,
    COMPRESS,
    EVAL_FAST_ROTATION,
    EVALATINDEX,
    EVALMERGE,
    EVAL_LINEAR_WSUM,
    RE_ENCRYPTION,
    EVAL_POLY,
    METADATA,
    ADD_PACKED_PRECISION,
    MULT_PACKED_PRECISION,
    EVALSQUARE,
    SMALL_SCALING_MOD_SIZE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case ADD_PACKED:
            typeName = "ADD_PACKED";
            break;
        case MULT_PACKED:
            typeName = "MULT_PACKED";
            break;
        case SCALE_FACTOR_ADJUSTMENTS:
            typeName = "SCALE_FACTOR_ADJUSTMENTS";
            break;
        case AUTO_LEVEL_REDUCE:
            typeName = "AUTO_LEVEL_REDUCE";
            break;
        case COMPRESS:
            typeName = "COMPRESS";
            break;
        case EVAL_FAST_ROTATION:
            typeName = "EVAL_FAST_ROTATION";
            break;
        case EVALATINDEX:
            typeName = "EVALATINDEX";
            break;
        case EVALMERGE:
            typeName = "EVALMERGE";
            break;
        case EVAL_LINEAR_WSUM:
            typeName = "EVAL_LINEAR_WSUM";
            break;
        case RE_ENCRYPTION:
            typeName = "RE_ENCRYPTION";
            break;
        case EVAL_POLY:
            typeName = "EVAL_POLY";
            break;
        case METADATA:
            typeName = "METADATA";
            break;
        case ADD_PACKED_PRECISION:
            typeName = "ADD_PACKED_PRECISION";
            break;
        case MULT_PACKED_PRECISION:
            typeName = "MULT_PACKED_PRECISION";
            break;
        case EVALSQUARE:
            typeName = "EVALSQUARE";
            break;
        case SMALL_SCALING_MOD_SIZE:
            typeName = "SMALL_SCALING_MOD_SIZE";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_CS {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    // ........
    uint32_t slots;
    ScalingTechnique lower_precision_technique;
    ScalingTechnique higher_precision_technique;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_CS>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_CS& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
/***
 * DSIZE: The bit decomposition count used in BV relinearization.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
constexpr uint32_t RING_DIM = 512;
constexpr uint32_t RING_DIM_HALF = 256;
constexpr uint32_t DSIZE = 10;
constexpr uint32_t BATCH = 8;
// #if CIPHER_NATIVE_INT != 128 && !defined(__EMSCRIPTEN__)
// constexpr uint32_t RING_DIM_PREC = 2048;  // for test cases with approximation error comparison only
// #endif
// MIN_PRECISION_DIFF is the minimal difference expected between approximation error/precision for FLEXIBLEAUTO and FLEXIBLEAUTOEXT
constexpr double MIN_PRECISION_DIFF = 1.5;
// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_CS> test_cases = {
    // TestType,  Descr, Scheme,         RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { ADD_PACKED, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         60,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { ADD_PACKED, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         90,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { ADD_PACKED, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { ADD_PACKED, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { ADD_PACKED, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { ADD_PACKED, "06", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,         118,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,   DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    // TestType,  Descr, Scheme,         RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { ADD_PACKED, "11", {CKKSRNS_SCHEME, RING_DIM, 7,         63,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 3},   0},
    { ADD_PACKED, "12", {CKKSRNS_SCHEME, RING_DIM, 7,         90,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 4},   0},
    { ADD_PACKED, "13", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 64, 2},   0},
    { ADD_PACKED, "14", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          54,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 2},   0},
    { ADD_PACKED, "15", {CKKSRNS_SCHEME, RING_DIM, 7,         89,       DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, 4},   0},
    { ADD_PACKED, "16", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   UNIFORM_TERNARY, DFLT,         118,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 48, 3},   0},
    // ==========================================
    // TestType,  Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,              LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { MULT_PACKED, "01", {CKKSRNS_SCHEME, RING_DIM, 7,          52,      DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { MULT_PACKED, "02", {CKKSRNS_SCHEME, RING_DIM, 7,          63,      DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { MULT_PACKED, "03", {CKKSRNS_SCHEME, RING_DIM, 7,          66,      DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { MULT_PACKED, "04", {CKKSRNS_SCHEME, RING_DIM, 7,          80,      DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    { MULT_PACKED, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT},   0},
    // TestType,  Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { MULT_PACKED, "31", {CKKSRNS_SCHEME, RING_DIM, 7,          52,      DSIZE, BATCH,   DFLT,       DFLT,          54,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 2},   0},
    { MULT_PACKED, "32", {CKKSRNS_SCHEME, RING_DIM, 7,          63,      DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 3},   0},
    { MULT_PACKED, "33", {CKKSRNS_SCHEME, RING_DIM, 7,          89,      DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, 4},   0},
    { MULT_PACKED, "34", {CKKSRNS_SCHEME, RING_DIM, 7,          80,      DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 27, 4},   0},
    { MULT_PACKED, "35", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 48, 3},   0},
    // ==========================================
    // TestType,  Descr, Scheme,          RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,              LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { MULT_PACKED, "11", {CKKSRNS_SCHEME, RING_DIM, 7,          52,      DSIZE, BATCH,   DFLT,       DFLT,          62,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   32},
    { MULT_PACKED, "12", {CKKSRNS_SCHEME, RING_DIM, 7,          54,      DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   32},
    { MULT_PACKED, "13", {CKKSRNS_SCHEME, RING_DIM, 7,          66,      DSIZE, BATCH,   DFLT,       DFLT,          86,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   32},
    { MULT_PACKED, "14", {CKKSRNS_SCHEME, RING_DIM, 7,          80,      DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   32},
    { MULT_PACKED, "15", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   32},
    // ==========================================
    // TestType,  Descr, Scheme,          RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,              LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { MULT_PACKED, "21", {CKKSRNS_SCHEME, RING_DIM, 7,          52,      DSIZE, BATCH,   DFLT,       DFLT,           62,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   RING_DIM_HALF},
    { MULT_PACKED, "22", {CKKSRNS_SCHEME, RING_DIM, 7,          54,      DSIZE, BATCH,   DFLT,       DFLT,           64,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   RING_DIM_HALF},
    { MULT_PACKED, "23", {CKKSRNS_SCHEME, RING_DIM, 7,          66,      DSIZE, BATCH,   DFLT,       DFLT,           96,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   RING_DIM_HALF},
    { MULT_PACKED, "24", {CKKSRNS_SCHEME, RING_DIM, 7,          80,      DSIZE, BATCH,   DFLT,       DFLT,           96,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   RING_DIM_HALF},
    { MULT_PACKED, "25", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT},   RING_DIM_HALF},
    // ==========================================
    // TestType,               Descr, Scheme,           RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,              LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { SCALE_FACTOR_ADJUSTMENTS, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          62,       HEStd_NotSet, HYBRID,  COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID,  COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         60,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID,  COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // ==========================================
    // TestType,  Descr, Scheme,                 RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { AUTO_LEVEL_REDUCE, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,           62,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { AUTO_LEVEL_REDUCE, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,           64,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { AUTO_LEVEL_REDUCE, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,           76,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { AUTO_LEVEL_REDUCE, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,           90,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { AUTO_LEVEL_REDUCE, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,          118,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },

    // ==========================================
    // TestType, Descr, Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { COMPRESS, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,           62,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { COMPRESS, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,           64,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { COMPRESS, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,           76,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { COMPRESS, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,           90,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { COMPRESS, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,          118,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },

    // ==========================================
    // TestType,         Descr,  Scheme,         RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { EVAL_FAST_ROTATION, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVAL_FAST_ROTATION, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVAL_FAST_ROTATION, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVAL_FAST_ROTATION, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVAL_FAST_ROTATION, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},

    { EVAL_FAST_ROTATION, "09", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 1},
    { EVAL_FAST_ROTATION, "10", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 1},
    { EVAL_FAST_ROTATION, "11", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 1},
    { EVAL_FAST_ROTATION, "12", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 1},
    { EVAL_FAST_ROTATION, "13", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 1},

    { EVAL_FAST_ROTATION, "17", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 2},
    { EVAL_FAST_ROTATION, "18", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 2},
    { EVAL_FAST_ROTATION, "19", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 2},
    { EVAL_FAST_ROTATION, "20", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 2},
    { EVAL_FAST_ROTATION, "21", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 2},

    { EVAL_FAST_ROTATION, "25", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 4},
    { EVAL_FAST_ROTATION, "26", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 4},
    { EVAL_FAST_ROTATION, "27", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 4},
    { EVAL_FAST_ROTATION, "28", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 4},
    { EVAL_FAST_ROTATION, "29", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 4},

    { EVAL_FAST_ROTATION, "33", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, BATCH},
    { EVAL_FAST_ROTATION, "34", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, BATCH},
    { EVAL_FAST_ROTATION, "35", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, BATCH},
    { EVAL_FAST_ROTATION, "36", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, BATCH},
    { EVAL_FAST_ROTATION, "37", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, BATCH},

    { EVAL_FAST_ROTATION, "41", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, RING_DIM_HALF},
    { EVAL_FAST_ROTATION, "42", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, RING_DIM_HALF},
    { EVAL_FAST_ROTATION, "43", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, RING_DIM_HALF},
    { EVAL_FAST_ROTATION, "44", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, RING_DIM_HALF},
    { EVAL_FAST_ROTATION, "45", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, RING_DIM_HALF},

    // ==========================================
    // TestType,  Descr, Scheme,          RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, Slots
    { EVALATINDEX, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            62,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVALATINDEX, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         54,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVALATINDEX, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            76,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVALATINDEX, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            90,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    { EVALATINDEX, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         108,      DSIZE, BATCH,   DFLT,       DFLT,           118,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, 0},
    // ==========================================
    // TestType,  Descr, Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVALMERGE, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALMERGE, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         55,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALMERGE, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            96,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALMERGE, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            96,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALMERGE, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,           120,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // ==========================================
    // TestType,  Descr, Scheme,               RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVAL_LINEAR_WSUM, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_LINEAR_WSUM, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         55,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_LINEAR_WSUM, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_LINEAR_WSUM, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_LINEAR_WSUM, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // TestType,  Descr, Scheme,               RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVAL_LINEAR_WSUM, "11", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          56,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 28, 2}, },
    { EVAL_LINEAR_WSUM, "12", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          54,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 2}, },
    { EVAL_LINEAR_WSUM, "13", {CKKSRNS_SCHEME, RING_DIM, 7,         86,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 48, 2}, },
    { EVAL_LINEAR_WSUM, "14", {CKKSRNS_SCHEME, RING_DIM, 7,         90,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 4}, },
    { EVAL_LINEAR_WSUM, "15", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 3}, },
    // ==========================================
    // TestType,  Descr, Scheme,            RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { RE_ENCRYPTION, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { RE_ENCRYPTION, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         55,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { RE_ENCRYPTION, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { RE_ENCRYPTION, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { RE_ENCRYPTION, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // ==========================================
    // TestType,  Descr, Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVAL_POLY, "01", {CKKSRNS_SCHEME, RING_DIM, 5,         52,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_POLY, "02", {CKKSRNS_SCHEME, RING_DIM, 5,         55,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_POLY, "03", {CKKSRNS_SCHEME, RING_DIM, 5,         66,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_POLY, "04", {CKKSRNS_SCHEME, RING_DIM, 5,         80,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVAL_POLY, "05", {CKKSRNS_SCHEME, RING_DIM, 5,         117,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // TestType,  Descr, Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVAL_POLY, "11", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          56,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 28, 2}, },
    { EVAL_POLY, "12", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          54,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 2}, },
    { EVAL_POLY, "13", {CKKSRNS_SCHEME, RING_DIM, 7,         86,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 48, 2}, },
    { EVAL_POLY, "14", {CKKSRNS_SCHEME, RING_DIM, 7,         90,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 4}, },
    { EVAL_POLY, "15", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 3}, },
    // ==========================================
    // TestType,  Descr, Scheme,       RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { METADATA, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { METADATA, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         55,       DSIZE, BATCH,   DFLT,       DFLT,            64,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { METADATA, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,            96,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { METADATA, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,            96,     HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { METADATA, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,            120,    HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // ==========================================
    // TestType,  Descr, Scheme,         RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,             LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVALSQUARE, "01", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALSQUARE, "02", {CKKSRNS_SCHEME, RING_DIM, 7,         55,       DSIZE, BATCH,   DFLT,       DFLT,          64,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALSQUARE, "03", {CKKSRNS_SCHEME, RING_DIM, 7,         66,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALSQUARE, "04", {CKKSRNS_SCHEME, RING_DIM, 7,         80,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    { EVALSQUARE, "05", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,         120,       HEStd_NotSet, HYBRID, COMPOSITESCALINGAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 32, DFLT}, },
    // TestType,  Descr, Scheme,         RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,               LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree
    { EVALSQUARE, "11", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          56,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 28, 2}, },
    { EVALSQUARE, "12", {CKKSRNS_SCHEME, RING_DIM, 7,         52,       DSIZE, BATCH,   DFLT,       DFLT,          54,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 2}, },
    { EVALSQUARE, "13", {CKKSRNS_SCHEME, RING_DIM, 7,         86,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 48, 2}, },
    { EVALSQUARE, "14", {CKKSRNS_SCHEME, RING_DIM, 7,         90,       DSIZE, BATCH,   DFLT,       DFLT,          96,       HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 27, 4}, },
    { EVALSQUARE, "15", {CKKSRNS_SCHEME, RING_DIM, 7,         118,      DSIZE, BATCH,   DFLT,       DFLT,          120,      HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT, DFLT, DFLT, DFLT, DFLT, 64, 3}, },
};
// clang-format on
//===========================================================================================================
/**
 * Function to check minimal difference between 2 numeric values
 *
 * @param high    higher value
 * @param low     lower value
 * @param diff    minimal expected difference between high and low
 */
template <typename T>
bool check_min_diff(const T& high, const T& low, const uint32_t diff) {
    if (high > low)
        return ((high - low) >= diff);
    return false;
}

/**
 * Function to check minimal difference between elements of 2 vectors with numeric values
 *
 * @param high   vector with higher values
 * @param low    vector with lower values
 * @param diff   minimal expected difference between elements in high and low
 */
template <typename V>
bool check_min_diff(const std::vector<V>& high, const std::vector<V>& low, const uint32_t diff) {
    if (high.size() != low.size())
        return false;

    return std::equal(high.begin(), high.end(), low.begin(),
                      [&diff](const V& high, const V& low) { return check_min_diff(high, low, diff); });
}

/**
 * Function to check minimal difference between elements of 2 vectors with numeric values
 *
 * @param high   vector with higher values
 * @param low    vector with lower values
 * @param err_msg Debug message to display upon failure
 * @param diff   minimal expected difference between elements in high and low
 */
template <typename V>
void check_min_diff(const std::vector<V>& high, const std::vector<V>& low, const uint32_t diff,
                  const std::string& err_msg) {
    // print vector values to error message
    std::stringstream ss;
    ss << ": HIGHER precision/LOWER error: [";
    std::copy(high.begin(), high.end(), std::ostream_iterator<V>(ss, " "));
    ss << "]; LOWER precisions/HIGHER error: [";
    std::copy(low.begin(), low.end(), std::ostream_iterator<V>(ss, " "));
    ss << "]";

    std::string msg(err_msg);
    msg += ss.str();
    EXPECT_TRUE(check_min_diff(high, low, diff)) << msg;
}
//===========================================================================================================
class UTCKKSRNSCS : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_CS> {
    using Element = RnsPoly;

    // the size for all vectors remains const - 8 elements
    const uint32_t VECTOR_SIZE = 8;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = EPSILON;

    const double eps_high = 0.00001;

    const double factor = 1 << 25;

    const std::vector<std::complex<double>> vector_of_ints0_7{0, 1, 2, 3, 4, 5, 6, 7};
    const std::vector<std::complex<double>> vector_of_ints0_7_neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<std::complex<double>> vector_of_ints0_7_add{0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5};
    const std::vector<std::complex<double>> vector_of_ints0_7_add_large_scalar{
            0 + factor, 1 + factor, 2 + factor, 3 + factor, 4 + factor, 5 + factor, 6 + factor, 7 + factor};
    const std::vector<std::complex<double>> vector_of_ints0_7_sub{-0.5, 0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5};
    const std::vector<std::complex<double>> vector_of_ints0_7neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<std::complex<double>> vector_of_ints7_0{7, 6, 5, 4, 3, 2, 1, 0};

    const std::vector<std::complex<double>> vector_of_ints1_8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<std::complex<double>> vector_of_ints1_8neg{-1, -2, -3, -4, -5, -6, -7, -8};
    const std::vector<std::complex<double>> vector_of_ints8_1{8, 7, 6, 5, 4, 3, 2, 1};

    const std::vector<std::complex<double>> vector_of_ints1s{1, 1, 1, 1, 1, 1, 1, 1};  // all 1's

    // calculate_approximation_error() calculates the precision number (or approximation error).
    // The higher the precision, the less the error.
    template <typename T>
    double calculate_approximation_error(const std::vector<std::complex<double>>& result,
                                       const std::vector<std::complex<double>>& expected_result) {
        CIPHER_THROW("CalculateApproximationError() is not implemented for this datatype");
    }

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    template <typename T>
    bool unit_test_add_packed(const TEST_CASE_UTCKKSRNS_CS& test_data, std::vector<T>& approximation_errors,
                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints0_7, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext1_add_scalar =
                    cc->make_ckks_packed_plaintext(vector_of_ints0_7_add, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext1_add_large_scalar =
                    cc->make_ckks_packed_plaintext(vector_of_ints0_7_add_large_scalar, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext1_sub_scalar =
                    cc->make_ckks_packed_plaintext(vector_of_ints0_7_sub, 1, 0, nullptr, test_data.slots);
            Plaintext negatives1 = cc->make_ckks_packed_plaintext(vector_of_ints0_7neg, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints7_0, 1, 0, nullptr, test_data.slots);

            Plaintext plaintext_add = cc->make_ckks_packed_plaintext(std::vector<std::complex<double>>(VECTOR_SIZE, 7), 1,
                                                                 0, nullptr, test_data.slots);  // vector of 7s
            Plaintext plaintext_sub = cc->make_ckks_packed_plaintext(
                    std::vector<std::complex<double>>{-7, -5, -3, -1, 1, 3, 5, 7}, 1, 0, nullptr, test_data.slots);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext1_mutable = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);

            // Testing eval_add
            Plaintext results;
            Ciphertext<Element> c_result;

            c_result = cc->eval_add(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAdd fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value()));

            cc->eval_add_in_place(ciphertext1_mutable, ciphertext2);
            cc->decrypt(kp.secret_key, ciphertext1_mutable, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAddInPlace fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing operator+
            c_result = ciphertext1 + ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator+ fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing operator+=
            Ciphertext<Element> cadd_inplace(ciphertext1);
            cadd_inplace += ciphertext2;
            cc->decrypt(kp.secret_key, cadd_inplace, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator+= fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value()));

            c_result = cc->eval_sub(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalSub fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing operator-
            c_result = ciphertext1 - ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator- fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing operator-=
            Ciphertext<Element> csub_inplace(ciphertext1);
            csub_inplace -= ciphertext2;
            cc->decrypt(kp.secret_key, csub_inplace, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator-= fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing eval_add ciphertext + plaintext
            c_result = cc->eval_add(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_add->get_length());
            check_equality(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAdd Ct and Pt fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_add->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing eval_sub ciphertext - plaintext
            c_result = cc->eval_sub(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_sub->get_length());
            check_equality(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalSub Ct and Pt fails fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_sub->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing eval_add ciphertext + double
            c_result = cc->eval_add(ciphertext1, 0.5);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext1_add_scalar->get_length());
            check_equality(plaintext1_add_scalar->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAdd Ct and double fails");
            approximation_errors.emplace_back(calculate_approximation_error<T>(plaintext1_add_scalar->get_ckks_packed_value(),
                                                                            results->get_ckks_packed_value()));

            // Testing eval_add ciphertext - double
            c_result = cc->eval_sub(ciphertext1, 0.5);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext1_sub_scalar->get_length());
            check_equality(plaintext1_sub_scalar->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalSub Ct and double fails");
            approximation_errors.emplace_back(calculate_approximation_error<T>(plaintext1_sub_scalar->get_ckks_packed_value(),
                                                                            results->get_ckks_packed_value()));

            // Testing eval_add ciphertext + negative double
            c_result = cc->eval_add(ciphertext1, -0.5);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext1_sub_scalar->get_length());
            check_equality(plaintext1_sub_scalar->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAdd Ct and negative double fails");
            approximation_errors.emplace_back(calculate_approximation_error<T>(plaintext1_sub_scalar->get_ckks_packed_value(),
                                                                            results->get_ckks_packed_value()));

            // Testing eval_add ciphertext - negative double
            c_result = cc->eval_sub(ciphertext1, -0.5);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext1_add_scalar->get_length());
            check_equality(plaintext1_add_scalar->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalSub Ct and negative double fails");
            approximation_errors.emplace_back(calculate_approximation_error<T>(plaintext1_add_scalar->get_ckks_packed_value(),
                                                                            results->get_ckks_packed_value()));
            if (test_data.params.multiplicative_depth > 0) {
                // Testing eval_add ciphertext + large double
                c_result = cc->eval_add(ciphertext1, factor);
                cc->decrypt(kp.secret_key, c_result, &results);
                results->set_length(plaintext1_add_large_scalar->get_length());
                check_equality(plaintext1_add_large_scalar->get_ckks_packed_value(), results->get_ckks_packed_value(),
                              factor * eps, failmsg + " EvalAdd Ct and large double fails");
            }

            // Testing eval_negate
            c_result = cc->eval_negate(ciphertext1);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(negatives1->get_length());
            check_equality(negatives1->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalNegate fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(negatives1->get_ckks_packed_value(), results->get_ckks_packed_value()));

            return true;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        return false;
    }

    void unit_test_add_packed(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        std::vector<double> precisions;
        unit_test_add_packed(test_data, precisions, failmsg);
    }

    void unit_test_add_packed_precision(const TEST_CASE_UTCKKSRNS_CS& test_data,
                                       const std::string& failmsg = std::string()) {
        TEST_CASE_UTCKKSRNS_CS test_data_local(test_data);

        std::vector<double> low_precisions;
        ContextFactory<RnsPoly>::release_all_contexts();
        test_data_local.params.scal_tech = test_data_local.lower_precision_technique;
        if (!unit_test_add_packed(test_data_local, low_precisions, failmsg))
            return;

        std::vector<double> high_precisions;
        ContextFactory<RnsPoly>::release_all_contexts();
        test_data_local.params.scal_tech = test_data_local.higher_precision_technique;
        if (!unit_test_add_packed(test_data_local, high_precisions, failmsg))
            return;

        check_min_diff(high_precisions, low_precisions, MIN_PRECISION_DIFF,
                     failmsg + " Approximation errors' comparison failed");
    }

    template <typename T>
    bool unit_test_mult_packed(const TEST_CASE_UTCKKSRNS_CS& test_data, std::vector<T>& approximation_errors,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints0_7, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints7_0, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext_neg = cc->make_ckks_packed_plaintext(vector_of_ints0_7_neg, 1, 0, nullptr, test_data.slots);
            Plaintext plaintext_mult = cc->make_ckks_packed_plaintext(
                    std::vector<std::complex<double>>({0, 6, 10, 12, 12, 10, 6, 0}), 1, 0, nullptr, test_data.slots);
            Plaintext plaintext_large =
                    cc->make_ckks_packed_plaintext(std::vector<std::complex<double>>({factor, factor, 0, 0, 0, 0, 0, 0}),
                                                1, 0, nullptr, test_data.slots);
            Plaintext plaintext_large_mult = cc->make_ckks_packed_plaintext(
                    std::vector<std::complex<double>>({7 * factor, 6 * factor, 0, 0, 0, 0, 0, 0}), 1, 0, nullptr,
                    test_data.slots);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);

            // adding an extra multiplication so that precision tests could clearly
            // show differences between different scaling techniques
            ciphertext1 = cc->eval_mult(ciphertext1, 1.0);
            // cc->rescale_in_place(ciphertext1);
            ciphertext2 = cc->eval_mult(ciphertext2, 1.0);
            // cc->rescale_in_place(ciphertext2);

            // Testing eval_mult
            Ciphertext<Element> c_result;
            Plaintext results;
            c_result = cc->eval_mult(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMult fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing eval_mult by a large plaintext
            c_result = cc->eval_mult(ciphertext2, plaintext_large);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_large_mult->get_length());
            check_equality(plaintext_large_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), factor * eps,
                          failmsg + " EvalMult by a large plaintext fails");

            // Testing operator*
            c_result = ciphertext1 * ciphertext2;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator* fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing operator*=
            Ciphertext<Element> cmult_inplace(ciphertext1);
            cmult_inplace *= ciphertext2;
            cc->decrypt(kp.secret_key, cmult_inplace, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " operator*= fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value()));

            // Testing eval_mult ciphertext * plaintext
            c_result = cc->eval_mult(ciphertext1, plaintext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMult Ct and Pt fails");

            // Testing eval_mult ciphertext * positive double
            c_result = cc->eval_mult(ciphertext1, 1.0);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext1->get_length());
            check_equality(plaintext1->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMult Ct and positive double fails");

            // Testing eval_mult ciphertext * negative double
            c_result = cc->eval_mult(ciphertext1, -1.0);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_neg->get_length());
            std::stringstream buffer1;
            buffer1 << "should be: " << plaintext_neg->get_ckks_packed_value()
                    << " - we get: " << results->get_ckks_packed_value();
            check_equality(plaintext_neg->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMult Ct and negative double fails; " + buffer1.str());

            // Testing eval_mult_no_relin ciphertext * ciphertext
            c_result = cc->eval_mult_no_relin(ciphertext1, ciphertext2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_mult->get_length());
            check_equality(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMultNoRelin Ct fails");
            approximation_errors.emplace_back(
                    calculate_approximation_error<T>(plaintext_mult->get_ckks_packed_value(), results->get_ckks_packed_value()));

            return true;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        return false;
    }

    void unit_test_mult_packed(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        std::vector<double> precisions;
        unit_test_mult_packed(test_data, precisions, failmsg);
    }

    void unit_test_mult_packed_precision(const TEST_CASE_UTCKKSRNS_CS& test_data,
                                        const std::string& failmsg = std::string()) {
        TEST_CASE_UTCKKSRNS_CS test_data_local(test_data);

        std::vector<double> low_precisions;
        ContextFactory<RnsPoly>::release_all_contexts();
        test_data_local.params.scal_tech = test_data_local.lower_precision_technique;
        if (!unit_test_mult_packed(test_data_local, low_precisions, failmsg))
            return;

        std::vector<double> high_precisions;
        ContextFactory<RnsPoly>::release_all_contexts();
        test_data_local.params.scal_tech = test_data_local.higher_precision_technique;
        if (!unit_test_mult_packed(test_data_local, high_precisions, failmsg))
            return;

        check_min_diff(high_precisions, low_precisions, MIN_PRECISION_DIFF,
                     failmsg + " Approximation errors' comparison failed");
    }

    /**
     * Tests the correct operation of the following:
     * - addition/subtraction of constant to ciphertext of depth > 1
     * - addition/subtraction of plaintext to ciphertext of depth > 1
     * - encoding of plaintext at depth > 1
     * - automatic scaling up of plaintexts to a depth that matches that of a
     * ciphertext
     */
    void unit_test_scale_factor_adjustments(const TEST_CASE_UTCKKSRNS_CS& test_data,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<std::complex<double>> vector_of_ints1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);

            std::vector<std::complex<double>> constant_ints(
                    std::vector<std::complex<double>>(VECTOR_SIZE, 11));  // vector of 11s
            Plaintext plaintext_const = cc->make_ckks_packed_plaintext(constant_ints);
            Plaintext plaintext_const_deep = cc->make_ckks_packed_plaintext(constant_ints, 2);

            std::vector<std::complex<double>> constant_ints2(
                    std::vector<std::complex<double>>(VECTOR_SIZE, -11));  // vector of "-11"s
            Plaintext plaintext_const2 = cc->make_ckks_packed_plaintext(constant_ints2);
            Plaintext plaintext_const2_deep = cc->make_ckks_packed_plaintext(constant_ints2, 2);

            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints7_0);
            Plaintext plaintext3 = cc->make_ckks_packed_plaintext(vector_of_ints0_7neg);

            std::vector<std::complex<double>> vector_of_ints_mult(VECTOR_SIZE);
            std::vector<std::complex<double>> vector_of_ints_mult2(VECTOR_SIZE);
            std::vector<std::complex<double>> vector_of_ints_add_after_mult(VECTOR_SIZE);
            std::vector<std::complex<double>> vector_of_ints_sub_after_mult(VECTOR_SIZE);
            std::vector<std::complex<double>> vector_of_ints_add_after_mult2(VECTOR_SIZE);
            std::vector<std::complex<double>> vector_of_ints_sub_after_mult2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                vector_of_ints_mult[i] = i * VECTOR_SIZE - i * i - i;
                vector_of_ints_add_after_mult[i] = vector_of_ints_mult[i] + std::complex<double>(10, 0);
                vector_of_ints_sub_after_mult[i] = vector_of_ints_mult[i] - std::complex<double>(10, 0);
                vector_of_ints_mult2[i] = vector_of_ints_mult[i] * vector_of_ints1[i];
                vector_of_ints_add_after_mult2[i] = vector_of_ints_mult2[i] + constant_ints[i];  // complex<double>({11,0});
                vector_of_ints_sub_after_mult2[i] = vector_of_ints_mult2[i] - constant_ints[i];  // complex<double>({11,0});
            }
            // The vector values should be:
            // vector_of_ints_mult = { 0,6,10,12,12,10,6,0 };
            // vector_of_ints_mult2 = { 0,6,20,36,48,50,36,0 };
            // vector_of_ints_add_after_mult = { 10,16,20,22,22,20,16,10 };
            // vector_of_ints_sub_after_mult = { -10,-4,0,2,2,0,-4,-10 };
            // vector_of_ints_add_after_mult2 = { 11,17,31,47,59,61,47,11 };
            // vector_of_ints_sub_after_mult2 = { -11,-5,9,25,37,39,25,-11 };
            Plaintext plaintext_mult = cc->make_ckks_packed_plaintext(vector_of_ints_mult);
            Plaintext plaintex_add_after_mult = cc->make_ckks_packed_plaintext(vector_of_ints_add_after_mult);
            Plaintext plaintex_sub_after_mult = cc->make_ckks_packed_plaintext(vector_of_ints_sub_after_mult);
            Plaintext plaintextt_mult2 = cc->make_ckks_packed_plaintext(vector_of_ints_mult2);
            Plaintext plaintex_add_after_mult2 = cc->make_ckks_packed_plaintext(vector_of_ints_add_after_mult2);
            Plaintext plaintex_sub_after_mult2 = cc->make_ckks_packed_plaintext(vector_of_ints_sub_after_mult2);
            Plaintext plaintex2_add_after_mult2 = cc->make_ckks_packed_plaintext(vector_of_ints_sub_after_mult2);
            Plaintext plaintex2_sub_after_mult2 = cc->make_ckks_packed_plaintext(vector_of_ints_add_after_mult2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext2);

            auto c_mult = cc->eval_mult(ciphertext1, ciphertext2);
            auto c_mult_rs = cc->rescale(c_mult);

            auto c_add_after_mult = cc->eval_add(c_mult_rs, 10);
            auto c_sub_after_mult = cc->eval_sub(c_mult_rs, 10);
            auto c_mult2 = cc->eval_mult(ciphertext1, c_mult_rs);
            auto c_mult_rs2 = cc->rescale(c_mult2);
            auto c_add_after_mult2 = cc->eval_add(c_mult_rs2, 11);
            auto c_sub_after_mult2 = cc->eval_sub(c_mult_rs2, 11);
            auto c2_add_after_mult2 = cc->eval_add(c_mult_rs2, -11);
            auto c2_sub_after_mult2 = cc->eval_sub(c_mult_rs2, -11);
            auto c_add_pt_after_mult2 = cc->eval_add(c_mult_rs2, plaintext_const);
            auto c_sub_pt_after_mult2 = cc->eval_sub(c_mult_rs2, plaintext_const);
            auto c_add_pt2_after_mult2 = cc->eval_add(c_mult_rs2, plaintext_const2);
            auto c_sub_pt2_after_mult2 = cc->eval_sub(c_mult_rs2, plaintext_const2);
            auto c_deep_add = cc->eval_add(c_mult_rs2, plaintext_const_deep);
            auto c_deep_sub = cc->eval_sub(c_mult_rs2, plaintext_const_deep);
            auto c2_deep_add = cc->eval_add(c_mult_rs2, plaintext_const2_deep);
            auto c2_deep_sub = cc->eval_sub(c_mult_rs2, plaintext_const2_deep);

            Plaintext results;
            cc->decrypt(kp.secret_key, c_add_after_mult, &results);
            results->set_length(plaintex_add_after_mult->get_length());
            check_equality(plaintex_add_after_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add after 1 multiplication fails");

            cc->decrypt(kp.secret_key, c_sub_after_mult, &results);
            results->set_length(plaintex_sub_after_mult->get_length());
            check_equality(plaintex_sub_after_mult->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract after 1 multiplication fails");

            cc->decrypt(kp.secret_key, c_add_after_mult2, &results);
            results->set_length(plaintex_add_after_mult2->get_length());
            check_equality(plaintex_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_sub_after_mult2, &results);
            results->set_length(plaintex_sub_after_mult2->get_length());
            check_equality(plaintex_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c2_add_after_mult2, &results);
            results->set_length(plaintex2_add_after_mult2->get_length());
            check_equality(plaintex2_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add (negative) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c2_sub_after_mult2, &results);
            results->set_length(plaintex2_sub_after_mult2->get_length());
            check_equality(plaintex2_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract (negative) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_add_pt_after_mult2, &results);
            results->set_length(plaintex_add_after_mult2->get_length());
            check_equality(plaintex_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_sub_pt_after_mult2, &results);
            results->set_length(plaintex_sub_after_mult2->get_length());
            check_equality(plaintex_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_add_pt2_after_mult2, &results);
            results->set_length(plaintex2_add_after_mult2->get_length());
            check_equality(
                    plaintex2_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                    failmsg + " add negative plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_sub_pt2_after_mult2, &results);
            results->set_length(plaintex2_sub_after_mult2->get_length());
            check_equality(
                    plaintex2_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                    failmsg +
                            " subtract negative plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->decrypt(kp.secret_key, c_deep_add, &results);
            results->set_length(plaintex_add_after_mult2->get_length());
            check_equality(plaintex_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add with deep plaintext fails");

            cc->decrypt(kp.secret_key, c_deep_sub, &results);
            results->set_length(plaintex_sub_after_mult2->get_length());
            check_equality(plaintex_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract with deep plaintext fails");

            cc->decrypt(kp.secret_key, c2_deep_add, &results);
            results->set_length(plaintex2_add_after_mult2->get_length());
            check_equality(plaintex2_add_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " add with deep negative plaintext fails");

            cc->decrypt(kp.secret_key, c2_deep_sub, &results);
            results->set_length(plaintex2_sub_after_mult2->get_length());
            check_equality(plaintex2_sub_after_mult2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtract with deep negative plaintext fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_auto_level_reduce(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<std::complex<double>> vector_of_ints1(vector_of_ints0_7);
            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1);

            std::vector<std::complex<double>> vector_of_ints2(vector_of_ints7_0);
            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints2);

            std::vector<std::complex<double>> p_ct_mult(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct_mult3(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct3(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct3_b(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct4(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct5(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct6(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct7(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct_5(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct_6(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct_7(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct8(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct9(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct10(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct11(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct12(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct13(VECTOR_SIZE);
            std::vector<std::complex<double>> p_ct14(VECTOR_SIZE);
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
            Plaintext plaintext_ct3 = cc->make_ckks_packed_plaintext(p_ct3);
            Plaintext plaintext_ct4 = cc->make_ckks_packed_plaintext(p_ct4);
            Plaintext plaintext_ct5 = cc->make_ckks_packed_plaintext(p_ct5);
            Plaintext plaintext_ct6 = cc->make_ckks_packed_plaintext(p_ct6);
            Plaintext plaintext_ct7 = cc->make_ckks_packed_plaintext(p_ct7);
            Plaintext plaintext_ct_5 = cc->make_ckks_packed_plaintext(p_ct_5);
            Plaintext plaintext_ct_6 = cc->make_ckks_packed_plaintext(p_ct_6);
            Plaintext plaintext_ct_7 = cc->make_ckks_packed_plaintext(p_ct_7);
            Plaintext plaintext_ct8 = cc->make_ckks_packed_plaintext(p_ct8);
            Plaintext plaintext_ct9 = cc->make_ckks_packed_plaintext(p_ct9);
            Plaintext plaintext_ct10 = cc->make_ckks_packed_plaintext(p_ct10);
            Plaintext plaintext_ct11 = cc->make_ckks_packed_plaintext(p_ct11);
            Plaintext plaintext_ct12 = cc->make_ckks_packed_plaintext(p_ct12);
            Plaintext plaintext_ct13 = cc->make_ckks_packed_plaintext(p_ct13);
            Plaintext plaintext_ct14 = cc->make_ckks_packed_plaintext(p_ct14);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->encrypt(kp.public_key, plaintext1);
            Ciphertext<Element> ct2 = cc->encrypt(kp.public_key, plaintext2);

            auto ct_mul = cc->eval_mult(ct, ct2);
            auto ct_red = cc->mod_reduce(ct_mul);

            Plaintext results;
            // Addition with tower diff = 1
            auto ct3 = cc->eval_add(ct_red, ct);
            cc->decrypt(kp.secret_key, ct3, &results);
            results->set_length(plaintext_ct3->get_length());
            check_equality(plaintext_ct3->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " addition with tower diff = 1 fails");

            // in-place addition with tower diff = 1
            auto ct_red_clone = ct_red->clone();
            cc->eval_add_in_place(ct_red_clone, ct);
            cc->decrypt(kp.secret_key, ct_red_clone, &results);
            results->set_length(plaintext_ct3->get_length());
            check_equality(plaintext_ct3->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " in-place addition with tower diff = 1 fails");

            // Subtraction with tower diff = 1
            auto ct4 = cc->eval_sub(ct_red, ct);
            cc->decrypt(kp.secret_key, ct4, &results);
            results->set_length(plaintext_ct4->get_length());
            check_equality(plaintext_ct4->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtraction with tower diff = 1 fails");

            // Multiplication with tower diff = 1
            auto ct5 = cc->eval_mult(ct_red, ct);
            cc->decrypt(kp.secret_key, ct5, &results);
            results->set_length(plaintext_ct5->get_length());
            check_equality(plaintext_ct5->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " multiplication with tower diff = 1 fails");

            // Addition with tower diff = 1 (inputs reversed)
            auto ct6 = cc->eval_add(ct, ct_red);
            cc->decrypt(kp.secret_key, ct6, &results);
            results->set_length(plaintext_ct6->get_length());
            check_equality(plaintext_ct6->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " addition (reverse) with tower diff = 1 fails");

            // in-place addition with tower diff = 1 (inputs reversed)
            Ciphertext<Element> ct_clone_value = ct->clone();
            cc->eval_add_in_place(ct_clone_value, ct_red);
            cc->decrypt(kp.secret_key, ct_clone_value, &results);
            results->set_length(plaintext_ct6->get_length());
            check_equality(plaintext_ct6->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " in-place addition (reverse) with tower diff = 1 fails");

            // Subtraction with tower diff = 1 (inputs reversed)
            auto ct7 = cc->eval_sub(ct, ct_red);
            cc->decrypt(kp.secret_key, ct7, &results);
            results->set_length(plaintext_ct7->get_length());
            check_equality(plaintext_ct7->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtraction (reverse) with tower diff = 1 fails");

            // Multiplication with tower diff = 1 (inputs reversed)
            auto ct8 = cc->eval_mult(ct, ct_red);
            cc->decrypt(kp.secret_key, ct8, &results);
            results->set_length(plaintext_ct8->get_length());
            check_equality(plaintext_ct8->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " multiplication (reverse) with tower diff = 1 fails");

            auto ct_mul2 = cc->eval_mult(ct_red, ct);
            auto ct_red2 = cc->mod_reduce(ct_mul2);
            auto ct_mul3 = cc->eval_mult(ct_red2, ct);
            auto ct_red3 = cc->mod_reduce(ct_mul3);

            // Addition with more than 1 level difference
            auto ct9 = cc->eval_add(ct_red3, ct);
            cc->decrypt(kp.secret_key, ct9, &results);
            results->set_length(plaintext_ct9->get_length());
            check_equality(plaintext_ct9->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " addition with tower diff > 1 fails");

            // In-place addition with more than 1 level difference
            auto ct_red3_clone = ct_red3->clone();
            cc->eval_add_in_place(ct_red3_clone, ct);
            cc->decrypt(kp.secret_key, ct_red3_clone, &results);
            results->set_length(plaintext_ct9->get_length());
            check_equality(plaintext_ct9->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " in-place addition with tower diff > 1 fails");

            // Subtraction with more than 1 level difference
            auto ct10 = cc->eval_sub(ct_red3, ct);
            cc->decrypt(kp.secret_key, ct10, &results);
            results->set_length(plaintext_ct10->get_length());
            check_equality(plaintext_ct10->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " in-place addition with tower diff > 1 fails");

            // Multiplication with more than 1 level difference
            auto ct11 = cc->eval_mult(ct_red3, ct);
            cc->decrypt(kp.secret_key, ct11, &results);
            results->set_length(plaintext_ct11->get_length());
            std::stringstream buffer;
            buffer << plaintext_ct11->get_ckks_packed_value() << " - we get: " << results->get_ckks_packed_value();
            check_equality(plaintext_ct11->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " multiplication with tower diff > 1 fails" + buffer.str());

            // Addition with more than 1 level difference (inputs reversed)
            auto ct12 = cc->eval_add(ct, ct_red3);
            cc->decrypt(kp.secret_key, ct12, &results);
            results->set_length(plaintext_ct12->get_length());
            check_equality(plaintext_ct12->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " addition (reverse) with tower diff > 1 fails");

            // In-place addition with more than 1 level difference (inputs reversed)
            ct_clone_value = ct->clone();
            cc->eval_add_in_place(ct_clone_value, ct_red3);
            cc->decrypt(kp.secret_key, ct_clone_value, &results);
            results->set_length(plaintext_ct12->get_length());
            check_equality(plaintext_ct12->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " in-place addition (reverse) with tower diff > 1 fails");

            // Subtraction with more than 1 level difference (inputs reversed)
            auto ct13 = cc->eval_sub(ct, ct_red3);
            cc->decrypt(kp.secret_key, ct13, &results);
            results->set_length(plaintext_ct13->get_length());
            check_equality(plaintext_ct13->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " subtraction (reverse) with tower diff > 1 fails");

            // Multiplication with more than 1 level difference (inputs reversed)
            auto ct14 = cc->eval_mult(ct, ct_red3);
            cc->decrypt(kp.secret_key, ct14, &results);
            results->set_length(plaintext_ct14->get_length());
            check_equality(plaintext_ct14->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " multiplication (reverse) with tower diff > 1 fails");

            // This scenario tests for operations on ciphertext and plaintext that differ on
            // both scaling factor and number of towers.
            auto ct_1 = cc->eval_mult(ct, plaintext1);
            auto ct_2 = cc->eval_add(ct_1, ct_1);
            auto ct_3 = cc->mod_reduce(ct_2);
            auto ct_4 = cc->eval_mult(ct_3, plaintext1);
            ct_4 = cc->mod_reduce(ct_4);

            // Addition with plaintext and tower diff = 1
            auto ct_5 = cc->eval_add(ct_4, plaintext2);
            cc->decrypt(kp.secret_key, ct_5, &results);
            results->set_length(plaintext_ct_5->get_length());
            check_equality(plaintext_ct_5->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " addition with plaintext and tower diff = 1 fails");

            // Subtraction with plaintext and tower diff = 1
            auto ct_6 = cc->eval_sub(ct_4, plaintext2);
            cc->decrypt(kp.secret_key, ct_6, &results);
            results->set_length(plaintext_ct_6->get_length());
            check_equality(plaintext_ct_6->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " subtraction with plaintext and tower diff = 1 fails");

            // Multiplication with plaintext and tower diff = 1
            auto ct_7 = cc->eval_mult(ct_4, plaintext2);
            cc->decrypt(kp.secret_key, ct_7, &results);
            results->set_length(plaintext_ct_7->get_length());
            check_equality(plaintext_ct_7->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " multiplication with plaintext and tower diff = 1 fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_compress(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext = cc->make_ckks_packed_plaintext(vector_of_ints0_7);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->encrypt(kp.public_key, plaintext);
            ct *= ct;
            size_t target_towers = 1;
            auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
            uint32_t composite_degree = crypto_params->get_composite_degree();
            target_towers *= composite_degree;
            auto ct_compressed = cc->compress(ct, target_towers);

            size_t towers_left = ct_compressed->get_elements()[0].get_num_of_elements();
            EXPECT_TRUE(towers_left == target_towers) << " compress fails - towers mismatch";

            Plaintext result;
            Plaintext result_compressed;
            cc->decrypt(kp.secret_key, ct, &result);
            cc->decrypt(kp.secret_key, ct_compressed, &result_compressed);
            check_equality(result->get_ckks_packed_value(), result_compressed->get_ckks_packed_value(), eps,
                          failmsg + " compress fails - result is incorrect");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_fast_rotation(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            const uint32_t ring_dim = cc->get_ring_dimension();
            uint32_t slots = (test_data.slots != 0) ? test_data.slots : (BATCH != 0) ? BATCH : cc->get_ring_dimension() / 2;

            std::vector<std::complex<double>> vector_of_ints1(slots);
            for (uint32_t i = 0; i < slots; i++) {
                vector_of_ints1[i] = rand() % 10;  // NOLINT
            }
            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1, 1, 0, nullptr, test_data.slots);

            std::vector<std::complex<double>> v_ints_right_rotate2(slots);
            for (uint32_t i = 0; i < slots; i++) {
                v_ints_right_rotate2[(i + slots + 2) % slots] = vector_of_ints1[i];
            }
            Plaintext plaintext_right2 = cc->make_ckks_packed_plaintext(v_ints_right_rotate2, 1, 0, nullptr, test_data.slots);

            std::vector<std::complex<double>> v_ints_left_rotate2(slots);
            for (uint32_t i = 0; i < slots; i++) {
                // here 2*slots for the case if slots = 1, to avoid negative index
                v_ints_left_rotate2[(i + 2 * slots - 2) % slots] = vector_of_ints1[i];
            }
            Plaintext plaintext_left2 = cc->make_ckks_packed_plaintext(v_ints_left_rotate2, 1, 0, nullptr, test_data.slots);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
            cc->eval_at_index_key_gen(kp.secret_key, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            std::vector<std::complex<double>> v_ones(slots, 1);  // all 1s
            Plaintext p_ones = cc->make_ckks_packed_plaintext(v_ones, 1, 0, nullptr, test_data.slots);
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);
            ciphertext1 *= c_ones;

            /* Testing EvalFastRotate +2 (left rotate)
             */
            uint32_t M = ring_dim << 1;
            auto c_precomp1 = cc->eval_fast_rotation_precompute(ciphertext1);
            Ciphertext<Element> c_result = cc->eval_fast_rotation(ciphertext1, 2, M, c_precomp1);
            Plaintext results;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_left2->get_length());
            check_equality(plaintext_left2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalFastRotation(+2) fails");

            /* Testing EvalFastRotate -2 (right rotate)
             */
            c_result = cc->eval_fast_rotation(ciphertext1, -2, M, c_precomp1);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_right2->get_length());
            check_equality(plaintext_right2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalFastRotation(-2) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_at_index(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints1_8, 1, 0, nullptr, test_data.slots);

            // v_ints_right_shift2 = { 0,0,1,2,3,4,5,6 } if slots > 8;
            // v_ints_right_shift2 = { 7,8,1,2,3,4,5,6 } if slots = 8;
            std::vector<std::complex<double>> v_ints_right_shift2(VECTOR_SIZE);
            uint32_t slots = (test_data.slots != 0) ? test_data.slots : (BATCH != 0) ? BATCH : cc->get_ring_dimension() / 2;
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                if ((slots + i - 2) % slots < VECTOR_SIZE) {
                    v_ints_right_shift2[i] = vector_of_ints1_8[(slots + i - 2) % slots];
                } else {
                    v_ints_right_shift2[i] = 0;
                }
            }
            Plaintext plaintext_right2 = cc->make_ckks_packed_plaintext(v_ints_right_shift2, 1, 0, nullptr, test_data.slots);

            // v_ints_right_shift2 = { 3,4,5,6,7,8,0,0 } if slots > 8;
            // v_ints_right_shift2 = { 3,4,5,6,7,8,1,2 } if slots = 8;
            std::vector<std::complex<double>> v_ints_left_shift2(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                if ((i + 2) % slots < VECTOR_SIZE) {
                    v_ints_left_shift2[i] = vector_of_ints1_8[(i + 2) % slots];
                } else {
                    v_ints_left_shift2[i] = 0;
                }
            }
            Plaintext plaintext_left2 = cc->make_ckks_packed_plaintext(v_ints_left_shift2, 1, 0, nullptr, test_data.slots);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->eval_at_index_key_gen(kp.secret_key, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            Plaintext p_ones = cc->make_ckks_packed_plaintext(vector_of_ints1s, 1, 0, nullptr, test_data.slots);
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);
            ciphertext1 *= c_ones;

            /* Testing eval_at_index +2
             */
            Ciphertext<Element> c_result = cc->eval_at_index(ciphertext1, 2);
            Plaintext results;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_left2->get_length());
            check_equality(plaintext_left2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAtIndex(+2) fails");

            /* Testing eval_at_index -2
             */
            c_result = cc->eval_at_index(ciphertext1, -2);
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(plaintext_right2->get_length());
            check_equality(plaintext_right2->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalAtIndex(-2) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_merge(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        // TODO (dsuponit) error from pke/include/schemebase/base-scheme.h:1500 eval_merge operation has not been enabled"
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // v* = { i,0,0,0,0,0,0,0 };
            std::vector<std::complex<double>> v_one(VECTOR_SIZE, 0);
            v_one[0] = 1;
            std::vector<std::complex<double>> v_two(VECTOR_SIZE, 0);
            v_two[0] = 2;
            std::vector<std::complex<double>> v_three(VECTOR_SIZE, 0);
            v_three[0] = 3;
            std::vector<std::complex<double>> v_four(VECTOR_SIZE, 0);
            v_four[0] = 4;
            std::vector<std::complex<double>> v_five(VECTOR_SIZE, 0);
            v_five[0] = 5;
            std::vector<std::complex<double>> v_six(VECTOR_SIZE, 0);
            v_six[0] = 6;
            std::vector<std::complex<double>> v_seven(VECTOR_SIZE, 0);
            v_seven[0] = 7;
            std::vector<std::complex<double>> v_eight(VECTOR_SIZE, 0);
            v_eight[0] = 8;
            Plaintext p_one = cc->make_ckks_packed_plaintext(v_one);
            Plaintext p_two = cc->make_ckks_packed_plaintext(v_two);
            Plaintext p_three = cc->make_ckks_packed_plaintext(v_three);
            Plaintext p_four = cc->make_ckks_packed_plaintext(v_four);
            Plaintext p_five = cc->make_ckks_packed_plaintext(v_five);
            Plaintext p_six = cc->make_ckks_packed_plaintext(v_six);
            Plaintext p_seven = cc->make_ckks_packed_plaintext(v_seven);
            Plaintext p_eight = cc->make_ckks_packed_plaintext(v_eight);

            Plaintext p_merged = cc->make_ckks_packed_plaintext(vector_of_ints1_8);
            Plaintext p_ones = cc->make_ckks_packed_plaintext(vector_of_ints1s);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);
            // Generate rotation keys for all right rotations 1 to 8.
            std::vector<int32_t> index_list = {-1, -2, -3, -4, -5, -6, -7, -8};
            cc->eval_at_index_key_gen(kp.secret_key, index_list);

            // Encrypt plaintexts
            Ciphertext<Element> c_ones = cc->encrypt(kp.public_key, p_ones);

            // Here, we perform the same trick (mult with one) as in
            // UnitTest_EvalAtiIndex.
            std::vector<Ciphertext<Element>> ciphertexts;
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_one) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_two) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_three) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_four) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_five) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_six) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_seven) * c_ones);
            ciphertexts.push_back(cc->encrypt(kp.public_key, p_eight) * c_ones);

            /* Testing eval_merge
             */
            auto c_result = cc->eval_merge(ciphertexts);
            Plaintext results;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(p_merged->get_length());
            check_equality(p_merged->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalMerge fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_linear_w_sum(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::vector<double> weights{0, 1, 2};
            std::vector<std::complex<double>> in1(VECTOR_SIZE, 3);  // all 3's
            std::vector<std::complex<double>> in2(VECTOR_SIZE, 2);  // all 2's
            std::vector<std::complex<double>> in3(VECTOR_SIZE, 1);  // all 1's
            std::vector<std::complex<double>> out(VECTOR_SIZE);
            for (uint32_t i = 0; i < VECTOR_SIZE; i++) {
                // TODO (dsuponit): what is the purpose of this calculation? to have a noise?
                // otherwise it is better to create "out" without calculating values in the loop
                out[i] = weights[0] * in1[i] + weights[1] * in2[i] + weights[2] * in3[i];
            }
            Plaintext p_in1 = cc->make_ckks_packed_plaintext(in1);
            Plaintext p_in2 = cc->make_ckks_packed_plaintext(in2);
            Plaintext p_in3 = cc->make_ckks_packed_plaintext(in3);
            Plaintext p_out = cc->make_ckks_packed_plaintext(out);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> c_in1 = cc->encrypt(kp.public_key, p_in1);
            Ciphertext<Element> c_in2 = cc->encrypt(kp.public_key, p_in2);
            Ciphertext<Element> c_in3 = cc->encrypt(kp.public_key, p_in3);

            std::vector<Ciphertext<Element>> ciphertexts{c_in1, c_in2, c_in3};
            std::vector<ReadOnlyCiphertext<Element>> const_ciphertexts{c_in1, c_in2, c_in3};

            auto c_result = cc->eval_linear_w_sum(const_ciphertexts, weights);
            Plaintext results;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(p_out->get_length());
            check_equality(p_out->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalLinearWSum fails");

            auto c_result2 = cc->eval_linear_w_sum_mutable(ciphertexts, weights);
            cc->decrypt(kp.secret_key, c_result2, &results);
            results->set_length(p_out->get_length());
            check_equality(p_out->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalLinearWSumMutable fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_re_encryption(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            size_t max = 128;
            auto ptm = 10;

            std::vector<std::complex<double>> intvec(max);
            for (size_t i = 0; i < max; ++i) {
                intvec[i] = (rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1);  // NOLINT
            }
            Plaintext plaintext_int = cc->make_ckks_packed_plaintext(intvec, 1, 0, nullptr, max);

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
            auto tmp_a = plaintext_int_new->get_ckks_packed_value();
            auto tmp_b = plaintext_int->get_ckks_packed_value();
            std::stringstream buffer;
            buffer << tmp_b << " - we get: " << tmp_a;
            check_equality(tmp_a, tmp_b, eps_high, failmsg + " ReEncrypt integer plaintext " + buffer.str());

            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext_int);
            Ciphertext<Element> re_ciphertext2 = cc->re_encrypt(ciphertext2, eval_key, kp.public_key);
            Plaintext plaintext_int_new2;
            cc->decrypt(new_kp.secret_key, re_ciphertext2, &plaintext_int_new2);
            plaintext_int_new2->set_length(plaintext_int->get_length());
            tmp_a = plaintext_int_new2->get_ckks_packed_value();
            tmp_b = plaintext_int->get_ckks_packed_value();
            std::stringstream buffer2;
            buffer2 << tmp_b << " - we get: " << tmp_a;
            check_equality(tmp_a, tmp_b, eps_high, failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_poly(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Encode inputs as CKKS inputs.
            std::vector<std::complex<double>> input{0.5, 0.7, 0.9, 0.95, 0.93};
            const size_t encoded_length = input.size();

            // with only positive coefficients
            // x^16 + x^11 + 2 x^9 + x^8 + x^6 + 1.25 x^3 + 0.75*x + 0.15
            std::vector<double> coefficients1{0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 + 1.25 x^3 - 0.75*x + 0.15
            // with negative coefficients
            std::vector<double> coefficients2{0.15, -0.75, 0, 1.25, 0, 0, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x^16
            // power function
            std::vector<double> coefficients3{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 - 1.25 x^5 + 1.25 x^3 - 1.75*x + 0.15
            // with negative coefficients with magnitude greater than 1
            std::vector<double> coefficients4{0.15, -1.75, 0, 1.25, 0, -1.25, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x + x^2 - x^3
            // low-degree function to check linear implementation
            std::vector<double> coefficients5{0, 1, 1, -1};

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input);

            std::vector<std::complex<double>> output1{0.705191, 1.38285, 3.97211, 5.60216, 4.86358};
            Plaintext plaintext_result1 = cc->make_ckks_packed_plaintext(output1);

            std::vector<std::complex<double>> output2{-0.0526215, 0.217555, 1.76118, 2.85032, 2.34941};
            Plaintext plaintext_result2 = cc->make_ckks_packed_plaintext(output2);

            std::vector<std::complex<double>> output3{0.0000152588, 0.00332329, 0.185302, 0.440127, 0.313132};
            Plaintext plaintext_result3 = cc->make_ckks_packed_plaintext(output3);

            std::vector<std::complex<double>> output4{-0.59168396, -0.69253274, 0.12306489, 0.93308964, 0.54980166};
            Plaintext plaintext_result4 = cc->make_ckks_packed_plaintext(output4);

            std::vector<std::complex<double>> output5{0.625, 0.847, 0.9809999999, 0.995125, 0.990543};
            Plaintext plaintext_result5 = cc->make_ckks_packed_plaintext(output5);

            // Generate encryption keys
            KeyPair<Element> kp = cc->key_gen();
            // Generate multiplication keys
            cc->eval_mult_key_gen(kp.secret_key);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, plaintext1);

            /* Testing eval_poly
             */
            Ciphertext<Element> c_result1 = cc->eval_poly_linear(ciphertext1, coefficients1);
            Plaintext results1;
            cc->decrypt(kp.secret_key, c_result1, &results1);
            results1->set_length(encoded_length);
            std::stringstream buffer1;
            buffer1 << "should be: " << plaintext_result1->get_ckks_packed_value()
                    << " - we get: " << results1->get_ckks_packed_value();
            check_equality(plaintext_result1->get_ckks_packed_value(), results1->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalPoly with positive coefficients failed: " + buffer1.str());

            Ciphertext<Element> c_result2 = cc->eval_poly_linear(ciphertext1, coefficients2);
            Plaintext results2;
            cc->decrypt(kp.secret_key, c_result2, &results2);
            results2->set_length(encoded_length);
            std::stringstream buffer2;
            buffer2 << "should be: " << plaintext_result2->get_ckks_packed_value()
                    << " - we get: " << results2->get_ckks_packed_value();
            check_equality(plaintext_result2->get_ckks_packed_value(), results2->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalPoly with negative coefficients failed: " + buffer2.str());

            Ciphertext<Element> c_result3 = cc->eval_poly_linear(ciphertext1, coefficients3);
            Plaintext results3;
            cc->decrypt(kp.secret_key, c_result3, &results3);
            results3->set_length(encoded_length);
            std::stringstream buffer3;
            buffer3 << "should be: " << plaintext_result3->get_ckks_packed_value()
                    << " - we get: " << results3->get_ckks_packed_value();
            check_equality(plaintext_result3->get_ckks_packed_value(), results3->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalPoly for a power function failed: " + buffer3.str());

            Ciphertext<Element> c_result4 = cc->eval_poly_linear(ciphertext1, coefficients4);
            Plaintext results4;
            cc->decrypt(kp.secret_key, c_result4, &results4);
            results4->set_length(encoded_length);
            std::stringstream buffer4;
            buffer4 << "should be: " << plaintext_result4->get_ckks_packed_value()
                    << " - we get: " << results4->get_ckks_packed_value();
            check_equality(plaintext_result4->get_ckks_packed_value(), results4->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalPoly for negative coefficients with magnitude > 1 failed: " + buffer4.str());

            Ciphertext<Element> c_result5 = cc->eval_poly_linear(ciphertext1, coefficients5);
            Plaintext results5;
            cc->decrypt(kp.secret_key, c_result5, &results5);
            results5->set_length(encoded_length);
            std::stringstream buffer5;
            buffer5 << "should be: " << plaintext_result5->get_ckks_packed_value()
                    << " - we get: " << results5->get_ckks_packed_value();
            check_equality(plaintext_result5->get_ckks_packed_value(), results5->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalPoly for low-degree polynomial failed: " + buffer5.str());
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    /***
     * Tests whether metadata is carried over for several operations in CKKS
     */
    void unit_test_metadata(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(vector_of_ints0_7);
            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(vector_of_ints0_7neg);

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

            // Checking if metadata is carried over in eval_add(ctx,ctx)
            Ciphertext<Element> ciphertext1_clone_value = ciphertext1->clone();
            cc->eval_add_in_place(ciphertext1, ciphertext2);
            auto add_cc_in_place_val_test = MetadataTest::get_metadata<Element>(ciphertext1_clone_value);
            EXPECT_EQ(val1->get_metadata(), add_cc_in_place_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

            // Checking if metadata is carried over in eval_add(ctx,ptx)
            Ciphertext<Element> c_add_cp = cc->eval_add(ciphertext1, plaintext1);
            auto add_cp_val_test = MetadataTest::get_metadata<Element>(c_add_cp);
            EXPECT_EQ(val1->get_metadata(), add_cp_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAdd(ctx,ptx)";

            // Checking if metadata is carried over in eval_add(ctx,double)
            Ciphertext<Element> c_add_cd = cc->eval_add(ciphertext1, 2.0);
            auto add_cd_val_test = MetadataTest::get_metadata<Element>(c_add_cd);
            EXPECT_EQ(val1->get_metadata(), add_cd_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalAdd(ctx,double)";

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

            // Checking if metadata is carried over in eval_sub(ctx,double)
            Ciphertext<Element> c_sub_cd = cc->eval_sub(ciphertext1, 2.0);
            auto sub_cd_val_test = MetadataTest::get_metadata<Element>(c_sub_cd);
            EXPECT_EQ(val1->get_metadata(), sub_cd_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalSub(ctx,double)";

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

            // Checking if metadata is carried over in eval_mult(ctx,double)
            Ciphertext<Element> c_mult_cd = cc->eval_mult(ciphertext1, 2.0);
            auto mult_cd_val_test = MetadataTest::get_metadata<Element>(c_mult_cd);
            EXPECT_EQ(val1->get_metadata(), mult_cd_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalMult(ctx,double)";

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

            uint32_t N = cc->get_ring_dimension();
            uint32_t M = N << 1;

            // Checking if metadata is carried over EvalFastRotate +2 (left rotate)
            auto c_precomp1 = cc->eval_fast_rotation_precompute(ciphertext1);
            auto c_fast_rot2 = cc->eval_fast_rotation(ciphertext1, 2, M, c_precomp1);
            auto fast_rot2_val_test = MetadataTest::get_metadata<Element>(c_fast_rot2);
            EXPECT_EQ(val1->get_metadata(), fast_rot2_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalFastRotation +2";

            // Checking if metadata is carried over EvalFastRotate -2 (right rotate)
            auto c_fast_rot_minus2 = cc->eval_fast_rotation(ciphertext1, -2, M, c_precomp1);
            auto fast_rot_minus2_val_test = MetadataTest::get_metadata<Element>(c_fast_rot_minus2);
            EXPECT_EQ(val1->get_metadata(), fast_rot_minus2_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalFastRotation -2";

            std::vector<double> weights(2);
            for (int i = 0; i < 2; i++)
                weights[i] = i;

            std::vector<ReadOnlyCiphertext<Element>> ciphertexts{ciphertext1, ciphertext2};

            // Checking if metadata is carried over in eval_linear_w_sum
            auto c_lws = cc->eval_linear_w_sum(ciphertexts, weights);
            auto lws_val_test = MetadataTest::get_metadata<Element>(c_lws);
            EXPECT_EQ(val1->get_metadata(), lws_val_test->get_metadata())
                    << "Ciphertext metadata mismatch in EvalLinearWSum";

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

    void unit_test_eval_square(const TEST_CASE_UTCKKSRNS_CS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            const std::vector<std::complex<double>> vector_of_ints = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext = cc->make_ckks_packed_plaintext(vector_of_ints);

            // For cyclotomic order != 16, the expected result is the convolution of
            // vectorOfInt21 and vector_of_ints2
            const std::vector<std::complex<double>> vector_of_ints_square = {1, 0, 9, 1, 0, 1, 4, 1};
            Plaintext int_array_expected_square = cc->make_ckks_packed_plaintext(vector_of_ints_square);

            const std::vector<std::complex<double>> vector_of_ints_sixth = {1, 0, 729, 1, 0, 1, 64, 1};
            Plaintext int_array_expected_sixth = cc->make_ckks_packed_plaintext(vector_of_ints_sixth);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            Ciphertext<Element> ciphertext = cc->encrypt(kp.public_key, plaintext);

            cc->eval_mult_key_gen(kp.secret_key);

            Plaintext results;

            Ciphertext<Element> ciphertext_sq = cc->eval_square(ciphertext);
            cc->decrypt(kp.secret_key, ciphertext_sq, &results);
            results->set_length(int_array_expected_square->get_length());
            check_equality(int_array_expected_square->get_ckks_packed_value(), results->get_ckks_packed_value(), eps,
                          failmsg + " EvalSquare (CKKSPacked) fails");

            Ciphertext<Element> ciphertext_third = cc->eval_mult(ciphertext_sq, plaintext);

            Ciphertext<Element> ciphertext_sixth = cc->eval_square(ciphertext_third);
            cc->decrypt(kp.secret_key, ciphertext_sixth, &results);
            results->set_length(int_array_expected_sixth->get_length());
            check_equality(int_array_expected_sixth->get_ckks_packed_value(), results->get_ckks_packed_value(), eps_high,
                          failmsg + " EvalSquare Sixth (CKKSPacked) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_small_scaling_mod_size(const TEST_CASE_UTCKKSRNS_CS& test_data,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

template <>
double UTCKKSRNSCS::calculate_approximation_error<double>(const std::vector<std::complex<double>>& result,
                                                        const std::vector<std::complex<double>>& expected_result) {
    if (result.size() != expected_result.size())
        CIPHER_THROW("Cannot compare vectors with different numbers of elements");

    // using the Euclidean norm
    double avrg = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        avrg += std::pow(std::abs(result[i] - expected_result[i]), 2);
    }

    avrg = std::sqrt(avrg) / result.size();  // get the average
    return std::abs(std::log2(avrg));
}

// template<>
// uint32_t UTCKKSRNSCS::calculate_approximation_error<int>(
//    const std::vector<std::complex<double>>& result,
//    const std::vector<std::complex<double>>& expected_result) {
//
//    double err = calculate_approximation_error<double>(result, expected_result);
//    return std::round(err * 10) / 10; // should return an unsigned integer
// }

//===========================================================================================================
TEST_P(UTCKKSRNSCS, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case ADD_PACKED:
            unit_test_add_packed(test, test.build_test_name());
            break;
        case MULT_PACKED:
            unit_test_mult_packed(test, test.build_test_name());
            break;
        case SCALE_FACTOR_ADJUSTMENTS:
            unit_test_scale_factor_adjustments(test, test.build_test_name());
            break;
        case AUTO_LEVEL_REDUCE:
            unit_test_auto_level_reduce(test, test.build_test_name());
            break;
        case COMPRESS:
            unit_test_compress(test, test.build_test_name());
            break;
        case EVAL_FAST_ROTATION:
            unit_test_eval_fast_rotation(test, test.build_test_name());
            break;
        case EVALATINDEX:
            unit_test_eval_at_index(test, test.build_test_name());
            break;
        case EVALMERGE:
            unit_test_eval_merge(test, test.build_test_name());
            break;
        case EVAL_LINEAR_WSUM:
            unit_test_eval_linear_w_sum(test, test.build_test_name());
            break;
        case RE_ENCRYPTION:
            unit_test_re_encryption(test, test.build_test_name());
            break;
        case EVAL_POLY:
            unit_test_eval_poly(test, test.build_test_name());
            break;
        case METADATA:
            unit_test_metadata(test, test.build_test_name());
            break;
        case ADD_PACKED_PRECISION:
            unit_test_add_packed_precision(test, test.build_test_name());
            break;
        case MULT_PACKED_PRECISION:
            unit_test_mult_packed_precision(test, test.build_test_name());
            break;
        case EVALSQUARE:
            unit_test_eval_square(test, test.build_test_name());
            break;
        case SMALL_SCALING_MOD_SIZE:
            unit_test_small_scaling_mod_size(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNSCS, ::testing::ValuesIn(test_cases), testName);
#endif
