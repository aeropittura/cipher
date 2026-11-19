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
  Unit tests for the CKKS scheme
 */

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "cipher/fhe/context_ser.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/ser.h"
#include "cipher/fhe/ckks/utils.h"

using namespace cipher;
using namespace std::literals;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    BOOTSTRAP_FULL = 0,
    BOOTSTRAP_EDGE,
    BOOTSTRAP_SPARSE,
    BOOTSTRAP_KEY_SWITCH,
    BOOTSTRAP_ITERATIVE,
    BOOTSTRAP_NUM_TOWERS,
    BOOTSTRAP_SERIALIZE,
    BOOTSTRAP_SPARSE_ENCAPSULATED,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case BOOTSTRAP_FULL:
            type_name_of = "BOOTSTRAP_FULL";
            break;
        case BOOTSTRAP_EDGE:
            type_name_of = "BOOTSTRAP_EDGE";
            break;
        case BOOTSTRAP_SPARSE:
            type_name_of = "BOOTSTRAP_SPARSE";
            break;
        case BOOTSTRAP_KEY_SWITCH:
            type_name_of = "BOOTSTRAP_KEY_SWITCH";
            break;
        case BOOTSTRAP_ITERATIVE:
            type_name_of = "BOOTSTRAP_ITERATIVE";
            break;
        case BOOTSTRAP_NUM_TOWERS:
            type_name_of = "BOOTSTRAP_NUM_TOWERS";
            break;
        case BOOTSTRAP_SERIALIZE:
            type_name_of = "BOOTSTRAP_SERIALIZE";
            break;
        case BOOTSTRAP_SPARSE_ENCAPSULATED:
            type_name_of = "BOOTSTRAP_SPARSE_ENCAPSULATED";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}

//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_BOOT {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    // ........
    std::vector<uint32_t> level_budget;
    std::vector<uint32_t> dim1;
    uint32_t slots;

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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_BOOT>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_BOOT& test) {
    return os << test.to_string_impl();
}

//===========================================================================================================
constexpr uint32_t MULT_DEPTH = 25;
constexpr uint32_t RDIM = 64;
constexpr uint32_t NUM_LRG_DIGS = 3;

#if CIPHER_NATIVE_INT == 128
constexpr uint32_t SMODSIZE = 78;
constexpr uint32_t FMODSIZE = 89;
#else
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_BOOT> test_cases = {
    // TestType,     Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_FULL, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_FULL, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_FULL, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
#endif
    // ==========================================
    // TestType,     Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_FULL, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "17", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "18", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "19", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "20", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "21", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_FULL, "22", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "23", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "24", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "25", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "26", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "27", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
    { BOOTSTRAP_FULL, "28", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, RDIM/2 },
#endif
    // ==========================================
    // TestType,     Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_EDGE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, RDIM/4 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_EDGE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, RDIM/4 },
#endif
    // ==========================================
    // TestType,     Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_EDGE, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 2, 2 },  { 0, 0 }, RDIM/4 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_EDGE, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "17", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "18", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "19", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "20", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "21", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 2048 },
    { BOOTSTRAP_EDGE, "22", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 32 },
#endif
    { BOOTSTRAP_EDGE, "23", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, RDIM/4 },
    { BOOTSTRAP_EDGE, "24", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, RDIM/4 },
    // ==========================================
    // TestType,       Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 8, 8 }, 8 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_SPARSE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 8, 8 }, 8 },
#endif
    // ==========================================
    // TestType,       Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 2, 2 },  { 0, 0 }, 8 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_SPARSE, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "17", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "18", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "19", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "20", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 2, 2 },  { 0, 0 }, 8 },
#endif
    // ==========================================
    // TestType,       Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE, "21", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "22", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "23", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "24", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "25", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, 8 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_SPARSE, "26", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "27", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "28", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "29", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "30", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, 8 },
#endif
    // ==========================================
    // TestType,       Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE, "31", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "32", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "33", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "34", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "35", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, 8 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_SPARSE, "36", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "37", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "38", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "39", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "40", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, 8 },
#endif
    // ==========================================
    // TestType,       Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE, "41", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "42", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "43", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "44", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "45", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, 1 },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_SPARSE, "46", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "47", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "48", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "49", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
    { BOOTSTRAP_SPARSE, "50", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 0, 0 }, 1 },
#endif
    { BOOTSTRAP_SPARSE, "51", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE, "52", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "53", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "54", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8 },
    { BOOTSTRAP_SPARSE, "55", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 0, 0 }, 1 },
#if CIPHER_NATIVE_INT != 128
    // 50-bit scaling factor with a 60-bit first modulus: the uniform-secret overflow bound K must be folded into the
    // CoeffsToSlots matrix, since the runtime scalar 2^-deg/(K*N) would keep only log2(SF) - log2(K*N) - deg bits
    // when encoded at the scaling factor (see CkksRnsFhe::get_mod_raise_overflow_bound)
    // (FIXEDAUTO is not included because its precision at a 50-bit scaling factor is below the epsilon of this suite)
    { BOOTSTRAP_SPARSE, "56", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH,       50,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT,       60, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 3 },  { 0, 0 }, 8 },
#endif
    // ==========================================
    // TestType,           Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_KEY_SWITCH, "01", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "02", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "03", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "04", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_KEY_SWITCH, "05", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "06", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "07", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "08", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
#endif
    { BOOTSTRAP_KEY_SWITCH, "09", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    { BOOTSTRAP_KEY_SWITCH, "10", {CKKSRNS_SCHEME, 2048, MULT_DEPTH, SMODSIZE,  DFLT,     8, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 } },
    // ==========================================
    // TestType,          Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_ITERATIVE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, 8},
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_ITERATIVE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, 8},
#endif
    // ==========================================
    // TestType,          Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_ITERATIVE, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, RDIM/2},
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_ITERATIVE, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "17", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "18", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "19", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "20", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, RDIM/2},
#endif
    { BOOTSTRAP_ITERATIVE, "21", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "22", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_ITERATIVE, "23", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_ITERATIVE, "24", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 3, 2 },  { 0, 0 }, RDIM/2},
    // ==========================================
    // TestType,           Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_NUM_TOWERS, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_NUM_TOWERS, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
#endif
    // ==========================================
    // TestType,           Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_NUM_TOWERS, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,     FIXEDMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
#if CIPHER_NATIVE_INT != 128
    { BOOTSTRAP_NUM_TOWERS, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,    FLEXIBLEAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    { BOOTSTRAP_NUM_TOWERS, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
#endif
    { BOOTSTRAP_NUM_TOWERS, "17", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,     8, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, 8},
    { BOOTSTRAP_NUM_TOWERS, "18", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 3, 2 },  { 0, 0 }, RDIM/2},
    // ==========================================
    // TestType,          Descr,          Scheme, RDim,  MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,        scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SERIALIZE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 },   RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 0, 0 },   RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 4, 4 },   RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 4, 4 },   RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,     UNIFORM_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 2, 2 },  { 0, 0 },   RDIM/2 },
    { BOOTSTRAP_SERIALIZE, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 2, 2 },  { 4, 4 },   RDIM/2 },
    // COMPLEX with level budget {1,1}: the sparsely packed slots/2 recompute goes through the pair-matrix
    // branch of eval_bootstrap_precompute for the coefficients-first variant, which setup and recompute
    // previously selected differently
    { BOOTSTRAP_SERIALIZE, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,  DFLT,  DFLT,      SPARSE_TERNARY, DFLT, FMODSIZE, HEStd_NotSet, HYBRID,       FIXEDAUTO, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,   DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, COMPLEX},   { 1, 1 },  { 32, 32 }, RDIM/2 },
    // ==========================================
    // TestType,                    Descr,          Scheme,    RDim, MultDepth, SModSize, DSize, BSize, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl, KSTech,    scal_tech,      LDigits, PtMod,std_dev, EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode, MultipartyMode, decryption_noise_mode, ExecutionMode, NoiseEstimate, RegisterWordSize, CompositeDegree, CkksDataType, LvlBudget, Dim1,       Slots
    { BOOTSTRAP_SPARSE_ENCAPSULATED, "01", {CKKSRNS_SCHEME, 1 << 12,        18,       50,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT,       60, HEStd_NotSet, HYBRID,   FIXEDAUTO, NUM_LRG_DIGS,  DFLT,  DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 4, 4 },  { 8, 8 }, 8 },
    { BOOTSTRAP_SPARSE_ENCAPSULATED, "02", {CKKSRNS_SCHEME, 1 << 12,        18,       50,  DFLT,  DFLT, SPARSE_ENCAPSULATED, DFLT,       60, HEStd_NotSet, HYBRID, FIXEDMANUAL, NUM_LRG_DIGS,  DFLT,  DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           DFLT,  DFLT,   DFLT,      DFLT, DFLT, DFLT, REAL},   { 4, 4 },  { 8, 8 }, 8 },
};
// clang-format on

//===========================================================================================================
class UTCKKSRNS_BOOT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_BOOT> {
    using Element = RnsPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    static constexpr double eps = 0.0001;

    // calculate_approximation_error() calculates the precision number (or approximation error).
    // The higher the precision, the less the error.
    double calculate_approximation_error(const std::vector<std::complex<double>>& result,
                                         const std::vector<std::complex<double>>& expected_result) {
        if (result.size() != expected_result.size())
            CIPHER_THROW("Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double max_error = 0.;
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
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_bootstrap(const TEST_CASE_UTCKKSRNS_BOOT& test_data, const bool st_c_flag,
                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots, 0, true, st_c_flag);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_at_index_key_gen(key_pair.secret_key, {6});
            cc->eval_mult_key_gen(key_pair.secret_key);

            std::vector<std::complex<double>> input;
            // If CkksDataType is set to REAL, the imaginary parts are ignored.
            if (test_data.slots < 8) {
                input = fill_slots({0.1415926 + 0.1415926i}, test_data.slots);
            } else {
                input = fill_slots(
                        {0.111111 + 0.999999i, 0.222222 - 0.888888i, 0.333333 + 0.777777i, 0.444444 - 0.666666i,
                         0.555555 + 0.555555i, 0.666666 - 0.444444i, 0.777777 + 0.333333i, 0.888888 - 0.222222i},
                        test_data.slots);
            }

            size_t encoded_length = input.size();

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(
                    input, 1, MULT_DEPTH - 1 - test_data.level_budget[1] * st_c_flag, nullptr, test_data.slots);
            auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext_after = cc->eval_bootstrap(ciphertext1);

            Plaintext result;
            cc->decrypt(key_pair.secret_key, ciphertext_after, &result);
            result->set_length(encoded_length);
            plaintext1->set_length(encoded_length);
            check_equality(result->get_ckks_packed_value(), plaintext1->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping for fully packed ciphertexts fails for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");

            int32_t rot_index = (test_data.slots < 8) ? 0 : 6;
            if (cc->get_ckks_data_type() == REAL) {
                for (size_t i = 0; i < test_data.slots; i++)
                    input[i].imag(0.0);
            }
            auto temp6 = input;
            std::rotate(temp6.begin(), temp6.begin() + rot_index, temp6.end());

            auto ciphertext6 = cc->eval_at_index(ciphertext_after, rot_index);
            Plaintext result6;
            cc->decrypt(key_pair.secret_key, ciphertext6, &result6);
            result6->set_length(encoded_length);
            check_equality(result6->get_ckks_packed_value(), temp6, eps,
                           failmsg + " eval_at_index after Bootstrapping for fully packed ciphertexts fails for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bootstrap_key_switching(const TEST_CASE_UTCKKSRNS_BOOT& test_data,
                                           const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // We set the cout precision to 8 decimal digits for a nicer output.
            // If you want to see the error/noise introduced by CKKS, bump it up
            // to 15 and it should become visible.
            // std::cout.precision(8);
            auto key_pair = cc->key_gen();
            cc->eval_at_index_key_gen(key_pair.secret_key, {1});

            double eps = 0.00000001;
            std::vector<std::complex<double>> a = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
            std::vector<std::complex<double>> b = {0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
            Plaintext plaintext_a = cc->make_ckks_packed_plaintext(a);
            auto comp_a = plaintext_a->get_ckks_packed_value();
            Plaintext plaintext_b = cc->make_ckks_packed_plaintext(b);
            auto comp_b = plaintext_b->get_ckks_packed_value();

            // Test for key_switch_ext + key_switch_down
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext_a);
            ciphertext = cc->key_switch_ext(ciphertext, true);
            ciphertext = cc->key_switch_down(ciphertext);

            Plaintext result;
            cc->decrypt(key_pair.secret_key, ciphertext, &result);
            result->set_length(a.size());
            check_equality(result->get_ckks_packed_value(), comp_a, eps,
                           failmsg + " Bootstrapping for key_switch_ext + key_switch_down failed");

            // Test for eval_fast_rotation_ext
            ciphertext = cc->encrypt(key_pair.public_key, plaintext_a);
            auto digits = cc->eval_fast_rotation_precompute(ciphertext);
            ciphertext = cc->eval_fast_rotation_ext(ciphertext, 1, digits, true);
            ciphertext = cc->key_switch_down(ciphertext);

            cc->decrypt(key_pair.secret_key, ciphertext, &result);
            result->set_length(b.size());
            check_equality(result->get_ckks_packed_value(), comp_b, eps,
                           failmsg + " Bootstrapping for eval_fast_rotation_ext failed");

            // Test for key_switch_ext + key_switch_down w/o first element
            ciphertext = cc->encrypt(key_pair.public_key, plaintext_a);
            auto first_current = ciphertext->get_elements()[0];
            ciphertext = cc->key_switch_ext(ciphertext, false);
            ciphertext = cc->key_switch_down(ciphertext);
            auto elements = ciphertext->get_elements();
            elements[0] += first_current;
            ciphertext->set_elements(elements);

            cc->decrypt(key_pair.secret_key, ciphertext, &result);
            result->set_length(a.size());
            check_equality(result->get_ckks_packed_value(), comp_a, eps,
                           failmsg + " Bootstrapping for key_switch_ext + key_switch_down w/o first element failed");

            // Test for eval_fast_rotation_ext w/o first element
            ciphertext = cc->encrypt(key_pair.public_key, plaintext_a);
            first_current = ciphertext->get_elements()[0];
            // Find the automorphism index that corresponds to rotation index index.
            uint32_t auto_index = find_automorphism_index2n_complex(1, 4096);
            std::vector<uint32_t> map(4096 / 2);
            precompute_auto_map(4096 / 2, auto_index, &map);
            first_current = first_current.automorphism_transform(auto_index, map);
            digits = cc->eval_fast_rotation_precompute(ciphertext);
            ciphertext = cc->eval_fast_rotation_ext(ciphertext, 1, digits, false);
            ciphertext = cc->key_switch_down(ciphertext);
            elements = ciphertext->get_elements();
            elements[0] += first_current;
            ciphertext->set_elements(elements);

            cc->decrypt(key_pair.secret_key, ciphertext, &result);
            result->set_length(b.size());
            check_equality(result->get_ckks_packed_value(), comp_b, eps,
                           failmsg + " Bootstrapping for eval_fast_rotation_ext w/o first element failed");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bootstrap_iterative(const TEST_CASE_UTCKKSRNS_BOOT& test_data, const bool st_c_flag,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // For small ring dimensions like the ones tested, the correction factor for StC-first should be small, e.g., 10.
            cc->eval_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots, (st_c_flag) ? 10 : 0,
                                     true, st_c_flag);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_at_index_key_gen(key_pair.secret_key, {6});
            cc->eval_mult_key_gen(key_pair.secret_key);

            // If CkksDataType is set to REAL, the imaginary parts are ignored.
            auto input(
                    fill_slots({0.111111 + 0.999999i, 0.222222 - 0.888888i, 0.333333 + 0.777777i, 0.444444 - 0.666666i,
                                0.555555 + 0.555555i, 0.666666 - 0.444444i, 0.777777 + 0.333333i, 0.888888 - 0.222222i},
                               test_data.slots));

            size_t encoded_length = input.size();

            Plaintext plaintext = cc->make_ckks_packed_plaintext(
                    input, 1, MULT_DEPTH - 1 - test_data.level_budget[1] * st_c_flag, nullptr, test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
            auto ciphertext_after = cc->eval_bootstrap(ciphertext);

            Plaintext result;
            cc->decrypt(key_pair.secret_key, ciphertext_after, &result);
            result->set_length(encoded_length);
            uint32_t precision = std::floor(
                    calculate_approximation_error(result->get_ckks_packed_value(), plaintext->get_ckks_packed_value()));

            // Give buffer for precision to be lower than one measured result.
            const double precision_buffer = 5;
            precision -= precision_buffer;

            // Add num_iterations as a parameter.
            uint32_t num_iterations = 2;
            auto ciphertext_two_iterations = cc->eval_bootstrap(ciphertext, num_iterations, precision);

            Plaintext result_two_iterations;
            cc->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
            result->set_length(encoded_length);
            auto actual_result = result_two_iterations->get_ckks_packed_value();
            check_equality(actual_result, plaintext->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping with " + std::to_string(num_iterations) +
                                   " iterations failed for " + ((st_c_flag) ? "StC-first" : "ModRaise-first") +
                                   " version.");
            double precision_multiple_iterations =
                    calculate_approximation_error(actual_result, plaintext->get_ckks_packed_value());

            // std::cerr << "Initial precision = " << precision + precision_buffer
            //           << ", META-BTS used precision: " << precision
            //           << ", precision_multiple_iterations = " << precision_multiple_iterations << std::endl;

            double valid_precision = num_iterations * precision;
            EXPECT_GE(precision_multiple_iterations + precision_buffer, valid_precision);

            if (cc->get_ckks_data_type() == REAL) {
                for (size_t i = 0; i < test_data.slots; i++)
                    input[i].imag(0.0);
            }
            auto temp6 = input;
            std::rotate(temp6.begin(), temp6.begin() + 6, temp6.end());

            auto ciphertext6 = cc->eval_at_index(ciphertext_after, 6);
            Plaintext result6;
            cc->decrypt(key_pair.secret_key, ciphertext6, &result6);
            result6->set_length(encoded_length);
            check_equality(result6->get_ckks_packed_value(), temp6, eps,
                           failmsg + " eval_at_index after Bootstrapping for ciphertexts fails for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bootstrap_num_towers(const TEST_CASE_UTCKKSRNS_BOOT& test_data, const bool st_c_flag,
                                        const std::string& failmsg = std::string()) {
        // This test checks to make sure that we return the original ciphertext if we
        // start with more towers than the number of towers we would end up with by
        // bootstrapping.
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots, 0, true, st_c_flag);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_at_index_key_gen(key_pair.secret_key, {6});
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto input(fill_slots({0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888},
                                  test_data.slots));
            size_t encoded_length = input.size();

            // We start with a ciphertext with 0 levels consumed.
            Plaintext plaintext = cc->make_ckks_packed_plaintext(input);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
            auto ciphertext_after = cc->eval_bootstrap(ciphertext);

            auto init_num_towers = ciphertext->get_elements()[0].get_num_of_elements();
            auto bootstrapping_num_towers = ciphertext_after->get_elements()[0].get_num_of_elements();
            // Check to make sure we don't lose any towers.
            EXPECT_EQ(init_num_towers, bootstrapping_num_towers);

            Plaintext result;
            cc->decrypt(key_pair.secret_key, ciphertext_after, &result);
            result->set_length(encoded_length);
            auto actual_result = result->get_ckks_packed_value();
            check_equality(actual_result, plaintext->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping failed for " + ((st_c_flag) ? "StC-first" : "ModRaise-first") +
                                   " version.");

            auto ciphertext_two_iterations = cc->eval_bootstrap(ciphertext);
            auto bootstrapping_num_towers_two_iterations =
                    ciphertext_two_iterations->get_elements()[0].get_num_of_elements();
            // Check to make sure we don't lose any towers with double-iteration bootstrapping.
            EXPECT_EQ(init_num_towers, bootstrapping_num_towers_two_iterations);

            Plaintext result2;
            cc->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result2);
            result->set_length(encoded_length);
            auto actual_result2 = result2->get_ckks_packed_value();
            check_equality(actual_result2, plaintext->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping with two iterations failed for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bootstrap_serialize(const TEST_CASE_UTCKKSRNS_BOOT& test_data, const bool st_c_flag,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContext<Element> cc_init(unit_test_generate_context(test_data.params));
            cc_init->eval_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots, 0, false, st_c_flag);
            cc_init->eval_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots / 2, 0, false,
                                          st_c_flag);

            auto key_pair_init = cc_init->key_gen();
            cc_init->eval_mult_key_gen(key_pair_init.secret_key);
            cc_init->eval_bootstrap_key_gen(key_pair_init.secret_key, test_data.slots);
            cc_init->eval_bootstrap_key_gen(key_pair_init.secret_key, test_data.slots / 2);
            //==============================================================
            // Serialize all necessary objects
            std::stringstream cc_stream;
            serialization::to_stream(cc_init, cc_stream, SerType::BINARY);

            std::stringstream secret_key_stream;
            serialization::to_stream(key_pair_init.secret_key, secret_key_stream, SerType::BINARY);

            std::stringstream public_key_stream;
            serialization::to_stream(key_pair_init.public_key, public_key_stream, SerType::BINARY);

            std::stringstream automorphism_key_stream;
            CryptoContextImpl<RnsPoly>::serialize_eval_automorphism_key(automorphism_key_stream, SerType::BINARY);

            std::stringstream eval_mult_key_stream;
            CryptoContextImpl<RnsPoly>::serialize_eval_mult_key(eval_mult_key_stream, SerType::BINARY);
            //====================================================================================================
            // Removed the serialized objects from the memory
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<RnsPoly>::release_all_contexts();
            //====================================================================================================
            // Deserialize all necessary objects
            CryptoContext<Element> cc;
            serialization::from_stream(cc, cc_stream, SerType::BINARY);

            KeyPair<Element> key_pair;
            serialization::from_stream(key_pair.secret_key, secret_key_stream, SerType::BINARY);
            serialization::from_stream(key_pair.public_key, public_key_stream, SerType::BINARY);
            CryptoContextImpl<RnsPoly>::deserialize_eval_automorphism_key(automorphism_key_stream, SerType::BINARY);
            CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key(eval_mult_key_stream, SerType::BINARY);

            cc->eval_bootstrap_precompute(test_data.slots);
            cc->eval_bootstrap_precompute(test_data.slots / 2);
            //====================================================================================================
            // If CkksDataType is set to REAL, the imaginary parts are ignored.
            auto input(
                    fill_slots({0.111111 + 0.999999i, 0.222222 - 0.888888i, 0.333333 + 0.777777i, 0.444444 - 0.666666i,
                                0.555555 + 0.555555i, 0.666666 - 0.444444i, 0.777777 + 0.333333i, 0.888888 - 0.222222i},
                               test_data.slots));
            size_t encoded_length = input.size();

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(
                    input, 1, MULT_DEPTH - 1 - test_data.level_budget[1] * st_c_flag, nullptr, test_data.slots);
            auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);
            auto ciphertext1_after = cc->eval_bootstrap(ciphertext1);

            Plaintext result;
            cc->decrypt(key_pair.secret_key, ciphertext1_after, &result);
            result->set_length(encoded_length);
            plaintext1->set_length(encoded_length);
            check_equality(result->get_ckks_packed_value(), plaintext1->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping for fully packed ciphertexts fails for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");

            //====================================================================================================
            auto input2(
                    fill_slots({0.111111 + 0.999999i, 0.222222 - 0.888888i, 0.333333 + 0.777777i, 0.444444 - 0.666666i},
                               test_data.slots / 2));
            size_t encoded_length2 = input2.size();

            Plaintext plaintext2 = cc->make_ckks_packed_plaintext(
                    input2, 1, MULT_DEPTH - 1 - test_data.level_budget[1] * st_c_flag, nullptr, test_data.slots / 2);
            auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);
            auto ciphertext2_after = cc->eval_bootstrap(ciphertext2);

            cc->decrypt(key_pair.secret_key, ciphertext2_after, &result);
            result->set_length(encoded_length2);
            plaintext2->set_length(encoded_length2);
            check_equality(result->get_ckks_packed_value(), plaintext2->get_ckks_packed_value(), eps,
                           failmsg + " Bootstrapping for fully packed ciphertexts fails for " +
                                   ((st_c_flag) ? "StC-first" : "ModRaise-first") + " version.");
            //====================================================================================================
            EXPECT_TRUE(1 == 1) << failmsg;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_bootstrap_se(const TEST_CASE_UTCKKSRNS_BOOT& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            auto key_pair = cc->key_gen();

            auto crypto_params =
                    std::dynamic_pointer_cast<CkksRnsCryptoParams>(key_pair.secret_key->get_crypto_parameters());

            std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 0.375, 0.675, 0.125, 0.925};
            size_t encoded_length = x.size();

            // We start with a depleted ciphertext that has used up all of its levels.
            auto depth = crypto_params->get_multiplicative_depth();
            auto ptxt = cc->make_ckks_packed_plaintext(x, 1, depth - 1);
            ptxt->set_length(encoded_length);
            auto ctxt = cc->encrypt(key_pair.public_key, ptxt);

            // Test key_switch_sparse(key_pair.secret_key, ctxt)
            const auto params_q = crypto_params->get_element_params();

            RnsPoly::TugType tug;
            RnsPoly s_new(tug, params_q, Format::EVALUATION, 32);

            auto sk_new = std::make_shared<PrivateKeyImpl<RnsPoly>>(cc);
            sk_new->set_private_element(std::move(s_new));

            auto eval_key = CkksRnsFhe::key_switch_gen_sparse(key_pair.secret_key, sk_new);

            auto ctresult = CkksRnsFhe::key_switch_sparse(ctxt, eval_key);

            Plaintext result;
            cc->decrypt(sk_new, ctresult, &result);
            result->set_length(8);

            check_equality(ptxt->get_ckks_packed_value(), result->get_ckks_packed_value(), eps,
                           failmsg + " input/output mismatch");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

//===========================================================================================================
TEST_P(UTCKKSRNS_BOOT, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case BOOTSTRAP_FULL:
        case BOOTSTRAP_EDGE:
        case BOOTSTRAP_SPARSE:
            unit_test_bootstrap(test, false, test.build_test_name());
            unit_test_bootstrap(test, true, test.build_test_name());
            break;
        case BOOTSTRAP_KEY_SWITCH:
            unit_test_bootstrap_key_switching(test, test.build_test_name());
            break;
        case BOOTSTRAP_ITERATIVE:
            unit_test_bootstrap_iterative(test, false, test.build_test_name());
            unit_test_bootstrap_iterative(test, true, test.build_test_name());
            break;
        case BOOTSTRAP_NUM_TOWERS:
            unit_test_bootstrap_num_towers(test, false, test.build_test_name());
            unit_test_bootstrap_num_towers(test, true, test.build_test_name());
            break;
        case BOOTSTRAP_SERIALIZE:
            unit_test_bootstrap_serialize(test, false, test.build_test_name());
            unit_test_bootstrap_serialize(test, true, test.build_test_name());
            break;
        case BOOTSTRAP_SPARSE_ENCAPSULATED:
            unit_test_bootstrap_se(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_BOOT, ::testing::ValuesIn(test_cases), make_test_name);
