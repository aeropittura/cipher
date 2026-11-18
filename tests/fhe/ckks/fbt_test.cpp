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
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "cipher/config.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/math/hermite.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/utils.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/fhe/schemelet/rlwe_mp.h"
#include "cipher/util/debug.h"

// Define BENCH below to enable more fine-grained benchmarking.
// The benchmarks using SPARSE_TERNARY distribution correspond exactly to Tables 2 and A.3 in
// https://eprint.iacr.org/2024/1623.pdf, while the benchmarks using SPARSE_ENCAPSULATED are more
// secure and lead to slightly more efficient results as compared to those tables.
// #define BENCH

using namespace cipher;

enum TEST_CASE_TYPE : int {
    FBT_ARBLUT = 0,
    FBT_SIGNDIGIT,
    FBT_CONSECLEV,
    FBT_MVB,
    FBT_NOISE,
    FBT_NOISE_VS_FLEXIBLE,
    FBT_MVB_REUSE,
    FBT_INVALID,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case FBT_ARBLUT:
            typeName = "FBT_ARBLUT";
            break;
        case FBT_SIGNDIGIT:
            typeName = "FBT_SIGNDIGIT";
            break;
        case FBT_CONSECLEV:
            typeName = "FBT_CONSECLEV";
            break;
        case FBT_MVB:
            typeName = "FBT_MVB";
            break;
        case FBT_NOISE:
            typeName = "FBT_NOISE";
            break;
        case FBT_NOISE_VS_FLEXIBLE:
            typeName = "FBT_NOISE_VS_FLEXIBLE";
            break;
        case FBT_MVB_REUSE:
            typeName = "FBT_MVB_REUSE";
            break;
        case FBT_INVALID:
            typeName = "FBT_INVALID";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

static std::string scal_tech_name(ScalingTechnique st) {
    switch (st) {
        case FIXEDMANUAL:
            return "FIXEDMANUAL";
        case FIXEDAUTO:
            return "FIXEDAUTO";
        case FLEXIBLEAUTO:
            return "FLEXIBLEAUTO";
        case FLEXIBLEAUTOEXT:
            return "FLEXIBLEAUTOEXT";
        case COMPOSITESCALINGAUTO:
            return "COMPOSITESCALINGAUTO";
        case COMPOSITESCALINGMANUAL:
            return "COMPOSITESCALINGMANUAL";
        default:
            return "UNKNOWN";
    }
}

// The CKKS scaling factor has the same bit length as the RLWE ciphertext modulus. The first modulus has the
// same size too, except for composite scaling, whose parameter generation requires first_mod_size_value > scaling_mod_size;
// there the first modulus is one bit larger (the ratio between the first modulus and the RLWE ciphertext
// modulus is compensated exactly by the scale bookkeeping of functional bootstrapping).
static uint32_t first_mod_size(uint32_t dcrt_bits, ScalingTechnique st) {
    return (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ? dcrt_bits + 1 : dcrt_bits;
}

// Composite scaling with a register word size of w bits yields composite degree ceil(dcrt_bits / w), i.e., with the
// default w = 32, 2 for the scaling factor sizes used in most composite rows and 3 for the 90-bit rows (the default
// register word size of the library would yield composite degree 1, which is rejected). COMPOSITESCALINGMANUAL
// requires the composite degree to be set explicitly; the same degree as the one COMPOSITESCALINGAUTO would choose
// is used.
static uint32_t composite_degree_for_test(uint32_t dcrt_bits, ScalingTechnique st, uint32_t register_word_size) {
    return (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ?
                   (dcrt_bits + register_word_size - 1) / register_word_size :
                   1;
}

static void set_scaling_technique_params(ContextParams<CkksRnsContext>& parameters, ScalingTechnique st,
                                      uint32_t dcrt_bits, uint32_t register_word_size) {
    parameters.set_scaling_technique(st);
    if (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) {
        parameters.set_register_word_size(register_word_size);
        if (st == COMPOSITESCALINGMANUAL)
            parameters.set_composite_degree(composite_degree_for_test(dcrt_bits, st, register_word_size));
    }
}

struct TEST_CASE_FBT {
    TEST_CASE_TYPE test_case_type;
    std::string description;

    BigInteger qbfv_init;
    BigInteger p_input;
    BigInteger p_output;
    BigInteger Q;
    BigInteger bigq;
    double scale_thi;
    double scale_step_thi;
    size_t order;
    uint32_t num_slots;
    uint32_t ring_dim;
    uint32_t levels_available_after_bootstrap;
    uint32_t levels_available_before_bootstrap;
    uint32_t dnum;
    uint32_t levels_computation;
    std::vector<uint32_t> lvlb;
    SecretKeyDist skd;
    // scaling technique used for the CKKS cryptocontext; FIXEDMANUAL by default
    ScalingTechnique scal_tech = FIXEDMANUAL;
    // register word size for the COMPOSITESCALING* techniques; 32 by default
    uint32_t register_word_size = 32;

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description << "_" << scal_tech_name(scal_tech);
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_FBT>& test) {
    return test.param.build_test_name();
};

[[maybe_unused]] const BigInteger PINPUT(256);
[[maybe_unused]] const BigInteger POUTPUT(256);
[[maybe_unused]] const BigInteger Q21(BigInteger(1) << 21);
[[maybe_unused]] const BigInteger Q32(BigInteger(1) << 32);
[[maybe_unused]] const BigInteger Q33(BigInteger(1) << 33);
[[maybe_unused]] const BigInteger Q35(BigInteger(1) << 35);
[[maybe_unused]] const BigInteger Q36(BigInteger(1) << 36);
[[maybe_unused]] const BigInteger Q37(BigInteger(1) << 37);
[[maybe_unused]] const BigInteger Q38(BigInteger(1) << 38);
[[maybe_unused]] const BigInteger Q40(BigInteger(1) << 40);
[[maybe_unused]] const BigInteger Q42(BigInteger(1) << 42);
[[maybe_unused]] const BigInteger Q43(BigInteger(1) << 43);
[[maybe_unused]] const BigInteger Q44(BigInteger(1) << 44);
[[maybe_unused]] const BigInteger Q45(BigInteger(1) << 45);
[[maybe_unused]] const BigInteger Q46(BigInteger(1) << 46);
[[maybe_unused]] const BigInteger Q47(BigInteger(1) << 47);
[[maybe_unused]] const BigInteger Q48(BigInteger(1) << 48);
[[maybe_unused]] const BigInteger Q54(BigInteger(1) << 54);
[[maybe_unused]] const BigInteger Q55(BigInteger(1) << 55);
[[maybe_unused]] const BigInteger Q56(BigInteger(1) << 56);
[[maybe_unused]] const BigInteger Q57(BigInteger(1) << 57);
[[maybe_unused]] const BigInteger Q58(BigInteger(1) << 58);
[[maybe_unused]] const BigInteger Q59(BigInteger(1) << 59);
[[maybe_unused]] const BigInteger Q60(BigInteger(1) << 60);
[[maybe_unused]] const BigInteger Q63(BigInteger(1) << 63);
[[maybe_unused]] const BigInteger Q64(BigInteger(1) << 64);
[[maybe_unused]] const BigInteger Q71(BigInteger(1) << 71);
[[maybe_unused]] const BigInteger Q80(BigInteger(1) << 80);
[[maybe_unused]] const BigInteger Q90(BigInteger(1) << 90);
[[maybe_unused]] const BigInteger Q110(BigInteger(1) << 110);
[[maybe_unused]] const BigInteger Q119(BigInteger(1) << 119);
[[maybe_unused]] const BigInteger Q120(BigInteger(1) << 120);
[[maybe_unused]] const BigInteger Q140(BigInteger(1) << 140);
[[maybe_unused]] const BigInteger Q130(BigInteger(1) << 130);

[[maybe_unused]] constexpr double SCALETHI(32.0);
[[maybe_unused]] constexpr double SCALESTEPTHI(1.0);
[[maybe_unused]] constexpr uint32_t AFTERBOOT(0);
[[maybe_unused]] constexpr uint32_t BEFOREBOOT(0);
[[maybe_unused]] constexpr uint32_t LVLSCOMP(0);
[[maybe_unused]] constexpr uint32_t SLOTSPARSE(8);
[[maybe_unused]] constexpr uint32_t SLOTFULL(32);
[[maybe_unused]] constexpr uint32_t RINGDM(32);
[[maybe_unused]] const std::vector<uint32_t> LVLBDFLT = {3, 3};

// clang-format off
static std::vector<TEST_CASE_FBT> test_cases = {
// Functional Bootstrapping does not support NATIVE_SIZE == 128: every case below fails there, for the
// FIXED* modes as well, because the 128-bit scaling path that standard CKKS bootstrapping implements
// (the correction factor) has no counterpart here. The supported rescaling modes are FIXEDMANUAL,
// FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL on the 64-bit
// build (composite scaling rows are 10xx below).
#if CIPHER_NATIVE_INT != 128
#ifndef BENCH
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "04",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "05",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "06",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "07",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "08",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "09",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "10",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "11",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "12",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "13",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "14",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "15",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "16",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "17",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "18",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "19",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "20",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "21",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "22",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "23",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "24",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    // TestCaseType,  Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "104",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "105",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "106",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "107",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "108",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "109",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "110",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "111",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "112",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "113",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "114",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "115",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "116",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "117",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "118",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "119",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "120",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "121",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "122",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "123",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "124",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "201",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "202",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "203",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FIXEDAUTO},
    { FBT_SIGNDIGIT, "204",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    { FBT_CONSECLEV, "205",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {       FBT_MVB, "206",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "301",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "302",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "303",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FLEXIBLEAUTO},
    { FBT_SIGNDIGIT, "304",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    { FBT_CONSECLEV, "305",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {       FBT_MVB, "306",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "401",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "402",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "403",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FLEXIBLEAUTOEXT},
    { FBT_SIGNDIGIT, "404",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    { FBT_CONSECLEV, "405",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {       FBT_MVB, "406",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    // Noise-comparison tests: the same LUT is evaluated with FIXEDMANUAL and with the scaling technique below,
    // and the test checks that the FLEXIBLE* technique yields smaller noise in the output RLWE ciphertext.
    {     FBT_NOISE, "501",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {     FBT_NOISE, "502",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    // Multi-limb initial scaling: the RLWE ciphertext is imported with one level available before
    // bootstrapping, so initial_scaling in eval_fbt covers two RNS limbs (q0*q1) and must be
    // corrected before the modulus raise.
    {    FBT_ARBLUT, "601",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "602",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "603",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "604",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    // Repeated LUT evaluation on the same precomputed powers (checks the precomputation is not
    // corrupted in place) and rejection of invalid arguments.
    { FBT_MVB_REUSE, "701",      Q60,      2,       4, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_MVB_REUSE, "702",      Q60,      2,       4, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    { FBT_MVB_REUSE, "703",      Q60,      4,       4, Q36, Q36,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_MVB_REUSE, "704",      Q60,      4,       4, Q36, Q36,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_MVB_REUSE, "705",      Q60,      4,       4, Q36, Q36,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {   FBT_INVALID, "801",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    // UNIFORM_TERNARY: the uniform secret distribution uses six double-angle iterations instead of two
    // and a degree-104 Chebyshev interpolation instead of degree 64/46 (the mod-raise overflow bound is
    // K_UNIFORM_FBT = 672 vs 28/16 for the sparse distributions), which adds 5 levels of multiplicative
    // depth. Larger scaling factors are used as well, because the mod-raised message is scaled down by
    // K_UNIFORM_FBT before CoeffsToSlots, which amplifies the (fixed-size) encoding noise relative to the
    // message.
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "901",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "902",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "903",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "904",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "905",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "906",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "907",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "908",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "909",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "910",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "911",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    {    FBT_ARBLUT, "912",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_SIGNDIGIT, "913",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_SIGNDIGIT, "914",      Q80,    Q21,       2, Q63, Q43,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_SIGNDIGIT, "915",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_SIGNDIGIT, "916",      Q80,    Q21,       2, Q63, Q43,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_CONSECLEV, "917",      Q60,      2,       2, Q42, Q42,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_CONSECLEV, "918",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_CONSECLEV, "919",      Q60,      2,       2, Q42, Q42,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    { FBT_CONSECLEV, "920",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    {       FBT_MVB, "921",      Q60,      2,       2, Q42, Q42,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    {       FBT_MVB, "922",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    {       FBT_MVB, "923",      Q60,      2,       2, Q42, Q42,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    {       FBT_MVB, "924",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY},
    // UNIFORM_TERNARY with the other supported scaling techniques
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "931",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "932",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "933",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "934",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    { FBT_SIGNDIGIT, "935",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "936",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "937",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTOEXT},
    {       FBT_MVB, "938",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    // UNIFORM_TERNARY, sparse packing (num_slots < ring_dim/2), with the other supported scaling techniques
    {    FBT_ARBLUT, "941",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "942",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "943",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "944",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "945",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTOEXT},
    { FBT_SIGNDIGIT, "946",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    // COMPOSITESCALINGAUTO (composite degree 2 for these scaling factor sizes, with the default register word
    // size of 32 bits). The parameter generation for composite scaling requires primes of at least 19 bits,
    // hence the larger moduli (the same ones as for UNIFORM_TERNARY are used), and a first modulus larger than
    // the scaling factor (see first_mod_size). The FBT_NOISE_VS_FLEXIBLE rows check that the output noise is
    // within 3 bits of FLEXIBLEAUTO for the same parameters (measured differences are below 1 bit; the tolerance
    // covers the run-to-run variation of the maximum noise over the few slots of these small rings, and the rows
    // are chosen among the configurations whose noise is stable across runs; binary LUTs with UNIFORM_TERNARY
    // vary by ~3 bits across runs for both techniques and are therefore not used here).
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "1001",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1002",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1003",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1004",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_SIGNDIGIT, "1005",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_CONSECLEV, "1006",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {       FBT_MVB, "1007",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_MVB_REUSE, "1008",      Q60,      2,       4, Q42, Q42,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_MVB_REUSE, "1067",      Q60,      4,       4, Q42, Q42,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1009",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1010",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1011",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1012",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_SIGNDIGIT, "1013",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
    {       FBT_MVB, "1014",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_NOISE_VS_FLEXIBLE, "1021", Q60,  2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_NOISE_VS_FLEXIBLE, "1022", Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI, 1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_NOISE_VS_FLEXIBLE, "1023", Q60,  PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI, 2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_NOISE_VS_FLEXIBLE, "1024", Q60,     16,      16, Q48, Q48,       16, SCALESTEPTHI, 1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
    // Large scaling factors (90 bits, composite degree 3 with 30-bit primes), which only composite scaling supports
    // on the 64-bit build; the RLWE ciphertext modulus has the same bit length as the scaling factor.
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "1031",     Q110, PINPUT, POUTPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1032",     Q110, PINPUT, POUTPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
#if CIPHER_MATH_BACKEND != 2
    // Excluded for CIPHER_MATH_BACKEND 2: the modulus chain of these deeper 90-bit rows exceeds the fixed 3500-bit
    // width of its multiprecision integers.
    {    FBT_ARBLUT, "1033",     Q110,   4096,    4096, Q90, Q90,     2000, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1034",     Q110, PINPUT, POUTPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGAUTO},
#endif
    { FBT_SIGNDIGIT, "1035",     Q130,    Q21,       2, Q110, Q90,       1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    {       FBT_MVB, "1036",     Q110, PINPUT,  PINPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    { FBT_CONSECLEV, "1037",     Q110, PINPUT,  PINPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO},
    // COMPOSITESCALINGMANUAL (composite degree set explicitly, see set_scaling_technique_params)
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "1041",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    {    FBT_ARBLUT, "1042",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    {    FBT_ARBLUT, "1043",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGMANUAL},
    { FBT_SIGNDIGIT, "1044",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    {       FBT_MVB, "1045",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    {    FBT_ARBLUT, "1046",     Q110, PINPUT, POUTPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    { FBT_NOISE_VS_FLEXIBLE, "1047", Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI, 1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGMANUAL},
    // SPARSE_ENCAPSULATED with composite scaling (sparse key switching over the composite bottom basis): the K = 16
    // approximations for first moduli of at most 60 bits (Q40/Q54/Q55 rows, Hamming weight 32) and the K = 28
    // approximations of SPARSE_TERNARY for larger first moduli (Q64/Q90 rows, Hamming weight 64)
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "1051",      Q60,      2,       2, Q40, Q40,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1052",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1053",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    { FBT_SIGNDIGIT, "1054",      Q80,    Q21,       2, Q64, Q44,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    {       FBT_MVB, "1055",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1056",     Q110, PINPUT, POUTPUT, Q90, Q90, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO},
    {    FBT_ARBLUT, "1057",      Q60, PINPUT, POUTPUT, Q54, Q54, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGMANUAL},
    // Largest scaling factors: 119 bits (120-bit first modulus) is the maximum for a register word size of 64 bits
    // (composite degree 2 with 60-bit primes), and 120 bits (121-bit first modulus), the maximum of composite scaling,
    // requires a smaller register word size (32 bits: composite degree 4).
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order,   num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique, register_word_size
#if CIPHER_MATH_BACKEND != 2
    // Excluded for CIPHER_MATH_BACKEND 2: the modulus chains of the 119/120-bit rows exceed the fixed 3500-bit width of
    // its multiprecision integers.
    {    FBT_ARBLUT, "1061",     Q140, PINPUT, POUTPUT, Q119, Q119, SCALETHI, SCALESTEPTHI,   1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO, 64},
    {    FBT_ARBLUT, "1062",     Q140, PINPUT, POUTPUT, Q119, Q119, SCALETHI, SCALESTEPTHI,   2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO, 64},
    {    FBT_ARBLUT, "1063",     Q140, PINPUT, POUTPUT, Q119, Q119, SCALETHI, SCALESTEPTHI,   1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, UNIFORM_TERNARY, COMPOSITESCALINGMANUAL, 64},
    {    FBT_ARBLUT, "1064",     Q140, PINPUT, POUTPUT, Q120, Q120, SCALETHI, SCALESTEPTHI,   1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO, 32},
    {    FBT_ARBLUT, "1065",     Q140, PINPUT, POUTPUT, Q120, Q120, SCALETHI, SCALESTEPTHI,   1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, COMPOSITESCALINGAUTO, 32},
    {       FBT_MVB, "1066",     Q140, PINPUT,  PINPUT, Q120, Q120, SCALETHI, SCALESTEPTHI,   1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, COMPOSITESCALINGAUTO, 32},
#endif
    { FBT_CONSECLEV, "947",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
    {       FBT_MVB, "948",      Q60, PINPUT,  PINPUT, Q55, Q55, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, UNIFORM_TERNARY, FLEXIBLEAUTO},
#else
    // TestCaseType, Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order, num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "04",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "05",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "06",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "07",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "08",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "09",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "10",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "11",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "12",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "13",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "14",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "15",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "16",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "17",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "18",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "19",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "20",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "21",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "22",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "23",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "24",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "25",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "27",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "29",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "31",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "33",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "35",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "37",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "39",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "41",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    // TestCaseType,  Desc, qbfv_init, p_input, p_output,  Q, Bigq, scale_thi, scale_step_thi, order, num_slots, ring_dim, lvls_after_boot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "104",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "105",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "106",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "107",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "108",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "109",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "110",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "111",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "112",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "113",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "114",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "115",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "116",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "117",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "118",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "119",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "120",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "121",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "122",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "123",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "124",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "125",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "127",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "129",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "131",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "133",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "135",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "137",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "139",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "141",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
#endif
#endif
};
// clang-format on

// Measures the maximum noise (in bits) in the message coefficients of an RLWE ciphertext encrypting
// delta*m for delta = Q/p. It follows SchemeletRlweMp::decrypt_coeff, but instead of rounding to the
// nearest multiple of delta, it returns the centered residual modulo delta (the rounding error).
static double measure_noise_bits(const std::vector<Poly>& input, const BigInteger& Q, const BigInteger& p,
                               const PrivateKey<RnsPoly>& private_key,
                               const std::shared_ptr<RnsParams<RnsPoly::Integer>>& ep, uint32_t num_slots,
                               uint32_t length) {
    const auto& big_q_prime = ep->get_modulus();

    Poly b_poly = input[0];
    Poly a_poly = input[1];
    if (Q < big_q_prime) {
        b_poly.switch_modulus(big_q_prime, 1, 0, 0);
        b_poly = b_poly.multiply_and_round(big_q_prime, Q);
        a_poly.switch_modulus(big_q_prime, 1, 0, 0);
        a_poly = a_poly.multiply_and_round(big_q_prime, Q);
    } else {
        b_poly = b_poly.multiply_and_round(big_q_prime, Q);
        b_poly.switch_modulus(big_q_prime, 1, 0, 0);
        a_poly = a_poly.multiply_and_round(big_q_prime, Q);
        a_poly.switch_modulus(big_q_prime, 1, 0, 0);
    }

    std::vector<RnsPoly> ba{RnsPoly(b_poly, ep), RnsPoly(a_poly, ep)};
    ba[0].set_format(Format::EVALUATION);
    ba[1].set_format(Format::EVALUATION);

    auto scopy(private_key->get_private_element());
    scopy.drop_last_elements(scopy.get_params()->get_params().size() - ep->get_params().size());

    auto m = ba[0] + ba[1] * scopy;
    m.set_format(Format::COEFFICIENT);
    auto m_poly = m.crt_interpolate();

    if (Q < big_q_prime) {
        m_poly = m_poly.multiply_and_round(Q, big_q_prime);
        m_poly.switch_modulus(Q, 1, 0, 0);
    } else {
        m_poly.switch_modulus(Q, 1, 0, 0);
        m_poly = m_poly.multiply_and_round(Q, big_q_prime);
    }

    BigInteger delta = Q / p;
    BigInteger half = delta >> 1;
    uint32_t gap = m_poly.get_length() / (2 * num_slots);
    gap = (gap == 0) ? 1 : gap;

    BigInteger max_noise(0);
    for (uint32_t i = 0, idx = 0; i < length; ++i, idx += gap) {
        BigInteger r = m_poly[idx].mod(delta);
        if (r > half)
            r = delta - r;
        if (r > max_noise)
            max_noise = r;
    }
    return std::log2(max_noise.convert_to_double() + 1);
}

class UTCKKSRNS_FBT : public ::testing::TestWithParam<TEST_CASE_FBT> {
  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    };

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_arb_lut(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
            // t.num_slots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {(t.p_input.convert_to_int<int64_t>() / 2),
                                      (t.p_input.convert_to_int<int64_t>() / 2) + 1,
                                      0,
                                      3,
                                      16,
                                      33,
                                      64,
                                      (t.p_input.convert_to_int<int64_t>() - 1)};
            if (x.size() < t.num_slots)
                x = Fill<int64_t>(x, t.num_slots);

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
            if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                coeffint = {f(1), f(0) - f(1)};
            else  // divided by 2
                coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
            ContextParams<CkksRnsContext> parameters;
            parameters.set_secret_key_dist(t.skd);
            parameters.set_security_level(HEStd_NotSet);
            parameters.set_scaling_mod_size(dcrt_bits);
            set_scaling_technique_params(parameters, t.scal_tech, dcrt_bits, t.register_word_size);
            parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
            parameters.set_num_large_digits(t.dnum);
            parameters.set_batch_size(num_slots_ckks);
            parameters.set_ring_dim(t.ring_dim);
            uint32_t depth = t.levels_available_after_bootstrap;

            if (binary_lut)
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));
            else
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));

            parameters.set_multiplicative_depth(depth);

            auto cc = make_crypto_context(parameters);
            cc->enable(PKE);
            cc->enable(KEYSWITCH);
            cc->enable(LEVELEDSHE);
            cc->enable(ADVANCEDSHE);
            cc->enable(FHE);

            auto key_pair = cc->key_gen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binary_lut)
                cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                                 t.levels_available_after_bootstrap, 0, t.order);
            else
                cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, 0, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
            cc->eval_mult_key_gen(key_pair.secret_key);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key,
                                                        depth - (t.levels_available_before_bootstrap > 0));

            auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

            auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks,
                                                           depth - (t.levels_available_before_bootstrap > 0));

            Ciphertext<RnsPoly> ctxt_after_fbt;
            if (binary_lut)
                ctxt_after_fbt =
                        cc->eval_fbt(ctxt, coeffint, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0, t.order);
            else
                ctxt_after_fbt =
                        cc->eval_fbt(ctxt, coeffcomp, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0, t.order);

            auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed = SchemeletRlweMp::decrypt_coeff(polys, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks,
                                                          t.num_slots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) > t.p_output.convert_to_double() / 2.) ? f(elem) - t.p_output.convert_to_int<int64_t>() :
                                                                      f(elem);
            });

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->clear_static_maps_and_vectors();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_sign_digit(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
            // t.num_slots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();

            auto func_mod = [b](int64_t x) -> int64_t {
                return (x % b);
            };
            auto func_step = [a, b](int64_t x) -> int64_t {
                return (x % a) >= (b / 2);
            };

            std::vector<int64_t> x = {
                    t.p_input.convert_to_int<int64_t>() / 2, t.p_input.convert_to_int<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                    t.p_input.convert_to_int<int64_t>() - 1};
            if (x.size() < t.num_slots)
                x = Fill<int64_t>(x, t.num_slots);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(),
                           [&](int64_t elem) { return (elem >= t.p_input.convert_to_double() / 2.); });

            std::vector<int64_t> coeffint_mod;
            std::vector<std::complex<double>> coeffcomp_mod;
            std::vector<std::complex<double>> coeffcomp_step;
            bool binary_lut = (t.p_output.convert_to_int() == 2) && (t.order == 1);
            if (binary_lut) {
                coeffint_mod = {func_mod(1),
                               func_mod(0) - func_mod(1)};  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
            } else {
                coeffcomp_mod = get_hermite_trig_coefficients(func_mod, t.p_output.convert_to_int(), t.order,
                                                          t.scale_thi);  // divided by 2
                coeffcomp_step = get_hermite_trig_coefficients(func_step, t.p_output.convert_to_int(), t.order,
                                                           t.scale_step_thi);  // divided by 2
            }

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
            ContextParams<CkksRnsContext> parameters;
            parameters.set_secret_key_dist(t.skd);
            parameters.set_security_level(HEStd_NotSet);
            parameters.set_scaling_mod_size(dcrt_bits);
            set_scaling_technique_params(parameters, t.scal_tech, dcrt_bits, t.register_word_size);
            parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
            parameters.set_num_large_digits(t.dnum);
            parameters.set_batch_size(num_slots_ckks);
            parameters.set_ring_dim(t.ring_dim);

            uint32_t depth = t.levels_available_after_bootstrap;

            if (binary_lut)
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint_mod, t.p_output, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));
            else
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp_mod, t.p_output, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));

            parameters.set_multiplicative_depth(depth);

            auto cc = make_crypto_context(parameters);
            cc->enable(PKE);
            cc->enable(KEYSWITCH);
            cc->enable(LEVELEDSHE);
            cc->enable(ADVANCEDSHE);
            cc->enable(FHE);

            auto key_pair = cc->key_gen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binary_lut)
                cc->eval_fbt_setup(coeffint_mod, num_slots_ckks, t.p_output, t.p_input, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, 0, t.order);
            else
                cc->eval_fbt_setup(coeffcomp_mod, num_slots_ckks, t.p_output, t.p_input, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, 0, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
            cc->eval_mult_key_gen(key_pair.secret_key);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key,
                                                        depth - (t.levels_available_before_bootstrap > 0));

            auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            if (binary_lut)
                coeffint = coeffint_mod;
            else
                coeffcomp = coeffcomp_mod;

            SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

            uint32_t qbfv_bits = t.Q.get_msb() - 1;

            auto Q = t.Q;            // Will get modified in the loop.
            auto p_input = t.p_input;  // Will get modified in the loop.

            BigInteger Q_new;

            const bool checkeq2 = t.p_output.convert_to_int() == 2;
            const bool checkgt2 = t.p_output.convert_to_int() > 2;
            const uint32_t p_digit_bits = t.p_output.get_msb() - 1;

            uint64_t scale_thi = t.scale_thi;
            bool step = false;
            bool go = qbfv_bits > dcrt_bits;
            size_t levels_to_drop = 0;
            uint32_t post_scaling_bits = 0;

            // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
            // Currently this only works when log(pNew) divides log(p).
            while (go) {
                auto encrypted_digit = ctxt_bfv;

                // Apply mod q
                encrypted_digit[0].switch_modulus(t.bigq, 1, 0, 0);
                encrypted_digit[1].switch_modulus(t.bigq, 1, 0, 0);

                auto ctxt =
                        SchemeletRlweMp::convert_rlwe_to_ckks(*cc, encrypted_digit, key_pair.public_key, t.bigq, num_slots_ckks,
                                                           depth - (t.levels_available_before_bootstrap > 0));

                // Bootstrap the digit.
                Ciphertext<RnsPoly> ctxt_after_fbt;
                if (binary_lut)
                    ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, p_digit_bits, ep->get_modulus(),
                                               scale_thi * (1 << post_scaling_bits), levels_to_drop, t.order);
                else
                    ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, p_digit_bits, ep->get_modulus(),
                                               scale_thi * (1 << post_scaling_bits), levels_to_drop, t.order);

                auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, Q);

                if (!step) {
                    Q_new = Q >> p_digit_bits;

                    // Subtract digit and switch mod from Q to Q_new for BFV ciphertext
                    ctxt_bfv[0] = (ctxt_bfv[0] - polys[0]).multiply_and_round(Q_new, Q);
                    ctxt_bfv[0].switch_modulus(Q_new, 1, 0, 0);
                    ctxt_bfv[1] = (ctxt_bfv[1] - polys[1]).multiply_and_round(Q_new, Q);
                    ctxt_bfv[1].switch_modulus(Q_new, 1, 0, 0);
                    Q >>= p_digit_bits;
                    p_input >>= p_digit_bits;
                    qbfv_bits -= p_digit_bits;
                    post_scaling_bits += p_digit_bits;
                } else {
                    ctxt_bfv[0] = std::move(polys[0]);
                    ctxt_bfv[1] = std::move(polys[1]);
                }

                go = qbfv_bits > dcrt_bits;

                if (step || (checkeq2 && !go)) {
#ifdef BENCH
                    stop = std::chrono::high_resolution_clock::now();
                    std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count()
                              << " s\n";
                    start = std::chrono::high_resolution_clock::now();
#endif

                    auto computed = SchemeletRlweMp::decrypt_coeff(ctxt_bfv, Q, p_input, key_pair.secret_key, ep,
                                                                  num_slots_ckks, t.num_slots);

#ifdef BENCH
                    stop = std::chrono::high_resolution_clock::now();
                    std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
                    start = std::chrono::high_resolution_clock::now();
#endif

                    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
                    std::transform(exact.begin(), exact.end(), exact.begin(),
                                   [&](int64_t elem) { return (std::abs(elem)) % (t.p_input.convert_to_int()); });
                    auto max_error_it = std::max_element(exact.begin(), exact.end());
                    // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
                    // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
                    check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001,
                                  failmsg + " MP sign evaluation fails");
                }

                if (checkgt2 && !go && !step) {
                    if (!binary_lut)
                        coeffcomp = coeffcomp_step;
                    scale_thi = t.scale_step_thi;
                    step = true;
                    go = true;

                    int64_t lvls_to_drop = get_multiplicative_depth_by_coeff_vector(coeffcomp_mod, true) -
                                         get_multiplicative_depth_by_coeff_vector(coeffcomp_step, true);
                    if (coeffcomp_mod.size() > 4 && lvls_to_drop > 0)
                        levels_to_drop = lvls_to_drop;
                }
            }

            cc->clear_static_maps_and_vectors();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_consec_lev_lut(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flag_br = (t.lvlb[0] != 1 || t.lvlb[1] != 1);
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing

            // t.num_slots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {
                    t.p_input.convert_to_int<int64_t>() / 2, t.p_input.convert_to_int<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                    t.p_input.convert_to_int<int64_t>() - 1};
            if (x.size() < t.num_slots)
                x = Fill<int64_t>(x, t.num_slots);

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
            if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                coeffint = {f(1), f(0) - f(1)};
            else  // divided by 2
                coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
            ContextParams<CkksRnsContext> parameters;
            parameters.set_secret_key_dist(t.skd);
            parameters.set_security_level(HEStd_NotSet);
            parameters.set_scaling_mod_size(dcrt_bits);
            set_scaling_technique_params(parameters, t.scal_tech, dcrt_bits, t.register_word_size);
            parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
            parameters.set_num_large_digits(t.dnum);
            parameters.set_batch_size(num_slots_ckks);
            parameters.set_ring_dim(t.ring_dim);
            uint32_t depth = t.levels_available_after_bootstrap + t.levels_computation;

            if (binary_lut)
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));
            else
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));

            parameters.set_multiplicative_depth(depth);

            auto cc = make_crypto_context(parameters);
            cc->enable(PKE);
            cc->enable(KEYSWITCH);
            cc->enable(LEVELEDSHE);
            cc->enable(ADVANCEDSHE);
            cc->enable(FHE);

            auto key_pair = cc->key_gen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binary_lut)
                cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                                 t.levels_available_after_bootstrap, t.levels_computation, t.order);
            else
                cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, t.levels_computation, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
            cc->eval_mult_key_gen(key_pair.secret_key);
            cc->eval_at_index_key_gen(key_pair.secret_key, std::vector<int32_t>({-2}));

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto mask_real = Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, t.num_slots);

            // The mask level is counted in towers on the full modulus chain, which has an extra modulus for
            // FLEXIBLEAUTOEXT and composite_degree towers per level for composite scaling
            const uint32_t ext_off = (t.scal_tech == FLEXIBLEAUTOEXT) ? 1 : 0;
            const uint32_t cd =
                    std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters())->get_composite_degree();

            // Note that the corresponding plaintext mask for full packing can be just real, as real times complex multiplies both real and imaginary parts
            Plaintext ptxt_mask = cc->make_ckks_packed_plaintext(
                    Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, num_slots_ckks), 1,
                    cd * (depth - t.lvlb[1] - t.levels_available_after_bootstrap - t.levels_computation) + ext_off, nullptr,
                    num_slots_ckks);

            auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key,
                                                        depth - (t.levels_available_before_bootstrap > 0));

            // Set bit_reverse true to be able to perform correct rotations in CKKS
            auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep, flag_br);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

            auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks,
                                                           depth - (t.levels_available_before_bootstrap > 0));

            // Apply LUT and remain in slots encodings.
            Ciphertext<RnsPoly> ctxt_after_fbt;
            if (binary_lut)
                ctxt_after_fbt = cc->eval_fbt_no_decoding(ctxt, coeffint, t.p_input.get_msb() - 1, ep->get_modulus(), t.order);
            else
                ctxt_after_fbt = cc->eval_fbt_no_decoding(ctxt, coeffcomp, t.p_input.get_msb() - 1, ep->get_modulus(), t.order);

            // Apply a rotation
            ctxt_after_fbt = cc->eval_rotate(ctxt_after_fbt, -2);

            // Apply a multiplicative mask
            ctxt_after_fbt = cc->eval_mult(ctxt_after_fbt, ptxt_mask);
            cc->mod_reduce_in_place(ctxt_after_fbt);

            // Go back to coefficients, 0 because there are no extra levels to remove
            ctxt_after_fbt = cc->eval_hom_decoding(ctxt_after_fbt, t.scale_thi, 0);

            auto polys1 = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, t.Q);

            // Apply a subsequent LUT
            ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, polys1, key_pair.public_key, t.bigq, num_slots_ckks,
                                                      depth - (t.levels_available_before_bootstrap > 0));

            if (binary_lut)
                ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi,
                                           t.levels_computation, t.order);
            else
                ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi,
                                           t.levels_computation, t.order);

            auto polys2 = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed1 = SchemeletRlweMp::decrypt_coeff(polys1, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks,
                                                           t.num_slots, flag_br);

            auto computed2 = SchemeletRlweMp::decrypt_coeff(polys2, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks,
                                                           t.num_slots, flag_br);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) % t.p_output.convert_to_int() > t.p_output.convert_to_double() / 2.) ?
                               f(elem) % t.p_output.convert_to_int() - t.p_output.convert_to_int() :
                               f(elem) % t.p_output.convert_to_int();
            });

            // Apply a rotation
            std::vector<int64_t> exact2 = flag_sp ? Rotate(exact, -2) : rotate_two_halves(exact, -2);

            std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

            auto exact3 = exact2;

            std::transform(exact2.begin(), exact2.end(), computed1.begin(), exact2.begin(), std::minus<int64_t>());
            std::transform(exact2.begin(), exact2.end(), exact2.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });

            auto max_error_it = std::max_element(exact2.begin(), exact2.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(exact3.begin(), exact3.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) % t.p_output.convert_to_int() > t.p_output.convert_to_double() / 2.) ?
                               f(elem) % t.p_output.convert_to_int() - t.p_output.convert_to_int() :
                               f(elem) % t.p_output.convert_to_int();
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->clear_static_maps_and_vectors();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_mvb(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
            // t.num_slots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();
            auto f1 = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };
            auto f2 = [a, b](int64_t x) -> int64_t {
                return (x % a) % b;
            };

            std::vector<int64_t> x = {
                    t.p_input.convert_to_int<int64_t>() / 2, t.p_input.convert_to_int<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                    t.p_input.convert_to_int<int64_t>() - 1};
            if (x.size() < t.num_slots)
                x = Fill<int64_t>(x, t.num_slots);

            std::vector<int64_t> coeffint1;
            std::vector<int64_t> coeffint2;
            std::vector<std::complex<double>> coeffcomp1;
            std::vector<std::complex<double>> coeffcomp2;
            bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
            if (binary_lut) {
                coeffint1 = {f1(1), f1(0) - f1(1)};
                coeffint2 = {f2(1), f2(0) - f2(1)};
            } else {
                coeffcomp1 = get_hermite_trig_coefficients(f1, t.p_input.convert_to_int(), t.order, t.scale_thi);
                coeffcomp2 = get_hermite_trig_coefficients(f2, t.p_input.convert_to_int(), t.order, t.scale_thi);
            }

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
            ContextParams<CkksRnsContext> parameters;
            parameters.set_secret_key_dist(t.skd);
            parameters.set_security_level(HEStd_NotSet);
            parameters.set_scaling_mod_size(dcrt_bits);
            set_scaling_technique_params(parameters, t.scal_tech, dcrt_bits, t.register_word_size);
            parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
            parameters.set_num_large_digits(t.dnum);
            parameters.set_batch_size(num_slots_ckks);
            parameters.set_ring_dim(t.ring_dim);
            uint32_t depth = t.levels_available_after_bootstrap + t.levels_computation;

            if (binary_lut)
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint1, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));
            else
                depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp1, t.p_input, t.order, t.skd,
                                                 first_mod_size(dcrt_bits, t.scal_tech));

            parameters.set_multiplicative_depth(depth);

            auto cc = make_crypto_context(parameters);
            cc->enable(PKE);
            cc->enable(KEYSWITCH);
            cc->enable(LEVELEDSHE);
            cc->enable(ADVANCEDSHE);
            cc->enable(FHE);

            auto key_pair = cc->key_gen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binary_lut)
                cc->eval_fbt_setup(coeffint1, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, t.levels_computation, t.order);
            else
                cc->eval_fbt_setup(coeffcomp1, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, t.levels_computation, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
            cc->eval_mult_key_gen(key_pair.secret_key);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key,
                                                        depth - (t.levels_available_before_bootstrap > 0));

            auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

            auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks,
                                                           depth - (t.levels_available_before_bootstrap > 0));

            std::vector<Ciphertext<RnsPoly>> complex_exp;
            Ciphertext<RnsPoly> ctxt_after_fbt1, ctxt_after_fbt2;

            if (binary_lut) {
                // Compute the complex exponential and its powers to reuse
                auto complex_exp_powers =
                        cc->eval_mvb_precompute(ctxt, coeffint1, t.p_input.get_msb() - 1, ep->get_modulus(), t.order);
                // Apply multiple LUTs
                ctxt_after_fbt1 = cc->eval_mvb(complex_exp_powers, coeffint1, t.p_input.get_msb() - 1, t.scale_thi,
                                            t.levels_computation, t.order);
                ctxt_after_fbt2 = cc->eval_mvb_no_decoding(complex_exp_powers, coeffint2, t.p_input.get_msb() - 1, t.order);
                ctxt_after_fbt2 = cc->eval_hom_decoding(ctxt_after_fbt2, t.scale_thi, t.levels_computation);
            } else {
                // Compute the complex exponential and its powers to reuse
                auto complex_exp_powers =
                        cc->eval_mvb_precompute(ctxt, coeffcomp1, t.p_input.get_msb() - 1, ep->get_modulus(), t.order);
                // Apply multiple LUTs
                ctxt_after_fbt1 = cc->eval_mvb(complex_exp_powers, coeffcomp1, t.p_input.get_msb() - 1, t.scale_thi,
                                            t.levels_computation, t.order);
                ctxt_after_fbt2 = cc->eval_mvb_no_decoding(complex_exp_powers, coeffcomp2, t.p_input.get_msb() - 1, t.order);
                ctxt_after_fbt2 = cc->eval_hom_decoding(ctxt_after_fbt2, t.scale_thi, t.levels_computation);
            }

            auto polys1 = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt1, t.Q);

            auto polys2 = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt2, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed1 = SchemeletRlweMp::decrypt_coeff(polys1, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks,
                                                           t.num_slots);

            auto computed2 = SchemeletRlweMp::decrypt_coeff(polys2, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks,
                                                           t.num_slots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f1(elem) % t.p_output.convert_to_int() > t.p_output.convert_to_double() / 2.) ?
                               f1(elem) % t.p_output.convert_to_int() - t.p_output.convert_to_int() :
                               f1(elem);
            });

            std::transform(exact.begin(), exact.end(), computed1.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f2(elem) % t.p_output.convert_to_int() > t.p_output.convert_to_double() / 2.) ?
                               f2(elem) % t.p_output.convert_to_int() - t.p_output.convert_to_int() :
                               f2(elem);
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            check_equality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->clear_static_maps_and_vectors();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    // Evaluates the same LUT with FIXEDMANUAL and with t.scal_tech (a FLEXIBLE* technique) and checks that
    // the FLEXIBLE* technique yields smaller noise in the output RLWE ciphertext. The FLEXIBLE* techniques
    // track the exact level-specific scaling factors, so the scaling-factor drift of the FIXED* techniques
    // is absent; for the same parameters this shows up as smaller output noise (equivalently, correctness
    // can be achieved with a smaller CKKS scaling factor).
    void unit_test_noise(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            auto run_once = [&t](ScalingTechnique scal_tech, int64_t& max_err) -> double {
                bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
                auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

                auto a = t.p_input.convert_to_int<int64_t>();
                auto b = t.p_output.convert_to_int<int64_t>();
                auto f = [a, b](int64_t x) -> int64_t {
                    return (x % a - a / 2) % b;
                };

                std::vector<int64_t> x = {(t.p_input.convert_to_int<int64_t>() / 2),
                                          (t.p_input.convert_to_int<int64_t>() / 2) + 1,
                                          0,
                                          3,
                                          16,
                                          33,
                                          64,
                                          (t.p_input.convert_to_int<int64_t>() - 1)};
                if (x.size() < t.num_slots)
                    x = Fill<int64_t>(x, t.num_slots);

                std::vector<int64_t> coeffint;
                std::vector<std::complex<double>> coeffcomp;
                bool binary_lut = (t.p_input.convert_to_int() == 2) && (t.order == 1);
                if (binary_lut)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                    coeffint = {f(1), f(0) - f(1)};
                else  // divided by 2
                    coeffcomp = get_hermite_trig_coefficients(f, t.p_input.convert_to_int(), t.order, t.scale_thi);

                const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
                ContextParams<CkksRnsContext> parameters;
                parameters.set_secret_key_dist(t.skd);
                parameters.set_security_level(HEStd_NotSet);
                parameters.set_scaling_mod_size(dcrt_bits);
                set_scaling_technique_params(parameters, scal_tech, dcrt_bits, t.register_word_size);
                parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
                parameters.set_num_large_digits(t.dnum);
                parameters.set_batch_size(num_slots_ckks);
                parameters.set_ring_dim(t.ring_dim);
                uint32_t depth = t.levels_available_after_bootstrap;

                if (binary_lut)
                    depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd,
                                                     first_mod_size(dcrt_bits, t.scal_tech));
                else
                    depth += CkksRnsFhe::get_fbt_depth(t.lvlb, coeffcomp, t.p_input, t.order, t.skd,
                                                     first_mod_size(dcrt_bits, t.scal_tech));

                parameters.set_multiplicative_depth(depth);

                auto cc = make_crypto_context(parameters);
                cc->enable(PKE);
                cc->enable(KEYSWITCH);
                cc->enable(LEVELEDSHE);
                cc->enable(ADVANCEDSHE);
                cc->enable(FHE);

                auto key_pair = cc->key_gen();

                if (binary_lut)
                    cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                     t.lvlb, t.levels_available_after_bootstrap, 0, t.order);
                else
                    cc->eval_fbt_setup(coeffcomp, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                     t.lvlb, t.levels_available_after_bootstrap, 0, t.order);

                cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
                cc->eval_mult_key_gen(key_pair.secret_key);

                auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth);

                auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);

                SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);

                auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks,
                                                               depth);

                Ciphertext<RnsPoly> ctxt_after_fbt;
                if (binary_lut)
                    ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0,
                                               t.order);
                else
                    ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, t.p_input.get_msb() - 1, ep->get_modulus(), t.scale_thi, 0,
                                               t.order);

                auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, t.Q);

                auto computed = SchemeletRlweMp::decrypt_coeff(polys, t.Q, t.p_output, key_pair.secret_key, ep,
                                                              num_slots_ckks, t.num_slots);

                auto exact(x);
                std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                    return (f(elem) > t.p_output.convert_to_double() / 2.) ? f(elem) - t.p_output.convert_to_int<int64_t>() :
                                                                          f(elem);
                });

                std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
                std::transform(exact.begin(), exact.end(), exact.begin(),
                               [&](int64_t elem) { return (std::abs(elem)) % (t.p_output.convert_to_int()); });
                max_err = *std::max_element(exact.begin(), exact.end());

                double noise_bits =
                        measure_noise_bits(polys, t.Q, t.p_output, key_pair.secret_key, ep, num_slots_ckks, t.num_slots);

                cc->clear_static_maps_and_vectors();
                return noise_bits;
            };

            // FBT_NOISE checks that t.scal_tech yields less noise than FIXEDMANUAL; FBT_NOISE_VS_FLEXIBLE checks
            // that t.scal_tech (composite scaling) yields roughly the same noise as FLEXIBLEAUTO. Both runs use
            // the same modulus sizes (see first_mod_size).
            const bool vs_flexible = (t.test_case_type == FBT_NOISE_VS_FLEXIBLE);
            const ScalingTechnique ref_st = vs_flexible ? FLEXIBLEAUTO : FIXEDMANUAL;
            int64_t err_ref = -1;
            int64_t err_flex = -1;
            double noise_ref = run_once(ref_st, err_ref);
            double noise_flex = run_once(t.scal_tech, err_flex);
            if (vs_flexible) {
                // The noise of a single run occasionally lands well below the typical value (the approximation
                // error depends on the key-dependent mod-raise overflows), so the comparison uses the largest
                // noise over several runs; row 1023 needs seven (it is bimodal, modes ~3 bits apart).
                for (uint32_t run_fn = 1; run_fn < 7; ++run_fn) {
                    int64_t err_value = -1;
                    noise_ref = std::max(noise_ref, run_once(ref_st, err_value));
                    err_ref = std::max(err_ref, err_value);
                    noise_flex = std::max(noise_flex, run_once(t.scal_tech, err_value));
                    err_flex = std::max(err_flex, err_value);
                }
            }

            check_equality(err_ref, static_cast<int64_t>(0), 0.0001,
                          failmsg + " " + scal_tech_name(ref_st) + " LUT evaluation fails");
            check_equality(err_flex, static_cast<int64_t>(0), 0.0001,
                          failmsg + " " + scal_tech_name(t.scal_tech) + " LUT evaluation fails");
            if (vs_flexible) {
                // roughly the same noise: within 3 bits of FLEXIBLEAUTO
                EXPECT_LE(noise_flex, noise_ref + 3.0) << failmsg << " " << scal_tech_name(t.scal_tech)
                                                     << " noise exceeds FLEXIBLEAUTO by more than 3 bits (" << noise_flex
                                                     << " vs " << noise_ref << " bits)";
            } else {
                EXPECT_LT(noise_flex, noise_ref) << failmsg << " " << scal_tech_name(t.scal_tech)
                                               << " did not yield smaller noise than FIXEDMANUAL (" << noise_flex
                                               << " vs " << noise_ref << " bits)";
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Evaluates two LUTs on the same precomputed powers, in the order f1, f2, f1, and checks every result, so
    // that the later evaluations detect any in-place corruption of the shared precomputation by the earlier
    // ones. The binary rows (p_input = 2 at order 1) take the special-cased degree-1 path, with the
    // coefficients {1, 1} for f1 and {1, -1} for f2 covering its two branches. The p_input = 4 rows have Hermite
    // trigonometric coefficients of degree 3, which are evaluated straight from the shared powers rather than
    // by Paterson-Stockmeyer (degree 5 and above).
    void unit_test_mvb_reuse(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();
            auto f1 = [a, b](int64_t x) -> int64_t {
                return (a - x % a) % b;
            };
            auto f2 = [a, b](int64_t x) -> int64_t {
                return (x % a) % b;
            };

            std::vector<int64_t> x(t.num_slots);
            for (size_t i = 0; i < x.size(); ++i)
                x[i] = static_cast<int64_t>(3 * i + 1) % a;

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;

            // coefficients1 (of f1) fix the depth and the precomputation; coefficients2 belong to f2
            auto run_fn = [&](const auto& coefficients1, const auto& coefficients2) {
                ContextParams<CkksRnsContext> parameters;
                parameters.set_secret_key_dist(t.skd);
                parameters.set_security_level(HEStd_NotSet);
                parameters.set_scaling_mod_size(dcrt_bits);
                set_scaling_technique_params(parameters, t.scal_tech, dcrt_bits, t.register_word_size);
                parameters.set_first_mod_size(first_mod_size(dcrt_bits, t.scal_tech));
                parameters.set_num_large_digits(t.dnum);
                parameters.set_batch_size(num_slots_ckks);
                parameters.set_ring_dim(t.ring_dim);
                uint32_t depth = t.levels_available_after_bootstrap +
                                 CkksRnsFhe::get_fbt_depth(t.lvlb, coefficients1, t.p_input, t.order, t.skd,
                                                         first_mod_size(dcrt_bits, t.scal_tech));
                parameters.set_multiplicative_depth(depth);

                auto cc = make_crypto_context(parameters);
                cc->enable(PKE);
                cc->enable(KEYSWITCH);
                cc->enable(LEVELEDSHE);
                cc->enable(ADVANCEDSHE);
                cc->enable(FHE);

                auto key_pair = cc->key_gen();

                cc->eval_fbt_setup(coefficients1, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0},
                                 t.lvlb, t.levels_available_after_bootstrap, 0, t.order);
                cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
                cc->eval_mult_key_gen(key_pair.secret_key);

                auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth);
                auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, t.qbfv_init, t.p_input, key_pair.secret_key, ep);
                SchemeletRlweMp::mod_switch(ctxt_bfv, t.Q, t.qbfv_init);
                auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, t.bigq, num_slots_ckks,
                                                               depth);

                auto powers =
                        cc->eval_mvb_precompute(ctxt, coefficients1, t.p_input.get_msb() - 1, ep->get_modulus(), t.order);

                auto eval_and_check = [&](const auto& coefficients, const auto& f, const std::string& label) {
                    auto ctxt_after_fbt =
                            cc->eval_mvb(powers, coefficients, t.p_input.get_msb() - 1, t.scale_thi, 0, t.order);
                    auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, t.Q);
                    auto computed = SchemeletRlweMp::decrypt_coeff(polys, t.Q, t.p_output, key_pair.secret_key, ep,
                                                                  num_slots_ckks, t.num_slots);

                    std::vector<int64_t> err_value(x.size());
                    std::transform(x.begin(), x.end(), computed.begin(), err_value.begin(),
                                   [&](int64_t in, int64_t out) { return std::abs(f(in) - out) % b; });
                    check_equality(*std::max_element(err_value.begin(), err_value.end()), static_cast<int64_t>(0), 0.0001,
                                  failmsg + " " + label + " on the reused precomputation fails");
                };

                eval_and_check(coefficients1, f1, "LUT evaluation 1 (first function)");
                eval_and_check(coefficients2, f2, "LUT evaluation 2 (second function)");
                eval_and_check(coefficients1, f1, "LUT evaluation 3 (first function again)");

                cc->clear_static_maps_and_vectors();
            };

            if ((a == 2) && (t.order == 1)) {
                run_fn(std::vector<int64_t>{f1(1), f1(0) - f1(1)}, std::vector<int64_t>{f2(1), f2(0) - f2(1)});
            } else {
                run_fn(get_hermite_trig_coefficients(f1, t.p_input.convert_to_int(), t.order, t.scale_thi),
                    get_hermite_trig_coefficients(f2, t.p_input.convert_to_int(), t.order, t.scale_thi));
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Checks that invalid usage is rejected with an exception instead of silently corrupting results:
    // 1) more levels requested after bootstrapping than the modulus chain has, 2) an oversized
    // level_to_reduce in eval_hom_decoding under FLEXIBLE*, and 3) a FLEXIBLEAUTOEXT input that still
    // includes the extra modulus.
    void unit_test_invalid_args(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            bool flag_sp = (t.num_slots <= t.ring_dim / 2);  // sparse packing
            auto num_slots_ckks = flag_sp ? t.num_slots : t.num_slots / 2;

            auto a = t.p_input.convert_to_int<int64_t>();
            auto b = t.p_output.convert_to_int<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };
            std::vector<int64_t> coeffint = {f(1), f(0) - f(1)};

            const uint32_t dcrt_bits = t.bigq.get_msb() - 1;
            uint32_t depth = t.levels_available_after_bootstrap +
                             CkksRnsFhe::get_fbt_depth(t.lvlb, coeffint, t.p_input, t.order, t.skd,
                                                     first_mod_size(dcrt_bits, t.scal_tech));

            auto make_params = [&](ScalingTechnique st) {
                ContextParams<CkksRnsContext> parameters;
                parameters.set_secret_key_dist(t.skd);
                parameters.set_security_level(HEStd_NotSet);
                parameters.set_scaling_mod_size(dcrt_bits);
                set_scaling_technique_params(parameters, st, dcrt_bits, t.register_word_size);
                parameters.set_first_mod_size(first_mod_size(dcrt_bits, st));
                parameters.set_num_large_digits(t.dnum);
                parameters.set_batch_size(num_slots_ckks);
                parameters.set_ring_dim(t.ring_dim);
                parameters.set_multiplicative_depth(depth);
                return parameters;
            };
            auto enable_all = [](CryptoContext<RnsPoly>& cc) {
                cc->enable(PKE);
                cc->enable(KEYSWITCH);
                cc->enable(LEVELEDSHE);
                cc->enable(ADVANCEDSHE);
                cc->enable(FHE);
            };

            {
                // an oversized level_to_reduce under FLEXIBLE* is rejected instead of silently zeroing the result
                auto parameters = make_params(FLEXIBLEAUTO);
                auto cc = make_crypto_context(parameters);
                enable_all(cc);
                auto key_pair = cc->key_gen();

                // more levels after bootstrapping than the chain provides is rejected at setup, rather
                // than reading past the modulus vector and wrapping the level arithmetic
                const std::vector<uint32_t> dim1{0, 0};
                EXPECT_THROW(cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key,
                                              dim1, t.lvlb, depth + 1, 0, t.order),
                             CipherException)
                        << failmsg << " oversized lvlsAfterBoot not rejected";

                cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                                 t.levels_available_after_bootstrap, 0, t.order);
                std::vector<double> y(num_slots_ckks, 0.5);
                auto ctxt = cc->encrypt(key_pair.public_key, cc->make_ckks_packed_plaintext(y));
                EXPECT_THROW(cc->eval_hom_decoding(ctxt, 1, depth), CipherException)
                        << failmsg << " oversized levelToReduce not rejected";
                cc->clear_static_maps_and_vectors();
            }

            {
                // a FLEXIBLEAUTOEXT input that includes the extra modulus is rejected
                auto parameters = make_params(FLEXIBLEAUTOEXT);
                auto cc = make_crypto_context(parameters);
                enable_all(cc);
                auto key_pair = cc->key_gen();
                cc->eval_fbt_setup(coeffint, num_slots_ckks, t.p_input, t.p_output, t.bigq, key_pair.public_key, {0, 0}, t.lvlb,
                                 t.levels_available_after_bootstrap, 0, t.order);
                cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
                cc->eval_mult_key_gen(key_pair.secret_key);
                std::vector<double> y(num_slots_ckks, 0.5);
                // a level-0 ciphertext still includes the FLEXIBLEAUTOEXT extra modulus
                auto ctxt = cc->encrypt(key_pair.public_key, cc->make_ckks_packed_plaintext(y));
                EXPECT_THROW(cc->eval_fbt(ctxt, coeffint, t.p_input.get_msb() - 1, t.bigq, t.scale_thi, 0, t.order),
                             CipherException)
                        << failmsg << " FLEXIBLEAUTOEXT level-0 input not rejected";
                cc->clear_static_maps_and_vectors();
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

// ===========================================================================================================
TEST_P(UTCKKSRNS_FBT, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case FBT_ARBLUT:
            unit_test_arb_lut(test, test.build_test_name());
            break;
        case FBT_SIGNDIGIT:
            unit_test_sign_digit(test, test.build_test_name());
            break;
        case FBT_CONSECLEV:
            unit_test_consec_lev_lut(test, test.build_test_name());
            break;
        case FBT_MVB:
            unit_test_mvb(test, test.build_test_name());
            break;
        case FBT_NOISE:
        case FBT_NOISE_VS_FLEXIBLE:
            unit_test_noise(test, test.build_test_name());
            break;
        case FBT_MVB_REUSE:
            unit_test_mvb_reuse(test, test.build_test_name());
            break;
        case FBT_INVALID:
            unit_test_invalid_args(test, test.build_test_name());
            break;
        default:
            break;
    }
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(UTCKKSRNS_FBT);  // test_cases.size() == 0 if CIPHER_NATIVE_INT == 128
INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FBT, ::testing::ValuesIn(test_cases), testName);
