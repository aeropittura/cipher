//==================================================================================
//
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
  Unit tests for pure CKKS FE functional bootstrapping
 */

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/fhe.h"

using namespace cipher;

namespace {

enum TEST_CASE_TYPE : int {
    FEFBT_ACCURACY = 0,
    FEFBT_POST_ROTATION,
    FEFBT_CS_VS_FA,
    FEFBT_COMPLEX_INPUT,
    FEFBT_MULTI_VALUE,
    FEFBT_VARIANT_MIX,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case FEFBT_ACCURACY:
            type_name_of = "FEFBT_ACCURACY";
            break;
        case FEFBT_POST_ROTATION:
            type_name_of = "FEFBT_POST_ROTATION";
            break;
        case FEFBT_CS_VS_FA:
            type_name_of = "FEFBT_CS_VS_FA";
            break;
        case FEFBT_COMPLEX_INPUT:
            type_name_of = "FEFBT_COMPLEX_INPUT";
            break;
        case FEFBT_MULTI_VALUE:
            type_name_of = "FEFBT_MULTI_VALUE";
            break;
        case FEFBT_VARIANT_MIX:
            type_name_of = "FEFBT_VARIANT_MIX";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}

enum FEFBT_FUNCTION : int {
    FEFBT_EXP = 0,
    FEFBT_SIGMOID,
    FEFBT_GELU_TANH,
};

static std::ostream& operator<<(std::ostream& os, const FEFBT_FUNCTION& type) {
    std::string type_name_of;
    switch (type) {
        case FEFBT_EXP:
            type_name_of = "FEFBT_EXP";
            break;
        case FEFBT_SIGMOID:
            type_name_of = "FEFBT_SIGMOID";
            break;
        case FEFBT_GELU_TANH:
            type_name_of = "FEFBT_GELU_TANH";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}

struct TEST_CASE_UTCKKSRNS_FEFBT {
    TEST_CASE_TYPE test_case_type;
    std::string description;
    TestContextParams params;
    std::vector<uint32_t> level_budget;
    std::vector<uint32_t> dim1;
    uint32_t slots;
    FEFBT_FUNCTION function_type;
    // FEFBT_CS_VS_FA only: COMPOSITESCALINGAUTO may lag FLEXIBLEAUTO by at most this many precision bits
    double gap_tol_bits = 0.0;

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }

    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "testCaseType [" << test_case_type << "], function_type [" << function_type << "], "
           << params.to_string_impl() << ", slots [" << slots << "]";
        return ss.str();
    }
};

static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_FEFBT>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_FEFBT& test) {
    return os << test.to_string_impl();
}

constexpr uint32_t MULT_DEPTH = 26;
// register word size for the COMPOSITESCALING* techniques: composite degree 2 for the 59-bit scaling factor
constexpr uint32_t REG_WORD_SIZE = 32;

#if CIPHER_NATIVE_INT != 128
constexpr uint32_t RDIM = 1 << 12;
constexpr uint32_t NUM_LRG_DIGS = 3;
constexpr uint32_t SPARSE_SLOTS = 8;
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;
// composite degree 3 for the 32-bit register word size (three ~26-bit primes per level); FE functional
// bootstrapping requires the first modulus to be exactly one bit larger than the scaling factor
constexpr uint32_t SMODSIZED3 = 78;
constexpr uint32_t FMODSIZED3 = 79;

TestContextParams make_fefbt_params(uint32_t batch_size, SecretKeyDist skd,
                                    ScalingTechnique scaling_technique = FIXEDMANUAL,
                                    uint32_t scaling_mod_size = SMODSIZE, uint32_t first_mod_size_value = FMODSIZE) {
    TestContextParams params;
    params.scheme_id_value = CKKSRNS_SCHEME;
    params.ring_dimension_value = RDIM;
    params.multiplicative_depth = MULT_DEPTH;
    params.scaling_mod_size = scaling_mod_size;
    params.batch_size = batch_size;
    params.secret_key_dist = skd;
    params.first_mod_size_value = first_mod_size_value;
    params.security_level = HEStd_NotSet;
    params.ks_tech = HYBRID;
    params.scal_tech = scaling_technique;
    params.num_large_digits = NUM_LRG_DIGS;
    params.ckks_data_type = REAL;
    if (scaling_technique == COMPOSITESCALINGAUTO || scaling_technique == COMPOSITESCALINGMANUAL) {
        params.register_word_size = REG_WORD_SIZE;
        if (scaling_technique == COMPOSITESCALINGMANUAL)
            params.composite_degree = (scaling_mod_size + REG_WORD_SIZE - 1) / REG_WORD_SIZE;
    }

    return params;
}

TEST_CASE_UTCKKSRNS_FEFBT make_fefbt_case(TEST_CASE_TYPE test_case_type, const std::string& description,
                                          uint32_t batch_size, SecretKeyDist skd, uint32_t slots,
                                          FEFBT_FUNCTION function_type, std::vector<uint32_t> level_budget = {3, 2},
                                          ScalingTechnique scaling_technique = FIXEDMANUAL,
                                          uint32_t scaling_mod_size = SMODSIZE,
                                          uint32_t first_mod_size_value = FMODSIZE) {
    TEST_CASE_UTCKKSRNS_FEFBT test_case_value;
    test_case_value.test_case_type = test_case_type;
    test_case_value.description = description;
    test_case_value.params =
            make_fefbt_params(batch_size, skd, scaling_technique, scaling_mod_size, first_mod_size_value);
    test_case_value.level_budget = std::move(level_budget);
    test_case_value.dim1 = {0, 0};
    test_case_value.slots = slots;
    test_case_value.function_type = function_type;

    return test_case_value;
}

// A CS-vs-FA precision-gap case: the same FE functional bootstrapping is run under FLEXIBLEAUTO and under
// COMPOSITESCALINGAUTO, and the CS precision must come within gap_tol_bits of the FA precision (the analog of
// the FBT_NOISE_VS_FLEXIBLE rows of UnitTestFBT and of UnitTestCKKSrnsCompositeScalingVsFlexible).
TEST_CASE_UTCKKSRNS_FEFBT make_fefbtc_svs_fa_case(const std::string& description, uint32_t slots, SecretKeyDist skd,
                                                  FEFBT_FUNCTION function_type, std::vector<uint32_t> level_budget,
                                                  double gap_tol_bits) {
    TEST_CASE_UTCKKSRNS_FEFBT test_case_value =
            make_fefbt_case(FEFBT_CS_VS_FA, description, slots, skd, slots, function_type, std::move(level_budget));
    test_case_value.gap_tol_bits = gap_tol_bits;
    return test_case_value;
}

// A CkksDataType COMPLEX case: the input carries nonzero imaginary parts, which FE functional
// bootstrapping discards (its output is twice the real part of a Fourier series, hence always real).
TEST_CASE_UTCKKSRNS_FEFBT make_fefbt_complex_input_case(const std::string& description, uint32_t slots,
                                                        FEFBT_FUNCTION function_type,
                                                        std::vector<uint32_t> level_budget) {
    TEST_CASE_UTCKKSRNS_FEFBT test_case_value = make_fefbt_case(FEFBT_COMPLEX_INPUT, description, slots, SPARSE_TERNARY,
                                                                slots, function_type, std::move(level_budget));
    test_case_value.params.ckks_data_type = COMPLEX;
    return test_case_value;
}

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_FEFBT> test_cases = {
    make_fefbt_case(FEFBT_ACCURACY,      "01", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID),
    make_fefbt_case(FEFBT_ACCURACY,      "02", RDIM / 2,    SPARSE_ENCAPSULATED, RDIM / 2,   FEFBT_SIGMOID),
    make_fefbt_case(FEFBT_ACCURACY,      "03", RDIM / 2,    UNIFORM_TERNARY,     RDIM / 2,   FEFBT_SIGMOID),
    make_fefbt_case(FEFBT_ACCURACY,      "04", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID),
    make_fefbt_case(FEFBT_POST_ROTATION, "05", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID),
    make_fefbt_case(FEFBT_ACCURACY,      "06", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_EXP),
    make_fefbt_case(FEFBT_ACCURACY,      "07", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_GELU_TANH),
    make_fefbt_case(FEFBT_ACCURACY,      "08", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FIXEDMANUAL),
    make_fefbt_case(FEFBT_ACCURACY,      "09", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FLEXIBLEAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "10", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FLEXIBLEAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "11", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FIXEDAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "12", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FIXEDAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "13", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FLEXIBLEAUTOEXT),
    make_fefbt_case(FEFBT_ACCURACY,      "14", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FLEXIBLEAUTOEXT),
    make_fefbt_case(FEFBT_ACCURACY,      "15", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, COMPOSITESCALINGAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "16", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, COMPOSITESCALINGAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "17", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_EXP,
                  {3, 2}, COMPOSITESCALINGMANUAL),
    make_fefbt_case(FEFBT_ACCURACY,      "18", RDIM / 2,    UNIFORM_TERNARY,     RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, COMPOSITESCALINGAUTO),
    make_fefbt_case(FEFBT_ACCURACY,      "19", RDIM / 2,    SPARSE_ENCAPSULATED, RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, COMPOSITESCALINGAUTO),
    // CS-vs-FA precision-gap cases. Each gap (fa_bits - cs_bits) is a random variable; measured over 10 runs
    // per case on x86_64 / GCC, NATIVE_SIZE = 64:
    //   20 full packing, SPARSE_TERNARY, {3,2}       gap  0.010 +/- 0.008  (FA 31.6, CS 31.6)
    //   21 8 slots (LT), SPARSE_TERNARY, {1,1}       gap  0.001 +/- 0.007  (FA 31.9, CS 31.9)
    //   22 full packing, UNIFORM_TERNARY, {3,2}      gap -0.219 +/- 0.165  (FA 29.1, CS 29.4)
    //   23 full packing, SPARSE_ENCAPSULATED, {3,2}  gap -0.102 +/- 0.017  (FA 31.5, CS 31.6)
    // The shared 1.0-bit tolerance sits more than 5 standard deviations above every measured mean, so a
    // false failure is negligible while a real regression of even one bit is caught. The SPARSE_ENCAPSULATED case
    // keeps the K = 16 exponential table under CS (its 60-bit first modulus keeps the Hamming weight of the sparse
    // secret at 32); the K = 28 table of the denser sparse secret is covered by case 30.
    make_fefbtc_svs_fa_case("20", RDIM / 2,     SPARSE_TERNARY,      FEFBT_SIGMOID, {3, 2}, 1.0),
    make_fefbtc_svs_fa_case("21", SPARSE_SLOTS, SPARSE_TERNARY,      FEFBT_SIGMOID, {1, 1}, 1.0),
    make_fefbtc_svs_fa_case("22", RDIM / 2,     UNIFORM_TERNARY,     FEFBT_SIGMOID, {3, 2}, 1.0),
    make_fefbtc_svs_fa_case("23", RDIM / 2,     SPARSE_ENCAPSULATED, FEFBT_SIGMOID, {3, 2}, 1.0),
    make_fefbt_complex_input_case("24", RDIM / 2,     FEFBT_SIGMOID, {3, 2}),
    make_fefbt_complex_input_case("25", SPARSE_SLOTS, FEFBT_SIGMOID, {1, 1}),
    // function_type names the series the powers are precomputed for; every function is then evaluated
    // against those powers
    make_fefbt_case(FEFBT_MULTI_VALUE, "26", RDIM / 2,     SPARSE_TERNARY, RDIM / 2,     FEFBT_GELU_TANH),
    make_fefbt_case(FEFBT_MULTI_VALUE, "27", SPARSE_SLOTS, SPARSE_TERNARY, SPARSE_SLOTS, FEFBT_GELU_TANH,
                  {1, 1}, FLEXIBLEAUTO),
    // composite degree 3 with UNIFORM_TERNARY: the K = 696 overflow bound of the lower composite degrees is
    // used for every composite degree
    make_fefbt_case(FEFBT_ACCURACY,      "28", RDIM / 2,    UNIFORM_TERNARY,     RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, COMPOSITESCALINGAUTO, SMODSIZED3, FMODSIZED3),
    make_fefbt_case(FEFBT_ACCURACY,      "29", SPARSE_SLOTS, UNIFORM_TERNARY,    SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, COMPOSITESCALINGMANUAL, SMODSIZED3, FMODSIZED3),
    // SPARSE_ENCAPSULATED with a first modulus above 60 bits: the sparse secret has Hamming weight 64 and the K = 28
    // exponential table of SPARSE_TERNARY is used
    make_fefbt_case(FEFBT_ACCURACY,      "30", RDIM / 2,    SPARSE_ENCAPSULATED, RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, COMPOSITESCALINGAUTO, SMODSIZED3, FMODSIZED3),
    // eval_bootstrap on a precomputation generated by eval_fe_func_bootstrap_setup must throw: the two variants
    // fold different uniform-secret overflow bounds K into the CoeffsToSlots matrix (K_UNIFORM vs
    // K_UNIFORM_FEFBT), so sharing it would silently lose precision
    make_fefbt_case(FEFBT_VARIANT_MIX,   "31", SPARSE_SLOTS, UNIFORM_TERNARY,    SPARSE_SLOTS, FEFBT_SIGMOID, {1, 1}),
};
// clang-format on
#else
static std::vector<TEST_CASE_UTCKKSRNS_FEFBT> test_cases = {};
#endif

static const std::vector<std::complex<double>> coeff_exp_2_double_29{
        std::complex<double>(3.222093706013e+00, 0.000000000000e+00),
        std::complex<double>(-3.847497325992e+00, -3.036911315182e+00),
        std::complex<double>(1.613269565467e+00, 2.561562635536e+00),
        std::complex<double>(-7.142688329459e-01, -1.718044084361e+00),
        std::complex<double>(3.343375256712e-01, 1.087677253934e+00),
        std::complex<double>(-1.590083748525e-01, -6.591856314553e-01),
        std::complex<double>(7.444125399842e-02, 3.797240558554e-01),
        std::complex<double>(-3.347789249240e-02, -2.057416664390e-01),
        std::complex<double>(1.415639337190e-02, 1.036151378646e-01),
        std::complex<double>(-5.504078824289e-03, -4.782261609566e-02),
        std::complex<double>(1.912943397918e-03, 1.985252654576e-02),
        std::complex<double>(-5.690043709362e-04, -7.207032810727e-03),
        std::complex<double>(1.328669037822e-04, 2.177453328757e-03),
        std::complex<double>(-1.854630094550e-05, -4.890711403220e-04),
        std::complex<double>(-1.453596732859e-06, 5.053417952833e-05),
        std::complex<double>(1.572743922262e-06, 1.548627313317e-05),
        std::complex<double>(-2.838788709181e-07, -8.312159353832e-06),
        std::complex<double>(-7.562004956940e-08, 8.274522508133e-07),
        std::complex<double>(4.633880680387e-08, 6.598799631857e-07),
        std::complex<double>(-5.869467412101e-10, -2.528773346321e-07),
        std::complex<double>(-6.055031566421e-09, -3.204665662698e-08),
        std::complex<double>(1.190783888161e-09, 4.385916878681e-08),
        std::complex<double>(7.747582545133e-10, -3.358504294115e-09),
        std::complex<double>(-3.348892690935e-10, -7.088429287982e-09),
        std::complex<double>(-9.585399054352e-11, 1.863929871559e-09),
        std::complex<double>(8.204146390023e-11, 1.136804343802e-09),
        std::complex<double>(9.573941899682e-12, -5.803840255614e-10),
        std::complex<double>(-2.013818972690e-11, -1.764939479287e-10),
        std::complex<double>(1.533040187851e-13, 1.657178907988e-10),
        std::complex<double>(5.134323521894e-12, 2.323787581630e-11)};

static const std::vector<std::complex<double>> coeff_sigmoid_8_double_34{
        std::complex<double>(2.500000000000e-01, 0.000000000000e+00),
        std::complex<double>(1.276756478319e-15, -2.986114677117e-01),
        std::complex<double>(-2.711798613355e-15, -1.305833657358e-03),
        std::complex<double>(2.012279232133e-15, -6.069910606535e-02),
        std::complex<double>(-3.874233833051e-17, -3.496972005070e-03),
        std::complex<double>(-5.065392549852e-16, -1.436915534313e-02),
        std::complex<double>(-4.025501720156e-16, -3.090757902275e-03),
        std::complex<double>(6.661338147751e-16, -3.011048528323e-03),
        std::complex<double>(9.549219054383e-17, -1.395169741000e-03),
        std::complex<double>(-4.406197628981e-16, -7.358936474771e-04),
        std::complex<double>(-2.137022113088e-16, -4.185575122752e-04),
        std::complex<double>(4.614364446098e-16, -2.239585471946e-04),
        std::complex<double>(4.897883314203e-19, -1.182545527493e-04),
        std::complex<double>(-4.024558464266e-16, -6.447113701542e-05),
        std::complex<double>(-1.695114860110e-16, -3.521198006050e-05),
        std::complex<double>(3.903127820948e-16, -1.881494613389e-05),
        std::complex<double>(1.909467050622e-16, -1.006822281208e-05),
        std::complex<double>(-9.540979117872e-17, -5.490602888772e-06),
        std::complex<double>(-6.585471100731e-17, -2.983401096265e-06),
        std::complex<double>(1.040834085586e-16, -1.590510122180e-06),
        std::complex<double>(1.641151407480e-16, -8.526983863427e-07),
        std::complex<double>(-6.938893903907e-17, -4.673955051855e-07),
        std::complex<double>(-1.931861246494e-16, -2.539297722240e-07),
        std::complex<double>(3.035766082959e-16, -1.341034123884e-07),
        std::complex<double>(7.532874064103e-17, -7.180768169489e-08),
        std::complex<double>(-1.049507702966e-16, -4.002071006315e-08),
        std::complex<double>(-8.495889538759e-17, -2.179193493192e-08),
        std::complex<double>(1.587271980519e-16, -1.117364778916e-08),
        std::complex<double>(5.298577332100e-17, -5.959189144748e-09),
        std::complex<double>(-3.009745230820e-16, -3.501207830137e-09),
        std::complex<double>(-9.186228167035e-17, -1.915294608676e-09),
        std::complex<double>(2.055647319033e-16, -8.879601871852e-10),
        std::complex<double>(4.123369939761e-16, -4.698662414010e-10),
        std::complex<double>(-3.139849491518e-16, -3.309931637583e-10),
        std::complex<double>(5.506066522859e-17, -1.816820400721e-10)};

static const std::vector<std::complex<double>> coeff_gelu_8_double_44{
        std::complex<double>(1.970461314322e+00, 0.000000000000e+00),
        std::complex<double>(-1.593875111273e+00, -2.423646025475e+00),
        std::complex<double>(-5.332570094236e-02, 1.043627310063e+00),
        std::complex<double>(-1.570391974449e-01, -5.402873054677e-01),
        std::complex<double>(-3.940694771457e-02, 2.819289867863e-01),
        std::complex<double>(-4.716127625363e-02, -1.391268773786e-01),
        std::complex<double>(-2.418730432251e-02, 6.233923043025e-02),
        std::complex<double>(-1.941167643365e-02, -2.432937320475e-02),
        std::complex<double>(-1.260556521786e-02, 7.763676253796e-03),
        std::complex<double>(-8.664960605021e-03, -1.754420766855e-03),
        std::complex<double>(-5.704614002479e-03, 1.292565051534e-04),
        std::complex<double>(-3.651093482904e-03, 8.792842531399e-05),
        std::complex<double>(-2.270560959509e-03, -3.329062052015e-05),
        std::complex<double>(-1.367226398367e-03, -2.302378982580e-06),
        std::complex<double>(-7.979823621962e-04, 4.854603433774e-06),
        std::complex<double>(-4.528446723700e-04, -5.500080713671e-07),
        std::complex<double>(-2.508556888546e-04, -7.491453056646e-07),
        std::complex<double>(-1.363438350097e-04, 2.239517241233e-07),
        std::complex<double>(-7.312414261638e-05, 1.280298946860e-07),
        std::complex<double>(-3.885704183314e-05, -6.935818435338e-08),
        std::complex<double>(-2.045210744808e-05, -2.372215028579e-08),
        std::complex<double>(-1.059289000752e-05, 2.148573735963e-08),
        std::complex<double>(-5.323541994507e-06, 4.532466957308e-09),
        std::complex<double>(-2.534606159357e-06, -7.005649868379e-09),
        std::complex<double>(-1.095525020071e-06, -8.007947707722e-10),
        std::complex<double>(-3.890401084408e-07, 2.430954434496e-09),
        std::complex<double>(-7.123273537061e-08, 8.161443049159e-11),
        std::complex<double>(5.044242802621e-08, -8.975149646921e-10),
        std::complex<double>(8.120772961289e-08, 3.455961905541e-11),
        std::complex<double>(7.542928368715e-08, 3.512492108152e-10),
        std::complex<double>(5.884712616061e-08, -3.699939660207e-11),
        std::complex<double>(4.212943410103e-08, -1.450199807245e-10),
        std::complex<double>(2.870135674255e-08, 2.446543662105e-11),
        std::complex<double>(1.893829504329e-08, 6.286847323116e-11),
        std::complex<double>(1.220565836477e-08, -1.443831859627e-11),
        std::complex<double>(7.712072154498e-09, -2.849185102259e-11),
        std::complex<double>(4.784403550098e-09, 8.229923686986e-12),
        std::complex<double>(2.915358732203e-09, 1.344066297062e-11),
        std::complex<double>(1.744138401955e-09, -5.307266236734e-12),
        std::complex<double>(1.034329697769e-09, -6.648169766598e-12),
        std::complex<double>(6.098917724102e-10, 3.421664931631e-12),
        std::complex<double>(3.589237189208e-10, 2.944192267787e-12),
        std::complex<double>(2.213863333275e-10, -2.779015756058e-12),
        std::complex<double>(1.478126284614e-10, -1.420742295235e-12),
        std::complex<double>(1.014093012815e-10, 4.286355138519e-13)};

// each level consists of composite_degree towers, so the encoding level scales accordingly
static uint32_t fefbt_encode_level(const CryptoContext<RnsPoly>& cc, const TEST_CASE_UTCKKSRNS_FEFBT& test_data) {
    uint32_t composite_degree =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters())->get_composite_degree();
    return composite_degree * (MULT_DEPTH - (test_data.level_budget[1] + 1));
}

class UTCKKSRNS_FEFBT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_FEFBT> {
    using Element = RnsPoly;

    static constexpr double eps = 0.0001;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    const std::vector<std::complex<double>>& get_coefficients(FEFBT_FUNCTION function_type) const {
        switch (function_type) {
            case FEFBT_EXP:
                return coeff_exp_2_double_29;
            case FEFBT_SIGMOID:
                return coeff_sigmoid_8_double_34;
            case FEFBT_GELU_TANH:
                return coeff_gelu_8_double_44;
            default:
                CIPHER_THROW("Unsupported FEFBT function type");
        }
    }

    double get_radius(FEFBT_FUNCTION function_type) const {
        switch (function_type) {
            case FEFBT_EXP:
                return 2.0;
            case FEFBT_SIGMOID:
            case FEFBT_GELU_TANH:
                return 8.0;
            default:
                CIPHER_THROW("Unsupported FEFBT function type");
        }
    }

    std::string get_function_name(FEFBT_FUNCTION function_type) const {
        switch (function_type) {
            case FEFBT_EXP:
                return "exp[-2,2]";
            case FEFBT_SIGMOID:
                return "sigmoid[-8,8]";
            case FEFBT_GELU_TANH:
                return "gelu_tanh[-8,8]";
            default:
                return "unknown";
        }
    }

    double evaluate_target(FEFBT_FUNCTION function_type, double x) const {
        constexpr double PI = 3.14159265358979323846;

        switch (function_type) {
            case FEFBT_EXP:
                return std::exp(x);
            case FEFBT_SIGMOID:
                return 1.0 / (1.0 + std::exp(-x));
            case FEFBT_GELU_TANH:
                return 0.5 * x * (1.0 + std::tanh(std::sqrt(2.0 / PI) * (x + 0.044715 * std::pow(x, 3))));
            default:
                CIPHER_THROW("Unsupported FEFBT function type");
        }
    }

    std::vector<double> build_normalized_input(uint32_t slots) const {
        std::vector<double> input(slots);
        constexpr double left = -0.5;
        constexpr double right = 0.5;

        for (uint32_t i = 0; i < slots; ++i) {
            input[i] = left + static_cast<double>(i) * (right - left) / static_cast<double>(slots);
        }

        return input;
    }

    std::vector<double> build_expected_output(FEFBT_FUNCTION function_type,
                                              const std::vector<double>& normalized_input) const {
        std::vector<double> expected(normalized_input.size());
        const double radius = get_radius(function_type);

        for (size_t i = 0; i < normalized_input.size(); ++i) {
            expected[i] = evaluate_target(function_type, 2.0 * radius * normalized_input[i]);
        }

        return expected;
    }

    void unit_test_fefbt(const TEST_CASE_UTCKKSRNS_FEFBT& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto input = build_normalized_input(test_data.slots);
            auto expected = build_expected_output(test_data.function_type, input);
            Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr,
                                                                 test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
            auto result_ct = cc->eval_fe_func_bootstrap(ciphertext, get_coefficients(test_data.function_type));

            Plaintext result;
            cc->decrypt(key_pair.secret_key, result_ct, &result);
            result->set_length(expected.size());

            check_equality(result->get_real_packed_value(), expected, eps,
                           failmsg + " FE functional bootstrapping failed for " +
                                   get_function_name(test_data.function_type) + ".");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Runs the FE functional bootstrapping of test_data under the given scaling technique and returns the
    // achieved precision in bits (-log2 of the maximum slot error). Releases its own context before
    // returning so a CS-vs-FA test never holds two bootstrapping key sets at once.
    double fefbt_precision_bits(const TEST_CASE_UTCKKSRNS_FEFBT& test_data, ScalingTechnique scaling_technique) {
        auto params = test_data.params;
        params.scal_tech = scaling_technique;
        if (scaling_technique == COMPOSITESCALINGAUTO)
            params.register_word_size = REG_WORD_SIZE;

        CryptoContext<Element> cc(unit_test_generate_context(params));

        cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

        auto key_pair = cc->key_gen();
        cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
        cc->eval_mult_key_gen(key_pair.secret_key);

        auto input = build_normalized_input(test_data.slots);
        auto expected = build_expected_output(test_data.function_type, input);
        Plaintext plaintext =
                cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr, test_data.slots);
        auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
        auto result_ct = cc->eval_fe_func_bootstrap(ciphertext, get_coefficients(test_data.function_type));

        Plaintext result;
        cc->decrypt(key_pair.secret_key, result_ct, &result);
        result->set_length(expected.size());
        auto values = result->get_real_packed_value();

        double max_err = 0.0;
        for (size_t i = 0; i < expected.size(); ++i)
            max_err = std::max(max_err, std::abs(values[i] - expected[i]));
        ContextFactory<RnsPoly>::release_all_contexts();
        // a tiny floor avoids +inf when the error is ~0
        return -std::log2(std::max(max_err, 1e-18));
    }

    // Verifies that COMPOSITESCALINGAUTO does not lose precision relative to FLEXIBLEAUTO: the same FE
    // functional bootstrapping is run under both techniques and the CS precision must come within
    // test_data.gap_tol_bits of the FA precision (see the tolerance notes next to the test cases).
    void unit_test_fefbt_c_svs_fa(const TEST_CASE_UTCKKSRNS_FEFBT& test_data,
                                  const std::string& failmsg = std::string()) {
        try {
            double fa_bits = fefbt_precision_bits(test_data, FLEXIBLEAUTO);
            double cs_bits = fefbt_precision_bits(test_data, COMPOSITESCALINGAUTO);

            // sanity floor: the accuracy tests require eps = 1e-4, i.e. ~13.3 bits
            EXPECT_GT(cs_bits, 13.3) << failmsg << " CS FE functional bootstrapping precision unexpectedly low ("
                                     << cs_bits << " bits) for " << get_function_name(test_data.function_type) << ".";
            EXPECT_GE(cs_bits, fa_bits - test_data.gap_tol_bits)
                    << failmsg << " CS lags FA by >" << test_data.gap_tol_bits << " bits (CS=" << cs_bits
                    << ", FA=" << fa_bits << ") for " << get_function_name(test_data.function_type) << ".";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_fefbt_post_rotation(const TEST_CASE_UTCKKSRNS_FEFBT& test_data,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_at_index_key_gen(key_pair.secret_key, {6});
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto input = build_normalized_input(test_data.slots);
            auto expected = build_expected_output(test_data.function_type, input);
            Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr,
                                                                 test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
            auto result_ct = cc->eval_fe_func_bootstrap(ciphertext, get_coefficients(test_data.function_type));

            constexpr int32_t rot_index = 6;
            auto rotated_ct = cc->eval_at_index(result_ct, rot_index);
            std::rotate(expected.begin(), expected.begin() + rot_index, expected.end());

            Plaintext result;
            cc->decrypt(key_pair.secret_key, rotated_ct, &result);
            result->set_length(expected.size());

            check_equality(result->get_real_packed_value(), expected, eps,
                           failmsg + " eval_at_index after FE functional bootstrapping failed for " +
                                   get_function_name(test_data.function_type) + ".");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // One eval_fe_func_bootstrap_precompute followed by one eval_fe_func_bootstrap_with_precomp per function must
    // agree, slot for slot, with running the single-shot eval_fe_func_bootstrap for each of them. The powers
    // are precomputed for test_data.function_type, the longest series of the family, and the shorter series
    // are evaluated against those same powers.
    void unit_test_fefbt_multi_value(const TEST_CASE_UTCKKSRNS_FEFBT& test_data,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto input = build_normalized_input(test_data.slots);
            Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr,
                                                                 test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);

            auto powers = cc->eval_fe_func_bootstrap_precompute(ciphertext, get_coefficients(test_data.function_type));

            for (auto function_type : {FEFBT_GELU_TANH, FEFBT_SIGMOID, FEFBT_EXP}) {
                const auto& coefficients = get_coefficients(function_type);
                auto expected = build_expected_output(function_type, input);

                Plaintext shared;
                auto shared_ct = cc->eval_fe_func_bootstrap_with_precomp(powers, coefficients);
                cc->decrypt(key_pair.secret_key, shared_ct, &shared);
                shared->set_length(expected.size());

                check_equality(shared->get_real_packed_value(), expected, eps,
                               failmsg + " FE functional bootstrapping with precomputed powers failed for " +
                                       get_function_name(function_type) + ".");

                // and the shared-powers result must match the single-shot path, not merely the target
                Plaintext single_value;
                auto single_ct = cc->eval_fe_func_bootstrap(ciphertext, coefficients);
                cc->decrypt(key_pair.secret_key, single_ct, &single_value);
                single_value->set_length(expected.size());

                check_equality(shared->get_real_packed_value(), single_value->get_real_packed_value(), eps,
                               failmsg +
                                       " precomputed-powers and single-shot FE functional bootstrapping "
                                       "disagree for " +
                                       get_function_name(function_type) + ".");
            }

            // A series padded with trailing zeros denotes the same polynomial, so it must give the same
            // answer as the trimmed one rather than indexing past the end of the precomputed basis.
            std::vector<std::complex<double>> short_padded(10, {0.0, 0.0});
            for (uint32_t i = 0; i < 4; ++i)
                short_padded[i] = {0.1 * (i + 1), 0.0};
            const std::vector<std::complex<double>> short_trimmed(short_padded.cbegin(), short_padded.cbegin() + 4);

            Plaintext from_padded, from_trimmed;
            cc->decrypt(key_pair.secret_key, cc->eval_fe_func_bootstrap_with_precomp(powers, short_padded),
                        &from_padded);
            cc->decrypt(key_pair.secret_key, cc->eval_fe_func_bootstrap_with_precomp(powers, short_trimmed),
                        &from_trimmed);
            from_padded->set_length(test_data.slots);
            from_trimmed->set_length(test_data.slots);

            check_equality(from_padded->get_real_packed_value(), from_trimmed->get_real_packed_value(), eps,
                           failmsg + " a trailing-zero padded series did not match the trimmed one.");

            // A precomputation made for a short series leaves a correspondingly narrow power basis; a later
            // series that would read past it must be rejected rather than overrun it.
            auto narrow_powers =
                    cc->eval_fe_func_bootstrap_precompute(ciphertext, std::vector<std::complex<double>>(7, {0.1, 0.0}));
            EXPECT_THROW(cc->eval_fe_func_bootstrap_with_precomp(narrow_powers,
                                                                 std::vector<std::complex<double>>(5, {0.1, 0.0})),
                         CipherException)
                    << failmsg << " a series wider than the precomputed basis was not rejected.";

            // A series short enough to be evaluated straight from the power basis must leave the shared
            // powers intact: evaluate one, then check a real function again.
            cc->eval_fe_func_bootstrap_with_precomp(powers, std::vector<std::complex<double>>(4, {0.1, 0.0}));

            auto expected_after = build_expected_output(FEFBT_SIGMOID, input);
            Plaintext after;
            cc->decrypt(key_pair.secret_key,
                        cc->eval_fe_func_bootstrap_with_precomp(powers, get_coefficients(FEFBT_SIGMOID)), &after);
            after->set_length(expected_after.size());

            check_equality(after->get_real_packed_value(), expected_after, eps,
                           failmsg + " the shared powers did not survive evaluating a short series.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Under CkksDataType COMPLEX the CoeffsToSlots output carries the imaginary half of the message in its
    // own channel, which FE functional bootstrapping drops (its result, twice the real part of a Fourier
    // series, is real-valued). This pins that contract down: the function is applied to the real part of
    // every slot, and the imaginary part of the result is zero regardless of the input's imaginary part.
    void unit_test_fefbt_complex_input(const TEST_CASE_UTCKKSRNS_FEFBT& test_data,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto real_part = build_normalized_input(test_data.slots);
            auto expected = build_expected_output(test_data.function_type, real_part);

            // imaginary parts large enough that leaking any of them into the result would break the
            // comparison below by orders of magnitude more than eps
            std::vector<std::complex<double>> input(test_data.slots);
            for (uint32_t i = 0; i < test_data.slots; ++i)
                input[i] = {real_part[i], 0.25 * std::sin(6.0 * M_PI * i / test_data.slots)};

            Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr,
                                                                 test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);
            auto result_ct = cc->eval_fe_func_bootstrap(ciphertext, get_coefficients(test_data.function_type));

            Plaintext result;
            cc->decrypt(key_pair.secret_key, result_ct, &result);
            result->set_length(expected.size());

            const auto packed = result->get_ckks_packed_value();
            std::vector<double> actual_real(packed.size());
            std::vector<double> actual_imag(packed.size());
            for (size_t i = 0; i < packed.size(); ++i) {
                actual_real[i] = packed[i].real();
                actual_imag[i] = packed[i].imag();
            }

            check_equality(actual_real, expected, eps,
                           failmsg + " FE functional bootstrapping of a complex input did not apply " +
                                   get_function_name(test_data.function_type) + " to the real part.");
            check_equality(actual_imag, std::vector<double>(packed.size(), 0.0), eps,
                           failmsg +
                                   " FE functional bootstrapping of a complex input returned a nonzero "
                                   "imaginary part.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Mixing bootstrapping variants is not supported: eval_bootstrap on a precomputation generated by
    // eval_fe_func_bootstrap_setup must throw instead of silently using the wrong overflow bound K.
    void unit_test_fefbt_variant_mix(const TEST_CASE_UTCKKSRNS_FEFBT& test_data,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            cc->eval_fe_func_bootstrap_setup(test_data.level_budget, test_data.dim1, test_data.slots);

            auto key_pair = cc->key_gen();
            cc->eval_bootstrap_key_gen(key_pair.secret_key, test_data.slots);
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto input = build_normalized_input(test_data.slots);
            Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, fefbt_encode_level(cc, test_data), nullptr,
                                                                 test_data.slots);
            auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);

            EXPECT_THROW(cc->eval_bootstrap(ciphertext), CipherException)
                    << failmsg << " eval_bootstrap on an eval_fe_func_bootstrap_setup precomputation did not throw.";

            // the recompute path must not convert the FE precomputation into a regular-bootstrapping one
            EXPECT_THROW(cc->eval_bootstrap_precompute(test_data.slots), CipherException)
                    << failmsg
                    << " eval_bootstrap_precompute on an eval_fe_func_bootstrap_setup precomputation did not throw.";

            // the FE functional bootstrapping precomputation itself must remain usable
            auto result_ct = cc->eval_fe_func_bootstrap(ciphertext, get_coefficients(test_data.function_type));
            auto expected = build_expected_output(test_data.function_type, input);
            Plaintext result;
            cc->decrypt(key_pair.secret_key, result_ct, &result);
            result->set_length(expected.size());
            check_equality(result->get_real_packed_value(), expected, eps,
                           failmsg + " FE functional bootstrapping failed after the rejected eval_bootstrap call.");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

TEST_P(UTCKKSRNS_FEFBT, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case FEFBT_ACCURACY:
            unit_test_fefbt(test, test.build_test_name());
            break;
        case FEFBT_POST_ROTATION:
            unit_test_fefbt_post_rotation(test, test.build_test_name());
            break;
        case FEFBT_CS_VS_FA:
            unit_test_fefbt_c_svs_fa(test, test.build_test_name());
            break;
        case FEFBT_COMPLEX_INPUT:
            unit_test_fefbt_complex_input(test, test.build_test_name());
            break;
        case FEFBT_MULTI_VALUE:
            unit_test_fefbt_multi_value(test, test.build_test_name());
            break;
        case FEFBT_VARIANT_MIX:
            unit_test_fefbt_variant_mix(test, test.build_test_name());
            break;
        default:
            break;
    }
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(UTCKKSRNS_FEFBT);
INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FEFBT, ::testing::ValuesIn(test_cases), make_test_name);

}  // namespace
