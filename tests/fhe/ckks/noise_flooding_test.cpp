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
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int { NOISE_ESTIMATION, FULL_NOISE_FLOODING, MULTIPARTY_NOISE_FLOODING };

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case NOISE_ESTIMATION:
            typeName = "NOISE_ESTIMATION";
            break;
        case FULL_NOISE_FLOODING:
            typeName = "FULL_NOISE_FLOODING";
            break;
        case MULTIPARTY_NOISE_FLOODING:
            typeName = "MULTIPARTY_NOISE_FLOODING";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_NOISE_FLOODING {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_NOISE_FLOODING>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t MULT_DEPTH = 25;
constexpr uint32_t RDIM = 512;
constexpr uint32_t NUM_LRG_DIGS = 3;
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;
constexpr double NOISE_ESTIMATE_FLEX_AUTO_EXT = 2;
constexpr double NOISE_ESTIMATE = 5.5;
#if CIPHER_NATIVE_INT != 128
constexpr double MP_NOISE_ESTIMATE_FLEX_AUTO_EXT = 1;
#endif
constexpr double MP_NOISE_ESTIMATE = 3.5;

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> test_cases = {
    // TestType,       Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,         NoiseEstimate
    { NOISE_ESTIMATION, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#if CIPHER_NATIVE_INT != 128
    { NOISE_ESTIMATION, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#endif
    // TestType,          Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,   NoiseEstimate
    { FULL_NOISE_FLOODING, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
#if CIPHER_NATIVE_INT != 128
    { FULL_NOISE_FLOODING, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
    { FULL_NOISE_FLOODING, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
#endif
    // TestType,                Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, std_dev, EvalAddCt, KSCt, MultTech, EncTech, pre_mode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,
    { MULTIPARTY_NOISE_FLOODING, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
#if CIPHER_NATIVE_INT != 128
    { MULTIPARTY_NOISE_FLOODING, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},
    { MULTIPARTY_NOISE_FLOODING, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},

#endif
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_NOISE_FLOODING : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> {
    using Element = RnsPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = 0.0001;
    const double buffer = 1;

    Ciphertext<RnsPoly> encrypted_computation(CryptoContext<RnsPoly>& crypto_context, PublicKey<RnsPoly> public_key) {
        // Encoding and encryption of inputs
        // Generate random input
        std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

        // Encoding as plaintexts and encrypt
        Plaintext ptxt1 = crypto_context->make_ckks_packed_plaintext(vec1);
        Plaintext ptxt2 = crypto_context->make_ckks_packed_plaintext(vec2);
        Ciphertext<RnsPoly> ciph1 = crypto_context->encrypt(public_key, ptxt1);
        Ciphertext<RnsPoly> ciph2 = crypto_context->encrypt(public_key, ptxt2);

        Ciphertext<RnsPoly> ciph_mult = crypto_context->eval_mult(ciph1, ciph2);
        crypto_context->mod_reduce_in_place(ciph_mult);
        Ciphertext<RnsPoly> ciph_mult2 = crypto_context->eval_mult(ciph_mult, ciph1);
        crypto_context->mod_reduce_in_place(ciph_mult2);
        Ciphertext<RnsPoly> ciph_result = crypto_context->eval_add(ciph_mult2, ciph2);

        return ciph_result;
    }

    Ciphertext<RnsPoly> encrypted_multiparty_computation(CryptoContext<RnsPoly>& crypto_context,
                                                        PublicKey<RnsPoly> public_key) {
        // Encoding and encryption of inputs
        // Generate random input
        std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

        // Encoding as plaintexts and encrypt
        Plaintext ptxt1 = crypto_context->make_ckks_packed_plaintext(vec1);
        Plaintext ptxt2 = crypto_context->make_ckks_packed_plaintext(vec2);
        Ciphertext<RnsPoly> ciph1 = crypto_context->encrypt(public_key, ptxt1);
        Ciphertext<RnsPoly> ciph2 = crypto_context->encrypt(public_key, ptxt2);

        Ciphertext<RnsPoly> ciph_mult = crypto_context->eval_mult(ciph1, ciph2);
        return ciph_mult;
    }

    void generate_multiparty_keys(CryptoContext<RnsPoly>& crypto_context, KeyPair<RnsPoly> kp1, KeyPair<RnsPoly> kp2) {
        auto eval_mult_key = crypto_context->key_switch_gen(kp1.secret_key, kp1.secret_key);
        auto eval_mult_key2 = crypto_context->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);
        auto eval_mult_ab = crypto_context->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());
        auto eval_mult_bab = crypto_context->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
        auto eval_mult_aab = crypto_context->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
        auto eval_mult_final = crypto_context->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab, eval_mult_ab->get_key_tag());
        crypto_context->insert_eval_mult_key({eval_mult_final});
    }

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_noise_estimation(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& test_data,
                                  const std::string& failmsg = std::string()) {
        try {
            CryptoContext<RnsPoly> cc(unit_test_generate_context(test_data.params));
            cc->enable(PKE);
            cc->enable(LEVELEDSHE);

            auto key_pair = cc->key_gen();
            cc->eval_mult_key_gen(key_pair.secret_key);

            auto noise_ciphertext = encrypted_computation(cc, key_pair.public_key);

            Plaintext noise_plaintext;
            cc->decrypt(key_pair.secret_key, noise_ciphertext, &noise_plaintext);
            double noise = noise_plaintext->get_log_error();
            double expected_noise =
                    test_data.params.scal_tech == FLEXIBLEAUTOEXT ? NOISE_ESTIMATE_FLEX_AUTO_EXT : NOISE_ESTIMATE;
            EXPECT_TRUE(check_equality(noise, expected_noise, buffer)) << failmsg + " CKKS Noise estimation fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    void unit_test_full_noise_flooding(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& test_data,
                                    const std::string& failmsg = std::string()) {
        CryptoContext<RnsPoly> cc(unit_test_generate_context(test_data.params));
        cc->enable(PKE);
        cc->enable(LEVELEDSHE);

        auto key_pair = cc->key_gen();
        cc->eval_mult_key_gen(key_pair.secret_key);

        auto ciphertext_result = encrypted_computation(cc, key_pair.public_key);

        Plaintext result;
        cc->decrypt(key_pair.secret_key, ciphertext_result, &result);
        size_t vec_size = 8;
        result->set_length(vec_size);

        std::vector<std::complex<double>> expected_result = {1.01, 1.04, 0, 0, 1.25, 0, 0, 1.64};

        check_equality(result->get_ckks_packed_value(), expected_result, eps, failmsg + " Noise flooding computation fails");
    }

    void unit_test_multiparty_noise_flooding(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& test_data,
                                          const std::string& failmsg = std::string()) {
        CryptoContext<RnsPoly> cc(unit_test_generate_context(test_data.params));
        cc->enable(PKE);
        cc->enable(LEVELEDSHE);
        cc->enable(MULTIPARTY);

        auto kp1 = cc->key_gen();
        KeyPair<Element> kp2 = cc->multiparty_key_gen(kp1.public_key, false, true);
        generate_multiparty_keys(cc, kp1, kp2);
        auto pub_key_for_encryption = cc->multi_add_pub_keys(kp1.public_key, kp2.public_key, kp2.public_key->get_key_tag());

        auto ciphertext_result = encrypted_multiparty_computation(cc, pub_key_for_encryption);

        Plaintext result;
        auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_result}, kp1.secret_key);
        auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_result}, kp2.secret_key);
        std::vector<Ciphertext<Element>> partial_ciphertext_vec_mult{ciphertext_partial1[0], ciphertext_partial2[0]};
        cc->multiparty_decrypt_fusion(partial_ciphertext_vec_mult, &result);
        size_t vec_size = 8;
        result->set_length(vec_size);

        std::vector<std::complex<double>> expected_result = {0.1, 0.2, 0, 0, 0.5, 0, 0, 0.8};

        check_equality(result->get_ckks_packed_value(), expected_result, eps, failmsg + " Noise flooding computation fails");
    }
};

//===========================================================================================================
TEST_P(UTCKKSRNS_NOISE_FLOODING, CKKSRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case NOISE_ESTIMATION:
            unit_test_noise_estimation(test, test.build_test_name());
            break;
        case FULL_NOISE_FLOODING:
            unit_test_full_noise_flooding(test, test.build_test_name());
            break;
        case MULTIPARTY_NOISE_FLOODING:
            unit_test_multiparty_noise_flooding(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_NOISE_FLOODING, ::testing::ValuesIn(test_cases), testName);
