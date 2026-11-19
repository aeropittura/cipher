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
#include "fhe/support/ser_test.h"
#include "fhe/support/test_utils.h"
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/globals.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/ser.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    CONTEXT_WITH_SERTYPE = 0,
    KEYS_AND_CIPHERTEXTS,
    NO_CRT_TABLES,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case CONTEXT_WITH_SERTYPE:
            type_name_of = "CONTEXT_WITH_SERTYPE";
            break;
        case KEYS_AND_CIPHERTEXTS:
            type_name_of = "KEYS_AND_CIPHERTEXTS";
            break;
        case NO_CRT_TABLES:
            type_name_of = "NO_CRT_TABLES";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_SER {
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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_SER>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_SER& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS. RING_DIM = ORDER/2
 * SMODSIZE: Scaling parameter 2^p. Also, Size of each co-prime in bits.
 *       Should fit into a machine word, i.e., less than 64.
 * DSIZE: The bit decomposition count used in relinearization. Use 0 to go with max possible.
 *        Use small values (3-4?) if you need rotations before any multiplications.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
constexpr uint32_t RING_DIM = 32;
constexpr uint32_t SMODSIZE = 50;
constexpr uint32_t MULT_DEPTH = 3;
constexpr uint32_t DSIZE = 20;
constexpr uint32_t BATCH = 16;
// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_SER> test_cases = {
    // TestType,            Descr, Scheme,         RDim,     MultDepth,  SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,  enc_tech, pre_mode
    { CONTEXT_WITH_SERTYPE, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { CONTEXT_WITH_SERTYPE, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { CONTEXT_WITH_SERTYPE, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#endif
    // ==========================================
    // TestType,            Descr, Scheme,         RDim,     MultDepth,  SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,  enc_tech, pre_mode
    { KEYS_AND_CIPHERTEXTS, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { KEYS_AND_CIPHERTEXTS, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#endif
    // ==========================================
    // TestType,            Descr, Scheme,         RDim,     MultDepth,  SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,  enc_tech, pre_mode
    { KEYS_AND_CIPHERTEXTS, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { KEYS_AND_CIPHERTEXTS, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "16", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "17", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "18", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#endif
    // ==========================================
    // TestType,    Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, scal_tech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,  enc_tech, pre_mode
    { NO_CRT_TABLES, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#if CIPHER_NATIVE_INT != 128
    { NO_CRT_TABLES, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
    { NO_CRT_TABLES, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, 0,     BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,      DFLT,    DFLT}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_SER : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_SER> {
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

    void unit_test_context(const TEST_CASE_UTCKKSRNS_SER& test_data, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

        unit_test_context_with_sertype(cc, SerType::JSON, "json");
        CryptoContextImpl<Element>::clear_eval_mult_keys(cc);
        CryptoContextImpl<Element>::clear_eval_automorphism_keys(cc);
        unit_test_context_with_sertype(cc, SerType::BINARY, "binary");
    }

    template <typename ST>
    void test_keys_and_ciphertexts(const TEST_CASE_UTCKKSRNS_SER& test_data, const ST& sertype,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            CIPHER_DEBUG_FLAG(false);

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();

            CIPHER_DEBUG("step 0");
            {
                std::stringstream s;
                serialization::to_stream(cc, s, sertype);
                ASSERT_TRUE(ContextFactory<RnsPoly>::get_context_count() == 1);
                ContextFactory<RnsPoly>::release_all_contexts();
                ASSERT_TRUE(ContextFactory<RnsPoly>::get_context_count() == 0);
                serialization::from_stream(cc, s, sertype);

                ASSERT_TRUE(cc) << "Deser failed";
                ASSERT_TRUE(ContextFactory<RnsPoly>::get_context_count() == 1);
            }

            disable_precompute_crt_tables_after_deserializaton();
            KeyPair<RnsPoly> kp = cc->key_gen();
            KeyPair<RnsPoly> kpnew;

            CIPHER_DEBUG("step 1");
            {
                std::stringstream s;
                serialization::to_stream(kp.public_key, s, sertype);
                serialization::from_stream(kpnew.public_key, s, sertype);
                EXPECT_EQ(*kp.public_key, *kpnew.public_key) << "Public key mismatch after ser/deser";
            }
            CIPHER_DEBUG("step 2");
            {
                std::stringstream s;
                serialization::to_stream(kp.secret_key, s, sertype);
                serialization::from_stream(kpnew.secret_key, s, sertype);
                EXPECT_EQ(*kp.secret_key, *kpnew.secret_key) << "Secret key mismatch after ser/deser";
            }
            CIPHER_DEBUG("step 3");
            std::vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0, 2.0, 4.0, 6.0, 8.0, 11.0};
            Plaintext plaintext_short = cc->make_ckks_packed_plaintext(vals);
            Plaintext plaintext_short_l2_d2 = cc->make_ckks_packed_plaintext(vals, 2, 2);
            Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext_short);
            Ciphertext<RnsPoly> ciphertext_l2_d2 = cc->encrypt(kp.public_key, plaintext_short_l2_d2);

            CIPHER_DEBUG("step 4");
            Ciphertext<RnsPoly> new_c;
            Ciphertext<RnsPoly> new_cl2_d2;
            {
                std::stringstream s;
                serialization::to_stream(ciphertext, s, sertype);
                serialization::from_stream(new_c, s, sertype);
                std::stringstream s2;
                serialization::to_stream(ciphertext_l2_d2, s2, sertype);
                serialization::from_stream(new_cl2_d2, s2, sertype);
                EXPECT_EQ(*ciphertext, *new_c) << "Ciphertext mismatch";
                EXPECT_EQ(*ciphertext_l2_d2, *new_cl2_d2) << "Ciphertext mismatch";
            }

            CIPHER_DEBUG("step 5");
            Plaintext plaintext_short_new;
            Plaintext plaintext_short_new_l2_d2;
            cc->decrypt(kp.secret_key, new_c, &plaintext_short_new);
            cc->decrypt(kp.secret_key, new_cl2_d2, &plaintext_short_new_l2_d2);
            plaintext_short_new->set_length(plaintext_short->get_length());
            plaintext_short_new_l2_d2->set_length(plaintext_short_l2_d2->get_length());
            check_equality(plaintext_short_new->get_ckks_packed_value(), plaintext_short->get_ckks_packed_value(), eps,
                           failmsg + " Decrypted serialization test fails");
            check_equality(plaintext_short_new_l2_d2->get_ckks_packed_value(),
                           plaintext_short_l2_d2->get_ckks_packed_value(), eps,
                           failmsg + " Decrypted serialization test fails (level 2, depth 2)");

            CIPHER_DEBUG("step 6");
            KeyPair<RnsPoly> kp2 = cc->key_gen();

            cc->eval_mult_key_gen(kp.secret_key);
            cc->eval_mult_key_gen(kp2.secret_key);
            cc->eval_sum_key_gen(kp.secret_key);
            cc->eval_sum_key_gen(kp2.secret_key);

            CIPHER_DEBUG("step 7");
            // serialize a bunch of mult keys
            std::stringstream ser0;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_mult_key(ser0, sertype, kp.secret_key->get_key_tag()),
                      true)
                    << "single eval mult key ser fails";
            std::stringstream ser2a;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_mult_key(ser2a, sertype, cc), true)
                    << "context 1 eval mult key ser fails";
            std::stringstream ser3;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_mult_key(ser3, sertype), true)
                    << "all context eval mult key ser fails";

            CIPHER_DEBUG("step 8");
            // serialize a bunch of sum keys
            std::stringstream aser0;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_sum_key(aser0, sertype, kp.secret_key->get_key_tag()),
                      true)
                    << "single eval sum key ser fails";
            std::stringstream aser2a;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_sum_key(aser2a, sertype, cc), true)
                    << "single ctx eval sum key ser fails";
            std::stringstream aser3;
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::serialize_eval_sum_key(aser3, sertype), true)
                    << "all eval sum key ser fails";

            CIPHER_DEBUG("step 9");
            cc.reset();

            // test mult deserialize
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 0) << "after release";

            std::vector<EvalKey<RnsPoly>> eval_mult_keys;
            CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key(ser0, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "one-key deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_mult_keys().size(), 1U) << "one-key deser, keys";

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key(ser2a, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "one-ctx deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_mult_keys().size(), 2U) << "one-ctx deser, keys";

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key(ser3, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "all-key deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_mult_keys().size(), 2U) << "all-key deser, keys";

            CIPHER_DEBUG("step 10");
            // test sum deserialize

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContextImpl<RnsPoly>::deserialize_eval_sum_key(aser0, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "one-key deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_sum_keys().size(), 1U) << "one-key deser, keys";

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContextImpl<RnsPoly>::deserialize_eval_sum_key(aser2a, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "one-ctx deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_sum_keys().size(), 2U) << "one-ctx deser, keys";

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContextImpl<RnsPoly>::deserialize_eval_sum_key(aser3, sertype);
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 1) << "all-key deser, context";
            EXPECT_EQ(CryptoContextImpl<RnsPoly>::get_all_eval_sum_keys().size(), 2U) << "all-key deser, keys";

            // ending cleanup
            enable_precompute_crt_tables_after_deserializaton();
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<RnsPoly>::release_all_contexts();
        } catch (std::exception& e) {
            enable_precompute_crt_tables_after_deserializaton();
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            enable_precompute_crt_tables_after_deserializaton();
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    void unit_test_keys_and_ciphertexts(const TEST_CASE_UTCKKSRNS_SER& test_data,
                                        const std::string& failmsg = std::string()) {
        test_keys_and_ciphertexts(test_data, SerType::JSON, "json");
        test_keys_and_ciphertexts(test_data, SerType::BINARY, "binary");
    }

    template <typename ST>
    void test_decryption_ser_no_crt_tables(const TEST_CASE_UTCKKSRNS_SER& test_data, const ST& sertype,
                                           const std::string& failmsg = std::string()) {
        try {
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<RnsPoly>::release_all_contexts();

            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            KeyPair<Element> kp = cc->key_gen();

            std::vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0, 2.0, 4.0, 6.0, 8.0, 11.0};
            Plaintext plaintext_short = cc->make_ckks_packed_plaintext(vals);
            Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext_short);

            std::stringstream s;
            serialization::to_stream(cc, s, sertype);

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<Element>::release_all_contexts();

            disable_precompute_crt_tables_after_deserializaton();

            CryptoContext<Element> newcc;

            serialization::from_stream(newcc, s, sertype);

            ASSERT_TRUE(newcc) << failmsg << " Deserialize failed";

            s.str("");
            s.clear();
            serialization::to_stream(kp.public_key, s, sertype);

            PublicKey<Element> new_pub;
            serialization::from_stream(new_pub, s, sertype);
            ASSERT_TRUE(new_pub) << failmsg << " Key deserialize failed";

            s.str("");
            s.clear();
            serialization::to_stream(ciphertext, s, sertype);

            Ciphertext<RnsPoly> new_c;
            serialization::from_stream(new_c, s, sertype);
            ASSERT_TRUE(new_c) << failmsg << " ciphertext deserialize failed";

            Plaintext result;
            cc->decrypt(kp.secret_key, new_c, &result);
            result->set_length(plaintext_short->get_length());
            check_equality(plaintext_short->get_ckks_packed_value(), result->get_ckks_packed_value(), eps,
                           failmsg + " Decryption Failed");

            enable_precompute_crt_tables_after_deserializaton();
            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
            ContextFactory<RnsPoly>::release_all_contexts();
        } catch (std::exception& e) {
            enable_precompute_crt_tables_after_deserializaton();
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            enable_precompute_crt_tables_after_deserializaton();
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    void unit_test_decryption_ser_no_crt_tables(const TEST_CASE_UTCKKSRNS_SER& test_data,
                                                const std::string& failmsg = std::string()) {
        test_decryption_ser_no_crt_tables(test_data, SerType::JSON, "json");
        test_decryption_ser_no_crt_tables(test_data, SerType::BINARY, "binary");
    }
};
//===========================================================================================================
TEST_P(UTCKKSRNS_SER, CKKSSer) {
    setup_signals();
    auto test = GetParam();

    if (test.test_case_type == CONTEXT_WITH_SERTYPE)
        unit_test_context(test, test.build_test_name());
    else if (test.test_case_type == KEYS_AND_CIPHERTEXTS)
        unit_test_keys_and_ciphertexts(test, test.build_test_name());
    else if (test.test_case_type == NO_CRT_TABLES)
        unit_test_decryption_ser_no_crt_tables(test, test.build_test_name());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_SER, ::testing::ValuesIn(test_cases), make_test_name);
