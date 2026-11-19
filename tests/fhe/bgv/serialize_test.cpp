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
#include "fhe/support/ser_test.h"
#include "fhe/support/test_utils.h"
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/globals.h"
#include "include/gtest/gtest.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/bgv/ser.h"
#include "cipher/util/exception.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    CONTEXT = 0,
    KEYS_AND_CIPHERTEXTS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case CONTEXT:
            type_name_of = "CONTEXT";
            break;
        case KEYS_AND_CIPHERTEXTS:
            type_name_of = "KEYS_AND_CIPHERTEXTS";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_SER {
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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_SER>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_SER& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
/***
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus (size of each co-prime in bits or
 *             scaling factor bits).
 * 		       Should fit into a machine word, i.e., less than 64.
 * DSIZE:      The bit decomposition count used in relinearization.
 *  	       Use 0 to go with max possible. Use small values (3-4?) if you need rotations before any multiplications.
 * PTM:        The plaintext modulus.
 * BATCH:      The length of the packed vectors to be used with CKKS.
 */
constexpr uint32_t RING_DIM = 32;
constexpr uint32_t MULT_DEPTH = 3;
constexpr uint32_t MAX_RELIN_DEG = 2;
constexpr uint32_t DSIZE = 4;
constexpr uint32_t PTM = 65537;
constexpr uint32_t BATCH = 16;
constexpr uint32_t FIRST_MOD_SIZE = 0;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
// TODO (dsuponit): are there any changes under this condition - #if CIPHER_NATIVE_INT != 128?

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS_SER> test_cases = {
    // TestType, Descr, Scheme,      RDim,     MultDepth,  SModSize,   DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, scal_tech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode
    { CONTEXT, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, scal_tech,        LDigits, PtMod, std_dev,   EvalAddCt, KSCt, mult_tech, enc_tech, pre_mode
    { KEYS_AND_CIPHERTEXTS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "09", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "10", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "11", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "12", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "13", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "14", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "15", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "16", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTBGVRNS_SER : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_SER> {
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

    void unit_test_context(const TEST_CASE_UTBGVRNS_SER& test_data, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

        unit_test_context_with_sertype(cc, SerType::JSON, "json");
        unit_test_context_with_sertype(cc, SerType::BINARY, "binary");
    }

    template <typename ST>
    void test_keys_and_ciphertexts(const TEST_CASE_UTBGVRNS_SER& test_data, const ST& sertype,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            CIPHER_DEBUG_FLAG(false);

            CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
            CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();

            // // The batch size for our tests.
            int vec_size = 10;

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

            // Update the batch_size from the default value
            const auto crypto_params_bgv_rns =
                    std::dynamic_pointer_cast<BgvRnsCryptoParams>(kp.public_key->get_crypto_parameters());

            EncodingParams encoding_params_new(
                    std::make_shared<EncodingParamsImpl>(cc->get_encoding_params()->get_plaintext_modulus(), vec_size));
            crypto_params_bgv_rns->set_encoding_params(encoding_params_new);

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
            std::vector<int64_t> vals = {1, 3, 5, 7, 9, 2, 4, 6, 8, 11};
            Plaintext plaintext_short = cc->make_packed_plaintext(vals);
            Ciphertext<RnsPoly> ciphertext = cc->encrypt(kp.public_key, plaintext_short);

            CIPHER_DEBUG("step 4");
            Ciphertext<RnsPoly> new_c;
            {
                std::stringstream s;
                serialization::to_stream(ciphertext, s, sertype);
                serialization::from_stream(new_c, s, sertype);
                EXPECT_EQ(*ciphertext, *new_c) << "Ciphertext mismatch";
            }

            CIPHER_DEBUG("step 5");
            Plaintext plaintext_short_new;
            cc->decrypt(kp.secret_key, new_c, &plaintext_short_new);
            plaintext_short_new->set_length(plaintext_short->get_length());

            std::stringstream buffer_short;
            buffer_short << "should be: " << plaintext_short_new->get_packed_value()
                         << " - we get: " << plaintext_short->get_packed_value();
            check_equality(plaintext_short_new->get_packed_value(), plaintext_short->get_packed_value(), eps,
                           failmsg + " Decrypted serialization test fails" + buffer_short.str());

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
            EXPECT_EQ(ContextFactory<RnsPoly>::get_context_count(), 0) << "after release" << std::endl;

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

    void unit_test_keys_and_ciphertexts(const TEST_CASE_UTBGVRNS_SER& test_data,
                                        const std::string& failmsg = std::string()) {
        test_keys_and_ciphertexts(test_data, SerType::JSON, "json");
        test_keys_and_ciphertexts(test_data, SerType::BINARY, "binary");
    }
};
//===========================================================================================================
TEST_P(UTBGVRNS_SER, BGVSer) {
    setup_signals();
    auto test = GetParam();

    if (test.test_case_type == CONTEXT)
        unit_test_context(test, test.build_test_name());
    else if (test.test_case_type == KEYS_AND_CIPHERTEXTS)
        unit_test_keys_and_ciphertexts(test, test.build_test_name());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_SER, ::testing::ValuesIn(test_cases), make_test_name);
