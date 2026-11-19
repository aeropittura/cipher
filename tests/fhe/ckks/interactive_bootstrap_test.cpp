//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "fhe/support/base_test_case.h"
#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/csv_data.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;
class Params;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    INTERACTIVE_MP_BOOT = 0,
    INTERACTIVE_MP_BOOT_CHEBYSHEV,
    INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY,
    INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY,
    INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY,
    INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY,
};
static TEST_CASE_TYPE convert_string_to_case_type(const std::string& str) {
    const std::unordered_map<std::string, TEST_CASE_TYPE> string_to_case_type = {
            {"INTERACTIVE_MP_BOOT", INTERACTIVE_MP_BOOT},
            {"INTERACTIVE_MP_BOOT_CHEBYSHEV", INTERACTIVE_MP_BOOT_CHEBYSHEV},
            {"INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY", INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY},
            {"INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY", INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY},
            {"INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY", INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY},
            {"INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY", INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY}};
    auto search = string_to_case_type.find(str);
    if (string_to_case_type.end() != search) {
        return search->second;
    }
    CIPHER_THROW(std::string("Can not convert ") + str + "to test case");
}
static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    const std::unordered_map<TEST_CASE_TYPE, std::string> case_type_to_string = {
            {INTERACTIVE_MP_BOOT, "INTERACTIVE_MP_BOOT"},
            {INTERACTIVE_MP_BOOT_CHEBYSHEV, "INTERACTIVE_MP_BOOT_CHEBYSHEV"},
            {INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY, "INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY"},
            {INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY, "INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY"},
            {INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY, "INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY"},
            {INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY, "INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY"}};
    auto search = case_type_to_string.find(type);
    if (case_type_to_string.end() != search) {
        return os << search->second;
    }
    CIPHER_THROW("Unknown test case");
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT : public BaseTestCase {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    // additional test case data
    uint32_t num_parties;
    uint32_t num_towers;  // number of RNS limbs after compressing (default is 1)

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }
    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "[testCase: " << test_case_type << "], [description: " << description
           << "], [params: " << get_crypto_context_param_overrides() << "], [numParties: " << num_parties
           << "], [numTowers: " << num_towers << "]";
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT>& test_param_info) {
    return test_param_info.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
static std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> get_test_data(std::string file_name) {
    // TODO: add a new test data file for CIPHER_NATIVE_INT == 128
    std::string test_data_file_name(create_data_file_name(file_name));
    std::vector<std::vector<std::string>> file_rows(read_data_file(test_data_file_name));
    size_t num_rows = file_rows.size();

    std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> all_data;
    all_data.reserve(num_rows);

    for (const std::vector<std::string>& vec : file_rows) {
        TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT test_case_value;

        auto it = vec.begin();
        test_case_value.test_case_type = convert_string_to_case_type(*it);
        test_case_value.description = *(++it);

        // size_t num_overrides = test_case_value.populate_crypto_context_params(++it);
        size_t num_overrides = test_case_value.set_crypto_context_params_overrides(++it);

        it += num_overrides;
        if (it != vec.end() && !(*it).empty()) {
            // process additional test date
            test_case_value.num_parties = static_cast<uint32_t>(std::stoul(*it));
        }
        ++it;
        if (it != vec.end() && !(*it).empty()) {
            // process additional test date
            test_case_value.num_towers = static_cast<uint32_t>(std::stoul(*it));
        }

        all_data.push_back(std::move(test_case_value));
    }
    return all_data;
}
//===========================================================================================================
static std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> test_cases_utckksrns_interactive_boot =
        get_test_data(__FILE__);
//===========================================================================================================

class UTCKKSRNS_INTERACTIVE_BOOT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> {
    using Element = RnsPoly;
    // The precision after which we consider two values equal as CKKS works for approximate numbers.
    const double eps = 0.0001;

    /**
     * Party is a utility class defining a party involved in the collective bootstrapping protocol
     */
    struct Party {
        uint32_t id;                // unique party identifier starting from 0
        KeyPair<Element> kp_shard;  // key-pair shard (pk, sk_i)
    };

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<Element>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_multi_party_boot(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                    const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            // Initialization - Assuming num_parties (n) of parties P0 is the leading party
            // generate the joint public key for (s_0 + s_1 + ... + s_n)
            std::vector<Party> parties(test_data.num_parties);
            parties[0].id = 0;
            parties[0].kp_shard = cc->key_gen();
            if (!parties[0].kp_shard.good())
                CIPHER_THROW(std::string("Key generation failed for party ") + std::to_string(0));
            for (uint32_t i = 1; i < parties.size(); i++) {
                parties[i].id = i;
                parties[i].kp_shard = cc->multiparty_key_gen(parties[0].kp_shard.public_key);
                if (!parties[i].kp_shard.good())
                    CIPHER_THROW(std::string("Key generation failed for party ") + std::to_string(i));
            }

            // Generate the collective public key
            std::vector<PrivateKey<Element>> secret_keys;
            for (const auto& party : parties) {
                secret_keys.push_back(party.kp_shard.secret_key);
            }

            // Joint public key
            KeyPair<Element> kp_multiparty =
                    cc->multiparty_key_gen(secret_keys);  // This is the same core key generation operation.

            // Prepare input vector
            const std::vector<std::complex<double>> in_vec{-0.9, -0.8, 0.2, 0.4};
            Plaintext ptxt = cc->make_ckks_packed_plaintext(in_vec);

            // Encryption
            Ciphertext<Element> in_ctxt = cc->encrypt(kp_multiparty.public_key, ptxt);

            // Compressing ctxt to the smallest possible number of towers
            in_ctxt = cc->int_mp_boot_adjust_scale(in_ctxt);

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // INTERACTIVE BOOTSTRAPPING
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Leading party (P0) generates a Common Random Poly (a_ctxt) at max coefficient modulus (QNumPrime).
            // a is sampled at random uniformly from R_{Q}
            Ciphertext<Element> a_ctxt = cc->int_mp_boot_random_element_gen(parties[0].kp_shard.public_key);

            // Each party generates its own shares: masked_decryption_share (h_{0,i}, h_{1,i}) and re_encryption_share
            std::vector<std::vector<Ciphertext<Element>>> shares_pair_vec;

            // Make a copy of input ciphertext and remove the first element (c0), we only c1 for int_mp_boot_decrypt
            auto c1 = in_ctxt->clone();
            c1->get_elements().erase(c1->get_elements().begin());
            for (const auto& party : parties) {
                shares_pair_vec.push_back(cc->int_mp_boot_decrypt(party.kp_shard.secret_key, c1, a_ctxt));
            }

            // P0 finalizes the protocol by aggregating the shares and reEncrypting the results
            auto aggregated_shares_pair = cc->int_mp_boot_add(shares_pair_vec);
            // Make sure you provide the non-striped ciphertext (in_ctxt) in int_mp_boot_encrypt
            auto out_ctxt =
                    cc->int_mp_boot_encrypt(parties[0].kp_shard.public_key, aggregated_shares_pair, a_ctxt, in_ctxt);
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // END OF INTERACTIVE BOOTSTRAPPING
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Distributed (interactive) decryption
            std::vector<Ciphertext<Element>> partial_ciphertext_vec;
            partial_ciphertext_vec.push_back(
                    cc->multiparty_decrypt_lead({out_ctxt}, parties[0].kp_shard.secret_key)[0]);
            for (uint32_t i = 1; i < parties.size(); i++) {
                partial_ciphertext_vec.push_back(
                        cc->multiparty_decrypt_main({out_ctxt}, parties[i].kp_shard.secret_key)[0]);
            }

            // Check the results
            Plaintext result_ptxt;
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &result_ptxt);
            result_ptxt->set_length(in_vec.size());
            check_equality(ptxt->get_ckks_packed_value(), result_ptxt->get_ckks_packed_value(), eps,
                           failmsg + " Interactive multiparty bootstrapping fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_multi_party_boot_chebyshev(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<RnsPoly> cc(unit_test_generate_context(test_data));

            // Initialize Public Key Containers
            KeyPair<RnsPoly> kp1;  // Party 1
            KeyPair<RnsPoly> kp2;  // Party 2
            KeyPair<RnsPoly> kp3;  // Lead party 3: encrypts and finalizes the bootstrapping protocol

            ////////////////////////////////////////////////////////////
            // Key Generation Operation
            ////////////////////////////////////////////////////////////
            kp1 = cc->key_gen();
            if (!kp1.good())
                CIPHER_THROW(std::string("Key generation failed"));
            // Generate evalmult key
            auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);

            // Generate evalsum key
            cc->eval_sum_key_gen(kp1.secret_key);
            auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
                    cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

            kp2 = cc->multiparty_key_gen(kp1.public_key);
            if (!kp2.good())
                CIPHER_THROW(std::string("Key generation failed"));
            auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);
            auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());
            auto eval_mult_bab = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
            auto eval_sum_keys_b =
                    cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());
            auto eval_sum_keys_join =
                    cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());
            cc->insert_eval_sum_key(eval_sum_keys_join);
            auto eval_mult_aab = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
            auto eval_mult_final =
                    cc->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab, eval_mult_ab->get_key_tag());
            cc->insert_eval_mult_key({eval_mult_final});

            kp3 = cc->multiparty_key_gen(kp2.public_key);
            if (!kp3.good())
                CIPHER_THROW(std::string("Key generation failed"));
            auto eval_mult_key3 = cc->multi_key_switch_gen(kp3.secret_key, kp3.secret_key, eval_mult_key);
            auto eval_mult_abc = cc->multi_add_eval_keys(eval_mult_ab, eval_mult_key3, kp3.public_key->get_key_tag());
            auto eval_mult_babc = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
            auto eval_mult_aabc = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
            auto eval_mult_cabc = cc->multi_mult_eval_key(kp3.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
            auto eval_mult_ababc =
                    cc->multi_add_eval_mult_keys(eval_mult_babc, eval_mult_aabc, eval_mult_babc->get_key_tag());
            auto eval_mult_final2 =
                    cc->multi_add_eval_mult_keys(eval_mult_ababc, eval_mult_cabc, eval_mult_cabc->get_key_tag());
            cc->insert_eval_mult_key({eval_mult_final2});

            auto eval_sum_keys_c =
                    cc->multi_eval_sum_key_gen(kp3.secret_key, eval_sum_keys, kp3.public_key->get_key_tag());
            auto eval_sum_keys_join2 =
                    cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_c, kp3.public_key->get_key_tag());
            cc->insert_eval_sum_key(eval_sum_keys_join2);

            const std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
            const std::vector<double> coefficients{1.0, 0.558971,     0.0, -0.0943712,   0.0, 0.0215023,
                                                   0.0, -0.00505348,  0.0, 0.00119324,   0.0, -0.000281928,
                                                   0.0, 0.0000664347, 0.0, -0.0000148709};

            Plaintext pt1 = cc->make_ckks_packed_plaintext(input);
            auto ct1 = cc->encrypt(kp3.public_key, pt1);
            double a = -4;
            double b = 4;
            ct1 = cc->eval_chebyshev_series(ct1, coefficients, a, b);

            // INTERACTIVE BOOTSTRAPPING
            ct1 = cc->int_mp_boot_adjust_scale(ct1);

            // Leading party (party 3) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
            // a is sampled at random uniformly from R_{Q}
            auto crp = cc->int_mp_boot_random_element_gen(kp3.public_key);
            // extract c1 - element-wise
            auto c1 = ct1->clone();
            c1->get_elements().erase(c1->get_elements().begin());

            // masked decryption on the client: c1 = a*s1
            // Each party generates its own shares: masked_decryption_share and re_encryption_share
            // (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)
            // we use a vector inseat of std::pair for Python API compatibility
            std::vector<Ciphertext<RnsPoly>> shares_pair1 = cc->int_mp_boot_decrypt(kp1.secret_key, c1, crp);
            std::vector<Ciphertext<RnsPoly>> shares_pair2 = cc->int_mp_boot_decrypt(kp2.secret_key, c1, crp);
            std::vector<Ciphertext<RnsPoly>> shares_pair3 = cc->int_mp_boot_decrypt(kp3.secret_key, c1, crp);

            std::vector<std::vector<Ciphertext<RnsPoly>>> shares_pair_vec{shares_pair1, shares_pair2, shares_pair3};

            // Party 3 finalizes the protocol by aggregating the shares and reEncrypting the results
            auto aggregated_shares_pair = cc->int_mp_boot_add(shares_pair_vec);
            auto ciphertext_output = cc->int_mp_boot_encrypt(kp3.public_key, aggregated_shares_pair, crp, ct1);

            // END OF INTERACTIVE BOOTSTRAPPING

            // distributed decryption
            auto ciphertext_partial1 = cc->multiparty_decrypt_main({ciphertext_output}, kp1.secret_key);
            auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);
            auto ciphertext_partial3 = cc->multiparty_decrypt_lead({ciphertext_output}, kp3.secret_key);
            std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec{ciphertext_partial1[0], ciphertext_partial2[0],
                                                                    ciphertext_partial3[0]};

            Plaintext plaintext_multiparty;
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);
            plaintext_multiparty->set_length(input.size());

            const std::vector<std::complex<double>> result1{0.0179885, 0.0474289, 0.119205, 0.268936, 0.5,
                                                            0.731064,  0.880795,  0.952571, 0.982011};
            Plaintext plaintext_result1 = cc->make_ckks_packed_plaintext(result1);
            check_equality(plaintext_result1->get_ckks_packed_value(), plaintext_multiparty->get_ckks_packed_value(),
                           eps, failmsg + " Interactive multiparty bootstrapping Chebyshev fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_multi_party_boot_encrypt2(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            KeyPair<RnsPoly> kp = cc->key_gen();
            if (!kp.good())
                CIPHER_THROW(std::string("Key generation failed"));

            // Prepare input vector
            const std::vector<std::complex<double>> in_vec{-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9};
            Plaintext ptxt = cc->make_ckks_packed_plaintext(in_vec);

            // Encryption
            Ciphertext<Element> in_ctxt = cc->encrypt(kp.public_key, ptxt);

            // Compressing ctxt to the number of towers
            in_ctxt = cc->compress(in_ctxt, test_data.num_towers);

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // INTERACTIVE BOOTSTRAPPING
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            Ciphertext<Element> out_ctxt = cc->int_boot_decrypt(kp.secret_key, in_ctxt);
            out_ctxt = cc->int_boot_encrypt(kp.public_key, out_ctxt);

            Plaintext result_ptxt;
            cc->decrypt(kp.secret_key, out_ctxt, &result_ptxt);
            result_ptxt->set_length(in_vec.size());

            check_equality(ptxt->get_ckks_packed_value(), result_ptxt->get_ckks_packed_value(), eps,
                           failmsg + " Interactive multiparty bootstrapping (encrypt) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_multi_party_boot_decrypt2(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                             const std::string& failmsg = std::string()) {
        try {
            constexpr uint32_t NUM_PARTIES = 2;

            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            KeyPair<RnsPoly> kp = cc->key_gen();
            if (!kp.good())
                CIPHER_THROW(std::string("Key generation failed"));

            // Prepare input vector
            const std::vector<std::complex<double>> in_vec{-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9};
            Plaintext ptxt = cc->make_ckks_packed_plaintext(in_vec);

            // Encryption
            Ciphertext<Element> in_ctxt = cc->encrypt(kp.public_key, ptxt);

            auto s = kp.secret_key->get_private_element();
            kp.secret_key->set_private_element(NUM_PARTIES * s);
            auto out_ctxt = cc->int_boot_decrypt(kp.secret_key, in_ctxt);

            auto c_poly_rns = out_ctxt->get_elements()[0];
            auto c_poly_rns_interpolated = c_poly_rns.crt_interpolate();

            auto c = in_ctxt->get_elements();
            auto cs = NUM_PARTIES * c[1] * s + c[0];
            cs.set_format(Format::COEFFICIENT);

            auto c_poly = cs.crt_interpolate();

            auto Q = c_poly.get_modulus();
            auto qhalf = Q / BigInteger(2);
            auto q1quart = Q / BigInteger(4);
            auto q3quart = (BigInteger(3) * Q) / BigInteger(4);

            for (uint32_t i = 0; i < c_poly.get_ring_dimension(); i++) {
                if ((c_poly[i] > q1quart) && (c_poly[i] <= q3quart))
                    c_poly[i].mod_add_eq(qhalf, Q);
            }

            EXPECT_TRUE(c_poly == c_poly_rns_interpolated)
                    << failmsg + " Interactive multiparty bootstrapping (decrypt) fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_multi_party_boot_threshold_fhe2(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            KeyPair<RnsPoly> kp1 = cc->key_gen();
            if (!kp1.good())
                CIPHER_THROW(std::string("Key generation failed"));

            KeyPair<RnsPoly> kp2 = cc->multiparty_key_gen(kp1.public_key);

            // Prepare input vector
            const std::vector<std::complex<double>> in_vec{-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9};
            Plaintext ptxt = cc->make_ckks_packed_plaintext(in_vec);
            Ciphertext<Element> in_ctxt1 = cc->encrypt(kp2.public_key, ptxt);

            in_ctxt1 = cc->int_boot_adjust_scale(in_ctxt1);

            // masked decryption on the server: c0 = b + a*s0
            auto out_ctxt1 = cc->int_boot_decrypt(kp1.secret_key, in_ctxt1);

            auto in_ctxt2 = in_ctxt1->clone();
            in_ctxt2->set_elements({in_ctxt2->get_elements()[1]});

            // masked decryption on the client: c1 = a*s1
            auto out_ctxt2 = cc->int_boot_decrypt(kp2.secret_key, in_ctxt2);

            // Encryption of masked decryption c1 = a*s1
            out_ctxt2 = cc->int_boot_encrypt(kp2.public_key, out_ctxt2);

            // Compute Enc(c1) + c0
            auto out_ctxt = cc->int_boot_add(out_ctxt2, out_ctxt1);

            auto ciphertext_partial1 = cc->multiparty_decrypt_lead({out_ctxt}, kp1.secret_key);
            auto ciphertext_partial2 = cc->multiparty_decrypt_main({out_ctxt}, kp2.secret_key);

            std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
            partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
            partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

            Plaintext plaintext_multiparty;
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);
            plaintext_multiparty->set_length(in_vec.size());

            check_equality(ptxt->get_ckks_packed_value(), plaintext_multiparty->get_ckks_packed_value(), eps,
                           failmsg + " Interactive multiparty bootstrapping (ThresholdFHE2) fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_multi_party_boot_chebyshev2(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test_data,
                                               const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            KeyPair<RnsPoly> kp1 = cc->key_gen();
            if (!kp1.good())
                CIPHER_THROW(std::string("Key generation failed"));

            // joint public key for (s_a + s_b)
            KeyPair<RnsPoly> kp2 = cc->multiparty_key_gen(kp1.public_key);

            auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);
            cc->eval_sum_key_gen(kp1.secret_key);
            auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
                    cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

            // joint evaluation multiplication key for (s_a + s_b)
            auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);

            auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());

            auto eval_mult_bab = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());

            auto eval_sum_keys_b =
                    cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());

            auto eval_sum_keys_join =
                    cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());

            cc->insert_eval_sum_key(eval_sum_keys_join);

            auto eval_mult_aab = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());

            auto eval_mult_final =
                    cc->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab, eval_mult_ab->get_key_tag());

            cc->insert_eval_mult_key({eval_mult_final});

            std::vector<std::complex<double>> input({-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0});
            std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0,
                                              0.00119324, 0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});
            std::vector<double> result{0.504497, 0.511855, 0.529766, 0.566832, 0.622459,
                                       0.675039, 0.706987, 0.721632, 0.727508};
            double a = -4;
            double b = 4;

            Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input);
            auto ciphertext1 = cc->encrypt(kp2.public_key, plaintext1);
            ciphertext1 = cc->eval_chebyshev_series(ciphertext1, coefficients, a, b);

            // INTERACTIVE BOOTSTRAPPING STARTS
            ciphertext1 = cc->int_boot_adjust_scale(ciphertext1);

            // masked decryption on the server: c0 = b + a*s0
            auto ciphertext_output1 = cc->int_boot_decrypt(kp1.secret_key, ciphertext1);

            auto ciphertext2 = ciphertext1->clone();
            ciphertext2->set_elements({ciphertext2->get_elements()[1]});

            // masked decryption on the client: c1 = a*s1
            auto ciphertext_output2 = cc->int_boot_decrypt(kp2.secret_key, ciphertext2);

            // Encryption of masked decryption c1 = a*s1
            ciphertext_output2 = cc->int_boot_encrypt(kp2.public_key, ciphertext_output2);

            // Compute Enc(c1) + c0
            auto ciphertext_output = cc->int_boot_add(ciphertext_output2, ciphertext_output1);

            // INTERACTIVE BOOTSTRAPPING ENDS

            auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_output}, kp1.secret_key);
            auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);

            std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
            partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
            partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

            Plaintext plaintext_multiparty;
            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);
            plaintext_multiparty->set_length(input.size());
            ciphertext_output = cc->eval_chebyshev_series(ciphertext_output, coefficients, a, b);

            ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_output}, kp1.secret_key);
            ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);
            partial_ciphertext_vec.resize(0);
            partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
            partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

            cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);

            plaintext_multiparty->set_length(input.size());

            check_equality(plaintext_multiparty->get_real_packed_value(), result, eps,
                           failmsg + " Interactive multiparty bootstrapping (Chebyshev2) fails");
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
TEST_P(UTCKKSRNS_INTERACTIVE_BOOT, InteractiveBoot) {
    setup_signals();
    auto test = GetParam();

    if (!test.skip_test()) {
        switch (test.test_case_type) {
            case INTERACTIVE_MP_BOOT:
                unit_test_multi_party_boot(test, test.build_test_name());
                break;
            case INTERACTIVE_MP_BOOT_CHEBYSHEV:
                unit_test_multi_party_boot_chebyshev(test, test.build_test_name());
                break;
#if CIPHER_NATIVE_INT != 128
            case INTERACTIVE_MP_BOOT_ENCRYPT_2PARTY_ONLY:
                unit_test_multi_party_boot_encrypt2(test, test.build_test_name());
                break;
            case INTERACTIVE_MP_BOOT_DECRYPT_2PARTY_ONLY:
                unit_test_multi_party_boot_decrypt2(test, test.build_test_name());
                break;
            case INTERACTIVE_MP_BOOT_THRESHOLD_FHE_2PARTY_ONLY:
                unit_test_multi_party_boot_threshold_fhe2(test, test.build_test_name());
                break;
            case INTERACTIVE_MP_BOOT_CHEBYSHEV_2PARTY_ONLY:
                unit_test_multi_party_boot_chebyshev2(test, test.build_test_name());
                break;
#endif
            default:
                break;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_INTERACTIVE_BOOT,
                         ::testing::ValuesIn(test_cases_utckksrns_interactive_boot), make_test_name);
