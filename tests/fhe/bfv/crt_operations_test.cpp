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
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/encoding/encodings.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/util/debug.h"

using namespace cipher;

class UTBFVRNS_CRT : public ::testing::Test {
  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

  public:
};

void bfv_rns_test_multiplicative_depth_limitation(MultiplicationTechnique multiplication_technique,
                                                  uint32_t multiplicative_depth) {
    ContextParams<BfvRnsContext> parameters;
    const uint64_t ptm = 786433;

    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(multiplicative_depth);

    parameters.set_multiplication_technique(multiplication_technique);

    // For speed
    parameters.set_security_level(SecurityLevel::HEStd_NotSet);
    parameters.set_ring_dim(32);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // Enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    // Generate a public/private key pair
    key_pair = crypto_context->key_gen();

    // Generate the relinearization key

    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    // First plaintext vector is encoded
    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

    size_t expected_result_size =
            (vector_of_ints1.size() < vector_of_ints2.size()) ? vector_of_ints1.size() : vector_of_ints2.size();
    std::vector<int64_t> expected_result(expected_result_size);
    for (size_t i = 0; i < expected_result_size; ++i) {
        expected_result[i] = vector_of_ints1[i] * vector_of_ints2[i];
    }
    Plaintext expected_plaintext = crypto_context->make_packed_plaintext(expected_result);

    // The encoded vectors are encrypted
    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

    // Homomorphic multiplications
    auto ciphertext_mul12 = crypto_context->eval_mult(ciphertext1, ciphertext2);

    // Decrypt the result of multiplications
    Plaintext plaintext_mult_result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12, &plaintext_mult_result);
    plaintext_mult_result->set_length(expected_result_size);
    std::vector<int64_t> decvec = plaintext_mult_result->get_packed_value();
    Plaintext d_res = crypto_context->make_packed_plaintext(decvec);

    EXPECT_EQ(plaintext_mult_result, expected_plaintext);
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_BEHZ) {
    bfv_rns_test_multiplicative_depth_limitation(BEHZ, 32);
    bfv_rns_test_multiplicative_depth_limitation(BEHZ, 33);
    bfv_rns_test_multiplicative_depth_limitation(BEHZ, 34);

    if (CIPHER_MATH_BACKEND != 2) {
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 65);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 66);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 67);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 68);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 99);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 100);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 101);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 102);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 132);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 133);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 134);
        bfv_rns_test_multiplicative_depth_limitation(BEHZ, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPS) {
    bfv_rns_test_multiplicative_depth_limitation(HPS, 33);
    bfv_rns_test_multiplicative_depth_limitation(HPS, 32);
    bfv_rns_test_multiplicative_depth_limitation(HPS, 34);

    if (CIPHER_MATH_BACKEND != 2) {
        bfv_rns_test_multiplicative_depth_limitation(HPS, 65);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 66);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 67);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 68);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 99);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 100);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 101);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 102);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 132);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 133);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 134);
        bfv_rns_test_multiplicative_depth_limitation(HPS, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPSPOVERQ) {
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 32);
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 33);
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 34);

    if (CIPHER_MATH_BACKEND != 2) {
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 65);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 66);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 67);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 68);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 99);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 100);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 134);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQ, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPSPOVERQLEVELED) {
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 32);
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 33);
    bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 34);

    if (CIPHER_MATH_BACKEND != 2) {
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 65);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 66);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 67);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 68);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 99);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 100);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 134);
        bfv_rns_test_multiplicative_depth_limitation(HPSPOVERQLEVELED, 135);
    }
}

TEST_F(UTBFVRNS_CRT, BFVrns_FastBaseConvqToBskMontgomery) {
    TestContextParams parameters;
    parameters.scheme_id_value = BFVRNS_SCHEME;
    parameters.plaintext_modulus = 65537;
    parameters.standard_deviation = 3.19;
    parameters.max_relin_sk_deg = 2;
    parameters.scal_tech = NORESCALE;
    parameters.num_large_digits = 0;
    parameters.multiplicative_depth = 2;
    parameters.scaling_mod_size = 60;
    parameters.ks_tech = BV;
    parameters.digit_size = 20;
    parameters.security_level = HEStd_NotSet;
    parameters.ring_dimension_value = 8;
    parameters.first_mod_size_value = 60;
    parameters.batch_size = 8;
    parameters.secret_key_dist = UNIFORM_TERNARY;
    parameters.multiplication_technique = BEHZ;

    CryptoContext<Element> cc(unit_test_generate_context(parameters));

    const std::shared_ptr<RnsParams<BigInteger>> params = cc->get_crypto_parameters()->get_element_params();

    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters());

    // Generate the element "a" of the public key
    RnsPoly a(params, Format::EVALUATION);

    uint32_t m1 = 16;
    NativeInteger modulus0 = 1152921504606846577;
    NativeInteger modulus1 = 1152921504606846097;
    NativeInteger root_of_unity0(root_of_unity(m1, modulus0));
    NativeInteger root_of_unity1(root_of_unity(m1, modulus1));

    NativePolyParams poly_params0(m1, modulus0, root_of_unity0);
    NativePolyParams poly_params1(m1, modulus1, root_of_unity1);
    auto x0p = std::make_shared<NativePolyParams>(poly_params0);
    auto x1p = std::make_shared<NativePolyParams>(poly_params1);

    NativePoly poly0(x0p, Format::EVALUATION);
    NativePoly poly1(x1p, Format::EVALUATION);
    poly0 = {611651427055975783, 739811248882229946, 790810915716521716, 536363726228107588,
             647651536262422014, 322042217691169971, 138609670727909932, 793736138075446811};
    poly1 = {846754661443099927,  602279558317502186, 342175723088143584, 904036735987820179,
             1124341799555345257, 885339199454111253, 417243638107713607, 548811148460128084};

    a.set_element_at_index(0, poly0);
    a.set_element_at_index(1, poly1);

    a.fast_base_convq_to_bsk_montgomery(
            crypto_params->get_params_q_bsk(), crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
            crypto_params->get_modbsk_barrett_mu(), crypto_params->get_mtilde_q_hat_inv_modq(),
            crypto_params->get_mtilde_q_hat_inv_modq_precon(), crypto_params->get_q_hat_modbsk(),
            crypto_params->get_q_hat_modmtilde(), crypto_params->get_q_modbsk(), crypto_params->get_q_modbsk_precon(),
            crypto_params->get_neg_q_inv_modmtilde(), crypto_params->get_mtilde_inv_modbsk(),
            crypto_params->get_mtilde_inv_modbsk_precon());

    NativeInteger modulus2 = 1152921504606845777;
    NativeInteger modulus3 = 1152921504606845473;
    NativeInteger modulus4 = 1152921504606844913;
    NativeInteger root_of_unity2(root_of_unity(m1, modulus2));
    NativeInteger root_of_unity3(root_of_unity(m1, modulus3));
    NativeInteger root_of_unity4(root_of_unity(m1, modulus4));

    NativePolyParams poly_params2(m1, modulus2, root_of_unity2);
    NativePolyParams poly_params3(m1, modulus3, root_of_unity3);
    NativePolyParams poly_params4(m1, modulus4, root_of_unity4);
    auto x2p = std::make_shared<NativePolyParams>(poly_params2);
    auto x3p = std::make_shared<NativePolyParams>(poly_params3);
    auto x4p = std::make_shared<NativePolyParams>(poly_params4);
    NativePoly ans0(x0p, Format::EVALUATION);
    NativePoly ans1(x1p, Format::EVALUATION);
    NativePoly ans2(x2p, Format::EVALUATION);
    NativePoly ans3(x3p, Format::EVALUATION);
    NativePoly ans4(x4p, Format::EVALUATION);
    ans0 = {611651427055975783, 739811248882229946, 790810915716521716, 536363726228107588,
            647651536262422014, 322042217691169971, 138609670727909932, 793736138075446811};
    ans1 = {846754661443099927,  602279558317502186, 342175723088143584, 904036735987820179,
            1124341799555345257, 885339199454111253, 417243638107713607, 548811148460128084};
    ans2 = {524228833460429474, 692928367413813885, 465662343623521646, 107498520099165490,
            81602760285107383,  482417615916109741, 249076385001962496, 719980682178715834};
    ans3 = {474506930637362424, 723790960760608304, 7991172453764409,   738286918217632692,
            933904287195446155, 98490114749039532,  293617451261147895, 1050780276990075548};
    ans4 = {612459830520599999, 273948808875966259, 276211279884817131,  805184382328000673,
            605603488049806384, 756318612975583592, 1014214483788531002, 480836070509458175};

    EXPECT_EQ(a.get_element_at_index(0), ans0);
    EXPECT_EQ(a.get_element_at_index(1), ans1);
    EXPECT_EQ(a.get_element_at_index(2), ans2);
    EXPECT_EQ(a.get_element_at_index(3), ans3);
    EXPECT_EQ(a.get_element_at_index(4), ans4);
}

// TODO (dsuponit): review and fix multiple errors in this file
TEST_F(UTBFVRNS_CRT, BFVrns_FastExpandCRTBasisPloverQ) {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_ring_dim(8);
    parameters.set_multiplicative_depth(2);
    parameters.set_digit_size(20);
    parameters.set_batch_size(8);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_multiplication_technique(HPSPOVERQ);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    const std::shared_ptr<RnsParams<BigInteger>> params = cc->get_crypto_parameters()->get_element_params();

    const auto crypto_params_bfv_rns = std::dynamic_pointer_cast<BfvRnsCryptoParams>(cc->get_crypto_parameters());

    size_t size_q = 2;

    // Generate the element "a" of the public key
    RnsPoly a(params, Format::COEFFICIENT);

    uint32_t m1 = 16;
    NativeInteger modulus0 = NativeInteger("1152921504606846577");
    NativeInteger modulus1 = NativeInteger("1152921504606846097");
    NativeInteger root_of_unity0(root_of_unity(m1, modulus0));
    NativeInteger root_of_unity1(root_of_unity(m1, modulus1));

    NativePolyParams poly_params0(m1, modulus0, root_of_unity0);
    NativePolyParams poly_params1(m1, modulus1, root_of_unity1);
    auto x0p = std::make_shared<NativePolyParams>(poly_params0);
    auto x1p = std::make_shared<NativePolyParams>(poly_params1);

    NativePoly poly0(x0p, Format::COEFFICIENT);
    NativePoly poly1(x1p, Format::COEFFICIENT);
    poly0 = {242947838436205858, 458804958636264704, 813208723994158017, 738376275125875131,
             269337450701982501, 633721177525656427, 406635995163024073, 763204304316606329};
    poly1 = {1024863409567898083, 845721255474383902,  537504300724180111, 1018489837930110795,
             112800627588840746,  1119710169440476902, 77894506676832730,  34149187620514595};

    a.set_element_at_index(0, poly0);
    a.set_element_at_index(1, poly1);

    auto param1 = crypto_params_bfv_rns->get_params_ql_rl(size_q - 1);
    auto param2 = crypto_params_bfv_rns->get_params_rl(size_q - 1);
    auto param3 = crypto_params_bfv_rns->get_params_ql(size_q - 1);
    auto param4 = crypto_params_bfv_rns->get_m_neg_rl_q_hat_inv_modq(size_q - 1);
    auto param5 = crypto_params_bfv_rns->get_m_neg_rl_q_hat_inv_modq_precon(size_q - 1);
    auto param6 = crypto_params_bfv_rns->get_q_inv_modr();
    auto param7 = crypto_params_bfv_rns->get_modr_barrett_mu();
    auto param8 = crypto_params_bfv_rns->get_rl_hat_inv_modr(size_q - 1);
    auto param9 = crypto_params_bfv_rns->get_rl_hat_inv_modr_precon(size_q - 1);
    auto param10 = crypto_params_bfv_rns->get_rl_hat_modq(size_q - 1);
    auto param11 = crypto_params_bfv_rns->get_alpha_rl_modq(size_q - 1);
    auto param12 = crypto_params_bfv_rns->get_modq_barrett_mu();
    auto param13 = crypto_params_bfv_rns->get_r_inv();
    RnsPoly::CrtBasisExtensionPrecomputations basis_pq(param1, param2, param3, param4, param5, param6, param7, param8,
                                                       param9, param10, param11, param12, param13);

    a.fast_expand_crt_basis_plover_q(basis_pq);

    NativeInteger modulus2 = NativeInteger("1152921504606845777");
    NativeInteger modulus3 = NativeInteger("1152921504606845473");
    NativeInteger root_of_unity2(root_of_unity(m1, modulus2));
    NativeInteger root_of_unity3(root_of_unity(m1, modulus3));

    NativePolyParams poly_params2(m1, modulus2, root_of_unity2);
    NativePolyParams poly_params3(m1, modulus3, root_of_unity3);
    auto x2p = std::make_shared<NativePolyParams>(poly_params2);
    auto x3p = std::make_shared<NativePolyParams>(poly_params3);
    NativePoly ans0(x0p, Format::COEFFICIENT);
    NativePoly ans1(x1p, Format::COEFFICIENT);
    NativePoly ans2(x2p, Format::COEFFICIENT);
    NativePoly ans3(x3p, Format::COEFFICIENT);

#if defined(CIPHER_WITH_REDUCED_NOISE)
    ans0 = {805568738929329615, 1078766251747424581, 785656076316475931, 599125608237504783,
            541576441836927289, 152721755350883625,  574857357780891059, 1081393409810468824};
    ans1 = {434562805454153183, 312761043978375122, 509951653046700585, 879239171041671807,
            385039618723450974, 638710747265582660, 246115869294473636, 352338293114574370};
    ans2 = {955839852875274613,  186398073668078475, 710455872402389880, 1065981546244475423,
            1049296073052489282, 578396240339812091, 26954876970280154,  1019223053257416911};
    ans3 = {874592295621923163, 585167928946466636, 612704504638527026, 551633899923050544,
            758002500979691773, 694035684451390661, 625796987487151014, 96319544173820806};
#else
    ans0 = {805568738929329616, 1078766251747424582, 785656076316475932, 599125608237504784,
            541576441836927290, 152721755350883626,  574857357780891061, 1081393409810468825};
    ans1 = {434562805454153184, 312761043978375123, 509951653046700586, 879239171041671808,
            385039618723450975, 638710747265582661, 246115869294473638, 352338293114574371};
    ans2 = {955839852875274614,  186398073668078476, 710455872402389881, 1065981546244475424,
            1049296073052489283, 578396240339812092, 26954876970280156,  1019223053257416912};
    ans3 = {874592295621923164, 585167928946466637, 612704504638527027, 551633899923050545,
            758002500979691774, 694035684451390662, 625796987487151016, 96319544173820807};
#endif

    EXPECT_EQ(a.get_element_at_index(0), ans0);
    EXPECT_EQ(a.get_element_at_index(1), ans1);
    EXPECT_EQ(a.get_element_at_index(2), ans2);
    EXPECT_EQ(a.get_element_at_index(3), ans3);
}

TEST_F(UTBFVRNS_CRT, BFVrns_SwitchCRTBasis) {
    ContextParams<BfvRnsContext> parameters;
    uint32_t ptm = 1 << 31;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_multiplicative_depth(7);
    parameters.set_max_relin_sk_deg(8);
    parameters.set_scaling_mod_size(60);
    parameters.set_multiplication_technique(HPS);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    const std::shared_ptr<RnsParams<BigInteger>> params = crypto_context->get_crypto_parameters()->get_element_params();

    const auto crypto_params_bfv_rns =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(crypto_context->get_crypto_parameters());

    const std::shared_ptr<RnsParams<BigInteger>> params_r = crypto_params_bfv_rns->get_params_rl();

    typename RnsPoly::DugType dug;

    // Generate the element "a" of the public key
    const RnsPoly a(dug, params, Format::COEFFICIENT);

    Poly result_a = a.crt_interpolate();

    const RnsPoly b = a.switch_crt_basis(
            params_r, crypto_params_bfv_rns->get_ql_hat_inv_modq(), crypto_params_bfv_rns->get_ql_hat_inv_modq_precon(),
            crypto_params_bfv_rns->get_ql_hat_modr(), crypto_params_bfv_rns->get_alpha_ql_modr(),
            crypto_params_bfv_rns->get_modr_barrett_mu(), crypto_params_bfv_rns->get_q_inv());

    Poly result_b = b.crt_interpolate();

    BigInteger A0 = result_a.at(0);

    if (A0 > (params->get_modulus() >> 1))
        A0 = params->get_modulus() - A0;

    BigInteger B0 = result_b.at(0);

    if (B0 > (params_r->get_modulus() >> 1))
        B0 = params_r->get_modulus() - B0;

    EXPECT_EQ(A0, B0) << "switch_crt_basis produced incorrect results";
}

// TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL
TEST_F(UTBFVRNS_CRT, BFVrns_Mult_by_Constant) {
    ContextParams<BfvRnsContext> parameters;
    uint32_t ptm = 1 << 15;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_scaling_mod_size(60);
    parameters.set_multiplication_technique(HPS);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    const std::shared_ptr<RnsParams<BigInteger>> params_q =
            crypto_context->get_crypto_parameters()->get_element_params();

    const auto crypto_params_bfv_rns =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(crypto_context->get_crypto_parameters());

    const std::shared_ptr<RnsParams<BigInteger>> params_r = crypto_params_bfv_rns->get_params_rl();

    const std::shared_ptr<RnsParams<BigInteger>> params_qr = crypto_params_bfv_rns->get_params_ql_rl();

    typename RnsPoly::DugType dug;

    // Generate uninform element
    RnsPoly a(dug, params_q, Format::COEFFICIENT);

    // Generate constant element
    RnsPoly b(params_q, Format::COEFFICIENT, true);
    b = b + (uint64_t)1976860313128;
    b = b.negate();

    Poly a_poly = a.crt_interpolate();

    Poly b_poly = b.crt_interpolate();

    a.expand_crt_basis(params_qr, params_r, crypto_params_bfv_rns->get_ql_hat_inv_modq(),
                       crypto_params_bfv_rns->get_ql_hat_inv_modq_precon(), crypto_params_bfv_rns->get_ql_hat_modr(),
                       crypto_params_bfv_rns->get_alpha_ql_modr(), crypto_params_bfv_rns->get_modr_barrett_mu(),
                       crypto_params_bfv_rns->get_q_inv(), Format::EVALUATION);

    b.expand_crt_basis(params_qr, params_r, crypto_params_bfv_rns->get_ql_hat_inv_modq(),
                       crypto_params_bfv_rns->get_ql_hat_inv_modq_precon(), crypto_params_bfv_rns->get_ql_hat_modr(),
                       crypto_params_bfv_rns->get_alpha_ql_modr(), crypto_params_bfv_rns->get_modr_barrett_mu(),
                       crypto_params_bfv_rns->get_q_inv(), Format::EVALUATION);

    auto tmp{b};
    tmp.set_format(Format::COEFFICIENT);
    Poly result_expanded_b = tmp.crt_interpolate();

    BigInteger A0 = b_poly.at(0);

    if (A0 > (b_poly.get_modulus() >> 1))
        A0 = b_poly.get_modulus() - A0;

    BigInteger B0 = result_expanded_b.at(0);

    if (B0 > (result_expanded_b.get_modulus() >> 1))
        B0 = result_expanded_b.get_modulus() - B0;

    EXPECT_EQ(A0, B0) << "CRT expansion of polynomial b worked incorrectly";

    // a and b are already in evaluation representation after expand_crt_basis

    // Polynomial multiplication in Q*S CRT basis
    RnsPoly c = a * b;

    c.set_format(Format::COEFFICIENT);

    Poly result_c = c.crt_interpolate();

    // Starting multiprecision polynomial multiplication

    BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
    BigInteger root("859703842628303907691187858658134128225754111718143879712783");
    uint32_t m = 8192;

    auto params_poly = std::make_shared<PolyParams>(m, modulus, root);

    a_poly.switch_modulus(modulus, root, 0, 0);
    b_poly.switch_modulus(modulus, root, 0, 0);

    a_poly.set_format(Format::EVALUATION);
    b_poly.set_format(Format::EVALUATION);

    // Polynomial multiplication in Q*S CRT basis
    Poly c_poly = a_poly * b_poly;

    c_poly.set_format(Format::COEFFICIENT);

    // Ended multiprecision multiplication

    A0 = c_poly.at(0);

    if (A0 > (c_poly.get_modulus() >> 1))
        A0 = c_poly.get_modulus() - A0;

    B0 = result_c.at(0);

    if (B0 > (result_c.get_modulus() >> 1))
        B0 = result_c.get_modulus() - B0;

    EXPECT_EQ(A0, B0) << "Results of multiprecision and CRT multiplication do not match";

    RnsPoly rounded = c.scale_and_round(params_r, crypto_params_bfv_rns->get_t_rs_hat_inv_mods_divs_modr(),
                                        crypto_params_bfv_rns->get_t_rs_hat_inv_mods_divs_frac(),
                                        crypto_params_bfv_rns->get_modr_barrett_mu());

    RnsPoly rounded_q = rounded.switch_crt_basis(
            params_q, crypto_params_bfv_rns->get_rl_hat_inv_modr(), crypto_params_bfv_rns->get_rl_hat_inv_modr_precon(),
            crypto_params_bfv_rns->get_rl_hat_modq(), crypto_params_bfv_rns->get_alpha_rl_modq(),
            crypto_params_bfv_rns->get_modq_barrett_mu(), crypto_params_bfv_rns->get_r_inv());

    Poly result_rounded_q = rounded_q.crt_interpolate();

    Poly rounded_mp = c_poly.multiply_and_round(BigInteger(ptm), rounded_q.get_modulus());

    A0 = rounded_mp.at(0);

    if (A0 > (rounded_mp.get_modulus() >> 1))
        A0 = rounded_mp.get_modulus() - A0;

    B0 = result_rounded_q.at(0);

    if (B0 > (result_rounded_q.get_modulus() >> 1))
        B0 = result_rounded_q.get_modulus() - B0;

    // uint64_t result = (A0 + BigInteger(2) - B0).convert_to_int();

    // EXPECT_TRUE((result >= 1) && (result <= 3)) << "Results of multiprecision
    // and CRT multiplication after scaling + rounding do not match";
}

// TESTING POLYNOMIAL MULTIPLICATION - UNIFORM AND GAUSSIAN RANDOM POLYNOMIALS
TEST_F(UTBFVRNS_CRT, BFVrns_Mult_by_Gaussian) {
    ContextParams<BfvRnsContext> parameters;
    uint32_t ptm = 1 << 15;
    parameters.set_plaintext_modulus(ptm);
    parameters.set_scaling_mod_size(60);
    parameters.set_multiplication_technique(HPS);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    const std::shared_ptr<RnsParams<BigInteger>> params_q =
            crypto_context->get_crypto_parameters()->get_element_params();

    const auto crypto_params_bfv_rns =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(crypto_context->get_crypto_parameters());

    const std::shared_ptr<RnsParams<BigInteger>> params_r = crypto_params_bfv_rns->get_params_rl();

    const std::shared_ptr<RnsParams<BigInteger>> params_qr = crypto_params_bfv_rns->get_params_ql_rl();

    typename RnsPoly::DugType dug;

    // Generate uninform element
    RnsPoly a(dug, params_q, Format::COEFFICIENT);

    // dgg with distribution parameter 400000
    typename RnsPoly::DggType dgg(400000);

    // Generate Discrete Gaussian element
    RnsPoly b(dgg, params_q, Format::COEFFICIENT);

    Poly a_poly = a.crt_interpolate();

    Poly b_poly = b.crt_interpolate();

    a.expand_crt_basis(params_qr, params_r, crypto_params_bfv_rns->get_ql_hat_inv_modq(),
                       crypto_params_bfv_rns->get_ql_hat_inv_modq_precon(), crypto_params_bfv_rns->get_ql_hat_modr(),
                       crypto_params_bfv_rns->get_alpha_ql_modr(), crypto_params_bfv_rns->get_modr_barrett_mu(),
                       crypto_params_bfv_rns->get_q_inv(), Format::EVALUATION);

    b.expand_crt_basis(params_qr, params_r, crypto_params_bfv_rns->get_ql_hat_inv_modq(),
                       crypto_params_bfv_rns->get_ql_hat_inv_modq_precon(), crypto_params_bfv_rns->get_ql_hat_modr(),
                       crypto_params_bfv_rns->get_alpha_ql_modr(), crypto_params_bfv_rns->get_modr_barrett_mu(),
                       crypto_params_bfv_rns->get_q_inv(), Format::EVALUATION);

    auto tmp{b};
    tmp.set_format(Format::COEFFICIENT);
    Poly result_expanded_b = tmp.crt_interpolate();

    BigInteger A0 = b_poly.at(0);

    if (A0 > (b_poly.get_modulus() >> 1))
        A0 = b_poly.get_modulus() - A0;

    BigInteger B0 = result_expanded_b.at(0);

    if (B0 > (result_expanded_b.get_modulus() >> 1))
        B0 = result_expanded_b.get_modulus() - B0;

    EXPECT_EQ(A0, B0) << "CRT expansion of polynomial b worked incorrectly";

    // a and b are already in evaluation representation after expand_crt_basis

    // Polynomial multiplication in Q*S CRT basis
    RnsPoly c = a * b;

    c.set_format(Format::COEFFICIENT);

    Poly result_c = c.crt_interpolate();

    // Starting multiprecision polynomial multiplication

    BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
    BigInteger root("859703842628303907691187858658134128225754111718143879712783");
    uint32_t m = 8192;

    auto params_poly = std::make_shared<PolyParams>(m, modulus, root);

    a_poly.switch_modulus(modulus, root, 0, 0);
    b_poly.switch_modulus(modulus, root, 0, 0);

    a_poly.set_format(Format::EVALUATION);
    b_poly.set_format(Format::EVALUATION);

    // Polynomial multiplication in Q*S CRT basis
    Poly c_poly = a_poly * b_poly;

    c_poly.set_format(Format::COEFFICIENT);

    // Ended multiprecision multiplication

    A0 = c_poly.at(0);

    if (A0 > (c_poly.get_modulus() >> 1))
        A0 = c_poly.get_modulus() - A0;

    B0 = result_c.at(0);

    if (B0 > (result_c.get_modulus() >> 1))
        B0 = result_c.get_modulus() - B0;

    // TODO (andrey) fix this part of the test
    //  EXPECT_EQ(A0, B0)
    //      << "Results of multiprecision and CRT multiplication do not match";

    RnsPoly rounded = c.scale_and_round(params_r, crypto_params_bfv_rns->get_t_rs_hat_inv_mods_divs_modr(),
                                        crypto_params_bfv_rns->get_t_rs_hat_inv_mods_divs_frac(),
                                        crypto_params_bfv_rns->get_modr_barrett_mu());

    RnsPoly rounded_q = rounded.switch_crt_basis(
            params_q, crypto_params_bfv_rns->get_rl_hat_inv_modr(), crypto_params_bfv_rns->get_rl_hat_inv_modr_precon(),
            crypto_params_bfv_rns->get_rl_hat_modq(), crypto_params_bfv_rns->get_alpha_rl_modq(),
            crypto_params_bfv_rns->get_modq_barrett_mu(), crypto_params_bfv_rns->get_r_inv());

    Poly result_rounded_q = rounded_q.crt_interpolate();

    Poly rounded_mp = c_poly.multiply_and_round(BigInteger(ptm), rounded_q.get_modulus());

    A0 = rounded_mp.at(0);

    if (A0 > (rounded_mp.get_modulus() >> 1))
        A0 = rounded_mp.get_modulus() - A0;

    B0 = result_rounded_q.at(0);

    if (B0 > (result_rounded_q.get_modulus() >> 1))
        B0 = result_rounded_q.get_modulus() - B0;

    // uint64_t result = (A0 + BigInteger(2) - B0).convert_to_int();

    // EXPECT_TRUE((result >= 1) && (result <= 3)) <<  "Results of multiprecision
    // and CRT multiplication after scaling + rounding do not match";
}
