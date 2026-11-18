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

#include <cmath>
#include <cstdint>
#include <iostream>
#include <memory>
#include <utility>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/ring/trapdoor.h"
#include "cipher/ring/trapdoor_params.h"
#include "cipher/math/distributions.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

class UnitTestTrapdoor : public ::testing::Test {
  protected:
    virtual void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    virtual void TearDown() {
        cipher_parallel_controls.unit_test_stop();
    }
};

/************************************************/
/*  TESTING METHODS OF TRAPDOOR CLASS    */
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

TEST(UTTrapdoor, randomized_round) {
    //  It compiles! ...
    // RandomizeRound(0, 4.3, 1024);
}

TEST(UTTrapdoor, sizes) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    float stddev = 4;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    auto fast_params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair =
            RlweTrapdoorUtility<Poly>::trapdoor_gen(fast_params, stddev);

    EXPECT_EQ(1U, trap_pair.first.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k + 2, trap_pair.first.get_cols()) << "Failure testing number of colums";

    EXPECT_EQ(1U, trap_pair.second.r_.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trap_pair.second.r_.get_cols()) << "Failure testing number of colums";

    EXPECT_EQ(1U, trap_pair.second.e_.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trap_pair.second.e_.get_cols()) << "Failure testing number of colums";
}

TEST(UTTrapdoor, TrapDoorPairTest) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    float stddev = 4;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair = RlweTrapdoorUtility<Poly>::trapdoor_gen(params, stddev);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;
    Matrix<Poly> eye_kk = Matrix<Poly>(zero_alloc, k, k).identity();

    // std::cout << e_hat <<std::endl;
    // std::cout << r_hat <<std::endl;
    // std::cout << eye_kk <<std::endl;

    Matrix<Poly> stacked_trap1 = e_hat.v_stack(r_hat);
    // std::cout << stacked_trap2 <<std::endl;

    EXPECT_EQ(2U, stacked_trap1.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, stacked_trap1.get_cols()) << "Failure testing number of colums";

    Matrix<Poly> stacked_trap2 = stacked_trap1.v_stack(eye_kk);

    EXPECT_EQ(k + 2, stacked_trap2.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, stacked_trap2.get_cols()) << "Failure testing number of colums";

    // Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).gadget_vector();
}

TEST(UTTrapdoor, TrapDoorPairTestSquareMat) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    float stddev = 4;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::ceil(std::log2(val));
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    size_t d = 5;

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair =
            RlweTrapdoorUtility<Poly>::trapdoor_gen_square_mat(params, stddev, d);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;
    Matrix<Poly> eye_kk = Matrix<Poly>(zero_alloc, d * k, d * k).identity();

    Matrix<Poly> stacked_trap1 = r_hat.v_stack(e_hat);
    // std::cout << stacked_trap2 <<std::endl;

    EXPECT_EQ(2 * d, stacked_trap1.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, stacked_trap1.get_cols()) << "Failure testing number of colums";

    Matrix<Poly> stacked_trap2 = stacked_trap1.v_stack(eye_kk);

    EXPECT_EQ(d * (k + 2), stacked_trap2.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, stacked_trap2.get_cols()) << "Failure testing number of colums";

    // Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).gadget_vector();
}

TEST(UTTrapdoor, GadgetTest) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).gadget_vector();

    EXPECT_EQ(1U, g.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, g.get_cols()) << "Failure testing number of colums";
}

TEST(UTTrapdoor, TrapDoorMultTest) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    float stddev = 4;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair = RlweTrapdoorUtility<Poly>::trapdoor_gen(params, stddev);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;
    Matrix<Poly> eye_kk = Matrix<Poly>(zero_alloc, k, k).identity();

    // std::cout << e_hat <<std::endl;
    // std::cout << r_hat <<std::endl;
    // std::cout << eye_kk <<std::endl;

    Matrix<Poly> stacked_trap1 = e_hat.v_stack(r_hat);
    Matrix<Poly> stacked_trap2 = stacked_trap1.v_stack(eye_kk);

    Matrix<Poly> trap_mult = (trap_pair.first) * (stacked_trap2);
    EXPECT_EQ(1U, trap_mult.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trap_mult.get_cols()) << "Failure testing number of colums";

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).gadget_vector();
    EXPECT_EQ(g, trap_mult);
}

TEST(UTTrapdoor, TrapDoorMultTestSquareMat) {
    uint32_t m = 16;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    float stddev = 4;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::ceil(std::log2(val));
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    size_t d = 5;

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair =
            RlweTrapdoorUtility<Poly>::trapdoor_gen_square_mat(params, stddev, d);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;
    Matrix<Poly> eye_kk = Matrix<Poly>(zero_alloc, d * k, d * k).identity();

    Matrix<Poly> stacked_trap1 = r_hat.v_stack(e_hat);
    Matrix<Poly> stacked_trap2 = stacked_trap1.v_stack(eye_kk);

    Matrix<Poly> trap_mult = (trap_pair.first) * (stacked_trap2);
    EXPECT_EQ(d, trap_mult.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, trap_mult.get_cols()) << "Failure testing number of colums";

    Matrix<Poly> G = Matrix<Poly>(zero_alloc, d, d * k).gadget_vector();

    // std::cerr << G << std::endl;

    EXPECT_EQ(G, trap_mult);
}

TEST(UTTrapdoor, TrapDoorGaussGqSampTest) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("start tests");
    uint32_t m = 16;
    uint32_t n = m / 2;
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    // BigInteger modulus("134218081");
    // BigInteger root_of_unity_value("19091337");
    // BigInteger modulus("1048609");
    // BigInteger root_of_unity_value("389832");
    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    uint64_t base = 2;
    double sigma = (base + 1) * SIGMA;

    Poly::DggType dgg(sigma);
    Poly::DugType dug;

    CIPHER_DEBUG("1");
    Poly u(dug, params, Format::COEFFICIENT);
    CIPHER_DEBUG("2");
    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    // YSP check log_two computation
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);

    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, m / 2);

    CIPHER_DEBUG("3");
    CIPHER_DEBUG("u " << u);
    CIPHER_DEBUG("sigma " << sigma);
    CIPHER_DEBUG("k " << k);
    CIPHER_DEBUG("modulus " << modulus);

    LatticeGaussSampUtility<Poly>::gauss_samp_gq(u, sigma, k, modulus, base, dgg, &z_hat_bbi);

    EXPECT_EQ(k, z_hat_bbi.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(u.get_length(), z_hat_bbi.get_cols()) << "Failure testing number of colums";
    CIPHER_DEBUG("4");
    Matrix<Poly> z = split_int64_alt_into_elements<Poly>(z_hat_bbi, n, params);
    z.switch_format();

    Poly u_est;
    u_est = (Matrix<Poly>(zero_alloc, 1, k).gadget_vector() * z)(0, 0);
    u_est.switch_format();

    EXPECT_EQ(u, u_est);
    CIPHER_DEBUG("end tests");
}

// this test does not work correctly in the web assembly configuration
// it is not needed for the functionality exposed through the web assembly
#if !defined(__EMSCRIPTEN__) && !defined(__CYGWIN__)
TEST(UTTrapdoor, TrapDoorGaussSampTestDCRT) {
    uint32_t n = 16;  // cyclotomic order
    size_t k_res = 51;
    size_t base = 8;
    size_t size = 4;
    double sigma = SIGMA;

    auto params = std::make_shared<RnsParams<BigInteger>>(2 * n, size, k_res);
    int64_t digit_count =
            static_cast<int64_t>(std::ceil(std::log2((*params)[0]->get_modulus().convert_to_double()) / std::log2(base)));

    std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>> trap_pair =
            RlweTrapdoorUtility<RnsPoly>::trapdoor_gen(params, sigma, base);

    Matrix<RnsPoly> e_hat = trap_pair.second.e_;
    Matrix<RnsPoly> r_hat = trap_pair.second.r_;

    RnsPoly::DggType dgg(sigma);
    RnsPoly::DugType dug;
    RnsPoly u(dug, params, Format::COEFFICIENT);

    uint32_t k = size * digit_count;

    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, k, base);
    RnsPoly::DggType dgg_large_sigma(std::sqrt(s * s - c * c));

    u.switch_format();

    Matrix<RnsPoly> z = RlweTrapdoorUtility<RnsPoly>::gauss_samp(n, k, trap_pair.first, trap_pair.second, u, dgg,
                                                                  dgg_large_sigma, base);

    // Matrix<Poly> u_est = trap_pair.first * z;

    EXPECT_EQ(trap_pair.first.get_cols(), z.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(n, z(0, 0).get_length()) << "Failure testing ring dimension for the first ring element";

    RnsPoly u_est = (trap_pair.first * z)(0, 0);

    u_est.switch_format();
    u.switch_format();

    EXPECT_EQ(u, u_est);
}
#endif

TEST(UTTrapdoor, TrapDoorGaussGqSampTestBase1024) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("start tests");

    uint32_t m = 1024;
    uint32_t n = m / 2;
    BigInteger modulus("8399873");
    BigInteger root_of_unity_value("824894");
    // BigInteger modulus("134218081");
    // BigInteger root_of_unity_value("19091337");
    // BigInteger modulus("1048609");
    // BigInteger root_of_unity_value("389832");
    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);
    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    uint64_t base = 1 << 10;
    double sigma = (base + 1) * SIGMA;

    Poly::DggType dgg(SIGMA);
    Poly::DugType dug;

    CIPHER_DEBUG("1");
    Poly u(dug, params, Format::COEFFICIENT);
    CIPHER_DEBUG("2");
    // double val = modulus.convert_to_double(); //TODO get the next few lines
    // working in a single instance. YSP check log_two computation

    uint32_t n_bits = std::floor(std::log2(modulus.convert_to_double() - 1.0) + 1.0);
    uint32_t k = std::ceil(n_bits / std::log2(base));

    // double log_two = log2(val - 1.0) + 1.0;
    // uint32_t k = (uint32_t)floor(log_two);

    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, m / 2);

    CIPHER_DEBUG("3");
    CIPHER_DEBUG("u " << u);
    CIPHER_DEBUG("sigma " << sigma);
    CIPHER_DEBUG("k " << k);
    CIPHER_DEBUG("modulus " << modulus);
    CIPHER_DEBUG("base = " << base);

    LatticeGaussSampUtility<Poly>::gauss_samp_gq(u, sigma, k, modulus, base, dgg, &z_hat_bbi);

    EXPECT_EQ(k, z_hat_bbi.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(u.get_length(), z_hat_bbi.get_cols()) << "Failure testing number of colums";
    CIPHER_DEBUG("4");

    // int32_t maxValue = 0;

    // for (size_t i = 0; i < z_hat_bbi.get_rows(); i++)
    //  for (size_t j = 0; j < z_hat_bbi.get_cols(); j++)
    //    if (std::abs(z_hat_bbi(i, j)) > maxValue)
    //      maxValue = std::abs(z_hat_bbi(i, j));
    //
    // std::cout << maxValue << std::endl;

    Matrix<Poly> z = split_int64_alt_into_elements<Poly>(z_hat_bbi, n, params);
    CIPHER_DEBUG("4.5");
    // TODO for some reason I must do this before calling switchformat (which
    // uses omp for parallel execution)
    // TODO my guess is there is a race in the calculation/caching of factors
    // underneath, though the critical
    // TODO region *should* address that...
    auto mmm = z.get_data()[0][0];
    mmm.switch_format();

    z.switch_format();

    CIPHER_DEBUG("5");
    Poly u_est;
    u_est = (Matrix<Poly>(zero_alloc, 1, k).gadget_vector(base) * z)(0, 0);
    u_est.switch_format();

    // std::cout << u - u_est << std::endl;

    EXPECT_EQ(u, u_est);
    CIPHER_DEBUG("end tests");
}

// Test of Gaussian Sampling using the UCSD integer perturbation sampling
// algorithm
TEST(UTTrapdoor, TrapDoorGaussSampTest) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("in test");
    uint32_t m = 16;
    uint32_t n = m / 2;

    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    double sigma = SIGMA;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    CIPHER_DEBUG("k = " << k);
    CIPHER_DEBUG("sigma = " << sigma);
    CIPHER_DEBUG("m = " << m);
    CIPHER_DEBUG("modulus = " << modulus);
    CIPHER_DEBUG("root = " << root_of_unity_value);

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair = RlweTrapdoorUtility<Poly>::trapdoor_gen(params, sigma);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;
    // auto uniform_alloc = Poly::make_discrete_uniform_allocator(params,
    // Format::EVALUATION);

    Poly::DggType dgg(sigma);
    Poly::DugType dug;

    uint32_t base = 2;
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, k, base);
    Poly::DggType dgg_large_sigma(std::sqrt(s * s - c * c));

    Poly u(dug, params, Format::COEFFICIENT);

    CIPHER_DEBUG("u " << u);
    u.switch_format();
    CIPHER_DEBUG("u " << u);

    Matrix<Poly> z =
            RlweTrapdoorUtility<Poly>::gauss_samp(m / 2, k, trap_pair.first, trap_pair.second, u, dgg, dgg_large_sigma);

    // Matrix<Poly> u_est = trap_pair.first * z;

    EXPECT_EQ(trap_pair.first.get_cols(), z.get_rows()) << "Failure testing number of rows";
    EXPECT_EQ(m / 2, z(0, 0).get_length()) << "Failure testing ring dimension for the first ring element";

    Poly u_est = (trap_pair.first * z)(0, 0);

    CIPHER_DEBUG("uEst " << u_est);
    CIPHER_DEBUG("u " << u);

    CIPHER_DEBUG("uEst.GetModulus() " << u_est.get_modulus());
    CIPHER_DEBUG("u.GetModulus() " << u.get_modulus());

    u_est.switch_format();
    u.switch_format();

    EXPECT_EQ(u, u_est);

    // std::cout << z << std::endl;
}

// Test of Gaussian Sampling for matrices from 2x2 to 5x5
TEST(UTTrapdoor, TrapDoorGaussSampTestSquareMatrices) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("in test");
    uint32_t m = 16;
    uint32_t n = m / 2;

    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");
    double sigma = SIGMA;

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::ceil(std::log2(val));
    uint32_t k = (uint32_t)(log_two);

    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);

    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);
    auto uniform_alloc = Poly::make_discrete_uniform_allocator(params, Format::EVALUATION);

    for (size_t d = 2; d < 6; d++) {
        std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair =
                RlweTrapdoorUtility<Poly>::trapdoor_gen_square_mat(params, sigma, d);

        Matrix<Poly> R = trap_pair.second.r_;
        Matrix<Poly> E = trap_pair.second.e_;

        Poly::DggType dgg(sigma);

        uint32_t base = 2;
        double c = (base + 1) * SIGMA;
        double s = SPECTRAL_BOUND_D(n, k, base, d);
        Poly::DggType dgg_large_sigma(std::sqrt(s * s - c * c));

        Matrix<Poly> U(zero_alloc, d, d, uniform_alloc);

        Matrix<Poly> z = RlweTrapdoorUtility<Poly>::gauss_samp_square_mat(m / 2, k, trap_pair.first, trap_pair.second, U,
                                                                       dgg, dgg_large_sigma);

        EXPECT_EQ(trap_pair.first.get_cols(), z.get_rows()) << "Failure testing number of rows";
        EXPECT_EQ(m / 2, z(0, 0).get_length()) << "Failure testing ring dimension for the first ring element";

        Matrix<Poly> U_est = trap_pair.first * z;

        U_est.switch_format();
        U.switch_format();

        EXPECT_EQ(U, U_est) << "Failure trapdoor sampling test for " << d << "x" << d << " matrices";
    }
}

// this test does not work correctly in the web assembly configuration
// it is not needed for the functionality exposed through the web assembly
#if !defined(__EMSCRIPTEN__) && !defined(__CYGWIN__)
// Test of Gaussian Sampling for matrices from 2x2 to 5x5
TEST(UTTrapdoor, TrapDoorGaussSampTestSquareMatricesDCRT) {
    uint32_t m = 16;
    uint32_t n = m / 2;
    size_t dcrt_bits = 57;
    size_t size = 3;
    double sigma = SIGMA;

    auto params = std::make_shared<RnsParams<BigInteger>>(2 * n, size, dcrt_bits);

    double val = params->get_modulus().convert_to_double();
    double log_two = std::ceil(std::log2(val));
    uint32_t k = (uint32_t)(log_two);

    auto zero_alloc = RnsPoly::allocator(params, Format::EVALUATION);
    auto uniform_alloc = RnsPoly::make_discrete_uniform_allocator(params, Format::EVALUATION);

    for (size_t d = 2; d < 6; d++) {
        std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>> trap_pair =
                RlweTrapdoorUtility<RnsPoly>::trapdoor_gen_square_mat(params, sigma, d);

        Matrix<RnsPoly> R = trap_pair.second.r_;
        Matrix<RnsPoly> E = trap_pair.second.e_;

        RnsPoly::DggType dgg(sigma);

        uint32_t base = 2;
        double c = (base + 1) * SIGMA;
        double s = SPECTRAL_BOUND_D(n, k, base, d);
        RnsPoly::DggType dgg_large_sigma(std::sqrt(s * s - c * c));

        Matrix<RnsPoly> U(zero_alloc, d, d, uniform_alloc);

        Matrix<RnsPoly> z = RlweTrapdoorUtility<RnsPoly>::gauss_samp_square_mat(m / 2, k, trap_pair.first,
                                                                               trap_pair.second, U, dgg, dgg_large_sigma);

        EXPECT_EQ(trap_pair.first.get_cols(), z.get_rows()) << "Failure testing number of rows";
        EXPECT_EQ(m / 2, z(0, 0).get_length()) << "Failure testing ring dimension for the first ring element";

        Matrix<RnsPoly> U_est = trap_pair.first * z;

        U_est.switch_format();
        U.switch_format();

        EXPECT_EQ(U, U_est) << "Failure trapdoor sampling test for " << d << "x" << d << " matrices";
    }
}
#endif

// Test  UCSD integer perturbation sampling algorithm
// So far the test simply runs 100 instances of z_sample_sigma_p
// and makes sure no exceptions are encountered - this validates that
// covariance matrices at all steps are positive definite
TEST(UTTrapdoor, TrapDoorPerturbationSamplingTest) {
    // uint32_t m = 2048;
    uint32_t m = 16;
    // uint32_t m = 8192;
    uint32_t n = m / 2;

    // for m = 16
    BigInteger modulus("67108913");
    BigInteger root_of_unity_value("61564");

    // for m = 2048
    // BigInteger modulus("134246401");
    // BigInteger root_of_unity_value("34044212");

    // for m = 2^13
    // BigInteger modulus("268460033");
    // BigInteger root_of_unity_value("154905983");

    // BigInteger modulus("1237940039285380274899136513");
    // BigInteger root_of_unity_value("977145384161930579732228319");

    double val = modulus.convert_to_double();  // TODO get the next few lines
                                             // working in a single instance.
    double log_two = std::log2(val - 1.0) + 1.0;
    uint32_t k = (uint32_t)std::floor(log_two);  // = this->m_cryptoParameters.get_modulus();

    // smoothing parameter
    // double c(2 * sqrt(log(2 * n*(1 + 1 / DG_ERROR)) / M_PI));
    uint32_t base = 2;
    double c = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    // std::cout << "sigma = " << SIGMA << std::endl;
    // std::cout << "s = " << s << std::endl;

    // Generate the trapdoor pair
    auto params = std::make_shared<PolyParams>(m, modulus, root_of_unity_value);

    double sigma = SIGMA;

    // std::cout << 50 / (c*sigma) << std::endl;

    std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> trap_pair = RlweTrapdoorUtility<Poly>::trapdoor_gen(params, sigma);

    Matrix<Poly> e_hat = trap_pair.second.e_;
    Matrix<Poly> r_hat = trap_pair.second.r_;

    Poly::DggType dgg(sigma);
    Poly::DggType dgg_large_sigma(std::sqrt(s * s - c * c));

    auto zero_alloc = Poly::allocator(params, Format::EVALUATION);

    // Do perturbation sampling
    auto p_hat = std::make_shared<Matrix<Poly>>(zero_alloc, k + 2, 1);

    Matrix<int32_t> p([]() { return 0; }, (2 + k) * n, 1);

    Matrix<int32_t> p_covariance_matrix([]() { return 0; }, 2 * n, 2 * n);

    // std::vector<Matrix<int32_t>> pTrapdoors;

    Matrix<int32_t> p_trapdoor([]() { return 0; }, 2 * n, 1);

    Matrix<BigInteger> bbi_trapdoor(BigInteger::allocator, 2 * n, 1);

    Matrix<int32_t> p_trapdoor_average([]() { return 0; }, 2 * n, 1);

    size_t count = 100;

    for (size_t i = 0; i < count; i++) {
        RlweTrapdoorUtility<Poly>::z_sample_sigma_p(n, s, c, trap_pair.second, dgg, dgg_large_sigma, p_hat);

        // convert to Format::COEFFICIENT representation
        p_hat->switch_format();

        for (size_t j = 0; j < n; j++) {
            bbi_trapdoor(j, 0) = (*p_hat)(0, 0).get_values().at(j);
            bbi_trapdoor(j + n, 0) = (*p_hat)(1, 0).get_values().at(j);
        }

        p_trapdoor = convert_to_int32(bbi_trapdoor, modulus);

        for (size_t j = 0; j < 2 * n; j++) {
            p_trapdoor_average(j, 0) = p_trapdoor_average(j, 0) + p_trapdoor(j, 0);
        }
        // pTrapdoors.push_back(p_trapdoor);

        p_covariance_matrix = p_covariance_matrix + p_trapdoor * p_trapdoor.transposed();
    }

    Matrix<Poly> tprime0 = e_hat;
    Matrix<Poly> tprime1 = r_hat;

    // all three polynomials are initialized with "0" coefficients
    Poly va(params, Format::EVALUATION, 1);
    Poly vb(params, Format::EVALUATION, 1);
    Poly vd(params, Format::EVALUATION, 1);

    for (size_t i = 0; i < k; i++) {
        va = va + tprime0(0, i) * tprime0(0, i).transposed();
        vb = vb + tprime1(0, i) * tprime0(0, i).transposed();
        vd = vd + tprime1(0, i) * tprime1(0, i).transposed();
    }

    // Switch the ring elements (polynomials) to Format::COEFFICIENT
    // representation
    va.switch_format();
    vb.switch_format();
    vd.switch_format();

    // Create field elements from ring elements
    Field2n a(va), b(vb), d(vd);

    double scalar_factor = -s * s * c * c / (s * s - c * c);

    a = a.scalar_mult(scalar_factor);
    b = b.scalar_mult(scalar_factor);
    d = d.scalar_mult(scalar_factor);

    a = a + s * s;
    d = d + s * s;

    // for (size_t j = 0; j < 2 * n; j++) {
    //  p_trapdoor_average(j, 0) = p_trapdoor_average(j, 0) / count;
    //}

    // std::cout << a << std::endl;

    Matrix<int32_t> mean_matrix = p_trapdoor_average * p_trapdoor_average.transposed();

    // std::cout << (double(p_covariance_matrix(0, 0)) - mean_matrix(0, 0))/ count <<
    // std::endl; std::cout << (double(p_covariance_matrix(1, 0)) - mean_matrix(1,
    // 0)) / count << std::endl; std::cout << (double(p_covariance_matrix(2, 0)) -
    // mean_matrix(2, 0)) / count << std::endl; std::cout <<
    // (double(p_covariance_matrix(3, 0)) - mean_matrix(3, 0)) / count << std::endl;
}

// the getters are const members, so they have to be callable on const objects
TEST(UTTrapdoor, ParameterConstGetters) {
    const TrapdoorParams<RnsPoly> params;
    EXPECT_EQ(nullptr, params.get_elem_params());
    const PerturbationVector<RnsPoly> perturbation;
    EXPECT_EQ(nullptr, perturbation.get_vector());
}
