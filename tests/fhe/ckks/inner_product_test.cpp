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
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/util/debug.h"

using namespace cipher;

namespace {
class UTCKKSRNS_INNERPRODUCT : public ::testing::Test {
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

enum TEST_ESTIMATED_RESULT { SUCCESS, FAILURE };

}  // anonymous namespace

template <class T>
T plain_inner_product(std::vector<T> vec) {
    T res = 0.0;
    for (auto& el : vec) {
        res += (el * el);
    }
    return res;
}

//================================================================================================

// declaration for Automorphism Test on BFVrns scheme with polynomial operation
// in power of 2 cyclotomics.
double ckks_rns_inner_product(const std::vector<double> test_vec) {
    cipher::SecurityLevel security_level = cipher::HEStd_NotSet;
    uint32_t dcrt_bits = 59;
    uint32_t ring_dim = 1 << 8;
    uint32_t batch_size = ring_dim / 2;
    cipher::ContextParams<cipher::CkksRnsContext> parameters;
    uint32_t mult_depth_value = 10;

    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_batch_size(batch_size);
    parameters.set_security_level(security_level);
    parameters.set_ring_dim(ring_dim);

    cipher::CryptoContext<cipher::RnsPoly> cc;
    cc = make_crypto_context(parameters);

    cc->enable(PKE);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);

    KeyPair<RnsPoly> keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);
    cc->eval_sum_key_gen(keys.secret_key);

    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(test_vec);
    auto ct1 = cc->encrypt(keys.public_key, plaintext1);
    auto final_result = cc->eval_inner_product(ct1, ct1, batch_size);
    cipher::Plaintext res;
    cc->decrypt(keys.secret_key, final_result, &res);
    res->set_length(test_vec.size());
    return res->get_ckks_packed_value()[0].real();
}

TEST_F(UTCKKSRNS_INNERPRODUCT, Test_CKKSrns_INNERPRODUCT) {
    std::vector<double> test_vec{1, 2, 3, 4, 5};

    for (size_t i = 0; i < test_vec.size(); i++) {
        test_vec[i] += (test_vec[i] / 100.0);
    }
    auto inner_product_he = ckks_rns_inner_product(test_vec);

    double expected_result = plain_inner_product(test_vec);

    EXPECT_LT(std::abs(expected_result - inner_product_he), 0.00001);
}
