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
  This code exercises the encoding libraries of the Cipher lattice encryption library.
*/

#include <cmath>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/encoding/encodings.h"
#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/backend.h"
#include "cipher/util/utilities.h"

using namespace cipher;

class UTGENERAL_ENCODING : public ::testing::Test {
  protected:
    virtual void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    virtual void TearDown() {
        cipher_parallel_controls.unit_test_stop();
    }
};

TEST_F(UTGENERAL_ENCODING, coef_packed_encoding) {
    std::vector<int64_t> value = {32, 17, 8, -12, -32, 22, -101, 6};
    uint32_t m = 16;

    auto lp = std::make_shared<PolyParamsImpl<BigInteger>>(m);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(256));

    CoefPackedEncoding se(lp, ep, value);
    se.encode();
    se.decode();
    se.set_length(value.size());
    EXPECT_EQ(se.get_coef_packed_value(), value) << "COEF_PACKED_ENCODING";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding) {
    uint32_t m = 22;
    PlaintextModulus p = 89;
    BigInteger modulus_q("955263939794561");
    BigInteger square_root_of_root("941018665059848");
    BigInteger bigmodulus("80899135611688102162227204937217");
    BigInteger bigroot("77936753846653065954043047918387");

    auto cyclo_poly = get_cyclotomic_polynomial<BigVector>(m, modulus_q);
    ChineseRemainderTransformArb<BigVector>().set_cylotomic_polynomial(cyclo_poly, modulus_q);

    auto lp = std::make_shared<PolyParams>(m, modulus_q, square_root_of_root, bigmodulus, bigroot);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p, 8));

    PackedEncoding::set_params(m, ep);

    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};
    PackedEncoding se(lp, ep, vector_of_ints1);
    se.encode();
    se.decode();
    EXPECT_EQ(se.get_packed_value(), vector_of_ints1) << "packed int";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_negative) {
    uint32_t m = 22;
    PlaintextModulus p = 89;
    BigInteger modulus_q("955263939794561");
    BigInteger square_root_of_root("941018665059848");
    BigInteger bigmodulus("80899135611688102162227204937217");
    BigInteger bigroot("77936753846653065954043047918387");

    auto cyclo_poly = get_cyclotomic_polynomial<BigVector>(m, modulus_q);
    ChineseRemainderTransformArb<BigVector>().set_cylotomic_polynomial(cyclo_poly, modulus_q);

    auto lp = std::make_shared<PolyParams>(m, modulus_q, square_root_of_root, bigmodulus, bigroot);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p, 8));

    PackedEncoding::set_params(m, ep);

    std::vector<int64_t> vector_of_ints1 = {1, 2, -3, 4, 5, -6, 7, 8, 0, 0};
    PackedEncoding se(lp, ep, vector_of_ints1);
    se.encode();
    se.decode();
    EXPECT_EQ(se.get_packed_value(), vector_of_ints1) << "packed int";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_RnsPoly_prime_cyclotomics) {
    uint32_t init_size = 3;
    uint32_t dcrt_bits = 24;
    // Bluestein needs big_modulus > m * q^2 (about 2^58.8 for 24-bit towers at m = 1811)
    uint32_t dcrt_bits_big = 60;

    uint32_t m = 1811;

    PlaintextModulus p = 2 * m + 1;
    BigInteger modulus_p(p);

    uint32_t m_arb = 2 * m;
    uint32_t m_ntt = std::pow(2, std::ceil(std::log2(2 * m - 1)));

    // populate the towers for the small modulus

    std::vector<NativeInteger> init_moduli(init_size);
    std::vector<NativeInteger> init_roots_of_unity(init_size);

    init_moduli[0] = last_prime<NativeInteger>(dcrt_bits, m_arb);
    init_roots_of_unity[0] = root_of_unity(m_arb, init_moduli[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli[i] = previous_prime(init_moduli[i - 1], m_arb);
        init_roots_of_unity[i] = root_of_unity(m_arb, init_moduli[i]);
    }

    // populate the towers for the big modulus

    std::vector<NativeInteger> init_moduli_ntt(init_size);
    std::vector<NativeInteger> init_roots_of_unity_ntt(init_size);

    init_moduli_ntt[0] = last_prime<NativeInteger>(dcrt_bits_big, m_ntt);
    init_roots_of_unity_ntt[0] = root_of_unity(m_ntt, init_moduli_ntt[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli_ntt[i] = previous_prime(init_moduli_ntt[i - 1], m_ntt);
        init_roots_of_unity_ntt[i] = root_of_unity(m_ntt, init_moduli_ntt[i]);
    }

    auto params_dcrt = std::make_shared<RnsParams<BigInteger>>(m, init_moduli, init_roots_of_unity, init_moduli_ntt,
                                                               init_roots_of_unity_ntt);

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p));

    PackedEncoding::set_params(m, ep);

    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};
    PackedEncoding se(params_dcrt, ep, vector_of_ints1);

    se.encode();
    se.get_element<RnsPoly>().set_format(Format::COEFFICIENT);

    se.get_element<RnsPoly>().switch_format();
    se.get_element<RnsPoly>().switch_format();

    se.decode();

    se.set_length(vector_of_ints1.size());

    EXPECT_EQ(se.get_packed_value(), vector_of_ints1) << "packed int - prime cyclotomics";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_RnsPoly_prime_cyclotomics_negative) {
    uint32_t init_size = 3;
    uint32_t dcrt_bits = 24;
    // Bluestein needs big_modulus > m * q^2 (about 2^58.8 for 24-bit towers at m = 1811)
    uint32_t dcrt_bits_big = 60;

    uint32_t m = 1811;

    PlaintextModulus p = 2 * m + 1;
    BigInteger modulus_p(p);

    uint32_t m_arb = 2 * m;
    uint32_t m_ntt = std::pow(2, std::ceil(std::log2(2 * m - 1)));

    // populate the towers for the small modulus
    std::vector<NativeInteger> init_moduli(init_size);
    std::vector<NativeInteger> init_roots_of_unity(init_size);

    init_moduli[0] = last_prime<NativeInteger>(dcrt_bits, m_arb);
    init_roots_of_unity[0] = root_of_unity(m_arb, init_moduli[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli[i] = previous_prime(init_moduli[i - 1], m_arb);
        init_roots_of_unity[i] = root_of_unity(m_arb, init_moduli[i]);
    }

    // populate the towers for the big modulus

    std::vector<NativeInteger> init_moduli_ntt(init_size);
    std::vector<NativeInteger> init_roots_of_unity_ntt(init_size);

    init_moduli_ntt[0] = last_prime<NativeInteger>(dcrt_bits_big, m_ntt);
    init_roots_of_unity_ntt[0] = root_of_unity(m_ntt, init_moduli_ntt[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli_ntt[i] = previous_prime(init_moduli_ntt[i - 1], m_ntt);
        init_roots_of_unity_ntt[i] = root_of_unity(m_ntt, init_moduli_ntt[i]);
    }

    auto params_dcrt = std::make_shared<RnsParams<BigInteger>>(m, init_moduli, init_roots_of_unity, init_moduli_ntt,
                                                               init_roots_of_unity_ntt);

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p));

    PackedEncoding::set_params(m, ep);

    std::vector<int64_t> vector_of_ints1 = {1, 2, -3, 4, 5, 6, -7, 8, 0, 0};
    PackedEncoding se(params_dcrt, ep, vector_of_ints1);

    se.encode();
    se.get_element<RnsPoly>().set_format(Format::COEFFICIENT);

    se.get_element<RnsPoly>().switch_format();
    se.get_element<RnsPoly>().switch_format();

    se.decode();

    se.set_length(vector_of_ints1.size());

    EXPECT_EQ(se.get_packed_value(), vector_of_ints1) << "packed int - prime cyclotomics";
}

TEST_F(UTGENERAL_ENCODING, string_encoding) {
    std::string value = "Hello, world!";
    uint32_t m = 64;

    auto lp = std::make_shared<PolyParamsImpl<BigInteger>>(m);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(256));

    StringEncoding se(lp, ep, value);
    se.encode();
    se.decode();
    EXPECT_EQ(se.get_string_value(), value) << "string encode/decode";

    // truncate!
    auto lp2 = std::make_shared<PolyParamsImpl<BigInteger>>(4);
    StringEncoding se2(lp2, ep, value);
    se2.encode();
    se2.decode();
    EXPECT_EQ(se2.get_string_value(), value.substr(0, lp2->get_ring_dimension())) << "string truncate encode/decode";
}
