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
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "core/test_defs.h"
#include "cipher/util/debug.h"

using namespace cipher;

// --------------- TESTING METHODS OF LATTICE ELEMENTS ---------------
// these tests only work on Poly, and have not been ported to DCRT
// NOTE tests that only work on Poly because DCRT versions have not been
// coded are here
// When they are completed and run for both types,  they move to
// UnitTestCommonElements.cpp

template <typename Element>
void rounding_ops(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer q("73");
    typename VecType::Integer primitive_root_of_unity("22");
    typename VecType::Integer p("8");

    auto ilparams = std::make_shared<ParmType>(m, q, primitive_root_of_unity);

    // temporary larger modulus that is used for polynomial multiplication before
    // rounding
    typename VecType::Integer q2("16417");
    typename VecType::Integer primitive_root_of_unity2("13161");

    auto ilparams2 = std::make_shared<ParmType>(m, q2, primitive_root_of_unity2);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"31", "21", "15", "34"};
    CIPHER_DEBUGEXP(ilvector2n1);
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.get_length(), m / 2) << msg << " Failure: ={init list string}";

    Element ilvector2n2(ilparams, Format::COEFFICIENT);
    ilvector2n2 = {"21", "11", "35", "32"};
    CIPHER_DEBUGEXP(ilvector2n2);

    CIPHER_DEBUG("unit test for multiply_and_round");
    Element rounding_correct1(ilparams, Format::COEFFICIENT);
    rounding_correct1 = {"3", "2", "2", "4"};

    CIPHER_DEBUGEXP(ilvector2n1);

    Element rounding1 = ilvector2n1.multiply_and_round(p, q);

    EXPECT_EQ(rounding_correct1, rounding1) << msg << " Failure: Rounding p*polynomial/q";

    CIPHER_DEBUG("unit test for multiply_and_round after a polynomial");
    CIPHER_DEBUG("multiplication using the larger modulus");

    Element rounding_correct2(ilparams2, Format::COEFFICIENT);
    rounding_correct2 = {"16316", "16320", "60", "286"};

    ilvector2n1.switch_modulus(q2, primitive_root_of_unity2, 0, 0);
    ilvector2n2.switch_modulus(q2, primitive_root_of_unity2, 0, 0);
    CIPHER_DEBUGEXP(ilvector2n1);
    CIPHER_DEBUGEXP(ilvector2n2);

    ilvector2n1.switch_format();
    ilvector2n2.switch_format();
    CIPHER_DEBUGEXP(ilvector2n1);
    CIPHER_DEBUGEXP(ilvector2n2);

    Element rounding2 = ilvector2n1 * ilvector2n2;

    CIPHER_DEBUGEXP(rounding2);
    rounding2.switch_format();
    CIPHER_DEBUGEXP(rounding2);
    rounding2 = rounding2.multiply_and_round(p, q);
    CIPHER_DEBUGEXP(rounding2);
    EXPECT_EQ(rounding_correct2, rounding2) << msg << " Failure: Rounding p*polynomial1*polynomial2/q";

    CIPHER_DEBUG("makes sure the result is correct after");
    CIPHER_DEBUG("going back to the original modulus");

    rounding2.switch_modulus(q, primitive_root_of_unity, 0, 0);
    CIPHER_DEBUGEXP(rounding2);

    Element rounding_correct3(ilparams, Format::COEFFICIENT);
    rounding_correct3 = {"45", "49", "60", "67"};

    EXPECT_EQ(rounding_correct3, rounding2) << msg << " Failure p*polynomial1*polynomial2/q (mod q)";
}

// instantiate various test for rounding_ops()
TEST(UTPoly, rounding_ops) {
    RUN_ALL_POLYS(rounding_ops, "Poly rounding_ops");
}

// TODO RnsPoly needs an assignment op/ctor
TEST(UTRnsPoly, rounding_ops) {
    // std::cerr<<"*** skipping DCRT rounding_ops till multiply_and_round is
    // coded"<<std::endl; RUN_BIG_RNS_POLYS(rounding_ops, "DCRT rounding_ops");
}

// template for set_get_values()
template <typename Element>
void set_get_values(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);
    {  // test set_values()
        Element ilvector2n(ilparams);
        VecType bbv(m / 2, prime_modulus);
        bbv = {"3", "0", "0", "0"};
        ilvector2n.set_values(bbv, Format::COEFFICIENT);
        CIPHER_DEBUGEXP(ilvector2n);
        // test for bug where length was 0
        EXPECT_EQ(ilvector2n.get_length(), m / 2) << msg << " Failure: ={init list string}";

        Element ilvector2n2(ilparams);
        VecType bbv2(m / 2, prime_modulus);
        bbv2 = {"3", "3", "3", "3"};
        ilvector2n2.set_values(bbv2, Format::COEFFICIENT);

        // test set_values()
        EXPECT_NE(ilvector2n, ilvector2n2) << msg << " Failure: set_values NE";
        bbv2 = bbv;
        ilvector2n2.set_values(bbv2, Format::COEFFICIENT);
        EXPECT_EQ(ilvector2n, ilvector2n2) << msg << " Failure: set_values EQ";
    }
    {  // test get_value() and at()
        Element ilvector2n(ilparams);
        ilvector2n = {"1", "2", "0", "1"};
        Element bbv(ilparams);
        bbv = {"1", "2", "0", "1"};
        CIPHER_DEBUGEXP(ilvector2n);
        CIPHER_DEBUGEXP(bbv);

        EXPECT_EQ(bbv.get_values(), ilvector2n.get_values()) << msg << "Failure: get_values()";

        uint32_t index = 3;
        bbv[index] = 11;
        for (uint32_t i = 0; i < m / 2; ++i) {
            if (i == index) {
                EXPECT_NE(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            } else {
                EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
        }
    }
}

// instantiate various test for set_get_values()
TEST(UTPoly, set_get_values) {
    RUN_ALL_POLYS(set_get_values, "Poly set_get_values");
}

// TODO RnsPoly needs a set_get_values()
TEST(UTRnsPoly, set_get_values) {
    // std::cerr<<"*** skipping DCRT set_get_values till coded"<<std::endl;
    // RUN_BIG_RNS_POLYS(set_get_values, "DCRT set_values");
}

// template for at()
template <typename Element>
void at(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);

    {  // test and at() and []
        Element ilvector2n(ilparams);
        ilvector2n = {"1", "2", "0", "1"};
        Element bbv(ilparams);
        bbv = {"1", "2", "0", "1"};
        CIPHER_DEBUGEXP(ilvector2n);
        CIPHER_DEBUGEXP(bbv);
        // test for bug where length was 0
        EXPECT_EQ(ilvector2n.get_length(), m / 2) << msg << " Failure: ={init list string}";

        uint32_t index = 3;
        bbv[index] = 11;
        for (uint32_t i = 0; i < m / 2; ++i) {
            if (i == index) {
                EXPECT_NE(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            } else {
                EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
            }
        }
        bbv.at(index) = 1;
        for (uint32_t i = 0; i < m / 2; ++i) {
            EXPECT_EQ(bbv[i], ilvector2n[i]) << msg << " Failure: lhs[] at(" << i << ")";
        }
    }
}

// instantiate various test for at()
TEST(UTPoly, at) {
    RUN_ALL_POLYS(at, "Poly at");
}

// TODO RnsPoly needs a at() and []
TEST(UTRnsPoly, at) {
    // std::cerr<<"*** skipping DCRT at till coded"<<std::endl;
    // RUN_BIG_RNS_POLYS(at, "DCRT at");
}

// template for switch_modulus_impl

template <typename Element>
void switch_modulus_impl(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;
    // using IntType = typename Element::Vector::Integer;

    uint32_t m = 8;
    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);
    CIPHER_DEBUG("switch_modulus");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "2"};
        // test for bug where length was 0
        EXPECT_EQ(ilv.get_length(), m / 2) << msg << " Failure: ={init list string}";

        typename VecType::Integer modulus("17");
        typename VecType::Integer root_of_unity_value("15");

        ilv.switch_modulus(modulus, root_of_unity_value, 0, 0);

        auto ilparams2 = std::make_shared<ParmType>(m, modulus, root_of_unity_value);
        Element expected(ilparams2, Format::COEFFICIENT);
        expected = {"0", "1", "15", "2"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: switch_modulus()";

        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = {"56", "43", "35", "28"};
        typename VecType::Integer modulus1("193");
        typename VecType::Integer root_of_unity1("150");

        ilv1.switch_modulus(modulus1, root_of_unity1, 0, 0);
        auto ilparams3 = std::make_shared<ParmType>(m, modulus1, root_of_unity1);
        Element expected2(ilparams3, Format::COEFFICIENT);
        expected2 = {"176", "163", "35", "28"};
        EXPECT_EQ(expected2, ilv1) << msg << " Failure: switch_modulus()";
    }
}
// instantiations for switch_modulus_impl()
TEST(UTPoly, switch_modulus) {
    RUN_ALL_POLYS(switch_modulus_impl, "Poly switch_modulus");
}

TEST(UTRnsPoly, switch_modulus) {
    // std::cerr<<"*** skipping DCRT switch_modulus_impl till coded"<<std::endl;
    // //RUN_BIG_RNS_POLYS(switch_modulus_impl, "Poly switch_modulus_impl");
}

// template fore rn_generators()
template <typename Element>
void rn_generators(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8;
    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    float std_dev_value = 4.0f;
    typename Element::DggType dgg(std_dev_value);
    typename Element::BugType bug;
    typename Element::DugType dug;

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);

    CIPHER_DEBUG("DestroyPreComputedSamples");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"2", "1", "3", "2"};
        // test for bug where length was 0
        EXPECT_EQ(ilv.get_length(), m / 2) << msg << " Failure: ={init list string}";

        Element ilvector2n1(ilparams);
        Element ilvector2n2(ilparams);
        Element ilvector2n3(ilv);
        Element ilvector2n4(dgg, ilparams);
        Element ilvector2n5(bug, ilparams);
        Element ilvector2n6(dug, ilparams);

        EXPECT_EQ(true, ilvector2n1.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n1";
        EXPECT_EQ(true, ilvector2n2.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n2";
        EXPECT_EQ(false, ilvector2n3.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n3";
        EXPECT_EQ(false, ilvector2n4.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n4";
        EXPECT_EQ(false, ilvector2n5.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n5";
        EXPECT_EQ(false, ilvector2n6.is_empty()) << msg << " Failure: destroy_pre_computed_samples() 2n6";
    }
}

// Instantiations of rn_generators()
TEST(UTPoly, rn_generators) {
    RUN_ALL_POLYS(rn_generators, "Poly rn_generators");
}

TEST(UTRnsPoly, rn_generators) {
    // std::cerr<<"*** skipping DCRT rn_generators till coded"<<std::endl;
    // RUN_BIG_RNS_POLYS(rn_generators, "DCRT rn_generators");
}

// template fore poly_other_methods()
template <typename Element>
void poly_other_methods(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8;
    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);

    Element ilvector2n(ilparams);
    ilvector2n = {"2", "1", "3", "2"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n.get_length(), m / 2) << msg << " Failure: ={init list string}";

    CIPHER_DEBUG("switch_format");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"2", "1", "3", "2"};

        ilv.switch_format();

        EXPECT_EQ(prime_modulus, ilv.get_modulus()) << msg << " Failure: switch_format() ilv modulus";
        EXPECT_EQ(primitive_root_of_unity, ilv.get_root_of_unity())
                << msg << " Failure: switch_format() ilv rootOfUnity";
        EXPECT_EQ(Format::EVALUATION, ilv.get_format()) << msg << " Failure: switch_format() ilv format";
        Element expected(ilparams);
        expected = {"69", "65", "44", "49"};
        EXPECT_EQ(expected, ilv) << msg << " Failure: ivl.switch_format() values";

        Element ilv1(ilparams, Format::EVALUATION);
        ilv1 = {"2", "3", "1", "2"};

        ilv1.switch_format();

        EXPECT_EQ(prime_modulus, ilv1.get_modulus()) << msg << " Failure: switch_format() ilv1 modulus";
        EXPECT_EQ(primitive_root_of_unity, ilv1.get_root_of_unity())
                << msg << " Failure: switch_format() ilv1 rootOfUnity";
        EXPECT_EQ(Format::COEFFICIENT, ilv1.get_format()) << msg << " Failure: switch_format() ilv1 format";
        Element expected2(ilparams, Format::COEFFICIENT);
        expected2 = {"2", "3", "50", "3"};
        EXPECT_EQ(expected2, ilv1) << msg << " Failure: ivl1.switch_format() values";
    }

    CIPHER_DEBUG("multiplicative_inverse");
    {
        Element ilv1(ilparams, Format::EVALUATION);
        ilv1 = {"2", "4", "3", "2"};

        Element ilv_inverse1 = ilv1.multiplicative_inverse();
        Element ilv_product1 = ilv1 * ilv_inverse1;

        for (uint32_t i = 0; i < m / 2; ++i) {
            EXPECT_EQ(ilv_product1[i], typename Element::Integer(1))
                    << msg << " Failure: ilv_product1.multiplicative_inverse() @ index " << i;
        }
    }

    CIPHER_DEBUG("Norm");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "1"};
        EXPECT_EQ(36, ilv.norm()) << msg << " Failure: norm()";
    }
}

// Instantiations of poly_other_methods()
TEST(UTPoly, poly_other_methods) {
    RUN_ALL_POLYS(poly_other_methods, "poly_other_methods");
}

// TODO
TEST(UTRnsPoly, poly_other_methods) {
    // std::cerr<<"*** skipping DCRT poly_other_methods till these functions are
    // coded"<<std::endl;
    //   RUN_BIG_RNS_POLYS(poly_other_methods, "DCRT poly_other_methods");
}

// Signed mod must handle the modulo operation for both positive and negative
// numbers It is used in decoding/decryption of homomorphic encryption schemes
template <typename Element>
void signed_mod(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t m = 8;

    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"62", "7", "65", "8"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.get_length(), m / 2) << msg << " Failure: ={init list string}";

    {
        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = ilvector2n1.mod(2);
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"1", "1", "0", "0"};
        EXPECT_EQ(expected, ilv1) << msg << " Failure: ilv1.mod(TWO)";
    }

    {
        Element ilv1(ilparams, Format::COEFFICIENT);
        ilv1 = ilvector2n1.mod(5);
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"4", "2", "2", "3"};
        EXPECT_EQ(expected, ilv1) << msg << " Failure: ilv1.mod(FIVE)";
    }
}
// Instantiations of signed_mod()
TEST(UTPoly, signed_mod) {
    RUN_ALL_POLYS(signed_mod, "signed_mod");
}

// TODO
TEST(UTRnsPoly, signed_mod) {
    // std::cerr<<"*** skipping DCRT signed_mod till coded"<<std::endl;
    //  RUN_BIG_RNS_POLYS(signed_mod, "signed_mod");
}

// template fore automorphism_transform_impl()
template <typename Element>
void automorphism_transform_impl(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8;
    typename VecType::Integer prime_modulus("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, prime_modulus, primitive_root_of_unity);

    Element ilvector2n(ilparams);
    ilvector2n = {"2", "1", "3", "2"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n.get_length(), m / 2) << msg << " Failure: ={init list string}";

    CIPHER_DEBUG("automorphism_transform");
    {
        Element ilv(ilparams, Format::COEFFICIENT);
        ilv = {"56", "1", "37", "2"};

        uint32_t index = 3;
        Element ilv_auto(ilv.automorphism_transform(index));
        Element expected(ilparams, Format::COEFFICIENT);
        expected = {"56", "2", "36", "1"};
        EXPECT_EQ(expected, ilv_auto) << msg << " Failure: automorphism_transform()";
    }
}
// Instantiations of automorphism_transform_impl()
TEST(UTPoly, automorphism_transform) {
    RUN_ALL_POLYS(automorphism_transform_impl, "Poly automorphism_transform");
}

// TODO
TEST(UTRnsPoly, automorphism_transform) {
    // std::cerr<<"*** skipping DCRT automorphism_transform_impl till coded"<<std::endl;
    //  RUN_BIG_RNS_POLYS(automorphism_transform_impl, "DCRT automorphism_transform_impl");
}

template <typename Element>
void transposition(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8;

    typename VecType::Integer q("73");
    typename VecType::Integer primitive_root_of_unity("22");

    auto ilparams = std::make_shared<ParmType>(m, q, primitive_root_of_unity);

    Element ilvector2n1(ilparams, Format::COEFFICIENT);
    ilvector2n1 = {"31", "21", "15", "34"};
    // test for bug where length was 0
    EXPECT_EQ(ilvector2n1.get_length(), m / 2) << msg << " Failure: ={init list string}";

    // converts to Format::EVALUATION representation
    ilvector2n1.switch_format();
    CIPHER_DEBUG("ilvector2n1 a " << ilvector2n1);

    ilvector2n1 = ilvector2n1.transposed();
    CIPHER_DEBUG("ilvector2n1 b " << ilvector2n1);

    // converts back to Format::COEFFICIENT representation
    ilvector2n1.switch_format();

    CIPHER_DEBUG("ilvector2n1 c " << ilvector2n1);

    Element ilvector2n2(ilparams, Format::COEFFICIENT);
    ilvector2n2 = {"31", "39", "58", "52"};

    CIPHER_DEBUG("ilvector2n2 a " << ilvector2n2);

    EXPECT_EQ(ilvector2n2, ilvector2n1) << msg << " Failure: transposition test";
}
// Instantiations of transposition()
TEST(UTPoly, transposition) {
    RUN_ALL_POLYS(transposition, "transposition");
}

// TODO
TEST(UTRnsPoly, transposition) {
    // std::cerr<<"*** skipping DCRT transposition till coded"<<std::endl;
    //  RUN_BIG_RNS_POLYS(transposition, "transposition");
}

template <typename Element>
void poly_mod_ops_on_two_elements(const std::string& msg) {
    using VecType = typename Element::Vector;
    using ParmType = typename Element::Params;

    uint32_t order = 8;
    uint32_t n_bits = 7;

    typename VecType::Integer prime_modulus = last_prime<typename VecType::Integer>(n_bits, order);
    auto ilparams = std::make_shared<ParmType>(order, prime_modulus);

    typename Element::DugType distr_uni_gen;

    Element ilv1(distr_uni_gen, ilparams);
    VecType bbv1(ilv1.get_values());

    Element ilv2(distr_uni_gen, ilparams);
    VecType bbv2(ilv2.get_values());

    {
        Element ilv_result = ilv1 + ilv2;
        VecType bbv_result(ilv_result.get_values());

        for (uint32_t i = 0; i < order / 2; i++) {
            EXPECT_EQ(bbv_result[i], (bbv1[i] + bbv2[i]).mod(prime_modulus))
                    << msg << " Poly + operation returns incorrect results.";
        }
    }

    {
        Element ilv_result = ilv1 * ilv2;
        VecType bbv_result(ilv_result.get_values());

        for (uint32_t i = 0; i < order / 2; i++) {
            EXPECT_EQ(bbv_result[i], (bbv1[i] * bbv2[i]).mod(prime_modulus))
                    << msg << " Poly * operation returns incorrect results.";
        }
    }
}

TEST(UTPoly, Poly_mod_ops_on_two_elements) {
    RUN_ALL_POLYS(poly_mod_ops_on_two_elements, "Poly Poly_mod_ops_on_two_elements");
}
