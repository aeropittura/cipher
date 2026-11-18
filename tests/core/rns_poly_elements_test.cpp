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
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "core/test_defs.h"
#include "cipher/util/debug.h"
#include "cipher/util/exception.h"

using namespace cipher;

void test_rns_poly_constructor_negative(std::vector<NativePoly>& towers);

// --------------- TESTING METHODS OF LATTICE ELEMENTS ---------------
// these tests work only for RnsPoly

template <typename Element>
void dcrt_constructors(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};
    std::vector<NativeInteger> roots_of_unity_value(towersize);
    roots_of_unity_value = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].convert_to_int());
    }

    auto ilparams0 = std::make_shared<NativePolyParams>(m, moduli[0], roots_of_unity_value[0]);
    auto ilparams1 = std::make_shared<NativePolyParams>(m, moduli[1], roots_of_unity_value[1]);
    auto ilparams2 = std::make_shared<NativePolyParams>(m, moduli[2], roots_of_unity_value[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(m / 2, moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.set_values(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

    auto ildcrtparams = std::make_shared<RnsParams<typename Element::Integer>>(m, moduli, roots_of_unity_value);

    std::vector<NativePoly> ilvector2n_vector;
    ilvector2n_vector.push_back(ilv0);
    ilvector2n_vector.push_back(ilv1);
    ilvector2n_vector.push_back(ilv2);

    CIPHER_DEBUG("1");
    float std_dev_value = 4.0;
    typename Element::DggType dgg(std_dev_value);

    {
        Element ilva(ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.get_format()) << msg << " Failure: ildcrtparams ctor ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.get_modulus()) << msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
        EXPECT_EQ(m, ilva.get_cyclotomic_order()) << msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
        EXPECT_EQ(towersize, ilva.get_num_of_elements())
                << msg << " Failure: ildcrtparams ctor ilva.GetNumOfElements()";
    }

    CIPHER_DEBUG("2");
    {
        Element ilva(ilvector2n_vector);

        CIPHER_DEBUG("2.0");
        EXPECT_EQ(Format::EVALUATION, ilva.get_format()) << msg << " Failure: ctor ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.get_modulus()) << msg << " Failure: ctor ilva.GetModulus()";
        EXPECT_EQ(m, ilva.get_cyclotomic_order()) << msg << " Failure: ctor ilva.GetCyclotomicOrder()";
        EXPECT_EQ(towersize, ilva.get_num_of_elements()) << msg << " Failure: ctor ilva.GetNumOfElements()";

        CIPHER_DEBUG("2.1");
        std::vector<NativePoly> ilvector2n_vector_inconsistent(towersize);
        auto ilparams_negative_test_case =
                std::make_shared<NativePolyParams>(128, NativeInteger("1231"), NativeInteger("213"));
        NativePoly ilv_negative(ilparams_negative_test_case);
        ilvector2n_vector_inconsistent[0] = ilv_negative;
        ilvector2n_vector_inconsistent[1] = ilv1;
        ilvector2n_vector_inconsistent[2] = ilv2;

        CIPHER_DEBUG("2.2");
        for (size_t ii = 0; ii < ilvector2n_vector_inconsistent.size(); ii++) {
            CIPHER_DEBUG(ii << " item " << ilvector2n_vector_inconsistent.at(ii).get_params().use_count());
        }
        EXPECT_THROW(test_rns_poly_constructor_negative(ilvector2n_vector_inconsistent), CipherException)
                << msg << " Failure: ilvector2nVectorInconsistent";
    }

    CIPHER_DEBUG("4");
    {
        Element ilva0;
        Element ilva1(ildcrtparams);
        Element ilva2(ilvector2n_vector);

        std::vector<Element> ilva_vector({ilva0, ilva1, ilva2});

        // copy constructor
        Element ilva0_copy(ilva0);
        Element ilva1_copy(ilva1);
        Element ilva2_copy(ilva2);

        std::vector<Element> ilva_copy_vector({ilva0_copy, ilva1_copy, ilva2_copy});

        for (uint32_t i = 0; i < 3; ++i) {
            EXPECT_EQ(ilva_vector[i].get_format(), ilva_copy_vector[i].get_format())
                    << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetFormat()";
            EXPECT_EQ(ilva_vector[i].get_modulus(), ilva_copy_vector[i].get_modulus())
                    << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetModulus()";
            EXPECT_EQ(ilva_vector[i].get_cyclotomic_order(), ilva_copy_vector[i].get_cyclotomic_order())
                    << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetCyclotomicOrder()";
            EXPECT_EQ(ilva_vector[i].get_num_of_elements(), ilva_copy_vector[i].get_num_of_elements())
                    << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetNumOfElements()";
            // to ensure that get_element_at_index is not called
            // on uninitialized RnsPoly objects.
            if (i == 0 || i == 1)
                continue;
            for (uint32_t j = 0; j < towersize; ++j) {
                EXPECT_EQ(ilva_vector[i].get_element_at_index(j), ilva_copy_vector[i].get_element_at_index(j))
                        << msg << " Failure: ctor ilvaCopyVector[" << i << "].GetElementAtIndex(" << j << ")";
            }
        }
    }

    CIPHER_DEBUG("5");
    {
        CIPHER_DEBUG("ild mod " << ildcrtparams->get_modulus());
        Element ilva(dgg, ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.get_format()) << msg << " Failure: ctor(dgg, ldcrtparams) ilva.GetFormat()";
        EXPECT_EQ(modulus, ilva.get_modulus()) << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetModulus()";
        EXPECT_EQ(m, ilva.get_cyclotomic_order())
                << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetCyclotomicOrder()";
        EXPECT_EQ(towersize, ilva.get_num_of_elements())
                << msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetNumOfElements()";
    }

    CIPHER_DEBUG("6");
    {
        Element ilva(dgg, ildcrtparams);
        Element ilva_clone(ilva.clone_parameters_only());

        std::vector<NativePoly> towers_in_clone = ilva_clone.get_all_elements();

        EXPECT_EQ(Format::EVALUATION, ilva.get_format()) << msg << "Failure: clone parameters format mismatch";
        EXPECT_EQ(ilva.get_params(), ilva_clone.get_params()) << msg << "Failure: clone parameters parameter mismatch";
        EXPECT_EQ(towers_in_clone.size(), ilva.get_all_elements().size())
                << msg << "Failure: clone parameters towers size mismatch";
    }
}

TEST(UTDCRTPoly, DCRT_constructors) {
    RUN_BIG_DCRTPOLYS(dcrt_constructors, "DCRT constructors");
}

template <typename Element>
void dcrt_getters_and_ops(const std::string& msg) {
    uint32_t m = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};

    std::vector<NativeInteger> roots_of_unity_value(towersize);

    roots_of_unity_value = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].convert_to_int());
    }

    auto ilparams0 = std::make_shared<NativePolyParams>(m, moduli[0], roots_of_unity_value[0]);
    auto ilparams1 = std::make_shared<NativePolyParams>(m, moduli[1], roots_of_unity_value[1]);
    auto ilparams2 = std::make_shared<NativePolyParams>(m, moduli[2], roots_of_unity_value[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(ilparams0->get_ring_dimension(), moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.set_values(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

    auto ildcrtparams = std::make_shared<RnsParams<typename Element::Integer>>(m, moduli, roots_of_unity_value);

    std::vector<NativePoly> ilvector2n_vector(towersize);

    ilvector2n_vector = {ilv0, ilv1, ilv2};
    {
        Element ilva(ildcrtparams);

        EXPECT_EQ(Format::EVALUATION, ilva.get_format()) << msg << " Failure: ilva format";
        EXPECT_EQ(modulus, ilva.get_modulus()) << msg << " Failure: ilva modulus";
        EXPECT_EQ(m, ilva.get_cyclotomic_order()) << msg << " Failure: ilva cyclotomicOrder";
        EXPECT_EQ(towersize, ilva.get_num_of_elements()) << msg << " Failure: ilva number of elements";
    }

    Element ilva(ilvector2n_vector);

    {
        Element ilva1(ilva);
        EXPECT_TRUE(ilva == ilva1) << msg << " Failure: ilva CTOR";
    }

    {
        Element ilva1 = ilva;
        EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva operator=";
    }

    {
        // a constant is the same value in every slot only in EVALUATION format, which the element and its towers
        // must agree on
        Element ilva_const(ildcrtparams, Format::COEFFICIENT, true);
        ilva_const = uint64_t{5};
        EXPECT_EQ(Format::EVALUATION, ilva_const.get_format()) << msg << " Failure: operator=(uint64_t) format";
        for (uint32_t i = 0; i < ilva_const.get_num_of_elements(); ++i)
            EXPECT_EQ(Format::EVALUATION, ilva_const.get_element_at_index(i).get_format())
                    << msg << " Failure: operator=(uint64_t) tower format";
    }

    {
        Element ilva_coeff(ildcrtparams, Format::COEFFICIENT, true);
        EXPECT_THROW(ilva_coeff.add_il_element_one(), CipherException)
                << msg << " Failure: AddILElementOne format check";
    }

    {
        // assigning a native polynomial gives the element that polynomial's format
        NativePoly coeff(ilparams0, Format::COEFFICIENT, true);
        coeff[1] = NativeInteger(3);
        Element ilva_native(ildcrtparams, Format::EVALUATION, true);
        ilva_native = coeff;
        EXPECT_EQ(Format::COEFFICIENT, ilva_native.get_format()) << msg << " Failure: operator=(PolyType) format";
        for (uint32_t i = 0; i < ilva_native.get_num_of_elements(); ++i) {
            EXPECT_EQ(Format::COEFFICIENT, ilva_native.get_element_at_index(i).get_format())
                    << msg << " Failure: operator=(PolyType) tower format";
            EXPECT_EQ(NativeInteger(3), ilva_native.get_element_at_index(i)[1])
                    << msg << " Failure: operator=(PolyType)";
        }
    }

    {
        // the noise is a small polynomial, the same integers in every tower, whatever the source and requested
        // formats
        DiscreteGaussianGeneratorImpl<typename Element::Vector> dgg(4);
        for (auto src : {Format::COEFFICIENT, Format::EVALUATION}) {
            for (auto dst : {Format::COEFFICIENT, Format::EVALUATION}) {
                Element noise = Element(ildcrtparams, src, true).clone_with_noise(dgg, dst);
                EXPECT_EQ(dst, noise.get_format()) << msg << " Failure: CloneWithNoise format";
                noise.set_format(Format::COEFFICIENT);
                for (uint32_t j = 0; j < noise.get_ring_dimension(); ++j) {
                    int64_t first = 0;
                    for (uint32_t i = 0; i < noise.get_num_of_elements(); ++i) {
                        const auto q =
                                static_cast<int64_t>(noise.get_element_at_index(i).get_modulus().convert_to_int());
                        auto v = static_cast<int64_t>(noise.get_element_at_index(i)[j].convert_to_int());
                        if (v > q / 2)
                            v -= q;
                        if (i == 0)
                            first = v;
                        EXPECT_LE(std::abs(v), 64) << msg << " Failure: CloneWithNoise coefficient is not small";
                        EXPECT_EQ(first, v) << msg << " Failure: CloneWithNoise towers disagree";
                    }
                }
            }
        }
    }

    {
        Element ilva1(ildcrtparams);
        ilva1 = {2, 4, 3, 2};
        EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva CTOR(params)";
    }

    {
        NativePoly ilvect0(ilparams0);
        NativeVector bbv1(m / 2, moduli[0]);
        bbv1 = {"2", "1", "3", "2"};
        ilvect0.set_values(bbv1, Format::EVALUATION);

        NativePoly ilvect1(ilvect0);
        ilvect1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);

        NativePoly ilvect2(ilvect0);
        ilvect2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

        std::vector<NativePoly> ilvector2n_vector1(towersize);
        ilvector2n_vector1 = {ilvect0, ilvect1, ilvect2};

        Element ilva1(ilvector2n_vector1);

        EXPECT_TRUE(ilva != ilva1) << msg << " Failure: ilva operator!=";
    }
}

TEST(UTDCRTPoly, DCRT_getters_and_ops) {
    RUN_BIG_DCRTPOLYS(dcrt_getters_and_ops, "DCRT getters_and_ops");
}

template <typename Element>
void dcrt_arithmetic_ops_element(const std::string& msg) {
    uint32_t m = 8;
    uint32_t towersize = 3;

    std::vector<NativeInteger> moduli(towersize);
    moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};
    std::vector<NativeInteger> roots_of_unity_value(towersize);
    roots_of_unity_value = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

    typename Element::Integer modulus(1);
    for (uint32_t i = 0; i < towersize; ++i) {
        modulus = modulus * typename Element::Integer(moduli[i].convert_to_int());
    }

    auto ilparams0 = std::make_shared<NativePolyParams>(m, moduli[0], roots_of_unity_value[0]);
    auto ilparams1 = std::make_shared<NativePolyParams>(m, moduli[1], roots_of_unity_value[1]);
    auto ilparams2 = std::make_shared<NativePolyParams>(m, moduli[2], roots_of_unity_value[2]);

    NativePoly ilv0(ilparams0);
    NativeVector bbv0(m / 2, moduli[0]);
    bbv0 = {"2", "4", "3", "2"};
    ilv0.set_values(bbv0, Format::EVALUATION);

    NativePoly ilv1(ilv0);
    ilv1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);

    NativePoly ilv2(ilv0);
    ilv2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

    auto ildcrtparams = std::make_shared<RnsParams<typename Element::Integer>>(m, moduli, roots_of_unity_value);

    std::vector<NativePoly> ilvector2n_vector(towersize);
    ilvector2n_vector[0] = ilv0;
    ilvector2n_vector[1] = ilv1;
    ilvector2n_vector[2] = ilv2;

    Element ilva(ilvector2n_vector);

    NativePoly ilvect0(ilparams0);
    NativeVector bbv1(m / 2, moduli[0]);
    bbv1 = {"2", "1", "2", "0"};
    ilvect0.set_values(bbv1, Format::EVALUATION);

    NativePoly ilvect1(ilvect0);
    ilvect1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);

    NativePoly ilvect2(ilvect0);
    ilvect2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

    std::vector<NativePoly> ilvector2n_vector1(towersize);
    ilvector2n_vector1[0] = ilvect0;
    ilvector2n_vector1[1] = ilvect1;
    ilvector2n_vector1[2] = ilvect2;

    Element ilva1(ilvector2n_vector1);

    // Plus method
    {
        Element ilva_copy(ilva.plus_impl(ilva1));

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: Plus()";
        }
    }

    // operator+ (which is mod_add)
    {
        Element ilva_copy(ilva + ilva1);

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: +";
        }
    }

    // += (which is mod_add_eq)
    {
        Element ilva_copy(ilva);
        ilva_copy += ilva1;

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"4", "5", "5", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: +=";
        }
    }

    {
        Element ilva_copy(ilva.minus_impl(ilva1));
        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"0", "3", "1", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: Minus";
        }
    }
    {
        Element ilva_result(ilva);
        ilva_result -= ilva1;
        for (uint32_t i = 0; i < ilva_result.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_result.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"0", "3", "1", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: -=";
        }
    }
    {
        Element ilva_result(ilva.Times(ilva1));
        for (uint32_t i = 0; i < ilva_result.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_result.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"4", "4", "6", "0"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: Times()";
        }
    }
    {
        Element ilva_copy(ilva);
        ilva_copy.add_il_element_one();

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"3", "5", "4", "3"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: AddILElementOne";
        }
    }

    {
        Element ilva_inv(ilva.multiplicative_inverse());

        NativePoly ilvect_inv0 = ilva_inv.get_element_at_index(0);
        // TODO: SHOULD BE ABLE TO SAY NativePoly ilvect_inv0 = ilva_inv[0];
        NativePoly ilvect_inv1 = ilva_inv.get_element_at_index(1);
        NativePoly ilvect_inv2 = ilva_inv.get_element_at_index(2);
        NativeVector expected0(4, ilvect_inv0.get_modulus());
        expected0 = {"4177", "6265", "5569", "4177"};
        EXPECT_EQ(expected0, ilvect_inv0.get_values()) << msg << " Failure: ilvectInv0 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8353"), ilvect_inv0.get_modulus())
                << msg << " Failure: ilvectInv0 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("8163"), ilvect_inv0.get_root_of_unity())
                << msg << " Failure: ilvectInv0 MultiplicativeInverse() rootOfUnity";

        NativeVector expected1(4, ilvect_inv1.get_modulus());
        expected1 = {"4185", "6277", "2790", "4185"};
        EXPECT_EQ(expected1, ilvect_inv1.get_values()) << msg << " Failure: ilvectInv1 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8369"), ilvect_inv1.get_modulus())
                << msg << " Failure: ilvectInv1 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("6677"), ilvect_inv1.get_root_of_unity())
                << msg << " Failure: ilvectInv1 MultiplicativeInverse() rootOfUnity";

        NativeVector expected2(4, ilvect_inv2.get_modulus());
        expected2 = {"4257", "6385", "2838", "4257"};
        EXPECT_EQ(expected2, ilvect_inv2.get_values()) << msg << " Failure: ilvectInv2 MultiplicativeInverse()";
        EXPECT_EQ(NativeInteger("8513"), ilvect_inv2.get_modulus())
                << msg << " Failure: ilvectInv2 MultiplicativeInverse() modulus";
        EXPECT_EQ(NativeInteger("156"), ilvect_inv2.get_root_of_unity())
                << msg << " Failure: ilvectInv2 MultiplicativeInverse() rootOfUnity";
        EXPECT_THROW(ilva1.multiplicative_inverse(), CipherException)
                << msg << " Failure: throw MultiplicativeInverse()";
    }

    // RnsPoly::make_sparse() Only used by RingSwitching, which is no longer supported
    if (false) {
        Element ilva_copy(ilva);

        ilva_copy.make_sparse(2);

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);

            EXPECT_EQ(NativeInteger(0), ilv.at(1)) << msg << " Failure MakeSparse() index 1";
            EXPECT_EQ(NativeInteger(0), ilv.at(3)) << msg << " Failure MakeSparse() index 3";
        }
    }

    {
        EXPECT_TRUE(ilva.inverse_exists()) << msg << " Failure: ilva.InverseExists()";
        EXPECT_FALSE(ilva1.inverse_exists()) << msg << " Failure: ilva1.InverseExists()";
    }

    // this case is NOT used because switch_modulus is not really defined for an
    // RnsPoly, so...
    if (false) {
        NativePoly ilv_s0(ilparams0);
        NativeVector bbv_s0(m / 2, moduli[0]);
        bbv_s0 = {"23462", "467986", "33863", "2113"};
        ilv_s0.set_values(bbv_s0, Format::EVALUATION);

        NativePoly ilv_s1(ilv_s0);
        NativePoly ilv_s2(ilv_s0);

        ilv_s0.switch_modulus(moduli[0], roots_of_unity_value[0], 0, 0);
        ilv_s1.switch_modulus(moduli[1], roots_of_unity_value[1], 0, 0);
        ilv_s2.switch_modulus(moduli[2], roots_of_unity_value[2], 0, 0);

        std::vector<NativePoly> ilvector2n_vector_s(towersize);
        ilvector2n_vector_s[0] = ilv_s0;
        ilvector2n_vector_s[1] = ilv_s1;
        ilvector2n_vector_s[2] = ilv_s2;

        Element ilva_s(ilvector2n_vector_s);
        typename Element::Integer modulus2("113");
        typename Element::Integer root_of_unity2(cipher::root_of_unity<typename Element::Integer>(m, modulus2));

        ilva_s.switch_modulus(modulus2, root_of_unity2, 0, 0);

        NativePoly ilvect_s0 = ilva_s.get_element_at_index(0);
        NativePoly ilvect_s1 = ilva_s.get_element_at_index(1);
        NativePoly ilvect_s2 = ilva_s.get_element_at_index(2);

        EXPECT_EQ(NativeInteger("80"), ilvect_s0.at(0));
        EXPECT_EQ(NativeInteger("62"), ilvect_s0.at(1));
        EXPECT_EQ(NativeInteger("85"), ilvect_s0.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvect_s0.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvect_s0.get_modulus());
        EXPECT_EQ(root_of_unity2.convert_to_int(), ilvect_s0.get_root_of_unity().convert_to_int());

        EXPECT_EQ(NativeInteger("66"), ilvect_s1.at(0));
        EXPECT_EQ(NativeInteger("16"), ilvect_s1.at(1));
        EXPECT_EQ(NativeInteger("64"), ilvect_s1.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvect_s1.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvect_s1.get_modulus());
        EXPECT_EQ(root_of_unity2.convert_to_int(), ilvect_s1.get_root_of_unity().convert_to_int());

        EXPECT_EQ(NativeInteger(4), ilvect_s2.at(0));
        EXPECT_EQ(NativeInteger("44"), ilvect_s2.at(1));
        EXPECT_EQ(NativeInteger("84"), ilvect_s2.at(2));
        EXPECT_EQ(NativeInteger("79"), ilvect_s2.at(3));
        EXPECT_EQ(NativeInteger("113"), ilvect_s2.get_modulus());
        EXPECT_EQ(root_of_unity2.convert_to_int(), ilvect_s2.get_root_of_unity().convert_to_int());
    }

    {
        Element ilva_copy(ilva);
        const auto original_modulus = ilva.get_modulus();
        const auto original_tower0 = ilva.get_params()->get_params()[0];
        typename Element::Integer modulus2("113");
        typename Element::Integer root_of_unity2(cipher::root_of_unity<typename Element::Integer>(m, modulus2));
        ilva_copy.switch_modulus_at_index(0, modulus2, root_of_unity2);

        // the copy's parameters record the new tower and composite modulus; the original's are untouched
        const auto& towers = ilva_copy.get_params()->get_params();
        EXPECT_EQ(modulus2.convert_to_int(), towers[0]->get_modulus().convert_to_int())
                << msg << " Failure: SwitchModulusAtIndex tower parameters";
        typename Element::Integer composite(1);
        for (const auto& t : towers)
            composite *= typename Element::Integer(t->get_modulus().convert_to_int());
        EXPECT_EQ(composite, ilva_copy.get_modulus()) << msg << " Failure: SwitchModulusAtIndex composite modulus";
        EXPECT_EQ(original_modulus, ilva.get_modulus()) << msg << " Failure: SwitchModulusAtIndex changed the source";
        EXPECT_EQ(original_tower0, ilva.get_params()->get_params()[0])
                << msg << " Failure: SwitchModulusAtIndex changed the source's tower";

        for (uint32_t i = 0; i < ilva_copy.get_num_of_elements(); ++i) {
            NativePoly ilv = ilva_copy.get_element_at_index(i);
            NativeVector expected(4, ilv.get_modulus());
            expected = {"2", "4", "3", "2"};
            EXPECT_EQ(expected, ilv.get_values()) << msg << " Failure: ilv.SwitchModulusAtIndex";

            if (i == 0) {
                EXPECT_EQ(modulus2.convert_to_int(), ilv.get_modulus().convert_to_int())
                        << msg << " Failure: SwitchModulusAtIndex modulus";
                EXPECT_EQ(root_of_unity2.convert_to_int(), ilv.get_root_of_unity().convert_to_int())
                        << msg << " Failure: SwitchModulusAtIndex rootOfUnity";
            }
        }
    }
}

TEST(UTDCRTPoly, DCRT_arithmetic_ops_element) {
    RUN_BIG_DCRTPOLYS(dcrt_arithmetic_ops_element, "DCRT_arithmetic_ops_element");
}

template <typename Element>
void dcrt_mod_ops_on_two_elements(const std::string& msg) {
    uint32_t order = 16;
    uint32_t n_bits = 24;
    uint32_t towersize = 3;

    auto ildcrtparams = std::make_shared<RnsParams<typename Element::Integer>>(order, towersize, n_bits);

    typename Element::DugType dug;

    Element op1(dug, ildcrtparams);
    Element op2(dug, ildcrtparams);

    {
        Element sum = op1 + op2;

        for (uint32_t i = 0; i < towersize; i++) {
            for (uint32_t j = 0; j < ildcrtparams->get_ring_dimension(); j++) {
                NativeInteger actual_result(sum.get_element_at_index(i).at(j));
                NativeInteger expected_result((op1.get_element_at_index(i).at(j) + op2.get_element_at_index(i).at(j))
                                                      .mod(ildcrtparams->get_params()[i]->get_modulus()));
                EXPECT_EQ(actual_result, expected_result)
                        << msg << " Failure: DCRTPoly + operation tower " << i << " index " << j;
            }
        }
    }

    {
        Element prod = op1 * op2;

        for (uint32_t i = 0; i < towersize; i++) {
            for (uint32_t j = 0; j < ildcrtparams->get_ring_dimension(); j++) {
                NativeInteger actual_result(prod.get_element_at_index(i).at(j));
                NativeInteger expected_result((op1.get_element_at_index(i).at(j) * op2.get_element_at_index(i).at(j))
                                                      .mod(ildcrtparams->get_params()[i]->get_modulus()));
                EXPECT_EQ(actual_result, expected_result)
                        << msg << " Failure: DCRTPoly * operation tower " << i << " index " << j;
            }
        }
    }
}

TEST(UTDCRTPoly, DCRT_mod_ops_on_two_elements) {
    RUN_BIG_DCRTPOLYS(dcrt_mod_ops_on_two_elements, "DCRT DCRT_mod_ops_on_two_elements");
}

// only need to try this with one
void test_rns_poly_constructor_negative(std::vector<NativePoly>& towers) {
    RnsPoly expect_exception(towers);
}
