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
  This code exercises serialization in CORE for the OpenFHE lattice encryption library
 */

#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/matrix.h"
#include "cipher/math/number_theory.h"
#include "core/test_defs.h"
#include "cipher/util/serial.h"
#include "cipher/util/utilities.h"

using namespace cipher;

template <typename T>
void bigint(const std::string& msg) {
    T small(7);
    T medium(uint64_t(1) << 27 | uint64_t(1) << 22);
    T larger(uint64_t(1) << 40 | uint64_t(1) << 22);

    auto sfunc = [&](T& val, std::string siz) {
        std::stringstream s;
        T deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(val, deser) << msg << " " << siz << " integer json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);

        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(val, deser) << msg << " " << siz << " integer binary ser/deser fails";
    };

    sfunc(small, "small");
    sfunc(medium, "medium");
    sfunc(larger, "larger");
}

TEST(UTSer, bigint) {
    RUN_ALL_BACKENDS_INT(bigint, "bigint")
}

template <typename T>
void hugeint(const std::string& msg) {
    T yooge("371828316732191777888912");

    auto sfunc = [&](T& val, std::string siz) {
        std::stringstream s;
        T deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(val, deser) << msg << " " << siz << " integer json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(val, deser) << msg << " " << siz << " integer binary ser/deser fails";
    };

    sfunc(yooge, "Huge");
}

TEST(UTSer, hugeint) {
    RUN_BIG_BACKENDS_INT(hugeint, "hugeint")
}

template <typename V>
void vector_of_bigint(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    const int vecsize = 100;

    CIPHER_DEBUG("step 0");
    typename V::Integer mod_value((uint64_t)1 << 40);

    CIPHER_DEBUG("step 1");
    V testvec(vecsize, mod_value);
    CIPHER_DEBUG("step 2");
    DiscreteUniformGeneratorImpl<V> dug;
    CIPHER_DEBUG("step 3");
    dug.set_modulus(mod_value);
    typename V::Integer ranval;

    for (int i = 0; i < vecsize; i++) {
        ranval = dug.generate_integer();
        testvec.at(i) = ranval;
    }

    auto sfunc = [&](V& val) {
        std::stringstream s;
        V deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(val, deser) << msg << " vector json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(val, deser) << msg << " vector binary ser/deser fails";
    };

    sfunc(testvec);
}

template <typename Element>
void ilparams_test(const std::string& msg) {
    auto p = std::make_shared<typename Element::Params>(1024);

    auto sfunc = [&msg](decltype(p) val) {
        std::stringstream s;
        decltype(p) deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(*val, *deser) << msg << " json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(*val, *deser) << msg << " binary ser/deser fails";
    };

    sfunc(p);
}

TEST(UTSer, ilparams_test) {
    RUN_ALL_POLYS(ilparams_test, "ilparams_test")
}

template <typename Element>
void ildcrtparams_test(const std::string& msg) {
    auto p = std::make_shared<RnsParams<typename Element::Integer>>(1024, 5, 30);

    auto sfunc = [&msg](decltype(p) val) {
        std::stringstream s;
        decltype(p) deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(*val, *deser) << msg << " json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(*val, *deser) << msg << " binary ser/deser fails";
    };

    sfunc(p);
}

TEST(UTSer, ildcrtparams_test) {
    RUN_BIG_DCRTPOLYS(ildcrtparams_test, "ildcrtparams_test")
}

template <typename Element>
void ilvector_test(const std::string& msg) {
    auto p = std::make_shared<typename Element::Params>(1024);
    typename Element::DugType dug;
    Element vec(dug, p);

    auto sfunc = [&](Element& val) {
        std::stringstream s;
        Element deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(val, deser) << msg << " vector json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(val, deser) << msg << " vector binary ser/deser fails";
    };

    sfunc(vec);
}

TEST(UTSer, ilvector_test) {
    RUN_ALL_POLYS(ilvector_test, "ilvector_test")
}

template <typename Element>
void ildcrtpoly_test(const std::string& msg) {
    auto p = std::make_shared<RnsParams<typename Element::Integer>>(1024, 5, 30);
    typename Element::DugType dug;
    Element vec(dug, p);

    auto sfunc = [&](Element& val) {
        std::stringstream s;
        Element deser;

        serialization::to_stream(val, s, SerType::JSON);
        serialization::from_stream(deser, s, SerType::JSON);
        EXPECT_EQ(val, deser) << msg << " vector json ser/deser fails";

        s.str("");
        serialization::to_stream(val, s, SerType::BINARY);
        serialization::from_stream(deser, s, SerType::BINARY);
        EXPECT_EQ(val, deser) << msg << " vector binary ser/deser fails";
    };

    sfunc(vec);
}

TEST(UTSer, ildcrtpoly_test) {
    RUN_BIG_DCRTPOLYS(ildcrtpoly_test, "ildcrtpoly_test")
}

////////////////////////////////////////////////////////////
template <typename V>
void serialize_matrix_bigint(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    // dimensions of matrix.
    const int nrows = 4;
    const int ncols = 8;

    CIPHER_DEBUG("step 0");
    const typename V::Integer mod_value((uint64_t)1 << 40);

    CIPHER_DEBUG("step 1");
    Matrix<typename V::Integer> testmat(V::Integer::allocator, nrows, ncols);

    CIPHER_DEBUG("step 2");
    DiscreteUniformGeneratorImpl<V> dug;

    CIPHER_DEBUG("step 3");
    dug.set_modulus(mod_value);
    typename V::Integer ranval;

    // load up the matix with random values
    for (size_t i = 0; i < nrows; i++) {
        for (size_t j = 0; j < ncols; j++) {
            ranval = dug.generate_integer();
            testmat(i, j) = ranval;
        }
    }

    CIPHER_DEBUG("step 4");
    // serialize the Matrix

    std::stringstream ss;
    serialization::to_stream(testmat, ss, SerType::BINARY);

#if !defined(NDEBUG)
    if (dbg_flag) {
        std::cout << serialization::serialize_to_string(testmat) << std::endl;
    }
#endif
    CIPHER_DEBUG("step 5");

    // empty matrix
    Matrix<typename V::Integer> newmat(V::Integer::allocator, 0, 0);

    serialization::from_stream(newmat, ss, SerType::BINARY);

    CIPHER_DEBUG("step 9");
    EXPECT_EQ(testmat, newmat) << msg << " Mismatch after ser/deser";
    CIPHER_DEBUGEXP(testmat);
    CIPHER_DEBUGEXP(newmat);
}

TEST(UTSer, serialize_matrix_bigint) {
    RUN_ALL_BACKENDS(serialize_matrix_bigint, "serialize_matrix_bigint")
}
