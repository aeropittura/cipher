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
  This code tests the utils for selecting lattice parameters.
  unit tests for the utility to to find security parameters using the HomomorphicEncryption.org HE standard
 */

#include <cstdint>
#include <iostream>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/ring/standard_params.h"
#include "cipher/util/inttypes.h"

using namespace cipher;

class LatticeParamsTest : public ::testing::Test {
  protected:
    virtual void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    virtual void TearDown() {
        cipher_parallel_controls.unit_test_stop();
    }
};

// tests the edge cases when log q is right near the point where the ring dimension
// needs to be doubled to be compliant with the HE security standard
TEST_F(LatticeParamsTest, edge_cases) {
    uint32_t max_q = StdLatticeParm::find_max_q(HEStd_ternary, HEStd_128_classic, 4096);
    uint32_t ring_dim = StdLatticeParm::find_ring_dim(HEStd_ternary, HEStd_128_classic, max_q);
    EXPECT_EQ(ring_dim, (uint32_t)4096) << "Ring dimension is incorrect for an edge case of curQ = maxQ";
    ring_dim = StdLatticeParm::find_ring_dim(HEStd_ternary, HEStd_128_classic, max_q - 1);
    EXPECT_EQ(ring_dim, (uint32_t)4096) << "Ring dimension is incorrect for an edge case of curQ = maxQ - 1";
    ring_dim = StdLatticeParm::find_ring_dim(HEStd_ternary, HEStd_128_classic, max_q + 1);
    EXPECT_EQ(ring_dim, (uint32_t)8192) << "Ring dimension is incorrect for an edge case of curQ = maxQ + 1";
}
