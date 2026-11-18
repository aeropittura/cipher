//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
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
  Differential coverage of the NativeInteger modular-multiplication family at
  MAX_MODULUS_SIZE (and one bit below), checked against the multiprecision backend.
  Pins the maximum-modulus contract on every build configuration; in particular,
  builds without a 128-bit integer type reduce through the two-word (TypeD) path,
  which is exercised here at the widths where it previously overflowed (issue #667).
*/

#include <cstdint>

#include "gtest/gtest.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/inttypes.h"

using namespace cipher;

namespace {
BigInteger Ref(const NativeInteger& x) {
    return BigInteger(x.to_string());
}

NativeInteger from_ref(const BigInteger& x) {
    return NativeInteger(x.to_string());
}
}  // namespace

TEST(UTMaxModulus, mod_mul_family_at_max_modulus_size) {
    for (uint32_t bits : {uint32_t(MAX_MODULUS_SIZE) - 1, uint32_t(MAX_MODULUS_SIZE)}) {
        NativeInteger q{last_prime<NativeInteger>(bits, 65536)};
        NativeInteger mu{q.compute_mu()};
        BigInteger q_ref{Ref(q)};

        DiscreteUniformGeneratorImpl<NativeVector> dug;
        constexpr uint32_t n = 512;
        NativeVector av{dug.generate_vector(n, q)};
        NativeVector bv{dug.generate_vector(n, q)};

        for (uint32_t i = 0; i < n; ++i) {
            NativeInteger a{av[i]};
            NativeInteger b{bv[i]};
            NativeInteger expect{from_ref((Ref(a) * Ref(b)).mod(q_ref))};

            EXPECT_EQ(a.mod_mul(b, q), expect) << "ModMul bits=" << bits;
            EXPECT_EQ(a.mod_mul(b, q, mu), expect) << "ModMul(mu) bits=" << bits;
            EXPECT_EQ(a.mod_mul_fast(b, q), expect) << "ModMulFast bits=" << bits;
            EXPECT_EQ(a.mod_mul_fast(b, q, mu), expect) << "ModMulFast(mu) bits=" << bits;
            NativeInteger c{a};
            c.mod_mul_fast_eq(b, q, mu);
            EXPECT_EQ(c, expect) << "ModMulFastEq(mu) bits=" << bits;
            EXPECT_EQ(a.mod_mul_fast_const(b, q, b.prep_mod_mul_const(q)), expect) << "ModMulFastConst bits=" << bits;

            // unreduced input through the Barrett normalization path (value in [q, 2q))
            NativeInteger u{a.add(q)};
            EXPECT_EQ(u.mod(q, mu), a) << "Mod(mu) unreduced bits=" << bits;
            EXPECT_EQ(u.mod_add(b, q, mu), a.mod_add(b, q)) << "ModAdd(mu) unreduced bits=" << bits;
            EXPECT_EQ(u.mod_sub(b, q, mu), a.mod_sub(b, q)) << "ModSub(mu) unreduced bits=" << bits;
        }

        // vector-level multiply (hoisted-Barrett loop)
        NativeVector pv{av.mod_mul(bv)};
        for (uint32_t i = 0; i < n; ++i) {
            EXPECT_EQ(pv[i], from_ref((Ref(av[i]) * Ref(bv[i])).mod(q_ref))) << "NativeVector::ModMul bits=" << bits;
        }

        // Fermat: 3^(q-1) = 1 mod q for prime q
        EXPECT_EQ(NativeInteger(3).mod_exp(q - 1, q), NativeInteger(1)) << "ModExp bits=" << bits;
    }

    // first_prime scans candidates (and returns a prime) one bit ABOVE the cap, so
    // Miller-Rabin's mod_exp/mod_mul must be exact at MAX_MODULUS_SIZE + 1 bits
    NativeInteger p1{first_prime<NativeInteger>(MAX_MODULUS_SIZE, 65536)};
    EXPECT_EQ(p1.get_msb(), uint32_t(MAX_MODULUS_SIZE) + 1);
    EXPECT_EQ(NativeInteger(3).mod_exp(p1 - 1, p1), NativeInteger(1)) << "ModExp above cap";
}
