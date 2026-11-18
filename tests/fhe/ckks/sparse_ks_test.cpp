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
  Regression test for the sparse secret encapsulation key switching
  (https://github.com/openfheorg/openfhe-development/issues/1041): the noise added by
  key_switch_sparse must stay at the modulus switching (rounding) noise level.
*/

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "fhe/support/test_exception.h"
#include "fhe/support/test_utils.h"
#include "cipher/config.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/util/debug.h"

using namespace cipher;

// Regression test for https://github.com/openfheorg/openfhe-development/issues/1041: the
// noise added by the sparse encapsulation key switching must stay at the modulus switching
// (rounding) noise level. The noise added by key_switch_sparse decomposes as
// floor(c1*e/P') + delta_0 + delta_1*s_new, where the delta rounding terms are inherent to
// any modulus switch and are bounded by (1 + ||s_new||_1)/2 = 16.5 per coefficient for a
// Hamming weight 32 secret. With the auxiliary modulus P' of ~66 bits (two 33-bit primes)
// the key switching term is below one per coefficient, and the measured maximum is ~2^3.
// With a single ~60-bit auxiliary prime (the previous approach) the key switching term
// dominates at ~2^8, so this test fails.
TEST(UTCKKSRNS_SPARSE_KS, KeySwitchSparseAddedNoise) {
    setup_signals();
    cipher_parallel_controls.unit_test_start();

    const std::string failmsg("KeySwitchSparseAddedNoise");

    try {
        // scaling factor close to the first modulus: the regime where the sparse
        // encapsulation key switching noise is exposed
        ContextParams<CkksRnsContext> parameters;
        parameters.set_multiplicative_depth(2);
        parameters.set_scaling_mod_size(59);
        parameters.set_first_mod_size(60);
        parameters.set_scaling_technique(FIXEDMANUAL);
        parameters.set_secret_key_dist(SPARSE_ENCAPSULATED);
        parameters.set_security_level(HEStd_NotSet);
        parameters.set_ring_dim(1 << 12);
        parameters.set_key_switch_technique(HYBRID);

        auto cc = make_crypto_context(parameters);
        cc->enable(PKE);
        cc->enable(KEYSWITCH);
        cc->enable(LEVELEDSHE);
        cc->enable(ADVANCEDSHE);
        cc->enable(FHE);

        auto key_pair = cc->key_gen();
        auto crypto_params =
                std::dynamic_pointer_cast<CkksRnsCryptoParams>(key_pair.secret_key->get_crypto_parameters());

        // encode at the last level so the ciphertext has a single tower (q0), as at the
        // modulus raise step of bootstrapping
        std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 0.375, 0.675, 0.125, 0.925};
        auto ptxt = cc->make_ckks_packed_plaintext(x, 1, crypto_params->get_multiplicative_depth());
        auto ctxt = cc->encrypt(key_pair.public_key, ptxt);

        // sparse key used for the modraising step
        RnsPoly::TugType tug;
        auto sk_new = std::make_shared<PrivateKeyImpl<RnsPoly>>(cc);
        sk_new->set_private_element(RnsPoly(tug, crypto_params->get_element_params(), Format::EVALUATION, 32));

        auto eval_key = CkksRnsFhe::key_switch_gen_sparse(key_pair.secret_key, sk_new);
        auto ctresult = CkksRnsFhe::key_switch_sparse(ctxt, eval_key);

        // the noise added by the key switch: difference of the raw decryptions b + a*s
        // over q0 under the respective secret keys (the shared encryption noise cancels)
        const auto s_old0 = key_pair.secret_key->get_private_element().get_element_at_index(0);
        const auto s_new0 = sk_new->get_private_element().get_element_at_index(0);
        const auto& cvo = ctxt->get_elements();
        const auto& cvn = ctresult->get_elements();
        auto diff = (cvo[0].get_element_at_index(0) + cvo[1].get_element_at_index(0) * s_old0) -
                    (cvn[0].get_element_at_index(0) + cvn[1].get_element_at_index(0) * s_new0);
        diff.set_format(Format::COEFFICIENT);

        const NativeInteger q = diff.get_modulus();
        const NativeInteger half = q >> 1;
        NativeInteger max_noise(0);
        for (uint32_t i = 0; i < diff.get_length(); ++i) {
            NativeInteger v = diff[i];
            if (v > half)
                v = q - v;
            if (v > max_noise)
                max_noise = v;
        }

        EXPECT_LE(max_noise.convert_to_int<uint64_t>(), 32u)
                << "the noise added by the sparse encapsulation key switching exceeds the modulus switching noise level";
    } catch (std::exception& e) {
        std::cerr << "Exception thrown from KeySwitchSparseAddedNoise: " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    } catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }

    ContextFactory<RnsPoly>::release_all_contexts();
    cipher_parallel_controls.unit_test_stop();
}
