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
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cipher/fhe/bgv/crypto_params.h"

#include <cstdint>
#include <vector>

namespace cipher {

// Precomputation of CRT tables encryption, decryption, and  homomorphic
// multiplication
void BgvRnsCryptoParams::precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech,
                                               EncryptionTechnique enc_tech, MultiplicationTechnique mult_tech,
                                               uint32_t num_part_q, uint32_t aux_bits, uint32_t extra_bits) {
    RnsCryptoParams::precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, extra_bits);

    size_t size_q = get_element_params()->get_params().size();

    std::vector<NativeInteger> moduli_q(size_q);
    std::vector<NativeInteger> roots_q(size_q);

    for (size_t i = 0; i < size_q; i++) {
        moduli_q[i] = get_element_params()->get_params()[i]->get_modulus();
        roots_q[i] = get_element_params()->get_params()[i]->get_root_of_unity();
    }

    NativeInteger t(get_plaintext_modulus());

    if (ks_technique_ == HYBRID) {
        size_t size_p = get_params_p()->get_params().size();
        std::vector<NativeInteger> moduli_p(size_p);
        for (size_t j = 0; j < size_p; j++) {
            moduli_p[j] = get_params_p()->get_params()[j]->get_modulus();
        }

        // Pre-compute values [t^{-1}]_{q_i}, precomputations for  [t]_{q_i}
        t_inv_modq_.resize(size_q);
        t_inv_modq_precon_.resize(size_q);
        for (uint32_t i = 0; i < size_q; i++) {
            t_inv_modq_[i] = t.mod_inverse(moduli_q[i]);
            t_inv_modq_precon_[i] = t_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // Pre-compute values [t^{-1}]_{p_i}, precomputations for [t]_{q_i}
        t_inv_modp_.resize(size_p);
        t_inv_modp_precon_.resize(size_p);
        for (uint32_t j = 0; j < size_p; j++) {
            t_inv_modp_[j] = t.mod_inverse(moduli_p[j]);
            t_inv_modp_precon_[j] = t_inv_modp_[j].prep_mod_mul_const(moduli_p[j]);
        }
    }

    negt_inv_modq_.resize(size_q);
    negt_inv_modq_precon_.resize(size_q);
    t_modq_precon_.resize(size_q);
    ql_inv_modq_.resize(size_q);
    ql_inv_modq_precon_.resize(size_q);
    for (uint32_t i = 0; i < size_q; i++) {
        negt_inv_modq_[i] = moduli_q[i] - t.mod_inverse(moduli_q[i]);
        negt_inv_modq_precon_[i] = negt_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        NativeInteger t_mod_qi = t.mod(moduli_q[i]);
        t_modq_precon_[i] = t_mod_qi.prep_mod_mul_const(moduli_q[i]);
        ql_inv_modq_[i].resize(i);
        ql_inv_modq_precon_[i].resize(i);
        for (uint32_t j = 0; j < i; ++j) {
            ql_inv_modq_[i][j] = moduli_q[i].mod_inverse(moduli_q[j]);
            ql_inv_modq_precon_[i][j] = ql_inv_modq_[i][j].prep_mod_mul_const(moduli_q[j]);
        }
    }

    if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT) {
        scaling_factors_int_.resize(size_q);
        scaling_factors_int_[0] = moduli_q[size_q - 1] % t;
        uint32_t is_flexible_auto_ext = (scal_technique_ == FLEXIBLEAUTOEXT) ? 1 : 0;
        if (is_flexible_auto_ext) {
            scaling_factors_int_[1] = moduli_q[size_q - 2] % t;
        }
        for (uint32_t k = 1 + is_flexible_auto_ext; k < size_q - is_flexible_auto_ext; k++) {
            NativeInteger prev_sf = scaling_factors_int_[k - 1];
            NativeInteger q_inv = moduli_q[size_q - k].mod_inverse(t);
            scaling_factors_int_[k] = prev_sf.mod_mul(prev_sf, t).mod_mul(q_inv, t);
        }

        scaling_factors_int_big_.resize(size_q - 1);

        if (scaling_factors_int_big_.size() > 0) {
            if (scal_technique_ == FLEXIBLEAUTO) {
                scaling_factors_int_big_[0] = scaling_factors_int_[0].mod_mul(scaling_factors_int_[0], t);
            } else {
                scaling_factors_int_big_[0] = scaling_factors_int_[0].mod_mul(scaling_factors_int_[1], t);
            }
            for (uint32_t k = 1; k < size_q - 1; k++) {
                scaling_factors_int_big_[k] = scaling_factors_int_[k].mod_mul(scaling_factors_int_[k], t);
            }
        }

        // Moduli mod t
        q_modt_.resize(size_q);
        for (uint32_t i = 0; i < size_q; i++) {
            q_modt_[i] = moduli_q[i].mod(t);
        }
    }

    if (ks_technique_ == HYBRID) {
        const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
        modq_barrett_mu_.resize(size_q);
        for (uint32_t i = 0; i < size_q; i++) {
            modq_barrett_mu_[i] = (barrett_base128_bit / BigInteger(moduli_q[i])).convert_to_int<DoubleNativeInt>();
        }
    }
}

uint64_t BgvRnsCryptoParams::find_aux_prime_step() const {
    size_t n = get_element_params()->get_ring_dimension();
    uint32_t plaintext_modulus = get_plaintext_modulus();
    uint32_t cycl_order = 2 * n;
    uint32_t pow2ptm = 1;

    // The largest power of 2 dividing ptm
    // Check whether it is larger than cycl_order or not
    while (plaintext_modulus % 2 == 0) {
        plaintext_modulus >>= 1;
        pow2ptm <<= 1;
    }

    if (pow2ptm < cycl_order)
        pow2ptm = cycl_order;

    return static_cast<uint64_t>(pow2ptm) * plaintext_modulus;
}

}  // namespace cipher
