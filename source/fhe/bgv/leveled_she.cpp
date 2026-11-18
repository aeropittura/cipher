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

#include "cipher/fhe/bgv/leveled_she.h"

#include <cstdint>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/bgv/crypto_params.h"

namespace cipher {

void BgvRnsLeveledShe::mod_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const {
    const auto crypto_params = std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    const auto t = ciphertext->get_crypto_parameters()->get_plaintext_modulus();

    auto& cv = ciphertext->get_elements();
    size_t size_ql = cv[0].get_num_of_elements();

    if (size_ql > levels && size_ql > 0) {
        for (auto& c : cv) {
            for (size_t i = size_ql - 1; i >= size_ql - levels; --i) {
                c.mod_reduce(t, crypto_params->get_t_modq_precon(), crypto_params->get_negt_inv_modq(i),
                             crypto_params->get_negt_inv_modq_precon(i), crypto_params->get_ql_inv_modq(i),
                             crypto_params->get_ql_inv_modq_precon(i));
            }
        }
    } else {
        CIPHER_THROW("Too few towers to support ModReduce.");
    }

    ciphertext->set_level(ciphertext->get_level() + levels);
    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() - levels);

    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
        for (size_t i = 0; i < levels; ++i) {
            NativeInteger mod_reduce_factor = crypto_params->get_mod_reduce_factor_int(size_ql - 1 - i);
            NativeInteger mod_reduce_factor_inv = mod_reduce_factor.mod_inverse(t);
            ciphertext->set_scaling_factor_int(ciphertext->get_scaling_factor_int().mod_mul(mod_reduce_factor_inv, t));
        }
    }
}

void BgvRnsLeveledShe::level_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const {
    for (auto& e : ciphertext->get_elements())
        e.drop_last_elements(levels);
    ciphertext->set_level(ciphertext->get_level() + levels);
}

void BgvRnsLeveledShe::adjust_levels_and_depth_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                        Ciphertext<RnsPoly>& ciphertext2) const {
    const auto crypto_params = std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext1->get_crypto_parameters());

    const NativeInteger t(crypto_params->get_plaintext_modulus());

    uint32_t c1lvl = ciphertext1->get_level();
    uint32_t c2lvl = ciphertext2->get_level();
    uint32_t c1depth = ciphertext1->get_noise_scale_deg();
    uint32_t c2depth = ciphertext2->get_noise_scale_deg();
    auto size_ql1 = ciphertext1->get_elements()[0].get_num_of_elements();
    auto size_ql2 = ciphertext2->get_elements()[0].get_num_of_elements();

    if (c1lvl < c2lvl) {
        if (c1depth == 2) {
            if (c2depth == 2) {
                NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                NativeInteger ql1_modt = crypto_params->get_mod_reduce_factor_int(size_ql1 - 1);
                NativeInteger scf1_inv = scf1.mod_inverse(t);

                eval_mult_core_in_place(ciphertext1, scf2.mod_mul(scf1_inv, t).mod_mul(ql1_modt, t).convert_to_int());
                mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                if (c1lvl + 1 < c2lvl) {
                    level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - 1);
                }
                ciphertext1->set_scaling_factor_int(ciphertext2->get_scaling_factor_int());
            } else {
                if (c1lvl + 1 == c2lvl) {
                    mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                } else {
                    NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                    NativeInteger scf2 = crypto_params->get_scaling_factor_int_big(c2lvl - 1);
                    NativeInteger ql1_modt = crypto_params->get_mod_reduce_factor_int(size_ql1 - 1);
                    NativeInteger scf1_inv = scf1.mod_inverse(t);

                    eval_mult_core_in_place(ciphertext1,
                                            scf2.mod_mul(scf1_inv, t).mod_mul(ql1_modt, t).convert_to_int());
                    mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    if (c1lvl + 2 < c2lvl) {
                        level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - 2);
                    }
                    mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext1->set_scaling_factor_int(ciphertext2->get_scaling_factor_int());
                }
            }
        } else {
            if (c2depth == 2) {
                NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                NativeInteger scf1_inv = scf1.mod_inverse(t);

                eval_mult_core_in_place(ciphertext1, scf2.mod_mul(scf1_inv, t).convert_to_int());
                level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl);
                ciphertext1->set_scaling_factor_int(scf2);
            } else {
                NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                NativeInteger scf2 = crypto_params->get_scaling_factor_int_big(c2lvl - 1);
                NativeInteger scf1_inv = scf1.mod_inverse(t);

                eval_mult_core_in_place(ciphertext1, scf2.mod_mul(scf1_inv, t).convert_to_int());
                if (c1lvl + 1 < c2lvl) {
                    level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - 1);
                }
                mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                ciphertext1->set_scaling_factor_int(ciphertext2->get_scaling_factor_int());
            }
        }
    } else if (c1lvl > c2lvl) {
        if (c2depth == 2) {
            if (c1depth == 2) {
                NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                NativeInteger ql2_modt = crypto_params->get_mod_reduce_factor_int(size_ql2 - 1);
                NativeInteger scf2_inv = scf2.mod_inverse(t);

                eval_mult_core_in_place(ciphertext2, scf1.mod_mul(scf2_inv, t).mod_mul(ql2_modt, t).convert_to_int());
                mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                if (c2lvl + 1 < c1lvl) {
                    level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - 1);
                }
                ciphertext2->set_scaling_factor_int(ciphertext1->get_scaling_factor_int());
            } else {
                if (c2lvl + 1 == c1lvl) {
                    mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                } else {
                    NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                    NativeInteger scf1 = crypto_params->get_scaling_factor_int_big(c1lvl - 1);
                    NativeInteger ql2_modt = crypto_params->get_mod_reduce_factor_int(size_ql2 - 1);
                    NativeInteger scf2_inv = scf2.mod_inverse(t);

                    eval_mult_core_in_place(ciphertext2,
                                            scf1.mod_mul(scf2_inv, t).mod_mul(ql2_modt, t).convert_to_int());
                    mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    if (c2lvl + 2 < c1lvl) {
                        level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - 2);
                    }
                    mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext2->set_scaling_factor_int(ciphertext1->get_scaling_factor_int());
                }
            }
        } else {
            if (c1depth == 2) {
                NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                NativeInteger scf1 = ciphertext1->get_scaling_factor_int();
                NativeInteger scf2_inv = scf2.mod_inverse(t);

                eval_mult_core_in_place(ciphertext2, scf1.mod_mul(scf2_inv, t).convert_to_int());
                level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl);
                ciphertext2->set_scaling_factor_int(scf1);
            } else {
                NativeInteger scf2 = ciphertext2->get_scaling_factor_int();
                NativeInteger scf1 = crypto_params->get_scaling_factor_int_big(c1lvl - 1);
                NativeInteger scf2_inv = scf2.mod_inverse(t);

                eval_mult_core_in_place(ciphertext2, scf1.mod_mul(scf2_inv, t).convert_to_int());
                if (c2lvl + 1 < c1lvl) {
                    level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - 1);
                }
                mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                ciphertext2->set_scaling_factor_int(ciphertext1->get_scaling_factor_int());
            }
        }
    } else {
        if (c1depth < c2depth) {
            NativeInteger scf = ciphertext1->get_scaling_factor_int();
            eval_mult_core_in_place(ciphertext1, scf.convert_to_int());
        } else if (c2depth < c1depth) {
            NativeInteger scf = ciphertext2->get_scaling_factor_int();
            eval_mult_core_in_place(ciphertext2, scf.convert_to_int());
        }
    }
}

void BgvRnsLeveledShe::adjust_levels_and_depth_to_one_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                               Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_levels_and_depth_in_place(ciphertext1, ciphertext2);
    if (ciphertext1->get_noise_scale_deg() == 2) {
        mod_reduce_internal_in_place(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        if (ciphertext2 != ciphertext1)
            mod_reduce_internal_in_place(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
    }
}

void BgvRnsLeveledShe::eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, NativeInteger scalar) const {
    const auto crypto_params = std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto& cv = ciphertext->get_elements();
    for (uint32_t i = 0; i < cv.size(); ++i)
        cv[i] *= scalar;

    const NativeInteger t(crypto_params->get_plaintext_modulus());
    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
        ciphertext->set_scaling_factor_int(ciphertext->get_scaling_factor_int().mod_mul(scalar, t));
    }
}

void BgvRnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    RnsLeveledShe::eval_mult_in_place(ciphertext, plaintext);
    const auto crypto_params = std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext->get_crypto_parameters());
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
        const auto plain_mod = ciphertext->get_crypto_parameters()->get_plaintext_modulus();
        ciphertext->set_scaling_factor_int(
                ciphertext->get_scaling_factor_int().mod_mul(ciphertext->get_scaling_factor_int(), plain_mod));
    }
}

uint32_t BgvRnsLeveledShe::find_automorphism_index(uint32_t index, uint32_t m) const {
    return find_automorphism_index2n(index, m);
}

}  // namespace cipher
