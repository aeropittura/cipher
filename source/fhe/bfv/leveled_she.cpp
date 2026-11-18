//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cipher/fhe/bfv/leveled_she.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/bfv/crypto_params.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

void BfvRnsLeveledShe::eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto pt = plaintext->get_element<RnsPoly>();
    pt.set_format(COEFFICIENT);

    // enables encoding of plaintexts using a smaller number of RNS limbs
    auto size_q = crypto_params->get_element_params()->get_params().size();
    auto size_p = pt.get_params()->get_params().size();
    auto level = size_q - size_p;

    auto&& neg_q_modt = crypto_params->get_neg_q_modt(level);
    auto&& neg_q_modt_precon = crypto_params->get_neg_q_modt_precon(level);
    auto&& t_inv_modq = crypto_params->get_t_inv_modq();
    auto&& t = crypto_params->get_plaintext_modulus();
    pt.times_qovert(crypto_params->get_element_params(), t_inv_modq, t, neg_q_modt, neg_q_modt_precon);
    pt.set_format(EVALUATION);

    ciphertext->get_elements()[0] += pt;
}

void BfvRnsLeveledShe::eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto pt = plaintext->get_element<RnsPoly>();
    pt.set_format(COEFFICIENT);

    // enables encoding of plaintexts using a smaller number of RNS limbs
    auto size_q = crypto_params->get_element_params()->get_params().size();
    auto size_p = pt.get_params()->get_params().size();
    auto level = size_q - size_p;

    auto&& neg_q_modt = crypto_params->get_neg_q_modt(level);
    auto&& neg_q_modt_precon = crypto_params->get_neg_q_modt_precon(level);
    auto&& t_inv_modq = crypto_params->get_t_inv_modq();
    auto&& t = crypto_params->get_plaintext_modulus();
    pt.times_qovert(crypto_params->get_element_params(), t_inv_modq, t, neg_q_modt, neg_q_modt_precon);
    pt.set_format(EVALUATION);

    ciphertext->get_elements()[0] -= pt;
}

uint32_t find_levels_to_drop(uint32_t multiplicative_depth, std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params,
                             uint32_t dcrt_bits, bool key_switch_value = false) {
    const auto crypto_params_bfv_rns = std::dynamic_pointer_cast<BfvRnsCryptoParams>(crypto_params);
    double sigma = crypto_params_bfv_rns->get_distribution_parameter();
    double alpha = crypto_params_bfv_rns->get_assurance_measure();
    double p = static_cast<double>(crypto_params_bfv_rns->get_plaintext_modulus());
    uint32_t n = crypto_params_bfv_rns->get_element_params()->get_ring_dimension();
    uint32_t relin_window = crypto_params_bfv_rns->get_digit_size();
    KeySwitchTechnique scal_technique = crypto_params_bfv_rns->get_key_switch_technique();
    EncryptionTechnique enc_tech = crypto_params_bfv_rns->get_encryption_technique();

    uint32_t k = crypto_params_bfv_rns->get_num_per_part_q();
    uint32_t num_part_q = crypto_params_bfv_rns->get_num_part_q();
    uint32_t threshold_parties = crypto_params_bfv_rns->get_threshold_num_of_parties();

    // Bound of the Gaussian error polynomial
    double berr = sigma * std::sqrt(alpha);

    // Bkey set to threshold_parties * 1 for ternary distribution
    const double bkey = (crypto_params_bfv_rns->get_secret_key_dist() == GAUSSIAN) ?
                                std::sqrt(threshold_parties) * berr :
                                threshold_parties;

    double w = std::pow(2, relin_window == 0 ? dcrt_bits : relin_window);

    // expansion factor delta for a multiplication of a Gaussian polynomial by a random polynomial
    auto delta = [](uint32_t n) -> double {
        return (2. * std::sqrt(n));
    };

    // expansion factor delta for modulus switching
    auto delta_ms = [](uint32_t n) -> double {
        return (4. * std::sqrt(n));
    };

    // norm of fresh ciphertext polynomial (for EXTENDED the noise is reduced to modulus switching noise)
    auto vnorm = [&](uint32_t n) -> double {
        if (enc_tech == EXTENDED)
            return (1. + delta_ms(n) * bkey) / 2.;
        else
            return berr * (1. + 2. * delta(n) * bkey);
    };

    auto noise_ks = [&](uint32_t n, double logq_prev, double w) -> double {
        if (scal_technique == HYBRID)
#if defined(CIPHER_WITH_REDUCED_NOISE)
            return k * (num_part_q * delta(n) * berr + delta(n) * bkey + 1.0) / 2.0;
#else
            return k * (num_part_q * delta(n) * berr + delta_ms(n) * bkey + 1.0);
#endif
        else {
            double num_digits_per_tower = (relin_window == 0) ? 1 : ((dcrt_bits / relin_window) + 1);
            return delta(n) * num_digits_per_tower * (std::floor(logq_prev / dcrt_bits) + 1) * w * berr / 2.0;
        }
    };

    // function used in the eval_mult constraint
    auto C1 = [&](uint32_t n) -> double {
        return delta(n) * delta_ms(n) * p * bkey;
    };

    // function used in the eval_mult constraint
    auto C2 = [&](uint32_t n, double logq_prev) -> double {
        return delta(n) * delta_ms(n) * bkey * bkey / 2.0 + noise_ks(n, logq_prev, w);
    };

    // main correctness constraint
    auto logq_bfv = [&](uint32_t n, double logq_prev) -> double {
        if (multiplicative_depth > 0) {
            return std::log2(4 * p) + (multiplicative_depth - 1) * std::log2(C1(n)) +
                   std::log2(C1(n) * vnorm(n) + multiplicative_depth * C2(n, logq_prev));
        }
        return std::log2(p * (4 * (vnorm(n))));
    };

    // initial values
    double logq_prev = 6. * std::log2(10);
    double logq = logq_bfv(n, logq_prev);

    while (std::fabs(logq - logq_prev) > std::log2(1.001)) {
        logq_prev = logq;
        logq = logq_bfv(n, logq_prev);
    }

    // get an estimate of the error q / (4t)
    double loge = logq - 2 - std::log2(p);

    double log_extra = key_switch_value ? std::log2(noise_ks(n, logq, w)) : std::log2(delta_ms(n));

    // adding the cushon to the error (see Appendix D of https://eprint.iacr.org/2021/204.pdf for details)
    // adjusted empirical parameter to 16 from 4 for threshold scenarios to work correctly, this might need to
    // be further refined
    int32_t levels = std::floor((loge - 3 * multiplicative_depth - 16 - log_extra) / dcrt_bits);
    size_t size_q = crypto_params_bfv_rns->get_element_params()->get_params().size();

    if (levels < 0)
        levels = 0;
    else if (levels > static_cast<int32_t>(size_q) - 1)
        levels = size_q - 1;

    return levels;
};

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                                ConstCiphertext<RnsPoly>& ciphertext2) const {
    if (ciphertext1->get_crypto_parameters() != ciphertext2->get_crypto_parameters())
        CIPHER_THROW("crypto parameters are not the same");

    const auto crypto_params =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext1->get_crypto_context()->get_crypto_parameters());

    std::vector<RnsPoly> cv1 = ciphertext1->get_elements();
    std::vector<RnsPoly> cv2 = ciphertext2->get_elements();

    uint32_t cv1_size = cv1.size();
    uint32_t cv2_size = cv2.size();
    uint32_t cv_mult_size = cv1_size + cv2_size - 1;
    uint32_t size_q = cv1[0].get_num_of_elements();
    const auto element_params = crypto_params->get_element_params();
    // Maximum number of RNS limbs in the crypto context
    uint32_t size_qm = element_params->get_params().size();

    // l is index corresponding to leveled parameters in crypto_parameters precomputations in HPSPOVERQLEVELED
    uint32_t l = 0;

    std::vector<RnsPoly> cv_mult(cv_mult_size);

    if (crypto_params->get_multiplication_technique() == HPS) {
        for (uint32_t i = 0; i < cv1_size; ++i) {
            cv1[i].expand_crt_basis(crypto_params->get_params_ql_rl(), crypto_params->get_params_rl(),
                                    crypto_params->get_ql_hat_inv_modq(), crypto_params->get_ql_hat_inv_modq_precon(),
                                    crypto_params->get_ql_hat_modr(), crypto_params->get_alpha_ql_modr(),
                                    crypto_params->get_modr_barrett_mu(), crypto_params->get_q_inv(),
                                    Format::EVALUATION);
        }

        for (uint32_t i = 0; i < cv2_size; ++i) {
            cv2[i].expand_crt_basis(crypto_params->get_params_ql_rl(), crypto_params->get_params_rl(),
                                    crypto_params->get_ql_hat_inv_modq(), crypto_params->get_ql_hat_inv_modq_precon(),
                                    crypto_params->get_ql_hat_modr(), crypto_params->get_alpha_ql_modr(),
                                    crypto_params->get_modr_barrett_mu(), crypto_params->get_q_inv(),
                                    Format::EVALUATION);
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQ) ||
               ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q < size_qm))) {
        for (uint32_t i = 0; i < cv1_size; ++i) {
            // Expand ciphertext1 from basis Q to PQ (from Q_l to P_l*Q_l if manual compress/lower-level-encode was called)
            cv1[i].expand_crt_basis(
                    crypto_params->get_params_ql_rl(size_q - 1), crypto_params->get_params_rl(size_q - 1),
                    crypto_params->get_ql_hat_inv_modq(size_q - 1),
                    crypto_params->get_ql_hat_inv_modq_precon(size_q - 1), crypto_params->get_ql_hat_modr(size_q - 1),
                    crypto_params->get_alpha_ql_modr(size_q - 1), crypto_params->get_modr_barrett_mu(),
                    crypto_params->get_q_inv(), Format::EVALUATION);
        }

        RnsPoly::CrtBasisExtensionPrecomputations basis_pq(
                crypto_params->get_params_ql_rl(size_q - 1), crypto_params->get_params_rl(size_q - 1),
                crypto_params->get_params_ql(size_q - 1), crypto_params->get_m_neg_rl_ql_hat_inv_modq(size_q - 1),
                crypto_params->get_m_neg_rl_ql_hat_inv_modq_precon(size_q - 1), crypto_params->get_q_inv_modr(),
                crypto_params->get_modr_barrett_mu(), crypto_params->get_rl_hat_inv_modr(size_q - 1),
                crypto_params->get_rl_hat_inv_modr_precon(size_q - 1), crypto_params->get_rl_hat_modq(size_q - 1),
                crypto_params->get_alpha_rl_modq(size_q - 1), crypto_params->get_modq_barrett_mu(),
                crypto_params->get_r_inv());

        for (uint32_t i = 0; i < cv2_size; ++i) {
            cv2[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Switch ciphertext2 from basis Q to P to PQ (from Q_l to P_l to P_l*Q_l if manual compress/lower-level-encode was called).
            cv2[i].fast_expand_crt_basis_plover_q(basis_pq);
            cv2[i].set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm)) {
        uint32_t c1depth = ciphertext1->get_noise_scale_deg();
        uint32_t c2depth = ciphertext2->get_noise_scale_deg();

        uint32_t levels = std::max(c1depth, c2depth) - 1;
        uint32_t dcrt_bits = cv1[0].get_element_at_index(0).get_modulus().get_msb();

        // how many levels to drop
        uint32_t levels_dropped = find_levels_to_drop(levels, crypto_params, dcrt_bits, false);
        l = levels_dropped > 0 ? size_q - 1 - levels_dropped : size_q - 1;

        for (uint32_t i = 0; i < cv1_size; ++i) {
            cv1[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            if (l < size_q - 1) {
                // Drop from basis Q to Q_l.
                cv1[i] = cv1[i].scale_and_round(
                        crypto_params->get_params_ql(l), crypto_params->get_ql_q_hat_inv_modq_divq_modq(l),
                        crypto_params->get_ql_q_hat_inv_modq_divq_frac(l), crypto_params->get_modq_barrett_mu());
            }
            // Expand ciphertext1 from basis Q_l to P_l*Q_l.
            cv1[i].expand_crt_basis(crypto_params->get_params_ql_rl(l), crypto_params->get_params_rl(l),
                                    crypto_params->get_ql_hat_inv_modq(l), crypto_params->get_ql_hat_inv_modq_precon(l),
                                    crypto_params->get_ql_hat_modr(l), crypto_params->get_alpha_ql_modr(l),
                                    crypto_params->get_modr_barrett_mu(), crypto_params->get_q_inv(),
                                    Format::EVALUATION);
        }

        RnsPoly::CrtBasisExtensionPrecomputations basis_pq(
                crypto_params->get_params_ql_rl(l), crypto_params->get_params_rl(l), crypto_params->get_params_ql(l),
                crypto_params->get_m_neg_rl_q_hat_inv_modq(l), crypto_params->get_m_neg_rl_q_hat_inv_modq_precon(l),
                crypto_params->get_q_inv_modr(), crypto_params->get_modr_barrett_mu(),
                crypto_params->get_rl_hat_inv_modr(l), crypto_params->get_rl_hat_inv_modr_precon(l),
                crypto_params->get_rl_hat_modq(l), crypto_params->get_alpha_rl_modq(l),
                crypto_params->get_modq_barrett_mu(), crypto_params->get_r_inv());

        for (uint32_t i = 0; i < cv2_size; ++i) {
            cv2[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Switch ciphertext2 from basis Q to P_l to P_l*Q_l.
            cv2[i].fast_expand_crt_basis_plover_q(basis_pq);
            cv2[i].set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        }
    } else {
        for (uint32_t i = 0; i < cv1_size; ++i) {
            cv1[i].fast_base_convq_to_bsk_montgomery(
                    crypto_params->get_params_q_bsk(), crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
                    crypto_params->get_modbsk_barrett_mu(), crypto_params->get_mtilde_q_hat_inv_modq(),
                    crypto_params->get_mtilde_q_hat_inv_modq_precon(), crypto_params->get_q_hat_modbsk(),
                    crypto_params->get_q_hat_modmtilde(), crypto_params->get_q_modbsk(),
                    crypto_params->get_q_modbsk_precon(), crypto_params->get_neg_q_inv_modmtilde(),
                    crypto_params->get_mtilde_inv_modbsk(), crypto_params->get_mtilde_inv_modbsk_precon());
            cv1[i].set_format(Format::EVALUATION);
        }

        for (uint32_t i = 0; i < cv2_size; ++i) {
            cv2[i].fast_base_convq_to_bsk_montgomery(
                    crypto_params->get_params_q_bsk(), crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
                    crypto_params->get_modbsk_barrett_mu(), crypto_params->get_mtilde_q_hat_inv_modq(),
                    crypto_params->get_mtilde_q_hat_inv_modq_precon(), crypto_params->get_q_hat_modbsk(),
                    crypto_params->get_q_hat_modmtilde(), crypto_params->get_q_modbsk(),
                    crypto_params->get_q_modbsk_precon(), crypto_params->get_neg_q_inv_modmtilde(),
                    crypto_params->get_mtilde_inv_modbsk(), crypto_params->get_mtilde_inv_modbsk_precon());
            cv2[i].set_format(Format::EVALUATION);
        }
    }

#ifdef USE_KARATSUBA
    if (cv1_size == 2 && cv2_size == 2) {
        // size of each ciphertxt = 2, use Karatsuba
        cv_mult[0] = cv1[0] * cv2[0];  // a
        cv_mult[2] = cv1[1] * cv2[1];  // b

        cv_mult[1] = cv1[0] + cv1[1];
        cv_mult[1] *= (cv2[0] + cv2[1]);
        cv_mult[1] -= cv_mult[2];
        cv_mult[1] -= cv_mult[0];
    } else {  // if size of any of the ciphertexts > 2
        std::vector<bool> is_first_add(cv_mult_size, true);

        for (uint32_t i = 0; i < cv1_size; i++) {
            for (uint32_t j = 0; j < cv2_size; j++) {
                if (is_first_add[i + j] == true) {
                    cv_mult[i + j] = cv1[i] * cv2[j];
                    is_first_add[i + j] = false;
                } else {
                    cv_mult[i + j].mult_acc_eq_no_check(cv1[i], cv2[j]);
                }
            }
        }
    }
#else
    std::vector<bool> is_first_add(cv_mult_size, true);
    for (uint32_t i = 0; i < cv1_size; i++) {
        for (uint32_t j = 0; j < cv2_size; j++) {
            if (is_first_add[i + j] == true) {
                cv_mult[i + j] = cv1[i] * cv2[j];
                is_first_add[i + j] = false;
            } else {
                cv_mult[i + j].mult_acc_eq_no_check(cv1[i], cv2[j]);
            }
        }
    }
#endif

    if (crypto_params->get_multiplication_technique() == HPS) {
        for (uint32_t i = 0; i < cv_mult_size; ++i) {
            // converts to coefficient representation before rounding
            cv_mult[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis P
            cv_mult[i] = cv_mult[i].scale_and_round(
                    crypto_params->get_params_rl(), crypto_params->get_t_rs_hat_inv_mods_divs_modr(),
                    crypto_params->get_t_rs_hat_inv_mods_divs_frac(), crypto_params->get_modr_barrett_mu());

            // Converts from the CRT basis P to Q
            cv_mult[i] = cv_mult[i].switch_crt_basis(
                    crypto_params->get_element_params(), crypto_params->get_rl_hat_inv_modr(),
                    crypto_params->get_rl_hat_inv_modr_precon(), crypto_params->get_rl_hat_modq(),
                    crypto_params->get_alpha_rl_modq(), crypto_params->get_modq_barrett_mu(),
                    crypto_params->get_r_inv());
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQ) ||
               ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q < size_qm))) {
        l = size_q - 1;
        for (uint32_t i = 0; i < cv_mult_size; ++i) {
            cv_mult[i].set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q (Q_l if compress/lower-level encode was used)
            cv_mult[i] = cv_mult[i].scale_and_round(
                    crypto_params->get_params_ql(l), crypto_params->get_t_ql_sl_hat_inv_mods_divs_modq(l),
                    crypto_params->get_t_ql_sl_hat_inv_mods_divs_frac(l), crypto_params->get_modq_barrett_mu());
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm)) {
        for (uint32_t i = 0; i < cv_mult_size; ++i) {
            cv_mult[i].set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Ql
            cv_mult[i] = cv_mult[i].scale_and_round(
                    crypto_params->get_params_ql(l), crypto_params->get_t_ql_sl_hat_inv_mods_divs_modq(l),
                    crypto_params->get_t_ql_sl_hat_inv_mods_divs_frac(l), crypto_params->get_modq_barrett_mu());

            if (l < size_q - 1) {
                // Expand back to basis Q.
                cv_mult[i].expand_crt_basis_ql_hat(crypto_params->get_element_params(),
                                                   crypto_params->get_ql_hat_modq(l),
                                                   crypto_params->get_ql_hat_modq_precon(l), size_q);
            }
        }
    } else {
        const NativeInteger& t = crypto_params->get_plaintext_modulus();
        for (uint32_t i = 0; i < cv_mult_size; ++i) {
            // converts to Format::COEFFICIENT representation before rounding
            cv_mult[i].set_format(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis {Bsk}
            cv_mult[i].fast_rns_floorq(t, crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
                                       crypto_params->get_modbsk_barrett_mu(), crypto_params->get_t_q_hat_inv_modq(),
                                       crypto_params->get_t_q_hat_inv_modq_precon(), crypto_params->get_q_hat_modbsk(),
                                       crypto_params->get_q_inv_modbsk(), crypto_params->get_t_q_inv_modbsk(),
                                       crypto_params->get_t_q_inv_modbsk_precon());

            // Converts from the CRT basis {Bsk} to {Q}
            cv_mult[i].fast_base_conv_sk(crypto_params->get_element_params(), crypto_params->get_modq_barrett_mu(),
                                         crypto_params->get_moduli_bsk(), crypto_params->get_modbsk_barrett_mu(),
                                         crypto_params->get_b_hat_inv_modb(),
                                         crypto_params->get_b_hat_inv_modb_precon(), crypto_params->get_b_hat_modmsk(),
                                         crypto_params->get_b_inv_modmsk(), crypto_params->get_b_inv_modmsk_precon(),
                                         crypto_params->get_b_hat_modq(), crypto_params->get_b_modq(),
                                         crypto_params->get_b_modq_precon());
        }
    }

    auto ciphertext_mult = ciphertext1->clone_empty();
    ciphertext_mult->set_elements(std::move(cv_mult));
    ciphertext_mult->set_noise_scale_deg(
            std::max(ciphertext1->get_noise_scale_deg(), ciphertext2->get_noise_scale_deg()) + 1);
    return ciphertext_mult;
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_square(ConstCiphertext<RnsPoly>& ciphertext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_context()->get_crypto_parameters());

    std::vector<RnsPoly> cv = ciphertext->get_elements();

    size_t cv_size = cv.size();
    size_t cv_sq_size = 2 * cv_size - 1;
    size_t size_q = cv[0].get_num_of_elements();
    const auto element_params = crypto_params->get_element_params();
    // Maximum number of RNS limbs in the crypto context
    size_t size_qm = element_params->get_params().size();

    // l is index corresponding to leveled parameters in crypto_parameters precomputations in HPSPOVERQLEVELED
    size_t l = 0;

    std::vector<RnsPoly> cv_pover_q;
    if (crypto_params->get_multiplication_technique() == HPS) {
        for (size_t i = 0; i < cv_size; i++) {
            cv[i].expand_crt_basis(crypto_params->get_params_ql_rl(), crypto_params->get_params_rl(),
                                   crypto_params->get_ql_hat_inv_modq(), crypto_params->get_ql_hat_inv_modq_precon(),
                                   crypto_params->get_ql_hat_modr(), crypto_params->get_alpha_ql_modr(),
                                   crypto_params->get_modr_barrett_mu(), crypto_params->get_q_inv(),
                                   Format::EVALUATION);
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQ) ||
               ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q < size_qm))) {
        cv_pover_q = cv;
        for (size_t i = 0; i < cv_size; i++) {
            // Expand ciphertext1 from basis Q to PQ.
            cv[i].expand_crt_basis(
                    crypto_params->get_params_ql_rl(size_q - 1), crypto_params->get_params_rl(size_q - 1),
                    crypto_params->get_ql_hat_inv_modq(size_q - 1),
                    crypto_params->get_ql_hat_inv_modq_precon(size_q - 1), crypto_params->get_ql_hat_modr(size_q - 1),
                    crypto_params->get_alpha_ql_modr(size_q - 1), crypto_params->get_modr_barrett_mu(),
                    crypto_params->get_q_inv(), Format::EVALUATION);
        }

        RnsPoly::CrtBasisExtensionPrecomputations basis_pq(
                crypto_params->get_params_ql_rl(size_q - 1), crypto_params->get_params_rl(size_q - 1),
                crypto_params->get_params_ql(size_q - 1), crypto_params->get_m_neg_rl_ql_hat_inv_modq(size_q - 1),
                crypto_params->get_m_neg_rl_ql_hat_inv_modq_precon(size_q - 1), crypto_params->get_q_inv_modr(),
                crypto_params->get_modr_barrett_mu(), crypto_params->get_rl_hat_inv_modr(size_q - 1),
                crypto_params->get_rl_hat_inv_modr_precon(size_q - 1), crypto_params->get_rl_hat_modq(size_q - 1),
                crypto_params->get_alpha_rl_modq(size_q - 1), crypto_params->get_modq_barrett_mu(),
                crypto_params->get_r_inv());

        for (size_t i = 0; i < cv_size; i++) {
            cv_pover_q[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Switch ciphertext2 from basis Q to P to PQ (from Q_l to P_l to P_l*Q_l if manual compress/lower-level-encode was called).
            cv_pover_q[i].fast_expand_crt_basis_plover_q(basis_pq);
            cv_pover_q[i].set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm)) {
        uint32_t cdepth = ciphertext->get_noise_scale_deg();
        uint32_t levels = cdepth - 1;
        uint32_t dcrt_bits = cv[0].get_element_at_index(0).get_modulus().get_msb();

        // how many levels to drop
        uint32_t levels_dropped = find_levels_to_drop(levels, crypto_params, dcrt_bits, false);
        l = levels_dropped > 0 ? size_q - 1 - levels_dropped : size_q - 1;

        for (size_t i = 0; i < cv_size; i++) {
            cv[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        }

        cv_pover_q = cv;

        for (size_t i = 0; i < cv_size; i++) {
            if (l < size_q - 1) {
                // Drop from basis Q to Q_l.
                cv[i] = cv[i].scale_and_round(
                        crypto_params->get_params_ql(l), crypto_params->get_ql_q_hat_inv_modq_divq_modq(l),
                        crypto_params->get_ql_q_hat_inv_modq_divq_frac(l), crypto_params->get_modq_barrett_mu());
            }
            // Expand ciphertext1 from basis Q_l to PQ_l.
            cv[i].expand_crt_basis(crypto_params->get_params_ql_rl(l), crypto_params->get_params_rl(l),
                                   crypto_params->get_ql_hat_inv_modq(l), crypto_params->get_ql_hat_inv_modq_precon(l),
                                   crypto_params->get_ql_hat_modr(l), crypto_params->get_alpha_ql_modr(l),
                                   crypto_params->get_modr_barrett_mu(), crypto_params->get_q_inv(),
                                   Format::EVALUATION);
        }

        RnsPoly::CrtBasisExtensionPrecomputations basis_pq(
                crypto_params->get_params_ql_rl(l), crypto_params->get_params_rl(l), crypto_params->get_params_ql(l),
                crypto_params->get_m_neg_rl_q_hat_inv_modq(l), crypto_params->get_m_neg_rl_q_hat_inv_modq_precon(l),
                crypto_params->get_q_inv_modr(), crypto_params->get_modr_barrett_mu(),
                crypto_params->get_rl_hat_inv_modr(l), crypto_params->get_rl_hat_inv_modr_precon(l),
                crypto_params->get_rl_hat_modq(l), crypto_params->get_alpha_rl_modq(l),
                crypto_params->get_modq_barrett_mu(), crypto_params->get_r_inv());

        for (size_t i = 0; i < cv_size; i++) {
            cv_pover_q[i].fast_expand_crt_basis_plover_q(basis_pq);
            cv_pover_q[i].set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        }
    } else {
        for (size_t i = 0; i < cv_size; i++) {
            cv[i].fast_base_convq_to_bsk_montgomery(
                    crypto_params->get_params_q_bsk(), crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
                    crypto_params->get_modbsk_barrett_mu(), crypto_params->get_mtilde_q_hat_inv_modq(),
                    crypto_params->get_mtilde_q_hat_inv_modq_precon(), crypto_params->get_q_hat_modbsk(),
                    crypto_params->get_q_hat_modmtilde(), crypto_params->get_q_modbsk(),
                    crypto_params->get_q_modbsk_precon(), crypto_params->get_neg_q_inv_modmtilde(),
                    crypto_params->get_mtilde_inv_modbsk(), crypto_params->get_mtilde_inv_modbsk_precon());

            cv[i].set_format(Format::EVALUATION);
        }
    }

    std::vector<RnsPoly> cv_square(cv_sq_size);
#ifdef USE_KARATSUBA
    if (cv_size == 2) {
        if (crypto_params->get_multiplication_technique() == HPS ||
            crypto_params->get_multiplication_technique() == BEHZ) {
            // size of each ciphertxt = 2, use Karatsuba
            cv_square[0] = cv[0] * cv[0];  // a
            cv_square[2] = cv[1] * cv[1];  // b

            cv_square[1] = cv1[0] * cv1[1];
            cv_square[1] += cv_square[1];
        } else {
            // size of each ciphertxt = 2, use Karatsuba
            cv_square[0] = cv[0] * cv_pover_q[0];  // a
            cv_square[2] = cv[1] * cv_pover_q[1];  // b

            cv_square[1] = cv[0] + cv[1];
            cv_square[1] *= (cv_pover_q[0] + cv_pover_q[1]);
            cv_square[1] -= cv_square[2];
            cv_square[1] -= cv_square[0];
        }
    } else {
        std::vector<bool> is_first_add(cv_sq_size, true);
        RnsPoly cvtemp;

        if (crypto_params->get_multiplication_technique() == HPS ||
            crypto_params->get_multiplication_technique() == BEHZ) {
            for (size_t i = 0; i < cv_size; i++) {
                for (size_t j = i; j < cv_size; j++) {
                    if (is_first_add[i + j] == true) {
                        if (j == i) {
                            cv_square[i + j] = cv[i] * cv[j];
                        } else {
                            cvtemp = cv[i] * cv[j];
                            cv_square[i + j] = cvtemp;
                            cv_square[i + j] += cvtemp;
                        }
                        is_first_add[i + j] = false;
                    } else {
                        if (j == i) {
                            cv_square[i + j].mult_acc_eq_no_check(cv[i], cv[j]);
                        } else {
                            cvtemp = cv[i] * cv[j];
                            cv_square[i + j] += cvtemp;
                            cv_square[i + j] += cvtemp;
                        }
                    }
                }
            }
        } else {
            for (size_t i = 0; i < cv_size; i++) {
                for (size_t j = 0; j < cv_size; j++) {
                    if (is_first_add[i + j] == true) {
                        cv_square[i + j] = cv[i] * cv_pover_q[j];
                        is_first_add[i + j] = false;
                    } else {
                        cv_square[i + j].mult_acc_eq_no_check(cv[i], cv_pover_q[j]);
                    }
                }
            }
        }
    }
#else
    std::vector<bool> is_first_add(cv_sq_size, true);
    RnsPoly cvtemp;

    if (crypto_params->get_multiplication_technique() == HPS || crypto_params->get_multiplication_technique() == BEHZ) {
        for (size_t i = 0; i < cv_size; i++) {
            for (size_t j = i; j < cv_size; j++) {
                if (is_first_add[i + j] == true) {
                    if (j == i) {
                        cv_square[i + j] = cv[i] * cv[j];
                    } else {
                        cvtemp = cv[i] * cv[j];
                        cv_square[i + j] = cvtemp;
                        cv_square[i + j] += cvtemp;
                    }
                    is_first_add[i + j] = false;
                } else {
                    if (j == i) {
                        cv_square[i + j].mult_acc_eq_no_check(cv[i], cv[j]);
                    } else {
                        cvtemp = cv[i] * cv[j];
                        cv_square[i + j] += cvtemp;
                        cv_square[i + j] += cvtemp;
                    }
                }
            }
        }
    } else {
        for (size_t i = 0; i < cv_size; i++) {
            for (size_t j = 0; j < cv_size; j++) {
                if (is_first_add[i + j] == true) {
                    cv_square[i + j] = cv[i] * cv_pover_q[j];
                    is_first_add[i + j] = false;
                } else {
                    cv_square[i + j].mult_acc_eq_no_check(cv[i], cv_pover_q[j]);
                }
            }
        }
    }
#endif

    if (crypto_params->get_multiplication_technique() == HPS) {
        for (size_t i = 0; i < cv_sq_size; i++) {
            // converts to coefficient representation before rounding
            cv_square[i].set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis P
            cv_square[i] = cv_square[i].scale_and_round(
                    crypto_params->get_params_rl(), crypto_params->get_t_rs_hat_inv_mods_divs_modr(),
                    crypto_params->get_t_rs_hat_inv_mods_divs_frac(), crypto_params->get_modr_barrett_mu());

            // Converts from the CRT basis P to Q
            cv_square[i] = cv_square[i].switch_crt_basis(
                    crypto_params->get_element_params(), crypto_params->get_rl_hat_inv_modr(),
                    crypto_params->get_rl_hat_inv_modr_precon(), crypto_params->get_rl_hat_modq(),
                    crypto_params->get_alpha_rl_modq(), crypto_params->get_modq_barrett_mu(),
                    crypto_params->get_r_inv());
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQ) ||
               ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q < size_qm))) {
        l = size_q - 1;
        for (size_t i = 0; i < cv_sq_size; i++) {
            cv_square[i].set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q (Q_l if compress/lower-level encode was used)
            cv_square[i] = cv_square[i].scale_and_round(
                    crypto_params->get_params_ql(l), crypto_params->get_t_ql_sl_hat_inv_mods_divs_modq(l),
                    crypto_params->get_t_ql_sl_hat_inv_mods_divs_frac(l), crypto_params->get_modq_barrett_mu());
        }
    } else if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm)) {
        for (size_t i = 0; i < cv_sq_size; i++) {
            cv_square[i].set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q
            cv_square[i] = cv_square[i].scale_and_round(
                    crypto_params->get_params_ql(l), crypto_params->get_t_ql_sl_hat_inv_mods_divs_modq(l),
                    crypto_params->get_t_ql_sl_hat_inv_mods_divs_frac(l), crypto_params->get_modq_barrett_mu());

            if (l < size_q - 1) {
                // Expand back to basis Q.
                cv_square[i].expand_crt_basis_ql_hat(crypto_params->get_element_params(),
                                                     crypto_params->get_ql_hat_modq(l),
                                                     crypto_params->get_ql_hat_modq_precon(l), size_q);
            }
        }
    } else {
        const NativeInteger& t = crypto_params->get_plaintext_modulus();
        for (size_t i = 0; i < cv_sq_size; i++) {
            // converts to Format::COEFFICIENT representation before rounding
            cv_square[i].set_format(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis {Bsk}
            cv_square[i].fast_rns_floorq(t, crypto_params->get_moduli_q(), crypto_params->get_moduli_bsk(),
                                         crypto_params->get_modbsk_barrett_mu(), crypto_params->get_t_q_hat_inv_modq(),
                                         crypto_params->get_t_q_hat_inv_modq_precon(),
                                         crypto_params->get_q_hat_modbsk(), crypto_params->get_q_inv_modbsk(),
                                         crypto_params->get_t_q_inv_modbsk(),
                                         crypto_params->get_t_q_inv_modbsk_precon());

            // Converts from the CRT basis {Bsk} to {Q}
            cv_square[i].fast_base_conv_sk(crypto_params->get_element_params(), crypto_params->get_modq_barrett_mu(),
                                           crypto_params->get_moduli_bsk(), crypto_params->get_modbsk_barrett_mu(),
                                           crypto_params->get_b_hat_inv_modb(),
                                           crypto_params->get_b_hat_inv_modb_precon(),
                                           crypto_params->get_b_hat_modmsk(), crypto_params->get_b_inv_modmsk(),
                                           crypto_params->get_b_inv_modmsk_precon(), crypto_params->get_b_hat_modq(),
                                           crypto_params->get_b_modq(), crypto_params->get_b_modq_precon());
        }
    }

    auto ciphertext_sq = ciphertext->clone_empty();
    ciphertext_sq->set_elements(std::move(cv_square));
    ciphertext_sq->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);

    return ciphertext_sq;
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                                ConstCiphertext<RnsPoly>& ciphertext2,
                                                const EvalKey<RnsPoly> eval_key) const {
    auto ciphertext = eval_mult(ciphertext1, ciphertext2);
    relinearize_core(ciphertext, eval_key);
    return ciphertext;
}

void BfvRnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2,
                                          const EvalKey<RnsPoly> eval_key) const {
    ciphertext1 = eval_mult(ciphertext1, ciphertext2);
    relinearize_core(ciphertext1, eval_key);
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_square(ConstCiphertext<RnsPoly>& ciphertext,
                                                  const EvalKey<RnsPoly> eval_key) const {
    auto csquare = eval_square(ciphertext);
    relinearize_core(csquare, eval_key);
    return csquare;
}

void BfvRnsLeveledShe::eval_square_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key) const {
    ciphertext = eval_square(ciphertext);
    relinearize_core(ciphertext, eval_key);
}

void BfvRnsLeveledShe::eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, NativeInteger scalar) const {
    for (auto& cvi : ciphertext->get_elements())
        cvi *= scalar;
    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_automorphism(ConstCiphertext<RnsPoly>& ciphertext, uint32_t i,
                                                        const std::map<uint32_t, EvalKey<RnsPoly>>& eval_key_map,
                                                        CALLER_INFO_ARGS_CPP) const {
    uint32_t N = ciphertext->get_elements()[0].get_ring_dimension();
    std::vector<uint32_t> vec(N);
    precompute_auto_map(N, i, &vec);

    auto result = ciphertext->clone();
    relinearize_core(result, eval_key_map.at(i));
    auto& rcv = result->get_elements();
    rcv[0] = rcv[0].automorphism_transform(i, vec);
    rcv[1] = rcv[1].automorphism_transform(i, vec);
    return result;
}

std::shared_ptr<std::vector<RnsPoly>> BfvRnsLeveledShe::eval_fast_rotation_precompute(
        ConstCiphertext<RnsPoly>& ciphertext) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());
    auto algo = ciphertext->get_crypto_context()->get_scheme();

    size_t size_q = ciphertext->get_elements()[0].get_num_of_elements();
    const auto element_params = crypto_params->get_element_params();
    // Maximum number of RNS limbs in the crypto context
    size_t size_qm = element_params->get_params().size();

    // in the HPSPOVERQLEVELED mode (without manually calling compress-like operations),
    // an extra step of modulus reduction is needed
    // otherwise, run the shared implemented of eval_key_switch_precompute_core for all RNS schemes
    if (!((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm))) {
        return algo->eval_key_switch_precompute_core(ciphertext->get_elements()[1],
                                                     ciphertext->get_crypto_parameters());
    } else {
        RnsPoly c1 = ciphertext->get_elements()[1];
        uint32_t levels = ciphertext->get_noise_scale_deg() - 1;
        uint32_t dcrt_bits = c1.get_element_at_index(0).get_modulus().get_msb();
        // how many levels to drop
        uint32_t levels_dropped = find_levels_to_drop(levels, crypto_params, dcrt_bits, true);
        // l is index corresponding to leveled parameters in crypto_parameters precomputations in HPSPOVERQLEVELED
        uint32_t l = levels_dropped > 0 ? size_q - 1 - levels_dropped : size_q - 1;
        c1.set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        c1 = c1.scale_and_round(crypto_params->get_params_ql(l), crypto_params->get_ql_q_hat_inv_modq_divq_modq(l),
                                crypto_params->get_ql_q_hat_inv_modq_divq_frac(l),
                                crypto_params->get_modq_barrett_mu());
        c1.set_format(EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);

        return algo->eval_key_switch_precompute_core(c1, ciphertext->get_crypto_parameters());
    }
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_fast_rotation(ConstCiphertext<RnsPoly>& ciphertext, const uint32_t index,
                                                         const uint32_t m,
                                                         const std::shared_ptr<std::vector<RnsPoly>> digits) const {
    if (index == 0)
        return ciphertext->clone();

    const auto cc = ciphertext->get_crypto_context();

    uint32_t auto_index = find_automorphism_index(index, m);

    auto eval_key_map = cc->get_eval_automorphism_key_map(ciphertext->get_key_tag());
    // verify if the key auto_index exists in the eval_key_map
    auto eval_key_iterator = eval_key_map.find(auto_index);
    if (eval_key_iterator == eval_key_map.end()) {
        CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");
    }
    auto eval_key = eval_key_iterator->second;

    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    // We remove all auxiliary moduli P_i in the case of hybrid key switching
    // ATTN: elem_params should not be a shared_ptr because it would modify digits.
    // TODO (dsuponit): wrap the lines below in a function to return elem_params as an object
    auto elem_params = *((*digits)[0].get_params());
    if (crypto_params->get_key_switch_technique() == HYBRID) {
        size_t size_p = crypto_params->get_params_p()->get_params().size();
        for (size_t i = 0; i < size_p; ++i) {
            elem_params.pop_last_param();
        }
    }

    auto ba = cc->get_scheme()->eval_fast_key_switch_core(digits, eval_key,
                                                          std::make_shared<RnsPoly::Params>(elem_params));

    const auto element_params = crypto_params->get_element_params();

    // In the HPSPOVERQLEVELED mode, we need to increase the modulus back to Q
    const auto& cv = ciphertext->get_elements();
    size_t size_q = cv[0].get_num_of_elements();
    size_t size_qm = element_params->get_params().size();
    if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_q == size_qm)) {
        // l is index corresponding to leveled parameters in crypto_parameters precomputations in HPSPOVERQLEVELED, after the level dropping
        uint32_t l = elem_params.get_params().size() - 1;
        ba[0].expand_crt_basis_ql_hat(crypto_params->get_element_params(), crypto_params->get_ql_hat_modq(l),
                                      crypto_params->get_ql_hat_modq_precon(l), size_q);
        ba[1].expand_crt_basis_ql_hat(crypto_params->get_element_params(), crypto_params->get_ql_hat_modq(l),
                                      crypto_params->get_ql_hat_modq_precon(l), size_q);
    }

    uint32_t N = cc->get_ring_dimension();
    std::vector<uint32_t> vec(N);
    precompute_auto_map(N, auto_index, &vec);

    ba[0] += cv[0];
    ba[0] = ba[0].automorphism_transform(auto_index, vec);
    ba[1] = ba[1].automorphism_transform(auto_index, vec);

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(ba));
    return result;
}

uint32_t BfvRnsLeveledShe::find_automorphism_index(uint32_t index, uint32_t m) const {
    return find_automorphism_index2n(index, m);
}

void BfvRnsLeveledShe::relinearize_core(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto& cv = ciphertext->get_elements();
    bool is_key_switch = (cv.size() == 2);
    auto algo = ciphertext->get_crypto_context()->get_scheme();
    size_t sel = 1 + !is_key_switch;

    const auto element_params = crypto_params->get_element_params();

    size_t size_q = cv[0].get_num_of_elements();
    size_t size_qm = element_params->get_params().size();
    uint32_t l = 0;
    if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_qm == size_q)) {
        uint32_t levels = ciphertext->get_noise_scale_deg() - 1;
        uint32_t dcrt_bits = cv[0].get_element_at_index(0).get_modulus().get_msb();

        // how many levels to drop
        l = size_q - 1 - find_levels_to_drop(levels, crypto_params, dcrt_bits, is_key_switch);

        cv[sel].set_format(COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);
        cv[sel] = cv[sel].scale_and_round(
                crypto_params->get_params_ql(l), crypto_params->get_ql_q_hat_inv_modq_divq_modq(l),
                crypto_params->get_ql_q_hat_inv_modq_divq_frac(l), crypto_params->get_modq_barrett_mu());
    }

    cv[sel].set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
    auto ab = algo->key_switch_core(cv[sel], eval_key);

    if ((crypto_params->get_multiplication_technique() == HPSPOVERQLEVELED) && (size_qm == size_q)) {
        ab[0].expand_crt_basis_ql_hat(crypto_params->get_element_params(), crypto_params->get_ql_hat_modq(l),
                                      crypto_params->get_ql_hat_modq_precon(l), size_q);
        ab[1].expand_crt_basis_ql_hat(crypto_params->get_element_params(), crypto_params->get_ql_hat_modq(l),
                                      crypto_params->get_ql_hat_modq_precon(l), size_q);
    }

    cv[0].set_format(Format::EVALUATION);
    cv[0] += ab[0];
    if (is_key_switch) {
        cv[1] = std::move(ab[1]);
    } else {
        cv[1].set_format(Format::EVALUATION);
        cv[1] += ab[1];
    }
    cv.resize(2);
}

Ciphertext<RnsPoly> BfvRnsLeveledShe::compress(ConstCiphertext<RnsPoly>& ciphertext, size_t towers_left,
                                               size_t noise_scale_deg) const {
    const auto crypto_params = std::dynamic_pointer_cast<BfvRnsCryptoParams>(ciphertext->get_crypto_parameters());

    if ((crypto_params->get_multiplication_technique() == BEHZ) ||
        (crypto_params->get_multiplication_technique() == HPS)) {
        CIPHER_THROW(
                "BFV Compress is not currently supported for BEHZ or HPS. Use one of the HPSPOVERQ* methods instead.");
    }

    if ((crypto_params->get_encryption_technique() == EXTENDED)) {
        CIPHER_THROW(
                "BFV Compress is not currently supported for the EXTENDED encryption method. Use the STANDARD encryption method instead.");
    }

    Ciphertext<RnsPoly> result = std::make_shared<CiphertextImpl<RnsPoly>>(*ciphertext);

    std::vector<RnsPoly>& cv = result->get_elements();

    size_t size_q = crypto_params->get_element_params()->get_params().size();
    size_t size_ql = cv[0].get_num_of_elements();
    size_t diff_ql = size_q - size_ql;
    size_t levels = size_ql - towers_left;

    for (size_t l = 0; l < levels; ++l) {
        for (size_t i = 0; i < cv.size(); ++i) {
            cv[i].drop_last_element_and_scale(crypto_params->get_ql_inv_modq(diff_ql + l));
        }
    }

    return result;
}

// We do not need to support BfvRnsLeveledShe::eval_mult_mutable(InPlace) as no automated adjustment of ciphertexts is
// typically done in BFV.
static const std::string EVAL_MUTABLE_ERROR{
        "The mutable features are not supported in the BFV scheme. Please use a non-mutable version of this function"};
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                        Ciphertext<RnsPoly>& ciphertext2) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                        Ciphertext<RnsPoly>& ciphertext2,
                                                        const EvalKey<RnsPoly> eval_key) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2,
                                                  const EvalKey<RnsPoly> eval_key) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_add_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                       Ciphertext<RnsPoly>& ciphertext2) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_add_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                 Ciphertext<RnsPoly>& ciphertext2) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                       Ciphertext<RnsPoly>& ciphertext2) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
Ciphertext<RnsPoly> BfvRnsLeveledShe::eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                 Ciphertext<RnsPoly>& ciphertext2) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}
void BfvRnsLeveledShe::eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    CIPHER_THROW(EVAL_MUTABLE_ERROR);
}

}  // namespace cipher
