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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#include "cipher/fhe/bfv/crypto_params.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

namespace cipher {

// Precomputation of CRT tables for encryption, decryption, and homomorphic multiplication
void BfvRnsCryptoParams::precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech,
                                                 EncryptionTechnique enc_tech, MultiplicationTechnique mult_tech,
                                                 uint32_t num_part_q, uint32_t aux_bits, uint32_t extra_bits) {
    RnsCryptoParams::precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, extra_bits);

    NativeInteger t = get_plaintext_modulus();
    uint32_t n = get_element_params()->get_ring_dimension();
    BigInteger modulus_q = get_element_params()->get_modulus();
    const auto& params_q = get_element_params()->get_params();
    uint32_t size_q = params_q.size();

    modq_barrett_mu_.resize(0);
    modq_barrett_mu_.reserve(size_q);
    t_inv_modq_.resize(0);
    t_inv_modq_.reserve(size_q);

    std::vector<NativeInteger> moduli_q, roots_q;
    moduli_q.reserve(size_q);
    roots_q.reserve(size_q);

    const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
    for (const auto& p : params_q) {
        t_inv_modq_.emplace_back(t.mod_inverse(p->get_modulus()));
        modq_barrett_mu_.emplace_back((barrett_base128_bit / BigInteger(p->get_modulus())).convert_to_int<DoubleNativeInt>());
        moduli_q.emplace_back(p->get_modulus());
        roots_q.emplace_back(p->get_root_of_unity());
    }

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    NativeInteger modulusr = previous_prime<NativeInteger>(moduli_q[size_q - 1], 2 * n);
    NativeInteger rootr = root_of_unity<NativeInteger>(2 * n, modulusr);

    BigInteger tmp_modulus_q = modulus_q;

    neg_q_modt_.clear();
    neg_q_modt_precon_.clear();
    neg_q_modt_.resize(size_q);
    neg_q_modt_precon_.resize(size_q);
    for (uint32_t l = 0; l < size_q; ++l) {
        if (l > 0)
            tmp_modulus_q = tmp_modulus_q / BigInteger(moduli_q[size_q - l]);

        neg_q_modt_[l] = tmp_modulus_q.mod(BigInteger(get_plaintext_modulus())).convert_to_int();
        neg_q_modt_[l] = t.sub(neg_q_modt_[l]);
        neg_q_modt_precon_[l] = neg_q_modt_[l].prep_mod_mul_const(t);
    }

    // BFVrns : Encrypt : With extra
    if (enc_tech == EXTENDED) {
        std::vector<NativeInteger> moduli_qr_value(size_q + 1);
        std::vector<NativeInteger> roots_qr_value(size_q + 1);

        r_inv_modq_.resize(size_q);

        t_inv_modqr_.resize(size_q + 1);

        for (uint32_t i = 0; i < size_q; ++i) {
            moduli_qr_value[i] = moduli_q[i];
            roots_qr_value[i] = roots_q[i];

            t_inv_modqr_[i] = t_inv_modq_[i];
            r_inv_modq_[i] = modulusr.mod_inverse(moduli_q[i]);
        }
        moduli_qr_value[size_q] = modulusr;
        roots_qr_value[size_q] = rootr;
        params_qr_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_qr_value, roots_qr_value);

        t_inv_modqr_[size_q] = t.mod_inverse(modulusr);

        BigInteger modulus_qr_value = modulus_q.mul(modulusr);
        neg_qr_modt_ = modulus_qr_value.mod(BigInteger(t)).convert_to_int();
        neg_qr_modt_ = t.sub(neg_qr_modt_);
        neg_qr_modt_precon_ = neg_qr_modt_.prep_mod_mul_const(t);
    }

    /////////////////////////////////////
    // HPS Precomputation
    /////////////////////////////////////

    if (mult_tech != BEHZ) {
        uint32_t size_r = (mult_tech == HPS) ? size_q + 1 : size_q;
        std::vector<NativeInteger> moduli_r(size_r);
        std::vector<NativeInteger> roots_r(size_r);
        modr_barrett_mu_.resize(size_r);

        moduli_r[0] = modulusr;
        roots_r[0] = rootr;
        modr_barrett_mu_[0] = (barrett_base128_bit / BigInteger(moduli_r[0])).convert_to_int<DoubleNativeInt>();

        for (uint32_t j = 1; j < size_r; ++j) {
            moduli_r[j] = previous_prime<NativeInteger>(moduli_r[j - 1], 2 * n);
            roots_r[j] = root_of_unity<NativeInteger>(2 * n, moduli_r[j]);
            modr_barrett_mu_[j] = (barrett_base128_bit / BigInteger(moduli_r[j])).convert_to_int<DoubleNativeInt>();
        }

        ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_r, 2 * n, moduli_r);

        // BFVrns : Mult : expand_crt_basis
        // Pre-compute values [Ql/q_i]_{r_j}
        // Pre-compute values [(Ql/q_i)^{-1}]_{q_i}

        tmp_modulus_q = modulus_q;

        if (mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ) {
            ql_hat_inv_modq_.resize(size_q);
            ql_hat_inv_modq_precon_.resize(size_q);
            ql_hat_modr_.resize(size_q);

            for (uint32_t l = 0; l < size_q; ++l) {
                if (l > 0)
                    tmp_modulus_q = tmp_modulus_q / BigInteger(moduli_q[size_q - l]);

                ql_hat_inv_modq_[size_q - l - 1].resize(size_q - l);
                ql_hat_inv_modq_precon_[size_q - l - 1].resize(size_q - l);
                ql_hat_modr_[size_q - l - 1].resize(size_r);

                for (uint32_t j = 0; j < size_r; ++j) {
                    ql_hat_modr_[size_q - l - 1][j].resize(size_q - l);
                }

                for (uint32_t i = 0; i < size_q - l; ++i) {
                    ql_hat_modr_[size_q - l - 1][i].resize(size_r);
                    BigInteger q_hati = tmp_modulus_q / BigInteger(moduli_q[i]);
                    BigInteger q_hat_inv_modqi = q_hati.mod_inverse(moduli_q[i]);
                    ql_hat_inv_modq_[size_q - l - 1][i] = q_hat_inv_modqi.convert_to_int();
                    ql_hat_inv_modq_precon_[size_q - l - 1][i] =
                            ql_hat_inv_modq_[size_q - l - 1][i].prep_mod_mul_const(moduli_q[i]);
                    for (uint32_t j = 0; j < size_r; ++j) {
                        BigInteger ql_hat_modrij = q_hati.mod(moduli_r[j]);
                        ql_hat_modr_[size_q - l - 1][j][i] = ql_hat_modrij.convert_to_int();
                    }
                }
            }
        } else {
            ql_hat_inv_modq_.resize(1);
            ql_hat_inv_modq_precon_.resize(1);

            ql_hat_inv_modq_[0].resize(size_q);
            ql_hat_inv_modq_precon_[0].resize(size_q);

            for (uint32_t i = 0; i < size_q; ++i) {
                BigInteger q_hati = modulus_q / BigInteger(moduli_q[i]);
                BigInteger q_hat_inv_modqi = q_hati.mod_inverse(moduli_q[i]);
                ql_hat_inv_modq_[0][i] = q_hat_inv_modqi.convert_to_int();
                ql_hat_inv_modq_precon_[0][i] = ql_hat_inv_modq_[0][i].prep_mod_mul_const(moduli_q[i]);
            }

            ql_hat_modr_.resize(1);
            ql_hat_modr_[0].resize(size_r);
            for (uint32_t j = 0; j < size_r; ++j) {
                ql_hat_modr_[0][j].resize(size_q);
                for (uint32_t i = 0; i < size_q; ++i) {
                    BigInteger q_hati = modulus_q / BigInteger(moduli_q[i]);
                    ql_hat_modr_[0][j][i] = q_hati.mod(moduli_r[j]).convert_to_int();
                }
            }
        }

        // BFVrns : Mult : expand_crt_basis
        if (mult_tech == HPS) {
            params_ql_.resize(1);
            params_rl_.resize(1);
            params_ql_rl_.resize(1);
            params_ql_[0] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_q, roots_q);
            params_rl_[0] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_r, roots_r);
            std::vector<NativeInteger> moduli_qr(size_q + size_r);
            std::vector<NativeInteger> roots_qr(size_q + size_r);
            for (uint32_t i = 0; i < size_q; ++i) {
                moduli_qr[i] = moduli_q[i];
                roots_qr[i] = roots_q[i];
            }
            for (uint32_t j = 0; j < size_r; ++j) {
                moduli_qr[size_q + j] = moduli_r[j];
                roots_qr[size_q + j] = roots_r[j];
            }
            params_ql_rl_[0] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_qr, roots_qr);
        } else if (mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ) {
            params_ql_.resize(size_q);
            params_rl_.resize(size_q);
            params_ql_rl_.resize(size_q);

            std::vector<NativeInteger> moduli_ql;
            moduli_ql.reserve(size_q);
            std::vector<NativeInteger> roots_ql;
            roots_ql.reserve(size_q);
            std::vector<NativeInteger> moduli_rl;
            moduli_rl.reserve(size_q);
            std::vector<NativeInteger> roots_rl;
            roots_rl.reserve(size_q);
            std::vector<NativeInteger> moduli_ql_rl;
            moduli_ql_rl.reserve(2 * size_q);
            std::vector<NativeInteger> roots_ql_rl;
            roots_ql_rl.reserve(2 * size_q);

            for (uint32_t l = 0; l < size_q; ++l) {
                moduli_ql.push_back(moduli_q[l]);
                roots_ql.push_back(roots_q[l]);
                params_ql_[l] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_ql, roots_ql);
                moduli_rl.push_back(moduli_r[l]);
                roots_rl.push_back(roots_r[l]);
                params_rl_[l] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_rl, roots_rl);
                moduli_ql_rl.insert(moduli_ql_rl.begin() + l, moduli_q[l]);
                roots_ql_rl.insert(roots_ql_rl.begin() + l, roots_q[l]);
                moduli_ql_rl.push_back(moduli_r[l]);
                roots_ql_rl.push_back(roots_r[l]);
                params_ql_rl_[l] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_ql_rl, roots_ql_rl);
            }
        }

        modr_barrett_mu_.resize(size_r);
        for (uint32_t j = 0; j < size_r; ++j) {
            modr_barrett_mu_[j] = (barrett_base128_bit / BigInteger(moduli_r[j])).convert_to_int<DoubleNativeInt>();
        }

        q_inv_.resize(size_q);
        for (uint32_t i = 0; i < size_q; ++i) {
            q_inv_[i] = 1. / static_cast<double>(moduli_q[i].convert_to_int());
        }

        /////////////////////////////////////
        // BFVrns : Mult : scale_and_round
        /////////////////////////////////////

        const BigInteger modulus_r = mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ ?
                                            params_rl_[size_q - 1]->get_modulus() :
                                            params_rl_[0]->get_modulus();

        const BigInteger modulus_qr = mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ ?
                                             params_ql_rl_[size_q - 1]->get_modulus() :
                                             params_ql_rl_[0]->get_modulus();

        const BigInteger modulust(get_plaintext_modulus());

        t_rs_hat_inv_mods_divs_frac_.resize(size_q);
        for (uint32_t i = 0; i < size_q; ++i) {
            BigInteger qi(moduli_q[i].convert_to_int());
            t_rs_hat_inv_mods_divs_frac_[i] =
                    static_cast<double>(
                            ((modulus_qr.divided_by(qi)).mod_inverse(qi) * modulus_r * modulust).mod(qi).convert_to_int()) /
                    static_cast<double>(qi.convert_to_int());
        }

        t_rs_hat_inv_mods_divs_modr_.resize(size_r);
        for (uint32_t j = 0; j < size_r; ++j) {
            t_rs_hat_inv_mods_divs_modr_[j].reserve(size_q + 1);
            BigInteger rj(moduli_r[j].convert_to_int());
            for (uint32_t i = 0; i < size_q; ++i) {
                BigInteger qi(moduli_q[i].convert_to_int());
                BigInteger t_rs_hat_inv_mods = modulust * modulus_r * ((modulus_qr.divided_by(qi)).mod_inverse(qi));
                BigInteger t_rs_hat_inv_mods_divs = t_rs_hat_inv_mods / qi;
                t_rs_hat_inv_mods_divs_modr_[j].push_back(t_rs_hat_inv_mods_divs.mod(rj).convert_to_int());
            }

            BigInteger t_rs_hat_inv_mods = modulust * modulus_r * ((modulus_qr.divided_by(rj)).mod_inverse(rj));
            BigInteger t_rs_hat_inv_mods_divs = t_rs_hat_inv_mods / rj;
            t_rs_hat_inv_mods_divs_modr_[j].push_back(t_rs_hat_inv_mods_divs.mod(rj).convert_to_int());
        }

        /////////////////////////////////////
        // BFVrns : Mult : switch_crt_basis
        /////////////////////////////////////

        std::vector<BigInteger> ql_value(size_q + 1);
        std::vector<BigInteger> rl_value(size_q + 1);
        std::vector<BigInteger> ql_rl(size_q + 1);
        std::vector<BigInteger> ql_hat(size_q + 1);
        std::vector<BigInteger> rl_hat(size_q + 1);

        if (mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ) {
            ql_value[0] = 1;
            rl_value[0] = 1;
            ql_rl[0] = 1;
            ql_hat[0] = modulus_q;
            rl_hat[0] = modulus_r;
            for (uint32_t l = 0; l < size_q; ++l) {
                BigInteger ql(moduli_q[l].convert_to_int());
                BigInteger rl(moduli_r[l].convert_to_int());
                ql_value[l + 1] = ql_value[l] * ql;
                rl_value[l + 1] = rl_value[l] * rl;
                ql_rl[l + 1] = ql_rl[l] * ql;
                ql_rl[l + 1] = ql_rl[l + 1] * rl;
                ql_hat[l + 1] = ql_hat[l] / ql;
                rl_hat[l + 1] = rl_hat[l] / rl;
            }
        }

        // BFVrns : Mult : expand_crt_basis
        if (mult_tech == HPS) {
            alpha_ql_modr_.resize(1);
            alpha_ql_modr_[0].resize(size_q + 1, std::vector<NativeInteger>(size_r));
            for (uint32_t j = 0; j < size_r; ++j) {
                NativeInteger q_modrj = modulus_q.mod(moduli_r[j]).convert_to_int();
                for (uint32_t i = 0; i <= size_q; ++i) {
                    alpha_ql_modr_[0][i][j] = q_modrj.mod_mul(NativeInteger(i), moduli_r[j]);
                }
            }
        } else if (mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ) {
            alpha_ql_modr_.resize(size_q);
            for (uint32_t l = size_q; l > 0; l--) {
                alpha_ql_modr_[l - 1].resize(l + 1, std::vector<NativeInteger>(size_r));
                for (uint32_t i = 0; i < size_r; ++i) {
                    NativeInteger ql_modri = ql_value[l].mod(moduli_r[i]).convert_to_int();
                    for (uint32_t j = 0; j <= l; ++j) {
                        alpha_ql_modr_[l - 1][j][i] = ql_modri.mod_mul(NativeInteger(j), moduli_r[i]);
                    }
                }
            }
        }

        // Pre-compute values [Rl/r_j]_{q_i}
        // Pre-compute values [(Rl/r_j)^{-1}]_{r_j}
        if (mult_tech == HPS) {
            rl_hat_inv_modr_.resize(1);
            rl_hat_inv_modr_precon_.resize(1);

            rl_hat_inv_modr_[0].resize(size_r);
            rl_hat_inv_modr_precon_[0].resize(size_r);
            for (uint32_t j = 0; j < size_r; ++j) {
                BigInteger r_hatj = modulus_r / BigInteger(moduli_r[j]);
                rl_hat_inv_modr_[0][j] = r_hatj.mod_inverse(moduli_r[j]).convert_to_int();
                rl_hat_inv_modr_precon_[0][j] = rl_hat_inv_modr_[0][j].prep_mod_mul_const(moduli_r[j]);
            }

            rl_hat_modq_.resize(1);
            rl_hat_modq_[0].resize(size_q);
            for (uint32_t i = 0; i < size_q; ++i) {
                rl_hat_modq_[0][i].resize(size_r);
                for (uint32_t j = 0; j < size_r; ++j) {
                    BigInteger r_hatj = modulus_r / BigInteger(moduli_r[j]);
                    rl_hat_modq_[0][i][j] = r_hatj.mod(moduli_q[i]).convert_to_int();
                }
            }
        } else if (mult_tech == HPSPOVERQ || mult_tech == HPSPOVERQLEVELED) {
            rl_hat_inv_modr_.resize(size_r);
            rl_hat_inv_modr_precon_.resize(size_r);
            rl_hat_modq_.resize(size_r);

            for (uint32_t l = size_r; l > 0; l--) {
                rl_hat_inv_modr_[l - 1].resize(l);
                rl_hat_inv_modr_precon_[l - 1].resize(l);
                rl_hat_modq_[l - 1].resize(l, std::vector<NativeInteger>(l));
                for (uint32_t j = 0; j < l; ++j) {
                    BigInteger rl_hatj = rl_value[l] / BigInteger(moduli_r[j]);
                    BigInteger rl_hat_inv_modrj = rl_hatj.mod_inverse(moduli_r[j]);
                    rl_hat_inv_modr_[l - 1][j] = rl_hat_inv_modrj.convert_to_int();
                    rl_hat_inv_modr_precon_[l - 1][j] = rl_hat_inv_modr_[l - 1][j].prep_mod_mul_const(moduli_r[j]);
                    for (uint32_t i = 0; i < l; ++i) {
                        BigInteger rl_hat_modqji = rl_hatj.mod(moduli_q[i]);
                        rl_hat_modq_[l - 1][i][j] = rl_hat_modqji.convert_to_int();
                    }
                }
            }
        }

        // compute [\alpha*Rl]_{q_i} for 0 <= alpha <= sizeRl
        // used for homomorphic multiplication
        if (mult_tech == HPS) {
            alpha_rl_modq_.resize(1);
            alpha_rl_modq_[0].resize(size_r + 1, std::vector<NativeInteger>(size_q));
            for (uint32_t i = 0; i < size_q; ++i) {
                NativeInteger r_modqi = modulus_r.mod(moduli_q[i]).convert_to_int();
                for (uint32_t j = 0; j <= size_r; ++j) {
                    alpha_rl_modq_[0][j][i] = r_modqi.mod_mul(NativeInteger(j), moduli_q[i]);
                }
            }
        } else if (mult_tech == HPSPOVERQLEVELED || mult_tech == HPSPOVERQ) {
            alpha_rl_modq_.resize(size_r);
            for (uint32_t l = size_r; l > 0; l--) {
                alpha_rl_modq_[l - 1].resize(l + 1, std::vector<NativeInteger>(size_q));
                for (uint32_t i = 0; i < size_q; ++i) {
                    NativeInteger rl_modqi = rl_value[l].mod(moduli_q[i]).convert_to_int();
                    for (uint32_t j = 0; j <= l; ++j) {
                        alpha_rl_modq_[l - 1][j][i] = rl_modqi.mod_mul(NativeInteger(j), moduli_q[i]);
                    }
                }
            }
        }

        r_inv_.resize(size_r);
        for (uint32_t j = 0; j < size_r; ++j) {
            r_inv_[j] = 1. / static_cast<double>(moduli_r[j].convert_to_int());
        }

        /////////////////////////////////////
        // BFVrns : Decrypt : scale_and_round
        /////////////////////////////////////

        uint32_t q_msb = (*std::max_element(moduli_q.begin(), moduli_q.end())).get_msb();

        uint32_t size_qmsb = get_msb64(size_q);

        t_q_hat_inv_modq_divq_modt_.resize(size_q);
        t_q_hat_inv_modq_divq_modt_precon_.resize(size_q);
        t_q_hat_inv_modq_divq_frac_.resize(size_q);
        if (q_msb + size_qmsb < 52) {
            for (uint32_t i = 0; i < size_q; ++i) {
                BigInteger qi(moduli_q[i].convert_to_int());
                BigInteger t_q_hat_inv_modqi =
                        ((modulus_q.divided_by(qi)).mod_inverse(qi) * BigInteger(get_plaintext_modulus()));
                BigInteger t_q_hat_inv_modq_divqi = t_q_hat_inv_modqi.divided_by(qi);
                t_q_hat_inv_modq_divq_modt_[i] = t_q_hat_inv_modq_divqi.mod(get_plaintext_modulus()).convert_to_int();
                t_q_hat_inv_modq_divq_modt_precon_[i] = t_q_hat_inv_modq_divq_modt_[i].prep_mod_mul_const(get_plaintext_modulus());

                int64_t numerator = t_q_hat_inv_modqi.mod(qi).convert_to_int();
                int64_t denominator = moduli_q[i].convert_to_int();
                t_q_hat_inv_modq_divq_frac_[i] = static_cast<double>(numerator) / static_cast<double>(denominator);
            }
        } else {
            t_q_hat_inv_modq_b_divq_modt_.resize(size_q);
            t_q_hat_inv_modq_b_divq_modt_precon_.resize(size_q);
            t_q_hat_inv_modq_b_divq_frac_.resize(size_q);
            uint32_t q_msb_hf = q_msb >> 1;
            for (uint32_t i = 0; i < size_q; ++i) {
                BigInteger qi(moduli_q[i].convert_to_int());
                BigInteger t_q_hat_inv_modqi =
                        ((modulus_q.divided_by(qi)).mod_inverse(qi) * BigInteger(get_plaintext_modulus()));
                BigInteger t_q_hat_inv_modq_divqi = t_q_hat_inv_modqi.divided_by(qi);
                t_q_hat_inv_modq_divq_modt_[i] = t_q_hat_inv_modq_divqi.mod(get_plaintext_modulus()).convert_to_int();
                t_q_hat_inv_modq_divq_modt_precon_[i] = t_q_hat_inv_modq_divq_modt_[i].prep_mod_mul_const(get_plaintext_modulus());

                int64_t numerator = t_q_hat_inv_modqi.mod(qi).convert_to_int();
                int64_t denominator = moduli_q[i].convert_to_int();
                t_q_hat_inv_modq_divq_frac_[i] = static_cast<double>(numerator) / static_cast<double>(denominator);

                t_q_hat_inv_modqi.l_shift_eq(q_msb_hf);
                t_q_hat_inv_modq_divqi = t_q_hat_inv_modqi.divided_by(qi);
                t_q_hat_inv_modq_b_divq_modt_[i] = t_q_hat_inv_modq_divqi.mod(get_plaintext_modulus()).convert_to_int();
                t_q_hat_inv_modq_b_divq_modt_precon_[i] = t_q_hat_inv_modq_b_divq_modt_[i].prep_mod_mul_const(get_plaintext_modulus());

                numerator = t_q_hat_inv_modqi.mod(qi).convert_to_int();
                t_q_hat_inv_modq_b_divq_frac_[i] = static_cast<double>(numerator) / static_cast<double>(denominator);
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : fast_expand_crt_basis_plover_q
        /////////////////////////////////////

        if (mult_tech == HPSPOVERQ || mult_tech == HPSPOVERQLEVELED) {
            // Scenario when we go from Q to P_l
            neg_rl_q_hat_inv_modq_.resize(size_r);
            neg_rl_q_hat_inv_modq_precon_.resize(size_r);
            for (uint32_t l = size_r; l > 0; l--) {
                neg_rl_q_hat_inv_modq_[l - 1].resize(size_q);
                neg_rl_q_hat_inv_modq_precon_[l - 1].resize(size_q);
                for (uint32_t i = 0; i < size_q; ++i) {
                    BigInteger q_hati = modulus_q / BigInteger(moduli_q[i]);
                    BigInteger q_hat_inv_modqi = q_hati.mod_inverse(moduli_q[i]);
                    neg_rl_q_hat_inv_modq_[l - 1][i] = rl_value[l].mod_mul(q_hat_inv_modqi, moduli_q[i]).convert_to_int();
                    neg_rl_q_hat_inv_modq_[l - 1][i] = moduli_q[i].sub(neg_rl_q_hat_inv_modq_[l - 1][i]);
                    neg_rl_q_hat_inv_modq_precon_[l - 1][i] = neg_rl_q_hat_inv_modq_[l - 1][i].prep_mod_mul_const(moduli_q[i]);
                }
            }

            // Scenario when we go from Q_l to P_l
            neg_rl_ql_hat_inv_modq_.resize(size_r);
            neg_rl_ql_hat_inv_modq_precon_.resize(size_r);
            BigInteger modulus_qtmp = modulus_q;
            for (uint32_t l = size_r; l > 0; l--) {
                neg_rl_ql_hat_inv_modq_[l - 1].resize(l);
                neg_rl_ql_hat_inv_modq_precon_[l - 1].resize(l);
                for (uint32_t i = 0; i < l; ++i) {
                    BigInteger ql_hati = modulus_qtmp / BigInteger(moduli_q[i]);
                    BigInteger ql_hat_inv_modqi = ql_hati.mod_inverse(moduli_q[i]);
                    neg_rl_ql_hat_inv_modq_[l - 1][i] = rl_value[l].mod_mul(ql_hat_inv_modqi, moduli_q[i]).convert_to_int();
                    neg_rl_ql_hat_inv_modq_[l - 1][i] = moduli_q[i].sub(neg_rl_ql_hat_inv_modq_[l - 1][i]);
                    neg_rl_ql_hat_inv_modq_precon_[l - 1][i] = neg_rl_ql_hat_inv_modq_[l - 1][i].prep_mod_mul_const(moduli_q[i]);
                }
                modulus_qtmp = modulus_qtmp / BigInteger(moduli_q[l - 1]);
            }
        }

        q_inv_modr_.resize(size_q);
        for (uint32_t i = 0; i < size_q; ++i) {
            q_inv_modr_[i].resize(size_r);
            for (uint32_t j = 0; j < size_r; ++j) {
                q_inv_modr_[i][j] = moduli_q[i].mod_inverse(moduli_r[j]);
            }
        }

        modulus_q = get_element_params()->get_modulus();

        /////////////////////////////////////
        // BFVrns : Mult : ScaleAndRoundP
        /////////////////////////////////////

        if (mult_tech == HPS) {
            t_ql_sl_hat_inv_mods_divs_frac_.resize(1);

            t_ql_sl_hat_inv_mods_divs_frac_[0].resize(size_r);
            for (uint32_t j = 0; j < size_r; ++j) {
                BigInteger rj(moduli_r[j].convert_to_int());
                t_ql_sl_hat_inv_mods_divs_frac_[0][j] =
                        static_cast<double>(((modulus_qr.divided_by(rj)).mod_inverse(rj) * modulus_q * modulust)
                                                    .mod(rj)
                                                    .convert_to_int()) /
                        static_cast<double>(rj.convert_to_int());
            }
            t_ql_sl_hat_inv_mods_divs_modq_.resize(1);
            t_ql_sl_hat_inv_mods_divs_modq_[0].resize(size_q, std::vector<NativeInteger>(size_r + 1));
            for (uint32_t i = 0; i < size_q; ++i) {
                BigInteger qi(moduli_q[i].convert_to_int());
                for (uint32_t j = 0; j < size_r; ++j) {
                    BigInteger rj(moduli_r[j].convert_to_int());
                    BigInteger t_ql_sl_hat_inv_mods = modulust * modulus_q * ((modulus_qr.divided_by(rj)).mod_inverse(rj));
                    BigInteger t_ql_sl_hat_inv_mods_divs = t_ql_sl_hat_inv_mods / rj;
                    t_ql_sl_hat_inv_mods_divs_modq_[0][i][j] = t_ql_sl_hat_inv_mods_divs.mod(qi).convert_to_int();
                }

                BigInteger t_ql_sl_hat_inv_mods = modulust * modulus_q * ((modulus_qr.divided_by(qi)).mod_inverse(qi));
                BigInteger t_ql_sl_hat_inv_mods_divs = t_ql_sl_hat_inv_mods / qi;
                t_ql_sl_hat_inv_mods_divs_modq_[0][i][size_r] = t_ql_sl_hat_inv_mods_divs.mod(qi).convert_to_int();
            }
        } else if ((mult_tech == HPSPOVERQ) || (mult_tech == HPSPOVERQLEVELED)) {
            t_ql_sl_hat_inv_mods_divs_frac_.resize(size_q);
            t_ql_sl_hat_inv_mods_divs_modq_.resize(size_q);

            for (uint32_t l = size_q; l > 0; l--) {
                t_ql_sl_hat_inv_mods_divs_frac_[l - 1].resize(l);
                for (uint32_t j = 0; j < l; ++j) {
                    BigInteger rj(moduli_r[j].convert_to_int());
                    t_ql_sl_hat_inv_mods_divs_frac_[l - 1][j] =
                            static_cast<double>(((ql_rl[l].divided_by(rj)).mod_inverse(rj) * ql_value[l] * modulust)
                                                        .mod(rj)
                                                        .convert_to_int()) /
                            static_cast<double>(rj.convert_to_int());
                }
                t_ql_sl_hat_inv_mods_divs_modq_[l - 1].resize(l, std::vector<NativeInteger>(l + 1));
                for (uint32_t i = 0; i < l; ++i) {
                    BigInteger qi(moduli_q[i].convert_to_int());
                    for (uint32_t j = 0; j < l; ++j) {
                        BigInteger rj(moduli_r[j].convert_to_int());
                        BigInteger t_ql_sl_hat_inv_mods = modulust * ql_value[l] * ((ql_rl[l].divided_by(rj)).mod_inverse(rj));
                        BigInteger t_ql_sl_hat_inv_mods_divs = t_ql_sl_hat_inv_mods / rj;
                        t_ql_sl_hat_inv_mods_divs_modq_[l - 1][i][j] = t_ql_sl_hat_inv_mods_divs.mod(qi).convert_to_int();
                    }

                    BigInteger t_ql_sl_hat_inv_mods = modulust * ql_value[l] * ((ql_rl[l].divided_by(qi)).mod_inverse(qi));
                    BigInteger t_ql_sl_hat_inv_mods_divs = t_ql_sl_hat_inv_mods / qi;
                    t_ql_sl_hat_inv_mods_divs_modq_[l - 1][i][l] = t_ql_sl_hat_inv_mods_divs.mod(qi).convert_to_int();
                }
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : ScaleAndRoundQl
        /////////////////////////////////////

        ql_q_hat_inv_modq_divq_modq_.resize(size_q);
        ql_q_hat_inv_modq_divq_frac_.resize(size_q);
        for (uint32_t l = size_q; l > 0; l--) {
            ql_q_hat_inv_modq_divq_frac_[l - 1].resize(size_q - l);
            for (uint32_t j = 0; j < size_q - l; ++j) {
                BigInteger qj(moduli_q[j + l].convert_to_int());
                ql_q_hat_inv_modq_divq_frac_[l - 1][j] =
                        static_cast<double>(((modulus_q.divided_by(qj)).mod_inverse(qj) * ql_value[l]).mod(qj).convert_to_int()) /
                        static_cast<double>(qj.convert_to_int());
            }
            ql_q_hat_inv_modq_divq_modq_[l - 1].resize(l);
            for (uint32_t i = 0; i < l; ++i) {
                ql_q_hat_inv_modq_divq_modq_[l - 1][i].resize(size_q - l + 1);
                BigInteger qi(moduli_q[i].convert_to_int());
                for (uint32_t j = 0; j < size_q - l; ++j) {
                    BigInteger qj(moduli_q[l + j].convert_to_int());
                    BigInteger ql_q_hat_inv_modq = ql_value[l] * ((modulus_q.divided_by(qj)).mod_inverse(qj));
                    BigInteger ql_q_hat_inv_modq_divq = ql_q_hat_inv_modq / qj;
                    ql_q_hat_inv_modq_divq_modq_[l - 1][i][j] = ql_q_hat_inv_modq_divq.mod(qi).convert_to_int();
                }
                BigInteger ql_q_hat_inv_modq = ql_value[l] * ((modulus_q.divided_by(qi)).mod_inverse(qi));
                BigInteger ql_q_hat_inv_modq_divq = ql_q_hat_inv_modq / qi;
                ql_q_hat_inv_modq_divq_modq_[l - 1][i][size_q - l] = ql_q_hat_inv_modq_divq.mod(qi).convert_to_int();
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : expand_crt_basis_ql_hat
        /////////////////////////////////////

        ql_hat_modq_.resize(size_q);
        ql_hat_modq_precon_.resize(size_q);
        for (uint32_t l = size_q; l > 0; l--) {
            ql_hat_modq_[l - 1].resize(l);
            ql_hat_modq_precon_[l - 1].resize(l);
            for (uint32_t i = 0; i < l; ++i) {
                BigInteger qi(moduli_q[i].convert_to_int());
                ql_hat_modq_[l - 1][i] = ql_hat[l].mod(qi).convert_to_int();
                ql_hat_modq_precon_[l - 1][i] = ql_hat_modq_[l - 1][i].prep_mod_mul_const(qi);
            }
        }

        /////////////////////////////////////
        // drop_last_element_and_scale
        /////////////////////////////////////

        // Pre-compute values for rescaling in RNS
        ql_inv_modq_.resize(size_q - 1);
        ql_inv_modq_precon_.resize(size_q - 1);
        for (uint32_t k = 0; k < size_q - 1; ++k) {
            uint32_t l = size_q - (k + 1);
            ql_inv_modq_[k].resize(l);
            ql_inv_modq_precon_[k].resize(l);
            for (uint32_t i = 0; i < l; ++i) {
                ql_inv_modq_[k][i] = moduli_q[l].mod_inverse(moduli_q[i]);
                ql_inv_modq_precon_[k][i] = ql_inv_modq_[k][i].prep_mod_mul_const(moduli_q[i]);
            }
        }
    }

    /////////////////////////////////////
    // BEHZ Precomputation
    /////////////////////////////////////

    if (mult_tech == BEHZ) {
        moduli_q_ = moduli_q;
        numq_ = size_q;

        std::vector<std::shared_ptr<NativePolyParams>> params;
        params.reserve(2 * size_q + 1);
        moduli_b_.reserve(numq_);
        roots_bsk_.reserve(numq_ + 1);
        for (uint32_t i = 0; i < numq_; ++i)
            params.emplace_back(std::make_shared<NativePolyParams>(2 * n, moduli_q[i]));

        moduli_b_.push_back(previous_prime<NativeInteger>(moduli_q.back(), 2 * n));
        roots_bsk_.push_back(root_of_unity<NativeInteger>(2 * n, moduli_b_.back()));
        params.emplace_back(std::make_shared<NativePolyParams>(2 * n, moduli_b_.back(), roots_bsk_.back()));
        BigInteger B(moduli_b_.back());

        for (uint32_t i = 1; i < numq_; ++i) {  // we already added one prime
            moduli_b_.push_back(previous_prime<NativeInteger>(moduli_b_.back(), 2 * n));
            roots_bsk_.push_back(root_of_unity<NativeInteger>(2 * n, moduli_b_.back()));
            params.emplace_back(std::make_shared<NativePolyParams>(2 * n, moduli_b_.back(), roots_bsk_.back()));
            B = B * BigInteger(moduli_b_.back());
        }

        numb_ = numq_;
        msk_ = previous_prime<NativeInteger>(moduli_b_[numq_ - 1], 2 * n);
        uint32_t s = msk_.get_msb();

        BigInteger Q(get_element_params()->get_modulus());
        BigInteger max_convolution_value(BigInteger(2 * n) * BigInteger(get_plaintext_modulus()) * Q);
        // check msk is large enough
        while (B * BigInteger(msk_) < max_convolution_value) {
            // TODO: revisit this logic. Maybe change to msk_ = last_prime<NativeInteger>(++s, 2 * n);
            auto first_integer{first_prime<NativeInteger>(++s, 2 * n)};
            msk_ = next_prime<NativeInteger>(first_integer, 2 * n);
        }
        roots_bsk_.push_back(root_of_unity<NativeInteger>(2 * n, msk_));

        moduli_bsk_.reserve(numq_ + 1);
        moduli_bsk_ = moduli_b_;
        moduli_bsk_.push_back(msk_);

        params.emplace_back(std::make_shared<NativePolyParams>(2 * n, moduli_bsk_.back(), roots_bsk_.back()));
        params_q_bsk_ = std::make_shared<RnsParams<BigInteger>>(2 * n, params);

        ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_bsk_, 2 * n, moduli_bsk_);

        // populate Barrett constant for m_BskModuli
        modbsk_barrett_mu_.resize(moduli_bsk_.size());
        for (size_t i = 0; i < modbsk_barrett_mu_.size(); ++i) {
            modbsk_barrett_mu_[i] = (barrett_base128_bit / BigInteger(moduli_bsk_[i])).convert_to_int<DoubleNativeInt>();
        }

        // Populate [t*(Q/q_i)^-1]_{q_i}
        t_q_hat_inv_modq_.resize(numq_);
        t_q_hat_inv_modq_precon_.resize(numq_);
        for (uint32_t i = 0; i < numq_; ++i) {
            BigInteger t_q_hat_inv_modqi;
            t_q_hat_inv_modqi = Q.divided_by(moduli_q[i]);
            t_q_hat_inv_modqi = t_q_hat_inv_modqi.mod(moduli_q[i]);
            t_q_hat_inv_modqi = t_q_hat_inv_modqi.mod_inverse(moduli_q[i]);
            t_q_hat_inv_modqi = t_q_hat_inv_modqi.mod_mul(t.convert_to_int(), moduli_q[i]);
            t_q_hat_inv_modq_[i] = t_q_hat_inv_modqi.convert_to_int();
            t_q_hat_inv_modq_precon_[i] = t_q_hat_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // Populate [Q/q_i]_{bsk_j, mtilde}
        q_hat_modbsk_.resize(numq_);
        q_hat_modmtilde_.resize(numq_);
        for (uint32_t i = 0; i < numq_; ++i) {
            q_hat_modbsk_[i].resize(numb_ + 1);

            BigInteger q_hati = Q.divided_by(moduli_q[i]);
            for (size_t j = 0; j < q_hat_modbsk_[i].size(); ++j) {
                BigInteger q_hati_modbskj = q_hati.mod(moduli_bsk_[j]);
                q_hat_modbsk_[i][j] = q_hati_modbskj.convert_to_int();
            }
            q_hat_modmtilde_[i] = q_hati.mod(mtilde_).convert_to_int();
        }

        // Populate [1/q_i]_{bsk_j}
        q_inv_modbsk_.resize(numq_);
        for (uint32_t i = 0; i < numq_; ++i) {
            q_inv_modbsk_[i].resize(numb_ + 1);
            for (uint32_t j = 0; j <= numb_; ++j)
                q_inv_modbsk_[i][j] = moduli_q[i].mod_inverse(moduli_bsk_[j]);
        }

        // Populate [mtilde*(Q/q_i)^{-1}]_{q_i}
        mtilde_q_hat_inv_modq_.resize(numq_);
        mtilde_q_hat_inv_modq_precon_.resize(numq_);

        BigInteger bmtilde(mtilde_);
        for (uint32_t i = 0; i < numq_; ++i) {
            BigInteger mtilde_q_hat_inv_modqi = Q.divided_by(moduli_q[i]);
            mtilde_q_hat_inv_modqi = mtilde_q_hat_inv_modqi.mod(moduli_q[i]);
            mtilde_q_hat_inv_modqi = mtilde_q_hat_inv_modqi.mod_inverse(moduli_q[i]);
            mtilde_q_hat_inv_modqi = mtilde_q_hat_inv_modqi * bmtilde;
            mtilde_q_hat_inv_modqi = mtilde_q_hat_inv_modqi.mod(moduli_q[i]);
            mtilde_q_hat_inv_modq_[i] = mtilde_q_hat_inv_modqi.convert_to_int();
            mtilde_q_hat_inv_modq_precon_[i] = mtilde_q_hat_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // Populate [-Q^{-1}]_{mtilde}
        BigInteger neg_q_inv_modmtilde = (BigInteger(mtilde_ - 1) * Q.mod_inverse(mtilde_));
        neg_q_inv_modmtilde = neg_q_inv_modmtilde.mod(mtilde_);
        neg_q_inv_modmtilde_ = neg_q_inv_modmtilde.convert_to_int();

        // Populate [Q]_{bski_j}
        q_modbsk_.resize(numq_ + 1);
        q_modbsk_precon_.resize(numq_ + 1);

        for (uint32_t j = 0; j <= numq_; ++j) {
            BigInteger q_modbskij = Q.mod(moduli_bsk_[j]);
            q_modbsk_[j] = q_modbskij.convert_to_int();
            q_modbsk_precon_[j] = q_modbsk_[j].prep_mod_mul_const(moduli_bsk_[j]);
        }

        // Populate [mtilde^{-1}]_{bsk_j}
        mtilde_inv_modbsk_.resize(numb_ + 1);
        mtilde_inv_modbsk_precon_.resize(numb_ + 1);
        for (uint32_t j = 0; j <= numb_; ++j) {
            BigInteger mtilde_inv_modbskij = mtilde_ % moduli_bsk_[j];
            mtilde_inv_modbskij = mtilde_inv_modbskij.mod_inverse(moduli_bsk_[j]);
            mtilde_inv_modbsk_[j] = mtilde_inv_modbskij.convert_to_int();
            mtilde_inv_modbsk_precon_[j] = mtilde_inv_modbsk_[j].prep_mod_mul_const(moduli_bsk_[j]);
        }

        // Populate {t/Q}_{bsk_j}
        t_q_inv_modbsk_.resize(numb_ + 1);
        t_q_inv_modbsk_precon_.resize(numb_ + 1);

        for (uint32_t i = 0; i <= numb_; ++i) {
            BigInteger t_divq_mod_bski = Q.mod_inverse(moduli_bsk_[i]);
            t_divq_mod_bski.mod_mul_eq(t.convert_to_int(), moduli_bsk_[i]);
            t_q_inv_modbsk_[i] = t_divq_mod_bski.convert_to_int();
            t_q_inv_modbsk_precon_[i] = t_q_inv_modbsk_[i].prep_mod_mul_const(moduli_bsk_[i]);
        }

        // Populate [(B/b_j)^{-1}]_{b_j}
        b_hat_inv_modb_.resize(numb_);
        b_hat_inv_modb_precon_.resize(numb_);

        for (uint32_t i = 0; i < numb_; ++i) {
            BigInteger b_div_bi;
            b_div_bi = B.divided_by(moduli_b_[i]);
            b_div_bi = b_div_bi.mod(moduli_b_[i]);
            b_div_bi = b_div_bi.mod_inverse(moduli_b_[i]);
            b_hat_inv_modb_[i] = b_div_bi.convert_to_int();
            b_hat_inv_modb_precon_[i] = b_hat_inv_modb_[i].prep_mod_mul_const(moduli_b_[i]);
        }

        // Populate [B/b_j]_{q_i}
        b_hat_modq_.resize(numb_);
        for (uint32_t i = 0; i < numb_; ++i) {
            b_hat_modq_[i].resize(numq_);
            BigInteger b_div_bi = B.divided_by(moduli_b_[i]);
            for (uint32_t j = 0; j < numq_; ++j) {
                BigInteger b_div_bi_modqj = b_div_bi.mod(moduli_q[j]);
                b_hat_modq_[i][j] = b_div_bi_modqj.convert_to_int();
            }
        }

        // Populate [B/b_j]_{msk}
        b_hat_modmsk_.resize(numb_);
        for (uint32_t i = 0; i < numb_; ++i) {
            BigInteger b_div_bi = B.divided_by(moduli_b_[i]);
            b_hat_modmsk_[i] = (b_div_bi.mod(msk_)).convert_to_int();
        }

        // Populate [B^{-1}]_{msk}
        b_inv_modmsk_ = (B.mod_inverse(msk_)).convert_to_int();
        b_inv_modmsk_precon_ = b_inv_modmsk_.prep_mod_mul_const(msk_);

        // Populate [B]_{q_i}
        b_modq_.resize(numq_);
        b_modq_precon_.resize(numq_);
        for (uint32_t i = 0; i < numq_; ++i) {
            b_modq_[i] = (B.mod(moduli_q[i])).convert_to_int();
            b_modq_precon_[i] = b_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // Populate Decrns lookup tables

        NativeInteger tgamma = NativeInteger(t.convert_to_int() * gamma_);  // t*gamma

        tgamma_ = tgamma;

        // Populate [-1/q_i]_{t*gamma} (t*gamma < 2^58)
        neg_invq_modtgamma_.resize(numq_);
        neg_invq_modtgamma_precon_.resize(numq_);
        for (uint32_t i = 0; i < numq_; ++i) {
            BigInteger imod(moduli_q[i]);
            BigInteger neg_invqi = BigInteger((tgamma - 1)) * imod.mod_inverse(tgamma);

            BigInteger neg_invqi_modtgamma = neg_invqi.mod(tgamma);
            neg_invq_modtgamma_[i] = neg_invqi_modtgamma.convert_to_int();
            neg_invq_modtgamma_precon_[i] = neg_invq_modtgamma_[i].prep_mod_mul_const(tgamma);
        }

        // populate [t*gamma*(Q/q_i)^(-1)]_{q_i}
        tgamma_q_hat_inv_modq_.resize(numq_);
        tgamma_q_hat_inv_modq_precon_.resize(numq_);

        BigInteger bmgamma(gamma_);
        for (uint32_t i = 0; i < numq_; ++i) {
            BigInteger q_divqi = Q.divided_by(moduli_q[i]);
            BigInteger imod(moduli_q[i]);
            q_divqi = q_divqi.mod_inverse(moduli_q[i]);
            BigInteger gammaq_divqi = (q_divqi * bmgamma) % imod;
            BigInteger tgammaq_divqi = (gammaq_divqi * BigInteger(t)) % imod;
            tgamma_q_hat_inv_modq_[i] = tgammaq_divqi.convert_to_int();
            tgamma_q_hat_inv_modq_precon_[i] = tgamma_q_hat_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }
    }
}

uint64_t BfvRnsCryptoParams::find_aux_prime_step() const {
    return 2 * get_element_params()->get_ring_dimension();
}

}  // namespace cipher
