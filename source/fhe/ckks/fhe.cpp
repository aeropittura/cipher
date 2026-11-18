//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifdef BOOTSTRAPTIMING
    #define PROFILE
#endif

#include "cipher/fhe/ckks/fhe.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/ring/backend.h"
#include "cipher/math/dft.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/ckks/utils.h"
#include "cipher/fhe/base/scheme.h"
#include "cipher/util/diagnostic_output.h"
#include "cipher/util/exception.h"
#include "cipher/util/parallel.h"
#include "cipher/util/utilities.h"

namespace {
// get_big_modulus() calculates the big modulus as the product of
// the "composite_degree" number of parameter modulus
double get_big_modulus(const std::shared_ptr<cipher::CkksRnsCryptoParams>& crypto_params) {
    const auto& params = crypto_params->get_element_params()->get_params();
    uint32_t composite_degree = crypto_params->get_composite_degree();
    double q_double = 1.0;
    for (uint32_t j = 0; j < composite_degree; ++j) {
        q_double *= params[j]->get_modulus().convert_to_double();
    }
    return q_double;
}

// num/den as a double, without forming an intermediate that overflows the exponent range: both operands
// are shifted down to 53 bits (so each converts exactly) and the shift is restored with ldexp.
double ratio_to_double(const cipher::BigInteger& num, const cipher::BigInteger& den) {
    constexpr uint32_t keep = 53;
    const uint32_t nb = num.get_msb(), db = den.get_msb();
    const uint32_t ns = (nb > keep) ? nb - keep : 0;
    const uint32_t ds = (db > keep) ? db - keep : 0;
    const double n = (ns ? num.r_shift(static_cast<uint16_t>(ns)) : num).convert_to_double();
    const double d = (ds ? den.r_shift(static_cast<uint16_t>(ds)) : den).convert_to_double();
    return std::ldexp(n / d, static_cast<int>(ns) - static_cast<int>(ds));
}
}  // namespace

namespace cipher {

namespace {
// SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64: first modulus above 60 bits) uses the K = 28
// approximations of SPARSE_TERNARY instead of the K = 16 ones
bool uses_large_sparse_key(SecretKeyDist skd, uint32_t sparse_ks_hamming_weight_value) {
    return (skd == SPARSE_ENCAPSULATED) && (sparse_ks_hamming_weight_value > 32);
}
}  // namespace

double CkksRnsFhe::get_mod_raise_overflow_bound(const std::shared_ptr<CkksRnsCryptoParams>& crypto_params,
                                                double uniform_k) {
    switch (crypto_params->get_secret_key_dist()) {
        case UNIFORM_TERNARY:
            return uniform_k;
        case SPARSE_TERNARY:
            return K_SPARSE;
        case SPARSE_ENCAPSULATED:
            // K = 28 for the denser sparse secret (Hamming weight 64: first modulus above 60 bits)
            return uses_large_sparse_key(SPARSE_ENCAPSULATED, crypto_params->get_sparse_ks_hamming_weight()) ?
                           K_SPARSE :
                           K_SPARSE_ENCAPSULATED;
        default:
            CIPHER_THROW("Unsupported SecretKeyDist.");
    }
}

// Looks up the automorphism key, index and O(N) permutation map for a constant Horner giant
// stride. Hoisted out of the accumulation loop so these loop-invariant quantities are built once
// per stride instead of being re-derived by every eval_fast_rotation_ext call.
EvalKey<RnsPoly> CkksRnsFhe::get_giant_step_rotation(ConstCiphertext<RnsPoly> ct, int32_t stride, uint32_t& auto_index,
                                                     std::vector<uint32_t>& map) {
    auto cc = ct->get_crypto_context();
    const uint32_t M = cc->get_cyclotomic_order();
    const uint32_t N = cc->get_ring_dimension();
    auto_index = find_automorphism_index2n_complex(stride, M);
    auto eval_key_map = cc->get_eval_automorphism_key_map(ct->get_key_tag());
    auto eval_key_it = eval_key_map.find(auto_index);
    if (eval_key_it == eval_key_map.end())
        CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");
    map.resize(N);
    precompute_auto_map(N, auto_index, &map);
    return eval_key_it->second;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_horner_giant_rotate(ConstCiphertext<RnsPoly> outer, uint32_t auto_index,
                                                         const std::vector<uint32_t>& map,
                                                         const EvalKey<RnsPoly>& giant_key) {
    auto cc = outer->get_crypto_context();
    auto algo = cc->get_scheme();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(outer->get_crypto_parameters());
    const auto& cv_ext = outer->get_elements();
    const auto params_p = crypto_params->get_params_p();
    const auto params_ql_p = cv_ext[0].get_params();
    const uint32_t size_ql_p = params_ql_p->get_params().size();
    const uint32_t size_ql = size_ql_p - params_p->get_params().size();
    const auto params_ql = crypto_params->get_params_ql_hybrid(size_ql);
    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    RnsPoly c1_std = cv_ext[1].approx_mod_down(
            params_ql, params_p, crypto_params->get_p_inv_modq(), crypto_params->get_p_inv_modq_precon(),
            crypto_params->get_p_hat_inv_modp(), crypto_params->get_p_hat_inv_modp_precon(),
            crypto_params->get_p_hat_modq(), crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
            crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());

    auto digits = algo->eval_key_switch_precompute_core(c1_std, crypto_params);
    auto c_tilda = algo->eval_fast_key_switch_core_ext(digits, giant_key, params_ql);

    // c_tilda[0] += cv_ext[0]; element 0 is already extended, fold it in directly.
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
    for (uint32_t i = 0; i < size_ql_p; ++i)
        c_tilda[0].get_all_elements()[i] += cv_ext[0].get_all_elements()[i];

    c_tilda[0] = c_tilda[0].automorphism_transform(auto_index, map);
    c_tilda[1] = c_tilda[1].automorphism_transform(auto_index, map);

    auto rotated = outer->clone_empty();
    rotated->set_elements(std::move(c_tilda));
    return rotated;
}

//------------------------------------------------------------------------------
// Bootstrap Wrapper
//------------------------------------------------------------------------------

void CkksRnsFhe::eval_bootstrap_setup(const CryptoContextImpl<RnsPoly>& cc, std::vector<uint32_t> level_budget,
                                      std::vector<uint32_t> dim1, uint32_t num_slots, uint32_t correction_factor,
                                      bool precompute, bool bt_slots_encoding) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M = cc.get_cyclotomic_order();
    uint32_t slots = (num_slots == 0) ? M / 4 : num_slots;

    // Set correction factor by default, if it is not already set.
    if (correction_factor == 0) {
        auto st = crypto_params->get_scaling_technique();
        if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) {
            // The default correction factors chosen yielded the best precision in our experiments.
            // We chose the best fit line from our experiments by running ckks-bootstrapping-precision.cpp.
            // The spreadsheet with our experiments is here:
            // https://docs.google.com/spreadsheets/d/1p6-ZG9rBEE9SrkKIt0JjU1aJiYHevzblKOTuhLFW27U
            uint32_t tmp = bt_slots_encoding ?
                                   std::round(-0.1887 * (2 * std::log2(M / 2) + std::log2(slots)) + 19.763) :
                                   std::round(-0.2419 * (2 * std::log2(M / 2) + std::log2(slots)) + 19.081);
            correction_factor_ = std::clamp<uint32_t>(tmp, 7, 14);
        } else {
            uint32_t tmp = bt_slots_encoding ?
                                   std::round(-0.0645 * (2 * std::log2(M / 2) + std::log2(slots)) + 13.855) :
                                   std::round(-0.1516 * (2 * std::log2(M / 2) + std::log2(slots)) + 14.284);
            correction_factor_ = std::clamp<uint32_t>(tmp, 6, 13);
        }
    } else {
        correction_factor_ = correction_factor;
    }

    boot_precom_map_[slots] = std::make_shared<CkksBootstrapPrecomputation>();
    auto& precom = boot_precom_map_[slots];
    precom->slots_ = slots;
    precom->bt_slots_encoding = bt_slots_encoding;
    precom->variant_ = CkksBootstrapPrecomputation::BOOTSTRAP;

    // even for the case of a single slot we need one level for rescaling
    uint32_t log_slots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget and compute parameters
    uint32_t new_budget0 = level_budget[0];
    if (new_budget0 > log_slots) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding too large. Setting it to " << log_slots << "\n";
        new_budget0 = log_slots;
    }
    if (new_budget0 < 1) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding can not be zero. Setting it to 1\n";
        new_budget0 = 1;
    }
    uint32_t new_budget1 = level_budget[1];
    if (new_budget1 > log_slots) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding too large. Setting it to " << log_slots << "\n";
        new_budget1 = log_slots;
    }
    if (new_budget1 < 1) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding can not be zero. Setting it to 1\n";
        new_budget1 = 1;
    }

    precom->params_enc_ = get_collapsed_fft_params(slots, new_budget0, dim1[0]);
    precom->params_dec_ = get_collapsed_fft_params(slots, new_budget1, dim1[1]);

    if (precompute) {
        uint32_t m = 4 * slots;
        uint32_t mmask = m - 1;  // assumes m is power of 2
        bool is_sparse = (M != m);

        // computes indices for all primitive roots of unity
        std::vector<uint32_t> rot_group(slots);
        uint32_t five_pows = 1;
        for (uint32_t i = 0; i < slots; ++i) {
            rot_group[i] = five_pows;
            five_pows *= 5;
            five_pows &= mmask;
        }

        // computes all powers of a primitive root of unity exp(2 * M_PI/m)
        std::vector<std::complex<double>> ksi_pows(m + 1);
        double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(2))
        for (uint32_t j = 0; j < m; ++j) {
            double angle = ak * j;
            ksi_pows[j].real(std::cos(angle));
            ksi_pows[j].imag(std::sin(angle));
        }
        ksi_pows[m] = ksi_pows[0];

        double k = get_mod_raise_overflow_bound(crypto_params, K_UNIFORM);

        uint32_t composite_degree = crypto_params->get_composite_degree();

        double q_double = get_big_modulus(crypto_params);
        double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(q_double))));
        // For composite scaling, capture the (inexact) overflow normalization SF0/q_double as a coefficient
        // close to 1, SF0*post/q_double, which the CoeffsToSlots/SlotsToCoeffs matrices encode at full
        // precision and telescope away (scale_dec = 1/scale_enc*1/k cancels it). The exact power-of-two part
        // 1/post is applied as the shrink and restored by the integer "scalar" in eval_bootstrap. This
        // mirrors the FLEXIBLEAUTO scaling structure and avoids the precision loss of folding a tiny
        // non-power-of-two constant into a single plaintext multiply.
        double pre;
        double post = 1.0;
        if (composite_degree > 1) {
            double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
            post = std::pow(2, std::round(std::log2(q_double / pow_p)));
            pre = crypto_params->get_scaling_factor_real(0) * post / q_double;
        } else {
            pre = q_double / factor;
        }
        // For composite scaling, fold the exact power-of-two 2^-deg = 1/post shrink into the
        // CoeffsToSlots matrix (scale_enc) instead of applying it as a scalar before CoeffsToSlots (see
        // eval_bootstrap). This keeps the CtS rotations operating on the full-magnitude message, so the
        // key-switch noise they add scales down together with the signal (2^deg is restored by the
        // integer "scalar" after the sine) rather than being amplified by 2^deg. scale_dec inverts the
        // residual c1 only; the exact 2^deg telescopes against the integer restore.
        double scale_enc = ((composite_degree > 1) ? pre / post : pre) / k;
        double scale_dec = 1.0 / pre;

        // compute # of levels to remain when encoding the coefficients
        // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
        auto st = crypto_params->get_scaling_technique();
        uint32_t L0 = crypto_params->get_element_params()->get_params().size() - (st == FLEXIBLEAUTOEXT);

        uint32_t l_enc = L0 - composite_degree * (precom->params_enc_.lvlb + 1);
        uint32_t l_dec;
        if (precom->bt_slots_encoding) {
            l_dec = (2 + (st == FLEXIBLEAUTOEXT)) * composite_degree;
        } else {
            uint32_t depth_bt = get_mod_depth_internal(crypto_params->get_secret_key_dist()) +
                                precom->params_enc_.lvlb + precom->params_dec_.lvlb;
            l_dec = L0 - composite_degree * depth_bt;
        }

        bool is_lt_bootstrap = (precom->params_enc_.lvlb == 1) && (precom->params_dec_.lvlb == 1);

        if (is_lt_bootstrap) {
            if (is_sparse) {
                std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> u1hat_t(slots, std::vector<std::complex<double>>(slots));
                for (uint32_t i = 0; i < slots; ++i) {
                    for (uint32_t j = 0; j < slots; ++j) {
                        U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                        u0hat_t[j][i] = std::conj(U0[i][j]);
                        U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                        u1hat_t[j][i] = std::conj(U1[i][j]);
                    }
                }
                if (cc.get_ckks_data_type() == REAL || !precom->bt_slots_encoding) {
                    precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, U1, 1, scale_dec, l_dec);
                    precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, u1hat_t, 0, scale_enc, l_enc);
                } else {
                    precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
                    precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
                }
            } else {
                std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
                for (uint32_t i = 0; i < slots; ++i) {
                    for (uint32_t j = 0; j < slots; ++j) {
                        U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                        u0hat_t[j][i] = std::conj(U0[i][j]);
                    }
                }
                precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
                precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
            }
        } else {
            bool flag_pack = !(cc.get_ckks_data_type() == REAL || !precom->bt_slots_encoding);
            precom->u0_pre_fft_ =
                    eval_slots_to_coeffs_precompute(cc, ksi_pows, rot_group, false, scale_dec, l_dec, flag_pack);
            precom->u0hat_t_pre_fft_ =
                    eval_coeffs_to_slots_precompute(cc, ksi_pows, rot_group, false, scale_enc, l_enc, flag_pack);
        }
    }
}

std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> CkksRnsFhe::eval_bootstrap_key_gen(
        const PrivateKey<RnsPoly> private_key, uint32_t slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(private_key->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto cc = private_key->get_crypto_context();
    auto algo = cc->get_scheme();
    auto M = cc->get_cyclotomic_order();

    slots = (slots == 0) ? M / 4 : slots;

    // computing all indices for baby-step giant-step procedure
    auto eval_keys = algo->eval_at_index_key_gen(private_key, find_bootstrap_rotation_indices(slots, M));

    (*eval_keys)[M - 1] = conjugate_key_gen(private_key);

    if (crypto_params->get_secret_key_dist() == SPARSE_ENCAPSULATED) {
        // sparse key used for the modraising step (Hamming weight 32, or 64 for bottom moduli above 60 bits)
        RnsPoly::TugType tug;
        auto sk_new = std::make_shared<PrivateKeyImpl<RnsPoly>>(cc);
        sk_new->set_private_element(RnsPoly(tug, crypto_params->get_element_params(), Format::EVALUATION,
                                            crypto_params->get_sparse_ks_hamming_weight()));

        // we reserve M-4 and M-2 for the sparse encapsulation switching keys
        // Even autorphism indices are not possible, so there will not be any conflict
        (*eval_keys)[M - 4] = key_switch_gen_sparse(private_key, sk_new);
        (*eval_keys)[M - 2] = algo->key_switch_gen(sk_new, private_key);
    }

    return eval_keys;
}

std::vector<uint32_t> CkksRnsFhe::eval_bootstrap_key_map_indices(const CryptoContext<RnsPoly>& cc, uint32_t slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    if (!crypto_params)
        CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersCKKSRNS");

    auto M = cc->get_cyclotomic_order();
    slots = (slots == 0) ? M / 4 : slots;

    const auto bootstrap_rotations_indices = find_bootstrap_rotation_indices(slots, M);

    std::set<uint32_t> index_list;
    for (const auto rotation_index : bootstrap_rotations_indices)
        index_list.insert(find_automorphism_index2n_complex(rotation_index, M));

    index_list.insert(M - 1);

    if (crypto_params->get_secret_key_dist() == SPARSE_ENCAPSULATED) {
        index_list.insert(M - 2);
        index_list.insert(M - 4);
    }

    return std::vector<uint32_t>(index_list.begin(), index_list.end());
}

void CkksRnsFhe::eval_bootstrap_precompute(const CryptoContextImpl<RnsPoly>& cc, uint32_t num_slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M = cc.get_cyclotomic_order();
    uint32_t slots = (num_slots == 0) ? M / 4 : num_slots;

    // Only a regular-bootstrapping precomputation may be recomputed here: rebuilding an FBT or FEFBT
    // entry would fold the regular-bootstrapping K_UNIFORM into its matrices while keeping the rest of
    // its state (bt_slots_encoding, level budgets, no correction factor). A deserialized precomputation
    // loads with the default BOOTSTRAP tag, so the documented deserialize-then-recompute flow passes.
    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::BOOTSTRAP);

    p.params_enc_ = get_collapsed_fft_params(slots, p.params_enc_.lvlb, p.params_enc_.g);
    p.params_dec_ = get_collapsed_fft_params(slots, p.params_dec_.lvlb, p.params_dec_.g);

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool is_sparse = (M != m);

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rot_group(slots);
    uint32_t five_pows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rot_group[i] = five_pows;
        five_pows *= 5;
        five_pows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksi_pows(m + 1);
    double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(2))
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksi_pows[j].real(std::cos(angle));
        ksi_pows[j].imag(std::sin(angle));
    }
    ksi_pows[m] = ksi_pows[0];

    double k = get_mod_raise_overflow_bound(crypto_params, K_UNIFORM);

    uint32_t composite_degree = crypto_params->get_composite_degree();

    double q_double = get_big_modulus(crypto_params);
    double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(q_double))));
    // For composite scaling, capture the (inexact) overflow normalization SF0/q_double as a coefficient
    // close to 1, SF0*post/q_double, encoded at full precision in the CoeffsToSlots/SlotsToCoeffs matrices
    // and telescoped away; the exact power-of-two 1/post is applied as the shrink/scalar (see eval_bootstrap).
    double pre;
    double post = 1.0;
    if (composite_degree > 1) {
        double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
        post = std::pow(2, std::round(std::log2(q_double / pow_p)));
        pre = crypto_params->get_scaling_factor_real(0) * post / q_double;
    } else {
        pre = q_double / factor;
    }
    // For composite scaling, fold the exact power-of-two 2^-deg = 1/post shrink into the CoeffsToSlots
    // matrix (scale_enc) instead of applying it as a scalar before CoeffsToSlots (see eval_bootstrap), so
    // the CtS rotations act on the full-magnitude message and their key-switch noise scales down with
    // the signal rather than being amplified by 2^deg. scale_dec inverts the residual c1 only.
    double scale_enc = ((composite_degree > 1) ? pre / post : pre) / k;
    double scale_dec = 1.0 / pre;

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    auto st = crypto_params->get_scaling_technique();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size() - (st == FLEXIBLEAUTOEXT);

    uint32_t l_enc = L0 - composite_degree * (p.params_enc_.lvlb + 1);
    uint32_t l_dec;
    if (p.bt_slots_encoding) {
        l_dec = (2 + (st == FLEXIBLEAUTOEXT)) * composite_degree;
    } else {
        uint32_t depth_bt =
                get_mod_depth_internal(crypto_params->get_secret_key_dist()) + p.params_enc_.lvlb + p.params_dec_.lvlb;
        l_dec = L0 - composite_degree * depth_bt;
    }

    bool is_lt_bootstrap = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);

    if (is_lt_bootstrap) {
        if (is_sparse) {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u1hat_t(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                    u0hat_t[j][i] = std::conj(U0[i][j]);
                    U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                    u1hat_t[j][i] = std::conj(U1[i][j]);
                }
            }
            if (cc.get_ckks_data_type() == REAL || !p.bt_slots_encoding) {
                p.u0_pre_ = eval_linear_transform_precompute(cc, U0, U1, 1, scale_dec, l_dec);
                p.u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, u1hat_t, 0, scale_enc, l_enc);
            } else {
                p.u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
                p.u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
            }
        } else {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                    u0hat_t[j][i] = std::conj(U0[i][j]);
                }
            }
            p.u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
            p.u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
        }
    } else {
        bool flag_pack = !(cc.get_ckks_data_type() == REAL || !p.bt_slots_encoding);
        p.u0_pre_fft_ = eval_slots_to_coeffs_precompute(cc, ksi_pows, rot_group, false, scale_dec, l_dec, flag_pack);
        p.u0hat_t_pre_fft_ =
                eval_coeffs_to_slots_precompute(cc, ksi_pows, rot_group, false, scale_enc, l_enc, flag_pack);
    }
}

static_assert(CIPHER_PARTIAL_SUM_RADIX >= 2 && (CIPHER_PARTIAL_SUM_RADIX & (CIPHER_PARTIAL_SUM_RADIX - 1)) == 0,
              "PARTIAL_SUM_RADIX must be a power of two >= 2");

void CkksRnsFhe::eval_partial_sum_in_place(Ciphertext<RnsPoly>& raised, uint32_t slots) {
    const uint32_t N = raised->get_crypto_context()->get_ring_dimension();
    eval_partial_sum_in_place(raised, slots, N / (2 * slots), CIPHER_PARTIAL_SUM_RADIX);
}

void CkksRnsFhe::eval_partial_sum_in_place(Ciphertext<RnsPoly>& ct, uint32_t stride, uint32_t size) {
    if (size <= 1)
        return;

    const auto cc = ct->get_crypto_context();
    const uint32_t N = cc->get_ring_dimension();
    const uint32_t M = cc->get_cyclotomic_order();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ct->get_crypto_parameters());
    if (crypto_params->get_key_switch_technique() != HYBRID) {
        for (uint32_t s = 1; s < size; s <<= 1)
            cc->eval_add_in_place(ct, cc->eval_rotate(ct, stride * s));
        return;
    }

    const auto algo = cc->get_scheme();
    auto eval_key_map = cc->get_eval_automorphism_key_map(ct->get_key_tag());

    std::vector<RnsPoly>& cv = ct->get_elements();
    const auto params_ql = cv[0].get_params();
    const auto params_p = crypto_params->get_params_p();
    const auto params_ql_p = cv[0].get_extended_crt_basis(params_p);
    const uint32_t size_ql = params_ql->get_params().size();
    const uint32_t size_ql_p = params_ql_p->get_params().size();

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    RnsPoly acc(params_ql_p, Format::EVALUATION, true);
    auto c_mult = cv[0].times_no_check(crypto_params->get_p_modq());
    for (uint32_t i = 0; i < size_ql; ++i)
        acc.set_element_at_index(i, std::move(c_mult.get_element_at_index(i)));

    std::vector<uint32_t> vec(N);
    for (uint32_t s = 1; s < size; s <<= 1) {
        uint32_t auto_index = find_automorphism_index2n_complex(stride * s, M);
        auto eval_key_iterator = eval_key_map.find(auto_index);
        if (eval_key_iterator == eval_key_map.end())
            CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");

        precompute_auto_map(N, auto_index, &vec);

        auto digits = algo->eval_key_switch_precompute_core(cv[1], crypto_params);
        auto ba = algo->eval_fast_key_switch_core_ext(digits, eval_key_iterator->second, params_ql);

        // ba[0] += acc;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
        for (uint32_t i = 0; i < size_ql_p; ++i)
            ba[0].get_all_elements()[i] += acc.get_all_elements()[i];

        ba[0] = ba[0].automorphism_transform(auto_index, vec);

        // acc += ba[0];
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
        for (uint32_t i = 0; i < size_ql_p; ++i)
            acc.get_all_elements()[i] += ba[0].get_all_elements()[i];

        // Element 1 is settled every level: the next rotation needs its digit decomposition.
        cv[1] +=
                ba[1].automorphism_transform(auto_index, vec)
                        .approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(),
                                         crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                         crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                         crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                         crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
    }

    cv[0] = acc.approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(),
                                crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
}

void CkksRnsFhe::eval_partial_sum_in_place(Ciphertext<RnsPoly>& ct, uint32_t stride, uint32_t size, uint32_t radix) {
    if (size <= 1)
        return;
    if (radix == 2)
        return eval_partial_sum_in_place(ct, stride, size);

    const auto cc = ct->get_crypto_context();
    const uint32_t N = cc->get_ring_dimension();
    const uint32_t M = cc->get_cyclotomic_order();

    const uint32_t log_radix = cipher::get_msb(radix) - 1;
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ct->get_crypto_parameters());
    if (crypto_params->get_key_switch_technique() != HYBRID) {
        for (uint32_t s = 1; s < size; s <<= log_radix) {
            auto base = ct->clone();
            auto digits = cc->eval_fast_rotation_precompute(base);
            for (uint32_t idx = stride * s; idx < stride * size && idx < radix * stride * s; idx += stride * s)
                cc->eval_add_in_place(ct, cc->eval_fast_rotation(base, idx, M, digits));
        }
        return;
    }

    const auto algo = cc->get_scheme();
    auto eval_key_map = cc->get_eval_automorphism_key_map(ct->get_key_tag());

    std::vector<RnsPoly>& cv = ct->get_elements();
    const auto params_ql = cv[0].get_params();
    const auto params_p = crypto_params->get_params_p();
    const auto params_ql_p = cv[0].get_extended_crt_basis(params_p);
    const uint32_t size_ql = params_ql->get_params().size();
    const uint32_t size_ql_p = params_ql_p->get_params().size();

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    RnsPoly acc(params_ql_p, Format::EVALUATION, true);
    auto c_mult = cv[0].times_no_check(crypto_params->get_p_modq());
    for (uint32_t i = 0; i < size_ql; ++i)
        acc.set_element_at_index(i, std::move(c_mult.get_element_at_index(i)));

    std::vector<uint32_t> vec(N);
    for (uint32_t s = 1; s < size; s <<= log_radix) {
        // One digit decomposition per level, shared by all of the level's rotations.
        auto digits = algo->eval_key_switch_precompute_core(cv[1], crypto_params);

        // Per-level sums; the pre-level accumulator is folded into every rotation of the level.
        RnsPoly lvl0(params_ql_p, Format::EVALUATION, true);
        RnsPoly lvl1(params_ql_p, Format::EVALUATION, true);

        for (uint32_t idx = stride * s; idx < stride * size && idx < radix * stride * s; idx += stride * s) {
            uint32_t auto_index = find_automorphism_index2n_complex(idx, M);
            auto eval_key_iterator = eval_key_map.find(auto_index);
            if (eval_key_iterator == eval_key_map.end())
                CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");

            precompute_auto_map(N, auto_index, &vec);

            auto ba = algo->eval_fast_key_switch_core_ext(digits, eval_key_iterator->second, params_ql);

            // ba[0] += acc;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
            for (uint32_t i = 0; i < size_ql_p; ++i)
                ba[0].get_all_elements()[i] += acc.get_all_elements()[i];

            ba[0] = ba[0].automorphism_transform(auto_index, vec);
            ba[1] = ba[1].automorphism_transform(auto_index, vec);

            // lvl0 += ba[0]; lvl1 += ba[1];
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
            for (uint32_t i = 0; i < size_ql_p; ++i) {
                lvl0.get_all_elements()[i] += ba[0].get_all_elements()[i];
                lvl1.get_all_elements()[i] += ba[1].get_all_elements()[i];
            }
        }

        // acc += lvl0;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
        for (uint32_t i = 0; i < size_ql_p; ++i)
            acc.get_all_elements()[i] += lvl0.get_all_elements()[i];

        // Element 1 settles once per level from the level's extended sum: the next level's
        // rotations need its digit decomposition.
        cv[1] += lvl1.approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(),
                                      crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                      crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                      crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                      crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
    }

    cv[0] = acc.approx_mod_down(params_ql, params_p, crypto_params->get_p_inv_modq(),
                                crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_bootstrap(ConstCiphertext<RnsPoly>& ciphertext, uint32_t num_iterations,
                                               uint32_t precision) const {
    uint32_t slots = ciphertext->get_slots();
    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::BOOTSTRAP);

    if (p.bt_slots_encoding) {
        return eval_bootstrap_st_c_first(ciphertext, num_iterations, precision);
        // AA: Note that in the FIXEDMANUAL case, eval_bootstrap and eval_bootstrap_st_c_first return ciphertexts with different NoiseDeg.
    }

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping only supported with Hybrid key switching.");

    auto st = crypto_params->get_scaling_technique();
#if CIPHER_NATIVE_INT == 128
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS Bootstrapping only supported for FIXEDMANUAL and FIXEDAUTO.");
#endif

    if (num_iterations != 1 && num_iterations != 2)
        CIPHER_THROW("CKKS Bootstrapping only supported for 1 or 2 iterations.");

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc = ciphertext->get_crypto_context();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size();
    auto init_size_q = ciphertext->get_elements()[0].get_num_of_elements();
    uint32_t composite_degree = crypto_params->get_composite_degree();

    if (num_iterations > 1) {
        // Step 1: Get the input.
        uint32_t power_of_two_modulus = 1 << precision;

        // Step 3: Bootstrap the initial ciphertext.
        auto ct_initial_bootstrap = eval_bootstrap(ciphertext, num_iterations - 1, 0);
        cc->get_scheme()->mod_reduce_internal_in_place(ct_initial_bootstrap, composite_degree);

        // Step 4: Scale up by power_of_two_modulus.
        cc->get_scheme()->mult_by_integer_in_place(ct_initial_bootstrap, power_of_two_modulus);

        // If we start with more towers than we obtain from bootstrapping, return the original ciphertext.
        auto bootstrapping_size_q = ct_initial_bootstrap->get_elements()[0].get_num_of_elements();
        if (bootstrapping_size_q <= init_size_q)
            return ciphertext->clone();

        // Step 2: Scale up by power_of_two_modulus, and extend the modulus to power_of_two_modulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        auto ct_scaled_up = ciphertext->clone();
        if (st == FIXEDMANUAL) {
            cc->get_scheme()->mod_reduce_internal_in_place(ct_scaled_up, ct_scaled_up->get_noise_scale_deg() - 1);
        }
        // We multiply by power_of_two_modulus, and leave the last CRT value to be 0 (mod power_of_two_modulus).
        cc->get_scheme()->mult_by_integer_in_place(ct_scaled_up, power_of_two_modulus);

        // Step 5: Mod-down to power_of_two_modulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by power_of_two_modulus.
        auto ct_bootstrapped_scaled_down = ct_initial_bootstrap->clone();
        if (st == FIXEDAUTO) {
            for (auto& cv : ct_bootstrapped_scaled_down->get_elements())
                cv.drop_last_elements(bootstrapping_size_q - init_size_q);
            ct_bootstrapped_scaled_down->set_level(
                    L0 - ct_bootstrapped_scaled_down->get_elements()[0].get_num_of_elements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ct_bootstrapping_error = cc->eval_sub(ct_bootstrapped_scaled_down, ct_scaled_up);

        // Step 8: Bootstrap the error.
        auto ct_bootstrapped_error = eval_bootstrap(ct_bootstrapping_error, 1, 0);
        cc->get_scheme()->mod_reduce_internal_in_place(ct_bootstrapped_error, composite_degree);

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto final_ciphertext = cc->eval_sub(ct_initial_bootstrap, ct_bootstrapped_error);

        // Step 10: Scale back down by power_of_two_modulus to get the original message.
        cc->eval_mult_in_place(final_ciphertext, 1.0 / power_of_two_modulus);

        return final_ciphertext;
    }

    auto element_params_raised = *(crypto_params->get_element_params());
    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        element_params_raised.pop_last_param();

    const auto& params_q = element_params_raised.get_params();
    uint32_t size_q = params_q.size();
    std::vector<NativeInteger> moduli(size_q);
    std::vector<NativeInteger> roots(size_q);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    auto element_params_raised_ptr =
            std::make_shared<RnsParams<RnsPoly::Integer>>(cc->get_cyclotomic_order(), moduli, roots);

    double q_double = get_big_modulus(crypto_params);
    double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
    int32_t deg = std::round(std::log2(q_double / pow_p));
#if CIPHER_NATIVE_INT != 128
    if (deg > static_cast<int32_t>(correction_factor_) && st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
        CIPHER_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                     std::to_string(correction_factor_) + "].");
    }
#endif
    // For composite scaling, deg may exceed the correction factor (the check above is skipped, since with
    // larger composite degrees the first modulus is typically much larger than the scaling factor); in that
    // case no correction is applied instead of letting the unsigned subtraction wrap around.
    uint32_t correction = (deg < static_cast<int32_t>(correction_factor_)) ? correction_factor_ - deg : 0;
    double post = std::pow(2, static_cast<double>(deg));

    // For FLEXIBLE* the exact power-of-two 1/post is applied here as the shrink before CoeffsToSlots and
    // restored by the integer "scalar" after the sine. For composite scaling the entire overflow
    // normalization (the exact 2^-deg = 1/post AND the residual c1) is carried by the CoeffsToSlots/
    // SlotsToCoeffs matrix coefficients (see eval_bootstrap_setup), so no shrink is applied here; this
    // keeps the CtS rotations on the full-magnitude message and avoids amplifying their noise by 2^deg.
    double pre = (composite_degree > 1) ? 1.0 : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    auto raised = ciphertext->clone();
    auto algo = cc->get_scheme();
    algo->mod_reduce_internal_in_place(raised, composite_degree * (raised->get_noise_scale_deg() - 1));
    uint32_t lvl = crypto_params->get_scaling_technique() != FLEXIBLEAUTOEXT ? 0 : 1;
    adjust_ciphertext(raised, std::pow(2, -static_cast<int32_t>(correction)), lvl);

    uint32_t N = cc->get_ring_dimension();
    mod_raise_in_place(raised, element_params_raised_ptr);

#ifdef BOOTSTRAPTIMING
    auto num_towers = raised->get_elements()[0].get_num_of_elements() - 1;
    CIPHER_DIAGNOSTIC_ERR << "\nNumber of levels at the beginning of bootstrapping: " << num_towers << "\n";
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x). The overflow bound K
    // itself is folded into the CoeffsToSlots matrix (see get_mod_raise_overflow_bound), so only the exact 1/N
    // normalization is applied here.
    std::vector<double> coefficients;

    if (crypto_params->get_secret_key_dist() == SPARSE_TERNARY) {
        coefficients = g_coefficients_sparse;
    } else if (crypto_params->get_secret_key_dist() == SPARSE_ENCAPSULATED) {
        // K = 28 (the SPARSE_TERNARY table) for the denser sparse secret (Hamming weight 64: first modulus above
        // 60 bits), K = 16 otherwise
        coefficients = (crypto_params->get_sparse_ks_hamming_weight() > 32) ? g_coefficients_sparse :
                                                                              g_coefficients_sparse_encapsulated;
    } else {
        coefficients = g_coefficients_uniform;
    }

    cc->eval_mult_in_place(raised, pre / N);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeff_lower_bound = -1.0;
    double coeff_upper_bound = 1.0;

    bool is_lt_bootstrap = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);

    Ciphertext<RnsPoly> ctxt_dec;
    if (slots == cc->get_cyclotomic_order() / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->mod_reduce_internal_in_place(raised, composite_degree);

        // only one linear transform is needed as the other one can be derived
        auto ctxt_enc = (is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                            eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised);

        auto& eval_key_map = cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag());
        auto conj = Conjugate(ctxt_enc, eval_key_map);
        auto ctxt_enc_i = cc->eval_sub(ctxt_enc, conj);
        cc->eval_add_in_place(ctxt_enc, conj);
        algo->mult_by_monomial_in_place(ctxt_enc_i, 3 * slots);

        if (st == FIXEDMANUAL) {
            while (ctxt_enc->get_noise_scale_deg() > 1) {
                cc->mod_reduce_in_place(ctxt_enc);
                cc->mod_reduce_in_place(ctxt_enc_i);
            }
        } else {
            if (ctxt_enc->get_noise_scale_deg() == 2) {
                algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
                algo->mod_reduce_internal_in_place(ctxt_enc_i, composite_degree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);
        CIPHER_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
        // Running Approximate Mod Reduction
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxt_enc = algo->eval_chebyshev_series(ctxt_enc, coefficients, coeff_lower_bound, coeff_upper_bound);
        ctxt_enc_i = algo->eval_chebyshev_series(ctxt_enc_i, coefficients, coeff_lower_bound, coeff_upper_bound);

        // Double-angle iterations
        if (st != FIXEDMANUAL) {
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
            algo->mod_reduce_internal_in_place(ctxt_enc_i, composite_degree);
        }
        uint32_t num_iter;
        if (crypto_params->get_secret_key_dist() == UNIFORM_TERNARY)
            num_iter = R_UNIFORM;
        else
            num_iter = R_SPARSE;
        apply_double_angle_iterations(ctxt_enc, num_iter);
        apply_double_angle_iterations(ctxt_enc_i, num_iter);

        algo->mult_by_monomial_in_place(ctxt_enc_i, slots);
        cc->eval_add_in_place_no_check(ctxt_enc, ctxt_enc_i);

        // scale the message back up after Chebyshev interpolation; for composite scaling this restores
        // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
        // StC matrix, see eval_bootstrap_setup)
        algo->mult_by_integer_in_place(ctxt_enc, scalar);

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        CIPHER_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotToCoeff
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);

        // Only one linear transform is needed
        ctxt_dec = (is_lt_bootstrap) ? eval_linear_transform(p.u0_pre_, ctxt_enc) :
                                       eval_slots_to_coeffs(p.u0_pre_fft_, ctxt_enc);
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        eval_partial_sum_in_place(raised, slots);

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->mod_reduce_internal_in_place(raised, composite_degree);

        auto ctxt_enc = (is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                            eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised);

        auto& eval_key_map = cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag());
        cc->eval_add_in_place(ctxt_enc, Conjugate(ctxt_enc, eval_key_map));

        if (st == FIXEDMANUAL) {
            while (ctxt_enc->get_noise_scale_deg() > 1) {
                cc->mod_reduce_in_place(ctxt_enc);
            }
        } else {
            if (ctxt_enc->get_noise_scale_deg() == 2) {
                algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);
        CIPHER_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
        // Running Approximate Mod Reduction
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxt_enc = algo->eval_chebyshev_series(ctxt_enc, coefficients, coeff_lower_bound, coeff_upper_bound);

        // Double-angle iterations
        if (st != FIXEDMANUAL)
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
        uint32_t num_iter = (crypto_params->get_secret_key_dist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
        apply_double_angle_iterations(ctxt_enc, num_iter);

        // scale the message back up after Chebyshev interpolation; for composite scaling this restores
        // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
        // StC matrix, see eval_bootstrap_setup)
        algo->mult_by_integer_in_place(ctxt_enc, scalar);

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        CIPHER_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotsToCoeffs
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);

        // linear transform for decoding
        ctxt_dec = (is_lt_bootstrap) ? eval_linear_transform(p.u0_pre_, ctxt_enc) :
                                       eval_slots_to_coeffs(p.u0_pre_fft_, ctxt_enc);
        cc->eval_add_in_place_no_check(ctxt_dec, cc->eval_rotate(ctxt_dec, slots));
    }

#if CIPHER_NATIVE_INT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t cor_factor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->mult_by_integer_in_place(ctxt_dec, cor_factor);
#endif

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "Decoding time: " << timeDecode / 1000.0 << " s\n";
#endif

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (ctxt_dec->get_elements()[0].get_num_of_elements() <= init_size_q)
        return ciphertext->clone();
    return ctxt_dec;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_bootstrap_st_c_first(ConstCiphertext<RnsPoly>& ciphertext, uint32_t num_iterations,
                                                          uint32_t precision) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping only supported with Hybrid key switching.");

    auto st = crypto_params->get_scaling_technique();
#if CIPHER_NATIVE_INT == 128
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS Bootstrapping only supported for FIXEDMANUAL and FIXEDAUTO.");
#endif

    if (num_iterations != 1 && num_iterations != 2)
        CIPHER_THROW("CKKS Bootstrapping only supported for 1 or 2 iterations.");

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc = ciphertext->get_crypto_context();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size();
    auto init_size_q = ciphertext->get_elements()[0].get_num_of_elements();
    uint32_t composite_degree = crypto_params->get_composite_degree();

    if (num_iterations > 1) {
        // Step 1: Get the input.
        uint32_t power_of_two_modulus = 1 << precision;

        // Step 3: Bootstrap the initial ciphertext.
        auto ct_initial_bootstrap = eval_bootstrap_st_c_first(ciphertext, num_iterations - 1, 0);
        cc->get_scheme()->mod_reduce_internal_in_place(
                ct_initial_bootstrap, composite_degree * (ct_initial_bootstrap->get_noise_scale_deg() - 1));

        // Step 4: Scale up by power_of_two_modulus.
        cc->get_scheme()->mult_by_integer_in_place(ct_initial_bootstrap, power_of_two_modulus);

        // // If we start with more towers than we obtain from bootstrapping, return the original ciphertext.
        auto bootstrapping_size_q = ct_initial_bootstrap->get_elements()[0].get_num_of_elements();
        if (bootstrapping_size_q <= init_size_q)
            return ciphertext->clone();

        // Step 2: Scale up by power_of_two_modulus, and extend the modulus to power_of_two_modulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        auto ct_scaled_up = ciphertext->clone();
        if (st == FIXEDMANUAL) {
            cc->get_scheme()->mod_reduce_internal_in_place(ct_scaled_up, ct_scaled_up->get_noise_scale_deg() - 1);
        }
        // We multiply by power_of_two_modulus, and leave the last CRT value to be 0 (mod power_of_two_modulus).
        cc->get_scheme()->mult_by_integer_in_place(ct_scaled_up, power_of_two_modulus);

        // Step 5: Mod-down to power_of_two_modulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by power_of_two_modulus.
        auto ct_bootstrapped_scaled_down = ct_initial_bootstrap->clone();

        if (st == FIXEDAUTO) {
            for (auto& cv : ct_bootstrapped_scaled_down->get_elements())
                cv.drop_last_elements(bootstrapping_size_q - init_size_q);
            ct_bootstrapped_scaled_down->set_level(
                    L0 - ct_bootstrapped_scaled_down->get_elements()[0].get_num_of_elements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ct_bootstrapping_error = cc->eval_sub(ct_bootstrapped_scaled_down, ct_scaled_up);

        // Step 8: Bootstrap the error.
        auto ct_bootstrapped_error = eval_bootstrap_st_c_first(ct_bootstrapping_error, 1, 0);
        cc->get_scheme()->mod_reduce_internal_in_place(
                ct_bootstrapped_error, composite_degree * (ct_bootstrapped_error->get_noise_scale_deg() - 1));

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto final_ciphertext = cc->eval_sub(ct_initial_bootstrap, ct_bootstrapped_error);

        // Step 10: Scale back down by power_of_two_modulus to get the original message.
        cc->eval_mult_in_place(final_ciphertext, 1.0 / power_of_two_modulus);

        return final_ciphertext;
    }

    uint32_t slots = ciphertext->get_slots();
    auto element_params_raised = *(crypto_params->get_element_params());
    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        element_params_raised.pop_last_param();

    const auto& params_q = element_params_raised.get_params();
    uint32_t size_q = params_q.size();
    std::vector<NativeInteger> moduli(size_q);
    std::vector<NativeInteger> roots(size_q);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    auto element_params_raised_ptr =
            std::make_shared<RnsParams<RnsPoly::Integer>>(cc->get_cyclotomic_order(), moduli, roots);

    double q_double = get_big_modulus(crypto_params);
    double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
    int32_t deg = std::round(std::log2(q_double / pow_p));
#if CIPHER_NATIVE_INT != 128
    if (deg > static_cast<int32_t>(correction_factor_) && st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
        CIPHER_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                     std::to_string(correction_factor_) + "].");
    }
#endif
    // For composite scaling, deg may exceed the correction factor (the check above is skipped, since with
    // larger composite degrees the first modulus is typically much larger than the scaling factor); in that
    // case no correction is applied instead of letting the unsigned subtraction wrap around.
    uint32_t correction = (deg < static_cast<int32_t>(correction_factor_)) ? correction_factor_ - deg : 0;
    double post = std::pow(2, static_cast<double>(deg));

    // For FLEXIBLE* the exact power-of-two 1/post is applied here as the shrink before CoeffsToSlots and
    // restored by the integer "scalar" after the sine. For composite scaling the entire overflow
    // normalization (the exact 2^-deg = 1/post AND the residual c1) is carried by the CoeffsToSlots/
    // SlotsToCoeffs matrix coefficients (see eval_bootstrap_setup), so no shrink is applied here; this
    // keeps the CtS rotations on the full-magnitude message and avoids amplifying their noise by 2^deg.
    double pre = (composite_degree > 1) ? 1.0 : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    auto algo = cc->get_scheme();
    auto N = cc->get_ring_dimension();
    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::BOOTSTRAP);

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x). The overflow bound K
    // itself is folded into the CoeffsToSlots matrix (see get_mod_raise_overflow_bound), so only the exact 1/N
    // normalization is applied here.
    std::vector<double> coefficients;

    if (crypto_params->get_secret_key_dist() == SPARSE_TERNARY) {
        coefficients = g_coefficients_sparse;
    } else if (crypto_params->get_secret_key_dist() == SPARSE_ENCAPSULATED) {
        // K = 28 (the SPARSE_TERNARY table) for the denser sparse secret (Hamming weight 64: first modulus above
        // 60 bits), K = 16 otherwise
        coefficients = (crypto_params->get_sparse_ks_hamming_weight() > 32) ? g_coefficients_sparse :
                                                                              g_coefficients_sparse_encapsulated;
    } else {
        coefficients = g_coefficients_uniform;
    }

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeff_lower_bound = -1.0;
    double coeff_upper_bound = 1.0;

    bool is_lt_bootstrap = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);

    //------------------------------------------------------------------------------
    // Dropping Unnecessary Towers
    //------------------------------------------------------------------------------
    // Only work with the minimum number of required levels.
    auto ctxt_depleted = ciphertext->clone();

    // The SlotsToCoeffs matrix is encoded for an input with composite_degree * (lvlb + 2) towers
    // remaining (l_dec in eval_bootstrap_setup), so each level below costs composite_degree towers.
    // FLEXIBLEAUTOEXT (one extra tower) and composite scaling are mutually exclusive.
    auto expected_level = L0 - composite_degree * (p.params_dec_.lvlb + 2) - (st == FLEXIBLEAUTOEXT);

    if (ctxt_depleted->get_level() + composite_degree * (ctxt_depleted->get_noise_scale_deg() - 1) > expected_level) {
        CIPHER_THROW("Not enough levels to perform Bootstrapping.");
    }

    algo->mod_reduce_internal_in_place(ctxt_depleted, composite_degree * (ctxt_depleted->get_noise_scale_deg() - 1));
    auto ctxt_level = ctxt_depleted->get_level();

    if (st == FIXEDMANUAL || st == FIXEDAUTO) {
        if (ctxt_depleted->get_level() < expected_level) {
            cc->get_scheme()->level_reduce_internal_in_place(ctxt_depleted,
                                                             expected_level - ctxt_depleted->get_level());
        }
    } else {
        if (ctxt_level < expected_level) {
            // Bring the (noise degree 1) ciphertext down to expected_level with the exact scaling factor of
            // that level, using the same maneuver as adjust_levels_and_depth_in_place: multiply by a constant
            // (encoded at the scaling factor of the current level) so that one rescaling by the moduli of
            // the target level lands exactly on get_scaling_factor_real(expected_level). Mixing up the current
            // and target levels here is harmless for FLEXIBLEAUTO (its per-level scaling factors agree to
            // ~2^-30) but costs ~15 bits for composite scaling, whose per-level products of small primes
            // deviate from each other much more.
            double scf2 = ctxt_depleted->get_scaling_factor();
            double scf1 = crypto_params->get_scaling_factor_real_big(expected_level - composite_degree);
            double scf = crypto_params->get_scaling_factor_real(ctxt_level);
            double target_scf = crypto_params->get_scaling_factor_real(expected_level);
            ctxt_depleted = cc->eval_mult(ctxt_depleted, scf1 / scf2 / scf);
            if (ctxt_level + composite_degree < expected_level) {
                cc->get_scheme()->level_reduce_internal_in_place(ctxt_depleted,
                                                                 expected_level - ctxt_level - composite_degree);
            }
            algo->mod_reduce_internal_in_place(ctxt_depleted, composite_degree);
            ctxt_depleted->set_scaling_factor(target_scf);
        }
    }

    Ciphertext<RnsPoly> ctxt_enc;
#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotToCoeff
    //------------------------------------------------------------------------------

    // Linear transform for decoding
    ctxt_depleted = (is_lt_bootstrap) ? eval_linear_transform(p.u0_pre_, ctxt_depleted) :
                                        eval_slots_to_coeffs(p.u0_pre_fft_, ctxt_depleted);

    if (slots != N / 2 && cc->get_ckks_data_type() == REAL) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->eval_add_in_place_no_check(ctxt_depleted, cc->eval_rotate(ctxt_depleted, slots));
    }

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "Decoding time: " << timeDecode / 1000.0 << " s\n";
#endif

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    auto raised = ctxt_depleted->clone();
    algo->mod_reduce_internal_in_place(raised, composite_degree * (raised->get_noise_scale_deg() - 1));
    uint32_t lvl = crypto_params->get_scaling_technique() != FLEXIBLEAUTOEXT ? 0 : 1;
    adjust_ciphertext(raised, std::pow(2, -static_cast<int32_t>(correction)), lvl);

    mod_raise_in_place(raised, element_params_raised_ptr);

#ifdef BOOTSTRAPTIMING
    auto num_towers = raised->get_elements()[0].get_num_of_elements() - 1;
    CIPHER_DIAGNOSTIC_ERR << "\nNumber of levels after mod raise: " << num_towers << "\n";
#endif
    double normalization = pre / N;
    // Scaling adjustment before Coefficient to Slots
    cc->eval_mult_in_place(raised, normalization);

    if (slots != N / 2) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        eval_partial_sum_in_place(raised, slots);
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running CoeffsToSlots
    //------------------------------------------------------------------------------

    algo->mod_reduce_internal_in_place(raised, composite_degree);

    ctxt_enc = (is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                   eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised);

    auto& eval_key_map = cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag());
    auto conj = Conjugate(ctxt_enc, eval_key_map);
    Ciphertext<RnsPoly> ctxt_enc_i;
    if (cc->get_ckks_data_type() == COMPLEX) {
        ctxt_enc_i = cc->eval_sub(ctxt_enc, conj);
        algo->mult_by_monomial_in_place(ctxt_enc_i, 3 * N / 2);
    }
    cc->eval_add_in_place(ctxt_enc, conj);

    if (st == FIXEDMANUAL) {
        while (ctxt_enc->get_noise_scale_deg() > 1) {
            cc->mod_reduce_in_place(ctxt_enc);
            if (cc->get_ckks_data_type() == COMPLEX)
                cc->mod_reduce_in_place(ctxt_enc_i);
        }
    } else {
        if (ctxt_enc->get_noise_scale_deg() == 2) {
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
            if (cc->get_ckks_data_type() == COMPLEX)
                algo->mod_reduce_internal_in_place(ctxt_enc_i, composite_degree);
        }
    }

#ifdef BOOTSTRAPTIMING
    timeEncode = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
    // Running Approximate Mod Reduction
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running Approximate Mod Reduction
    //------------------------------------------------------------------------------

    // Evaluate Chebyshev series for the sine wave
    ctxt_enc = algo->eval_chebyshev_series(ctxt_enc, coefficients, coeff_lower_bound, coeff_upper_bound);
    // AA: Note that for sparse complex, we currently evaluate the polynomial over two ciphertexts.
    // This can be optimized to a single ciphertext (without additional consumed levels) if the last
    // multiplication of the eval_chebyshev_series separates the real and imaginary parts and is
    // combined with a multiplicative masking.
    if (cc->get_ckks_data_type() == COMPLEX)
        ctxt_enc_i = algo->eval_chebyshev_series(ctxt_enc_i, coefficients, coeff_lower_bound, coeff_upper_bound);

    // Double-angle iterations
    if (st != FIXEDMANUAL) {
        algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree * (ctxt_enc->get_noise_scale_deg() - 1));
        if (cc->get_ckks_data_type() == COMPLEX)
            algo->mod_reduce_internal_in_place(ctxt_enc_i, composite_degree);
    }
    uint32_t num_iter = (crypto_params->get_secret_key_dist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
    apply_double_angle_iterations(ctxt_enc, num_iter);

    if (cc->get_ckks_data_type() == COMPLEX) {
        apply_double_angle_iterations(ctxt_enc_i, num_iter);
        algo->mult_by_monomial_in_place(ctxt_enc_i, N / 2);
        cc->eval_add_in_place_no_check(ctxt_enc, ctxt_enc_i);
    }

    // scale the message back up after Chebyshev interpolation; for composite scaling this restores
    // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
    // StC matrix, see eval_bootstrap_setup)
    algo->mult_by_integer_in_place(ctxt_enc, scalar);

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
#endif

#if CIPHER_NATIVE_INT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t cor_factor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->mult_by_integer_in_place(ctxt_enc, cor_factor);
#endif

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (ctxt_enc->get_elements()[0].get_num_of_elements() <= init_size_q)
        return ciphertext->clone();

    return ctxt_enc;
}

void CkksRnsFhe::eval_fe_func_bootstrap_setup(const CryptoContextImpl<RnsPoly>& cc,
                                              const std::vector<uint32_t>& level_budget,
                                              const std::vector<uint32_t>& dim1, uint32_t num_slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS FE functional bootstrapping is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    CIPHER_THROW("128-bit CKKS FE functional bootstrapping is not supported.");
#endif

    uint32_t M = cc.get_cyclotomic_order();
    uint32_t slots = (num_slots == 0) ? M / 4 : num_slots;

    boot_precom_map_[slots] = std::make_shared<CkksBootstrapPrecomputation>();
    auto& precom = boot_precom_map_[slots];
    precom->slots_ = slots;
    precom->bt_slots_encoding = true;
    precom->variant_ = CkksBootstrapPrecomputation::FEFBT;

    // even for the case of a single slot we need one level for rescaling
    uint32_t log_slots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget and compute parameters
    uint32_t new_budget0 = level_budget[0];
    if (new_budget0 > log_slots) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding too large. Setting it to " << log_slots << "\n";
        new_budget0 = log_slots;
    }
    if (new_budget0 < 1) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding can not be zero. Setting it to 1\n";
        new_budget0 = 1;
    }
    uint32_t new_budget1 = level_budget[1];
    if (new_budget1 > log_slots) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding too large. Setting it to " << log_slots << "\n";
        new_budget1 = log_slots;
    }
    if (new_budget1 < 1) {
        CIPHER_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding can not be zero. Setting it to 1\n";
        new_budget1 = 1;
    }

    precom->params_enc_ = get_collapsed_fft_params(slots, new_budget0, dim1[0]);
    precom->params_dec_ = get_collapsed_fft_params(slots, new_budget1, dim1[1]);

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool is_sparse = (M != m);

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rot_group(slots);
    uint32_t five_pows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rot_group[i] = five_pows;
        five_pows *= 5;
        five_pows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksi_pows(m + 1);
    double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(2))
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksi_pows[j].real(std::cos(angle));
        ksi_pows[j].imag(std::sin(angle));
    }
    ksi_pows[m] = ksi_pows[0];

    uint32_t composite_degree = crypto_params->get_composite_degree();

    // K must match the range of the complex-exponential Chebyshev table selected in eval_fe_func_bootstrap;
    // K_UNIFORM_FEFBT covers all composite degrees and ring dimensions, as in regular bootstrapping
    double k = get_mod_raise_overflow_bound(crypto_params, K_UNIFORM_FEFBT);

    double q_double = get_big_modulus(crypto_params);
    double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(q_double))));
    // Same folding as eval_bootstrap_setup: for composite scaling the (inexact) overflow normalization
    // SF0*post/q_double is captured as a coefficient close to 1 that the CoeffsToSlots/SlotsToCoeffs
    // matrices encode at full precision and telescope away, and the exact power-of-two shrink 1/post is
    // folded into the CoeffsToSlots matrix so the CtS rotations act on the full-magnitude message.
    // Unlike regular bootstrapping, nothing is restored after the approximate evaluation: the 2^-deg
    // shrink (deg = 1, enforced in eval_fe_func_bootstrap) is exactly the half-period embedding of the
    // message into the argument of the Fourier series.
    double pre;
    double post = 1.0;
    if (composite_degree > 1) {
        double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
        post = std::pow(2, std::round(std::log2(q_double / pow_p)));
        pre = crypto_params->get_scaling_factor_real(0) * post / q_double;
    } else {
        pre = q_double / factor;
    }
    double scale_enc = ((composite_degree > 1) ? pre / post : pre) / k;
    double scale_dec = 1.0 / pre;

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    auto st = crypto_params->get_scaling_technique();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size() - (st == FLEXIBLEAUTOEXT);

    uint32_t l_enc = L0 - composite_degree * (precom->params_enc_.lvlb + 1);
    uint32_t l_dec = (2 + (st == FLEXIBLEAUTOEXT)) * composite_degree;

    bool is_lt_bootstrap = (precom->params_enc_.lvlb == 1) && (precom->params_dec_.lvlb == 1);

    if (is_lt_bootstrap) {
        if (is_sparse) {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u1hat_t(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                    u0hat_t[j][i] = std::conj(U0[i][j]);
                    U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                    u1hat_t[j][i] = std::conj(U1[i][j]);
                }
            }
            if (cc.get_ckks_data_type() == REAL) {
                precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, U1, 1, scale_dec, l_dec);
                precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, u1hat_t, 0, scale_enc, l_enc);
            } else {
                precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
                precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
            }
        } else {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                    u0hat_t[j][i] = std::conj(U0[i][j]);
                }
            }
            precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
            precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
        }
    } else {
        bool flag_pack = !(cc.get_ckks_data_type() == REAL);
        precom->u0_pre_fft_ =
                eval_slots_to_coeffs_precompute(cc, ksi_pows, rot_group, false, scale_dec, l_dec, flag_pack);
        precom->u0hat_t_pre_fft_ =
                eval_coeffs_to_slots_precompute(cc, ksi_pows, rot_group, false, scale_enc, l_enc, flag_pack);
    }
}

// Everything in FE functional bootstrapping that does not depend on the target function: SlotsToCoeffs,
// modulus raise, CoeffsToSlots, and the complex exponential. The result encrypts exp(2*Pi*i*t) with
// t = mu/2 the message embedded into half of the Fourier series period, which is the variable that every
// target function's series is then evaluated at.
Ciphertext<RnsPoly> CkksRnsFhe::eval_fe_func_bootstrap_exp(ConstCiphertext<RnsPoly>& ciphertext) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS FE functional bootstrapping is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    CIPHER_THROW("128-bit CKKS FE functional bootstrapping is not supported.");
#endif

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeStC(0.0);
    double timeCtS(0.0);
    double timeExp(0.0);
#endif

    auto cc = ciphertext->get_crypto_context();
    auto algo = cc->get_scheme();
    uint32_t N = cc->get_ring_dimension();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size();
    uint32_t slots = ciphertext->get_slots();
    uint32_t composite_degree = crypto_params->get_composite_degree();
    auto st = crypto_params->get_scaling_technique();
    auto skd = crypto_params->get_secret_key_dist();

    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::FEFBT);
    bool is_lt_bootstrap = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);

    auto element_params_raised = *(crypto_params->get_element_params());
    // For FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        element_params_raised.pop_last_param();

    const auto& params_q = element_params_raised.get_params();
    uint32_t size_q = params_q.size();
    std::vector<NativeInteger> moduli(size_q);
    std::vector<NativeInteger> roots(size_q);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    auto element_params_raised_ptr =
            std::make_shared<RnsParams<RnsPoly::Integer>>(cc->get_cyclotomic_order(), moduli, roots);

    // The Fourier series argument is the message embedded into half of its [-1/2, 1/2) period (t = mu/2),
    // realized by the exact 2^-deg shrink with deg = 1. Unlike regular bootstrapping, the shrink cannot
    // be restored after the approximate evaluation (it determines the argument of the complex
    // exponential), so deg must be exactly 1 and no correction factor is applied.
    double q_double = get_big_modulus(crypto_params);
    double pow_p = std::pow(2, crypto_params->get_plaintext_modulus());
    int32_t deg = std::round(std::log2(q_double / pow_p));
    if (deg != 1)
        CIPHER_THROW(
                "CKKS FE functional bootstrapping requires the first level modulus to be twice the scaling "
                "factor (FirstModSize = ScalingModSize + 1); log2(q0/SF) = " +
                std::to_string(deg) + ".");
    // For composite scaling the shrink is folded into the CoeffsToSlots matrix (see eval_fe_func_bootstrap_setup)
    double pre = (composite_degree > 1) ? 1.0 : std::pow(2, -deg);

    // complex-exponential Chebyshev table matching the K folded into the CoeffsToSlots matrix at setup; the K = 28
    // table of SPARSE_TERNARY is also used for SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64)
    const bool small_sparse_key = (skd == SPARSE_ENCAPSULATED) && (crypto_params->get_sparse_ks_hamming_weight() == 32);
    const auto& coeff_exp_value = (skd == UNIFORM_TERNARY) ? coeff_exp_696_double_27 :
                                  small_sparse_key         ? coeff_exp_16_double_23 :
                                                             coeff_exp_28_double_48;
    const uint32_t r_func = (skd == UNIFORM_TERNARY) ? r_func_696_double_27 :
                            small_sparse_key         ? r_func_16_double_23 :
                                                       r_func_28_double_48;

    //------------------------------------------------------------------------------
    // Dropping Unnecessary Towers
    //------------------------------------------------------------------------------
    // Only work with the minimum number of required levels.
    auto ctxt_depleted = ciphertext->clone();

    // The SlotsToCoeffs matrix is encoded for an input with composite_degree * (lvlb + 2) towers
    // remaining (l_dec in eval_fe_func_bootstrap_setup), so each level below costs composite_degree towers.
    // FLEXIBLEAUTOEXT (one extra tower) and composite scaling are mutually exclusive.
    auto expected_level = L0 - composite_degree * (p.params_dec_.lvlb + 2) - (st == FLEXIBLEAUTOEXT);

    if (ctxt_depleted->get_level() + composite_degree * (ctxt_depleted->get_noise_scale_deg() - 1) > expected_level) {
        CIPHER_THROW("Not enough levels to perform FE functional bootstrapping.");
    }

    algo->mod_reduce_internal_in_place(ctxt_depleted, composite_degree * (ctxt_depleted->get_noise_scale_deg() - 1));
    auto ctxt_level = ctxt_depleted->get_level();

    if (st == FIXEDMANUAL || st == FIXEDAUTO) {
        if (ctxt_depleted->get_level() < expected_level) {
            cc->get_scheme()->level_reduce_internal_in_place(ctxt_depleted,
                                                             expected_level - ctxt_depleted->get_level());
        }
    } else {
        if (ctxt_level < expected_level) {
            // Bring the (noise degree 1) ciphertext down to expected_level with the exact scaling factor of
            // that level, using the same maneuver as adjust_levels_and_depth_in_place (see eval_bootstrap_st_c_first).
            double scf2 = ctxt_depleted->get_scaling_factor();
            double scf1 = crypto_params->get_scaling_factor_real_big(expected_level - composite_degree);
            double scf = crypto_params->get_scaling_factor_real(ctxt_level);
            double target_scf = crypto_params->get_scaling_factor_real(expected_level);
            ctxt_depleted = cc->eval_mult(ctxt_depleted, scf1 / scf2 / scf);
            if (ctxt_level + composite_degree < expected_level) {
                cc->get_scheme()->level_reduce_internal_in_place(ctxt_depleted,
                                                                 expected_level - ctxt_level - composite_degree);
            }
            algo->mod_reduce_internal_in_place(ctxt_depleted, composite_degree);
            ctxt_depleted->set_scaling_factor(target_scf);
        }
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // Linear transform for decoding
    ctxt_depleted = (is_lt_bootstrap) ? eval_linear_transform(p.u0_pre_, ctxt_depleted) :
                                        eval_slots_to_coeffs(p.u0_pre_fft_, ctxt_depleted);

    if (slots != N / 2 && cc->get_ckks_data_type() == REAL) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->eval_add_in_place_no_check(ctxt_depleted, cc->eval_rotate(ctxt_depleted, slots));
    }

#ifdef BOOTSTRAPTIMING
    timeStC = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "\nSlotsToCoeffs time: " << timeStC / 1000.0 << " s\n";
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    auto raised = ctxt_depleted;
    algo->mod_reduce_internal_in_place(raised, composite_degree * (raised->get_noise_scale_deg() - 1));
    uint32_t lvl = (st != FLEXIBLEAUTOEXT) ? 0 : 1;
    // correction factor 1: the argument of the complex exponential must stay at the exact message scale
    adjust_ciphertext(raised, 1.0, lvl);

    mod_raise_in_place(raised, element_params_raised_ptr);

    // Scaling adjustment before CoeffsToSlots: K is folded into the CoeffsToSlots matrix for every secret
    // distribution (see eval_fe_func_bootstrap_setup), so the runtime normalization is the exact power of two 2^-deg/N
    double normalization = pre / N;
    cc->eval_mult_in_place(raised, normalization);

    if (slots != N / 2) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE: Running PartialSum
        //------------------------------------------------------------------------------
        eval_partial_sum_in_place(raised, slots);
    }

    //------------------------------------------------------------------------------
    // Running CoeffsToSlots
    //------------------------------------------------------------------------------

    algo->mod_reduce_internal_in_place(raised, composite_degree);

    auto ctxt_enc = (is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                        eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised);

    // Keep only the real channel: for CkksDataType REAL the encoding matrices pack both coefficient halves
    // into it (flag_pack is false in eval_fe_func_bootstrap_setup), and for COMPLEX the imaginary half of the
    // message is dropped, the Fourier series result being real-valued either way.
    auto& eval_key_map = cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag());
    auto conj = Conjugate(ctxt_enc, eval_key_map);
    cc->eval_add_in_place(ctxt_enc, conj);

    if (st == FIXEDMANUAL) {
        while (ctxt_enc->get_noise_scale_deg() > 1) {
            cc->mod_reduce_in_place(ctxt_enc);
        }
    } else {
        if (ctxt_enc->get_noise_scale_deg() == 2) {
            algo->mod_reduce_internal_in_place(ctxt_enc, composite_degree);
        }
    }

#ifdef BOOTSTRAPTIMING
    timeCtS = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "CoeffsToSlots time: " << timeCtS / 1000.0 << " s\n";
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running the Complex Exponential Evaluation
    //------------------------------------------------------------------------------

    auto ctxt_exp_value = algo->eval_chebyshev_series(ctxt_enc, coeff_exp_value, -1, 1);
    // double-angle iterations for the complex exponential: each squaring doubles the argument
    for (uint32_t i = 0; i < r_func; ++i) {
        cc->eval_square_in_place(ctxt_exp_value);
        cc->mod_reduce_in_place(ctxt_exp_value);
    }

#ifdef BOOTSTRAPTIMING
    timeExp = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "EvalExp time: " << timeExp / 1000.0 << " s\n";
#endif

    return ctxt_exp_value;
}

// Twice the real part of an evaluated Fourier series, which is the FE functional bootstrapping output
//   f(t) = 2*Re(c_0 + sum_{j>=1} c_j z^j).
// The constant term c_0 stays in the polynomial handed to eval_poly, which applies it as a single plaintext
// addition after the Paterson-Stockmeyer tree, and the conjugate-add doubles its real part along with the
// rest of the series.
Ciphertext<RnsPoly> CkksRnsFhe::twice_real_part(const Ciphertext<RnsPoly>& ctxt_series) {
    auto cc = ctxt_series->get_crypto_context();
    return cc->eval_add(ctxt_series,
                        Conjugate(ctxt_series, cc->get_eval_automorphism_key_map(ctxt_series->get_key_tag())));
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_fe_func_bootstrap(ConstCiphertext<RnsPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficients) const {
    auto ctxt_exp_value = eval_fe_func_bootstrap_exp(ciphertext);
    auto algo = ctxt_exp_value->get_crypto_context()->get_scheme();

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeSeries(0.0);
    TIC(t);
#endif

    auto result = twice_real_part(algo->eval_poly(ctxt_exp_value, coefficients));

#ifdef BOOTSTRAPTIMING
    timeSeries = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "EvalSeries time: " << timeSeries / 1000.0 << " s\n";
#endif

    return result;
}

std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsFhe::eval_fe_func_bootstrap_precompute(
        ConstCiphertext<RnsPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
    // Below degree 5 eval_powers builds only those powers the given coefficient vector actually needs and
    // leaves the rest of the basis unset, so the result is specific to one function and cannot be shared.
    // Fourier extensions of useful functions are far above this bound.
    if (Degree(coefficients) < 5)
        CIPHER_THROW(
                "CKKS FE functional bootstrapping needs a series of degree 5 or more to precompute shareable "
                "complex-exponential powers; use EvalFEFuncBootstrap for a shorter series.");

    auto ctxt_exp_value = eval_fe_func_bootstrap_exp(ciphertext);
    auto algo = ctxt_exp_value->get_crypto_context()->get_scheme();

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timePowers(0.0);
    TIC(t);
#endif

    auto powers = algo->eval_powers(ctxt_exp_value, coefficients);

#ifdef BOOTSTRAPTIMING
    timePowers = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "EvalPowers time: " << timePowers / 1000.0 << " s\n";
#endif

    return powers;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_fe_func_bootstrap_with_precomp(
        const std::shared_ptr<SeriesPowers<RnsPoly>>& powers,
        const std::vector<std::complex<double>>& coefficients) const {
    if (powers == nullptr || powers->powers_re.empty() || powers->powers2_re.empty())
        CIPHER_THROW("The series powers were not produced by EvalFEFuncBootstrapPrecompute.");
    if (coefficients.size() < 2)
        CIPHER_THROW("The coefficients vector should contain at least 2 elements");

    const uint32_t degree = Degree(coefficients);
    if (degree == 0)
        CIPHER_THROW("The Fourier series has no nonzero coefficient above the constant term.");
    const std::vector<std::complex<double>> trimmed(coefficients.cbegin(), coefficients.cbegin() + degree + 1);

    if (degree < 5) {
        // eval_poly_with_precomp evaluates a short series straight from the power basis, leaving the powers
        // intact for the next function. It reads the first "degree" powers, and the basis left behind by
        // the precomputation is only as wide as that series' Paterson-Stockmeyer k.
        if (degree > powers->powers_re.size())
            CIPHER_THROW("The Fourier series has degree " + std::to_string(degree) + ", above the maximum of " +
                         std::to_string(powers->powers_re.size()) +
                         " spanned by the precomputed complex-exponential powers.");
    } else {
        // The Paterson-Stockmeyer shape (k, m) fixed at precomputation spans degrees up to k*(2^m - 1) - 1,
        // the top coefficient of that range being reserved by the algorithm itself.
        const uint32_t capacity = powers->k * ((1U << powers->m) - 1);
        if (degree >= capacity)
            CIPHER_THROW("The Fourier series has degree " + std::to_string(degree) + ", above the maximum of " +
                         std::to_string(capacity - 1) + " spanned by the precomputed complex-exponential powers.");
    }

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeSeries(0.0);
    TIC(t);
#endif

    auto algo = powers->powers_re.front()->get_crypto_context()->get_scheme();
    auto result = twice_real_part(algo->eval_poly_with_precomp(powers, trimmed));

#ifdef BOOTSTRAPTIMING
    timeSeries = TOC(t);
    CIPHER_DIAGNOSTIC_ERR << "EvalSeries time (precomputed powers): " << timeSeries / 1000.0 << " s\n";
#endif

    return result;
}

//------------------------------------------------------------------------------
// Find Rotation Indices
//------------------------------------------------------------------------------

std::vector<int32_t> CkksRnsFhe::find_bootstrap_rotation_indices(uint32_t slots, uint32_t M) {
    const auto& p = get_boot_precom(slots);

    // Remove possible duplicates and remove automorphisms corresponding to 0 and M/4 by using std::set
    std::set<uint32_t> s;
    if (p.params_enc_.lvlb == 1 && p.params_dec_.lvlb == 1) {
        auto tmp = find_linear_transform_rotation_indices(slots, M);
        s.insert(tmp.begin(), tmp.end());
    } else {
        auto tmp = find_coeffs_to_slots_rotation_indices(slots, M);
        s.insert(tmp.begin(), tmp.end());
        tmp = find_slots_to_coeffs_rotation_indices(slots, M);
        s.insert(tmp.begin(), tmp.end());
    }
    s.insert(static_cast<uint32_t>(slots));
    s.erase(0);
    s.erase(M / 4);

    return std::vector<int32_t>(s.begin(), s.end());
}

// ATTN: This function is a helper methods to be called in find_bootstrap_rotation_indices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on find_bootstrap_rotation_indices() to do that.
std::vector<uint32_t> CkksRnsFhe::find_linear_transform_rotation_indices(uint32_t slots, uint32_t M) {
    const auto& p = get_boot_precom(slots);
    const uint32_t g = (p.params_enc_.g == 0) ? std::ceil(std::sqrt(slots)) : p.params_enc_.g;

    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices
    std::vector<uint32_t> index_list;
    index_list.reserve(g + 32);

    for (uint32_t i = 1; i <= g; ++i)
        index_list.emplace_back(i);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured eval_partial_sum_in_place fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                index_list.emplace_back(idx);
    }

    return index_list;
}

// ATTN: This function is a helper methods to be called in find_bootstrap_rotation_indices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on find_bootstrap_rotation_indices() to do that.
std::vector<uint32_t> CkksRnsFhe::find_coeffs_to_slots_rotation_indices(uint32_t slots, uint32_t M) {
    const auto& p = get_boot_precom(slots).params_enc_;

    // lvlb*(g+1)+g_rem sizes the per-level baby/giant rotations
    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices + correction key
    std::vector<uint32_t> index_list;
    index_list.reserve(p.lvlb * (p.g + 1) + p.g_rem + 32);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured eval_partial_sum_in_place fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                index_list.emplace_back(idx);
    }

    M >>= 2;
    // clamp all indices to [0, 2*slots)
    const uint32_t reduce_mod = std::min(M, 2 * slots);
    const int32_t flag_rem = (p.rem_collapse == 0) ? 0 : 1;
    for (int32_t s = -1 + p.lvlb; s >= flag_rem; --s) {
        const uint32_t scaling_factor = 1U << ((s - flag_rem) * p.layers_collapse + p.rem_collapse);
        for (uint32_t j = 1; j < p.g; ++j)
            index_list.emplace_back(reduce_rotation(j * scaling_factor, reduce_mod));
        if (p.b > 1)
            index_list.emplace_back(reduce_rotation(p.g * scaling_factor, reduce_mod));
    }

    if (flag_rem == 1) {
        for (uint32_t j = 1; j < p.g_rem; ++j)
            index_list.emplace_back(reduce_rotation(j, reduce_mod));
        if (p.b_rem > 1)
            index_list.emplace_back(reduce_rotation(p.g_rem, reduce_mod));
    }

    // StC correction key Aut_{-(slots-1)} (CtS correction is now absorbed into plaintexts)
    index_list.emplace_back(reduce_rotation(-static_cast<int32_t>(slots - 1), reduce_mod));

    return index_list;
}

std::vector<uint32_t> CkksRnsFhe::find_slots_to_coeffs_rotation_indices(uint32_t slots, uint32_t M) {
    const auto& p = get_boot_precom(slots).params_dec_;

    // lvlb*(g+1)+g_rem sizes the per-level baby/giant rotations
    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices
    std::vector<uint32_t> index_list;
    index_list.reserve(p.lvlb * (p.g + 1) + p.g_rem + 32);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured eval_partial_sum_in_place fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                index_list.emplace_back(idx);
    }

    M >>= 2;
    // clamp all indices to [0, 2*slots)
    const uint32_t reduce_mod = std::min(M, 2 * slots);
    const uint32_t flag_rem = (p.rem_collapse == 0) ? 0 : 1;
    const uint32_t smax = p.lvlb - flag_rem;
    for (uint32_t s = 0; s < smax; ++s) {
        const uint32_t scaling_factor = 1U << (s * p.layers_collapse);
        for (uint32_t j = 1; j < p.g; ++j)
            index_list.emplace_back(reduce_rotation(j * scaling_factor, reduce_mod));
        if (p.b > 1)
            index_list.emplace_back(reduce_rotation(p.g * scaling_factor, reduce_mod));
    }

    if (flag_rem == 1) {
        const uint32_t scaling_factor = 1U << (smax * p.layers_collapse);
        for (uint32_t j = 1; j < p.g_rem; ++j)
            index_list.emplace_back(reduce_rotation(j * scaling_factor, reduce_mod));
        if (p.b_rem > 1)
            index_list.emplace_back(reduce_rotation(p.g_rem * scaling_factor, reduce_mod));
    }

    return index_list;
}

//------------------------------------------------------------------------------
// Precomputations for CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

std::vector<ReadOnlyPlaintext> CkksRnsFhe::eval_linear_transform_precompute(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, double scale,
        uint32_t L) const {
    const int32_t slots = A.size();
    if (slots != static_cast<int32_t>(A[0].size()))
        CIPHER_THROW("The matrix passed to EvalLTPrecompute is not square");

    // make sure the plaintext is created only with the necessary amount of moduli
    auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    auto composite_degree = crypto_params->get_composite_degree();
    auto element_params = *(crypto_params->get_element_params());
    uint32_t towers_to_drop = (L == 0) ? 0 : element_params.get_params().size() - L - composite_degree;
    for (uint32_t i = 0; i < towers_to_drop; ++i)
        element_params.pop_last_param();

    const auto& params_q = element_params.get_params();
    uint32_t size_q = params_q.size();
    const auto& params_p = crypto_params->get_params_p()->get_params();
    uint32_t size_p = params_p.size();
    std::vector<NativeInteger> moduli(size_q + size_p);
    std::vector<NativeInteger> roots(size_q + size_p);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    for (uint32_t i = 0; i < size_p; ++i) {
        moduli[size_q + i] = params_p[i]->get_modulus();
        roots[size_q + i] = params_p[i]->get_root_of_unity();
    }
    auto element_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(cc.get_cyclotomic_order(), moduli, roots);

    auto g = get_boot_precom(slots).params_enc_.g;

    const int32_t step = (g == 0) ? std::ceil(std::sqrt(slots)) : g;

    std::vector<ReadOnlyPlaintext> result(slots);
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(slots))
#endif
    for (int32_t ji = 0; ji < slots; ++ji) {
        auto diag = extract_shifted_diagonal(A, ji);
        for (auto& d : diag)
            d *= scale;
        result[ji] = make_aux_plaintext(cc, element_params_ptr, Rotate(diag, -step * (ji / step)), 1, towers_to_drop,
                                        diag.size());
    }
    return result;
}

std::vector<ReadOnlyPlaintext> CkksRnsFhe::eval_linear_transform_precompute(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        const std::vector<std::vector<std::complex<double>>>& B, uint32_t orientation, double scale, uint32_t L) const {
    // make sure the plaintext is created only with the necessary amount of moduli
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();
    auto element_params = *(crypto_params->get_element_params());

    uint32_t towers_to_drop = (L == 0) ? 0 : element_params.get_params().size() - L - composite_degree;
    for (uint32_t i = 0; i < towers_to_drop; ++i)
        element_params.pop_last_param();

    const auto& params_q = element_params.get_params();
    uint32_t size_q = params_q.size();
    const auto& params_p = crypto_params->get_params_p()->get_params();
    uint32_t size_p = params_p.size();
    std::vector<NativeInteger> moduli(size_q + size_p);
    std::vector<NativeInteger> roots(size_q + size_p);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    for (uint32_t i = 0; i < size_p; ++i) {
        moduli[size_q + i] = params_p[i]->get_modulus();
        roots[size_q + i] = params_p[i]->get_root_of_unity();
    }
    auto element_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(cc.get_cyclotomic_order(), moduli, roots);

    const int32_t slots = static_cast<int32_t>(A.size());

    auto g = get_boot_precom(slots).params_enc_.g;

    const int32_t step = (g == 0) ? std::ceil(std::sqrt(slots)) : g;

    std::vector<ReadOnlyPlaintext> result(slots);

    if (orientation == 0) {
        // vertical concatenation - used during homomorphic encoding
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(slots))
#endif
        for (int32_t ji = 0; ji < slots; ++ji) {
            auto vec_a = extract_shifted_diagonal(A, ji);
            auto vec_b = extract_shifted_diagonal(B, ji);
            vec_a.insert(vec_a.end(), vec_b.begin(), vec_b.end());
            for (auto& v : vec_a)
                v *= scale;
            result[ji] = make_aux_plaintext(cc, element_params_ptr, Rotate(vec_a, -step * (ji / step)), 1,
                                            towers_to_drop, vec_a.size());
        }
    } else {
        // horizontal concatenation - used during homomorphic decoding
        std::vector<std::vector<std::complex<double>>> new_a(slots);

        //  A and B are concatenated horizontally
        for (int32_t i = 0; i < slots; ++i) {
            new_a[i].reserve(A[i].size() + B[i].size());
            new_a[i].insert(new_a[i].end(), A[i].begin(), A[i].end());
            new_a[i].insert(new_a[i].end(), B[i].begin(), B[i].end());
        }

#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(slots))
#endif
        for (int32_t ji = 0; ji < slots; ++ji) {
            // shifted diagonal is computed for rectangular map new_a of dimension
            // slots x 2*slots
            auto vec = extract_shifted_diagonal(new_a, ji);
            for (auto& v : vec)
                v *= scale;
            result[ji] = make_aux_plaintext(cc, element_params_ptr, Rotate(vec, -step * (ji / step)), 1, towers_to_drop,
                                            vec.size());
        }
    }

    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> CkksRnsFhe::eval_coeffs_to_slots_precompute(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::complex<double>>& A,
        const std::vector<uint32_t>& rot_group, bool flag_i, double scale, uint32_t L, bool flag_st_c_complex) const {
    const uint32_t slots = rot_group.size();

    const auto& p = get_boot_precom(slots).params_enc_;

    // result is the rotated plaintext version of the coefficients
    std::vector<std::vector<ReadOnlyPlaintext>> result(p.lvlb, std::vector<ReadOnlyPlaintext>(p.num_rotations));

    int32_t stop = -1;
    int32_t flag_rem = 0;
    if (p.rem_collapse != 0) {
        stop = 0;
        flag_rem = 1;

        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[0].resize(p.num_rotations_rem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();

    auto element_params = *(crypto_params->get_element_params());

    uint32_t towers_to_drop = (L == 0) ? 0 : element_params.get_params().size() - L - composite_degree * p.lvlb;
    for (uint32_t i = 0; i < towers_to_drop; ++i)
        element_params.pop_last_param();

    uint32_t level0 = towers_to_drop + composite_degree * (p.lvlb - 1);

    const auto& params_q = element_params.get_params();
    uint32_t size_q = params_q.size();
    const auto& params_p = crypto_params->get_params_p()->get_params();
    uint32_t size_p = params_p.size();
    std::vector<NativeInteger> moduli(size_q + size_p);
    std::vector<NativeInteger> roots(size_q + size_p);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    for (uint32_t i = 0; i < size_p; ++i) {
        moduli[size_q + i] = params_p[i]->get_modulus();
        roots[size_q + i] = params_p[i]->get_root_of_unity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    uint32_t M = cc.get_cyclotomic_order();
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_vector(p.lvlb - stop);
    for (int32_t s = p.lvlb - 1; s >= stop; --s) {
        params_vector[s - stop] = std::make_shared<RnsParams<BigInteger>>(M, moduli, roots);
        size_q -= composite_degree;
        moduli.erase(moduli.begin() + size_q, moduli.begin() + size_q + composite_degree);
        roots.erase(roots.begin() + size_q, roots.begin() + size_q + composite_degree);
    }

    // zero-based inner indices require shifting the pre-rotation by +offset*scale
    const int32_t offset = static_cast<int32_t>((p.num_rotations + 1) / 2) - 1;
    const int32_t offset_rem = static_cast<int32_t>((p.num_rotations_rem + 1) / 2) - 1;
    // running accumulated correction; plaintexts pre-absorb the per-level Aut_{-delta_s}
    int32_t running_acc = 0;

    if (uint32_t M4 = M / 4; slots == M4 || flag_st_c_complex) {
        //------------------------------------------------------------------------------
        // fully-packed mode
        //------------------------------------------------------------------------------

        auto coeff = coeff_encoding_collapse(A, rot_group, p.lvlb, flag_i);

        for (int32_t s = -1 + p.lvlb; s > stop; --s) {
            const int32_t shift_scale = 1 << ((s - flag_rem) * p.layers_collapse + p.rem_collapse);
            const int32_t rot_scale = shift_scale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations) {
                    if ((flag_rem == 0) && (s == stop + 1)) {
                        for (auto& c : coeff[s][ij])
                            c *= scale;
                    }

                    auto rot = Rotate(
                            coeff[s][ij],
                            reduce_rotation(-rot_scale * (ij / p.g) + offset * shift_scale + running_acc, slots));

                    result[s][ij] = make_aux_plaintext(cc, params_vector[s - stop], rot, 1,
                                                       level0 - composite_degree * s, rot.size());
                }
            }
            running_acc += offset * shift_scale;
        }

        if (flag_rem == 1) {
            const uint32_t limit = p.b_rem * p.g_rem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations_rem) {
                    for (auto& c : coeff[stop][ij])
                        c *= scale;

                    auto rot = Rotate(coeff[stop][ij], reduce_rotation(-static_cast<int32_t>(p.g_rem) * (ij / p.g_rem) +
                                                                               offset_rem + running_acc,
                                                                       slots));

                    result[stop][ij] = make_aux_plaintext(cc, params_vector[0], rot, 1, level0, rot.size());
                }
            }
        }
    } else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff = coeff_encoding_collapse(A, rot_group, p.lvlb, false);
        auto coeffi = coeff_encoding_collapse(A, rot_group, p.lvlb, true);

        for (int32_t s = -1 + p.lvlb; s > stop; --s) {
            const int32_t shift_scale = 1 << ((s - flag_rem) * p.layers_collapse + p.rem_collapse);
            const int32_t rot_scale = shift_scale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations) {
                    // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                    auto clear_tmp = coeff[s][ij];
                    auto& clear_tmpi = coeffi[s][ij];
                    clear_tmp.insert(clear_tmp.end(), clear_tmpi.begin(), clear_tmpi.end());
                    if ((flag_rem == 0) && (s == stop + 1)) {
                        for (auto& c : clear_tmp)
                            c *= scale;
                    }

                    auto rot = Rotate(
                            clear_tmp,
                            reduce_rotation(-rot_scale * (ij / p.g) + offset * shift_scale + running_acc, 2 * slots));

                    result[s][ij] = make_aux_plaintext(cc, params_vector[s - stop], rot, 1,
                                                       level0 - composite_degree * s, rot.size());
                }
            }
            running_acc += offset * shift_scale;
        }

        if (flag_rem == 1) {
            const uint32_t limit = p.b_rem * p.g_rem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations_rem) {
                    // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                    auto clear_tmp = coeff[stop][ij];
                    auto& clear_tmpi = coeffi[stop][ij];
                    clear_tmp.insert(clear_tmp.end(), clear_tmpi.begin(), clear_tmpi.end());
                    for (auto& c : clear_tmp)
                        c *= scale;

                    auto rot = Rotate(clear_tmp,
                                      reduce_rotation(-p.g_rem * (ij / p.g_rem) + offset_rem + running_acc, 2 * slots));

                    result[stop][ij] = make_aux_plaintext(cc, params_vector[0], rot, 1, level0, rot.size());
                }
            }
        }
    }
    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> CkksRnsFhe::eval_slots_to_coeffs_precompute(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::complex<double>>& A,
        const std::vector<uint32_t>& rot_group, bool flag_i, double scale, uint32_t L, bool flag_st_c_complex) const {
    const uint32_t slots = rot_group.size();

    const auto& p = get_boot_precom(slots).params_dec_;

    const int32_t flag_rem = (p.rem_collapse == 0) ? 0 : 1;

    // result is the rotated plaintext version of coeff
    std::vector<std::vector<ReadOnlyPlaintext>> result(p.lvlb, std::vector<ReadOnlyPlaintext>(p.num_rotations));
    if (flag_rem == 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[p.lvlb - 1].resize(p.num_rotations_rem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();
    auto element_params = *(crypto_params->get_element_params());

    const uint32_t towers_to_drop = (L == 0) ? 0 : element_params.get_params().size() - L - composite_degree * p.lvlb;
    for (uint32_t i = 0; i < towers_to_drop; ++i)
        element_params.pop_last_param();

    const auto& params_q = element_params.get_params();
    uint32_t size_q = params_q.size();
    const auto& params_p = crypto_params->get_params_p()->get_params();
    uint32_t size_p = params_p.size();
    std::vector<NativeInteger> moduli(size_q + size_p);
    std::vector<NativeInteger> roots(size_q + size_p);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }
    for (uint32_t i = 0; i < size_p; ++i) {
        moduli[size_q + i] = params_p[i]->get_modulus();
        roots[size_q + i] = params_p[i]->get_root_of_unity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    const uint32_t pvlen = p.lvlb + 1 - flag_rem;
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_vector(pvlen);
    for (uint32_t s = 0; s < pvlen; ++s) {
        params_vector[s] = std::make_shared<RnsParams<BigInteger>>(cc.get_cyclotomic_order(), moduli, roots);
        for (uint32_t i = 0; i < composite_degree; ++i, --size_q) {
            moduli.erase(moduli.begin() + size_q - 1);
            roots.erase(roots.begin() + size_q - 1);
        }
    }

    // zero-based inner indices require shifting the pre-rotation by +offset*shift_scale
    const int32_t offset = static_cast<int32_t>((p.num_rotations + 1) / 2) - 1;
    const int32_t offset_rem = static_cast<int32_t>((p.num_rotations_rem + 1) / 2) - 1;
    // CtS output now carries no extra rotation (absorbed into CtS precompute), so start at 0
    int32_t running_acc = 0;

    if (uint32_t M4 = cc.get_cyclotomic_order() / 4; M4 == slots || flag_st_c_complex) {
        auto coeff = coeff_decoding_collapse(A, rot_group, p.lvlb, flag_i);

        const uint32_t smax = p.lvlb - flag_rem;
        for (uint32_t s = 0; s < smax; ++s) {
            const int32_t shift_scale = 1 << (s * p.layers_collapse);
            const int32_t rot_scale = shift_scale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations) {
                    if ((flag_rem == 0) && (s + 1 == smax)) {
                        for (auto& c : coeff[s][ij])
                            c *= scale;
                    }

                    auto rot = Rotate(
                            coeff[s][ij],
                            reduce_rotation(-rot_scale * (ij / p.g) + offset * shift_scale + running_acc, slots));

                    result[s][ij] = make_aux_plaintext(cc, params_vector[s], rot, 1,
                                                       towers_to_drop + composite_degree * s, rot.size());
                }
            }
            running_acc += offset * shift_scale;
        }

        if (flag_rem == 1) {
            const int32_t shift_scale_rem = 1 << (smax * p.layers_collapse);
            const int32_t rot_scale = shift_scale_rem * static_cast<int32_t>(p.g_rem);
            const uint32_t limit = p.b_rem * p.g_rem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations_rem) {
                    for (auto& c : coeff[smax][ij])
                        c *= scale;

                    auto rot = Rotate(
                            coeff[smax][ij],
                            reduce_rotation(-rot_scale * (ij / p.g_rem) + offset_rem * shift_scale_rem + running_acc,
                                            slots));

                    result[smax][ij] = make_aux_plaintext(cc, params_vector[smax], rot, 1,
                                                          towers_to_drop + composite_degree * smax, rot.size());
                }
            }
        }
    } else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff = coeff_decoding_collapse(A, rot_group, p.lvlb, false);
        auto coeffi = coeff_decoding_collapse(A, rot_group, p.lvlb, true);

        const uint32_t smax = p.lvlb - flag_rem;
        for (uint32_t s = 0; s < smax; ++s) {
            const int32_t shift_scale = 1 << (s * p.layers_collapse);
            const int32_t rot_scale = shift_scale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations) {
                    // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                    auto clear_tmp = coeff[s][ij];
                    auto& clear_tmpi = coeffi[s][ij];
                    clear_tmp.insert(clear_tmp.end(), clear_tmpi.begin(), clear_tmpi.end());
                    if ((flag_rem == 0) && (s + 1 == smax)) {
                        // do the scaling only at the last set of coefficients
                        for (auto& c : clear_tmp)
                            c *= scale;
                    }

                    auto rot = Rotate(
                            clear_tmp,
                            reduce_rotation(-rot_scale * (ij / p.g) + offset * shift_scale + running_acc, 2 * slots));

                    result[s][ij] = make_aux_plaintext(cc, params_vector[s], rot, 1,
                                                       towers_to_drop + composite_degree * s, rot.size());
                }
            }
            running_acc += offset * shift_scale;
        }

        if (flag_rem == 1) {
            const int32_t shift_scale_rem = 1 << (smax * p.layers_collapse);
            const int32_t rot_scale = shift_scale_rem * static_cast<int32_t>(p.g_rem);
            const uint32_t limit = p.b_rem * p.g_rem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.num_rotations_rem) {
                    // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                    auto clear_tmp = coeff[smax][ij];
                    auto& clear_tmpi = coeffi[smax][ij];
                    clear_tmp.insert(clear_tmp.end(), clear_tmpi.begin(), clear_tmpi.end());
                    for (auto& c : clear_tmp)
                        c *= scale;

                    auto rot = Rotate(clear_tmp, reduce_rotation(-rot_scale * (ij / p.g_rem) +
                                                                         offset_rem * shift_scale_rem + running_acc,
                                                                 2 * slots));

                    result[smax][ij] = make_aux_plaintext(cc, params_vector[smax], rot, 1,
                                                          towers_to_drop + composite_degree * smax, rot.size());
                }
            }
        }
    }
    return result;
}

//------------------------------------------------------------------------------
// EVALUATION: CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

Ciphertext<RnsPoly> CkksRnsFhe::eval_linear_transform(const std::vector<ReadOnlyPlaintext>& A,
                                                      ConstCiphertext<RnsPoly>& ct) const {
    // Computing the baby-step b_step and the giant-step g_step.
    const int32_t slots = A.size();
    const auto& p = get_boot_precom(slots);
    const int32_t b_step = (p.params_enc_.g == 0) ? std::ceil(std::sqrt(slots)) : p.params_enc_.g;
    const int32_t g_step = std::ceil(static_cast<double>(slots) / b_step);

    auto cc = ct->get_crypto_context();
    auto digits = cc->eval_fast_rotation_precompute(ct);

    std::vector<Ciphertext<RnsPoly>> fast_rotation(b_step - 1);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(b_step - 1))
    for (int32_t j = 1; j < b_step; ++j)
        fast_rotation[j - 1] = cc->eval_fast_rotation_ext(ct, j, digits, true);

    auto ct_ext = cc->key_switch_ext(ct, true);

    uint32_t auto_index = 0;
    std::vector<uint32_t> map;
    EvalKey<RnsPoly> giant_key;
    if (g_step > 1)
        giant_key = get_giant_step_rotation(ct, b_step, auto_index, map);

    // Horner backward accumulation with a single giant stride t = b_step.
    const int32_t gtop = (g_step - 1) * b_step;
    Ciphertext<RnsPoly> outer = eval_mult_ext(ct_ext, A[gtop]);
    for (int32_t i = 1; i < b_step; ++i)
        if (gtop + i < slots)
            eval_add_ext_in_place(outer, eval_mult_ext(fast_rotation[i - 1], A[gtop + i]));

    for (int32_t j = g_step - 2; j >= 0; --j) {
        outer = eval_horner_giant_rotate(outer, auto_index, map, giant_key);
        const int32_t G = j * b_step;
        auto inner = eval_mult_ext(ct_ext, A[G]);
        for (int32_t i = 1; i < b_step; ++i)
            eval_add_ext_in_place(inner, eval_mult_ext(fast_rotation[i - 1], A[G + i]));
        eval_add_ext_in_place(outer, inner);
    }
    return cc->key_switch_down(outer);
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_coeffs_to_slots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                     ConstCiphertext<RnsPoly>& ctxt) const {
    const uint32_t slots = ctxt->get_slots();

    const auto& p = get_boot_precom(slots).params_enc_;

    int32_t stop = -1;
    int32_t flag_rem = 0;
    if (p.rem_collapse != 0) {
        stop = 0;
        flag_rem = 1;
    }

    auto cc = ctxt->get_crypto_context();

    const uint32_t M4 = cc->get_cyclotomic_order() / 4;
    const uint32_t reduce_mod = std::min(M4, 2 * slots);

    auto result = ctxt->clone();

    auto algo = cc->get_scheme();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();

    // the per-level accumulated rotation to undo so the output is in standard slot ordering;
    // folded into the final level's Horner output while it is still in the extended basis
    const int32_t ct_s_delta = reduce_rotation(-static_cast<int32_t>(slots - 1), reduce_mod);

    // hoisted automorphisms
    const int32_t smax = -1 + p.lvlb;
    for (int32_t s = smax; s > stop; --s) {
        if (s != smax)
            algo->mod_reduce_internal_in_place(result, composite_degree);

        const int32_t scale = 1 << ((s - flag_rem) * p.layers_collapse + p.rem_collapse);

        auto digits = cc->eval_fast_rotation_precompute(result);
        std::vector<Ciphertext<RnsPoly>> fast_rotation(p.g);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(p.g))
        for (uint32_t j = 0; j < p.g; ++j)
            fast_rotation[j] = (j != 0) ? cc->eval_fast_rotation_ext(result, reduce_rotation(scale * j, reduce_mod),
                                                                     digits, true) :
                                          cc->key_switch_ext(result, true);

        // Horner backward accumulation with single giant stride t = g * scale
        const int32_t t = reduce_rotation(scale * p.g, reduce_mod);

        const int32_t b_last = static_cast<int32_t>(p.b) - 1;

        uint32_t giant_auto_index = 0;
        std::vector<uint32_t> giant_map;
        EvalKey<RnsPoly> giant_key;
        if (t != 0 && b_last > 0)
            giant_key = get_giant_step_rotation(result, t, giant_auto_index, giant_map);

        const uint32_t gtop = p.g * b_last;
        Ciphertext<RnsPoly> outer = eval_mult_ext(fast_rotation[0], A[s][gtop]);
        for (uint32_t j = 1; j < p.g; ++j)
            if ((gtop + j) != p.num_rotations)
                eval_add_ext_in_place(outer, eval_mult_ext(fast_rotation[j], A[s][gtop + j]));

        for (int32_t i = b_last - 1; i >= 0; --i) {
            if (t != 0)
                outer = eval_horner_giant_rotate(outer, giant_auto_index, giant_map, giant_key);
            const uint32_t G = p.g * i;
            auto inner = eval_mult_ext(fast_rotation[0], A[s][G]);
            for (uint32_t j = 1; j < p.g; ++j)
                eval_add_ext_in_place(inner, eval_mult_ext(fast_rotation[j], A[s][G + j]));
            eval_add_ext_in_place(outer, inner);
        }
        if (s == stop + 1 && flag_rem == 0 && ct_s_delta != 0) {
            uint32_t delta_auto_index = 0;
            std::vector<uint32_t> delta_map;
            auto delta_key = get_giant_step_rotation(result, ct_s_delta, delta_auto_index, delta_map);
            outer = eval_horner_giant_rotate(outer, delta_auto_index, delta_map, delta_key);
        }
        result = cc->key_switch_down(outer);
    }

    if (flag_rem == 1) {
        algo->mod_reduce_internal_in_place(result, composite_degree);

        auto digits = cc->eval_fast_rotation_precompute(result);
        std::vector<Ciphertext<RnsPoly>> fast_rotation_rem(p.g_rem);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(p.g_rem))
        for (uint32_t j = 0; j < p.g_rem; ++j)
            fast_rotation_rem[j] =
                    (j != 0) ? cc->eval_fast_rotation_ext(result, reduce_rotation(j, reduce_mod), digits, true) :
                               cc->key_switch_ext(result, true);

        // Remainder scale is 1 in CtS; Horner giant stride = g_rem
        const int32_t t_rem = reduce_rotation(p.g_rem, reduce_mod);

        const int32_t b_last = static_cast<int32_t>(p.b_rem) - 1;

        uint32_t giant_auto_index = 0;
        std::vector<uint32_t> giant_map;
        EvalKey<RnsPoly> giant_key;
        if (t_rem != 0 && b_last > 0)
            giant_key = get_giant_step_rotation(result, t_rem, giant_auto_index, giant_map);

        const uint32_t gtop_rem = p.g_rem * b_last;
        Ciphertext<RnsPoly> outer = eval_mult_ext(fast_rotation_rem[0], A[stop][gtop_rem]);
        for (uint32_t j = 1; j < p.g_rem; ++j)
            if ((gtop_rem + j) != p.num_rotations_rem)
                eval_add_ext_in_place(outer, eval_mult_ext(fast_rotation_rem[j], A[stop][gtop_rem + j]));

        for (int32_t i = b_last - 1; i >= 0; --i) {
            if (t_rem != 0)
                outer = eval_horner_giant_rotate(outer, giant_auto_index, giant_map, giant_key);
            const uint32_t G_rem = p.g_rem * i;
            auto inner = eval_mult_ext(fast_rotation_rem[0], A[stop][G_rem]);
            for (uint32_t j = 1; j < p.g_rem; ++j)
                eval_add_ext_in_place(inner, eval_mult_ext(fast_rotation_rem[j], A[stop][G_rem + j]));
            eval_add_ext_in_place(outer, inner);
        }
        if (ct_s_delta != 0) {
            uint32_t delta_auto_index = 0;
            std::vector<uint32_t> delta_map;
            auto delta_key = get_giant_step_rotation(result, ct_s_delta, delta_auto_index, delta_map);
            outer = eval_horner_giant_rotate(outer, delta_auto_index, delta_map, delta_key);
        }
        result = cc->key_switch_down(outer);
    }

    return result;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_slots_to_coeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                     ConstCiphertext<RnsPoly>& ctxt) const {
    const uint32_t slots = ctxt->get_slots();

    const auto& p = get_boot_precom(slots).params_dec_;

    const int32_t flag_rem = (p.rem_collapse == 0) ? 0 : 1;

    auto cc = ctxt->get_crypto_context();

    const uint32_t M4 = cc->get_cyclotomic_order() / 4;
    const uint32_t reduce_mod = std::min(M4, 2 * slots);
    const int32_t smax = p.lvlb - flag_rem;

    auto result = ctxt->clone();

    auto algo = cc->get_scheme();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();

    // the StC accumulated correction Aut_{-Delta} where Delta = slots-1; folded into the
    // final level's Horner output while it is still in the extended basis
    const int32_t st_c_delta = reduce_rotation(-static_cast<int32_t>(slots - 1), reduce_mod);

    for (int32_t s = 0; s < smax; ++s) {
        if (s != 0)
            algo->mod_reduce_internal_in_place(result, composite_degree);

        const int32_t scale = 1 << (s * p.layers_collapse);

        auto digits = cc->eval_fast_rotation_precompute(result);
        std::vector<Ciphertext<RnsPoly>> fast_rotation(p.g);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(p.g))
        for (uint32_t j = 0; j < p.g; ++j)
            fast_rotation[j] = (j != 0) ? cc->eval_fast_rotation_ext(result, reduce_rotation(scale * j, reduce_mod),
                                                                     digits, true) :
                                          cc->key_switch_ext(result, true);

        // Horner backward accumulation with single giant stride t = g * scale
        const int32_t t = reduce_rotation(scale * p.g, reduce_mod);

        const int32_t b_last = static_cast<int32_t>(p.b) - 1;

        uint32_t giant_auto_index = 0;
        std::vector<uint32_t> giant_map;
        EvalKey<RnsPoly> giant_key;
        if (t != 0 && b_last > 0)
            giant_key = get_giant_step_rotation(result, t, giant_auto_index, giant_map);

        const uint32_t gtop = p.g * b_last;
        Ciphertext<RnsPoly> outer = eval_mult_ext(fast_rotation[0], A[s][gtop]);
        for (uint32_t j = 1; j < p.g; ++j)
            if ((gtop + j) != p.num_rotations)
                eval_add_ext_in_place(outer, eval_mult_ext(fast_rotation[j], A[s][gtop + j]));

        for (int32_t i = b_last - 1; i >= 0; --i) {
            if (t != 0)
                outer = eval_horner_giant_rotate(outer, giant_auto_index, giant_map, giant_key);
            const uint32_t G = p.g * i;
            auto inner = eval_mult_ext(fast_rotation[0], A[s][G]);
            for (uint32_t j = 1; j < p.g; ++j)
                eval_add_ext_in_place(inner, eval_mult_ext(fast_rotation[j], A[s][G + j]));
            eval_add_ext_in_place(outer, inner);
        }
        if (s == smax - 1 && flag_rem == 0 && st_c_delta != 0) {
            uint32_t delta_auto_index = 0;
            std::vector<uint32_t> delta_map;
            auto delta_key = get_giant_step_rotation(result, st_c_delta, delta_auto_index, delta_map);
            outer = eval_horner_giant_rotate(outer, delta_auto_index, delta_map, delta_key);
        }
        result = cc->key_switch_down(outer);
    }

    if (flag_rem == 1) {
        algo->mod_reduce_internal_in_place(result, composite_degree);

        const int32_t scale_rem = 1 << (smax * p.layers_collapse);

        auto digits = cc->eval_fast_rotation_precompute(result);
        std::vector<Ciphertext<RnsPoly>> fast_rotation_rem(p.g_rem);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(p.g_rem))
        for (uint32_t j = 0; j < p.g_rem; ++j)
            fast_rotation_rem[j] = (j != 0) ?
                                           cc->eval_fast_rotation_ext(
                                                   result, reduce_rotation(scale_rem * j, reduce_mod), digits, true) :
                                           cc->key_switch_ext(result, true);

        // Horner giant stride for remainder: g_rem * scale_rem
        const int32_t t_rem = reduce_rotation(scale_rem * p.g_rem, reduce_mod);

        const int32_t b_last = static_cast<int32_t>(p.b_rem) - 1;

        uint32_t giant_auto_index = 0;
        std::vector<uint32_t> giant_map;
        EvalKey<RnsPoly> giant_key;
        if (t_rem != 0 && b_last > 0)
            giant_key = get_giant_step_rotation(result, t_rem, giant_auto_index, giant_map);

        const uint32_t gtop_rem = p.g_rem * b_last;
        Ciphertext<RnsPoly> outer = eval_mult_ext(fast_rotation_rem[0], A[smax][gtop_rem]);
        for (uint32_t j = 1; j < p.g_rem; ++j)
            if ((gtop_rem + j) != p.num_rotations_rem)
                eval_add_ext_in_place(outer, eval_mult_ext(fast_rotation_rem[j], A[smax][gtop_rem + j]));

        for (int32_t i = b_last - 1; i >= 0; --i) {
            if (t_rem != 0)
                outer = eval_horner_giant_rotate(outer, giant_auto_index, giant_map, giant_key);
            const uint32_t G_rem = p.g_rem * i;
            auto inner = eval_mult_ext(fast_rotation_rem[0], A[smax][G_rem]);
            for (uint32_t j = 1; j < p.g_rem; ++j)
                eval_add_ext_in_place(inner, eval_mult_ext(fast_rotation_rem[j], A[smax][G_rem + j]));
            eval_add_ext_in_place(outer, inner);
        }
        if (st_c_delta != 0) {
            uint32_t delta_auto_index = 0;
            std::vector<uint32_t> delta_map;
            auto delta_key = get_giant_step_rotation(result, st_c_delta, delta_auto_index, delta_map);
            outer = eval_horner_giant_rotate(outer, delta_auto_index, delta_map, delta_key);
        }
        result = cc->key_switch_down(outer);
    }

    return result;
}

uint32_t CkksRnsFhe::get_bootstrap_depth(uint32_t approx_mod_depth, const std::vector<uint32_t>& level_budget,
                                         SecretKeyDist secret_key_dist) {
    if (secret_key_dist == UNIFORM_TERNARY)
        approx_mod_depth += R_UNIFORM - 1;
    return approx_mod_depth + level_budget[0] + level_budget[1];
}

uint32_t CkksRnsFhe::get_bootstrap_depth(const std::vector<uint32_t>& level_budget, SecretKeyDist secret_key_dist) {
    uint32_t approx_mod_depth = get_mod_depth_internal(secret_key_dist);
    // AA: note that the scalings by double constants are not captured here.
    // One extra level is consumed before ModRaise (correction factor), and another is consumed after ModRaise (normalization).
    return approx_mod_depth + level_budget[0] + level_budget[1];
}

//------------------------------------------------------------------------------
// Auxiliary Bootstrap Functions
//------------------------------------------------------------------------------
uint32_t CkksRnsFhe::get_bootstrap_depth_internal(uint32_t approx_mod_depth, const std::vector<uint32_t>& level_budget,
                                                  const CryptoContextImpl<RnsPoly>& cc) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    return get_bootstrap_depth(approx_mod_depth, level_budget, crypto_params->get_secret_key_dist());
}

uint32_t CkksRnsFhe::get_mod_depth_internal(SecretKeyDist secret_key_dist) {
    if (secret_key_dist == UNIFORM_TERNARY)
        return get_multiplicative_depth_by_coeff_vector(g_coefficients_uniform, false) + R_UNIFORM;
    return get_multiplicative_depth_by_coeff_vector(g_coefficients_sparse, false) + R_SPARSE;
}

void CkksRnsFhe::adjust_ciphertext(Ciphertext<RnsPoly>& ciphertext, double correction, uint32_t lvl,
                                   bool mod_reduce_value) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto cc = ciphertext->get_crypto_context();
    auto algo = cc->get_scheme();
    uint32_t composite_degree = crypto_params->get_composite_degree();

    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGAUTO ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGMANUAL) {
        double target_sf = crypto_params->get_scaling_factor_real(lvl);
        double source_sf = ciphertext->get_scaling_factor();
        uint32_t num_towers = ciphertext->get_elements()[0].get_num_of_elements();
        double mod_to_drop =
                crypto_params->get_element_params()->get_params()[num_towers - 1]->get_modulus().convert_to_double();
        for (uint32_t j = 2; j <= composite_degree; ++j) {
            mod_to_drop *= crypto_params->get_element_params()
                                   ->get_params()[num_towers - j]
                                   ->get_modulus()
                                   .convert_to_double();
        }

        // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
        // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for CIPHER_NATIVE_INT = 64.
        // So the other branch is for future purposes (in case we decide to add add the FLEXIBLEAUTO support
        // for CIPHER_NATIVE_INT = 128.
#if CIPHER_NATIVE_INT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        double adjustment_factor = (target_sf / source_sf) * (mod_to_drop / source_sf) * correction;
#else
        double adjustment_factor = (target_sf / source_sf) * (mod_to_drop / source_sf);
#endif
        cc->eval_mult_in_place(ciphertext, adjustment_factor);
        if (mod_reduce_value) {
            algo->mod_reduce_internal_in_place(ciphertext, composite_degree);
            ciphertext->set_scaling_factor(target_sf);
        }
    } else {
#if CIPHER_NATIVE_INT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        cc->eval_mult_in_place(ciphertext, correction);
        if (mod_reduce_value) {
            algo->mod_reduce_internal_in_place(ciphertext, composite_degree);
        }
#endif
    }
}

void CkksRnsFhe::adjust_ciphertext_fbt(Ciphertext<RnsPoly>& ciphertext, double correction) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("This version of AdjustCiphertext is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#if CIPHER_NATIVE_INT != 128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    auto cc = ciphertext->get_crypto_context();
    cc->eval_mult_in_place(ciphertext, correction);
    cc->get_scheme()->mod_reduce_internal_in_place(ciphertext, BASE_NUM_LEVELS_TO_DROP);
#endif
}

void CkksRnsFhe::extend_ciphertext(std::vector<RnsPoly>& ctxt_dcrt_s, const CryptoContextImpl<RnsPoly>& cc,
                                   const std::shared_ptr<RnsPoly::Params> element_params_raised_ptr) const {
    // Raise each ciphertext polynomial from the small bottom RNS basis Ql = {q_0, ..., q_{composite_degree-1}}
    // (the moduli remaining in the depleted ciphertext) to the full raised basis Q. We use the exact
    // RnsPoly::expand_crt_basis (CRT reconstruction with the integer-overflow / "alpha" correction), which
    // produces the balanced representative of [c]_Ql in (-Ql/2, Ql/2].
    // All CRT tables are precomputed in CkksRnsCryptoParams::precompute_crt_tables (at cryptocontext
    // instantiation), so this function stays in full RNS.

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    const uint32_t size_ql = crypto_params->get_composite_degree();  // bottom moduli: source basis Ql

    const auto& params_compl_ql = crypto_params->get_params_mod_raise_compl_ql();
    if (nullptr == params_compl_ql)
        CIPHER_THROW("The modulus-raise tables are not available (they are precomputed for compositeDegree > 1).");
    if (element_params_raised_ptr->get_params().size() != size_ql + params_compl_ql->get_params().size())
        CIPHER_THROW("The raised element parameters do not match the precomputed modulus-raise tables.");

    for (auto& dcrt : ctxt_dcrt_s) {
        // CKKS modulus raise only uses the bottom (level-0) modulus q0 = product of the first composite_degree
        // primes (analogous to the single-prime path, which keeps only index 0). If the input ciphertext still
        // carries more towers, keep just the bottom size_ql before extending, so the source basis matches the
        // precomputed tables (otherwise expand_crt_basis would index the tables out of bounds, corrupting memory).
        if (dcrt.get_num_of_elements() > size_ql)
            dcrt.drop_last_elements(dcrt.get_num_of_elements() - size_ql);
        dcrt.expand_crt_basis(
                element_params_raised_ptr, params_compl_ql, crypto_params->get_mod_raise_ql_hat_inv_modq(),
                crypto_params->get_mod_raise_ql_hat_inv_modq_precon(), crypto_params->get_mod_raise_ql_hat_mod_complq(),
                crypto_params->get_mod_raise_alpha_ql_mod_complq(),
                crypto_params->get_mod_raise_mod_complq_barrett_mu(), crypto_params->get_mod_raiseq_inv(),
                Format::EVALUATION);
    }
}

void CkksRnsFhe::apply_double_angle_iterations(Ciphertext<RnsPoly>& ciphertext, uint32_t num_iter) const {
    constexpr double two_pi = 2.0 * M_PI;

    auto cc = ciphertext->get_crypto_context();

    for (int32_t i = 1 - num_iter; i <= 0; ++i) {
        double scalar = -std::pow(two_pi, -std::pow(2.0, i));
        cc->eval_square_in_place(ciphertext);
        cc->eval_add_in_place(ciphertext, cc->eval_add(ciphertext, scalar));
        cc->mod_reduce_in_place(ciphertext);
    }
}

#if CIPHER_NATIVE_INT == 128
Plaintext CkksRnsFhe::make_aux_plaintext(const CryptoContextImpl<RnsPoly>& cc, const std::shared_ptr<ParmType> params,
                                         const std::vector<std::complex<double>>& value, size_t noise_scale_deg,
                                         uint32_t level, uint32_t slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    double sc_fact = crypto_params->get_scaling_factor_real(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.get_encoding_params(), value,
                                                                 noise_scale_deg, level, sc_fact, slots, COMPLEX));

    RnsPoly& plain_element = p->get_element<RnsPoly>();

    uint32_t N = cc.get_ring_dimension();

    std::vector<std::complex<double>> inverse_value = value;

    inverse_value.resize(slots);

    DiscreteFourierTransform::fft_special_inv(inverse_value, N * 2);
    uint64_t p_bits = cc.get_encoding_params()->get_plaintext_modulus();

    double pow_p = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t p_current = p_bits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> tmp(2 * slots);
    for (uint32_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse_value[i].real(), &n1) * pow_p;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse_value[i].imag(), &n2) * pow_p;

        // Check for possible overflow
        if (is128_bit_overflow(dre) || is128_bit_overflow(dim)) {
            DiscreteFourierTransform::fft_special(inverse_value, N * 2);

            double inv_len = static_cast<double>(inverse_value.size());
            double factor = 2 * M_PI * i;

            double real_max = -1, imag_max = -1;
            uint32_t real_max_idx = -1, imag_max_idx = -1;

            for (uint32_t idx = 0; idx < inverse_value.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> exp_factor = {cos((factor * idx) / inv_len), sin((factor * idx) / inv_len)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prod_factor = inverse_value[idx] * exp_factor;

                double real_val = prod_factor.real();
                double imag_val = prod_factor.imag();

                if (real_val > real_max) {
                    real_max = real_val;
                    real_max_idx = idx;
                }
                if (imag_val > imag_max) {
                    imag_max = imag_val;
                    imag_max_idx = idx;
                }
            }

            auto scaled_input_size = std::ceil(std::log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << real_max_idx << "]: " << real_max << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imag_max_idx << "]: " << imag_max << std::endl;
            buffer << "Scaling factor is " << std::ceil(std::log2(pow_p)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaled_input_size << " bits " << std::endl;
            CIPHER_THROW(buffer.str());
        }

        int128_t re = CKKSPackedEncoding::scale_by_power_of_two(std::llround(dre), p_current + n1);
        int128_t im = CKKSPackedEncoding::scale_by_power_of_two(std::llround(dim), p_current + n2);

        tmp[i] = (re < 0) ? max128_bit_value() + re : re;
        tmp[i + slots] = (im < 0) ? max128_bit_value() + im : im;

        if (is128_bit_overflow(tmp[i]) || is128_bit_overflow(tmp[i + slots])) {
            CIPHER_THROW("Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<RnsParams<BigInteger>> big_params = plain_element.get_params();
    const std::vector<std::shared_ptr<NativePolyParams>>& native_params = big_params->get_params();

    for (size_t i = 0; i < native_params.size(); i++) {
        NativeVector native_vec(N, native_params[i]->get_modulus());
        fit_to_native_vector(N, tmp, max128_bit_value(), &native_vec);
        NativePoly element = plain_element.get_element_at_index(i);
        element.set_values(std::move(native_vec), Format::COEFFICIENT);
        plain_element.set_element_at_index(i, std::move(element));
    }

    uint32_t num_towers = native_params.size();
    std::vector<RnsPoly::Integer> moduli(num_towers);
    for (uint32_t i = 0; i < num_towers; i++) {
        moduli[i] = native_params[i]->get_modulus();
    }

    RnsPoly::Integer int_pow_p = NativeInteger(1) << p_bits;
    std::vector<RnsPoly::Integer> crt_pow_p(num_towers, int_pow_p);

    auto curr_pow_p = crt_pow_p;

    // We want to scale tmp by 2^(pd), and the loop starts from j=2
    // because tmp is already scaled by 2^p in the re/im loop above,
    // and curr_pow_p already is 2^p.
    for (size_t i = 2; i < noise_scale_deg; i++) {
        curr_pow_p = CKKSPackedEncoding::crt_mult(curr_pow_p, crt_pow_p, moduli);
    }

    if (noise_scale_deg > 1) {
        plain_element = plain_element.Times(curr_pow_p);
    }

    p->set_format(Format::EVALUATION);
    p->set_scaling_factor(std::pow(p->get_scaling_factor(), noise_scale_deg));

    return p;
}
#else
Plaintext CkksRnsFhe::make_aux_plaintext(const CryptoContextImpl<RnsPoly>& cc, const std::shared_ptr<ParmType> params,
                                         const std::vector<std::complex<double>>& value, size_t noise_scale_deg,
                                         uint32_t level, uint32_t slots) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    const double sc_fact = crypto_params->get_scaling_factor_real(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.get_encoding_params(), value,
                                                                 noise_scale_deg, level, sc_fact, slots, COMPLEX));

    RnsPoly& plain_element = p->get_element<RnsPoly>();

    uint32_t N = cc.get_ring_dimension();

    std::vector<std::complex<double>> inverse_value = value;
    inverse_value.resize(slots);

    DiscreteFourierTransform::fft_special_inv(inverse_value, N * 2);
    double pow_p = sc_fact;

    // Compute approx_factor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = std::numeric_limits<int32_t>::min();
    for (uint32_t i = 0; i < slots; ++i) {
        inverse_value[i] *= pow_p;
        if (inverse_value[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(std::ceil(std::log2(std::abs(inverse_value[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse_value[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(std::ceil(std::log2(std::abs(inverse_value[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    logc = (logc == std::numeric_limits<int32_t>::min()) ? 0 : logc;
    if (logc < 0)
        CIPHER_THROW("Scaling factor too small");

    int32_t log_valid = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t log_approx = logc - log_valid;
    double approx_factor = std::pow(2, log_approx);

    std::vector<int64_t> tmp(2 * slots);

    for (uint32_t i = 0; i < slots; ++i) {
        // Scale down by approx_factor in case the value exceeds a 64-bit integer.
        double dre = inverse_value[i].real() / approx_factor;
        double dim = inverse_value[i].imag() / approx_factor;

        // Check for possible overflow
        if (is64_bit_overflow(dre) || is64_bit_overflow(dim)) {
            DiscreteFourierTransform::fft_special(inverse_value, N * 2);

            double inv_len = static_cast<double>(inverse_value.size());
            double factor = 2 * M_PI * i;

            double real_max = -1, imag_max = -1;
            uint32_t real_max_idx = -1, imag_max_idx = -1;

            for (uint32_t idx = 0; idx < inverse_value.size(); ++idx) {
                // X[k] * exp( j*2*pi*n*k/N )
                auto prod_factor = inverse_value[idx] * std::complex<double>{std::cos((factor * idx) / inv_len),
                                                                             std::sin((factor * idx) / inv_len)};

                if (prod_factor.real() > real_max) {
                    real_max = prod_factor.real();
                    real_max_idx = idx;
                }
                if (prod_factor.imag() > imag_max) {
                    imag_max = prod_factor.imag();
                    imag_max_idx = idx;
                }
            }

            auto scaled_input_size = std::ceil(std::log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << real_max_idx << "]: " << real_max << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imag_max_idx << "]: " << imag_max << std::endl;
            buffer << "Scaling factor is " << std::ceil(std::log2(pow_p)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaled_input_size << " bits " << std::endl;
            CIPHER_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        tmp[i] = (re < 0) ? max64_bit_value() + re : re;

        int64_t im = std::llround(dim);
        tmp[i + slots] = (im < 0) ? max64_bit_value() + im : im;
    }

    const auto& big_params = plain_element.get_params();
    const auto& native_params = big_params->get_params();

    for (size_t i = 0; i < native_params.size(); ++i) {
        NativeVector native_vec(N, native_params[i]->get_modulus());
        fit_to_native_vector(N, tmp, max64_bit_value(), &native_vec);
        NativePoly element = plain_element.get_element_at_index(i);
        element.set_values(std::move(native_vec), Format::COEFFICIENT);
        plain_element.set_element_at_index(i, std::move(element));
    }

    uint32_t num_towers = native_params.size();
    std::vector<RnsPoly::Integer> moduli(num_towers);
    for (uint32_t i = 0; i < num_towers; ++i) {
        moduli[i] = native_params[i]->get_modulus();
    }

    std::vector<RnsPoly::Integer> crt_pow_p;
    if (crypto_params->get_scaling_technique() == COMPOSITESCALINGAUTO ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGMANUAL) {
        // Duhyeong: Support the case pow_p > 2^64
        //           Later we might need to use the NATIVE_INT=128 version of CkksRnsFhe::make_aux_plaintext for higher precision
        int32_t log_pow_p = static_cast<int32_t>(std::ceil(std::log2(std::abs(pow_p))));

        if (log_pow_p > 64) {
            // Compute approx_factor, a value to scale down by, in case the value exceeds a 64-bit integer.
            log_valid = (log_pow_p <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                                log_pow_p :
                                LargeScalingFactorConstants::MAX_BITS_IN_WORD;
            int32_t log_approx_pow_p = log_pow_p - log_valid;
            if (log_approx_pow_p > 0) {
                int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                           log_approx_pow_p :
                                           LargeScalingFactorConstants::MAX_LOG_STEP;
                auto int_step = RnsPoly::Integer(1) << log_step;
                std::vector<RnsPoly::Integer> crt_approx(num_towers, int_step);
                log_approx_pow_p -= log_step;
                while (log_approx_pow_p > 0) {
                    int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                               log_approx :
                                               LargeScalingFactorConstants::MAX_LOG_STEP;
                    auto int_step = RnsPoly::Integer(1) << log_step;
                    std::vector<RnsPoly::Integer> crt_step(num_towers, int_step);
                    crt_approx = CKKSPackedEncoding::crt_mult(crt_approx, crt_step, moduli);
                    log_approx_pow_p -= log_step;
                }
                crt_pow_p = CKKSPackedEncoding::crt_mult(crt_pow_p, crt_approx, moduli);
            } else {
                double approx_factor = std::pow(2, log_approx_pow_p);
                RnsPoly::Integer int_pow_p{static_cast<uint64_t>(std::llround(pow_p / approx_factor))};
                crt_pow_p = std::vector<RnsPoly::Integer>(num_towers, int_pow_p);
            }
        } else {
            RnsPoly::Integer int_pow_p{static_cast<uint64_t>(std::llround(pow_p))};
            crt_pow_p = std::vector<RnsPoly::Integer>(num_towers, int_pow_p);
        }
    } else {
        RnsPoly::Integer int_pow_p{static_cast<uint64_t>(std::llround(pow_p))};
        crt_pow_p = std::vector<RnsPoly::Integer>(num_towers, int_pow_p);
    }

    auto curr_pow_p = crt_pow_p;

    // We want to scale tmp by 2^(pd), and the loop starts from j=2
    // because tmp is already scaled by 2^p in the re/im loop above,
    // and curr_pow_p already is 2^p.
    for (size_t i = 2; i < noise_scale_deg; ++i)
        curr_pow_p = CKKSPackedEncoding::crt_mult(curr_pow_p, crt_pow_p, moduli);
    if (noise_scale_deg > 1)
        plain_element = plain_element.Times(curr_pow_p);

    // Scale back up by the approx_factor to get the correct encoding.
    if (log_approx > 0) {
        int32_t log_step = (log_approx <= MAX_LOG_STEP) ? log_approx : MAX_LOG_STEP;
        auto int_step = RnsPoly::Integer(1) << log_step;
        std::vector<RnsPoly::Integer> crt_approx(num_towers, int_step);
        log_approx -= log_step;

        while (log_approx > 0) {
            log_step = (log_approx <= MAX_LOG_STEP) ? log_approx : MAX_LOG_STEP;
            int_step = RnsPoly::Integer(1) << log_step;
            std::vector<RnsPoly::Integer> crt_sf(num_towers, int_step);
            crt_approx = CKKSPackedEncoding::crt_mult(crt_approx, crt_sf, moduli);
            log_approx -= log_step;
        }
        plain_element = plain_element.Times(crt_approx);
    }

    p->set_format(Format::EVALUATION);
    p->set_scaling_factor(std::pow(p->get_scaling_factor(), noise_scale_deg));
    return p;
}
#endif

Ciphertext<RnsPoly> CkksRnsFhe::eval_mult_ext(ConstCiphertext<RnsPoly> ciphertext, ConstPlaintext plaintext) {
    auto pt = plaintext->get_element<RnsPoly>();
    pt.set_format(Format::EVALUATION);
    auto result = ciphertext->clone();
    for (auto& c : result->get_elements())
        c *= pt;
    result->set_noise_scale_deg(result->get_noise_scale_deg() + plaintext->get_noise_scale_deg());
    result->set_scaling_factor(result->get_scaling_factor() * plaintext->get_scaling_factor());
    return result;
}

void CkksRnsFhe::eval_add_ext_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly> ciphertext2) {
    auto& cv1 = ciphertext1->get_elements();
    auto& cv2 = ciphertext2->get_elements();
    uint32_t n = cv1.size();
    for (uint32_t i = 0; i < n; ++i)
        cv1[i] += cv2[i];
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_add_ext(ConstCiphertext<RnsPoly> ciphertext1,
                                             ConstCiphertext<RnsPoly> ciphertext2) {
    auto result = ciphertext1->clone();
    eval_add_ext_in_place(result, ciphertext2);
    return result;
}

EvalKey<RnsPoly> CkksRnsFhe::conjugate_key_gen(const PrivateKey<RnsPoly> private_key) {
    uint32_t N = private_key->get_private_element().get_ring_dimension();
    std::vector<uint32_t> vec(N);
    precompute_auto_map(N, 2 * N - 1, &vec);
    const auto cc = private_key->get_crypto_context();
    auto pk_permuted = std::make_shared<PrivateKeyImpl<RnsPoly>>(cc);
    pk_permuted->set_private_element(private_key->get_private_element().automorphism_transform(2 * N - 1, vec));
    pk_permuted->set_key_tag(private_key->get_key_tag());
    return cc->get_scheme()->key_switch_gen(private_key, pk_permuted);
}

Ciphertext<RnsPoly> CkksRnsFhe::Conjugate(ConstCiphertext<RnsPoly> ciphertext,
                                          const std::map<uint32_t, EvalKey<RnsPoly>>& eval_key_map) {
    uint32_t N = ciphertext->get_elements()[0].get_ring_dimension();
    auto algo = ciphertext->get_crypto_context()->get_scheme();
    return algo->eval_automorphism(ciphertext, 2 * N - 1, eval_key_map);
}

void CkksRnsFhe::fit_to_native_vector(uint32_t ring_dim, const std::vector<int64_t>& vec, int64_t big_bound,
                                      NativeVector* native_vec) {
    if (native_vec == nullptr)
        CIPHER_THROW("The passed native vector is empty.");
    NativeInteger big_value_hf(big_bound >> 1);
    NativeInteger modulus(native_vec->get_modulus());
    NativeInteger diff = big_bound - modulus;
    uint32_t dslots = vec.size();
    uint32_t gap = ring_dim / dslots;
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
    // word-scaled-reciprocal reduction (one multiply per element instead of a divide);
    // unlike compute_mu/mod_mu Barrett it is valid for the full 64-bit input range.
    // The biased values are nonnegative, so the int64 -> uint64 conversion is value-preserving.
    const uint64_t q{modulus.convert_to_int<uint64_t>()};
    const int64_t e{static_cast<int64_t>(get_msb(q)) - 2};
    if (e >= 1) {
        const uint64_t half{static_cast<uint64_t>(big_bound) >> 1};
        const uint64_t diff_r{(static_cast<uint64_t>(big_bound) - q) % q};
        const uint64_t mu{static_cast<uint64_t>((static_cast<unsigned __int128>(1) << (64 + e)) / q)};
        for (uint32_t i = 0; i < dslots; ++i) {
            const uint64_t v{static_cast<uint64_t>(vec[i])};
            uint64_t av{v};
            if (av >= q) {
                av -= static_cast<uint64_t>((static_cast<unsigned __int128>(v) * mu) >> 64 >> e) * q;
                if (av >= q)
                    av -= q;
            }
            uint64_t t{av - (diff_r & (0 - static_cast<uint64_t>(v > half)))};
            t += q & (0 - (t >> 63));
            (*native_vec)[gap * i] = t;
        }
        return;
    }
#endif
    for (uint32_t i = 0; i < dslots; ++i) {
        NativeInteger n(vec[i]);
        if (n > big_value_hf) {
            (*native_vec)[gap * i] = n.mod_sub(diff, modulus);
        } else {
            (*native_vec)[gap * i] = n.mod(modulus);
        }
    }
}

#if CIPHER_NATIVE_INT == 128
void CkksRnsFhe::fit_to_native_vector(uint32_t ring_dim, const std::vector<int128_t>& vec, int128_t big_bound,
                                      NativeVector* native_vec) {
    if (native_vec == nullptr)
        CIPHER_THROW("The passed native vector is empty.");
    NativeInteger big_value_hf((uint128_t)big_bound >> 1);
    NativeInteger modulus(native_vec->get_modulus());
    NativeInteger diff = NativeInteger((uint128_t)big_bound) - modulus;
    uint32_t dslots = vec.size();
    uint32_t gap = ring_dim / dslots;
    for (uint32_t i = 0; i < dslots; ++i) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > big_value_hf) {
            (*native_vec)[gap * i] = n.mod_sub(diff, modulus);
        } else {
            (*native_vec)[gap * i] = n.mod(modulus);
        }
    }
}
#endif

// CKKS Functional Bootstrapping implements the tower-drop and rescaling conventions only for the
// techniques below. Composite scaling is not supported yet: it needs a level-specific scaling-factor
// chain whose rescalings are multiples of the composite degree, which the tower drops here do not follow.
// The whole 128-bit build is rejected as well, for every scaling technique: functional bootstrapping has
// no counterpart to the correction-factor scaling path that standard CKKS bootstrapping implements for
// 128 bits, and enabling the unit tests on a 128-bit build shows every case, the FIXED* modes included,
// producing silently wrong results. Supporting it is future work.
static void validate_fbt_scaling_technique([[maybe_unused]] const std::shared_ptr<CkksRnsCryptoParams>& crypto_params) {
#if CIPHER_NATIVE_INT == 128
    CIPHER_THROW("CKKS Functional Bootstrapping is not supported for the 128-bit build (NATIVE_SIZE == 128).");
#else
    auto st = crypto_params->get_scaling_technique();
    if (st != FIXEDMANUAL && st != FIXEDAUTO && st != FLEXIBLEAUTO && st != FLEXIBLEAUTOEXT &&
        st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL)
        CIPHER_THROW(
                "CKKS Functional Bootstrapping is supported for the FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, "
                "FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL methods only.");
#endif
}

template <typename VectorDataType>
void CkksRnsFhe::eval_fbt_setup_internal(const CryptoContextImpl<RnsPoly>& cc,
                                         const std::vector<VectorDataType>& coeffs, uint32_t num_slots,
                                         const BigInteger& p_in, const BigInteger& P_out, const BigInteger& bigq,
                                         const PublicKey<RnsPoly>& pub_key, const std::vector<uint32_t>& dim1,
                                         const std::vector<uint32_t>& level_budget, uint32_t lvls_after_boot,
                                         uint32_t depth_leveled_computation, size_t order) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Functional Bootstrapping is only supported for the Hybrid key switching method.");
    validate_fbt_scaling_technique(crypto_params);

    uint32_t M = cc.get_cyclotomic_order();
    uint32_t slots = (num_slots == 0) ? M / 4 : num_slots;

    boot_precom_map_[slots] = std::make_shared<CkksBootstrapPrecomputation>();
    auto& precom = boot_precom_map_[slots];

    precom->slots_ = slots;
    precom->variant_ = CkksBootstrapPrecomputation::FBT;

    // even for the case of a single slot we need one level for rescaling
    uint32_t log_slots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget. Because the level budget is used outside this function,
    // changing it here leads to exceptions later. Alternatively, move this check outside or update all
    // the uses of level_budget.
    if (level_budget[0] > log_slots || level_budget[1] > log_slots)
        CIPHER_THROW("The level budget is too large. Please set it to be at least one and at most log(slots).");
    if (level_budget[0] < 1 || level_budget[1] < 1)
        CIPHER_THROW("The level budget cannot be zero. Please set it to be at least one and at most log(slots).");

    precom->params_enc_ = get_collapsed_fft_params(slots, level_budget[0], dim1[0]);
    precom->params_dec_ = get_collapsed_fft_params(slots, level_budget[1], dim1[1]);

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rot_group(slots);
    uint32_t five_pows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rot_group[i] = five_pows;
        five_pows *= 5;
        five_pows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksi_pows(m + 1);
    double ak = 2 * M_PI / m;
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksi_pows[j].real(std::cos(angle));
        ksi_pows[j].imag(std::sin(angle));
    }
    ksi_pows[m] = ksi_pows[0];

    auto skd = crypto_params->get_secret_key_dist();
    double k = get_mod_raise_overflow_bound(crypto_params, K_UNIFORM_FBT);

    auto& params = pub_key->get_public_elements()[0].get_params()->get_params();
    uint32_t composite_degree = crypto_params->get_composite_degree();

    // The output of functional bootstrapping keeps 1 + lvls_after_boot levels (composite_degree towers each), so
    // the modulus chain has to be long enough to provide them. Without this check the loop below reads past
    // the end of the params vector and the level arithmetic further down wraps around.
    uint32_t out_towers = composite_degree * (1 + lvls_after_boot);
    if (out_towers > params.size())
        CIPHER_THROW("lvlsAfterBoot (" + std::to_string(lvls_after_boot) +
                     ") is too large: it must be less than the number of levels (" +
                     std::to_string(params.size() / composite_degree) + ").");

    BigInteger q_prime = params[0]->get_modulus();
    for (uint32_t i = 1; i < out_towers; ++i)
        q_prime *= params[i]->get_modulus();

    auto st = crypto_params->get_scaling_technique();
    uint32_t L0 = crypto_params->get_element_params()->get_params().size();
    // the modes that track level-specific scaling factors (see eval_mvb_precompute)
    const bool tracks_level_sf =
            (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL);

    // pre = q / 2^round(log2 q) is the ratio between the modulus of the bottom level and the closest power of two.
    // In the FIXED* modes the message imported from RLWE keeps this ratio (the modulus switching to q is not
    // compensated), so it is folded into the encoding matrix and undone in the decoding matrix. In the modes
    // that track level-specific scaling factors, the ratio is instead removed exactly by the correction
    // 2^p/initial_scaling applied after ModRaise (see eval_mvb_precompute), so it must not be applied again here:
    // for a single prime q the difference is ~2^-30 and hence invisible, but for composite scaling q is a
    // product of small primes and can be off from a power of two by ~2^-10, which would otherwise multiply the
    // integer overflows of the modulus raise and corrupt the approximate modular reduction.
    double pre = 1.0;
    if (!tracks_level_sf) {
        // the modulus of the bottom level: a single prime, or the product of composite_degree primes
        BigInteger q = params[0]->get_modulus();
        for (uint32_t i = 1; i < composite_degree; ++i)
            q *= params[i]->get_modulus();
        const double q_double = q.convert_to_double();
        pre = q_double / std::ldexp(1.0, static_cast<int>(std::round(std::log2(q_double))));
    }
    double scale_enc = pre / k;
    double scale_mod = ratio_to_double(q_prime, bigq * P_out);
    double scale_dec = scale_mod / pre;

    // the depth of the functional bootstrapping itself, with the approximation tables of SPARSE_ENCAPSULATED
    // selected by the actual Hamming weight of its sparse secret (the same selection as in eval_mvb_precompute)
    uint32_t depth_bt =
            depth_leveled_computation + level_budget[0] + level_budget[1] +
            adjust_depth_fbt_internal(coeffs, p_in, order, skd, crypto_params->get_sparse_ks_hamming_weight());

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    if (tracks_level_sf) {
        // In the FLEXIBLE* and COMPOSITESCALING* modes, the ciphertext right after ModRaise is declared to
        // carry the exact level-specific scaling factor (so that all subsequent operations stay on the
        // precomputed scaling-factor chain), while the FBT scale bookkeeping above is done in terms of the
        // nominal power-of-two scaling factor 2^p. The two ratios below convert between the conventions:
        // - scale_enc absorbs SF(raised level)/2^p so the values entering the Chebyshev interpolation
        //   match the nominal convention exactly;
        // - scale_dec absorbs 2^p/SF(final level) so the decoded RLWE output lands at the exact absolute
        //   scale q_prime/P_out regardless of the level-specific scaling factor at the output level.
        double pow2p = std::pow(2.0, static_cast<double>(crypto_params->get_plaintext_modulus()));
        uint32_t raised_level = (st == FLEXIBLEAUTOEXT) ? 1 : 0;
        // the output of functional bootstrapping has out_towers towers remaining
        uint32_t final_level = L0 - out_towers;
        scale_enc *= crypto_params->get_scaling_factor_real(raised_level) / pow2p;
        scale_dec *= pow2p / crypto_params->get_scaling_factor_real(final_level);
    }

    L0 -= (st == FLEXIBLEAUTOEXT);

    // The encoding and decoding matrices are precomputed at the levels below, which have to exist on the
    // chain. Checking here reports the parameter that is actually wrong, instead of letting the unsigned
    // subtractions wrap and failing later inside the plaintext encoding with an unrelated message.
    if (composite_degree * (level_budget[0] + 1) > L0)
        CIPHER_THROW("The encoding level budget (" + std::to_string(level_budget[0]) +
                     ") is too large for the available number of levels (" + std::to_string(L0 / composite_degree) +
                     ").");
    if (composite_degree * depth_bt > L0)
        CIPHER_THROW("The functional bootstrapping depth (" + std::to_string(depth_bt) +
                     ") exceeds the available number of levels (" + std::to_string(L0 / composite_degree) +
                     "). Increase the multiplicative depth, or reduce the level budget or "
                     "depthLeveledComputation.");

    // each level consists of composite_degree towers
    uint32_t l_enc = L0 - composite_degree * (level_budget[0] + 1);
    uint32_t l_dec = L0 - composite_degree * depth_bt;

    bool is_lt_bootstrap = (level_budget[0] == 1) && (level_budget[1] == 1);
    if (is_lt_bootstrap) {
        // allocate all vectors
        std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> u0hat_t(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> u1hat_t(slots, std::vector<std::complex<double>>(slots));

        for (uint32_t i = 0; i < slots; ++i) {
            for (uint32_t j = 0; j < slots; ++j) {
                U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
                u0hat_t[j][i] = std::conj(U0[i][j]);
                U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                u1hat_t[j][i] = std::conj(U1[i][j]);
            }
        }

        if (M == m) {
            precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, scale_enc, l_enc);
            precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, scale_dec, l_dec);
        } else {
            precom->u0hat_t_pre_ = eval_linear_transform_precompute(cc, u0hat_t, u1hat_t, 0, scale_enc, l_enc);
            precom->u0_pre_ = eval_linear_transform_precompute(cc, U0, U1, 1, scale_dec, l_dec);
        }
    } else {
        precom->u0hat_t_pre_fft_ = eval_coeffs_to_slots_precompute(cc, ksi_pows, rot_group, false, scale_enc, l_enc);
        precom->u0_pre_fft_ = eval_slots_to_coeffs_precompute(cc, ksi_pows, rot_group, false, scale_dec, l_dec);
    }
}

void CkksRnsFhe::eval_fbt_setup(const CryptoContextImpl<RnsPoly>& cc,
                                const std::vector<std::complex<double>>& coefficients, uint32_t num_slots,
                                const BigInteger& p_in, const BigInteger& P_out, const BigInteger& bigq,
                                const PublicKey<RnsPoly>& pub_key, const std::vector<uint32_t>& dim1,
                                const std::vector<uint32_t>& level_budget, uint32_t lvls_after_boot,
                                uint32_t depth_leveled_computation, size_t order) {
    eval_fbt_setup_internal(cc, coefficients, num_slots, p_in, P_out, bigq, pub_key, dim1, level_budget,
                            lvls_after_boot, depth_leveled_computation, order);
}

void CkksRnsFhe::eval_fbt_setup(const CryptoContextImpl<RnsPoly>& cc, const std::vector<int64_t>& coefficients,
                                uint32_t num_slots, const BigInteger& p_in, const BigInteger& P_out,
                                const BigInteger& bigq, const PublicKey<RnsPoly>& pub_key,
                                const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& level_budget,
                                uint32_t lvls_after_boot, uint32_t depth_leveled_computation, size_t order) {
    eval_fbt_setup_internal(cc, coefficients, num_slots, p_in, P_out, bigq, pub_key, dim1, level_budget,
                            lvls_after_boot, depth_leveled_computation, order);
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_hom_decoding(ConstCiphertext<RnsPoly>& ciphertext, uint64_t post_scaling,
                                                  uint32_t level_to_reduce) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    validate_fbt_scaling_technique(crypto_params);

    auto ctxt_enc = ciphertext->clone();

    // Drop levels if needed
    auto cc = ciphertext->get_crypto_context();
    auto st = crypto_params->get_scaling_technique();
    uint32_t composite_degree = crypto_params->get_composite_degree();
    if (level_to_reduce > 0) {
        if (st == FIXEDMANUAL) {
            cc->level_reduce_in_place(ctxt_enc, nullptr, level_to_reduce);
        } else if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO ||
                   st == COMPOSITESCALINGMANUAL) {
            // In the FLEXIBLE* and COMPOSITESCALING* modes, towers cannot simply be dropped because the
            // ciphertext has to stay on the chain of level-specific scaling factors. As in
            // adjust_levels_and_depth_in_place, a single scalar multiplication adjusts the value to the scaling
            // factor of the destination level, the remaining towers are dropped directly, and the destination
            // scaling factor is set explicitly. Note that for a degree-2 input, eval_mult_in_place first rescales
            // (consuming one level, i.e., composite_degree towers). Levels are counted in towers here.
            uint32_t dst_level = ctxt_enc->get_level() + composite_degree * level_to_reduce;
            uint32_t cur_level = ctxt_enc->get_level() + composite_degree * (ctxt_enc->get_noise_scale_deg() == 2);
            // The level-specific scaling factors are precomputed only up to the second-to-last level
            // (the accessors silently fall back for larger indices), and the rescale before
            // SlotsToCoeffs consumes one more level anyway.
            uint32_t size_q = crypto_params->get_element_params()->get_params().size();
            if (dst_level > size_q - 2 * composite_degree)
                CIPHER_THROW("levelToReduce is too large: the level after reduction (" + std::to_string(dst_level) +
                             ") must be at most " + std::to_string(size_q - 2 * composite_degree) + ".");
            cc->eval_mult_in_place(ctxt_enc, crypto_params->get_scaling_factor_real_big(dst_level) /
                                                     crypto_params->get_scaling_factor_real_big(cur_level));
            if (dst_level > ctxt_enc->get_level())
                cc->get_scheme()->level_reduce_internal_in_place(ctxt_enc, dst_level - ctxt_enc->get_level());
            ctxt_enc->set_scaling_factor(crypto_params->get_scaling_factor_real_big(dst_level));
        } else {
            // FIXEDAUTO uses the same scaling factor at every level, so towers can be dropped directly
            // (the public level_reduce is a no-op for the AUTO modes).
            cc->get_scheme()->level_reduce_internal_in_place(ctxt_enc, level_to_reduce);
        }
    }

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // In the case of FLEXIBLEAUTO, we need one extra tower
    if (st != FIXEDMANUAL)
        cc->get_scheme()->mod_reduce_internal_in_place(ctxt_enc, composite_degree);

    // linear transform for decoding
    auto slots = ciphertext->get_slots();
    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::FBT);
    auto is_ltbs = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);
    auto ctxt_dec =
            (is_ltbs) ? eval_linear_transform(p.u0_pre_, ctxt_enc) : eval_slots_to_coeffs(p.u0_pre_fft_, ctxt_enc);

    if (slots != cc->get_cyclotomic_order() / 4) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->eval_add_in_place_no_check(ctxt_dec, cc->eval_rotate(ctxt_dec, slots));
    }

    // Because the linear transform might be scaled differently, we might need to scale up the result separately
    // Often, this scaling addreesses the previous division in the trigonometric Hermite coefficients
    if (post_scaling > 1)
        cc->get_scheme()->mult_by_integer_in_place(ctxt_dec, post_scaling);

    // The public mod_reduce is a no-op for the AUTO scaling techniques, so the internal rescaling is
    // called explicitly to bring the result to noise degree 1 (the RLWE output convention).
    if (st == FIXEDMANUAL)
        cc->mod_reduce_in_place(ctxt_dec);
    else
        cc->get_scheme()->mod_reduce_internal_in_place(ctxt_dec, composite_degree);

    // 64-bit only: No need to scale back the message to its original scale.
    return ctxt_dec;
}

template <typename VectorDataType>
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsFhe::eval_mvb_precompute_internal(
        ConstCiphertext<RnsPoly>& ciphertext, const std::vector<VectorDataType>& coefficients, uint32_t digit_bit_size,
        const BigInteger& initial_scaling, size_t order) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");

    validate_fbt_scaling_technique(crypto_params);
    auto st = crypto_params->get_scaling_technique();
    const uint32_t composite_degree = crypto_params->get_composite_degree();
    // The FLEXIBLE* and COMPOSITESCALING* modes track level-specific scaling factors and share the same
    // handling below (the correction is folded into the multiplication after ModRaise, and the raised
    // ciphertext is declared to carry the scaling factor of its level).
    const bool is_flexible =
            (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL);

    // The RLWE-imported payload must not include the FLEXIBLEAUTOEXT extra modulus, so the input has
    // to be imported at least one level deep (SchemeletRlweMp applies this offset automatically).
    if (st == FLEXIBLEAUTOEXT && ciphertext->get_level() == 0)
        CIPHER_THROW(
                "For FLEXIBLEAUTOEXT, the input to CKKS Functional Bootstrapping must be at level 1 or deeper so that it "
                "does not include the extra modulus.");

    // For FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    auto element_params_raised = *(crypto_params->get_element_params());
    if (st == FLEXIBLEAUTOEXT)
        element_params_raised.pop_last_param();

    const auto& params_q = element_params_raised.get_params();
    uint32_t size_q = params_q.size();
    std::vector<NativeInteger> moduli(size_q);
    std::vector<NativeInteger> roots(size_q);
    for (uint32_t i = 0; i < size_q; ++i) {
        moduli[i] = params_q[i]->get_modulus();
        roots[i] = params_q[i]->get_root_of_unity();
    }

    auto cc = ciphertext->get_crypto_context();
    auto M = cc->get_cyclotomic_order();
    auto N = cc->get_ring_dimension();

    auto element_params_raised_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(M, moduli, roots);

    // We don't need the type of scaling and correction as in the standard CKKS bootstrapping
    // because the message doesn't have to be scaled down.
    // Instead, we need to correct the encoding if it originates from a different ciphertext
    // (not typical CKKS).
    // For FLEXIBLE* the correction is expressed w.r.t. the nominal power-of-two scaling factor 2^p
    // (the residual ratio between 2^p and the level-specific scaling factor is folded into the
    // homomorphic encoding/decoding matrices in eval_fbt_setup).
    double nominal_sf = (is_flexible) ? std::pow(2.0, static_cast<double>(crypto_params->get_plaintext_modulus())) :
                                        crypto_params->get_scaling_factor_real(0);
    double correction = nominal_sf / initial_scaling.convert_to_double();

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    auto raised = ciphertext->clone();
    auto algo = cc->get_scheme();
    algo->mod_reduce_internal_in_place(raised, composite_degree * (raised->get_noise_scale_deg() - 1));

    // If correction ~ 1, we should not do this adjustment and save a level
    // AA: make the check more granular (around 1.0000x?)
    // For FLEXIBLE* the correction is instead folded into the multiplication by 1/(k*N) after ModRaise,
    // which does not consume an extra level.
    if (!is_flexible) {
        if (std::llround(correction) != 1.0)
            adjust_ciphertext_fbt(raised, correction);
    } else {
        // The modulus raise below keeps only tower 0, so a multi-tower input (an initial_scaling that
        // spans several RNS limbs, e.g. when levels are available before bootstrapping) must first be
        // brought down to a single tower by rounded rescaling. Each rescale divides the raw payload by
        // the dropped modulus, which correction absorbs, so the residual w.r.t. the nominal 2^p is
        // still folded in exactly after ModRaise. The noise scale degree is restored because the raw
        // payload is not on the CKKS scaling convention.
        while (raised->get_elements()[0].get_num_of_elements() > composite_degree) {
            uint32_t deg = raised->get_noise_scale_deg();
            const auto& moduli = raised->get_elements()[0].get_params()->get_params();
            const size_t size_ql = moduli.size();
            for (uint32_t j = 0; j < composite_degree; ++j)
                correction *= moduli[size_ql - 1 - j]->get_modulus().convert_to_double();
            algo->mod_reduce_internal_in_place(raised, composite_degree);
            raised->set_noise_scale_deg(deg);
        }
    }

    mod_raise_in_place(raised, element_params_raised_ptr);

    // In the FLEXIBLE* and COMPOSITESCALING* modes, declare the raised ciphertext to carry the exact scaling
    // factor of its level, so all subsequent operations track the precomputed chain of level-specific
    // scaling factors. The ratio between this scaling factor and the nominal 2^p is compensated in the
    // homomorphic encoding matrix (see eval_fbt_setup).
    if (is_flexible)
        raised->set_scaling_factor(crypto_params->get_scaling_factor_real(raised->get_level()));

#ifdef BOOTSTRAPTIMING
    auto num_towers = raised->get_elements()[0].get_num_of_elements() - 1;
    CIPHER_DIAGNOSTIC_ERR << "\nNumber of levels at the beginning of bootstrapping: " << num_towers << "\n";
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    auto skd = crypto_params->get_secret_key_dist();
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus
    // above 60 bits) uses the K = 28 approximations of SPARSE_TERNARY
    if (uses_large_sparse_key(skd, crypto_params->get_sparse_ks_hamming_weight()))
        skd = SPARSE_TERNARY;
    // number of double-angle iterations for the approximate modular reduction
    uint32_t num_iter = (skd == UNIFORM_TERNARY) ? R_UNIFORM_FBT : R_SPARSE_FBT;

    // The division by the overflow bound K is part of the CoeffsToSlots matrix (see eval_fbt_setup), so only the
    // 1/N normalization of the homomorphic encoding is applied here. For the modes tracking level-specific
    // scaling factors the initial-scaling correction is folded in as well, so no extra level is consumed.
    cc->eval_mult_in_place(raised, ((is_flexible) ? correction : 1.0) / N);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeff_lower_bound = -1.0;
    double coeff_upper_bound = 1.0;

    auto slots = ciphertext->get_slots();
    auto& p = get_boot_precom(slots, CkksBootstrapPrecomputation::FBT);
    bool is_lt_bootstrap = (p.params_enc_.lvlb == 1) && (p.params_dec_.lvlb == 1);

    std::vector<Ciphertext<RnsPoly>> ctxt_enc;
    ctxt_enc.reserve(2);
    std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers;

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->mod_reduce_internal_in_place(raised, composite_degree);

        // only one linear transform is needed as the other one can be derived
        ctxt_enc.emplace_back((is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                                  eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised));

        auto conj = Conjugate(ctxt_enc[0], cc->get_eval_automorphism_key_map(ctxt_enc[0]->get_key_tag()));

        ctxt_enc.emplace_back(cc->eval_sub(ctxt_enc[0], conj));
        cc->eval_add_in_place_no_check(ctxt_enc[0], conj);
        algo->mult_by_monomial_in_place(ctxt_enc[1], 3 * M / 4);

        if (crypto_params->get_scaling_technique() == FIXEDMANUAL) {
            while (ctxt_enc[0]->get_noise_scale_deg() > 1) {
                cc->mod_reduce_in_place(ctxt_enc[0]);
                cc->mod_reduce_in_place(ctxt_enc[1]);
            }
        } else {
            if (ctxt_enc[0]->get_noise_scale_deg() == 2) {
                algo->mod_reduce_internal_in_place(ctxt_enc[0], composite_degree);
                algo->mod_reduce_internal_in_place(ctxt_enc[1], composite_degree);
            }
        }

        //------------------------------------------------------------------------------
        // Computing the powers for Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digit_bit_size == 1 && order == 1) {
            auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                             coeff_cos_28_double_68;

            ctxt_enc[0] = algo->eval_chebyshev_series(ctxt_enc[0], coeff_cos, coeff_lower_bound, coeff_upper_bound);
            ctxt_enc[1] = algo->eval_chebyshev_series(ctxt_enc[1], coeff_cos, coeff_lower_bound, coeff_upper_bound);

            for (auto& ctxt : ctxt_enc) {
                // Double angle-iterations to get cos(pi*x)
                for (uint32_t i = 1; i < num_iter; ++i) {
                    cc->eval_square_in_place(ctxt);
                    cc->eval_add_in_place_no_check(ctxt, ctxt);
                    cc->eval_sub_in_place(ctxt, 1.0);
                    cc->mod_reduce_in_place(ctxt);
                }
                // cos(pi x) after the loop above; square once more to get cos^2(pi x)
                cc->eval_square_in_place(ctxt);
                cc->mod_reduce_in_place(ctxt);  // cos^2(pi x)
            }
        } else {
            auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                             coeff_exp_28_double_69;

            // Obtain the exp(2*Pi*i*x/2^num_iter) approximation via Chebyshev Basis Polynomial Interpolation
            ctxt_enc[0] = algo->eval_chebyshev_series(ctxt_enc[0], coeff_exp, coeff_lower_bound, coeff_upper_bound);
            ctxt_enc[1] = algo->eval_chebyshev_series(ctxt_enc[1], coeff_exp, coeff_lower_bound, coeff_upper_bound);

            for (auto& ctxt : ctxt_enc) {
                // Double angle-iterations to get exp(2*Pi*i*x)
                for (uint32_t i = 0; i < num_iter; ++i) {
                    cc->eval_square_in_place(ctxt);
                    cc->mod_reduce_in_place(ctxt);
                }
            }
        }

        auto ctxt_powers_re = algo->eval_powers(ctxt_enc[0], coefficients);
        auto ctxt_powers_im = algo->eval_powers(ctxt_enc[1], coefficients);

        if (ctxt_powers_re->powers2_re.size() == 0) {
            ctxt_powers = std::make_shared<SeriesPowers<RnsPoly>>(ctxt_powers_re->powers_re, ctxt_powers_im->powers_re);
        } else {
            ctxt_powers = std::make_shared<SeriesPowers<RnsPoly>>(
                    ctxt_powers_re->powers_re, ctxt_powers_re->powers2_re, ctxt_powers_re->power2km1_re,
                    ctxt_powers_re->k, ctxt_powers_re->m, ctxt_powers_im->powers_re, ctxt_powers_im->powers2_re,
                    ctxt_powers_im->power2km1_re);
        }
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        eval_partial_sum_in_place(raised, slots);

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->mod_reduce_internal_in_place(raised, composite_degree);

        ctxt_enc.emplace_back((is_lt_bootstrap) ? eval_linear_transform(p.u0hat_t_pre_, raised) :
                                                  eval_coeffs_to_slots(p.u0hat_t_pre_fft_, raised));

        auto& eval_key_map = cc->get_eval_automorphism_key_map(ctxt_enc[0]->get_key_tag());
        cc->eval_add_in_place(ctxt_enc[0], Conjugate(ctxt_enc[0], eval_key_map));

        if (crypto_params->get_scaling_technique() == FIXEDMANUAL) {
            while (ctxt_enc[0]->get_noise_scale_deg() > 1)
                cc->mod_reduce_in_place(ctxt_enc[0]);
        } else {
            if (ctxt_enc[0]->get_noise_scale_deg() == 2)
                algo->mod_reduce_internal_in_place(ctxt_enc[0], composite_degree);
        }

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digit_bit_size == 1 && order == 1) {
            auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                             coeff_cos_28_double_68;

            ctxt_enc[0] = algo->eval_chebyshev_series(ctxt_enc[0], coeff_cos, coeff_lower_bound, coeff_upper_bound);

            // Double angle-iterations to get cos(pi*x)
            for (uint32_t i = 1; i < num_iter; ++i) {
                cc->eval_square_in_place(ctxt_enc[0]);
                cc->eval_add_in_place_no_check(ctxt_enc[0], ctxt_enc[0]);
                cc->eval_sub_in_place(ctxt_enc[0], 1.0);
                cc->mod_reduce_in_place(ctxt_enc[0]);
            }
            // cos(pi x) after the loop above; square once more to get cos^2(pi x)
            cc->eval_square_in_place(ctxt_enc[0]);
            cc->mod_reduce_in_place(ctxt_enc[0]);  // cos^2(pi x)
        } else {
            auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                             coeff_exp_28_double_69;

            // Obtain the exp(2*Pi*i*x/2^num_iter) approximation via Chebyshev Basis Polynomial Interpolation
            ctxt_enc[0] = algo->eval_chebyshev_series(ctxt_enc[0], coeff_exp, coeff_lower_bound, coeff_upper_bound);

            // Double angle-iterations to get exp(2*Pi*i*x)
            for (uint32_t i = 0; i < num_iter; ++i) {
                cc->eval_square_in_place(ctxt_enc[0]);
                cc->mod_reduce_in_place(ctxt_enc[0]);
            }
        }

        // No need to scale the message back up after Chebyshev interpolation
        ctxt_powers = algo->eval_powers(ctxt_enc[0], coefficients);
    }

    // 64-bit only: No need to scale back the message to its original scale.
    return ctxt_powers;
}

std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsFhe::eval_mvb_precompute(
        ConstCiphertext<RnsPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients,
        uint32_t digit_bit_size, const BigInteger& initial_scaling, size_t order) {
    return eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order);
}
std::shared_ptr<SeriesPowers<RnsPoly>> CkksRnsFhe::eval_mvb_precompute(ConstCiphertext<RnsPoly>& ciphertext,
                                                                       const std::vector<int64_t>& coefficients,
                                                                       uint32_t digit_bit_size,
                                                                       const BigInteger& initial_scaling,
                                                                       size_t order) {
    return eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order);
}

template <typename VectorDataType>
Ciphertext<RnsPoly> CkksRnsFhe::eval_mvb_no_decoding_internal(const std::shared_ptr<SeriesPowers<RnsPoly>>& ciphertexts,
                                                              const std::vector<VectorDataType>& coefficients,
                                                              uint32_t digit_bit_size, size_t order) {
    const auto crypto_params =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertexts->powers_re[0]->get_crypto_parameters());
    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
    validate_fbt_scaling_technique(crypto_params);

    auto cc = ciphertexts->powers_re[0]->get_crypto_context();
    uint32_t M4 = cc->get_cyclotomic_order() / 4;
    uint32_t slots = ciphertexts->powers_re[0]->get_slots();
    auto algo = cc->get_scheme();

    Ciphertext<RnsPoly> ctxt_enc;

    if (slots == M4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------
        if (ciphertexts->powers_im.size() == 0)
            CIPHER_THROW("Full packing requires powers for both the real and imaginary parts.");
        Ciphertext<RnsPoly> ctxt_enc_i;

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex explonential
        //------------------------------------------------------------------------------

        if (digit_bit_size == 1 && order == 1) {
            ctxt_enc = ciphertexts->powers_re[0]->clone();
            ctxt_enc_i = ciphertexts->powers_im[0]->clone();
            // Assumes the function is integer and real!
            if (to_real(coefficients[1]) > 0) {  // mult_by_integer only works with positive integers
                algo->mult_by_integer_in_place(ctxt_enc, to_real(coefficients[1]));
                cc->eval_add_in_place(ctxt_enc, to_real(coefficients[0]));
                algo->mult_by_integer_in_place(ctxt_enc_i, to_real(coefficients[1]));
                cc->eval_add_in_place(ctxt_enc_i, to_real(coefficients[0]));
            } else {
                algo->mult_by_integer_in_place(ctxt_enc, -to_real(coefficients[1]));
                ctxt_enc = cc->eval_sub(to_real(coefficients[0]), ctxt_enc);
                algo->mult_by_integer_in_place(ctxt_enc_i, -to_real(coefficients[1]));
                ctxt_enc_i = cc->eval_sub(to_real(coefficients[0]), ctxt_enc_i);
            }
        } else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            // The repackaging below shares the precomputed ciphertexts with the caller. eval_poly_with_precomp
            // leaves them unmodified, so the same precomputation serves every function evaluated against it.
            std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers_re, ctxt_powers_im;
            if (ciphertexts->powers2_re.size() == 0) {
                ctxt_powers_re = std::make_shared<SeriesPowers<RnsPoly>>(ciphertexts->powers_re);
                ctxt_powers_im = std::make_shared<SeriesPowers<RnsPoly>>(ciphertexts->powers_im);
            } else {
                ctxt_powers_re = std::make_shared<SeriesPowers<RnsPoly>>(
                        ciphertexts->powers_re, ciphertexts->powers2_re, ciphertexts->power2km1_re, ciphertexts->k,
                        ciphertexts->m);
                ctxt_powers_im = std::make_shared<SeriesPowers<RnsPoly>>(
                        ciphertexts->powers_im, ciphertexts->powers2_im, ciphertexts->power2km1_im, ciphertexts->k,
                        ciphertexts->m);
            }

            // Take the real part
            // Division by 2 was already performed
            ctxt_enc = cc->eval_poly_with_precomp(ctxt_powers_re, coefficients);
            cc->eval_add_in_place(ctxt_enc,
                                  Conjugate(ctxt_enc, cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag())));
            ctxt_enc_i = cc->eval_poly_with_precomp(ctxt_powers_im, coefficients);
            cc->eval_add_in_place(ctxt_enc_i,
                                  Conjugate(ctxt_enc_i, cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag())));
        }

        algo->mult_by_monomial_in_place(ctxt_enc_i, M4);
        cc->eval_add_in_place(ctxt_enc, ctxt_enc_i);
        // No need to scale the message back up after Chebyshev interpolation
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex exponential
        //------------------------------------------------------------------------------

        if (digit_bit_size == 1 && order == 1) {
            ctxt_enc = ciphertexts->powers_re[0]->clone();
            // Assumes the function is integer and real!
            if (to_real(coefficients[1]) > 0) {  // mult_by_integer only works with positive integers
                algo->mult_by_integer_in_place(ctxt_enc, to_real(coefficients[1]));
                cc->eval_add_in_place(ctxt_enc, to_real(coefficients[0]));
            } else {
                algo->mult_by_integer_in_place(ctxt_enc, -to_real(coefficients[1]));
                ctxt_enc = cc->eval_sub(to_real(coefficients[0]), ctxt_enc);
            }
        } else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            std::shared_ptr<SeriesPowers<RnsPoly>> ctxt_powers_re;
            if (ciphertexts->powers2_re.size() == 0) {
                ctxt_powers_re = std::make_shared<SeriesPowers<RnsPoly>>(ciphertexts->powers_re);
            } else {
                ctxt_powers_re = std::make_shared<SeriesPowers<RnsPoly>>(
                        ciphertexts->powers_re, ciphertexts->powers2_re, ciphertexts->power2km1_re, ciphertexts->k,
                        ciphertexts->m);
            }
            ctxt_enc = cc->eval_poly_with_precomp(ctxt_powers_re, coefficients);

            // Take the real part
            // Division by 2 was already performed
            cc->eval_add_in_place_no_check(
                    ctxt_enc, Conjugate(ctxt_enc, cc->get_eval_automorphism_key_map(ctxt_enc->get_key_tag())));
        }

        // No need to scale the message back up after Chebyshev interpolation
    }

    // // 64-bit only: No need to scale back the message to its original scale.
    return ctxt_enc;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_fbt(ConstCiphertext<RnsPoly>& ciphertext,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digit_bit_size,
                                         const BigInteger& initial_scaling, uint64_t post_scaling,
                                         uint32_t level_to_reduce, size_t order) {
    return eval_hom_decoding(
            eval_mvb_no_decoding_internal(
                    eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order),
                    coefficients, digit_bit_size, order),
            post_scaling, level_to_reduce);
}
Ciphertext<RnsPoly> CkksRnsFhe::eval_fbt(ConstCiphertext<RnsPoly>& ciphertext, const std::vector<int64_t>& coefficients,
                                         uint32_t digit_bit_size, const BigInteger& initial_scaling,
                                         uint64_t post_scaling, uint32_t level_to_reduce, size_t order) {
    return eval_hom_decoding(
            eval_mvb_no_decoding_internal(
                    eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order),
                    coefficients, digit_bit_size, order),
            post_scaling, level_to_reduce);
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_fbt_no_decoding(ConstCiphertext<RnsPoly>& ciphertext,
                                                     const std::vector<std::complex<double>>& coefficients,
                                                     uint32_t digit_bit_size, const BigInteger& initial_scaling,
                                                     size_t order) {
    return eval_mvb_no_decoding_internal(
            eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order),
            coefficients, digit_bit_size, order);
}
Ciphertext<RnsPoly> CkksRnsFhe::eval_fbt_no_decoding(ConstCiphertext<RnsPoly>& ciphertext,
                                                     const std::vector<int64_t>& coefficients, uint32_t digit_bit_size,
                                                     const BigInteger& initial_scaling, size_t order) {
    return eval_mvb_no_decoding_internal(
            eval_mvb_precompute_internal(ciphertext, coefficients, digit_bit_size, initial_scaling, order),
            coefficients, digit_bit_size, order);
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_mvb(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digit_bit_size,
                                         uint64_t post_scaling, uint32_t level_to_reduce, size_t order) {
    return eval_hom_decoding(eval_mvb_no_decoding_internal(ciphertexts, coefficients, digit_bit_size, order),
                             post_scaling, level_to_reduce);
}
Ciphertext<RnsPoly> CkksRnsFhe::eval_mvb(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                         const std::vector<int64_t>& coefficients, uint32_t digit_bit_size,
                                         uint64_t post_scaling, uint32_t level_to_reduce, size_t order) {
    return eval_hom_decoding(eval_mvb_no_decoding_internal(ciphertexts, coefficients, digit_bit_size, order),
                             post_scaling, level_to_reduce);
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                                     const std::vector<std::complex<double>>& coefficients,
                                                     uint32_t digit_bit_size, size_t order) {
    return eval_mvb_no_decoding_internal(ciphertexts, coefficients, digit_bit_size, order);
}
Ciphertext<RnsPoly> CkksRnsFhe::eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                                     const std::vector<int64_t>& coefficients, uint32_t digit_bit_size,
                                                     size_t order) {
    return eval_mvb_no_decoding_internal(ciphertexts, coefficients, digit_bit_size, order);
}

template <typename VectorDataType>
Ciphertext<RnsPoly> CkksRnsFhe::eval_hermite_trig_series_internal(
        ConstCiphertext<RnsPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients_cheb, double a,
        double b, const std::vector<VectorDataType>& coefficients_herm, size_t precomp) {
    auto cc = ciphertext->get_crypto_context();
    auto& p = get_boot_precom(ciphertext->get_slots());

    auto& ctxt_exp = (precomp == 0 || precomp == 2) ? p.precomp_exp_ : p.precomp_exp_i_;
    if (precomp == 0 || precomp == 1) {
        // Obtain exp(Pi/2*i*x) approximation via Chebyshev Basis Polynomial Interpolation
        ctxt_exp = cc->eval_chebyshev_series(ciphertext, coefficients_cheb, a, b);

        // Double angle-iterations to get exp(2*Pi*i*x)
        cc->eval_square_in_place(ctxt_exp);
        cc->mod_reduce_in_place(ctxt_exp);
        cc->eval_square_in_place(ctxt_exp);
        cc->mod_reduce_in_place(ctxt_exp);
    }

    // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
    // Coefficients are divided by 2
    auto result = cc->eval_poly(ctxt_exp, coefficients_herm);
    // Take the real part
    // Division by 2 was already performed
    cc->eval_add_in_place_no_check(result, Conjugate(result, cc->get_eval_automorphism_key_map(result->get_key_tag())));

    return result;
}

Ciphertext<RnsPoly> CkksRnsFhe::eval_hermite_trig_series(ConstCiphertext<RnsPoly>& ciphertext,
                                                         const std::vector<std::complex<double>>& coefficients_cheb,
                                                         double a, double b,
                                                         const std::vector<std::complex<double>>& coefficients_herm,
                                                         size_t precomp) {
    return eval_hermite_trig_series_internal(ciphertext, coefficients_cheb, a, b, coefficients_herm, precomp);
}
Ciphertext<RnsPoly> CkksRnsFhe::eval_hermite_trig_series(ConstCiphertext<RnsPoly>& ciphertext,
                                                         const std::vector<std::complex<double>>& coefficients_cheb,
                                                         double a, double b,
                                                         const std::vector<int64_t>& coefficients_herm,
                                                         size_t precomp) {
    return eval_hermite_trig_series_internal(ciphertext, coefficients_cheb, a, b, coefficients_herm, precomp);
}

template <typename VectorDataType>
uint32_t CkksRnsFhe::adjust_depth_fbt_internal(const std::vector<VectorDataType>& coefficients,
                                               const BigInteger& p_input, size_t order, SecretKeyDist skd,
                                               uint32_t sparse_ks_hamming_weight_value) {
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus above 60 bits) uses the
    // K = 28 approximations of SPARSE_TERNARY
    if (uses_large_sparse_key(skd, sparse_ks_hamming_weight_value))
        skd = SPARSE_TERNARY;
    auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                      (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                     coeff_cos_28_double_68;
    auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                      (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                     coeff_exp_28_double_69;
    uint32_t depth = 0;
    switch (p_input.convert_to_int()) {
        case 2:
            if (order > 1) {
                depth += 3;
            }
            depth += get_multiplicative_depth_by_coeff_vector(coeff_cos, false);
            break;
        case 4:
            if (order == 1) {
                depth += 3;
            } else {
                depth += get_multiplicative_depth_by_coeff_vector(coefficients, true);
            }
            depth += get_multiplicative_depth_by_coeff_vector(coeff_exp, false);
            break;
        default:
            depth += get_multiplicative_depth_by_coeff_vector(coefficients, true);
            depth += get_multiplicative_depth_by_coeff_vector(coeff_exp, false);
            break;
    }
    // the number of double-angle iterations: 2 for the sparse distributions and 6 for UNIFORM_TERNARY
    depth += (skd == UNIFORM_TERNARY) ? R_UNIFORM_FBT : R_SPARSE_FBT;
    return depth;
}

template uint32_t CkksRnsFhe::adjust_depth_fbt_internal(const std::vector<int64_t>& coefficients,
                                                        const BigInteger& p_input, size_t order, SecretKeyDist skd,
                                                        uint32_t sparse_ks_hamming_weight_value);
template uint32_t CkksRnsFhe::adjust_depth_fbt_internal(const std::vector<std::complex<double>>& coefficients,
                                                        const BigInteger& p_input, size_t order, SecretKeyDist skd,
                                                        uint32_t sparse_ks_hamming_weight_value);

template <typename VectorDataType>
uint32_t CkksRnsFhe::adjust_depth_fbt(const std::vector<VectorDataType>& coefficients, const BigInteger& p_input,
                                      size_t order, SecretKeyDist skd, uint32_t first_mod_size_value) {
    return adjust_depth_fbt_internal(coefficients, p_input, order, skd,
                                     CkksRnsCryptoParams::sparse_ks_hamming_weight(first_mod_size_value));
}

template uint32_t CkksRnsFhe::adjust_depth_fbt(const std::vector<int64_t>& coefficients, const BigInteger& p_input,
                                               size_t order, SecretKeyDist skd, uint32_t first_mod_size_value);
template uint32_t CkksRnsFhe::adjust_depth_fbt(const std::vector<std::complex<double>>& coefficients,
                                               const BigInteger& p_input, size_t order, SecretKeyDist skd,
                                               uint32_t first_mod_size_value);

template <typename VectorDataType>
uint32_t CkksRnsFhe::get_fbt_depth(const std::vector<uint32_t>& level_budget,
                                   const std::vector<VectorDataType>& coefficients, const BigInteger& p_input,
                                   size_t order, SecretKeyDist skd, uint32_t first_mod_size_value) {
    return level_budget[0] + level_budget[1] +
           adjust_depth_fbt(coefficients, p_input, order, skd, first_mod_size_value);
}

template uint32_t CkksRnsFhe::get_fbt_depth(const std::vector<uint32_t>& level_budget,
                                            const std::vector<int64_t>& coefficients, const BigInteger& p_input,
                                            size_t order, SecretKeyDist skd, uint32_t first_mod_size_value);
template uint32_t CkksRnsFhe::get_fbt_depth(const std::vector<uint32_t>& level_budget,
                                            const std::vector<std::complex<double>>& coefficients,
                                            const BigInteger& p_input, size_t order, SecretKeyDist skd,
                                            uint32_t first_mod_size_value);

void CkksRnsFhe::mod_raise_in_place(Ciphertext<RnsPoly>& raised,
                                    const std::shared_ptr<RnsPoly::Params>& element_params_raised_ptr) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(raised->get_crypto_parameters());
    auto cc = raised->get_crypto_context();
    const uint32_t N = cc->get_ring_dimension();
    const uint32_t L0 = crypto_params->get_element_params()->get_params().size();
    const bool is_encapsulated = (crypto_params->get_secret_key_dist() == SPARSE_ENCAPSULATED);

    auto* eval_key_map = is_encapsulated ? &cc->get_eval_automorphism_key_map(raised->get_key_tag()) : nullptr;
    if (is_encapsulated) {
        // transform from a denser secret to a sparser one (over the bottom basis)
        raised = key_switch_sparse(raised, eval_key_map->at(2 * N - 4));
    }

    auto& ctxt_dcrt_s = raised->get_elements();
    if (crypto_params->get_composite_degree() > 1) {
        // exact RNS basis extension from the composite_degree bottom RNS limbs to the raised RNS basis
        extend_ciphertext(ctxt_dcrt_s, *cc, element_params_raised_ptr);
    } else {
        // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
        for (auto& dcrt : ctxt_dcrt_s) {
            dcrt.set_format(COEFFICIENT);
            RnsPoly tmp(dcrt.get_element_at_index(0), element_params_raised_ptr);
            tmp.set_format(EVALUATION);
            dcrt = std::move(tmp);
        }
    }
    raised->set_level(L0 - ctxt_dcrt_s[0].get_num_of_elements());

    if (is_encapsulated) {
        // go back to a denser secret (key_switch_sparse preserves the key tag, so the map above still applies)
        cc->get_scheme()->key_switch_in_place(raised, eval_key_map->at(2 * N - 2));
    }
}

namespace {
// Extends a polynomial given over (at least) the bottom basis Ql = {q_0, ..., q_{d-1}} of sparse encapsulation
// to the auxiliary basis P'. For a single limb the centered lift (switch_modulus) is the exact CRT basis
// extension; for several limbs the exact (HPS-style) CRT basis switch is used. Returns the P' limbs in
// EVALUATION format.
RnsPoly extend_sparse_ks_to_p(const RnsPoly& x_bottom, const std::shared_ptr<CkksRnsCryptoParams>& crypto_params) {
    const auto& params_p = crypto_params->get_sparse_ks_params_p();
    const auto& params_ql = crypto_params->get_sparse_ks_params_q();
    const size_t size_ql = params_ql->get_params().size();
    const size_t size_p = params_p->get_params().size();

    RnsPoly x_ql(x_bottom);
    x_ql.set_format(Format::COEFFICIENT, RnsPoly::THREADS_CRT_BASIS_SWITCH);

    RnsPoly x_p;
    if (size_ql == 1) {
        x_p = RnsPoly(params_p, Format::COEFFICIENT, false);
        auto poly = x_ql.get_element_at_index(0);
        for (size_t j = 0; j < size_p; ++j) {
            auto poly_p = poly;
            poly_p.switch_modulus(params_p->get_params()[j]->get_modulus(),
                                  params_p->get_params()[j]->get_root_of_unity(), 0, 0);
            x_p.set_element_at_index(j, std::move(poly_p));
        }
    } else {
        // [(Ql/q_i)^{-1}]_{q_i} and 1/q_i are shared with the composite scaling modulus raise
        const auto& ql_hat_inv_modq = crypto_params->get_mod_raise_ql_hat_inv_modq();
        if (ql_hat_inv_modq.size() != size_ql)
            CIPHER_THROW("The modulus-raise tables needed for the sparse key switching are not available.");
        x_p = x_ql.switch_crt_basis(
                params_p, ql_hat_inv_modq, crypto_params->get_mod_raise_ql_hat_inv_modq_precon(),
                crypto_params->get_sparse_ks_ql_hat_modp(), crypto_params->get_sparse_ks_alpha_ql_modp(),
                crypto_params->get_sparse_ks_modp_barrett_mu(), crypto_params->get_mod_raiseq_inv());
    }
    x_p.set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);
    return x_p;
}

// Builds the element over Ql*P' whose Ql limbs are the bottom limbs of x and whose P' limbs are the
// exact extension of x to P' (all in EVALUATION format).
RnsPoly extend_sparse_ks_to_qp(const RnsPoly& x, const std::shared_ptr<CkksRnsCryptoParams>& crypto_params) {
    const auto& paramsqp = crypto_params->get_sparse_ks_params_qp();
    const size_t size_ql = crypto_params->get_sparse_ks_params_q()->get_params().size();
    const size_t size_qp = paramsqp->get_params().size();

    RnsPoly x_ql = x.clone_towers(0, static_cast<uint32_t>(size_ql) - 1);
    RnsPoly x_p = extend_sparse_ks_to_p(x_ql, crypto_params);
    x_ql.set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);

    RnsPoly x_ext(paramsqp, Format::EVALUATION, false);
    auto& ext = x_ext.get_all_elements();
    for (size_t i = 0; i < size_ql; ++i)
        ext[i] = std::move(x_ql.get_all_elements()[i]);
    for (size_t j = size_ql; j < size_qp; ++j)
        ext[j] = std::move(x_p.get_all_elements()[j - size_ql]);
    return x_ext;
}
}  // namespace

template <typename VectorDataType>
uint32_t CkksRnsFhe::get_fefbt_depth(const std::vector<uint32_t>& level_budget,
                                     const std::vector<VectorDataType>& coefficients, SecretKeyDist skd,
                                     uint32_t first_mod_size_value) {
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus
    // above 60 bits) uses the K = 28 exponential table of SPARSE_TERNARY (see eval_fe_func_bootstrap_setup)
    const bool sparse_table =
            (skd == SPARSE_TERNARY) ||
            uses_large_sparse_key(skd, CkksRnsCryptoParams::sparse_ks_hamming_weight(first_mod_size_value));
    const auto& coeff_exp = (skd == UNIFORM_TERNARY) ? coeff_exp_696_double_27 :
                            sparse_table             ? coeff_exp_28_double_48 :
                                                       coeff_exp_16_double_23;
    const uint32_t exp_depth = get_multiplicative_depth_by_coeff_vector(coeff_exp, false);
    const uint32_t r_func = (skd == UNIFORM_TERNARY) ? r_func_696_double_27 :
                            sparse_table             ? r_func_28_double_48 :
                                                       r_func_16_double_23;
    return level_budget[0] + level_budget[1] + exp_depth + r_func +
           get_multiplicative_depth_by_coeff_vector(coefficients, true);
}

template uint32_t CkksRnsFhe::get_fefbt_depth(const std::vector<uint32_t>& level_budget,
                                              const std::vector<int64_t>& coefficients, SecretKeyDist skd,
                                              uint32_t first_mod_size_value);
template uint32_t CkksRnsFhe::get_fefbt_depth(const std::vector<uint32_t>& level_budget,
                                              const std::vector<std::complex<double>>& coefficients, SecretKeyDist skd,
                                              uint32_t first_mod_size_value);

EvalKey<RnsPoly> CkksRnsFhe::key_switch_gen_sparse(const PrivateKey<RnsPoly>& old_private_key,
                                                   const PrivateKey<RnsPoly>& new_private_key) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(new_private_key->get_crypto_parameters());

    // Params for Ql*P', where Ql is the bottom basis (composite_degree limbs) and P' is the auxiliary
    // modulus for sparse encapsulation (generated in CkksRnsCryptoParams::precompute_crt_tables)
    const auto& paramsqp = crypto_params->get_sparse_ks_params_qp();
    if (nullptr == paramsqp)
        CIPHER_THROW("The sparse key switching tables are only precomputed for SPARSE_ENCAPSULATED.");

    const size_t size_ql = crypto_params->get_sparse_ks_params_q()->get_params().size();
    const size_t size_qp = paramsqp->get_params().size();
    const auto& p_modq = crypto_params->get_sparse_ksp_modq();

    // creates the old and new keys in Ql*P'
    RnsPoly s_old_ext = extend_sparse_ks_to_qp(old_private_key->get_private_element(), crypto_params);
    RnsPoly s_new_ext = extend_sparse_ks_to_qp(new_private_key->get_private_element(), crypto_params);

    DugType dug;
    RnsPoly a(dug, paramsqp, Format::EVALUATION);
    RnsPoly e(crypto_params->get_discrete_gaussian_generator(), paramsqp, Format::EVALUATION);
    RnsPoly b(paramsqp, Format::EVALUATION, false);

    // computes the switching key for the GHS case: b = -a*s_new + P'*s_old + e over Ql*P';
    // as [P']_{p'_j} = 0, the P'*s_old term only contributes modulo the limbs of Ql
    for (size_t i = 0; i < size_ql; ++i)
        b.set_element_at_index(i, -a.get_element_at_index(i) * s_new_ext.get_element_at_index(i) +
                                          p_modq[i] * s_old_ext.get_element_at_index(i) + e.get_element_at_index(i));
    for (size_t j = size_ql; j < size_qp; ++j)
        b.set_element_at_index(
                j, -a.get_element_at_index(j) * s_new_ext.get_element_at_index(j) + e.get_element_at_index(j));

    auto ek(std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_private_key->get_crypto_context()));
    std::vector<RnsPoly> av_ext;
    av_ext.push_back(std::move(a));
    ek->set_a_vector(std::move(av_ext));
    std::vector<RnsPoly> bv_ext;
    bv_ext.push_back(std::move(b));
    ek->set_b_vector(std::move(bv_ext));
    ek->set_key_tag(new_private_key->get_key_tag());
    return ek;
}

Ciphertext<RnsPoly> CkksRnsFhe::key_switch_sparse(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly>& ek) {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    const auto& params_p = crypto_params->get_sparse_ks_params_p();
    const auto& params_ql = crypto_params->get_sparse_ks_params_q();
    if (nullptr == params_p)
        CIPHER_THROW("The sparse key switching tables are only precomputed for SPARSE_ENCAPSULATED.");

    const size_t size_p = params_p->get_params().size();
    const size_t size_ql = params_ql->get_params().size();

    auto& cv = ciphertext->get_elements();

    // only the bottom basis Ql of the ciphertext is used (the other towers are ignored, as in the modulus raise)
    RnsPoly c0_ql = cv[0].clone_towers(0, static_cast<uint32_t>(size_ql) - 1);
    c0_ql.set_format(Format::EVALUATION);

    // extend cv[1] from Ql to Ql*P'
    RnsPoly c1_ext = extend_sparse_ks_to_qp(cv[1], crypto_params);

    // multiply by the evaluation key
    std::vector<RnsPoly> cv_res{c1_ext * ek->get_b_vector()[0], c1_ext * ek->get_a_vector()[0]};

    // modswitch cv_res from Ql*P' to Ql, i.e., compute round(cv_res/P') mod Ql.
    // In RNS, we use the technique described in Appendix B.2.2 of https://eprint.iacr.org/2021/204
    // for the BFV case, i.e., for t=1. The balanced representative of [cv_res]_{P'} is computed
    // with the exact (HPS-style) CRT basis switch, which applies the floating-point overflow
    // correction instead of dropping the alpha*P' term, so the modulus switch only adds the
    // centered rounding noise.
    const auto& P_inv_modq = crypto_params->get_sparse_ksp_inv_modq();
    for (uint32_t i = 0; i < 2; ++i) {
        RnsPoly part_p(params_p, Format::COEFFICIENT, false);
        for (size_t j = 0; j < size_p; ++j) {
            auto poly_p = cv_res[i].get_element_at_index(size_ql + j);
            poly_p.set_format(Format::COEFFICIENT);
            part_p.set_element_at_index(j, std::move(poly_p));
        }
        // exact switch of the balanced [cv_res]_{P'} to the basis Ql
        auto part_p_modq = part_p.switch_crt_basis(
                params_ql, crypto_params->get_sparse_ksp_hat_inv_modp(),
                crypto_params->get_sparse_ksp_hat_inv_modp_precon(), crypto_params->get_sparse_ksp_hat_modq(),
                crypto_params->get_sparse_ks_alpha_p_modq(), crypto_params->get_sparse_ks_modq_barrett_mu(),
                crypto_params->get_sparse_ks_p_inv());
        part_p_modq.set_format(Format::EVALUATION, RnsPoly::THREADS_CRT_BASIS_SWITCH);

        cv_res[i].drop_last_elements(size_p);
        auto& res = cv_res[i].get_all_elements();
        const auto& part_q = part_p_modq.get_all_elements();
        for (size_t l = 0; l < size_ql; ++l) {
            res[l] -= part_q[l];
            res[l] *= P_inv_modq[l];
        }
    }

    // add to the original ciphertext
    cv_res[0] += c0_ql;

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(cv_res));
    return result;
}

}  // namespace cipher
