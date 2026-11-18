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

/**
 * Hybrid key switching implementation. See
 * Appendix of https://eprint.iacr.org/2021/204 for details.
 */

#include "cipher/fhe/keyswitch/hybrid.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/ckks/crypto_params.h"

namespace cipher {

EvalKey<RnsPoly> KeySwitchHybrid::key_switch_gen_internal(const PrivateKey<RnsPoly> old_key,
                                                          const PrivateKey<RnsPoly> new_key) const {
    return KeySwitchHybrid::key_switch_gen_internal(old_key, new_key, nullptr);
}

EvalKey<RnsPoly> KeySwitchHybrid::key_switch_gen_internal(const PrivateKey<RnsPoly> old_key,
                                                          const PrivateKey<RnsPoly> new_key,
                                                          const EvalKey<RnsPoly> ek_prev) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(new_key->get_crypto_parameters());
    const auto& params_q = crypto_params->get_element_params();
    const auto& params_qp = crypto_params->get_params_qp();
    const auto& pparams_qp = params_qp->get_params();

    // sk_new is currently in basis Q. This extends it to basis QP.

    RnsPoly s_new_ext(params_qp, Format::EVALUATION, false);
    const auto& s_new = new_key->get_private_element();

    auto s_new0 = s_new.get_element_at_index(0);
    s_new0.set_format(Format::COEFFICIENT);

    const uint32_t size_q = params_q->get_params().size();
    const uint32_t size_qp = params_qp->get_params().size();

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_qp))
    for (uint32_t i = 0; i < size_qp; ++i) {
        if (i < size_q) {
            auto tmp = s_new.get_element_at_index(i);
            tmp.set_format(Format::EVALUATION);
            s_new_ext.set_element_at_index(i, std::move(tmp));
        } else {
            NativePoly tmp(pparams_qp[i], Format::COEFFICIENT);
            tmp.set_values(NativeVector(s_new0.get_values(), pparams_qp[i]->get_modulus()), Format::COEFFICIENT);
            tmp.set_format(Format::EVALUATION);
            s_new_ext.set_element_at_index(i, std::move(tmp));
        }
    }

    const auto ns = crypto_params->get_noise_scale();

    const uint32_t num_per_part_q = crypto_params->get_num_per_part_q();
    const uint32_t num_part_q = crypto_params->get_num_part_q();
    std::vector<RnsPoly> av(num_part_q);
    std::vector<RnsPoly> bv(num_part_q);

    DugType dug;
    auto dgg = crypto_params->get_discrete_gaussian_generator();

    const auto& s_old = old_key->get_private_element();
    const auto& p_modq = crypto_params->get_p_modq();

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_part_q)) private(dug, dgg)
    for (uint32_t part = 0; part < num_part_q; ++part) {
        auto a = (ek_prev == nullptr) ? RnsPoly(dug, params_qp, Format::EVALUATION) :  // single-key HE
                                        ek_prev->get_a_vector()[part];                 // threshold HE
        RnsPoly e(dgg, params_qp, Format::EVALUATION);
        RnsPoly b(params_qp, Format::EVALUATION, false);

        const uint32_t start_part_idx = num_per_part_q * part;
        const uint32_t end_part_idx =
                (size_q > (start_part_idx + num_per_part_q)) ? (start_part_idx + num_per_part_q) : size_q;

        for (uint32_t i = 0; i < size_qp; ++i) {
            const auto& ai = a.get_element_at_index(i);
            const auto& ei = e.get_element_at_index(i);
            const auto& sni = s_new_ext.get_element_at_index(i);

            if (i < start_part_idx || i >= end_part_idx) {
                b.set_element_at_index(i, (-ai * sni) + (ns * ei));
            } else {
                const auto& soi = s_old.get_element_at_index(i);
                b.set_element_at_index(i, (-ai * sni) + (ns * ei) + (p_modq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    EvalKeyRelin<RnsPoly> ek(std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_key->get_crypto_context()));
    ek->set_a_vector(std::move(av));
    ek->set_b_vector(std::move(bv));
    ek->set_key_tag(new_key->get_key_tag());
    return ek;
}

EvalKey<RnsPoly> KeySwitchHybrid::key_switch_gen_internal(const PrivateKey<RnsPoly> old_key,
                                                          const PublicKey<RnsPoly> new_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(new_key->get_crypto_parameters());
    const auto& params_q = crypto_params->get_element_params();
    const auto& params_qp = crypto_params->get_params_qp();

    const uint32_t size_q = params_q->get_params().size();
    const uint32_t size_qp = params_qp->get_params().size();

    const auto ns = crypto_params->get_noise_scale();

    const uint32_t num_per_part_q = crypto_params->get_num_per_part_q();
    const uint32_t num_part_q = crypto_params->get_num_part_q();
    std::vector<RnsPoly> av(num_part_q);
    std::vector<RnsPoly> bv(num_part_q);

    TugType tug;
    auto dgg = crypto_params->get_discrete_gaussian_generator();

    const auto& s_old = old_key->get_private_element();
    const auto& newp0 = new_key->get_public_elements().at(0);
    const auto& newp1 = new_key->get_public_elements().at(1);
    const auto& p_modq = crypto_params->get_p_modq();

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_part_q)) private(dgg, tug)
    for (uint32_t part = 0; part < num_part_q; ++part) {
        auto u = (crypto_params->get_secret_key_dist() == GAUSSIAN) ? RnsPoly(dgg, params_qp, Format::EVALUATION) :
                                                                      RnsPoly(tug, params_qp, Format::EVALUATION);
        RnsPoly e0(dgg, params_qp, Format::EVALUATION);
        RnsPoly e1(dgg, params_qp, Format::EVALUATION);
        RnsPoly a(params_qp, Format::EVALUATION, false);
        RnsPoly b(params_qp, Format::EVALUATION, false);

        // starting and ending position of current part
        const uint32_t start_part_idx = num_per_part_q * part;
        const uint32_t end_part_idx =
                (size_q > start_part_idx + num_per_part_q) ? (start_part_idx + num_per_part_q) : size_q;

        for (uint32_t i = 0; i < size_qp; ++i) {
            const auto& ui = u.get_element_at_index(i);

            const auto& e0i = e0.get_element_at_index(i);
            const auto& e1i = e1.get_element_at_index(i);

            const auto& newp0i = newp0.get_element_at_index(i);
            const auto& newp1i = newp1.get_element_at_index(i);

            a.set_element_at_index(i, newp1i * ui + ns * e1i);

            if (i < start_part_idx || i >= end_part_idx) {
                b.set_element_at_index(i, (newp0i * ui) + (ns * e0i));
            } else {
                const auto& soi = s_old.get_element_at_index(i);
                b.set_element_at_index(i, (newp0i * ui) + (ns * e0i) + (p_modq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    EvalKeyRelin<RnsPoly> ek = std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_key->get_crypto_context());
    ek->set_a_vector(std::move(av));
    ek->set_b_vector(std::move(bv));
    ek->set_key_tag(new_key->get_key_tag());
    return ek;
}

void KeySwitchHybrid::key_switch_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> ek) const {
    auto& cv = ciphertext->get_elements();
    auto ba = key_switch_core(cv.back(), ek);
    cv[0].set_format(Format::EVALUATION);
    cv[0] += ba[0];
    if (cv.size() > 2) {
        cv[1].set_format(Format::EVALUATION);
        cv[1] += ba[1];
    } else {
        cv[1] = ba[1];
    }
    cv.resize(2);
}

Ciphertext<RnsPoly> KeySwitchHybrid::key_switch_ext(ConstCiphertext<RnsPoly> ciphertext, bool add_first) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    const auto& cv = ciphertext->get_elements();
    const auto& p_modq = crypto_params->get_p_modq();

    const auto params_p = crypto_params->get_params_p();
    const auto params_ql = cv[0].get_params();
    const auto params_ql_p = cv[0].get_extended_crt_basis(params_p);

    const uint32_t size_cv = cv.size();
    const uint32_t size_ql = params_ql->get_params().size();
    std::vector<RnsPoly> elements(size_cv);

    for (uint32_t k = 0; k < size_cv; ++k) {
        elements[k] = RnsPoly(params_ql_p, Format::EVALUATION, true);
        if ((add_first) || (k > 0)) {
            auto c_mult = cv[k].times_no_check(p_modq);
            for (uint32_t i = 0; i < size_ql; ++i) {
                elements[k].set_element_at_index(i, std::move(c_mult.get_element_at_index(i)));
            }
        }
    }

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(elements));
    return result;
}

Ciphertext<RnsPoly> KeySwitchHybrid::key_switch_down(ConstCiphertext<RnsPoly> ciphertext) const {
    const auto& cv = ciphertext->get_elements();
    const auto params_ql_p = cv[0].get_params();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    const auto params_p = crypto_params->get_params_p();

    const uint32_t size_ql = params_ql_p->get_params().size() - params_p->get_params().size();
    const auto params_ql = crypto_params->get_params_ql_hybrid(size_ql);

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    std::vector<RnsPoly> elements;
    elements.reserve(2);
    elements.emplace_back(
            cv[0].approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                                  crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                  crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                  crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                  crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon()));
    elements.emplace_back(
            cv[1].approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                                  crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                  crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                  crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                  crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon()));

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(elements));
    return result;
}

RnsPoly KeySwitchHybrid::key_switch_down_first_element(ConstCiphertext<RnsPoly> ciphertext) const {
    const auto& cv = ciphertext->get_elements()[0];
    const auto params_ql_p = cv.get_params();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    const auto params_p = crypto_params->get_params_p();

    const uint32_t size_ql = params_ql_p->get_params().size() - params_p->get_params().size();
    const auto params_ql = crypto_params->get_params_ql_hybrid(size_ql);

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    return cv.approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                              crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                              crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                              crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                              crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
}

std::vector<RnsPoly> KeySwitchHybrid::key_switch_core(const RnsPoly& a, const EvalKey<RnsPoly> eval_key) const {
    return eval_fast_key_switch_core(eval_key_switch_precompute_core(a, eval_key->get_crypto_parameters()), eval_key,
                                     a.get_params());
}

std::shared_ptr<std::vector<RnsPoly>> KeySwitchHybrid::eval_key_switch_precompute_core(
        const RnsPoly& c, std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params_base) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(crypto_params_base);

    const auto params_ql = c.get_params();
    const auto params_p = crypto_params->get_params_p();
    const auto params_ql_p = c.get_extended_crt_basis(params_p);

    const uint32_t size_ql = params_ql->get_params().size();
    const uint32_t size_p = params_p->get_params().size();
    const uint32_t size_ql_p = size_ql + size_p;
    const uint32_t ring_dim = params_ql->get_ring_dimension();
    const uint32_t alpha = crypto_params->get_num_per_part_q();
    // The number of digits of the current ciphertext
    uint32_t num_part_ql = std::ceil(static_cast<double>(size_ql) / alpha);
    if (num_part_ql > crypto_params->get_number_of_q_partitions())
        num_part_ql = crypto_params->get_number_of_q_partitions();

    auto result = std::make_shared<std::vector<RnsPoly>>(num_part_ql);

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < num_part_ql; ++part) {
        RnsPoly parts_ct;
        if (part == num_part_ql - 1) {
            const auto& params_part_q = crypto_params->get_params_part_q(part);

            uint32_t size_part_ql = size_ql - alpha * part;
            std::vector<NativeInteger> moduli(size_part_ql);
            std::vector<NativeInteger> roots(size_part_ql);
            for (uint32_t i = 0; i < size_part_ql; ++i) {
                moduli[i] = params_part_q->get_params()[i]->get_modulus();
                roots[i] = params_part_q->get_params()[i]->get_root_of_unity();
            }
            auto&& params = std::make_shared<ParmType>(params_part_q->get_cyclotomic_order(), moduli, roots);
            parts_ct = RnsPoly(params, Format::EVALUATION, false);
        } else {
            parts_ct = RnsPoly(crypto_params->get_params_part_q(part), Format::EVALUATION, false);
        }

        const uint32_t size_part_ql = parts_ct.get_num_of_elements();
        const uint32_t start_part_idx = alpha * part;
        for (uint32_t i = 0, idx = start_part_idx; i < size_part_ql; ++i, ++idx)
            parts_ct.set_element_at_index(i, c.get_element_at_index(idx));

        const uint32_t threads =
                RnsPoly::approx_switch_crt_basis_threads(ring_dim, size_part_ql, size_ql_p - size_part_ql);
        parts_ct.set_format(Format::COEFFICIENT, threads);
        auto parts_ct_compl = parts_ct.approx_switch_crt_basis(
                crypto_params->get_params_part_q(part), crypto_params->get_params_compl_part_q(size_ql - 1, part),
                crypto_params->get_part_ql_hat_inv_modq(part, size_part_ql - 1),
                crypto_params->get_part_ql_hat_inv_modq_precon(part, size_part_ql - 1),
                crypto_params->get_part_ql_hat_modp(size_ql - 1, part),
                crypto_params->get_mod_compl_partq_barrett_mu(size_ql - 1, part));
        parts_ct_compl.set_format(Format::EVALUATION, threads);

        (*result)[part] = RnsPoly(params_ql_p, Format::EVALUATION, false);

        const uint32_t end_part_idx = start_part_idx + size_part_ql;
        for (uint32_t i = 0; i < start_part_idx; ++i)
            (*result)[part].set_element_at_index(i, std::move(parts_ct_compl.get_element_at_index(i)));
        for (uint32_t i = start_part_idx; i < end_part_idx; ++i)
            (*result)[part].set_element_at_index(i, c.get_element_at_index(i));
        for (uint32_t i = end_part_idx; i < size_ql_p; ++i)
            (*result)[part].set_element_at_index(i, std::move(parts_ct_compl.get_element_at_index(i - size_part_ql)));
    }
    return result;
}

std::vector<RnsPoly> KeySwitchHybrid::eval_fast_key_switch_core(const std::shared_ptr<std::vector<RnsPoly>> digits,
                                                                const EvalKey<RnsPoly> eval_key,
                                                                const std::shared_ptr<ParmType> params_ql) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(eval_key->get_crypto_parameters());

    const PlaintextModulus t = (crypto_params->get_noise_scale() == 1) ? 0 : crypto_params->get_plaintext_modulus();

    auto result = eval_fast_key_switch_core_ext(digits, eval_key, params_ql);
    result[0] =
            result[0].approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                                      crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                      crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                      crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                      crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
    result[1] =
            result[1].approx_mod_down(params_ql, crypto_params->get_params_p(), crypto_params->get_p_inv_modq(),
                                      crypto_params->get_p_inv_modq_precon(), crypto_params->get_p_hat_inv_modp(),
                                      crypto_params->get_p_hat_inv_modp_precon(), crypto_params->get_p_hat_modq(),
                                      crypto_params->get_modq_barrett_mu(), crypto_params->get_t_inv_modp(),
                                      crypto_params->get_t_inv_modp_precon(), t, crypto_params->get_t_modq_precon());
    return result;
}

std::vector<RnsPoly> KeySwitchHybrid::eval_fast_key_switch_core_ext(const std::shared_ptr<std::vector<RnsPoly>> digits,
                                                                    const EvalKey<RnsPoly> eval_key,
                                                                    const std::shared_ptr<ParmType> params_ql) const {
    const auto params_ql_p = (*digits)[0].get_params();
    const uint32_t size_ql_p = params_ql_p->get_params().size();

    const uint32_t limit = digits->size();
    const uint32_t size_ql = params_ql->get_params().size();
    auto&& crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(eval_key->get_crypto_parameters());
    const uint32_t delta = crypto_params->get_element_params()->get_params().size() - size_ql;

    const auto& av = eval_key->get_a_vector();
    const auto& bv = eval_key->get_b_vector();

    std::vector<RnsPoly> result;
    result.reserve(2);
    result.emplace_back(params_ql_p, Format::EVALUATION, true);
    result.emplace_back(params_ql_p, Format::EVALUATION, true);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_ql_p))
    for (uint32_t i = 0; i < size_ql_p; ++i) {
        const auto idx = (i >= size_ql) ? i + delta : i;
        auto& r0 = result[0].get_all_elements()[i];
        auto& r1 = result[1].get_all_elements()[i];
        for (uint32_t j = 0; j < limit; ++j) {
            const auto& cji = (*digits)[j].get_element_at_index(i);
            r0.mult_acc_eq_no_check(cji, bv[j].get_element_at_index(idx));
            r1.mult_acc_eq_no_check(cji, av[j].get_element_at_index(idx));
        }
    }

    return result;
}

}  // namespace cipher
