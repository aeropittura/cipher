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
 * Implements BV scheme from [Fully Homomorphic Encryption from
    Ring-LWE and Security for Key Dependent Messages (BVScheme)](
    https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf
    )
 *  see the Appendix of https://eprint.iacr.org/2021/204 for more details
 */

#include "cipher/fhe/keyswitch/bv.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/rns/crypto_params.h"

namespace cipher {

EvalKey<RnsPoly> KeySwitchBv::key_switch_gen_internal(const PrivateKey<RnsPoly> old_key,
                                                      const PrivateKey<RnsPoly> new_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(new_key->get_crypto_parameters());

    DugType dug;
    auto dgg = crypto_params->get_discrete_gaussian_generator();

    const auto ns = crypto_params->get_noise_scale();
    const auto& s_new = new_key->get_private_element();
    const auto& ep = s_new.get_params();
    const auto& s_old = old_key->get_private_element();
    const uint32_t size_s_old = s_old.get_num_of_elements();

    std::vector<RnsPoly> av, bv;
    if (auto digit_size = crypto_params->get_digit_size(); digit_size > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arr_windows(size_s_old);
        uint32_t n_windows = 0;
        for (uint32_t i = 0; i < size_s_old; ++i) {
            arr_windows[i] = n_windows;
            double s_old_msb = s_old.get_element_at_index(i).get_modulus().get_msb();
            n_windows += std::ceil(s_old_msb / digit_size);
        }

        av.resize(n_windows);
        bv.resize(n_windows);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(dug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            auto s_old_decomposed = s_old.get_element_at_index(i).powers_of_base(digit_size);
            for (uint32_t j = arr_windows[i], k = 0; k < s_old_decomposed.size(); ++j, ++k) {
                av[j] = RnsPoly(dug, ep, Format::EVALUATION);
                bv[j] = RnsPoly(ep, Format::EVALUATION, true);
                bv[j].set_element_at_index(i, std::move(s_old_decomposed[k]));
                bv[j] -= (av[j] * s_new + RnsPoly(dgg, ep, Format::EVALUATION) * ns);
            }
        }
    } else {
        av.resize(size_s_old);
        bv.resize(size_s_old);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(dug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            av[i] = RnsPoly(dug, ep, Format::EVALUATION);
            bv[i] = RnsPoly(ep, Format::EVALUATION, true);
            bv[i].set_element_at_index(i, s_old.get_element_at_index(i));
            bv[i] -= (av[i] * s_new + RnsPoly(dgg, ep, Format::EVALUATION) * ns);
        }
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_key->get_crypto_context());
    ek->set_a_vector(std::move(av));
    ek->set_b_vector(std::move(bv));
    ek->set_key_tag(new_key->get_key_tag());
    return ek;
}

EvalKey<RnsPoly> KeySwitchBv::key_switch_gen_internal(const PrivateKey<RnsPoly> old_key,
                                                      const PrivateKey<RnsPoly> new_key,
                                                      const EvalKey<RnsPoly> ek) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(old_key->get_crypto_parameters());

    DugType dug;
    auto dgg = crypto_params->get_discrete_gaussian_generator();

    const auto ns = crypto_params->get_noise_scale();
    const auto& s_new = new_key->get_private_element();
    const auto& ep = s_new.get_params();
    const auto& s_old = old_key->get_private_element();
    const uint32_t size_s_old = s_old.get_num_of_elements();

    std::vector<RnsPoly> av, bv;
    if (auto digit_size = crypto_params->get_digit_size(); digit_size > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arr_windows(size_s_old);
        uint32_t n_windows = 0;
        for (uint32_t i = 0; i < size_s_old; ++i) {
            arr_windows[i] = n_windows;
            double s_old_msb = s_old.get_element_at_index(i).get_modulus().get_msb();
            n_windows += std::ceil(s_old_msb / digit_size);
        }

        av.resize(n_windows);
        bv.resize(n_windows);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(dug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            auto s_old_decomposed = s_old.get_element_at_index(i).powers_of_base(digit_size);
            for (uint32_t j = arr_windows[i], k = 0; k < s_old_decomposed.size(); ++j, ++k) {
                av[j] = ek ? ek->get_a_vector()[j] : RnsPoly(dug, ep, Format::EVALUATION);
                bv[j] = RnsPoly(ep, Format::EVALUATION, true);
                bv[j].set_element_at_index(i, std::move(s_old_decomposed[k]));
                bv[j] -= (av[j] * s_new + RnsPoly(dgg, ep, Format::EVALUATION) * ns);
            }
        }
    } else {
        av.resize(size_s_old);
        bv.resize(size_s_old);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(dug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            av[i] = ek ? ek->get_a_vector()[i] : RnsPoly(dug, ep, Format::EVALUATION);
            bv[i] = RnsPoly(ep, Format::EVALUATION, true);
            bv[i].set_element_at_index(i, s_old.get_element_at_index(i));
            bv[i] -= (av[i] * s_new + RnsPoly(dgg, ep, Format::EVALUATION) * ns);
        }
    }

    auto eval_key = std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_key->get_crypto_context());
    eval_key->set_a_vector(std::move(av));
    eval_key->set_b_vector(std::move(bv));
    eval_key->set_key_tag(new_key->get_key_tag());
    return eval_key;
}

EvalKey<RnsPoly> KeySwitchBv::key_switch_gen_internal(const PrivateKey<RnsPoly> old_sk,
                                                      const PublicKey<RnsPoly> new_pk) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(new_pk->get_crypto_parameters());

    TugType tug;
    auto dgg = crypto_params->get_discrete_gaussian_generator();

    const auto ns = crypto_params->get_noise_scale();
    const auto& newp0 = new_pk->get_public_elements().at(0);
    const auto& newp1 = new_pk->get_public_elements().at(1);
    const auto& ep = newp0.get_params();
    const auto& s_old = old_sk->get_private_element();
    const uint32_t size_s_old = s_old.get_num_of_elements();

    std::vector<RnsPoly> av, bv;
    if (uint32_t digit_size = crypto_params->get_digit_size(); digit_size > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arr_windows(size_s_old);
        uint32_t n_windows = 0;
        for (uint32_t i = 0; i < size_s_old; ++i) {
            arr_windows[i] = n_windows;
            double s_old_msb = s_old.get_element_at_index(i).get_modulus().get_msb();
            n_windows += std::ceil(s_old_msb / digit_size);
        }

        av.resize(n_windows);
        bv.resize(n_windows);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(tug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            auto s_old_decomposed = s_old.get_element_at_index(i).powers_of_base(digit_size);
            for (uint32_t j = arr_windows[i], k = 0; k < s_old_decomposed.size(); ++j, ++k) {
                bv[j] = RnsPoly(ep, Format::EVALUATION, true);
                bv[j].set_element_at_index(i, std::move(s_old_decomposed[k]));
                bv[j] += RnsPoly(dgg, ep, Format::EVALUATION) * ns;
                RnsPoly u = (crypto_params->get_secret_key_dist() == GAUSSIAN) ? RnsPoly(dgg, ep, Format::EVALUATION) :
                                                                                 RnsPoly(tug, ep, Format::EVALUATION);
                bv[j] += newp0 * u;
                av[j] = newp1 * u;
                av[j] += RnsPoly(dgg, ep, Format::EVALUATION) * ns;
            }
        }
    } else {
        av.resize(size_s_old);
        bv.resize(size_s_old);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size_s_old)) private(tug, dgg)
        for (uint32_t i = 0; i < size_s_old; ++i) {
            bv[i] = RnsPoly(ep, Format::EVALUATION, true);
            bv[i].set_element_at_index(i, s_old.get_element_at_index(i));
            bv[i] += RnsPoly(dgg, ep, Format::EVALUATION) * ns;
            RnsPoly u = (crypto_params->get_secret_key_dist() == GAUSSIAN) ? RnsPoly(dgg, ep, Format::EVALUATION) :
                                                                             RnsPoly(tug, ep, Format::EVALUATION);
            bv[i] += newp0 * u;
            av[i] = newp1 * u;
            av[i] += RnsPoly(dgg, ep, Format::EVALUATION) * ns;
        }
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<RnsPoly>>(new_pk->get_crypto_context());
    ek->set_a_vector(std::move(av));
    ek->set_b_vector(std::move(bv));
    ek->set_key_tag(new_pk->get_key_tag());
    return ek;
}

void KeySwitchBv::key_switch_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> ek) const {
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

std::vector<RnsPoly> KeySwitchBv::key_switch_core(const RnsPoly& a, const EvalKey<RnsPoly> eval_key) const {
    return eval_fast_key_switch_core(eval_key_switch_precompute_core(a, eval_key->get_crypto_parameters()), eval_key,
                                     a.get_params());
}

std::shared_ptr<std::vector<RnsPoly>> KeySwitchBv::eval_key_switch_precompute_core(
        const RnsPoly& c, std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params_base) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(crypto_params_base);
    return std::make_shared<std::vector<RnsPoly>>(c.crt_decompose(crypto_params->get_digit_size()));
}

std::vector<RnsPoly> KeySwitchBv::eval_fast_key_switch_core(const std::shared_ptr<std::vector<RnsPoly>> digits,
                                                            const EvalKey<RnsPoly> eval_key,
                                                            const std::shared_ptr<ParmType> params_ql) const {
    const std::vector<RnsPoly>& bref = eval_key->get_b_vector();
    const std::vector<RnsPoly>& aref = eval_key->get_a_vector();
    const uint32_t size_ql = params_ql->get_params().size();
    const uint32_t limit = digits->size();
    if (limit == 0)
        CIPHER_THROW("no digits to key switch");
    if ((*digits)[0].get_num_of_elements() != size_ql)
        CIPHER_THROW("the digits and the ciphertext have different numbers of towers");

    const uint64_t work = static_cast<uint64_t>(params_ql->get_ring_dimension()) * size_ql * limit;
    const uint32_t team = std::min<uint32_t>(cipher_parallel_controls.get_thread_limit(size_ql * limit),
                                             std::max<uint32_t>(size_ql, static_cast<uint32_t>(work >> 15)));
    const uint32_t groups = std::max<uint32_t>(1, std::min<uint32_t>(limit, team / size_ql));
    const uint32_t tasks = size_ql * groups;

    std::vector<RnsPoly> res;
    res.reserve(2);
    res.emplace_back(params_ql, Format::EVALUATION, false);
    res.emplace_back(params_ql, Format::EVALUATION, false);
    std::vector<RnsPoly::PolyType> part0(groups > 1 ? tasks : 0);
    std::vector<RnsPoly::PolyType> part1(groups > 1 ? tasks : 0);

#pragma omp parallel num_threads(cipher_parallel_controls.get_thread_limit(tasks))
    {
#pragma omp for
        for (uint32_t t = 0; t < tasks; ++t) {
            const uint32_t i = t / groups;
            const uint32_t g = t % groups;
            const uint32_t j0 = g * limit / groups;
            const uint32_t j1 = (g + 1) * limit / groups;
            auto& p0 = (groups > 1) ? part0[t] : res[0].get_all_elements()[i];
            auto& p1 = (groups > 1) ? part1[t] : res[1].get_all_elements()[i];
            const auto& d0 = (*digits)[j0].get_element_at_index(i);
            p0 = d0.Times(bref[j0].get_element_at_index(i));
            p1 = d0.Times(aref[j0].get_element_at_index(i));
            for (uint32_t j = j0 + 1; j < j1; ++j) {
                const auto& dji = (*digits)[j].get_element_at_index(i);
                p0.mult_acc_eq_no_check(dji, bref[j].get_element_at_index(i));
                p1.mult_acc_eq_no_check(dji, aref[j].get_element_at_index(i));
            }
        }
        if (groups > 1) {
            const uint32_t chunks = std::max<uint32_t>(1, team / size_ql);
            const uint32_t n = params_ql->get_ring_dimension();
#pragma omp for
            for (uint32_t t = 0; t < size_ql * chunks; ++t) {
                const uint32_t i = t / chunks;
                const uint32_t k0 = (t % chunks) * n / chunks;
                const uint32_t k1 = (t % chunks + 1) * n / chunks;
                auto& r0 = part0[i * groups];
                auto& r1 = part1[i * groups];
                const auto& q = r0.get_modulus();
                for (uint32_t g = 1; g < groups; ++g) {
                    const auto& s0 = part0[i * groups + g];
                    const auto& s1 = part1[i * groups + g];
                    for (uint32_t k = k0; k < k1; ++k) {
                        r0[k].mod_add_fast_eq(s0[k], q);
                        r1[k].mod_add_fast_eq(s1[k], q);
                    }
                }
            }
        }
    }
    if (groups > 1) {
        for (uint32_t i = 0; i < size_ql; ++i) {
            res[0].get_all_elements()[i] = std::move(part0[i * groups]);
            res[1].get_all_elements()[i] = std::move(part1[i * groups]);
        }
    }
    return res;
}

}  // namespace cipher
