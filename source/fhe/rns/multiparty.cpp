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
#include "cipher/fhe/rns/multiparty.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/rns/pke.h"

namespace cipher {

Ciphertext<RnsPoly> RnsMultiparty::multiparty_decrypt_lead(ConstCiphertext<RnsPoly> ciphertext,
                                                          const PrivateKey<RnsPoly> private_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(private_key->get_crypto_parameters());

    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    const auto ns = crypto_params->get_noise_scale();

    const RnsPoly& sk = private_key->get_private_element();
    size_t size_ql = cv[0].get_params()->get_params().size();
    auto s = sk.clone_towers(0, size_ql - 1);

    RnsPoly noise;
    if (crypto_params->get_multiparty_mode() == NOISE_FLOODING_MULTIPARTY) {
        if (size_ql < 3) {
            CIPHER_THROW("sizeQl " + std::to_string(size_ql) +
                          " must be at least 3 in NOISE_FLOODING_MULTIPARTY mode.");
        }
        DugType dug;
        auto params = cv[0].get_params();
        auto cycl_order = params->get_cyclotomic_order();
        std::vector<NativeInteger> moduli_first = {params->get_params()[0]->get_modulus()};
        std::vector<NativeInteger> roots_first = {params->get_params()[0]->get_root_of_unity()};
        auto params_first = std::make_shared<RnsParams<BigInteger>>(cycl_order, moduli_first, roots_first);
        std::vector<NativeInteger> moduli_all_but_first(size_ql - 1);
        std::vector<NativeInteger> roots_all_but_first(size_ql - 1);
        for (size_t i = 1; i < size_ql; i++) {
            moduli_all_but_first[i - 1] = params->get_params()[i]->get_modulus();
            roots_all_but_first[i - 1] = params->get_params()[i]->get_root_of_unity();
        }
        auto params_all_but_first =
                std::make_shared<RnsParams<BigInteger>>(cycl_order, moduli_all_but_first, roots_all_but_first);
        RnsPoly e(dug, params_all_but_first, Format::EVALUATION);

        e.expand_crt_basis_reverse_order(params, params_first, crypto_params->get_multiparty_q_hat_inv_modq_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_q_hat_inv_modq_precon_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_q_hat_modq0_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_alpha_q_modq0_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_modq0_barrett_mu(), crypto_params->get_multiparty_q_inv(),
                                     Format::EVALUATION);

        noise = std::move(e);
    } else if (crypto_params->get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
               crypto_params->get_execution_mode() == EXEC_EVALUATION) {
        auto dgg = crypto_params->get_flooding_discrete_gaussian_generator();
        RnsPoly e(dgg, cv[0].get_params(), Format::EVALUATION);
        noise = std::move(e);
    } else {
        DggType dgg(NoiseFlooding::MP_SD);
        RnsPoly e(dgg, cv[0].get_params(), Format::EVALUATION);
        noise = std::move(e);
    }

    // noise is added to do noise flooding
    if (ns != 1)
        noise *= RnsPoly::Integer(ns);

    auto result = ciphertext->clone_empty();
    result->set_element(cv[0] + s * cv[1] + noise);
    return result;
}

Ciphertext<RnsPoly> RnsMultiparty::multiparty_decrypt_main(ConstCiphertext<RnsPoly> ciphertext,
                                                          const PrivateKey<RnsPoly> private_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(private_key->get_crypto_parameters());
    const auto ns = crypto_params->get_noise_scale();

    const std::vector<RnsPoly>& cv = ciphertext->get_elements();

    const RnsPoly& sk = private_key->get_private_element();
    size_t size_ql = cv[0].get_params()->get_params().size();
    auto s = sk.clone_towers(0, size_ql - 1);

    RnsPoly noise;
    if (crypto_params->get_multiparty_mode() == NOISE_FLOODING_MULTIPARTY) {
        if (size_ql < 3) {
            CIPHER_THROW("sizeQl " + std::to_string(size_ql) +
                          " must be at least 3 in NOISE_FLOODING_MULTIPARTY mode.");
        }
        DugType dug;
        auto params = cv[0].get_params();
        RnsParams<BigInteger> params_copy = *params;
        params_copy.pop_first_param();
        auto params_all_but_first = std::make_shared<RnsParams<BigInteger>>(params_copy);
        RnsPoly e(dug, params_all_but_first, Format::EVALUATION);

        auto cycl_order = params->get_cyclotomic_order();
        std::vector<NativeInteger> moduli_first = {params->get_params()[0]->get_modulus()};
        std::vector<NativeInteger> roots_first = {params->get_params()[0]->get_root_of_unity()};
        auto params_first = std::make_shared<RnsParams<BigInteger>>(cycl_order, moduli_first, roots_first);
        e.expand_crt_basis_reverse_order(params, params_first, crypto_params->get_multiparty_q_hat_inv_modq_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_q_hat_inv_modq_precon_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_q_hat_modq0_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_alpha_q_modq0_at_index(size_ql - 2),
                                     crypto_params->get_multiparty_modq0_barrett_mu(), crypto_params->get_multiparty_q_inv(),
                                     Format::EVALUATION);

        noise = std::move(e);
    } else if (crypto_params->get_decryption_noise_mode() == NOISE_FLOODING_DECRYPT &&
               crypto_params->get_execution_mode() == EXEC_EVALUATION) {
        auto dgg = crypto_params->get_flooding_discrete_gaussian_generator();
        RnsPoly e(dgg, cv[0].get_params(), Format::EVALUATION);
        noise = std::move(e);
    } else {
        DggType dgg(NoiseFlooding::MP_SD);
        RnsPoly e(dgg, cv[0].get_params(), Format::EVALUATION);
        noise = std::move(e);
    }

    // noise is added to do noise flooding
    if (ns != 1)
        noise *= RnsPoly::Integer(ns);

    auto result = ciphertext->clone_empty();
    result->set_element(s * cv[1] + noise);
    return result;
}

EvalKey<RnsPoly> RnsMultiparty::multi_mult_eval_key(PrivateKey<RnsPoly> private_key, EvalKey<RnsPoly> eval_key) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<RnsCryptoParams>(eval_key->get_crypto_context()->get_crypto_parameters());
    const auto ns = crypto_params->get_noise_scale();

    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();

    EvalKey<RnsPoly> eval_key_result = std::make_shared<EvalKeyRelinImpl<RnsPoly>>(eval_key->get_crypto_context());

    const std::vector<RnsPoly>& a0 = eval_key->get_a_vector();
    const std::vector<RnsPoly>& b0 = eval_key->get_b_vector();

    const size_t size = a0.size();

    std::vector<RnsPoly> a;
    a.reserve(size);
    std::vector<RnsPoly> b;
    b.reserve(size);

    if (crypto_params->get_key_switch_technique() == BV) {
        const RnsPoly& s = private_key->get_private_element();
        const auto& element_params = s.get_params();
        for (size_t i = 0; i < size; ++i) {
            a.push_back(a0[i] * s + ns * RnsPoly(dgg, element_params, Format::EVALUATION));
            b.push_back(b0[i] * s + ns * RnsPoly(dgg, element_params, Format::EVALUATION));
        }
    } else {
        const auto& params_q = crypto_params->get_element_params();
        const auto& params_qp = crypto_params->get_params_qp();

        uint32_t size_q = params_q->get_params().size();
        uint32_t size_qp = params_qp->get_params().size();

        RnsPoly s = private_key->get_private_element().clone();

        s.set_format(Format::COEFFICIENT);
        RnsPoly s_ext(params_qp, Format::COEFFICIENT, false);

        for (uint32_t i = 0; i < size_q; i++) {
            s_ext.set_element_at_index(i, s.get_element_at_index(i));
        }

        for (uint32_t j = size_q; j < size_qp; j++) {
            const auto& pj = params_qp->get_params()[j];
            NativePoly s_new0(pj, Format::COEFFICIENT);
            s_new0.set_values(NativeVector(s.get_element_at_index(0).get_values(), pj->get_modulus()), Format::COEFFICIENT);
            s_ext.set_element_at_index(j, std::move(s_new0));
        }
        s_ext.set_format(Format::EVALUATION);

        for (uint32_t i = 0; i < size; i++) {
            a.push_back(a0[i] * s_ext + ns * RnsPoly(dgg, params_qp, Format::EVALUATION));
            b.push_back(b0[i] * s_ext + ns * RnsPoly(dgg, params_qp, Format::EVALUATION));
        }
    }

    eval_key_result->set_a_vector(std::move(a));
    eval_key_result->set_b_vector(std::move(b));
    return eval_key_result;
}

// Used a subroutine for interactive bootstrapping.
// Takes a polynomial with 2 two towers (RNS limbs)
// For each coefficient, applies the following logic
// If |coefficient| > q/4, then add q/2 to it
// The guarantees that rounded c_0 + c_1 < q/2,
// it prevents an overflow during interactive bootstrapping
void polynomial_round(RnsPoly& dcrtpoly) {
    const uint32_t NUM_TOWERS = dcrtpoly.get_num_of_elements();
    if (2 != NUM_TOWERS) {
        CIPHER_THROW("The input polynomial has " + std::to_string(NUM_TOWERS) + " instead of 2 RNS limbs");
    }

    std::vector<NativeInteger> q(NUM_TOWERS);
    std::vector<NativePoly> poly(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++) {
        poly[i] = dcrtpoly.get_element_at_index(i);
        q[i] = poly[i].get_modulus();
    }

    std::vector<NativeInteger> q_inv(NUM_TOWERS);
    q_inv[0] = q[1].mod_inverse(q[0]);
    q_inv[1] = q[0].mod_inverse(q[1]);

    std::vector<NativeInteger> precon(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++) {
        precon[i] = q_inv[i].prep_mod_mul_const(q[i]);
    }

    const BigInteger qbig{BigInteger(q[0].convert_to_int()) * BigInteger(q[1].convert_to_int())};
    const BigInteger qhalfbig{qbig / BigInteger(2)};
    std::vector<NativeInteger> q_half(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++)
        q_half[i] = qhalfbig.mod(BigInteger(q[i].convert_to_int())).convert_to_int();

    if constexpr (sizeof(NativeInteger::DNativeInt) > sizeof(BasicInteger)) {
        const auto Q = static_cast<NativeInteger::DNativeInt>(q[0].convert_to_int()) *
                       static_cast<NativeInteger::DNativeInt>(q[1].convert_to_int());
        const auto q1quart = Q / 4;
        const auto q3quart = 3 * Q / 4;
        for (size_t k = 0; k < dcrtpoly.get_ring_dimension(); k++) {
            NativeInteger::DNativeInt x128 =
                    static_cast<NativeInteger::DNativeInt>(
                            (poly[0][k].mod_mul_fast_const(q_inv[0], q[0], precon[0])).convert_to_int()) *
                    q[1].convert_to_int();
            x128 += static_cast<NativeInteger::DNativeInt>(
                            (poly[1][k].mod_mul_fast_const(q_inv[1], q[1], precon[1])).convert_to_int()) *
                    q[0].convert_to_int();
            if (x128 > Q)
                x128 %= Q;
            if ((x128 > q1quart) && (x128 <= q3quart)) {
                poly[0][k].mod_add_fast_eq(q_half[0], q[0]);
                poly[1][k].mod_add_fast_eq(q_half[1], q[1]);
            }
        }
    } else {
        const BigInteger q1quart{qbig / BigInteger(4)};
        const BigInteger q3quart{(BigInteger(3) * qbig) / BigInteger(4)};
        const BigInteger q0big{q[0].convert_to_int()};
        const BigInteger q1big{q[1].convert_to_int()};
        for (size_t k = 0; k < dcrtpoly.get_ring_dimension(); k++) {
            BigInteger x{BigInteger((poly[0][k].mod_mul_fast_const(q_inv[0], q[0], precon[0])).convert_to_int()) * q1big};
            x += BigInteger((poly[1][k].mod_mul_fast_const(q_inv[1], q[1], precon[1])).convert_to_int()) * q0big;
            if (x > qbig)
                x = x.mod(qbig);
            if ((x > q1quart) && (x <= q3quart)) {
                poly[0][k].mod_add_fast_eq(q_half[0], q[0]);
                poly[1][k].mod_add_fast_eq(q_half[1], q[1]);
            }
        }
    }

    dcrtpoly.set_element_at_index(0, poly[0]);
    dcrtpoly.set_element_at_index(1, poly[1]);
}

// Used as a subroutine in interactive bootstrapping.
// Extends a RnsPoly with 2 RNS limbs (from q) to the full
// RNS basis (to Q). The exact basis extension RNS procedure from
// https://eprint.iacr.org/2018/117 is used.
void extend_basis(RnsPoly& dcrtpoly, const std::shared_ptr<RnsPoly::Params> params_qp) {
    if (dcrtpoly.get_num_of_elements() != 2) {
        CIPHER_THROW(" The input polynomial should have 2 RNS limbs");
    }

    const auto params_q = dcrtpoly.get_params();
    uint32_t size_qp = params_qp->get_params().size();
    uint32_t size_q = params_q->get_params().size();
    uint32_t size_p = size_qp - size_q;

    // Loads all moduli and roots of unity
    std::vector<NativeInteger> moduli_q(size_q);
    // std::vector<NativeInteger> roots_q(size_q);  // TODO (dsuponit): do we need roots_q?
    for (size_t i = 0; i < size_q; i++) {
        moduli_q[i] = params_q->get_params()[i]->get_modulus();
        // roots_q[i]  = params_q->get_params()[i]->get_root_of_unity();
    }

    std::vector<NativeInteger> moduli_p(size_p);
    std::vector<NativeInteger> roots_p(size_p);
    for (size_t i = 0; i < size_p; i++) {
        moduli_p[i] = params_qp->get_params()[i + size_q]->get_modulus();
        roots_p[i] = params_qp->get_params()[i + size_q]->get_root_of_unity();
    }
    auto params_p = std::make_shared<typename RnsPoly::Params>(2 * params_q->get_ring_dimension(), moduli_p, roots_p);

    // Does all RNS precomputations
    std::vector<NativeInteger> q_hat_inv_modq(size_q);
    std::vector<NativeInteger> q_hat_inv_modq_precon(size_q);
    std::vector<std::vector<NativeInteger>> q_hat_modp(size_p);
    for (auto& v : q_hat_modp)
        v.reserve(size_q);

    const BigInteger modulus_q{dcrtpoly.get_modulus()};

    for (uint32_t i = 0; i < size_q; i++) {
        const BigInteger q_hati{modulus_q / BigInteger(moduli_q[i])};
        const NativeInteger q_hati_modqi{q_hati.mod(BigInteger(moduli_q[i])).convert_to_int()};
        q_hat_inv_modq[i] = q_hati_modqi.mod_inverse(moduli_q[i]).mod(moduli_q[i]);
        q_hat_inv_modq_precon[i] = q_hat_inv_modq[i].prep_mod_mul_const(moduli_q[i]);
        for (uint32_t j = 0; j < size_p; j++)
            q_hat_modp[j].push_back(NativeInteger(q_hati.mod(BigInteger(moduli_p[j])).convert_to_int()));
    }

    std::vector<std::vector<NativeInteger>> alpha_q_modp(size_q + 1);
    for (auto& v : alpha_q_modp)
        v.reserve(size_p);
    for (uint32_t j = 0; j < size_p; j++) {
        const NativeInteger q_modpj{modulus_q.mod(BigInteger(moduli_p[j])).convert_to_int()};
        for (uint32_t i = 0; i < size_q + 1; i++) {
            alpha_q_modp[i].push_back(q_modpj.mod_mul(NativeInteger(i), moduli_p[j]));
        }
    }

    const BigInteger barrett_base128_bit(BigInteger(1).l_shift_eq(128));
    const BigInteger two_power64(BigInteger(1).l_shift_eq(64));

    // Precomputations for Barrett modulo reduction
    std::vector<NativeInteger::DNativeInt> modp_barrett_mu(size_p);
    for (uint32_t j = 0; j < size_p; j++) {
        BigInteger mu = barrett_base128_bit / BigInteger(moduli_p[j]);
        uint64_t val[2];
        val[0] = (mu % two_power64).convert_to_int();
        val[1] = mu.r_shift(64).convert_to_int();

        memcpy(&modp_barrett_mu[j], val, sizeof(NativeInteger::DNativeInt));
    }

    std::vector<double> q_inv(size_q);
    for (size_t i = 0; i < size_q; i++) {
        q_inv[i] = 1. / static_cast<double>(moduli_q[i].convert_to_int());
    }

    // Calls the exact RNS basis extension procedure
    dcrtpoly.expand_crt_basis(params_qp, params_p, q_hat_inv_modq, q_hat_inv_modq_precon, q_hat_modp, alpha_q_modp, modp_barrett_mu,
                            q_inv, Format::COEFFICIENT);
}

Ciphertext<RnsPoly> RnsMultiparty::int_boot_decrypt(const PrivateKey<RnsPoly> private_key,
                                                   ConstCiphertext<RnsPoly> ciphertext) const {
    const size_t NUM_POLYNOMIALS = ciphertext->number_ciphertext_elements();
    if (NUM_POLYNOMIALS != 1 && NUM_POLYNOMIALS != 2) {
        std::string msg = "Ciphertext should contain either one or two polynomials. The input ciphertext has " +
                          std::to_string(NUM_POLYNOMIALS) + ".";
        CIPHER_THROW(msg);
    }

    std::vector<RnsPoly> c = ciphertext->get_elements();
    for (uint32_t i = 0; i < NUM_POLYNOMIALS; i++)
        c[i].set_format(Format::EVALUATION);
    size_t size_ql = c[0].get_params()->get_params().size();

    const RnsPoly& s = private_key->get_private_element();
    auto scopy = s.clone_towers(0, size_ql - 1);

    RnsPoly cs{(NUM_POLYNOMIALS == 1) ? (c[0] * scopy) : (c[1] * scopy + c[0])};
    cs.set_format(Format::COEFFICIENT);
    polynomial_round(cs);

    Ciphertext<RnsPoly> result = ciphertext->clone();
    result->set_elements({cs});

    return result;
}

Ciphertext<RnsPoly> RnsMultiparty::int_boot_encrypt(const PublicKey<RnsPoly> public_key,
                                                   ConstCiphertext<RnsPoly> ctxt) const {
    if (ctxt->get_elements().empty()) {
        CIPHER_THROW("No polynomials found in the input ciphertext");
    }

    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;
    using ParmType = typename RnsPoly::Params;

    const auto crypto_params =
            std::static_pointer_cast<RlweCryptoParams<RnsPoly>>(public_key->get_crypto_parameters());

    RnsPoly ptxt = ctxt->get_elements()[0];
    ptxt.set_format(Format::COEFFICIENT);

    // changes the modulus from small q (2 RNS limbs) to a large Q to support future computations
    extend_basis(ptxt, crypto_params->get_element_params());

    const std::shared_ptr<ParmType> ptxt_params = ptxt.get_params();
    const DggType& dgg = crypto_params->get_discrete_gaussian_generator();
    TugType tug;

    // Supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution (UNIFORM_TERNARY) cases
    RnsPoly v = (crypto_params->get_secret_key_dist() == GAUSSIAN) ? RnsPoly(dgg, ptxt_params, Format::EVALUATION) :
                                                                  RnsPoly(tug, ptxt_params, Format::EVALUATION);

    RnsPoly e0(dgg, ptxt_params, Format::COEFFICIENT);
    RnsPoly e1(dgg, ptxt_params, Format::EVALUATION);

    // we add in the coefficient representation to avoid extra NTTs
    ptxt += e0;
    ptxt.set_format(Format::EVALUATION);

    const std::vector<RnsPoly>& pk = public_key->get_public_elements();
    uint32_t size_ql = ptxt_params->get_params().size();
    uint32_t size_q = pk[0].get_params()->get_params().size();

    std::vector<RnsPoly> cv;
    cv.reserve(2);
    if (size_ql != size_q) {
        // Clone only the towers of the public keys that are still needed.
        RnsPoly b = pk[0].clone_towers(0, size_ql - 1);
        RnsPoly a = pk[1].clone_towers(0, size_ql - 1);

        // the error e0 was already added to ptxt
        cv.push_back(b * v + ptxt);
        cv.push_back(a * v + e1);
    } else {
        // Use public keys as they are
        const RnsPoly& b = pk[0];
        const RnsPoly& a = pk[1];

        // the error e0 was already added to ptxt
        cv.push_back(b * v + ptxt);
        cv.push_back(a * v + e1);
    }

    Ciphertext<RnsPoly> ciphertext(std::make_shared<CiphertextImpl<RnsPoly>>(public_key));
    ciphertext->set_elements(std::move(cv));

    // Ciphertext depth, level, and scaling factor should be equal to that of the plaintext.
    // However, Encrypt does not take Plaintext as input (only RnsPoly),
    // so we don't have access to these here and we copy them from the input ciphertext.
    ciphertext->set_encoding_type(ctxt->get_encoding_type());
    ciphertext->set_scaling_factor(ctxt->get_scaling_factor());
    ciphertext->set_noise_scale_deg(ctxt->get_noise_scale_deg());
    ciphertext->set_level(0);
    ciphertext->set_metadata_map(ctxt->get_metadata_map());
    ciphertext->set_slots(ctxt->get_slots());

    return ciphertext;
}

Ciphertext<RnsPoly> RnsMultiparty::int_boot_add(ConstCiphertext<RnsPoly> ciphertext1,
                                               ConstCiphertext<RnsPoly> ciphertext2) const {
    if (ciphertext1->get_elements().empty()) {
        CIPHER_THROW("No polynomials found in the input ciphertext1");
    }
    if (ciphertext2->get_elements().empty()) {
        CIPHER_THROW("No polynomials found in the input ciphertext2");
    }

    auto elements1 = ciphertext1->get_elements();
    auto elements2 = ciphertext2->get_elements();

    elements2[0].set_format(Format::COEFFICIENT);
    const auto crypto_params =
            std::static_pointer_cast<RlweCryptoParams<RnsPoly>>(ciphertext1->get_crypto_parameters());
    extend_basis(elements2[0], crypto_params->get_element_params());
    elements2[0].set_format(Format::EVALUATION);

    elements1[0] += elements2[0];

    Ciphertext<RnsPoly> result = ciphertext1->clone();
    result->set_elements(elements1);

    return result;
}

}  // namespace cipher
