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

#include "cipher/fhe/schemelet/rlwe_mp.h"

#include <stdint.h>

#include <complex>
#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/base/rlwe_params.h"
#include "cipher/fhe/rns/crypto_params.h"
#include "cipher/util/utilities.h"

template <typename TypeT>
static void BitReverse(TypeT& vals) {
    uint32_t size = vals.size();
    for (uint32_t i = 1, j = 0; i < size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }
}

template <typename TypeT>
static void bit_reverse_two_halves(TypeT& vals) {
    uint32_t size = vals.size() / 2;
    for (uint32_t i = 1, j = 0; i < size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }

    for (uint32_t i = size + 1, j = size; i < 2 * size; ++i) {
        uint32_t bit = size >> 1;
        for (; j >= size + bit; bit >>= 1)
            j -= bit;
        j += bit;
        if (i < j) {
            auto t = vals[i];
            vals[i] = vals[j];
            vals[j] = t;
        }
    }
}

namespace cipher {

namespace {

static std::vector<RnsPoly> mod_switch_up(const std::vector<Poly>& input, const BigInteger& qfrom, const BigInteger& qto,
                                         const std::shared_ptr<RnsParams<RnsPoly::Integer>>& ep) {
    Poly b_poly = input[0];
    b_poly.switch_modulus(qto, 1, 0, 0);

    Poly a_poly = input[1];
    a_poly.switch_modulus(qto, 1, 0, 0);

    std::vector<RnsPoly> output{RnsPoly(b_poly.multiply_and_round(qto, qfrom), ep),
                                 RnsPoly(a_poly.multiply_and_round(qto, qfrom), ep)};
    output[0].set_format(Format::EVALUATION);
    output[1].set_format(Format::EVALUATION);

    return output;
}

static std::vector<RnsPoly> mod_switch_down(const std::vector<Poly>& input, const BigInteger& qfrom,
                                           const BigInteger& qto,
                                           const std::shared_ptr<RnsParams<RnsPoly::Integer>>& ep) {
    Poly b_poly = input[0].multiply_and_round(qto, qfrom);
    b_poly.switch_modulus(qto, 1, 0, 0);

    Poly a_poly = input[1].multiply_and_round(qto, qfrom);
    a_poly.switch_modulus(qto, 1, 0, 0);

    std::vector<RnsPoly> output{RnsPoly(b_poly, ep), RnsPoly(a_poly, ep)};
    output[0].set_format(Format::EVALUATION);
    output[1].set_format(Format::EVALUATION);

    return output;
}

}  // namespace

std::shared_ptr<RnsParams<RnsPoly::Integer>> SchemeletRlweMp::get_element_params(
        const PrivateKey<RnsPoly>& private_key, uint32_t level) {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<RnsPoly>>(private_key->get_crypto_parameters());

    const auto crypto_params_rns = std::dynamic_pointer_cast<RnsCryptoParams>(private_key->get_crypto_parameters());
    if (crypto_params_rns != nullptr) {
        auto st = crypto_params_rns->get_scaling_technique();
        // in the COMPOSITESCALING* modes, every level consists of composite_degree towers
        if (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL)
            level *= crypto_params_rns->get_composite_degree();
        else if (st == FLEXIBLEAUTOEXT)
            ++level;
    }

    auto ep = std::make_shared<RnsParams<RnsPoly::Integer>>(*(crypto_params->get_element_params()));
    for (uint32_t i = 0; i < level; ++i)
        ep->pop_last_param();

    return ep;
}

std::vector<Poly> SchemeletRlweMp::encrypt_coeff(std::vector<int64_t> input, const BigInteger& Q, const BigInteger& p,
                                                const PrivateKey<RnsPoly>& private_key,
                                                const std::shared_ptr<RnsParams<RnsPoly::Integer>>& ep,
                                                bool bit_reverse) {
    const auto crypto_params =
            std::dynamic_pointer_cast<RlweCryptoParams<RnsPoly>>(private_key->get_crypto_parameters());

    DugType dug;
    RnsPoly a(dug, ep, Format::EVALUATION);
    RnsPoly e(crypto_params->get_discrete_gaussian_generator(), ep, Format::EVALUATION);

    auto scopy = private_key->get_private_element().clone_towers(0, ep->get_params().size() - 1);

    RnsPoly b = e - a * scopy;  // encryption of 0 using Q'

    a.set_format(Format::COEFFICIENT);
    auto a_poly = a.crt_interpolate();
    b.set_format(Format::COEFFICIENT);
    auto b_poly = b.crt_interpolate();

    BigInteger big_q_prime = b.get_modulus();

    // Do modulus switching from Q' to Q
    if (Q < big_q_prime) {
        b_poly = b_poly.multiply_and_round(Q, big_q_prime);
        b_poly.switch_modulus(Q, 1, 0, 0);

        a_poly = a_poly.multiply_and_round(Q, big_q_prime);
        a_poly.switch_modulus(Q, 1, 0, 0);
    } else {
        b_poly.switch_modulus(Q, 1, 0, 0);
        b_poly = b_poly.multiply_and_round(Q, big_q_prime);

        a_poly.switch_modulus(Q, 1, 0, 0);
        a_poly = a_poly.multiply_and_round(Q, big_q_prime);
    }

    auto m_poly = b_poly;
    m_poly.set_values_to_zero();

    auto delta = Q / p;
    uint32_t gap = m_poly.get_length() / (2.0 * input.size());

    // Input here is not yet padded up to the ring dimension
    if (bit_reverse) {
        if (gap == 0) {
            bit_reverse_two_halves(input);
        } else {
            BitReverse(input);
        }
    }

    gap = (gap == 0) ? 1 : gap;
    const uint32_t limit = input.size() < m_poly.get_length() ? input.size() : m_poly.get_length();
    for (uint32_t i = 0; i < limit; ++i) {
        auto entry = signed_to_residue(input[i], m_poly.get_modulus());
        m_poly[i * gap] = delta * entry;
        if (gap > 1) {
            m_poly[(i + limit) * gap] = delta * entry;
        }
    }

    return {b_poly += m_poly, a_poly};
}

std::vector<int64_t> SchemeletRlweMp::decrypt_coeff(const std::vector<Poly>& input, const BigInteger& Q,
                                                   const BigInteger& p, const PrivateKey<RnsPoly>& private_key,
                                                   const std::shared_ptr<RnsParams<RnsPoly::Integer>>& ep,
                                                   uint32_t num_slots, uint32_t length, bool bit_reverse) {
    const auto& big_q_prime = ep->get_modulus();

    auto ba = (Q < big_q_prime) ? mod_switch_up(input, Q, big_q_prime, ep) : mod_switch_down(input, Q, big_q_prime, ep);

    auto scopy = private_key->get_private_element().clone_towers(0, ep->get_params().size() - 1);

    auto m = ba[0] + ba[1] * scopy;

    m.set_format(Format::COEFFICIENT);

    auto m_poly = m.crt_interpolate();
    uint32_t gap = m_poly.get_length() / (2 * num_slots);

    if (Q < big_q_prime) {
        m_poly = m_poly.multiply_and_round(Q, big_q_prime);
        m_poly.switch_modulus(Q, 1, 0, 0);
    } else {
        m_poly.switch_modulus(Q, 1, 0, 0);
        m_poly = m_poly.multiply_and_round(Q, big_q_prime);
    }

    m_poly = m_poly.multiply_and_round(p, Q);
    m_poly.switch_modulus(p, 1, 0, 0);

    BigInteger half = p >> 1;

    length = (length == 0) ? num_slots : length;

    std::vector<int64_t> output(length);
    for (uint32_t i = 0, idx = 0; i < length; ++i, idx += gap)
        output[i] =
                (m_poly[idx] > half) ? -(p - m_poly[idx]).convert_to_int<int64_t>() : m_poly[idx].convert_to_int<int64_t>();

    if (bit_reverse) {
        if (num_slots < length) {
            bit_reverse_two_halves(output);
        } else {
            BitReverse(output);
        }
    }

    return output;
}

void SchemeletRlweMp::mod_switch(std::vector<Poly>& input, const BigInteger& Q1, const BigInteger& Q2) {
    input[0] = input[0].multiply_and_round(Q1, Q2);
    input[0].switch_modulus(Q1, 1, 0, 0);
    input[1] = input[1].multiply_and_round(Q1, Q2);
    input[1].switch_modulus(Q1, 1, 0, 0);
}

Ciphertext<RnsPoly> SchemeletRlweMp::convert_rlwe_to_ckks(const CryptoContextImpl<RnsPoly>& cc,
                                                        const std::vector<Poly>& coeffs,
                                                        const PublicKey<RnsPoly>& pub_key, const BigInteger& bigq,
                                                        uint32_t slots, uint32_t level) {
    const auto crypto_params_rns = std::dynamic_pointer_cast<RnsCryptoParams>(cc.get_crypto_parameters());
    if (crypto_params_rns != nullptr) {
        auto st = crypto_params_rns->get_scaling_technique();
        // in the COMPOSITESCALING* modes, every level consists of composite_degree towers
        if (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL)
            level *= crypto_params_rns->get_composite_degree();
        else if (st == FLEXIBLEAUTOEXT)
            ++level;
    }

    std::vector<std::complex<double>> y(1);
    auto ptxt = cc.make_ckks_packed_plaintext(y, 1, level);
    ptxt->set_length(slots);

    auto ctxt = cc.encrypt(pub_key, ptxt);

    auto ep = ptxt->get_element<RnsPoly>().get_params();

    auto& q_prime_ckks = ep->get_modulus();

    auto elements_ckks = (q_prime_ckks > bigq) ? mod_switch_up(coeffs, bigq, q_prime_ckks, ep) :
                                              mod_switch_down(coeffs, bigq, q_prime_ckks, ep);
    ctxt->set_elements(elements_ckks);
    return ctxt;
}

std::vector<Poly> SchemeletRlweMp::convert_ckks_to_rlwe(ConstCiphertext<RnsPoly>& ctxt, const BigInteger& Q) {
    auto b = ctxt->get_elements()[0];
    b.set_format(Format::COEFFICIENT);
    auto b_poly = b.crt_interpolate();

    auto a = ctxt->get_elements()[1];
    a.set_format(Format::COEFFICIENT);
    auto a_poly = a.crt_interpolate();

    BigInteger q_prime = ctxt->get_elements()[0].get_modulus();
    if (Q < q_prime) {
        b_poly = b_poly.multiply_and_round(Q, q_prime);
        b_poly.switch_modulus(Q, 1, 0, 0);

        a_poly = a_poly.multiply_and_round(Q, q_prime);
        a_poly.switch_modulus(Q, 1, 0, 0);
    } else {
        b_poly.switch_modulus(Q, 1, 0, 0);
        b_poly = b_poly.multiply_and_round(Q, q_prime);

        a_poly.switch_modulus(Q, 1, 0, 0);
        a_poly = a_poly.multiply_and_round(Q, q_prime);
    }
    return {b_poly, a_poly};
}

BigInteger SchemeletRlweMp::get_q_prime(const PublicKey<RnsPoly>& pub_key, uint32_t lvls) {
    auto& params = pub_key->get_public_elements()[0].get_params()->get_params();
    uint32_t cnt = 0;

    BigInteger q_prime = params[0]->get_modulus();
    while (lvls-- > 0)
        q_prime *= params[++cnt]->get_modulus();

    return q_prime;
}

}  // namespace cipher
