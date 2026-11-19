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

#define PROFILE

#include "cipher/fhe/rns/crypto_params.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include "cipher/math/dft.h"

namespace cipher {
namespace {
// global used to validate the estimated size_p value
uint32_t size_p_estimate_global{};
}  // namespace

void RnsCryptoParams::precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech,
                                            EncryptionTechnique enc_tech, MultiplicationTechnique mult_tech,
                                            uint32_t num_part_q, uint32_t aux_bits, uint32_t extra_bits) {
    // Set the key switching technique.
    ks_technique_ = ks_tech;
    // Set the scaling technique.
    scal_technique_ = scal_tech;
    // Set the key encryption technique.
    enc_technique_ = enc_tech;
    // Set the multiplication technique.
    mult_technique_ = mult_tech;
    // Set number of digits in HYBRID
    num_part_q_ = num_part_q;
    // Set auxiliary primes bit size in HYBRID
    aux_bits_ = aux_bits;
    // Set number of extra_bits for lower error
    extra_bits_ = extra_bits;

    size_t size_q = get_element_params()->get_params().size();
    size_t n = get_element_params()->get_ring_dimension();

    // Construct moduli_q and roots_q from crypto parameters
    std::vector<NativeInteger> moduli_q(size_q);
    std::vector<NativeInteger> roots_q(size_q);
    for (size_t i = 0; i < size_q; i++) {
        moduli_q[i] = get_element_params()->get_params()[i]->get_modulus();
        roots_q[i] = get_element_params()->get_params()[i]->get_root_of_unity();
    }

    // Pre-compute CRT::FFT values for Q
    DiscreteFourierTransform::initialize(n * 2, n / 2);
    ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_q, 2 * n, moduli_q);
    if (ks_technique_ == HYBRID) {
        // num_part_q can not be zero as there is a division by num_part_q
        if (num_part_q == 0)
            CIPHER_THROW("numPartQ is zero");

        // Compute ceil(size_q/num_part_q), the # of towers per digit
        uint32_t a = static_cast<uint32_t>(std::ceil(static_cast<double>(size_q) / num_part_q));
        if (size_q <= (a * (num_part_q - 1))) {
            auto str = "HYBRID key switching parameters: Can't appropriately distribute " + std::to_string(size_q) +
                       " towers into " + std::to_string(num_part_q) +
                       " digits. Please select different number of digits.";
            CIPHER_THROW(str);
        }

        num_per_part_q_ = a;

        // Compute the composite digits part_q = Q_j
        std::vector<BigInteger> moduli_part_q(num_part_q_, 1);
        for (uint32_t j = 0; j < num_part_q_; j++) {
            for (uint32_t i = a * j; i < (j + 1) * a; i++) {
                if (i < moduli_q.size())
                    moduli_part_q[j] *= moduli_q[i];
            }
        }

        // Compute PartQHat_i = Q/Q_j
        std::vector<BigInteger> part_q_hat_value(num_part_q_, 1);
        for (size_t i = 0; i < num_part_q_; i++) {
            for (size_t j = 0; j < num_part_q_; j++) {
                if (j != i)
                    part_q_hat_value[i] *= moduli_part_q[j];
            }
        }

        // Compute partitions of Q into num_part_q digits
        params_part_q_.resize(num_part_q_);
        for (uint32_t j = 0; j < num_part_q_; j++) {
            auto start_tower = j * a;
            auto end_tower = ((j + 1) * a - 1 < size_q) ? (j + 1) * a - 1 : size_q - 1;
            std::vector<std::shared_ptr<NativePolyParams>> params =
                    get_element_params()->get_param_partition(start_tower, end_tower);
            std::vector<NativeInteger> moduli(params.size());
            std::vector<NativeInteger> roots(params.size());
            for (uint32_t i = 0; i < params.size(); i++) {
                moduli[i] = params[i]->get_modulus();
                roots[i] = params[i]->get_root_of_unity();
            }
            params_part_q_[j] =
                    std::make_shared<RnsParams<BigInteger>>(params[0]->get_cyclotomic_order(), moduli, roots);
        }

        // Find number and size of individual special primes.
        uint32_t max_bits_value = moduli_part_q[0].get_length_for_base(2);
        for (uint32_t j = 1; j < num_part_q_; j++) {
            uint32_t bits = moduli_part_q[j].get_length_for_base(2);
            if (bits > max_bits_value)
                max_bits_value = bits;
        }
        // Select number of primes in auxiliary CRT basis
        uint32_t size_p = static_cast<uint32_t>(std::ceil(static_cast<double>(max_bits_value) / aux_bits));

        // We want to make sure that P exceeds the maximum digit in Q by a safe margin.
        // The safe margin is chosen to make hybrid key switching error closer to the modulus switching error.
        // The margin of 4 bits accounts for dnum * 3.19 for typical values of dnum. See the noise expression
        // in Section B.2.3 of https://eprint.iacr.org/2021/204 for more details.
        // Composite scaling uses a base margin of 6 bits, and the fast basis extension overflow grows
        // linearly with the number of limbs per digit, adding ceil(log2(composite_degree)) bits.
        uint32_t margin = (scal_tech == COMPOSITESCALINGAUTO || scal_tech == COMPOSITESCALINGMANUAL) ?
                                  6 + get_msb64(composite_degree_ - 1) :
                                  4;
        if (static_cast<uint64_t>(size_p) * aux_bits - max_bits_value < margin)
            ++size_p;
        // validate the estimated size_p value
        if (size_p_estimate_global > 0) {
            if (size_p > size_p_estimate_global) {
                auto str = "estimate_log_p() failure: expected size_p [" + std::to_string(size_p_estimate_global) +
                           "], but got size_p [" + std::to_string(size_p) + "]";
                CIPHER_THROW(str);
            }
            // reset size_p_estimate_global before the next use
            size_p_estimate_global = 0;
        }

        uint64_t prime_step = find_aux_prime_step();

        // Choose special primes in auxiliary basis and compute their roots
        // moduli_p holds special primes p1, p2, ..., pk
        // m_modulusP holds the product of special primes P = p1*p2*...pk
        std::vector<NativeInteger> moduli_p(size_p);
        std::vector<NativeInteger> roots_p(size_p);
        // first_p contains a prime whose size is PModSize.
        NativeInteger first_p = first_prime<NativeInteger>(aux_bits, prime_step);
        NativeInteger p_prev = first_p;
        BigInteger modulus_p(1);
        for (uint32_t i = 0; i < size_p; i++) {
            // The following loop makes sure that moduli in
            // P and Q are different
            bool found_in_q = false;
            do {
                moduli_p[i] = previous_prime<NativeInteger>(p_prev, prime_step);
                found_in_q = false;
                for (uint32_t j = 0; j < size_q; j++)
                    if (moduli_p[i] == moduli_q[j])
                        found_in_q = true;
                p_prev = moduli_p[i];
            } while (found_in_q);
            roots_p[i] = root_of_unity<NativeInteger>(2 * n, moduli_p[i]);
            modulus_p *= moduli_p[i];
            p_prev = moduli_p[i];
        }

        // Store the created moduli and roots in params_p_
        params_p_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_p, roots_p);

        // Create the moduli and roots for the extended CRT basis QP
        std::vector<NativeInteger> moduli_qp(size_q + size_p);
        std::vector<NativeInteger> roots_qp(size_q + size_p);
        for (size_t i = 0; i < size_q; i++) {
            moduli_qp[i] = moduli_q[i];
            roots_qp[i] = roots_q[i];
        }
        for (size_t i = 0; i < size_p; i++) {
            moduli_qp[size_q + i] = moduli_p[i];
            roots_qp[size_q + i] = roots_p[i];
        }

        params_qp_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_qp, roots_qp);

        // Precompute params for first 1..size_q towers of Q for key_switch_down (avoids per-call allocation).
        params_ql_hybrid_.resize(size_q);
        std::vector<NativeInteger> moduli_ql, roots_ql;
        moduli_ql.reserve(size_q);
        roots_ql.reserve(size_q);
        for (size_t i = 0; i < size_q; ++i) {
            moduli_ql.push_back(moduli_q[i]);
            roots_ql.push_back(roots_q[i]);
            params_ql_hybrid_[i] = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_ql, roots_ql);
        }

        // Pre-compute CRT::FFT values for P
        ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_p, 2 * n, moduli_p);

        // Pre-compute values [P]_{q_i}
        p_modq_.resize(size_q);
        for (uint32_t i = 0; i < size_q; i++) {
            p_modq_[i] = modulus_p.mod(moduli_q[i]).convert_to_int();
        }

        // Pre-compute values [P^{-1}]_{q_i}
        p_inv_modq_.resize(size_q);
        p_inv_modq_precon_.resize(size_q);
        for (size_t i = 0; i < size_q; i++) {
            BigInteger p_inv_modqi = modulus_p.mod_inverse(moduli_q[i]);
            p_inv_modq_[i] = p_inv_modqi.convert_to_int();
            p_inv_modq_precon_[i] = p_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // Pre-compute values [P/p_j]_{q_i}
        // Pre-compute values [(P/p_j)^{-1}]_{p_j}
        p_hat_inv_modp_.resize(size_p);
        p_hat_inv_modp_precon_.resize(size_p);
        p_hat_modq_.resize(size_p);
        for (size_t j = 0; j < size_p; j++) {
            BigInteger p_hatj = modulus_p / BigInteger(moduli_p[j]);
            BigInteger p_hat_inv_modpj = p_hatj.mod_inverse(moduli_p[j]);
            p_hat_inv_modp_[j] = p_hat_inv_modpj.convert_to_int();
            p_hat_inv_modp_precon_[j] = p_hat_inv_modp_[j].prep_mod_mul_const(moduli_p[j]);
            p_hat_modq_[j].resize(size_q);
            for (size_t i = 0; i < size_q; i++) {
                BigInteger p_hat_modqji = p_hatj.mod(moduli_q[i]);
                p_hat_modq_[j][i] = p_hat_modqji.convert_to_int();
            }
        }

        BigInteger modulus_q = get_element_params()->get_modulus();
        // Pre-compute values [Q/q_i]_{p_j}
        // Pre-compute values [(Q/q_i)^{-1}]_{q_i}
        ql_hat_inv_modq_.resize(size_q);
        ql_hat_inv_modq_precon_.resize(size_q);
        // l will run from 0 to size-2, but modulus_q values
        // run from Q^(l-1) to Q^(0)
        for (size_t l = 0; l < size_q; l++) {
            if (l > 0)
                modulus_q = modulus_q / BigInteger(moduli_q[size_q - l]);

            ql_hat_inv_modq_[size_q - l - 1].resize(size_q - l);
            ql_hat_inv_modq_precon_[size_q - l - 1].resize(size_q - l);
            for (size_t i = 0; i < size_q - l; i++) {
                BigInteger q_hati = modulus_q / BigInteger(moduli_q[i]);
                BigInteger q_hat_inv_modqi = q_hati.mod_inverse(moduli_q[i]);
                ql_hat_inv_modq_[size_q - l - 1][i] = q_hat_inv_modqi.convert_to_int();
                ql_hat_inv_modq_precon_[size_q - l - 1][i] =
                        ql_hat_inv_modq_[size_q - l - 1][i].prep_mod_mul_const(moduli_q[i]);
            }
        }

        // Pre-compute compementary partitions for ModUp
        uint32_t alpha = static_cast<uint32_t>(std::ceil(static_cast<double>(size_q) / num_part_q_));
        params_compl_part_q_.resize(size_q);
        mod_compl_partq_barrett_mu_.resize(size_q);
        for (int32_t l = size_q - 1; l >= 0; l--) {
            uint32_t beta = static_cast<uint32_t>(std::ceil(static_cast<double>(l + 1) / alpha));
            params_compl_part_q_[l].resize(beta);
            mod_compl_partq_barrett_mu_[l].resize(beta);
            for (uint32_t j = 0; j < beta; j++) {
                const std::shared_ptr<RnsParams<BigInteger>> digit_partition = get_params_part_q(j);
                auto cycl_order = digit_partition->get_cyclotomic_order();

                uint32_t size_part_qj = digit_partition->get_params().size();
                if (j == beta - 1)
                    size_part_qj = (l + 1) - j * alpha;
                uint32_t size_compl_part_qj = (l + 1) - size_part_qj + size_p;

                std::vector<NativeInteger> moduli(size_compl_part_qj);
                std::vector<NativeInteger> roots(size_compl_part_qj);

                for (uint32_t k = 0; k < size_compl_part_qj; k++) {
                    if (k < (l + 1) - size_part_qj) {
                        uint32_t curr_digit = k / alpha;
                        if (curr_digit >= j)
                            curr_digit++;
                        moduli[k] = get_params_part_q(curr_digit)->get_params()[k % alpha]->get_modulus();
                        roots[k] = get_params_part_q(curr_digit)->get_params()[k % alpha]->get_root_of_unity();
                    } else {
                        moduli[k] = moduli_p[k - ((l + 1) - size_part_qj)];
                        roots[k] = roots_p[k - ((l + 1) - size_part_qj)];
                    }
                }
                params_compl_part_q_[l][j] = std::make_shared<ParmType>(cycl_order, moduli, roots);

                const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
                mod_compl_partq_barrett_mu_[l][j].resize(moduli.size());
                for (uint32_t i = 0; i < moduli.size(); i++) {
                    mod_compl_partq_barrett_mu_[l][j][i] =
                            (barrett_base128_bit / BigInteger(moduli[i])).convert_to_int<DoubleNativeInt>();
                }
            }
        }

        // Pre-compute values [Q^(l)_j/q_i)^{-1}]_{q_i}
        part_ql_hat_inv_modq_.resize(num_part_q_);
        part_ql_hat_inv_modq_precon_.resize(num_part_q_);
        for (uint32_t k = 0; k < num_part_q_; k++) {
            auto params = params_part_q_[k]->get_params();
            uint32_t size_part_qk = params.size();
            part_ql_hat_inv_modq_[k].resize(size_part_qk);
            part_ql_hat_inv_modq_precon_[k].resize(size_part_qk);
            auto modulus_part_q = params_part_q_[k]->get_modulus();
            for (size_t l = 0; l < size_part_qk; l++) {
                if (l > 0)
                    modulus_part_q = modulus_part_q / BigInteger(params[size_part_qk - l]->get_modulus());

                part_ql_hat_inv_modq_[k][size_part_qk - l - 1].resize(size_part_qk - l);
                part_ql_hat_inv_modq_precon_[k][size_part_qk - l - 1].resize(size_part_qk - l);
                for (size_t i = 0; i < size_part_qk - l; i++) {
                    BigInteger q_hat = modulus_part_q / BigInteger(params[i]->get_modulus());
                    BigInteger q_hat_inv_modqi = q_hat.mod_inverse(params[i]->get_modulus());
                    part_ql_hat_inv_modq_[k][size_part_qk - l - 1][i] = q_hat_inv_modqi.convert_to_int();
                    part_ql_hat_inv_modq_precon_[k][size_part_qk - l - 1][i] =
                            part_ql_hat_inv_modq_[k][size_part_qk - l - 1][i].prep_mod_mul_const(
                                    params[i]->get_modulus());
                }
            }
        }

        // Pre-compute q_hat mod complementary partition qi's
        part_ql_hat_modp_.resize(size_q);
        for (uint32_t l = 0; l < size_q; l++) {
            uint32_t alpha = static_cast<uint32_t>(std::ceil(static_cast<double>(size_q) / num_part_q_));
            uint32_t beta = static_cast<uint32_t>(std::ceil(static_cast<double>(l + 1) / alpha));
            part_ql_hat_modp_[l].resize(beta);
            for (uint32_t k = 0; k < beta; k++) {
                auto params_part_q = get_params_part_q(k)->get_params();
                auto part_q = get_params_part_q(k)->get_modulus();
                uint32_t digit_size = params_part_q.size();
                if (k == beta - 1) {
                    digit_size = l + 1 - k * alpha;
                    for (uint32_t idx = digit_size; idx < params_part_q.size(); idx++) {
                        part_q = part_q / BigInteger(params_part_q[idx]->get_modulus());
                    }
                }

                part_ql_hat_modp_[l][k].resize(digit_size);
                for (uint32_t i = 0; i < digit_size; i++) {
                    BigInteger part_q_hat = part_q / BigInteger(params_part_q[i]->get_modulus());
                    auto compl_basis = get_params_compl_part_q(l, k);
                    part_ql_hat_modp_[l][k][i].resize(compl_basis->get_params().size());
                    for (size_t j = 0; j < compl_basis->get_params().size(); j++) {
                        BigInteger q_hat_modpj = part_q_hat.mod(compl_basis->get_params()[j]->get_modulus());
                        part_ql_hat_modp_[l][k][i][j] = q_hat_modpj.convert_to_int();
                    }
                }
            }
        }
    }
    /////////////////////////////////////
    // BFVrns and BGVrns : Multiparty Decryption : expand_crt_basis
    /////////////////////////////////////
    if (get_multiparty_mode() == NOISE_FLOODING_MULTIPARTY) {
        // Pre-compute values [*(Q/q_i/q_0)^{-1}]_{q_i}
        BigInteger modulus_q = BigInteger(get_element_params()->get_modulus()) / BigInteger(moduli_q[0]);
        multiparty_q_hat_inv_modq_.resize(size_q - 1);
        multiparty_q_hat_inv_modq_precon_.resize(size_q - 1);
        multiparty_q_hat_modq0_.resize(size_q - 1);
        // l will run from 0 to size-2, but modulus_q values
        // run from Q^(l-1) to Q^(0)
        for (size_t l = 0, m = size_q - l - 2; l < size_q - 1; ++l, --m) {
            if (l > 0)
                modulus_q = modulus_q / BigInteger(moduli_q[size_q - l]);

            multiparty_q_hat_inv_modq_[m].resize(m + 1);
            multiparty_q_hat_inv_modq_precon_[m].resize(m + 1);
            multiparty_q_hat_modq0_[m].resize(1);
            multiparty_q_hat_modq0_[m][0].resize(m + 1);
            for (size_t i = 1; i < m + 2; i++) {
                BigInteger q_hati = modulus_q / BigInteger(moduli_q[i]);
                BigInteger q_hat_inv_modqi = q_hati.mod_inverse(moduli_q[i]);
                multiparty_q_hat_inv_modq_[m][i - 1] = q_hat_inv_modqi.convert_to_int();
                multiparty_q_hat_inv_modq_precon_[m][i - 1] =
                        multiparty_q_hat_inv_modq_[m][i - 1].prep_mod_mul_const(moduli_q[i]);
                multiparty_q_hat_modq0_[m][0][i - 1] = q_hati.mod(moduli_q[0]);
            }
        }

        modulus_q = BigInteger(get_element_params()->get_modulus()) / BigInteger(moduli_q[0]);
        multiparty_alpha_q_modq0_.resize(size_q - 1);
        for (uint32_t l = size_q - 1; l > 0; l--) {
            if (l < size_q - 1)
                modulus_q = modulus_q / BigInteger(moduli_q[l + 1]);
            multiparty_alpha_q_modq0_[l - 1].resize(l + 1);
            NativeInteger ql_modq0 = modulus_q.mod(moduli_q[0]).convert_to_int();
            for (uint32_t j = 0; j < l + 1; ++j) {
                multiparty_alpha_q_modq0_[l - 1][j] = {ql_modq0.mod_mul(NativeInteger(j), moduli_q[0])};
            }
        }

        const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
        multiparty_modq0_barrett_mu_.resize(1);
        multiparty_modq0_barrett_mu_[0] =
                (barrett_base128_bit / BigInteger(moduli_q[0])).convert_to_int<DoubleNativeInt>();

        // Stores \frac{1/q_i}
        multiparty_q_inv_.resize(size_q - 1);
        for (size_t i = 1; i < size_q; i++) {
            multiparty_q_inv_[i - 1] = 1. / static_cast<double>(moduli_q[i].convert_to_int());
        }
    }
}

uint64_t RnsCryptoParams::find_aux_prime_step() const {
    return get_element_params()->get_ring_dimension();
}

std::pair<double, uint32_t> RnsCryptoParams::estimate_log_p(uint32_t num_part_q, double first_modulus_size,
                                                            double dcrt_bits, double extra_modulus_size,
                                                            uint32_t num_primes_value, uint32_t aux_bits,
                                                            ScalingTechnique scal_tech, bool add_one,
                                                            bool is_noise_flooding_multiparty,
                                                            uint32_t composite_degree) {
    // num_part_q can not be zero as there is a division by num_part_q
    if (num_part_q == 0)
        CIPHER_THROW("numPartQ is zero");

    size_t size_q = num_primes_value;
    if (extra_modulus_size > 0)
        size_q++;

    // handles a BFV-specific situation where the number of digits might be initially higher than number of RNS limbs in Q
    if (num_part_q > size_q)
        num_part_q = size_q;

    // Compute ceil(size_q/num_part_q), the # of towers per digit
    size_t num_per_part_q = static_cast<size_t>(std::ceil(static_cast<double>(size_q) / num_part_q));
    if (size_q <= (num_per_part_q * (num_part_q - 1))) {
        auto str = "HYBRID key switching parameters: Can't appropriately distribute " + std::to_string(size_q) +
                   " towers into " + std::to_string(num_part_q) + " digits. Please select different number of digits.";
        CIPHER_THROW(str);
    }

    // create a vector with the same value of bit sizes
    std::vector<double> qi(size_q, dcrt_bits);
    qi[0] = first_modulus_size;
    if (extra_modulus_size > 0)
        qi[size_q - 1] = extra_modulus_size;
    if (is_noise_flooding_multiparty) {
        for (size_t i = 1; i < (NoiseFlooding::NUM_MODULI_MULTIPARTY + 1); ++i) {
            qi[i] = NoiseFlooding::MULTIPARTY_MOD_SIZE;
        }
    }

    // Compute partitions of Q into num_part_q digits
    uint32_t max_bits_value = 0;
    for (size_t j = 0; j < num_part_q; ++j) {
        size_t start_tower = j * num_per_part_q;
        size_t end_tower = ((j + 1) * num_per_part_q - 1 < size_q) ? (j + 1) * num_per_part_q - 1 : size_q - 1;

        // sum qi elements qi[start_tower] + ... + qi[end_tower] inclusive. the end element should be qi.begin()+(end_tower+1)
        uint32_t bits =
                static_cast<uint32_t>(std::accumulate(qi.begin() + start_tower, qi.begin() + (end_tower + 1), 0.0));
        if (bits > max_bits_value)
            max_bits_value = bits;
    }

    // we add an extra bit to account for the special moduli selection logic in BGV and CKKS
    // ignore the case when there is only one max size modulus
    if (add_one && (max_bits_value != aux_bits))
        max_bits_value++;

    // Select number of primes in auxiliary CRT basis
    uint32_t size_p = static_cast<uint32_t>(std::ceil(static_cast<double>(max_bits_value) / aux_bits));

    // We want to make sure that P exceeds the maximum digit in Q by a safe margin.
    // The safe margin is chosen to make hybrid key switching error closer to the modulus switching error.
    // The margin of 4 bits accounts for dnum * 3.19 for typical values of dnum. See the noise expression
    // in Section B.2.3 of https://eprint.iacr.org/2021/204 for more details.
    // Composite scaling uses a base margin of 6 bits, and the fast basis extension overflow grows
    // linearly with the number of limbs per digit, adding ceil(log2(composite_degree)) bits.
    uint32_t margin = (scal_tech == COMPOSITESCALINGAUTO || scal_tech == COMPOSITESCALINGMANUAL) ?
                              6 + get_msb64(composite_degree - 1) :
                              4;
    if (static_cast<uint64_t>(size_p) * aux_bits - max_bits_value < margin)
        ++size_p;

    size_p_estimate_global = size_p;

    return std::make_pair(size_p * aux_bits, size_p);
}

}  // namespace cipher
