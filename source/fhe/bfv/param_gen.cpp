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

#define PROFILE

#include "cipher/fhe/bfv/param_gen.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "cipher/fhe/bfv/crypto_params.h"
#include "cipher/fhe/config/scheme_utils.h"

namespace cipher {

bool BfvRnsParamGen::params_gen_bfvrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params,
                                                        uint32_t eval_add_count, uint32_t multiplicative_depth,
                                                        uint32_t key_switch_count, size_t dcrt_bits, uint32_t n_custom,
                                                        uint32_t num_digits) const {
    if (!crypto_params)
        CIPHER_THROW("No crypto parameters are supplied to BFVrns ParamsGen");

    if ((dcrt_bits < DCRT_MODULUS::MIN_SIZE) || (dcrt_bits > DCRT_MODULUS::MAX_SIZE)) {
        CIPHER_THROW("Number of bits in CRT moduli should be in the range from " +
                      std::to_string(DCRT_MODULUS::MIN_SIZE) + " to " + std::to_string(DCRT_MODULUS::MAX_SIZE));
    }

    const auto crypto_params_bfvrns = std::dynamic_pointer_cast<BfvRnsCryptoParams>(crypto_params);

    KeySwitchTechnique ks_tech = crypto_params_bfvrns->get_key_switch_technique();
    ScalingTechnique scal_tech = crypto_params_bfvrns->get_scaling_technique();
    EncryptionTechnique enc_tech = crypto_params_bfvrns->get_encryption_technique();
    MultiplicationTechnique mult_tech = crypto_params_bfvrns->get_multiplication_technique();
    ProxyReEncryptionMode pre_mode = crypto_params_bfvrns->get_pre_mode();
    MultipartyMode multiparty_mode = crypto_params_bfvrns->get_multiparty_mode();

    if ((pre_mode != INDCPA) && (pre_mode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << pre_mode << " is not supported for BFVRNS";
        CIPHER_THROW(s.str());
    }

    double sigma = crypto_params_bfvrns->get_distribution_parameter();
    double alpha = crypto_params_bfvrns->get_assurance_measure();
    double p = static_cast<double>(crypto_params_bfvrns->get_plaintext_modulus());
    uint32_t digit_size = crypto_params_bfvrns->get_digit_size();
    SecurityLevel std_level = crypto_params_bfvrns->get_std_level();
    uint32_t aux_bits = DCRT_MODULUS::MAX_SIZE;

    // Bound of the Gaussian error polynomial
    double berr = sigma * std::sqrt(alpha);

    // Bound of the key polynomial
    double bkey = 0;

    DistributionType dist_type;

    uint32_t threshold_parties = crypto_params_bfvrns->get_threshold_num_of_parties();
    // supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution
    // (UNIFORM_TERNARY) cases
    if (crypto_params_bfvrns->get_secret_key_dist() == GAUSSIAN) {
        bkey = std::sqrt(threshold_parties) * berr;
        dist_type = HEStd_error;
    } else {
        // Bkey set to threshold_parties * 1 for ternary distribution
        bkey = threshold_parties;
        dist_type = HEStd_ternary;
    }

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

    // GAUSSIAN security constraint
    auto n_rlwe = [&](double logq) -> double {
        if (std_level == HEStd_NotSet) {
            return 0;
        } else {
            // takes into account the noise added during the threshold FHE instantiation of BFV
            if (multiparty_mode == NOISE_FLOODING_MULTIPARTY)
                logq += crypto_params_bfvrns->estimate_multiparty_flooding_log_q();
            // adds logP in the case of HYBRID key switching
            if (ks_tech == HYBRID) {
                // number of RNS limbs
                uint32_t k = static_cast<uint32_t>(std::ceil(std::ceil(logq) / dcrt_bits));
                // set the number of digits
                uint32_t num_part_q = compute_num_large_digits(num_digits, k - 1);
                auto hybrid_ks_info =
                        RnsCryptoParams::estimate_log_p(num_part_q, dcrt_bits, dcrt_bits, 0, k, aux_bits, scal_tech);
                logq += std::get<0>(hybrid_ks_info);
            }
            return static_cast<double>(
                    StdLatticeParm::find_ring_dim(dist_type, std_level, static_cast<uint32_t>(std::ceil(logq))));
        }
    };

    auto noise_ks = [&](uint32_t n, double logq_prev, double w, bool mult_value) -> double {
        if (ks_tech == HYBRID) {
            // conservative estimate for HYBRID to avoid the use of method of
            // iterative approximations; we do not know the number
            // of digits and moduli at this point and use upper bounds
            double num_towers = std::ceil(logq_prev / dcrt_bits);
#if defined(CIPHER_WITH_REDUCED_NOISE)
            return num_towers * (delta(n) * berr + delta_ms(n) * bkey + 1.0) / 2.0;
#else
            return num_towers * (delta(n) * berr + delta_ms(n) * bkey + 1.0);
#endif
        } else {
            double num_digits_per_tower = (digit_size == 0) ? 1 : ((dcrt_bits / digit_size) + 1);
            return delta(n) * num_digits_per_tower * (std::floor(logq_prev / (dcrt_bits)) + 1) * w * berr / 2.0;
        }
    };

    // initial values
    uint32_t n = (n_custom != 0) ? n_custom : 512;

    double logq = 0.;

    // only public key encryption and eval_add (optional when eval_add_count = 0)
    // operations are supported the correctness constraint from section 3.5 of
    // https://eprint.iacr.org/2014/062.pdf is used
    // optimization (noise reduction) from Section 3.1 of https://eprint.iacr.org/2021/204.pdf
    // is also applied
    if ((multiplicative_depth == 0) && (key_switch_count == 0)) {
        // Correctness constraint
        auto logq_bfv = [&](uint32_t n) -> double {
            return std::log2(p * (4 * ((eval_add_count + 1) * vnorm(n) + eval_add_count) + p));
        };

        // initial value
        logq = logq_bfv(n);

        while (n_rlwe(logq) > n) {
            n = 2 * n;
            logq = logq_bfv(n);
        }

        // this code updates n and q to account for the discrete size of CRT moduli
        // = dcrt_bits
        int32_t k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));

        double logq_ceil = k * dcrt_bits;

        while (n_rlwe(logq_ceil) > n) {
            n = 2 * n;
            logq = logq_bfv(n);
            k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));
            logq_ceil = k * dcrt_bits;
        }
    } else if ((multiplicative_depth == 0) && (key_switch_count > 0) && (eval_add_count == 0)) {
        // this case supports automorphism w/o any other operations
        // base for relinearization

        double w = std::pow(2, (digit_size == 0 ? dcrt_bits : digit_size));

        // Correctness constraint
        auto logq_bfv = [&](uint32_t n, double logq_prev) -> double {
            return std::log2(p * (4 * (vnorm(n) + key_switch_count * noise_ks(n, logq_prev, w, false)) + p));
        };

        // initial values
        double logq_prev = 6. * std::log2(10);
        logq = logq_bfv(n, logq_prev);
        logq_prev = logq;

        // increases n up to the level where desired security level is achieved
        while (n_rlwe(logq) > n) {
            n = 2 * n;
            logq = logq_bfv(n, logq_prev);
            logq_prev = logq;
        }

        logq = logq_bfv(n, logq_prev);

        // let logq converge with prescribed accuracy
        while (std::fabs(logq - logq_prev) > std::log2(1.001)) {
            logq_prev = logq;
            logq = logq_bfv(n, logq_prev);
        }

        // this code updates n and q to account for the discrete size of CRT
        // moduli = dcrt_bits
        int32_t k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));

        double logq_ceil = k * dcrt_bits;
        logq_prev = logq_ceil;

        while (n_rlwe(logq_ceil) > n) {
            n = 2 * n;
            logq = logq_bfv(n, logq_prev);
            k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));
            logq_ceil = k * dcrt_bits;
            logq_prev = logq_ceil;
        }
    } else if ((eval_add_count == 0) && (multiplicative_depth > 0) && (key_switch_count == 0)) {
        // Only eval_mult operations are used in the correctness constraint
        // the correctness constraint from Section 3.1 of https://eprint.iacr.org/2021/204.pdf
        // is used

        // base for relinearization
        double w = std::pow(2, (digit_size == 0 ? dcrt_bits : digit_size));

        // function used in the eval_mult constraint
        auto C1 = [&](uint32_t n) -> double {
            return delta(n) * delta_ms(n) * p * bkey;
        };

        // function used in the eval_mult constraint
        auto C2 = [&](uint32_t n, double logq_prev) -> double {
            return delta(n) * delta_ms(n) * bkey * bkey / 2.0 + noise_ks(n, logq_prev, w, true);
        };

        // main correctness constraint
        auto logq_bfv = [&](uint32_t n, double logq_prev) -> double {
            return std::log2(4 * p) + (multiplicative_depth - 1) * std::log2(C1(n)) +
                   std::log2(C1(n) * vnorm(n) + multiplicative_depth * C2(n, logq_prev));
        };

        // initial values
        double logq_prev = 6. * std::log2(10);
        logq = logq_bfv(n, logq_prev);
        logq_prev = logq;

        // increases n up to the level where desired security level is achieved
        while (n_rlwe(logq) > n) {
            n = 2 * n;
            logq = logq_bfv(n, logq_prev);
            logq_prev = logq;
        }

        logq = logq_bfv(n, logq_prev);

        // let logq converge with prescribed accuracy
        while (std::fabs(logq - logq_prev) > std::log2(1.001)) {
            logq_prev = logq;
            logq = logq_bfv(n, logq_prev);
        }

        // this code updates n and q to account for the discrete size of CRT
        // moduli = dcrt_bits

        int32_t k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));

        double logq_ceil = k * dcrt_bits;
        logq_prev = logq_ceil;

        while (n_rlwe(logq_ceil) > n) {
            n = 2 * n;
            logq = logq_bfv(n, logq_prev);
            k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrt_bits));
            logq_ceil = k * dcrt_bits;
            logq_prev = logq_ceil;
        }
    } else if ((multiplicative_depth && (eval_add_count || key_switch_count)) || (eval_add_count && key_switch_count)) {
        // throw an exception if at least 2 variables are not zero
        std::string err_msg("multiplicativeDepth, evalAddCount and keySwitchCount are incorrectly set to [ ");
        err_msg += std::to_string(multiplicative_depth) + ", ";
        err_msg += std::to_string(eval_add_count) + ", ";
        err_msg += std::to_string(key_switch_count) + " ]. Only one of them can be non-zero.";

        CIPHER_THROW(err_msg);
    }

    if ((n > n_custom) && (n_custom != 0))
        CIPHER_THROW("Ring dimension " + std::to_string(n_custom) +
                      " specified by the user does not meet the "
                      "security requirement. Please increase it to " +
                      std::to_string(n) + ".");

    const size_t num_initial_moduli = static_cast<size_t>(std::ceil(std::ceil(logq) / dcrt_bits));
    if (num_initial_moduli < 1)
        CIPHER_THROW("numInitialModuli must be greater than 0.");
    const size_t size_q = multiparty_mode == NOISE_FLOODING_MULTIPARTY ?
                                 num_initial_moduli + NoiseFlooding::NUM_MODULI_MULTIPARTY :
                                 num_initial_moduli;

    std::vector<NativeInteger> moduli_q(size_q);
    std::vector<NativeInteger> roots_q(size_q);

    // makes sure the first integer is less than 2^60-1
    moduli_q[0] = last_prime<NativeInteger>(dcrt_bits, 2 * n);
    roots_q[0] = root_of_unity<NativeInteger>(2 * n, moduli_q[0]);
    NativeInteger last_modulus = moduli_q[0];

    if (multiparty_mode == NOISE_FLOODING_MULTIPARTY) {
        moduli_q[1] = last_prime<NativeInteger>(NoiseFlooding::MULTIPARTY_MOD_SIZE, 2 * n);
        if (moduli_q[1] == last_modulus) {
            moduli_q[1] = previous_prime<NativeInteger>(moduli_q[1], 2 * n);
            last_modulus = moduli_q[1];
        }
        roots_q[1] = root_of_unity<NativeInteger>(2 * n, moduli_q[1]);

        for (size_t i = 2; i < 1 + NoiseFlooding::NUM_MODULI_MULTIPARTY; i++) {
            moduli_q[i] = previous_prime<NativeInteger>(moduli_q[i - 1], 2 * n);
            roots_q[i] = root_of_unity<NativeInteger>(2 * n, moduli_q[i]);
            if (last_modulus != moduli_q[0])
                last_modulus = moduli_q[i];
        }
    }

    size_t index = 1 + (size_q - num_initial_moduli);
    if (index < size_q) {
        moduli_q[index] = previous_prime<NativeInteger>(last_modulus, 2 * n);
        roots_q[index] = root_of_unity<NativeInteger>(2 * n, moduli_q[index]);
        for (size_t i = index + 1; i < size_q; i++) {
            moduli_q[i] = previous_prime<NativeInteger>(moduli_q[i - 1], 2 * n);
            roots_q[i] = root_of_unity<NativeInteger>(2 * n, moduli_q[i]);
        }
    }

    auto params = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_q, roots_q);

    ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_q, 2 * n, moduli_q);

    crypto_params_bfvrns->set_element_params(params);

    const EncodingParams encoding_params = crypto_params_bfvrns->get_encoding_params();
    if (encoding_params->get_batch_size() > n)
        CIPHER_THROW("The batch size cannot be larger than the ring dimension.");

    if (encoding_params->get_batch_size() & (encoding_params->get_batch_size() - 1))
        CIPHER_THROW("The batch size can only be set to zero (for full packing) or a power of two.");

    // if no batch size was specified, we set batch_size = n by default (for full
    // packing)
    if (encoding_params->get_batch_size() == 0) {
        uint32_t batch_size = n;
        EncodingParams encoding_params_new(
                std::make_shared<EncodingParamsImpl>(encoding_params->get_plaintext_modulus(), batch_size));
        crypto_params_bfvrns->set_encoding_params(encoding_params_new);
    }

    uint32_t num_part_q = compute_num_large_digits(num_digits, size_q - 1);

    crypto_params_bfvrns->precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, 0);

    // Validate the ring dimension found using estimated log_q(P) against actual log_q(P)
    if (std_level != HEStd_NotSet) {
        uint32_t log_actual_q = 0;
        if (ks_tech == HYBRID) {
            log_actual_q = crypto_params_bfvrns->get_params_qp()->get_modulus().get_msb();
        } else {
            log_actual_q = crypto_params_bfvrns->get_element_params()->get_modulus().get_msb();
        }

        uint32_t n_actual = StdLatticeParm::find_ring_dim(dist_type, std_level, log_actual_q);
        if (n < n_actual) {
            std::string err_msg("The ring dimension found using estimated logQ(P) [");
            err_msg += std::to_string(n) + "] does not meet security requirements. ";
            err_msg += "Report this problem to OpenFHE developers and set the ring dimension manually to ";
            err_msg += std::to_string(n_actual) + ".";

            CIPHER_THROW(err_msg);
        }
    }

    return true;
}

}  // namespace cipher
