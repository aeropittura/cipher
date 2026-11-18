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

#include "cipher/fhe/bgv/param_gen.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/bgv/crypto_params.h"

namespace cipher {

uint32_t BgvRnsParamGen::compute_ring_dimension(
        const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t q_bound,
        uint32_t cycl_order) const {
    const auto crypto_params_bgvrns = std::dynamic_pointer_cast<BgvRnsCryptoParams>(crypto_params);

    // GAUSSIAN security constraint
    DistributionType dist_type = (crypto_params_bgvrns->get_secret_key_dist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;

    // HE Standards compliance logic/check
    SecurityLevel std_level = crypto_params_bgvrns->get_std_level();

    uint32_t ring_dimension_value = cycl_order / 2;

    // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
    if (std_level != HEStd_NotSet) {
        auto he_std_n = StdLatticeParm::find_ring_dim(dist_type, std_level, q_bound);
        if (ring_dimension_value == 0) {
            // Case 2: SecurityLevel specified, but ring dimension not specified
            // Choose ring dimension based on security standards
            ring_dimension_value = he_std_n;
        } else if (ring_dimension_value < he_std_n) {
            // Case 3: Both SecurityLevel and ring dimension specified
            // Check whether particular selection is standards-compliant
            CIPHER_THROW("The specified ring dimension (" + std::to_string(ring_dimension_value) +
                          ") does not comply with HE standards recommendation (" + std::to_string(he_std_n) + ").");
        }
    } else if (ring_dimension_value == 0) {
        CIPHER_THROW("Please specify the ring dimension or desired security level.");
    }
    return ring_dimension_value;
}

BgvNoiseEstimates BgvRnsParamGen::compute_noise_estimates(
        const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t ring_dimension_value,
        uint32_t eval_add_count, uint32_t key_switch_count, uint32_t aux_towers, uint32_t num_primes_value) const {
    const auto crypto_params_bgvrns = std::dynamic_pointer_cast<BgvRnsCryptoParams>(crypto_params);
    uint32_t digit_size = crypto_params_bgvrns->get_digit_size();
    KeySwitchTechnique ks_tech = crypto_params_bgvrns->get_key_switch_technique();
    ScalingTechnique scal_tech = crypto_params_bgvrns->get_scaling_technique();
    double sigma = crypto_params_bgvrns->get_distribution_parameter();
    double alpha = crypto_params_bgvrns->get_assurance_measure();

    // Bound of the Gaussian error polynomial
    double berr = sigma * std::sqrt(alpha);
    // Bound of the key polynomial
    // supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution
    // (UNIFORM_TERNARY) cases
    uint32_t threshold_parties = crypto_params_bgvrns->get_threshold_num_of_parties();

    // Bkey set to threshold_parties * 1 for ternary distribution
    double bkey = (crypto_params_bgvrns->get_secret_key_dist() == GAUSSIAN) ? std::sqrt(threshold_parties) * berr :
                                                                         threshold_parties;
    // delta for multiplication of a Gaussian polynomial by a random polynomial
    auto expansion_factor = 2. * std::sqrt(ring_dimension_value);
    // delta for modulus switching
    auto expansion_factor_ms = 4. * std::sqrt(ring_dimension_value);
    // Vnorm
    auto fresh_encryption_noise = berr * (1. + 2. * expansion_factor * bkey);

    double key_switching_noise = 0;
    if (ks_tech == BV) {
        if (digit_size == 0) {
            CIPHER_THROW("digitSize is not allowed to be 0 for BV key switching in BGV when scalingModSize = 0.");
        }
        double relin_base = std::pow(2.0, digit_size);
        uint32_t mod_size_estimate = DCRT_MODULUS::MAX_SIZE;
        uint32_t num_windows = (mod_size_estimate / digit_size) + 1;
        key_switching_noise = num_windows * num_primes_value * expansion_factor * relin_base * berr / 2.0;
    } else {
        double num_towers_per_digit = crypto_params_bgvrns->get_num_per_part_q();
        double num_digits = crypto_params_bgvrns->get_num_part_q();
        key_switching_noise = num_towers_per_digit * num_digits * expansion_factor * berr;
        key_switching_noise += aux_towers * (1. + expansion_factor_ms * bkey);
#if defined(CIPHER_WITH_REDUCED_NOISE)
        key_switching_noise /= 2.0;
#endif
    }

    // V_ms
    auto mod_switching_noise = (1. + expansion_factor_ms * bkey) / 2.;

    // V_c
    double noise_per_level = 0;
    if (scal_tech == FLEXIBLEAUTOEXT) {
        noise_per_level = 1. + expansion_factor_ms * bkey;
    } else {
        noise_per_level = (eval_add_count + 1.) * fresh_encryption_noise + (key_switch_count + 1.) * key_switching_noise;
    }

    return BgvNoiseEstimates(berr, bkey, expansion_factor, fresh_encryption_noise, key_switching_noise, mod_switching_noise,
                             noise_per_level);
}

uint64_t BgvRnsParamGen::get_cyclic_order(const uint32_t ring_dimension_value, const int plain_modulus,
                                                   const ScalingTechnique scal_tech) const {
    // Moduli need to be primes that are 1 (mod 2n)
    uint32_t cycl_order = 2 * ring_dimension_value;
    uint64_t lcm_cycl_order_ptm = 0;

    if (scal_tech == FIXEDAUTO) {
        // In FIXEDAUTO, moduli also need to be 1 (mod t)
        uint32_t plaintext_modulus = plain_modulus;
        uint32_t pow2ptm = 1;  // The largest power of 2 dividing ptm (check whether it
                               // is larger than cycl_order or not)
        while (plaintext_modulus % 2 == 0) {
            plaintext_modulus >>= 1;
            pow2ptm <<= 1;
        }

        if (pow2ptm < cycl_order)
            pow2ptm = cycl_order;

        lcm_cycl_order_ptm = static_cast<uint64_t>(pow2ptm) * plaintext_modulus;
    } else {
        lcm_cycl_order_ptm = cycl_order;
    }
    return lcm_cycl_order_ptm;
}

std::pair<std::vector<NativeInteger>, uint32_t> BgvRnsParamGen::compute_moduli(
        const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t ring_dimension_value,
        uint32_t eval_add_count, uint32_t key_switch_count, uint32_t aux_towers, uint32_t num_primes_value) const {
    if (num_primes_value < 1) {
        CIPHER_THROW("numPrimes must be at least 1");
    }

    const auto crypto_params_bgvrns = std::dynamic_pointer_cast<BgvRnsCryptoParams>(crypto_params);
    ScalingTechnique scal_tech = crypto_params_bgvrns->get_scaling_technique();

    size_t num_moduli = scal_tech == FLEXIBLEAUTOEXT ? num_primes_value + 1 : num_primes_value;
    std::vector<NativeInteger> moduli_q(num_moduli);

    uint64_t plain_modulus = crypto_params_bgvrns->get_plaintext_modulus();
    NativeInteger plain_modulus_int = NativeInteger(plain_modulus);

    BgvNoiseEstimates noise_estimates =
            compute_noise_estimates(crypto_params, ring_dimension_value, eval_add_count, key_switch_count, aux_towers, num_primes_value);
    uint64_t cycl_order = get_cyclic_order(ring_dimension_value, plain_modulus, scal_tech);

    double first_mod_lower_bound = 0;
    if (scal_tech == FLEXIBLEAUTOEXT)
        first_mod_lower_bound = 2.0 * plain_modulus * noise_estimates.fresh_encryption_noise - plain_modulus;
    else
        first_mod_lower_bound = 2.0 * plain_modulus * noise_estimates.noise_per_level - plain_modulus;
    uint32_t first_mod_size_value = std::ceil(std::log2(first_mod_lower_bound));
    if (first_mod_size_value >= DCRT_MODULUS::MAX_SIZE) {
        CIPHER_THROW(std::string("Reduce the number of additions or key switches per level or the digit size. ") +
                      "We do not support moduli greater than " + std::to_string(DCRT_MODULUS::MAX_SIZE) + " bits.");
    }

    moduli_q[0] = first_prime<NativeInteger>(first_mod_size_value, cycl_order);

    if (scal_tech == FLEXIBLEAUTOEXT) {
        double extra_mod_lower_bound =
                noise_estimates.fresh_encryption_noise / noise_estimates.noise_per_level * (eval_add_count + 1);
        extra_mod_lower_bound += key_switch_count * noise_estimates.key_switching_noise / noise_estimates.noise_per_level;
        extra_mod_lower_bound *= 2;
        uint32_t extra_mod_size = std::ceil(std::log2(extra_mod_lower_bound));

        if (extra_mod_size >= DCRT_MODULUS::MAX_SIZE) {
            CIPHER_THROW(std::string("Reduce the number of additions or key switches per level or the digit size. ") +
                          "We do not support moduli greater than " + std::to_string(DCRT_MODULUS::MAX_SIZE) + " bits.");
        }

        moduli_q[num_primes_value] = first_prime<NativeInteger>(extra_mod_size, cycl_order);
        while (moduli_q[num_primes_value] == moduli_q[0] || moduli_q[num_primes_value] == plain_modulus_int) {
            moduli_q[num_primes_value] = next_prime<NativeInteger>(moduli_q[num_primes_value], cycl_order);
        }
    }

    if (num_primes_value > 1) {
        // Compute bounds.
        double mod_lower_bound = 0;
        if (scal_tech == FLEXIBLEAUTOEXT) {
            mod_lower_bound = 2 * noise_estimates.noise_per_level + 2 +
                            std::sqrt(ring_dimension_value) / 2.0 / noise_estimates.noise_per_level;
            mod_lower_bound *= noise_estimates.expansion_factor * plain_modulus * (eval_add_count + 1) / 2.0;
            mod_lower_bound += (key_switch_count + 1) * noise_estimates.key_switching_noise / noise_estimates.noise_per_level;
            mod_lower_bound *= 2;
        } else {
            double mod_lower_bound_numerator = 2 * noise_estimates.noise_per_level * noise_estimates.noise_per_level +
                                            2 * noise_estimates.noise_per_level + std::sqrt(ring_dimension_value) / 2.0;
            mod_lower_bound_numerator *= noise_estimates.expansion_factor * plain_modulus / 2. * (eval_add_count + 1);
            mod_lower_bound_numerator += (key_switch_count + 1) * noise_estimates.key_switching_noise;
            double mod_lower_bound_denom = noise_estimates.noise_per_level - noise_estimates.mod_switching_noise;
            mod_lower_bound = mod_lower_bound_numerator / mod_lower_bound_denom;
        }

        uint32_t mod_size = std::ceil(std::log2(mod_lower_bound));
        if (mod_size >= DCRT_MODULUS::MAX_SIZE) {
            CIPHER_THROW(std::string("Reduce the number of additions or key switches per level or the digit size. ") +
                          "We do not support moduli greater than " + std::to_string(DCRT_MODULUS::MAX_SIZE) + " bits.");
        }

        // Compute moduli.
        moduli_q[1] = first_prime<NativeInteger>(mod_size, cycl_order);
        if (scal_tech == FLEXIBLEAUTOEXT) {
            while (moduli_q[1] == moduli_q[0] || moduli_q[1] == moduli_q[num_primes_value] || moduli_q[1] == plain_modulus_int) {
                moduli_q[1] = next_prime<NativeInteger>(moduli_q[1], cycl_order);
            }

            for (size_t i = 2; i < num_primes_value; i++) {
                moduli_q[i] = next_prime<NativeInteger>(moduli_q[i - 1], cycl_order);
                while (moduli_q[i] == moduli_q[0] || moduli_q[i] == moduli_q[num_primes_value] || moduli_q[i] == plain_modulus_int) {
                    moduli_q[i] = next_prime<NativeInteger>(moduli_q[i], cycl_order);
                }
            }
        } else {
            while (moduli_q[1] == moduli_q[0] || moduli_q[1] == plain_modulus_int) {
                moduli_q[1] = next_prime<NativeInteger>(moduli_q[1], cycl_order);
            }

            for (size_t i = 2; i < num_primes_value; i++) {
                moduli_q[i] = next_prime<NativeInteger>(moduli_q[i - 1], cycl_order);
                while (moduli_q[i] == moduli_q[0] || moduli_q[i] == plain_modulus_int) {
                    moduli_q[i] = next_prime<NativeInteger>(moduli_q[i], cycl_order);
                }
            }
        }
    }

    BigInteger composite(1);
    for (BigInteger m : moduli_q)
        composite *= m;

    return std::make_pair(moduli_q, composite.get_msb());
}

void BgvRnsParamGen::initialize_flooding_dgg(
        const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t num_primes_value,
        uint32_t ring_dimension_value) const {
    const auto crypto_params_bgvrns = std::dynamic_pointer_cast<BgvRnsCryptoParams>(crypto_params);

    KeySwitchTechnique ks_tech = crypto_params_bgvrns->get_key_switch_technique();
    ProxyReEncryptionMode pre_mode = crypto_params_bgvrns->get_pre_mode();

    // compute the flooding distribution parameter based on the security mode for pre
    // get the re-encryption level and set the level after re-encryption
    double sigma = crypto_params_bgvrns->get_distribution_parameter();
    double alpha = crypto_params_bgvrns->get_assurance_measure();
    uint32_t r = crypto_params_bgvrns->get_digit_size();
    double b_e = std::sqrt(alpha) * sigma;
    uint32_t aux_bits = DCRT_MODULUS::MAX_SIZE;
    uint32_t threshold_parties = crypto_params_bgvrns->get_threshold_num_of_parties();
    // bound on the secret key is sigma*sqrt(alpha)*sqrt(threshold_parties) if the secret is sampled from discrete gaussian distribution
    // and is 1 * threshold number of parties if the secret is sampled from ternary distribution. The threshold number of
    // parties is 1 by default but can be set to the number of parties in a threshold application.
    // Bkey set to threshold_parties * 1 for ternary distribution
    double bkey =
            (crypto_params_bgvrns->get_secret_key_dist() == GAUSSIAN) ? b_e * std::sqrt(threshold_parties) : threshold_parties;

    double stat_sec_half = crypto_params_bgvrns->get_statistical_security() / 2;
    double num_queries = crypto_params_bgvrns->get_num_adversarial_queries();

    // get the flooding discrete gaussian distribution
    auto dgg_flooding = crypto_params_bgvrns->get_flooding_discrete_gaussian_generator();
    double noise_param = 1;
    if (pre_mode == FIXED_NOISE_HRA) {
        noise_param = NoiseFlooding::PRE_SD;
    } else if (pre_mode == NOISE_FLOODING_HRA) {
        // delta for multiplication of a Gaussian polynomial by a random polynomial
        auto expansion_factor = 2. * std::sqrt(ring_dimension_value);
        // delta for modulus switching
        auto expansion_factor_ms = 4. * std::sqrt(ring_dimension_value);
        // re-randomization noise
        auto fresh_encryption_noise = b_e * (1. + 2. * expansion_factor * bkey);

        if (ks_tech == BV) {
            if (r > 0) {
                // sqrt(12*num_queries) * pow(2, stat_sec_half) factor required for security analysis
                // 2*fresh_encryption_noise is done because after modulus switching the noise will be
                // bounded by fresh_encryption_noise
                // Note: std::pow(2, stat_sec_half - 1) == std::pow(2, stat_sec_half) / 2.0
                noise_param = std::sqrt(12 * num_queries) * std::pow(2, stat_sec_half - 1) *
                              (2 * fresh_encryption_noise +
                               num_primes_value * (aux_bits / r + 1) * expansion_factor * (std::pow(2, r) - 1) * b_e);
            } else {
                CIPHER_THROW("Digit size value cannot be 0 for BV keyswitching");
            }
        } else if (ks_tech == HYBRID) {
            if (r == 0) {
                // 2*fresh_encryption_noise is done because after modulus switching the noise will be
                // bounded by fresh_encryption_noise
                noise_param = 2 * fresh_encryption_noise;
                // we use num_primes_value here as an approximation of num_digits * [towers per digit]
                noise_param += num_primes_value * expansion_factor * b_e / 2.0;
                // we use num_primes_value (larger bound) instead of auxPrimes because we do not know auxPrimes yet
                noise_param += num_primes_value * (1 + expansion_factor_ms * bkey) / 2.0;
                // sqrt(12*num_queries) * pow(2, stat_sec_half) factor required for security analysis
                noise_param = std::sqrt(12 * num_queries) * std::pow(2, stat_sec_half) * noise_param;
            } else {
                CIPHER_THROW("Digit size can only be zero for Hybrid keyswitching");
            }
        }
    }
    // set the flooding distribution parameter to the distribution.
    dgg_flooding.set_std(noise_param);
    const auto crypto_params_rns = std::dynamic_pointer_cast<RnsCryptoParams>(crypto_params);
    crypto_params_rns->set_flooding_distribution_parameter(noise_param);
}

bool BgvRnsParamGen::params_gen_bgvrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params,
                                                        uint32_t eval_add_count, uint32_t key_switch_count,
                                                        uint32_t cycl_order, uint32_t num_primes_value, uint32_t first_mod_size_value,
                                                        uint32_t dcrt_bits, uint32_t num_part_q, uint32_t num_hops) const {
    const auto crypto_params_bgvrns = std::dynamic_pointer_cast<BgvRnsCryptoParams>(crypto_params);

    uint32_t ptm = crypto_params_bgvrns->get_plaintext_modulus();
    KeySwitchTechnique ks_tech = crypto_params_bgvrns->get_key_switch_technique();
    ScalingTechnique scal_tech = crypto_params_bgvrns->get_scaling_technique();
    EncryptionTechnique enc_tech = crypto_params_bgvrns->get_encryption_technique();
    MultiplicationTechnique mult_tech = crypto_params_bgvrns->get_multiplication_technique();
    ProxyReEncryptionMode pre_mode = crypto_params_bgvrns->get_pre_mode();
    MultipartyMode multiparty_mode = crypto_params_bgvrns->get_multiparty_mode();
    if (!ptm)
        CIPHER_THROW("plaintextModulus cannot be zero.");

    if ((pre_mode != INDCPA) && (pre_mode != FIXED_NOISE_HRA) && (pre_mode != NOISE_FLOODING_HRA) &&
        (pre_mode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << pre_mode << " is not supported for BGVRNS";
        CIPHER_THROW(s.str());
    }

    uint32_t ring_dimension_value = cycl_order / 2;
    initialize_flooding_dgg(crypto_params, num_hops, ring_dimension_value);

    if (scal_tech == FIXEDMANUAL) {
        if (pre_mode != NOISE_FLOODING_HRA) {
            // Select the size of moduli according to the plaintext modulus
            if (dcrt_bits == 0) {
                dcrt_bits =
                        ((28 + get_msb64(ptm)) > DCRT_MODULUS::MAX_SIZE) ? DCRT_MODULUS::MAX_SIZE : (28 + get_msb64(ptm));
            }
            // Select first_mod_size_value to be dcrt_bits if not indicated otherwise
            if (first_mod_size_value == 0)
                first_mod_size_value = dcrt_bits;
        } else {
            // we only support PRE in the HRA-secure mode; no FHE operations are supported yet
            num_primes_value = num_hops;

            double sigma = crypto_params_bgvrns->get_distribution_parameter();
            double alpha = crypto_params_bgvrns->get_assurance_measure();

            // Bound of the Gaussian error polynomial
            double berr = sigma * std::sqrt(alpha);

            // Bound of the key polynomial supports both
            // discrete Gaussian (GAUSSIAN) and ternary uniform distribution (UNIFORM_TERNARY) cases
            uint32_t threshold_parties = crypto_params_bgvrns->get_threshold_num_of_parties();
            // Bkey set to threshold_parties * 1 for ternary distribution
            double bkey = (crypto_params_bgvrns->get_secret_key_dist() == GAUSSIAN) ? std::sqrt(threshold_parties) * berr :
                                                                                 threshold_parties;
            // delta
            auto expansion_factor = 2. * std::sqrt(ring_dimension_value);
            // Vnorm
            auto fresh_encryption_noise = berr * (1. + 2. * expansion_factor * bkey);

            // the logic for finding the parameters for NOISE_FLOODING_HRA
            double flooding_bound = alpha * crypto_params_bgvrns->get_flooding_distribution_parameter();
            double first_mod_lower_bound = 2.0 * ptm * flooding_bound - ptm;
            first_mod_size_value = std::ceil(std::log2(first_mod_lower_bound));

            // Use one modulus if the first hop fits in 60 bits
            // Otherwise use two moduli
            if (first_mod_size_value > DCRT_MODULUS::MAX_SIZE) {
                first_mod_size_value = 20;
                num_primes_value++;
            }

            // selects the size of moduli for individual hops
            // the noise after modulus swicthing is set to roughly the fresh encryption noise
            // which is significantly less than fresh encryption noise + key switching noise that is incurred as
            // part of proxy re-encryption
            double dcrt_bits_noise = flooding_bound / fresh_encryption_noise;
            dcrt_bits = std::ceil(std::log2(dcrt_bits_noise));

            // check that the mod size needed for each hop fits in 60 bits
            if (dcrt_bits > DCRT_MODULUS::MAX_SIZE) {
                CIPHER_THROW("The modulus size for HRA-secure PRE (" + std::to_string(dcrt_bits) +
                              " bits) is above the maximum:" + std::to_string(DCRT_MODULUS::MAX_SIZE) +
                              ". Try reducing reducing the parameters for noise flooding.");
            }
        }
    }

    // Size of modulus P
    uint32_t aux_bits = DCRT_MODULUS::MAX_SIZE;

    // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
    uint32_t extra_mod_size = (scal_tech == FLEXIBLEAUTOEXT) ? DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE : 0;
    uint32_t q_bound = first_mod_size_value + (num_primes_value - 1) * dcrt_bits + extra_mod_size;

    // estimate the extra modulus Q needed for threshold FHE flooding
    if (multiparty_mode == NOISE_FLOODING_MULTIPARTY)
        q_bound += crypto_params_bgvrns->estimate_multiparty_flooding_log_q();

    uint32_t aux_towers = 0;
    if (ks_tech == HYBRID) {
        // we add an extra bit to account for the special logic of selecting the RNS moduli in BGV
        // ignore the case when there is only one max size modulus
        // no extra bit needs to be added for FIXEDMANUAL
        bool add_one = false;
        if ((q_bound != aux_bits) && (scal_tech != FIXEDMANUAL)) {
            q_bound++;
            add_one = true;
        }

        uint32_t num_primes_est = num_primes_value;
        bool is_noise_flooding_multiparty = (multiparty_mode == NOISE_FLOODING_MULTIPARTY);
        if (is_noise_flooding_multiparty)
            num_primes_est += NoiseFlooding::NUM_MODULI_MULTIPARTY;
        auto hybrid_ks_info =
                RnsCryptoParams::estimate_log_p(num_part_q, first_mod_size_value, dcrt_bits, extra_mod_size, num_primes_est, aux_bits,
                                                  scal_tech, add_one, is_noise_flooding_multiparty);
        q_bound += std::get<0>(hybrid_ks_info);
        aux_towers = std::get<1>(hybrid_ks_info);
    }

    // HE Standards compliance logic/check
    uint32_t n = compute_ring_dimension(crypto_params, q_bound, cycl_order);

    uint32_t vec_size = (scal_tech != FLEXIBLEAUTOEXT) ? num_primes_value : num_primes_value + 1;
    std::vector<NativeInteger> moduli_q(vec_size);
    std::vector<NativeInteger> roots_q(vec_size);
    uint64_t modulus_order = 0;

    if ((dcrt_bits == 0) && (scal_tech == FIXEDAUTO || scal_tech == FLEXIBLEAUTO || scal_tech == FLEXIBLEAUTOEXT)) {
        auto moduli_info = compute_moduli(crypto_params, n, eval_add_count, key_switch_count, aux_towers, num_primes_value);
        moduli_q = std::get<0>(moduli_info);
        uint32_t new_q_bound = std::get<1>(moduli_info);

        // the loop must be executed at least once
        do {
            q_bound = new_q_bound;
            n = compute_ring_dimension(crypto_params, new_q_bound, cycl_order);
            auto moduli_info = compute_moduli(crypto_params, n, eval_add_count, key_switch_count, aux_towers, num_primes_value);
            moduli_q = std::get<0>(moduli_info);
            new_q_bound = std::get<1>(moduli_info);
            if (multiparty_mode == NOISE_FLOODING_MULTIPARTY)
                new_q_bound += crypto_params_bgvrns->estimate_multiparty_flooding_log_q();
            if (ks_tech == HYBRID) {
                double dcrt_bits_est = (moduli_q.size() > 1) ? std::log2(moduli_q[1].convert_to_double()) : 0;
                uint32_t num_primes_est = (scal_tech == FLEXIBLEAUTOEXT) ? moduli_q.size() - 1 : moduli_q.size();
                bool is_noise_flooding_multiparty = (multiparty_mode == NOISE_FLOODING_MULTIPARTY);
                if (is_noise_flooding_multiparty)
                    num_primes_est += NoiseFlooding::NUM_MODULI_MULTIPARTY;
                auto hybrid_ks_info = RnsCryptoParams::estimate_log_p(
                        num_part_q, std::log2(moduli_q[0].convert_to_double()), dcrt_bits_est,
                        (scal_tech == FLEXIBLEAUTOEXT) ? std::log2(moduli_q[moduli_q.size() - 1].convert_to_double()) : 0,
                        num_primes_est, aux_bits, scal_tech, false, is_noise_flooding_multiparty);
                new_q_bound += std::get<0>(hybrid_ks_info);
            }
        } while (q_bound < new_q_bound);

        cycl_order = 2 * n;
        modulus_order = get_cyclic_order(n, ptm, scal_tech);

        for (size_t i = 0; i < vec_size; i++) {
            roots_q[i] = root_of_unity<NativeInteger>(cycl_order, moduli_q[i]);
        }
    } else {
        // FIXEDMANUAL mode
        cycl_order = 2 * n;
        // For ModulusSwitching to work we need the moduli to be also congruent to 1 modulo ptm
        uint32_t plaintext_modulus = ptm;
        uint32_t pow2ptm = 1;  // The largest power of 2 dividing ptm (check whether it
                               // is larger than cycl_order or not)
        while (plaintext_modulus % 2 == 0) {
            plaintext_modulus >>= 1;
            pow2ptm <<= 1;
        }

        if (pow2ptm < cycl_order)
            pow2ptm = cycl_order;

        modulus_order = static_cast<uint64_t>(pow2ptm) * plaintext_modulus;

        // Get the largest prime with size less or equal to first_mod_size_value bits.
        moduli_q[0] = last_prime<NativeInteger>(first_mod_size_value, modulus_order);
        roots_q[0] = root_of_unity<NativeInteger>(cycl_order, moduli_q[0]);

        if (num_primes_value > 1) {
            NativeInteger q =
                    (first_mod_size_value != dcrt_bits) ? last_prime<NativeInteger>(dcrt_bits, modulus_order) : moduli_q[0];

            moduli_q[1] = previous_prime<NativeInteger>(q, modulus_order);
            roots_q[1] = root_of_unity<NativeInteger>(cycl_order, moduli_q[1]);

            for (size_t i = 2; i < num_primes_value; i++) {
                moduli_q[i] = previous_prime<NativeInteger>(moduli_q[i - 1], modulus_order);
                roots_q[i] = root_of_unity<NativeInteger>(cycl_order, moduli_q[i]);
            }
        }
    }
    if (multiparty_mode == NOISE_FLOODING_MULTIPARTY) {
        NativeInteger extra_modulus = last_prime<NativeInteger>(NoiseFlooding::MULTIPARTY_MOD_SIZE, modulus_order);
        std::vector<NativeInteger> extra_moduli(NoiseFlooding::NUM_MODULI_MULTIPARTY);
        std::vector<NativeInteger> extra_roots(NoiseFlooding::NUM_MODULI_MULTIPARTY);

        for (size_t i = 0; i < NoiseFlooding::NUM_MODULI_MULTIPARTY; i++) {
            while (std::find(moduli_q.begin(), moduli_q.end(), extra_modulus) != moduli_q.end() ||
                   std::find(extra_moduli.begin(), extra_moduli.end(), extra_modulus) != extra_moduli.end()) {
                extra_modulus = previous_prime<NativeInteger>(extra_modulus, modulus_order);
            }
            extra_moduli[i] = extra_modulus;
            extra_roots[i] = root_of_unity<NativeInteger>(cycl_order, extra_modulus);
        }
        moduli_q.reserve(moduli_q.size() + extra_moduli.size());
        roots_q.reserve(roots_q.size() + extra_roots.size());
        // We insert the extra_moduli after the first modulus to improve security in multiparty decryption.
        moduli_q.insert(moduli_q.begin() + 1, std::make_move_iterator(extra_moduli.begin()),
                       std::make_move_iterator(extra_moduli.end()));
        roots_q.insert(roots_q.begin() + 1, std::make_move_iterator(extra_roots.begin()),
                      std::make_move_iterator(extra_roots.end()));
    }
    auto params_dcrt = std::make_shared<RnsParams<BigInteger>>(cycl_order, moduli_q, roots_q);

    ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_q, cycl_order, moduli_q);

    crypto_params_bgvrns->set_element_params(params_dcrt);

    const EncodingParams encoding_params = crypto_params_bgvrns->get_encoding_params();
    if (encoding_params->get_batch_size() > n)
        CIPHER_THROW("The batch size cannot be larger than the ring dimension.");

    if (encoding_params->get_batch_size() & (encoding_params->get_batch_size() - 1))
        CIPHER_THROW("The batch size can only be set to zero (for full packing) or a power of two.");

    // if no batch size was specified compute a default value
    if (encoding_params->get_batch_size() == 0) {
        // Check whether ptm and cycl_order are coprime
        uint32_t a, b, gcd;
        if (cycl_order > ptm) {
            a = cycl_order;
            b = ptm;
        } else {
            b = cycl_order;
            a = ptm;
        }

        gcd = b;
        while (b != 0) {
            gcd = b;
            b = a % b;
            a = gcd;
        }

        // if ptm and CyclOrder are not coprime we set batch_size = n by default (for full packing)
        uint32_t batch_size;
        if (gcd != 1) {
            batch_size = n;
        } else {
            // set batchsize to the actual batchsize i.e. n/d where d is the
            // order of ptm mod CyclOrder
            a = static_cast<uint64_t>(ptm) % cycl_order;
            b = 1;
            while (a != 1) {
                a = static_cast<uint64_t>(a * ptm) % cycl_order;
                b++;
            }

            if (n % b != 0)
                CIPHER_THROW("BGVrns.ParamsGen: something went wrong when computing the batchSize");

            batch_size = n / b;
        }

        EncodingParams encoding_params_new(
                std::make_shared<EncodingParamsImpl>(encoding_params->get_plaintext_modulus(), batch_size));
        crypto_params_bgvrns->set_encoding_params(encoding_params_new);
    }
    crypto_params_bgvrns->precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, 0);

    // Validate the ring dimension found using estimated log_q(P) against actual log_q(P)
    SecurityLevel std_level = crypto_params_bgvrns->get_std_level();
    if (std_level != HEStd_NotSet) {
        uint32_t log_actual_q = 0;
        if (ks_tech == HYBRID) {
            log_actual_q = crypto_params_bgvrns->get_params_qp()->get_modulus().get_msb();
        } else {
            log_actual_q = crypto_params_bgvrns->get_element_params()->get_modulus().get_msb();
        }

        DistributionType dist_type = (crypto_params_bgvrns->get_secret_key_dist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
        uint32_t n_actual = StdLatticeParm::find_ring_dim(dist_type, std_level, log_actual_q);

        if (n < n_actual) {
            std::string err_msg("The ring dimension found using estimated logQ(P) [");
            err_msg += std::to_string(n) + "] does not meet security requirements. ";
            err_msg += "Report this problem to Cipher developers and set the ring dimension manually to ";
            err_msg += std::to_string(n_actual) + ".";

            CIPHER_THROW(err_msg);
        }
    }

    return true;
}

}  // namespace cipher
