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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "cipher/fhe/ckks/param_gen.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "cipher/fhe/ckks/crypto_params.h"

namespace cipher {

#if CIPHER_NATIVE_INT == 128
constexpr size_t AUXMODSIZE = 119;
#elif CIPHER_NATIVE_INT == 32
constexpr size_t AUXMODSIZE = 28;
#else
constexpr size_t AUXMODSIZE = 60;
#endif

bool CkksRnsParamGen::params_gen_ckksrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params,
                                                          uint32_t cycl_order, uint32_t num_primes_value,
                                                          uint32_t scaling_mod_size, uint32_t first_mod_size_value,
                                                          uint32_t num_part_q,
                                                          CompressionLevel m_p_int_boot_ciphertext_compression_level) const {
    // the "const" modifier for crypto_params_ckksrns and encoding_params below doesn't mean that the objects those 2 pointers
    // point to are const (not changeable). it means that the pointers themselves are const only.
    const auto crypto_params_ckksrns = std::dynamic_pointer_cast<CkksRnsCryptoParams>(crypto_params);
    const EncodingParams encoding_params = crypto_params_ckksrns->get_encoding_params();

    KeySwitchTechnique ks_tech = crypto_params_ckksrns->get_key_switch_technique();
    ScalingTechnique scal_tech = crypto_params_ckksrns->get_scaling_technique();
    EncryptionTechnique enc_tech = crypto_params_ckksrns->get_encryption_technique();
    MultiplicationTechnique mult_tech = crypto_params_ckksrns->get_multiplication_technique();
    ProxyReEncryptionMode pre_mode = crypto_params_ckksrns->get_pre_mode();

    // Determine appropriate composite degree automatically if scaling technique set to COMPOSITESCALINGAUTO
    crypto_params_ckksrns->configure_composite_degree(first_mod_size_value);

    uint32_t composite_degree = crypto_params_ckksrns->get_composite_degree();
    uint32_t register_word_size = crypto_params_ckksrns->get_register_word_size();

    if (scal_tech == COMPOSITESCALINGAUTO || scal_tech == COMPOSITESCALINGMANUAL) {
        // TODO (Duhyeong): We need more exception cases in terms of
        //                  prime size (= scaling_mod_size / composite_degree), registerSize, and num_primes_value
        //                  e.g.1, assertion: prime size < registerSize (we may need at least 1-2 bit gap)
        //                  e.g.2, prime size > ??? if num_primes_value > ???
        if (composite_degree > 2 && scaling_mod_size < 60) {
            std::string error_msg = "Prime moduli size is too small. It must generally be greater than 19,";
            error_msg += " especially for larger multiplicative depth.";
            error_msg += " Please increase the scaling factor (scalingModSize) or the register word size.";
            error_msg += " Also, you can use COMPOSITESCALINGMANUAL at your own risk.";
            CIPHER_THROW(error_msg);
        } else if (composite_degree == 1 && register_word_size <= 64) {
            CIPHER_THROW(
                    "This COMPOSITESCALING* version does not support composite degree == 1 with register size <= 64.");
        } else if (composite_degree < 1) {
            CIPHER_THROW("Composite degree must be greater than or equal to 1.");
        }

        if (register_word_size < 20 && scal_tech == COMPOSITESCALINGAUTO) {
            CIPHER_THROW(
                    "Register word size must be greater than or equal to 20 for COMPOSITESCALINGAUTO. Otherwise, try it with COMPOSITESCALINGMANUAL.");
        }
    }

    if ((pre_mode != INDCPA) && (pre_mode != NOT_SET)) {
        std::stringstream s;
        s << "This PRE mode " << pre_mode << " is not supported for CKKSRNS";
        CIPHER_THROW(s.str());
    }

    // TODO: Allow the user to specify this?
    uint32_t extra_mod_size = (scal_tech == FLEXIBLEAUTOEXT) ? DCRT_MODULUS::DEFAULT_EXTRA_MOD_SIZE : 0;

    //// HE Standards compliance logic/check
    SecurityLevel std_level = crypto_params_ckksrns->get_std_level();
    // TODO Duhyeong: Let's check if aux_bits = register_word_size makes an error in the P prime generation.
    uint32_t aux_bits = ((scal_tech == COMPOSITESCALINGAUTO || scal_tech == COMPOSITESCALINGMANUAL) &&
                        register_word_size <= AUXMODSIZE) ?
                               (register_word_size - 1) :
                               AUXMODSIZE;
    uint32_t n = cycl_order / 2;

    // GAUSSIAN security constraint
    DistributionType dist_type = (crypto_params_ckksrns->get_secret_key_dist() == GAUSSIAN) ? HEStd_error : HEStd_ternary;
    if (std_level != HEStd_NotSet) {
        uint32_t q_bound = first_mod_size_value + (num_primes_value - 1) * scaling_mod_size + extra_mod_size;

        // we add an extra bit to account for the alternating logic of selecting the RNS moduli in CKKS
        // ignore the case when there is only one max size modulus
        if (q_bound != aux_bits)
            ++q_bound;

        // Estimate ciphertext modulus Q*P bound (in case of HYBRID P*Q)
        if (ks_tech == HYBRID)
            q_bound += std::get<0>(RnsCryptoParams::estimate_log_p(num_part_q, first_mod_size_value, scaling_mod_size,
                                                                    extra_mod_size, num_primes_value, aux_bits, scal_tech, true,
                                                                    false, composite_degree));

        uint32_t he_std_n = StdLatticeParm::find_ring_dim(dist_type, std_level, q_bound);

        if (n == 0) {
            // Choose ring dimension based on security standards
            n = he_std_n;
            cycl_order = 2 * n;
        } else {
            // Check whether particular selection is standards-compliant
            if (he_std_n > n) {
                CIPHER_THROW("The specified ring dimension (" + std::to_string(n) +
                              ") does not comply with HE standards recommendation (" + std::to_string(he_std_n) + ").");
            }
        }
    } else if (n == 0) {
        CIPHER_THROW("Please specify the ring dimension or desired security level.");
    }

    if (encoding_params->get_batch_size() > n / 2)
        CIPHER_THROW("The batch size cannot be larger than ring dimension / 2.");

    if (encoding_params->get_batch_size() & (encoding_params->get_batch_size() - 1))
        CIPHER_THROW("The batch size can only be set to zero (for full packing) or a power of two.");
    //// End HE Standards compliance logic/check

    uint32_t dcrt_bits = scaling_mod_size;

    // In COMPOSITESCALING mode, each modulus consists of composite_degree number of primes
    num_primes_value *= composite_degree;

    uint32_t vec_size = (extra_mod_size == 0) ? num_primes_value : num_primes_value + 1;
    std::vector<NativeInteger> moduli_q(vec_size);
    std::vector<NativeInteger> roots_q(vec_size);

    if ((scal_tech == COMPOSITESCALINGAUTO || scal_tech == COMPOSITESCALINGMANUAL) && (composite_degree > 1)) {
        composite_prime_moduli_gen(moduli_q, roots_q, composite_degree, num_primes_value, first_mod_size_value, dcrt_bits, cycl_order,
                                register_word_size);
    } else
        single_prime_moduli_gen(moduli_q, roots_q, scal_tech, num_primes_value, first_mod_size_value, dcrt_bits, cycl_order, extra_mod_size);

    auto params_dcrt = std::make_shared<RnsParams<BigInteger>>(cycl_order, moduli_q, roots_q);

    crypto_params_ckksrns->set_element_params(params_dcrt);

    // if no batch size was specified, we set batch_size = n/2 by default (for full packing)
    if (encoding_params->get_batch_size() == 0) {
        uint32_t batch_size = n / 2;
        EncodingParams encoding_params_new(
                std::make_shared<EncodingParamsImpl>(encoding_params->get_plaintext_modulus(), batch_size));
        crypto_params_ckksrns->set_encoding_params(encoding_params_new);
    }

    crypto_params_ckksrns->precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, extra_mod_size);

    // Validate the ring dimension found using estimated log_q(P) against actual log_q(P)
    if (std_level != HEStd_NotSet) {
        uint32_t log_actual_q = (ks_tech == HYBRID) ? crypto_params_ckksrns->get_params_qp()->get_modulus().get_msb() :
                                                   crypto_params_ckksrns->get_element_params()->get_modulus().get_msb();

        uint32_t n_actual = StdLatticeParm::find_ring_dim(dist_type, std_level, log_actual_q);
        if (n < n_actual) {
            std::string err_msg("The ring dimension [");
            err_msg += std::to_string(n) + "] does not meet security requirements. ";
            CIPHER_THROW(err_msg);
        }
    }

    return true;
}

void CkksRnsParamGen::composite_prime_moduli_gen(std::vector<NativeInteger>& moduli_q,
                                                         std::vector<NativeInteger>& roots_q, uint32_t composite_degree,
                                                         uint32_t num_primes_value, uint32_t first_mod_size_value, uint32_t dcrt_bits,
                                                         uint32_t cycl_order, uint32_t register_word_size) const {
    if (first_mod_size_value <= dcrt_bits) {
        CIPHER_THROW("firstModSize must be > scalingModSize.");
    }

    std::unordered_set<uint64_t> moduli_q_record;

    for (uint32_t d = 1, rem_bits = dcrt_bits; d <= composite_degree; ++d) {
        uint32_t q_bit_size = std::ceil(static_cast<double>(rem_bits) / (composite_degree - d + 1));
        NativeInteger q = first_prime<NativeInteger>(std::min(q_bit_size, register_word_size), cycl_order);
        q = previous_prime<NativeInteger>(q, cycl_order);
        while (std::log2(q.convert_to_double()) > register_word_size || std::log2(q.convert_to_double()) > q_bit_size ||
               moduli_q_record.find(q.convert_to_int()) != moduli_q_record.end()) {
            q = previous_prime<NativeInteger>(q, cycl_order);
        }
        moduli_q[num_primes_value - d] = q;
        roots_q[num_primes_value - d] = root_of_unity(cycl_order, moduli_q[num_primes_value - d]);
        moduli_q_record.emplace(q.convert_to_int());
        rem_bits -= q.get_msb();
    }

    const std::string composite_scaling_err_msg =
            "COMPOSITE SCALING prime sampling error. Consider increasing the scaling factor or the register word size.";

    if (num_primes_value > 1) {
        std::vector<NativeInteger> q_prev(std::ceil(static_cast<double>(composite_degree) / 2));
        std::vector<NativeInteger> q_next(composite_degree - static_cast<uint32_t>(q_prev.size()));

        // Prep to compute initial scaling factor
        double sf = moduli_q[num_primes_value - 1].convert_to_double();
        for (uint32_t d = 2; d <= composite_degree; ++d) {
            sf *= moduli_q[num_primes_value - d].convert_to_double();
        }

        NativeInteger register_ceiling(std::numeric_limits<uint64_t>::max());
        if (register_word_size < 63) {
            NativeInteger top(uint64_t(1) << register_word_size);
            register_ceiling = top - top.mod(cycl_order) + NativeInteger(1);
        }

        // Nominal scaling factor Delta_L = 2^dcrt_bits. Pinning the per-level prime product to
        // sf^2/Delta_L (instead of sf) forces the resulting scaling factor sf^2/product back to
        // Delta_L each level, so the discreteness error does not accumulate across levels.
        const double delta_l = std::pow(2.0, static_cast<double>(dcrt_bits));
        bool flag = true;
        for (uint32_t i = num_primes_value - composite_degree; i >= 2 * composite_degree; i -= composite_degree) {
            // Running scaling factor from the actually-chosen primes (self-correcting recurrence)
            sf = std::pow(sf, 2);
            for (uint32_t d = 0; d < composite_degree; ++d) {
                sf /= moduli_q[i + d].convert_to_double();
            }

            // Target product for this level's primes pins the next scaling factor to Delta_L
            double target_product = sf * sf / delta_l;
            auto sf_sqrt = std::pow(target_product, 1.0 / composite_degree);

            NativeInteger sf_int = std::llround(sf_sqrt);
            NativeInteger sf_rem = sf_int.mod(cycl_order);
            if (sf_int < NativeInteger(2 * static_cast<uint64_t>(cycl_order)))
                CIPHER_THROW(composite_scaling_err_msg);

            double prime_product = 1.0;
            std::unordered_set<uint64_t> q_current_record;  // current prime tracker

            for (size_t step = 0; step < q_prev.size(); ++step) {
                q_prev[step] = sf_int - sf_rem + NativeInteger(1) - NativeInteger(cycl_order);
                if (q_prev[step] > register_ceiling)
                    q_prev[step] = register_ceiling;
                do {
                    try {
                        q_prev[step] = cipher::previous_prime(q_prev[step], cycl_order);
                    } catch (const CipherException& ex) {
                        CIPHER_THROW(composite_scaling_err_msg);
                    }
                } while (std::log2(q_prev[step].convert_to_double()) > register_word_size ||
                         moduli_q_record.find(q_prev[step].convert_to_int()) != moduli_q_record.end() ||
                         q_current_record.find(q_prev[step].convert_to_int()) != q_current_record.end());
                q_current_record.emplace(q_prev[step].convert_to_int());
                prime_product *= q_prev[step].convert_to_double();
            }

            bool fits_register = true;
            for (size_t step = 0; step < q_next.size(); ++step) {
                q_next[step] = sf_int - sf_rem + NativeInteger(1) + NativeInteger(cycl_order);
                if (q_next[step] > register_ceiling) {
                    q_next[step] = register_ceiling;
                    fits_register = false;
                }
                do {
                    try {
                        if (fits_register == true) {
                            q_next[step] = cipher::next_prime(q_next[step], cycl_order);
                        } else {
                            q_next[step] = cipher::previous_prime(q_next[step], cycl_order);
                        }
                    } catch (const CipherException& ex) {
                        CIPHER_THROW(composite_scaling_err_msg);
                    }
                    if (std::log2(q_next[step].convert_to_double()) > register_word_size) {
                        fits_register = false;
                    }
                } while (std::log2(q_next[step].convert_to_double()) > register_word_size ||
                         moduli_q_record.find(q_next[step].convert_to_int()) != moduli_q_record.end() ||
                         q_current_record.find(q_next[step].convert_to_int()) != q_current_record.end());
                q_current_record.emplace(q_next[step].convert_to_int());
                prime_product *= q_next[step].convert_to_double();
            }

            if (flag == false) {
                NativeInteger q_prev_next = NativeInteger(q_next[q_next.size() - 1].convert_to_int());
                while (prime_product > target_product) {
                    q_current_record.erase(q_prev_next.convert_to_int());
                    do {
                        try {
                            q_prev_next = cipher::previous_prime(q_prev_next, cycl_order);
                        } catch (const CipherException& ex) {
                            CIPHER_THROW(composite_scaling_err_msg);
                        }
                    } while (std::log2(q_prev_next.convert_to_double()) > register_word_size ||
                             moduli_q_record.find(q_prev_next.convert_to_int()) != moduli_q_record.end() ||
                             q_current_record.find(q_prev_next.convert_to_int()) != q_current_record.end());
                    q_current_record.emplace(q_prev_next.convert_to_int());

                    prime_product /= q_next[q_next.size() - 1].convert_to_double();
                    q_next[q_next.size() - 1] = q_prev_next;
                    prime_product *= q_prev_next.convert_to_double();
                }

                uint32_t m = q_prev.size();
                for (uint32_t d = 1; d <= m; ++d) {
                    moduli_q[i - d] = q_prev[d - 1];
                }
                for (uint32_t d = m + 1; d <= composite_degree; ++d) {
                    moduli_q[i - d] = q_next[d - (m + 1)];
                }

                for (uint32_t d = 1; d <= composite_degree; ++d) {
                    roots_q[i - d] = root_of_unity(cycl_order, moduli_q[i - d]);
                    moduli_q_record.emplace(moduli_q[i - d].convert_to_int());
                }

                flag = true;
            } else {
                NativeInteger q_next_prev = NativeInteger(q_prev[q_prev.size() - 1].convert_to_int());
                while (prime_product < target_product) {
                    q_current_record.erase(q_next_prev.convert_to_int());
                    do {
                        try {
                            q_next_prev = cipher::next_prime(q_next_prev, cycl_order);
                        } catch (const CipherException& ex) {
                            CIPHER_THROW(composite_scaling_err_msg);
                        }
                        if (std::log2(q_next_prev.convert_to_double()) > register_word_size)
                            CIPHER_THROW(composite_scaling_err_msg);
                    } while (moduli_q_record.find(q_next_prev.convert_to_int()) != moduli_q_record.end() ||
                             q_current_record.find(q_next_prev.convert_to_int()) != q_current_record.end());
                    q_current_record.emplace(q_next_prev.convert_to_int());

                    prime_product /= q_prev[q_prev.size() - 1].convert_to_double();
                    q_prev[q_prev.size() - 1] = q_next_prev;
                    prime_product *= q_next_prev.convert_to_double();
                }

                uint32_t m = q_prev.size();
                for (uint32_t d = 1; d <= m; ++d) {
                    moduli_q[i - d] = q_prev[d - 1];
                }
                for (uint32_t d = m + 1; d <= composite_degree; ++d) {
                    moduli_q[i - d] = q_next[d - (m + 1)];
                }

                for (uint32_t d = 1; d <= composite_degree; ++d) {
                    roots_q[i - d] = root_of_unity(cycl_order, moduli_q[i - d]);
                    moduli_q_record.emplace(moduli_q[i - d].convert_to_int());
                }

                flag = false;
            }
        }  // for loop
    }  // if num_primes_value > 1

    for (uint32_t d = 1, rem_bits = first_mod_size_value; d <= composite_degree; ++d) {
        uint32_t q_bit_size = std::ceil(static_cast<double>(rem_bits) / (composite_degree - d + 1));
        try {
            // Find next prime
            NativeInteger next_integer = first_prime<NativeInteger>(std::min(q_bit_size, register_word_size), cycl_order);
            next_integer = previous_prime<NativeInteger>(next_integer, cycl_order);

            while (std::log2(next_integer.convert_to_double()) > q_bit_size ||
                   std::log2(next_integer.convert_to_double()) > register_word_size ||
                   moduli_q_record.find(next_integer.convert_to_int()) != moduli_q_record.end())
                next_integer = previous_prime<NativeInteger>(next_integer, cycl_order);

            // Store prime
            moduli_q[d - 1] = next_integer;
            roots_q[d - 1] = root_of_unity(cycl_order, moduli_q[d - 1]);
            // Keep track of existing primes
            moduli_q_record.emplace(moduli_q[d - 1].convert_to_int());
            rem_bits -= q_bit_size;
        } catch (const CipherException& ex) {
            CIPHER_THROW(composite_scaling_err_msg);
        }
    }

    return;
}

void CkksRnsParamGen::single_prime_moduli_gen(std::vector<NativeInteger>& moduli_q,
                                                      std::vector<NativeInteger>& roots_q, ScalingTechnique scal_tech,
                                                      uint32_t num_primes_value, uint32_t first_mod_size_value, uint32_t dcrt_bits,
                                                      uint32_t cycl_order, uint32_t extra_mod_size) const {
    NativeInteger q = first_prime<NativeInteger>(dcrt_bits, cycl_order);
    moduli_q[num_primes_value - 1] = q;
    roots_q[num_primes_value - 1] = root_of_unity(cycl_order, moduli_q[num_primes_value - 1]);

    NativeInteger max_prime{q};
    NativeInteger min_prime{q};
    if (num_primes_value > 1) {
        if (scal_tech != FLEXIBLEAUTO && scal_tech != FLEXIBLEAUTOEXT) {
            NativeInteger q_prev = q;
            NativeInteger q_next = q;
            for (size_t i = num_primes_value - 2, cnt = 0; i >= 1; --i, ++cnt) {
                if ((cnt % 2) == 0) {
                    q_prev = previous_prime(q_prev, cycl_order);
                    moduli_q[i] = q_prev;
                } else {
                    q_next = next_prime(q_next, cycl_order);
                    moduli_q[i] = q_next;
                }

                if (moduli_q[i] > max_prime)
                    max_prime = moduli_q[i];
                else if (moduli_q[i] < min_prime)
                    min_prime = moduli_q[i];

                roots_q[i] = root_of_unity(cycl_order, moduli_q[i]);
            }
        } else {  // FLEXIBLEAUTO
            /* Scaling factors in FLEXIBLEAUTO are a bit fragile,
             * in the sense that once one scaling factor gets far enough from the
             * original scaling factor, subsequent level scaling factors quickly
             * diverge to either 0 or infinity. To mitigate this problem to a certain
             * extend, we have a special prime selection process in place. The goal is
             * to maintain the scaling factor of all levels as close to the original
             * scale factor of level 0 as possible.
             */
            double sf = moduli_q[num_primes_value - 1].convert_to_double();
            for (size_t i = num_primes_value - 2, cnt = 0; i >= 1; --i, ++cnt) {
                sf = std::pow(sf, 2) / moduli_q[i + 1].convert_to_double();
                NativeInteger sf_int = std::llround(sf);
                NativeInteger sf_rem = sf_int.mod(cycl_order);
                bool has_same_mod = true;
                if ((cnt % 2) == 0) {
                    NativeInteger q_prev = sf_int - NativeInteger(cycl_order) - sf_rem + NativeInteger(1);
                    while (has_same_mod) {
                        has_same_mod = false;
                        q_prev = previous_prime(q_prev, cycl_order);
                        for (size_t j = i + 1; j < num_primes_value; j++) {
                            if (q_prev == moduli_q[j]) {
                                has_same_mod = true;
                                break;
                            }
                        }
                    }
                    moduli_q[i] = q_prev;
                } else {
                    NativeInteger q_next = sf_int + NativeInteger(cycl_order) - sf_rem + NativeInteger(1);
                    while (has_same_mod) {
                        has_same_mod = false;
                        q_next = next_prime(q_next, cycl_order);
                        for (size_t j = i + 1; j < num_primes_value; j++) {
                            if (q_next == moduli_q[j]) {
                                has_same_mod = true;
                                break;
                            }
                        }
                    }
                    moduli_q[i] = q_next;
                }
                if (moduli_q[i] > max_prime)
                    max_prime = moduli_q[i];
                else if (moduli_q[i] < min_prime)
                    min_prime = moduli_q[i];

                roots_q[i] = root_of_unity(cycl_order, moduli_q[i]);
            }
        }
    }

    if (first_mod_size_value == dcrt_bits) {  // this requires dcrt_bits < 60
        moduli_q[0] = next_prime<NativeInteger>(max_prime, cycl_order);
    } else {
        moduli_q[0] = last_prime<NativeInteger>(first_mod_size_value, cycl_order);

        // find if the value of moduli_q[0] is already in the vector starting with moduli_q[1] and
        // if there is, then get another prime for moduli_q[0]
        const auto pos = std::find(moduli_q.begin() + 1, moduli_q.end(), moduli_q[0]);
        if (pos != moduli_q.end()) {
            moduli_q[0] = next_prime<NativeInteger>(max_prime, cycl_order);
        }
    }
    if (moduli_q[0] > max_prime)
        max_prime = moduli_q[0];

    roots_q[0] = root_of_unity(cycl_order, moduli_q[0]);

    if (scal_tech == FLEXIBLEAUTOEXT) {
        // moduli_q[num_primes_value] must still be 0, so it has to be populated now

        // no need for extra checking as extra_mod_size is automatically chosen by the library
        auto temp_mod = first_prime<NativeInteger>(extra_mod_size - 1, cycl_order);
        // check if temp_mod has a duplicate in the vector (exclude moduli_q[num_primes_value] from this operation):
        const auto end_pos = moduli_q.end() - 1;
        auto pos = std::find(moduli_q.begin(), end_pos, temp_mod);
        // if there is a duplicate, then we call next_prime()
        moduli_q[num_primes_value] = (pos != end_pos) ? next_prime<NativeInteger>(max_prime, cycl_order) : temp_mod;

        roots_q[num_primes_value] = root_of_unity(cycl_order, moduli_q[num_primes_value]);
    }
}

}  // namespace cipher
