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

#include "cipher/fhe/ckks/crypto_params.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/math/dft.h"

namespace cipher {

// Precomputation of CRT tables encryption, decryption, and  homomorphic multiplication
void CkksRnsCryptoParams::precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech,
                                                EncryptionTechnique enc_tech, MultiplicationTechnique mult_tech,
                                                uint32_t num_part_q, uint32_t aux_bits, uint32_t extra_bits) {
    RnsCryptoParams::precompute_crt_tables(ks_tech, scal_tech, enc_tech, mult_tech, num_part_q, aux_bits, extra_bits);

    size_t size_q = get_element_params()->get_params().size();
    uint32_t composite_degree = composite_degree_;

    std::vector<NativeInteger> moduli_q(size_q);
    std::vector<NativeInteger> roots_q(size_q);

    for (size_t i = 0; i < size_q; i++) {
        moduli_q[i] = get_element_params()->get_params()[i]->get_modulus();
        roots_q[i] = get_element_params()->get_params()[i]->get_root_of_unity();
    }

    // Pre-compute values for rescaling
    ql_inv_modq_.resize(size_q - 1);
    ql_inv_modq_precon_.resize(size_q - 1);
    for (size_t k = 0; k < size_q - 1; k++) {
        size_t l = size_q - (k + 1);
        ql_inv_modq_[k].resize(l);
        ql_inv_modq_precon_[k].resize(l);
        for (uint32_t i = 0; i < l; i++) {
            ql_inv_modq_[k][i] = moduli_q[l].mod_inverse(moduli_q[i]);
            ql_inv_modq_precon_[k][i] = ql_inv_modq_[k][i].prep_mod_mul_const(moduli_q[i]);
        }
    }

    // Pre-compute scaling factors for each level (used in FLEXIBLE* scaling techniques)
    if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
        scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
        scaling_factors_real_.resize(size_q);

        if ((size_q == 1) && (extra_bits == 0) && (scal_technique_ != COMPOSITESCALINGAUTO) &&
            (scal_technique_ != COMPOSITESCALINGMANUAL)) {
            // mult depth = 0 and FLEXIBLEAUTO
            // when multiplicative depth = 0, we use the scaling mod size instead of modulus size
            // Plaintext modulus is used in EncodingParamsImpl to store the exponent p of the scaling factor
            scaling_factors_real_[0] = std::pow(2, get_plaintext_modulus());
        } else if ((size_q == 2) && (extra_bits > 0) && (scal_technique_ != COMPOSITESCALINGAUTO) &&
                   (scal_technique_ != COMPOSITESCALINGMANUAL)) {
            // mult depth = 0 and FLEXIBLEAUTOEXT
            // when multiplicative depth = 0, we use the scaling mod size instead of modulus size
            // Plaintext modulus is used in EncodingParamsImpl to store the exponent p of the scaling factor
            scaling_factors_real_[0] = moduli_q[size_q - 1].convert_to_double();
            scaling_factors_real_[1] = std::pow(2, get_plaintext_modulus());
        } else {
            scaling_factors_real_[0] = moduli_q[size_q - 1].convert_to_double();
            if (scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
                for (uint32_t j = 1; j < composite_degree; j++) {
                    scaling_factors_real_[0] *= moduli_q[size_q - j - 1].convert_to_double();
                }
            } else if (extra_bits > 0)
                scaling_factors_real_[1] = moduli_q[size_q - 2].convert_to_double();

            const double last_preset_factor = (extra_bits == 0) ? scaling_factors_real_[0] : scaling_factors_real_[1];
            // number of levels with pre-calculated factors
            const size_t num_preset_factors = (extra_bits == 0 || (scal_technique_ == COMPOSITESCALINGAUTO ||
                                                                   scal_technique_ == COMPOSITESCALINGMANUAL)) ?
                                                      1 :
                                                      2;

            for (size_t k = num_preset_factors; k < size_q; k++) {
                if (scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
                    if (k % composite_degree == 0) {
                        double prev_sf = scaling_factors_real_[k - composite_degree];
                        scaling_factors_real_[k] = prev_sf * prev_sf;
                        for (uint32_t j = 0; j < composite_degree; j++) {
                            scaling_factors_real_[k] /= moduli_q[size_q - k + j].convert_to_double();
                        }
                    } else {
                        scaling_factors_real_[k] = 1;
                    }
                } else {
                    double prev_sf = scaling_factors_real_[k - 1];
                    scaling_factors_real_[k] = prev_sf * prev_sf / moduli_q[size_q - k].convert_to_double();

                    if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT) {
                        double ratio = scaling_factors_real_[k] / last_preset_factor;
                        if (ratio <= 0.5 || ratio >= 2.0) {
                            CIPHER_THROW("FLEXIBLEAUTO scaling failed at level " + std::to_string(k) +
                                         " with scaling factor ratio " + std::to_string(ratio) +
                                         ". Use FIXEDMANUAL or FIXEDAUTO instead.");
                        }
                    }
                }
            }
        }

        scaling_factors_real_big_.resize(size_q - 1);

        if (scaling_factors_real_big_.size() > 0) {
            if (extra_bits == 0) {
                scaling_factors_real_big_[0] = scaling_factors_real_[0] * scaling_factors_real_[0];
            } else {
                scaling_factors_real_big_[0] = scaling_factors_real_[0] * scaling_factors_real_[1];
            }
            for (uint32_t k = 1; k < size_q - 1; k++) {
                scaling_factors_real_big_[k] = scaling_factors_real_[k] * scaling_factors_real_[k];
            }
        }

        // Moduli as real
        dmoduli_q_.resize(size_q);
        for (uint32_t i = 0; i < size_q; ++i) {
            dmoduli_q_[i] = moduli_q[i].convert_to_double();
        }
    } else {
        const auto p = get_plaintext_modulus();
        approx_sf_ = std::pow(2, p);
    }
    if (ks_technique_ == HYBRID) {
        const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
        modq_barrett_mu_.resize(size_q);
        for (uint32_t i = 0; i < size_q; i++) {
            modq_barrett_mu_[i] = (barrett_base128_bit / BigInteger(moduli_q[i])).convert_to_int<DoubleNativeInt>();
        }
    }

    /////////////////////////////////////
    // Composite scaling : bootstrapping modulus raise (extend_ciphertext)
    // Tables for the exact CRT basis extension (RnsPoly::expand_crt_basis) from the small
    // bottom basis Ql = {q_0, ..., q_{d-1}}, d = composite_degree (the towers remaining in
    // the depleted ciphertext), to the full basis Q. ComplQl = {q_d, ..., q_{L-1}} is the
    // complement of Ql in Q. Precomputing these here keeps extend_ciphertext in full RNS
    // (no multiprecision arithmetic at runtime).
    /////////////////////////////////////
    if (composite_degree > 1 && size_q > composite_degree) {
        uint32_t size_ql = composite_degree;
        uint32_t size_compl_ql = size_q - size_ql;

        std::vector<NativeInteger> moduli_compl_ql(moduli_q.begin() + size_ql, moduli_q.end());
        std::vector<NativeInteger> roots_compl_ql(roots_q.begin() + size_ql, roots_q.end());
        params_mod_raise_compl_ql_ = std::make_shared<RnsParams<BigInteger>>(
                get_element_params()->get_cyclotomic_order(), moduli_compl_ql, roots_compl_ql);

        BigInteger modulus_ql(1);
        for (uint32_t i = 0; i < size_ql; ++i)
            modulus_ql *= BigInteger(moduli_q[i]);

        // Ql/q_i, shared by the ql_hat_inv_modq and QlHatModComplq tables below
        std::vector<BigInteger> ql_hat(size_ql);
        for (uint32_t i = 0; i < size_ql; ++i)
            ql_hat[i] = modulus_ql / BigInteger(moduli_q[i]);

        // [(Ql/q_i)^{-1}]_{q_i}
        mod_raise_ql_hat_inv_modq_.resize(size_ql);
        mod_raise_ql_hat_inv_modq_precon_.resize(size_ql);
        for (uint32_t i = 0; i < size_ql; ++i) {
            mod_raise_ql_hat_inv_modq_[i] = ql_hat[i].mod_inverse(BigInteger(moduli_q[i])).convert_to_int();
            mod_raise_ql_hat_inv_modq_precon_[i] = mod_raise_ql_hat_inv_modq_[i].prep_mod_mul_const(moduli_q[i]);
        }

        // [Ql/q_i]_{q_j} and the overflow correction [a*Ql]_{q_j}, 0 <= a <= size_ql, q_j in ComplQl;
        // the alpha table is a running sum whose a = 0 row keeps the zero value assign() gives it
        mod_raise_ql_hat_mod_complq_.assign(size_compl_ql, std::vector<NativeInteger>(size_ql));
        mod_raise_alpha_ql_mod_complq_.assign(size_ql + 1, std::vector<NativeInteger>(size_compl_ql));
        for (uint32_t j = 0; j < size_compl_ql; ++j) {
            BigInteger qj(moduli_compl_ql[j]);
            for (uint32_t i = 0; i < size_ql; ++i)
                mod_raise_ql_hat_mod_complq_[j][i] = ql_hat[i].mod(qj).convert_to_int();
            NativeInteger ql_modqj = modulus_ql.mod(qj).convert_to_int();
            for (uint32_t a = 1; a <= size_ql; ++a)
                mod_raise_alpha_ql_mod_complq_[a][j] =
                        mod_raise_alpha_ql_mod_complq_[a - 1][j].mod_add_fast(ql_modqj, moduli_compl_ql[j]);
        }

        if (modq_barrett_mu_.size() == size_q) {
            // reuse the Barrett constants computed for HYBRID above
            mod_raise_mod_complq_barrett_mu_.assign(modq_barrett_mu_.begin() + size_ql, modq_barrett_mu_.end());
        } else {
            mod_raise_mod_complq_barrett_mu_.resize(size_compl_ql);
            const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
            for (uint32_t j = 0; j < size_compl_ql; ++j)
                mod_raise_mod_complq_barrett_mu_[j] =
                        (barrett_base128_bit / BigInteger(moduli_compl_ql[j])).convert_to_int<DoubleNativeInt>();
        }

        // 1./q_i for q_i in Ql (used for the fractional part of the overflow correction)
        mod_raiseq_inv_.resize(size_ql);
        for (uint32_t i = 0; i < size_ql; ++i)
            mod_raiseq_inv_[i] = 1.0 / moduli_q[i].convert_to_double();
    }

    /////////////////////////////////////
    // Sparse secret encapsulation (SPARSE_ENCAPSULATED): auxiliary basis and tables for the
    // key switching to/from the sparse secret at the bootstrapping modulus raise
    // (CkksRnsFhe::key_switch_gen_sparse / key_switch_sparse). The switching key is generated
    // over Ql*P', where Ql = {q_0, ..., q_{d-1}} (d = composite_degree) is the basis of the
    // bottom level and P' = p'_0*...*p'_{k-1} is an auxiliary modulus exceeding the bottom
    // modulus by ~6 bits, so that the key switching noise floor(Ql*e/P') is comparable to the
    // modulus switching noise.
    // - without composite scaling, two primes of MAX_MODULUS_SIZE/2 + 3 = 33 bits (the 64-bit build);
    // - with composite scaling, ~66 bits for a bottom modulus of at most 60 bits and ~127 bits for a
    //   larger one (at most 121 bits), split into primes that fit the register word size.
    // The primes of the composite scaling cases are searched upwards from the target size, so
    // that enough primes congruent to 1 modulo 2N exist for ring dimensions up to 2^17 (the
    // resulting P' is then slightly larger than the target, which only reduces the noise).
    // The tables below support the exact (HPS-style) CRT basis switches (RnsPoly::switch_crt_basis)
    // used to extend the ciphertext/keys from Ql to P' and to scale the key-switched ciphertext
    // back down from Ql*P' to Ql; the exact method is used so that no alpha*P' overflow term is
    // dropped during the basis switches.
    /////////////////////////////////////

    if (get_secret_key_dist() == SPARSE_ENCAPSULATED) {
        const uint32_t size_ql = composite_degree;
        // for composite_degree > 1 the Ql -> P' switch reuses the modulus-raise tables, which are only
        // precomputed when the chain is longer than the bottom level
        if (size_q < size_ql || (size_ql > 1 && size_q == size_ql))
            CIPHER_THROW("The modulus chain is too short for the composite degree.");

        BigInteger modulus_ql(1);
        for (uint32_t i = 0; i < size_ql; ++i)
            modulus_ql *= BigInteger(moduli_q[i]);
        const uint32_t bits_ql = modulus_ql.get_msb();
        if (bits_ql > 121)
            CIPHER_THROW(
                    "SPARSE_ENCAPSULATED supports a bottom (first) modulus of at most 121 bits; the current one has " +
                    std::to_string(bits_ql) + " bits.");

        // total size of P' and the number/size of its primes: with composite scaling ~66 bits, or ~127 bits
        // for a bottom modulus above 60 bits (whose sparse secret is denser as well); otherwise unchanged.
        // The size of the bottom modulus is taken as the sum of the bit lengths of its primes, i.e., the
        // first_mod_size_value the primes were generated for (composite_prime_moduli_gen for composite scaling), so that
        // the rule matches sparse_ks_hamming_weight(first_mod_size_value) used by the depth estimates.
        constexpr uint32_t aux_bits_plain = 2 * (MAX_MODULUS_SIZE / 2 + 3);
        const bool is_composite = (composite_degree > 1);
        uint32_t first_mod_size_value = 0;
        for (uint32_t i = 0; i < size_ql; ++i)
            first_mod_size_value += moduli_q[i].get_msb();
        sparse_ks_hamming_weight_ = sparse_ks_hamming_weight(first_mod_size_value);
        const bool large_bottom = (sparse_ks_hamming_weight_ > 32);
        const uint32_t aux_bits_sparse = (!is_composite) ? aux_bits_plain : (large_bottom ? 127 : 66);
        const uint32_t register_bits = (is_composite) ? get_register_word_size() : MAX_MODULUS_SIZE;
        const uint32_t max_prime_bits = std::min<uint32_t>(register_bits, MAX_MODULUS_SIZE);
        uint32_t size_p_sparse = 2;
        uint32_t bits_p_sparse = (aux_bits_sparse + size_p_sparse - 1) / size_p_sparse;
        // the primes have to fit (strictly) in the register word size and in a native integer
        while (bits_p_sparse >= register_bits || bits_p_sparse > MAX_MODULUS_SIZE) {
            ++size_p_sparse;
            bits_p_sparse = (aux_bits_sparse + size_p_sparse - 1) / size_p_sparse;
        }
        // the original configuration (two 33-bit primes searched downwards) is kept for the non-composite case
        const bool search_down = (!is_composite && size_p_sparse == 2);

        uint32_t n = get_element_params()->get_ring_dimension();
        uint64_t prime_step = find_aux_prime_step();

        // the auxiliary primes must differ from all moduli in Q and in the hybrid key
        // switching basis P (a repeated modulus would be registered with a different root
        // of unity in the NTT tables)
        std::vector<NativeInteger> moduli_to_avoid = moduli_q;
        if (get_params_p() != nullptr) {
            for (const auto& p : get_params_p()->get_params())
                moduli_to_avoid.push_back(p->get_modulus());
        }

        std::vector<NativeInteger> moduli_p_sparse(size_p_sparse);
        std::vector<NativeInteger> roots_p_sparse(size_p_sparse);
        NativeInteger p_cur = first_prime<NativeInteger>(bits_p_sparse, prime_step);
        if (!search_down) {
            // first_prime returns the smallest prime with bits_p_sparse bits; start just below it so the
            // loop below can accept it
            p_cur = previous_prime<NativeInteger>(p_cur, prime_step);
        }
        BigInteger modulus_p_sparse(1);
        for (uint32_t j = 0; j < size_p_sparse; ++j) {
            bool found = false;
            do {
                p_cur = (search_down) ? previous_prime<NativeInteger>(p_cur, prime_step) :
                                        next_prime<NativeInteger>(p_cur, prime_step);
                found = (std::find(moduli_to_avoid.begin(), moduli_to_avoid.end(), p_cur) != moduli_to_avoid.end());
            } while (found);
            if (p_cur.get_msb() > max_prime_bits)
                CIPHER_THROW("Could not find enough auxiliary primes of at most " + std::to_string(max_prime_bits) +
                             " bits for SPARSE_ENCAPSULATED at this ring dimension.");
            moduli_p_sparse[j] = p_cur;
            roots_p_sparse[j] = root_of_unity<NativeInteger>(2 * n, moduli_p_sparse[j]);
            modulus_p_sparse *= BigInteger(moduli_p_sparse[j]);
        }

        std::vector<NativeInteger> moduli_ql_sparse(moduli_q.begin(), moduli_q.begin() + size_ql);
        std::vector<NativeInteger> roots_ql_sparse(roots_q.begin(), roots_q.begin() + size_ql);

        sparse_ks_params_p_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_p_sparse, roots_p_sparse);
        sparse_ks_params_q_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_ql_sparse, roots_ql_sparse);

        std::vector<NativeInteger> moduli_qp_sparse(moduli_ql_sparse);
        std::vector<NativeInteger> roots_qp_sparse(roots_ql_sparse);
        moduli_qp_sparse.insert(moduli_qp_sparse.end(), moduli_p_sparse.begin(), moduli_p_sparse.end());
        roots_qp_sparse.insert(roots_qp_sparse.end(), roots_p_sparse.begin(), roots_p_sparse.end());
        sparse_ks_params_qp_ = std::make_shared<RnsParams<BigInteger>>(2 * n, moduli_qp_sparse, roots_qp_sparse);

        // Pre-compute CRT::FFT values for P'
        ChineseRemainderTransformFtt<NativeVector>().pre_compute(roots_p_sparse, 2 * n, moduli_p_sparse);

        const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));

        // ---- tables for the switch from P' to Ql (scaling down after the key switch) ----
        sparse_ksp_modq_.resize(size_ql);
        sparse_ksp_inv_modq_.resize(size_ql);
        sparse_ksp_hat_modq_.assign(size_ql, std::vector<NativeInteger>(size_p_sparse));
        sparse_ks_alpha_p_modq_.assign(size_p_sparse + 1, std::vector<NativeInteger>(size_ql));
        sparse_ks_modq_barrett_mu_.resize(size_ql);
        for (uint32_t i = 0; i < size_ql; ++i) {
            BigInteger qi(moduli_q[i]);
            sparse_ksp_modq_[i] = modulus_p_sparse.mod(qi).convert_to_int();
            sparse_ksp_inv_modq_[i] = modulus_p_sparse.mod_inverse(qi).convert_to_int();
            for (uint32_t j = 0; j < size_p_sparse; ++j)
                sparse_ksp_hat_modq_[i][j] =
                        (modulus_p_sparse / BigInteger(moduli_p_sparse[j])).mod(qi).convert_to_int();
            // the overflow correction [a*P']_{q_i}, 0 <= a <= k (running sum; the a = 0 row stays zero)
            for (uint32_t a = 1; a <= size_p_sparse; ++a)
                sparse_ks_alpha_p_modq_[a][i] =
                        sparse_ks_alpha_p_modq_[a - 1][i].mod_add_fast(sparse_ksp_modq_[i], moduli_q[i]);
            // reuse the Barrett constants computed for HYBRID above when available
            sparse_ks_modq_barrett_mu_[i] = (modq_barrett_mu_.size() > i) ?
                                                    modq_barrett_mu_[i] :
                                                    (barrett_base128_bit / qi).convert_to_int<DoubleNativeInt>();
        }
        // [(P'/p'_j)^{-1}]_{p'_j} and 1./p'_j
        sparse_ksp_hat_inv_modp_.resize(size_p_sparse);
        sparse_ksp_hat_inv_modp_precon_.resize(size_p_sparse);
        sparse_ks_p_inv_.resize(size_p_sparse);
        for (uint32_t j = 0; j < size_p_sparse; ++j) {
            BigInteger pj(moduli_p_sparse[j]);
            BigInteger p_hatj = modulus_p_sparse / pj;
            sparse_ksp_hat_inv_modp_[j] = p_hatj.mod_inverse(pj).convert_to_int();
            sparse_ksp_hat_inv_modp_precon_[j] = sparse_ksp_hat_inv_modp_[j].prep_mod_mul_const(moduli_p_sparse[j]);
            sparse_ks_p_inv_[j] = 1.0 / moduli_p_sparse[j].convert_to_double();
        }

        // ---- tables for the switch from Ql to P' (extending the ciphertext and the keys) ----
        // [(Ql/q_i)^{-1}]_{q_i} and 1/q_i are shared with the composite scaling modulus raise
        // (mod_raise_ql_hat_inv_modq_ etc.); only the P'-dependent tables are computed here.
        sparse_ks_ql_hat_modp_.assign(size_p_sparse, std::vector<NativeInteger>(size_ql));
        sparse_ks_alpha_ql_modp_.assign(size_ql + 1, std::vector<NativeInteger>(size_p_sparse));
        sparse_ks_modp_barrett_mu_.resize(size_p_sparse);
        for (uint32_t j = 0; j < size_p_sparse; ++j) {
            BigInteger pj(moduli_p_sparse[j]);
            for (uint32_t i = 0; i < size_ql; ++i)
                sparse_ks_ql_hat_modp_[j][i] = (modulus_ql / BigInteger(moduli_q[i])).mod(pj).convert_to_int();
            NativeInteger ql_modpj = modulus_ql.mod(pj).convert_to_int();
            for (uint32_t a = 1; a <= size_ql; ++a)
                sparse_ks_alpha_ql_modp_[a][j] =
                        sparse_ks_alpha_ql_modp_[a - 1][j].mod_add_fast(ql_modpj, moduli_p_sparse[j]);
            sparse_ks_modp_barrett_mu_[j] = (barrett_base128_bit / pj).convert_to_int<DoubleNativeInt>();
        }
    }
}

uint64_t CkksRnsCryptoParams::find_aux_prime_step() const {
    size_t n = get_element_params()->get_ring_dimension();
    return static_cast<uint64_t>(2 * n);
}

void CkksRnsCryptoParams::configure_composite_degree(uint32_t scaling_mod_size) {
    // Add logic to determine whether composite scaling is feasible or not
    if (get_scaling_technique() == COMPOSITESCALINGAUTO) {
        uint32_t register_word_size = get_register_word_size();
        if (register_word_size <= 64) {
            if (register_word_size < scaling_mod_size) {
                uint32_t composite_degree =
                        static_cast<uint32_t>(std::ceil(static_cast<float>(scaling_mod_size) / register_word_size));
                // Assert minimum allowed moduli size on composite scaling mode
                // @fdiasmor TODO: make it more robust for a range of multiplicative depth
                if (static_cast<float>(scaling_mod_size) / composite_degree < 19) {
                    std::string err_msg = "Moduli size (";
                    err_msg += std::to_string(static_cast<float>(scaling_mod_size) / composite_degree);
                    err_msg +=
                            ") is too short (< 19) for target multiplicative depth. Consider increasing the scaling factor or the register word size.";
                    CIPHER_THROW(err_msg);
                }
                composite_degree_ = composite_degree;
            }  // else composite degree remains set to 1
        } else {
            CIPHER_THROW("COMPOSITESCALING scaling technique only supports register word size <= 64.");
        }
    }
}

}  // namespace cipher
