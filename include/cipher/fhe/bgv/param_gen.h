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

#ifndef CIPHER_FHE_BGV_PARAM_GEN_H_
#define CIPHER_FHE_BGV_PARAM_GEN_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/rns/param_gen.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Struct that keeps track of all noise estimates necessary to compute the BGV moduli.
 */
struct BgvNoiseEstimates {
    /** the bound on the error distribution */
    double berr;
    /** the bound on the key distribution */
    double bkey;
    /** the expansion factor of the ring */
    double expansion_factor;
    /** the noise after encryption */
    double fresh_encryption_noise;
    /** the noise after key switching */
    double key_switching_noise;
    /** the noise after modulus switching */
    double mod_switching_noise;
    /** the noise we wish to maintain at each level */
    double noise_per_level;

    /**
     * Constructor that stores all noise estimates.
     *
     * @param Berr0 the bound on the error distribution.
     * @param Bkey0 the bound on the key distribution.
     * @param expansion_factor0 the expansion factor of the ring.
     * @param fresh_encryption_noise0 the noise after encryption.
     * @param key_switching_noise0 the noise after key switching.
     * @param mod_switching_noise0 the noise after modulus switching.
     * @param noise_per_level0 the noise we wish to maintain at each level.
     */
    BgvNoiseEstimates(double berr0, double bkey0, double expansion_factor0, double fresh_encryption_noise0,
                      double key_switching_noise0, double mod_switching_noise0, double noise_per_level0)
        : berr(berr0),
          bkey(bkey0),
          expansion_factor(expansion_factor0),
          fresh_encryption_noise(fresh_encryption_noise0),
          key_switching_noise(key_switching_noise0),
          mod_switching_noise(mod_switching_noise0),
          noise_per_level(noise_per_level0) {}
};

/**
 * @brief Parameter generation for the BGV scheme in the RNS representation: derives the ring dimension and
 * the CRT modulus chain from the BGV noise estimates, the requested number of levels and the security level.
 */
class BgvRnsParamGen : public RnsParamGen {
  public:
    virtual ~BgvRnsParamGen() {}

    /**
     * Method that generates parameters for the BGV RNS scheme.
     *
     * @param crypto_params contains parameters input by the user
     * @param eval_add_count is the maximum number of additions per level.
     * @param key_switch_count is the maximum number of key switches per level.
     * @param cycl_order is the cyclotomic order, which is twice the ring dimension.
     * @param num_primes_value Number of CRT moduli.
     * @param first_mod_size_value is the approximate bit size of the first CRT modulus.
     * @param dcrt_bits is the approximate bit size of the remaining CRT moduli.
     * @param num_part_q number of partitions (digits) of Q for HYBRID key switching.
     * @param num_hops numbers of hops for HRA-secure PRE
     * @return true on success (an exception is thrown otherwise).
     */
    bool params_gen_bgvrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params, uint32_t eval_add_count,
                                    uint32_t key_switch_count, uint32_t cycl_order, uint32_t num_primes_value,
                                    uint32_t first_mod_size_value, uint32_t dcrt_bits, uint32_t num_part_q,
                                    uint32_t num_hops) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "ParameterGenerationBGVRNS";
    }

  private:
    /**
     * Method that computes a security-compliant ring dimension.
     *
     * @param crypto_params contains parameters input by the user
     * @param q_bound is the upper bound on the number of bits in the ciphertext modulus
     * @param cycl_order is the cyclotomic order, which is twice the ring dimension.
     * @return The ring dimension.
     */
    uint32_t compute_ring_dimension(const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t q_bound,
                                    uint32_t cycl_order) const;

    /**
     * Computes the BGV noise bounds (fresh encryption, key switching, modulus switching and the noise to be
     * kept per level) for the given ring dimension and operation counts.
     *
     * @param crypto_params contains parameters input by the user.
     * @param ring_dimension_value is the dimension of the ring (n).
     * @param eval_add_count is the maximum number of additions per level.
     * @param key_switch_count is the maximum number of key switches per level.
     * @param aux_towers is the number of RNS limbs in the additional modulus P, used for hybrid key-switching.
     * @param num_primes_value Number of CRT moduli.
     * @return the noise estimates.
     */
    BgvNoiseEstimates compute_noise_estimates(const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params,
                                              uint32_t ring_dimension_value, uint32_t eval_add_count,
                                              uint32_t key_switch_count, uint32_t aux_towers,
                                              uint32_t num_primes_value) const;

    /**
     * Computes the modulus the CRT primes must be congruent to 1 with: the cyclotomic order 2n, or lcm(2n, t)
     * for FIXEDAUTO where the primes must also be 1 modulo the plaintext modulus t.
     *
     * @param ring_dimension_value is the dimension of the ring (n).
     * @param plain_modulus the plaintext modulus t.
     * @param scal_tech the scaling technique.
     * @return the modulus for the prime search.
     */
    uint64_t get_cyclic_order(const uint32_t ring_dimension_value, const int plain_modulus,
                              const ScalingTechnique scal_tech) const;

    /**
     * Method that generates moduli for FLEXIBLEAUTOEXT mode for the BGV RNS scheme.
     *
     * @param crypto_params contains parameters input by the user
     * @param ring_dimension_value is the dimension of the ring (n)
     * @param eval_add_count is the maximum number of additions per level.
     * @param key_switch_count is the maximum number of key switches per level.
     * @param aux_towers is the number of RNS limbs in the additional modulus P, used for hybrid key-switching.
     * @param num_primes_value Number of CRT moduli.
     * @return A pair containing: 1) a vector with the CRT moduli and 2) the total modulus size to be used for
     * ensuring security compliance.
     */
    std::pair<std::vector<NativeInteger>, uint32_t> compute_moduli(
            const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params, uint32_t ring_dimension_value,
            uint32_t eval_add_count, uint32_t key_switch_count, uint32_t aux_towers, uint32_t num_primes_value) const;

    /**
     * Method that initializes the Discrete Gaussian Generator with flooding for PRE.
     *
     * @param crypto_params contains parameters input by the user
     * @param num_primes_value Number of CRT moduli.
     * @param ring_dimension_value ring dimension.
     */
    void initialize_flooding_dgg(const std::shared_ptr<BaseCryptoParams<RnsPoly>>& crypto_params,
                                 uint32_t num_primes_value, uint32_t ring_dimension_value) const;
};

}  // namespace cipher

#endif  // CIPHER_FHE_BGV_PARAM_GEN_H_
