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

#ifndef CIPHER_FHE_CKKS_PARAM_GEN_H_
#define CIPHER_FHE_CKKS_PARAM_GEN_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/rns/param_gen.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Parameter generation for the CKKS scheme in RNS form: generates the modulus chain (one prime per level,
 * or composite_degree primes per level for the COMPOSITESCALING* techniques), the auxiliary moduli of key
 * switching and the CRT tables, and validates the ring dimension against the security level.
 */
class CkksRnsParamGen : public RnsParamGen {
  protected:
    /**
     * Generates the modulus chain for composite scaling: each level consists of composite_degree primes of at most
     * register_word_size bits whose product approximates 2^dcrt_bits (the scaling factor), and the first level of
     * primes whose product approximates 2^first_mod_size_value; all primes are distinct and congruent to 1 modulo the
     * cyclotomic order. Requires first_mod_size_value > dcrt_bits.
     *
     * @param moduli_q output: the moduli of the chain (size num_primes_value)
     * @param roots_q output: the corresponding roots of unity
     * @param composite_degree number of primes per level
     * @param num_primes_value total number of primes in the chain
     * @param first_mod_size_value size in bits of the modulus of the first level
     * @param dcrt_bits size in bits of the scaling factor (the modulus of each further level)
     * @param cycl_order cyclotomic order
     * @param register_word_size maximum size in bits of each prime
     */
    void composite_prime_moduli_gen(std::vector<NativeInteger>& moduli_q, std::vector<NativeInteger>& roots_q,
                                    uint32_t composite_degree, uint32_t num_primes_value, uint32_t first_mod_size_value,
                                    uint32_t dcrt_bits, uint32_t cycl_order, uint32_t register_word_size) const;

    /**
     * Generates the modulus chain with one prime per level: primes of dcrt_bits bits alternating around 2^dcrt_bits
     * (or, for FLEXIBLEAUTO and FLEXIBLEAUTOEXT, chosen so that the level-specific scaling factors stay close to
     * 2^dcrt_bits), a first prime of first_mod_size_value bits and, for FLEXIBLEAUTOEXT, an extra prime of extra_modsize
     * bits at the top of the chain.
     *
     * @param moduli_q output: the moduli of the chain (size num_primes_value)
     * @param roots_q output: the corresponding roots of unity
     * @param scal_tech scaling technique
     * @param num_primes_value total number of primes in the chain
     * @param first_mod_size_value size in bits of the first modulus
     * @param dcrt_bits size in bits of the scaling factor (the modulus of each further level)
     * @param cycl_order cyclotomic order
     * @param extra_modsize size in bits of the extra modulus of FLEXIBLEAUTOEXT
     */
    void single_prime_moduli_gen(std::vector<NativeInteger>& moduli_q, std::vector<NativeInteger>& roots_q,
                                 ScalingTechnique scal_tech, uint32_t num_primes_value, uint32_t first_mod_size_value,
                                 uint32_t dcrt_bits, uint32_t cycl_order, uint32_t extra_modsize) const;

  public:
    virtual ~CkksRnsParamGen() = default;

    /**
     * Generates the CKKS parameters: the modulus chain (see single_prime_moduli_gen and composite_prime_moduli_gen), the
     * auxiliary moduli of HYBRID key switching, the CRT tables (CkksRnsCryptoParams::precompute_crt_tables) and
     * the ring dimension, which is chosen from the security level when not set and validated otherwise.
     *
     * @param crypto_params the crypto parameters to complete
     * @param cycl_order cyclotomic order (twice the ring dimension; 0 = chosen from the security level)
     * @param num_primes_value number of levels in the modulus chain (multiplicative depth + 1)
     * @param scaling_mod_size size in bits of the scaling factor
     * @param first_mod_size_value size in bits of the first modulus
     * @param mul_part_q number of digits (partitions of Q) for HYBRID key switching
     * @param m_p_int_boot_ciphertext_compression_level compression level of interactive multiparty bootstrapping
     * @return true on success
     */
    bool params_gen_ckksrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params, uint32_t cycl_order,
                                     uint32_t num_primes_value, uint32_t scaling_mod_size,
                                     uint32_t first_mod_size_value, uint32_t mul_part_q,
                                     CompressionLevel m_p_int_boot_ciphertext_compression_level) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "ParameterGenerationCKKSRNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_PARAM_GEN_H_
