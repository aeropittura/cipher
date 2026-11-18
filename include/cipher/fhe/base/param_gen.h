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

#ifndef CIPHER_FHE_BASE_PARAM_GEN_H_
#define CIPHER_FHE_BASE_PARAM_GEN_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/constants.h"
#include "cipher/fhe/base/crypto_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Abstract interface for parameter generation algorithm
 * @tparam Element a ring element.
 */
template <class Element>
class BaseParamGen {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

  public:
    virtual ~BaseParamGen() = default;

    /**
     * Method for computing all derived parameters based on chosen primitive
     * parameters
     *
     * @param crypto_params the crypto parameters object to be populated with
     * parameters.
     * @param eval_add_count number of EvalAdds assuming no eval_mult and key_switch
     * operations are performed.
     * @param multiplicative_depth number of EvalMults assuming no eval_add and
     * key_switch operations are performed.
     * @param key_switch_count number of key_switch operations assuming no eval_add
     * and eval_mult operations are performed.
     * @param dcrt_bits number of bits in each CRT modulus*
     * @param n ring dimension in case the user wants to use a custom ring
     * dimension
     * @param num_part_q number of partitions of Q for HYBRID key switching
     * @return true if the parameters were generated successfully (errors are reported by throwing).
     */
    virtual bool params_gen_bfvrns_internal(std::shared_ptr<BaseCryptoParams<Element>> crypto_params,
                                            uint32_t eval_add_count, uint32_t multiplicative_depth,
                                            uint32_t key_switch_count, size_t dcrt_bits, uint32_t n,
                                            uint32_t num_part_q) const {
        CIPHER_THROW("Not supported for this scheme.");
    }

    /**
     * Method for computing all derived parameters based on chosen primitive
     * parameters.
     *
     * @param crypto_params the crypto parameters object to be populated with
     * parameters.
     * @param cycl_order the cyclotomic order.
     * @param num_primes_value number of modulus towers to support.
     * @param scaling_mod_size the bit-width for plaintexts and RnsPoly's.
     * @param first_mod_size_value the bit-size of the first modulus
     * @param num_part_q number of partitions of Q for HYBRID key switching
     * @param m_p_int_boot_ciphertext_compression_level compression level of the ciphertexts used in
     * multi-party interactive bootstrapping
     * @return true if the parameters were generated successfully (errors are reported by throwing).
     */
    virtual bool params_gen_ckksrns_internal(std::shared_ptr<BaseCryptoParams<Element>> crypto_params,
                                             uint32_t cycl_order, uint32_t num_primes_value, uint32_t scaling_mod_size,
                                             uint32_t first_mod_size_value, uint32_t num_part_q,
                                             CompressionLevel m_p_int_boot_ciphertext_compression_level) const {
        CIPHER_THROW("Not supported for this scheme.");
    }

    /**
     * Method for computing all derived parameters based on chosen primitive
     * parameters. This is intended for BGVrns
     * @param crypto_params the crypto parameters object to be populated with
     * parameters.
     * @param eval_add_count number of EvalAdds per level.
     * @param key_switch_count number of key_switch operations per level.
     * @param cycl_order the cyclotomic order.
     * @param num_primes_value number of modulus towers to support.
     * @param first_mod_size_value the bit-size of the first modulus
     * @param dcrt_bits the bit-width of moduli
     * @param num_part_q number of partitions of Q for HYBRID key switching
     * @param pre_num_hops bound for the HRA-secure mode of PRE
     * @return true if the parameters were generated successfully (errors are reported by throwing).
     */
    virtual bool params_gen_bgvrns_internal(std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params,
                                            uint32_t eval_add_count, uint32_t key_switch_count, uint32_t cycl_order,
                                            uint32_t num_primes_value, uint32_t first_mod_size_value,
                                            uint32_t dcrt_bits, uint32_t num_part_q, uint32_t pre_num_hops) const {
        CIPHER_THROW("Not supported for this scheme.");
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "ParameterGenerationBase";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_PARAM_GEN_H_
