//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#ifndef CIPHER_FHE_CONFIG_SWITCHING_PARAMS_H_
#define CIPHER_FHE_CONFIG_SWITCHING_PARAMS_H_

#include <cstdint>
#include <iosfwd>

#include "cipher/boolean/constants.h"
#include "cipher/ring/standard_params.h"
#include "cipher/math/backend.h"
#include "cipher/util/exception.h"

namespace cipher {

/**
 * @brief Parameters of the CKKS to FHEW and FHEW to CKKS scheme switching setup (eval_ckks_to_fhew_setup,
 * eval_scheme_switching_setup and related calls)
 *
 * The user-facing fields are set with the setters below. The fields marked as populated internally are filled
 * from the CKKS cryptocontext by CryptoContextImpl::set_params_from_ckks_cryptocontext(), and every getter throws an
 * exception until that call has been made.
 */
class SchSwchParams {
    // security level for CKKS cryptocontext
    SecurityLevel security_level_ckks{HEStd_128_classic};
    // security level for FHEW cryptocontext
    BINFHE_PARAMSET security_level_fhew{STD128};
    // number of slots in CKKS encryption
    uint32_t num_slots_ckks{0};
    // number of values to switch
    uint32_t num_values{0};
    // size of ciphertext modulus in FHEW for large-precision evaluation
    uint32_t ctxt_mod_size_fhew_large_prec{25};
    // size of ciphertext modulus in intermediate switch for security with the FHEW ring dimension
    uint32_t ctxt_mod_size_fhew_intermed_swch{27};
    // baby-step for the linear transform in CKKS to FHEW
    uint32_t b_step_l_tr_ckks_to_fhew{0};
    // baby-step for the linear transform in FHEW to CKKS
    uint32_t b_step_l_tr_fhew_to_ckks{0};
    // level on which to do the linear transform in CKKS to FHEW
    uint32_t level_l_tr_ckks_to_fhew{1};
    // level on which to do the linear transform in FHEW to CKKS
    uint32_t level_l_tr_fhew_to_ckks{0};
    // binfhecontext created is for arbitrary function evaluation
    bool arbitrary_function_evaluation{false};
    bool use_dynamic_mode_fhew{false};
    bool compute_argmin{false};
    // have the argmin result one hot encoding
    bool one_hot_encoding{true};
    // use the alternative version of argmin which requires fewer automorphism keys
    bool use_alt_argmin{false};

    // CKKS cryptocontext data (internally populated, NOT by the user)
    bool set_params_from_ckks_cryptocontext_called_{false};
    NativeInteger initial_ckks_modulus{0};
    uint32_t ring_dimension_value{0};
    uint32_t scaling_mod_size{0};
    uint32_t batch_size{0};

    void verify_object_data() const {
        if (!set_params_from_ckks_cryptocontext_called_) {
            CIPHER_THROW(
                    "Objects of class SchSwchParams may be used only after having called SetParamsFromCKKSCryptocontext()");
        }
    }

  public:
    /**
     * Prints all parameter values, including the ones populated from the CKKS cryptocontext.
     *
     * @param s the output stream
     * @param obj the parameter object to print
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& s, const SchSwchParams& obj);
    //=================================================================================================================
    /**
     * Sets the security level of the CKKS cryptocontext.
     * @param security_level_ckks0 security level of the CKKS cryptocontext
     */
    void set_security_level_ckks(SecurityLevel security_level_ckks0) {
        security_level_ckks = security_level_ckks0;
    }
    /**
     * Sets the FHEW/BinFHE parameter set (security level) of the FHEW cryptocontext.
     * @param security_level_fhew0 FHEW/BinFHE parameter set (security level) of the FHEW cryptocontext
     */
    void set_security_level_fhew(BINFHE_PARAMSET security_level_fhew0) {
        security_level_fhew = security_level_fhew0;
    }
    /**
     * Sets whether the FHEW cryptocontext is created for arbitrary function evaluation.
     * @param arbitrary_function_evaluation0 true if the FHEW cryptocontext is created for arbitrary function evaluation
     */
    void set_arbitrary_function_evaluation(bool arbitrary_function_evaluation0) {
        arbitrary_function_evaluation = arbitrary_function_evaluation0;
    }
    /**
     * Sets whether the FHEW cryptocontext is generated in dynamic mode.
     * @param use_dynamic_mode_fhew0 true to generate the FHEW cryptocontext in dynamic mode
     */
    void set_use_dynamic_mode_fhew(bool use_dynamic_mode_fhew0) {
        use_dynamic_mode_fhew = use_dynamic_mode_fhew0;
    }
    /**
     * Sets whether the argmin computation (and its keys) should be supported.
     * @param compute_argmin0 true if the argmin computation (and its keys) should be supported
     */
    void set_compute_argmin(bool compute_argmin0) {
        compute_argmin = compute_argmin0;
    }
    /**
     * Sets whether the argmin result is returned in one-hot encoding.
     * @param one_hot_encoding0 true to return the argmin result in one-hot encoding
     */
    void set_one_hot_encoding(bool one_hot_encoding0) {
        one_hot_encoding = one_hot_encoding0;
    }
    /**
     * Sets whether to use the alternative argmin version, which requires fewer automorphism keys.
     * @param use_alt_argmin0 true to use the alternative argmin version, which requires fewer automorphism keys
     */
    void set_use_alt_argmin(bool use_alt_argmin0) {
        use_alt_argmin = use_alt_argmin0;
    }
    /**
     * Sets the number of slots in the CKKS encryption.
     * @param num_slots_ckks0 number of slots in the CKKS encryption
     */
    void set_num_slots_ckks(uint32_t num_slots_ckks0) {
        num_slots_ckks = num_slots_ckks0;
    }
    /**
     * Sets the number of values to switch.
     * @param num_values0 number of values to switch
     */
    void set_num_values(uint32_t num_values0) {
        num_values = num_values0;
    }
    /**
     * Sets the bit size of the FHEW ciphertext modulus for large-precision evaluation.
     * @param ctxt_mod_size_fhew_large_prec0 bit size of the FHEW ciphertext modulus for large-precision evaluation
     */
    void set_ctxt_mod_size_fhew_large_prec(uint32_t ctxt_mod_size_fhew_large_prec0) {
        ctxt_mod_size_fhew_large_prec = ctxt_mod_size_fhew_large_prec0;
    }
    /**
     * Sets the bit size of the ciphertext modulus of the intermediate switch.
     * @param ctxt_mod_size_fhew_intermed_swch0 bit size of the ciphertext modulus of the intermediate switch, chosen for
     *        security with the FHEW ring dimension
     */
    void set_ctxt_mod_size_fhew_intermed_swch(uint32_t ctxt_mod_size_fhew_intermed_swch0) {
        ctxt_mod_size_fhew_intermed_swch = ctxt_mod_size_fhew_intermed_swch0;
    }
    /**
     * Sets the baby-step of the linear transform in the CKKS to FHEW switching.
     * @param b_step_l_tr_ckks_to_fhew0 baby-step of the linear transform in the CKKS to FHEW switching (0 selects the default)
     */
    void set_b_step_l_tr_ckks_to_fhew(uint32_t b_step_l_tr_ckks_to_fhew0) {
        b_step_l_tr_ckks_to_fhew = b_step_l_tr_ckks_to_fhew0;
    }
    /**
     * Sets the baby-step of the linear transform in the FHEW to CKKS switching.
     * @param b_step_l_tr_fhew_to_ckks0 baby-step of the linear transform in the FHEW to CKKS switching (0 selects the default)
     */
    void set_b_step_l_tr_fhew_to_ckks(uint32_t b_step_l_tr_fhew_to_ckks0) {
        b_step_l_tr_fhew_to_ckks = b_step_l_tr_fhew_to_ckks0;
    }
    /**
     * Sets the level at which the linear transform of the CKKS to FHEW switching is performed.
     * @param level_l_tr_ckks_to_fhew0 level at which the linear transform of the CKKS to FHEW switching is performed
     */
    void set_level_l_tr_ckks_to_fhew(uint32_t level_l_tr_ckks_to_fhew0) {
        level_l_tr_ckks_to_fhew = level_l_tr_ckks_to_fhew0;
    }
    /**
     * Sets the level at which the linear transform of the FHEW to CKKS switching is performed.
     * @param level_l_tr_fhew_to_ckks0 level at which the linear transform of the FHEW to CKKS switching is performed
     */
    void set_level_l_tr_fhew_to_ckks(uint32_t level_l_tr_fhew_to_ckks0) {
        level_l_tr_fhew_to_ckks = level_l_tr_fhew_to_ckks0;
    }
    /**
     * Marks the object as populated from the CKKS cryptocontext, which unlocks the getters. Called by
     * CryptoContextImpl::set_params_from_ckks_cryptocontext().
     */
    void set_params_from_ckks_cryptocontext_called() {
        set_params_from_ckks_cryptocontext_called_ = true;
    }
    /**
     * Sets the first modulus of the CKKS cryptocontext.
     * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
     * @param initial_ckks_modulus0 first (largest-level) modulus of the CKKS cryptocontext
     */
    void set_initial_ckks_modulus(NativeInteger initial_ckks_modulus0) {
        initial_ckks_modulus = initial_ckks_modulus0;
    }
    /**
     * Sets the ring dimension of the CKKS cryptocontext.
     * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
     * @param ring_dimension0 ring dimension of the CKKS cryptocontext
     */
    void set_ring_dimension(uint32_t ring_dimension0) {
        ring_dimension_value = ring_dimension0;
    }
    /**
     * Sets the bit size of the CKKS scaling modulus.
     * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
     * @param scaling_mod_size0 bit size of the CKKS scaling modulus
     */
    void set_scaling_mod_size(uint32_t scaling_mod_size0) {
        scaling_mod_size = scaling_mod_size0;
    }
    /**
     * Sets the batch size of the CKKS cryptocontext.
     * Populated internally from the CKKS cryptocontext; not meant to be set by the user.
     * @param batch_size0 batch size of the CKKS cryptocontext
     */
    void set_batch_size(uint32_t batch_size0) {
        batch_size = batch_size0;
    }
    //=================================================================================================================
    /**
     * Returns the security level of the CKKS cryptocontext.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the security level of the CKKS cryptocontext
     */
    SecurityLevel get_security_level_ckks() const {
        verify_object_data();
        return security_level_ckks;
    }
    /**
     * Returns the FHEW parameter set.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the FHEW parameter set
     */
    BINFHE_PARAMSET get_security_level_fhew() const {
        verify_object_data();
        return security_level_fhew;
    }
    /**
     * Returns whether the FHEW cryptocontext is created for arbitrary function evaluation.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return whether the FHEW cryptocontext is created for arbitrary function evaluation
     */
    bool get_arbitrary_function_evaluation() const {
        verify_object_data();
        return arbitrary_function_evaluation;
    }
    /**
     * Returns whether the FHEW cryptocontext is generated in dynamic mode.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return whether the FHEW cryptocontext is generated in dynamic mode
     */
    bool get_use_dynamic_mode_fhew() const {
        verify_object_data();
        return use_dynamic_mode_fhew;
    }
    /**
     * Returns whether the argmin computation is supported.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return whether the argmin computation is supported
     */
    bool get_compute_argmin() const {
        verify_object_data();
        return compute_argmin;
    }
    /**
     * Returns whether the argmin result is returned in one-hot encoding.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return whether the argmin result is returned in one-hot encoding
     */
    bool get_one_hot_encoding() const {
        verify_object_data();
        return one_hot_encoding;
    }
    /**
     * Returns whether the alternative argmin version is used.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return whether the alternative argmin version is used
     */
    bool get_use_alt_argmin() const {
        verify_object_data();
        return use_alt_argmin;
    }
    /**
     * Returns the number of slots in the CKKS encryption.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the number of slots in the CKKS encryption
     */
    uint32_t get_num_slots_ckks() const {
        verify_object_data();
        return num_slots_ckks;
    }
    /**
     * Returns the number of values to switch.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the number of values to switch
     */
    uint32_t get_num_values() const {
        verify_object_data();
        return num_values;
    }
    /**
     * Returns the bit size of the FHEW ciphertext modulus for large-precision evaluation.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the bit size of the FHEW ciphertext modulus for large-precision evaluation
     */
    uint32_t get_ctxt_mod_size_fhew_large_prec() const {
        verify_object_data();
        return ctxt_mod_size_fhew_large_prec;
    }
    /**
     * Returns the bit size of the intermediate-switch ciphertext modulus.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the bit size of the intermediate-switch ciphertext modulus
     */
    uint32_t get_ctxt_mod_size_fhew_intermed_swch() const {
        verify_object_data();
        return ctxt_mod_size_fhew_intermed_swch;
    }
    /**
     * Returns the baby-step of the CKKS to FHEW linear transform.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the baby-step of the CKKS to FHEW linear transform
     */
    uint32_t get_b_step_l_tr_ckks_to_fhew() const {
        verify_object_data();
        return b_step_l_tr_ckks_to_fhew;
    }
    /**
     * Returns the baby-step of the FHEW to CKKS linear transform.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the baby-step of the FHEW to CKKS linear transform
     */
    uint32_t get_b_step_l_tr_fhew_to_ckks() const {
        verify_object_data();
        return b_step_l_tr_fhew_to_ckks;
    }
    /**
     * Returns the level of the CKKS to FHEW linear transform.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the level of the CKKS to FHEW linear transform
     */
    uint32_t get_level_l_tr_ckks_to_fhew() const {
        verify_object_data();
        return level_l_tr_ckks_to_fhew;
    }
    /**
     * Returns the level of the FHEW to CKKS linear transform.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the level of the FHEW to CKKS linear transform
     */
    uint32_t get_level_l_tr_fhew_to_ckks() const {
        verify_object_data();
        return level_l_tr_fhew_to_ckks;
    }
    /**
     * Returns the first modulus of the CKKS cryptocontext.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the first modulus of the CKKS cryptocontext
     */
    NativeInteger get_initial_ckks_modulus() const {
        verify_object_data();
        return initial_ckks_modulus;
    }
    /**
     * Returns the CKKS ring dimension.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the CKKS ring dimension
     */
    uint32_t get_ring_dimension() const {
        verify_object_data();
        return ring_dimension_value;
    }
    /**
     * Returns the bit size of the CKKS scaling modulus.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the bit size of the CKKS scaling modulus
     */
    uint32_t get_scaling_mod_size() const {
        verify_object_data();
        return scaling_mod_size;
    }
    /**
     * Returns the CKKS batch size.
     * Throws an exception if set_params_from_ckks_cryptocontext() has not been called.
     * @return the CKKS batch size
     */
    uint32_t get_batch_size() const {
        verify_object_data();
        return batch_size;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CONFIG_SWITCHING_PARAMS_H_
