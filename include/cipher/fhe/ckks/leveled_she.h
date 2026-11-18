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

#ifndef CIPHER_FHE_CKKS_LEVELED_SHE_H_
#define CIPHER_FHE_CKKS_LEVELED_SHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/rns/leveled_she.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief CKKS implementation of the leveled SHE capability: operations with real and complex constants (encoded
 * at the scaling factor of the ciphertext's level), automatic rescaling and level alignment for the FLEXIBLE*
 * and COMPOSITESCALING* techniques, integer multiplication without scaling, and the CKKS (complex) automorphism
 * indexing used by rotations and conjugation.
 */
class CkksRnsLeveledShe : public RnsLeveledShe {
  public:
    virtual ~CkksRnsLeveledShe() = default;

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    using RnsLeveledShe::eval_add;
    using RnsLeveledShe::eval_add_in_place;

    /////////////////////////////////////////
    // SHE ADDITION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE ADDITION CONSTANT
    /////////////////////////////////////////

    /**
     * Adds a real constant to a ciphertext. The constant is scaled by the scaling factor of the ciphertext's
     * level raised to its noise scale degree and added to the first ciphertext element; no level is consumed.
     *
     * @param ciphertext the input ciphertext
     * @param operand the constant to add
     * @return the sum
     */
    Ciphertext<RnsPoly> eval_add(ConstCiphertext<RnsPoly>& ciphertext, double operand) const override;

    /**
     * Adds a real constant to a ciphertext in place (see eval_add).
     *
     * @param ciphertext the input ciphertext, replaced by the sum
     * @param operand the constant to add
     */
    void eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const override;

    /**
     * Adds a complex constant to a ciphertext. The constant is scaled by the scaling factor of the ciphertext's
     * level raised to its noise scale degree and added to the first ciphertext element; no level is consumed.
     *
     * @param ciphertext the input ciphertext
     * @param operand the constant to add
     * @return the sum
     */
    Ciphertext<RnsPoly> eval_add(ConstCiphertext<RnsPoly>& ciphertext, std::complex<double> operand) const override;

    /**
     * Adds a complex constant to a ciphertext in place (see eval_add).
     *
     * @param ciphertext the input ciphertext, replaced by the sum
     * @param operand the constant to add
     */
    void eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const override;

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE SUBTRACTION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE SUBTRACTION CONSTANT
    /////////////////////////////////////////

    using RnsLeveledShe::eval_sub;
    using RnsLeveledShe::eval_sub_in_place;

    /**
     * Subtracts a real constant from a ciphertext. The constant is scaled by the scaling factor of the
     * ciphertext's level raised to its noise scale degree and subtracted from the first ciphertext element; no
     * level is consumed.
     *
     * @param ciphertext the input ciphertext
     * @param operand the constant to subtract
     * @return the difference
     */
    Ciphertext<RnsPoly> eval_sub(ConstCiphertext<RnsPoly>& ciphertext, double operand) const override;

    /**
     * Subtracts a real constant from a ciphertext in place (see eval_sub).
     *
     * @param ciphertext the input ciphertext, replaced by the difference
     * @param operand the constant to subtract
     */
    void eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const override;

    /////////////////////////////////////////
    // SHE MULTIPLICATION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE MULTIPLICATION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE MULTIPLICATION CONSTANT
    /////////////////////////////////////////

    using BaseLeveledShe<RnsPoly>::eval_mult;
    using BaseLeveledShe<RnsPoly>::eval_mult_in_place;

    /**
     * Multiplies a ciphertext by a real constant. The constant is encoded at the scaling factor of the
     * ciphertext's level, so the noise scale degree increases by one; for the scaling techniques other than
     * FIXEDMANUAL an input of noise scale degree 2 is rescaled first.
     *
     * @param ciphertext the input ciphertext
     * @param operand the constant to multiply by
     * @return the product
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext, double operand) const override;

    /**
     * Multiplies a ciphertext by a real constant in place (see eval_mult).
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param operand the constant to multiply by
     */
    void eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const override;

    /**
     * Multiplies a ciphertext by a plaintext in place and updates the scaling factor of the product: for the
     * FLEXIBLE* and COMPOSITESCALING* techniques it is set to the precomputed level-specific scaling factor of a
     * degree-2 ciphertext at that level (the plaintext is encoded at the canonical scaling factor of the level),
     * for FIXEDMANUAL and FIXEDAUTO to the square of the ciphertext's scaling factor.
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param plaintext the plaintext to multiply by
     */
    void eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Multiplies a ciphertext by a complex constant. The constant is encoded at the scaling factor of the
     * ciphertext's level, so the noise scale degree increases by one; for the scaling techniques other than
     * FIXEDMANUAL an input of noise scale degree 2 is rescaled first.
     *
     * @param ciphertext the input ciphertext
     * @param operand the constant to multiply by
     * @return the product
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext, std::complex<double> operand) const override;

    /**
     * Multiplies a ciphertext by a complex constant in place (see eval_mult).
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param operand the constant to multiply by
     */
    void eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const override;

    /**
     * Multiplies a ciphertext by an unscaled integer: the ciphertext elements are multiplied by the integer directly,
     * so the noise scale degree, level and scaling factor do not change.
     *
     * @param ciphertext the input ciphertext
     * @param integer the integer to multiply by
     * @return the product
     */
    Ciphertext<RnsPoly> mult_by_integer(ConstCiphertext<RnsPoly>& ciphertext, uint64_t integer) const override;

    /**
     * Multiplies a ciphertext by an unscaled integer in place (see mult_by_integer).
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param integer the integer to multiply by
     */
    void mult_by_integer_in_place(Ciphertext<RnsPoly>& ciphertext, uint64_t integer) const override;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    /**
     * Hoisted rotation whose result stays in the extended basis Ql*P of HYBRID key switching: the digit
     * decomposition is multiplied by the automorphism key of the rotation, optionally the first ciphertext element
     * (scaled by P) is added, and the automorphism is applied. Several such results can be accumulated with
     * eval_add_ext before a single key_switch_down.
     *
     * @param ciphertext the input ciphertext (provides the first element when add_first is true)
     * @param index the rotation index
     * @param digits the digit decomposition of the second ciphertext element from eval_fast_rotation_precompute
     * @param add_first whether to add the first ciphertext element to the result before the automorphism
     * @param eval_keys map of automorphism keys
     * @return the rotated ciphertext in the extended basis Ql*P
     */
    Ciphertext<RnsPoly> eval_fast_rotation_ext(ConstCiphertext<RnsPoly>& ciphertext, uint32_t index,
                                               const std::shared_ptr<std::vector<RnsPoly>> digits, bool add_first,
                                               const std::map<uint32_t, EvalKey<RnsPoly>>& eval_keys) const override;

    /**
     * Finds the automorphism index of a CKKS slot rotation (5^index mod m, with the sign convention of the complex
     * canonical embedding).
     *
     * @param index the rotation index
     * @param m the cyclotomic order
     * @return the automorphism index
     */
    uint32_t find_automorphism_index(uint32_t index, uint32_t m) const override;

    /////////////////////////////////////
    // Mod Reduce
    /////////////////////////////////////

    /**
     * Method for scaling in-place.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @details \p ciphertext will have modulus reduction performed in-place.
     */
    void mod_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////
    // Level Reduce
    /////////////////////////////////////

    /**
     * Method for in-place Level Reduction in the CKKS scheme. It just drops
     * "levels" number of the towers of the ciphertext without changing the
     * underlying plaintext.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place
     * @param levels the number of towers to drop.
     */
    void level_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////
    // Compress
    /////////////////////////////////////

    /////////////////////////////////////
    // CKKS Core
    /////////////////////////////////////

    /**
     * Core of the multiplication by a real constant, without the preliminary rescaling of eval_mult_in_place:
     * multiplies the ciphertext elements by the constant encoded at the scaling factor of the current level,
     * increases the noise scale degree by one and multiplies the scaling factor of the ciphertext by that of the
     * level.
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param operand the constant to multiply by
     */
    void eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const;

    /**
     * Core of the multiplication by a complex constant (see the real overload).
     *
     * @param ciphertext the input ciphertext, replaced by the product
     * @param operand the constant to multiply by
     */
    void eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const;

    /**
     * Brings two ciphertexts to the same level and noise scale degree before a binary operation. For FIXEDMANUAL
     * and FIXEDAUTO, towers are dropped (and, for FIXEDAUTO, the degree is raised by multiplying by the dropped
     * modulus); for the FLEXIBLE* and COMPOSITESCALING* techniques the lower-level ciphertext is multiplied by the
     * ratio of the level-specific scaling factors and rescaled or level-reduced so that both operands end up with
     * the same scaling factor.
     *
     * @param ciphertext1 the first ciphertext (modified in place)
     * @param ciphertext2 the second ciphertext (modified in place)
     */
    void adjust_levels_and_depth_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                          Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Same as adjust_levels_and_depth_in_place, followed by a rescaling of both ciphertexts to noise scale degree 1 if
     * they ended up at degree 2.
     *
     * @param ciphertext1 the first ciphertext (modified in place)
     * @param ciphertext2 the second ciphertext (modified in place)
     */
    void adjust_levels_and_depth_to_one_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                 Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Encodes a non-negative real constant for addition to or subtraction from a ciphertext: the constant is scaled
     * by the scaling factor of the ciphertext's level raised to its noise scale degree and reduced modulo each RNS
     * modulus of the ciphertext.
     *
     * @param ciphertext the ciphertext the constant will be added to (provides the level, degree and moduli)
     * @param operand the constant
     * @return the CRT representation of the scaled constant, one residue per tower
     */
    std::vector<RnsPoly::Integer> get_element_for_eval_add_or_sub(ConstCiphertext<RnsPoly>& ciphertext,
                                                                  double operand) const;

    /**
     * Encodes a real constant for multiplication with a ciphertext: the constant is scaled by the scaling factor of
     * the ciphertext's level, rounded and reduced modulo each RNS modulus of the ciphertext (negative constants are
     * represented by their modular negation).
     *
     * @param ciphertext the ciphertext the constant will multiply (provides the level and moduli)
     * @param operand the constant
     * @return the CRT representation of the scaled constant, one residue per tower
     */
    std::vector<RnsPoly::Integer> get_element_for_eval_mult(ConstCiphertext<RnsPoly>& ciphertext, double operand) const;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<RnsLeveledShe>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<RnsLeveledShe>(this));
    }

    std::string serialized_object_name() const {
        return "LeveledSHECKKSRNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_LEVELED_SHE_H_
