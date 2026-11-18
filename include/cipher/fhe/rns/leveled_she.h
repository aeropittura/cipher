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

#ifndef CIPHER_FHE_RNS_LEVELED_SHE_H_
#define CIPHER_FHE_RNS_LEVELED_SHE_H_

#include <cstdint>
#include <string>

#include "cipher/ring/backend.h"
#include "cipher/fhe/base/leveled_she.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Abstract interface class for LBC SHE algorithms
 */
class RnsLeveledShe : public BaseLeveledShe<RnsPoly> {
  public:
    virtual ~RnsLeveledShe() = default;

    /////////////////////////////////////////
    // SHE NEGATION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    using BaseLeveledShe<RnsPoly>::eval_add;
    using BaseLeveledShe<RnsPoly>::eval_add_in_place;
    using BaseLeveledShe<RnsPoly>::eval_add_mutable;
    using BaseLeveledShe<RnsPoly>::eval_add_mutable_in_place;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_add(ConstCiphertext<RnsPoly>& ciphertext1,
                                 ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic addition
     * of ciphertexts.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    void eval_add_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_add_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                         Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * In-place homomorphic addition of ciphertexts. This is the mutable version - both input ciphertexts may
     * change (automatically rescaled, or towers dropped) to bring them to the same level and depth.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    void eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_add(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_add_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    using BaseLeveledShe<RnsPoly>::eval_sub;
    using BaseLeveledShe<RnsPoly>::eval_sub_in_place;
    using BaseLeveledShe<RnsPoly>::eval_sub_mutable;
    using BaseLeveledShe<RnsPoly>::eval_sub_mutable_in_place;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_sub(ConstCiphertext<RnsPoly>& ciphertext1,
                                 ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    void eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                         Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    void eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_sub(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * In-place homomorphic subtraction of a plaintext from a ciphertext. The plaintext is adjusted to the
     * level and depth of the ciphertext when needed.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /////////////////////////////////////////
    // SHE MULTIPLICATION
    /////////////////////////////////////////

    using BaseLeveledShe<RnsPoly>::eval_mult;
    using BaseLeveledShe<RnsPoly>::eval_mult_in_place;
    using BaseLeveledShe<RnsPoly>::eval_mult_mutable;
    using BaseLeveledShe<RnsPoly>::eval_mult_mutable_in_place;

    /**
     * Homomorphic multiplication of ciphertexts without relinearization. For the automatic scaling techniques
     * copies of the inputs are first brought to the same level and to noise scale degree 1.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext (with one more polynomial than the inputs).
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                  ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Homomorphic multiplication of ciphertexts without relinearization. This is the mutable version - the
     * input ciphertexts may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                          Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Homomorphic squaring of a ciphertext without relinearization. For the automatic scaling techniques a
     * ciphertext of noise scale degree 2 is first rescaled.
     *
     * @param ciphertext the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_square(ConstCiphertext<RnsPoly>& ciphertext) const override;

    /**
     * Homomorphic squaring of a ciphertext without relinearization. This is the mutable version - the input
     * ciphertext may be rescaled in place.
     *
     * @param ciphertext the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_square_mutable(Ciphertext<RnsPoly>& ciphertext) const override;

    /**
     * Homomorphic multiplication of a ciphertext by a plaintext.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * In-place homomorphic multiplication of a ciphertext by a plaintext. For the automatic scaling techniques
     * the plaintext is re-encoded to match the ciphertext level when needed and the noise scale degree of the
     * result is the sum of the input degrees.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Homomorphic multiplication of a ciphertext by a plaintext. This is the mutable version - the input
     * ciphertext may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * In-place homomorphic multiplication of a ciphertext by a plaintext. This is the mutable version - the
     * input ciphertext may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Multiplies a ciphertext by the monomial x^power (a rotation of the coefficients with sign flips).
     *
     * @param ciphertext the input ciphertext.
     * @param power the exponent of the monomial; it is reduced modulo the cyclotomic order 2N.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> mult_by_monomial(ConstCiphertext<RnsPoly>& ciphertext, uint32_t power) const override;

    /**
     * In-place multiplication of a ciphertext by the monomial x^power.
     *
     * @param ciphertext the input/output ciphertext.
     * @param power the exponent of the monomial; it is reduced modulo the cyclotomic order 2N.
     */
    void mult_by_monomial_in_place(Ciphertext<RnsPoly>& ciphertext, uint32_t power) const override;

    /////////////////////////////////////////
    // SHE AUTOMORPHISM
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE LEVELED Mod Reduce
    /////////////////////////////////////////

    /**
     * Method for Modulus Reduction (rescaling). It is a no-op for all scaling techniques other than FIXEDMANUAL,
     * where rescaling is done automatically.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction.
     */
    Ciphertext<RnsPoly> mod_reduce(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /**
     * Method for In-place Modulus Reduction.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     */
    void mod_reduce_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////////
    // SHE LEVELED Level Reduce
    /////////////////////////////////////////

    /**
     * Method for Level Reduction. Drops the given number of towers without changing the underlying plaintext.
     * Only FIXEDMANUAL performs the operation; the automatic techniques ignore it and NORESCALE throws.
     *
     * @param ciphertext is the original ciphertext to be level reduced.
     * @param eval_key evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     * @return the resulting ciphertext.
     */
    Ciphertext<RnsPoly> level_reduce(ConstCiphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key,
                                     size_t levels) const override;

    /**
     * Method for in-place Level Reduction. Drops the given number of towers without changing the underlying
     * plaintext. Only FIXEDMANUAL performs the operation; the automatic techniques ignore it and NORESCALE throws.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place.
     * @param eval_key evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     */
    void level_reduce_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key,
                               size_t levels) const override;

    /////////////////////////////////////////
    // SHE LEVELED Compress
    /////////////////////////////////////////

    /**
     * Compresses a ciphertext by rescaling it down to the requested noise scale degree and then dropping towers
     * until only towers_left towers remain. For the COMPOSITESCALING techniques towers_left must be a multiple of
     * the composite degree.
     *
     * @param ciphertext the input ciphertext.
     * @param towers_left the number of RNS towers to keep.
     * @param noise_scale_deg the noise scale degree the ciphertext is rescaled down to before dropping towers.
     * @return the compressed ciphertext.
     */
    Ciphertext<RnsPoly> compress(ConstCiphertext<RnsPoly>& ciphertext, size_t towers_left,
                                 size_t noise_scale_deg) const override;

    ////////////////////////////////////////
    // SHE LEVELED composed_eval_mult
    ////////////////////////////////////////

    using BaseLeveledShe<RnsPoly>::composed_eval_mult;

    /**
     * Method for Composed eval_mult: multiplication, relinearization with the given key and modulus reduction
     * by one level (or by the composite degree for the COMPOSITESCALING techniques).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key the relinearization key for the quadratic secret key after multiplication.
     * @return the resulting ciphertext.
     */
    Ciphertext<RnsPoly> composed_eval_mult(ConstCiphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2,
                                           const EvalKey<RnsPoly> eval_key) const override;

  protected:
    /////////////////////////////////////
    // RNS Core
    /////////////////////////////////////

    /**
     * Method for rescaling.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction performed.
     */
    Ciphertext<RnsPoly> mod_reduce_internal(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /**
     * Method for rescaling in-place.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @details \p ciphertext will have modulus reduction performed in-place.
     */
    void mod_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const override {
        CIPHER_THROW("Not supported for this scheme");
    }

    /**
     * Method for Level Reduction in the CKKS scheme. It just drops "levels"
     * number of the towers of the ciphertext without changing the underlying
     * plaintext.
     *
     * @param ciphertext is the original ciphertext to be level reduced.
     * @param levels the number of towers to drop.
     * @return resulting ciphertext.
     */
    Ciphertext<RnsPoly> level_reduce_internal(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const override;

    /**
     * Method for in-place Level Reduction in the CKKS scheme. It just drops
     * "levels" number of the towers of the ciphertext without changing the
     * underlying plaintext.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place
     * @param levels the number of towers to drop.
     */
    void level_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const override {
        CIPHER_THROW("Not supported for this scheme");
    }

    /**
     * Drops towers from the ciphertext with more towers so that both ciphertexts have the same number of RNS
     * towers (no rescaling is done).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    void adjust_levels_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Brings two operands of an addition or subtraction to the same level and noise scale degree. For
     * FIXEDMANUAL only the levels are matched and, when one operand is a (morphed) plaintext of lower depth, it
     * is scaled up by the moduli of the dropped towers; for the automatic techniques the scheme-specific
     * adjust_levels_and_depth_in_place() is called; for NORESCALE nothing is done.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    void adjust_for_add_or_sub_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                        Ciphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Brings two operands of a multiplication to the same level and to noise scale degree 1. For FIXEDMANUAL
     * only the levels are matched; for the automatic techniques the scheme-specific
     * adjust_levels_and_depth_to_one_in_place() is called; for NORESCALE nothing is done.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    void adjust_for_mult_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<BaseLeveledShe<RnsPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<BaseLeveledShe<RnsPoly>>(this));
    }

    std::string serialized_object_name() const {
        return "LeveledSHERNS";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_RNS_LEVELED_SHE_H_
