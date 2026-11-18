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

#ifndef CIPHER_FHE_BFV_LEVELED_SHE_H_
#define CIPHER_FHE_BFV_LEVELED_SHE_H_

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
 * @brief BFV implementation of the leveled SHE operations in the RNS representation. Ciphertext-ciphertext
 * multiplication is implemented with the HPS, BEHZ, HPSPOVERQ and HPSPOVERQLEVELED RNS techniques, and the
 * mutable operations are not supported since BFV performs no automatic rescaling.
 */
class BfvRnsLeveledShe : public RnsLeveledShe {
  public:
    virtual ~BfvRnsLeveledShe() = default;

    using RnsLeveledShe::eval_add_in_place;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    using RnsLeveledShe::eval_sub_in_place;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    using RnsLeveledShe::eval_mult;
    using RnsLeveledShe::eval_mult_in_place;

    using RnsLeveledShe::eval_square;
    using RnsLeveledShe::eval_square_in_place;

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                  ConstCiphertext<RnsPoly>& ciphertext2) const override;

    /**
     * Homomorphic squaring of a ciphertext without relinearization, using the configured multiplication
     * technique (HPS, BEHZ, HPSPOVERQ or HPSPOVERQLEVELED).
     *
     * @param ciphertext the input ciphertext.
     * @return the new ciphertext with noise scale degree increased by 1.
     */
    Ciphertext<RnsPoly> eval_square(ConstCiphertext<RnsPoly>& ciphertext) const override;

    /**
     * Homomorphic multiplication of two ciphertexts followed by relinearization with the given key.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key the relinearization key.
     * @return the new ciphertext with two polynomials.
     */
    Ciphertext<RnsPoly> eval_mult(ConstCiphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2,
                                  const EvalKey<RnsPoly> eval_key) const override;

    /**
     * In-place homomorphic multiplication of two ciphertexts followed by relinearization with the given key.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key the relinearization key.
     */
    void eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2,
                         const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the given key.
     *
     * @param ciphertext the input ciphertext.
     * @param eval_key the relinearization key.
     * @return the new ciphertext with two polynomials.
     */
    Ciphertext<RnsPoly> eval_square(ConstCiphertext<RnsPoly>& ciphertext,
                                    const EvalKey<RnsPoly> eval_key) const override;

    /**
     * In-place homomorphic squaring of a ciphertext followed by relinearization with the given key.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param eval_key the relinearization key.
     */
    void eval_square_in_place(Ciphertext<RnsPoly>& ciphertext1, const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Multiplies all polynomials of the ciphertext by an integer scalar and increases the noise scale degree
     * by 1.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer to multiply by.
     */
    void eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, NativeInteger scalar) const;

    // We do not need to support BfvRnsLeveledShe::Eval*Mutable(InPlace) as no automated adjustment of ciphertexts is
    // typically done in BFV. These functions throw an exception if called
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                         Ciphertext<RnsPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key the relinearization key.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2,
                                         const EvalKey<RnsPoly> eval_key) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key the relinearization key.
     */
    void eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2,
                                const EvalKey<RnsPoly> eval_key) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_add_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                        Ciphertext<RnsPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_add_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     */
    void eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                        Ciphertext<RnsPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<RnsPoly> eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     */
    void eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const override;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    /**
     * Evaluates the automorphism x -> x^i on a ciphertext. The ciphertext is first key switched with the key for
     * index i (which for HPSPOVERQLEVELED includes the modulus reduction to Q_l and the expansion back to Q) and
     * the automorphism is then applied to both polynomials.
     *
     * @param ciphertext the input ciphertext.
     * @param i automorphism index.
     * @param eval_key_map reference to the map of evaluation keys generated by eval_automorphism_key_gen.
     * @return the resulting ciphertext.
     */
    Ciphertext<RnsPoly> eval_automorphism(ConstCiphertext<RnsPoly>& ciphertext, uint32_t i,
                                          const std::map<uint32_t, EvalKey<RnsPoly>>& eval_key_map,
                                          CALLER_INFO_ARGS_HDR) const override;

    /**
     * Automorphism and key switching step of hoisted rotations. The auxiliary moduli are dropped from the
     * digits for HYBRID key switching and, for HPSPOVERQLEVELED, the key switched polynomials are expanded
     * back from Q_l to Q before the automorphism is applied.
     *
     * @param ciphertext the input ciphertext to perform the automorphism on.
     * @param index the index of the rotation. Positive indices correspond to left rotations and negative
     * indices correspond to right rotations.
     * @param m is the cyclotomic order.
     * @param digits the digit decomposition created by eval_fast_rotation_precompute at the precomputation step.
     * @return the rotated ciphertext.
     */
    Ciphertext<RnsPoly> eval_fast_rotation(ConstCiphertext<RnsPoly>& ciphertext, const uint32_t index, const uint32_t m,
                                          const std::shared_ptr<std::vector<RnsPoly>> digits) const override;

    /**
     * Precomputation step of hoisted rotations: the digit decomposition of the second ciphertext polynomial.
     * For HPSPOVERQLEVELED with a full-modulus ciphertext, the polynomial is first scaled down to the basis Q_l
     * determined by the noise budget.
     *
     * @param ciphertext the input ciphertext on which to do the precomputation (digit decomposition).
     * @return the digit decomposition of the ciphertext.
     */
    std::shared_ptr<std::vector<RnsPoly>> eval_fast_rotation_precompute(
            ConstCiphertext<RnsPoly>& ciphertext) const override;

    /**
     * Finds the automorphism index corresponding to a rotation index for a power-of-two cyclotomic order.
     *
     * @param index the rotation index.
     * @param m the cyclotomic order.
     * @return the automorphism index.
     */
    uint32_t find_automorphism_index(uint32_t index, uint32_t m) const override;

    /**
     * Compresses a BFV ciphertext by dropping towers (with the exact RNS rescaling by the dropped moduli) until
     * only towers_left towers remain. Only supported for HPSPOVERQ and HPSPOVERQLEVELED with STANDARD encryption.
     *
     * @param ciphertext the input ciphertext.
     * @param towers_left the number of RNS towers to keep.
     * @param noise_scale_deg unused in BFV (kept for a uniform interface).
     * @return the compressed ciphertext.
     */
    Ciphertext<RnsPoly> compress(ConstCiphertext<RnsPoly>& ciphertext, size_t towers_left,
                                  size_t noise_scale_deg) const override;

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
        return "LeveledSHEBFVRNS";
    }

  private:
    /**
     * Key switches the last polynomial of the ciphertext (c_2 after a multiplication, or c_1 for a plain key
     * switch) with the given key and folds the result into (c_0, c_1). For HPSPOVERQLEVELED with a full-modulus
     * ciphertext, the polynomial is scaled down to Q_l before key switching and the result is expanded back to Q.
     *
     * @param ciphertext the input/output ciphertext with two or three polynomials.
     * @param eval_key the key switching (relinearization) key.
     */
    void relinearize_core(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key) const;
};
}  // namespace cipher

#endif  // CIPHER_FHE_BFV_LEVELED_SHE_H_
