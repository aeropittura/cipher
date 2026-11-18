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
  Hybrid key switching: the digit decomposition of BV combined with the auxiliary modulus of GHS
  (https://eprint.iacr.org/2012/099). The RNS version was introduced in https://eprint.iacr.org/2019/688;
  see Appendix B of https://eprint.iacr.org/2021/204 for a detailed description.
 */
#ifndef CIPHER_FHE_KEYSWITCH_HYBRID_H_
#define CIPHER_FHE_KEYSWITCH_HYBRID_H_

#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/keyswitch/rns.h"
#include "cipher/fhe/base/rlwe_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief RNS variant of hybrid key switching, which combines the digit decomposition of BV with the auxiliary
 * modulus of Gentry-Halevi-Smart (GHS).
 *
 * GHS key switching (https://eprint.iacr.org/2012/099) multiplies the element to be switched by a key defined
 * modulo QP, where the old secret key is scaled by the auxiliary modulus P, and then divides the result by P, which
 * shrinks the noise added by the key switching by a factor P. Used alone it needs P of the size of Q, which halves
 * the usable modulus. The hybrid method (RNS version in https://eprint.iacr.org/2019/688, described in Appendix B
 * of https://eprint.iacr.org/2021/204) first decomposes the element into dnum large digits, each digit being the
 * product of alpha = ceil(size_q / dnum) consecutive RNS limbs of Q, and then applies the GHS product in the
 * extended basis QP. The noise is proportional to the size of one digit, so P only needs to be about as large as a
 * digit (the number of limbs of P is about alpha), and the cost is 2 * dnum * (number of limbs) NTTs, linear rather
 * than quadratic as in BV. The number of digits is set by the crypto parameter num_large_digits (dnum).
 *
 * The key holds one (b_j, a_j) pair per digit, defined modulo QP, with a_j uniformly random and
 * b_j = -a_j * sB + noise_scale_value * e_j + P * [sA]_{Q_j}, where [sA]_{Q_j} is the old key restricted to the limbs of
 * digit j (following https://eprint.iacr.org/2018/117 the CRT factors of the decomposition are folded into the key).
 * Key switching an element c at level l consists of: (1) splitting c into its digits, each extended from its limbs
 * to the whole basis QlP with an approximate CRT basis extension (eval_key_switch_precompute_core); (2) the inner
 * products of the digits with the two key vectors modulo QlP (eval_fast_key_switch_core_ext); (3) the division by P with
 * rounding, an approximate modulus switching from QlP to Ql (key_switch_down). Steps (1) and (2) can be hoisted or
 * accumulated across several key switchings, which is what fast rotations and the linear transforms of CKKS
 * bootstrapping rely on.
 */
class KeySwitchHybrid : public RnsKeySwitch {
    using ParmType = typename RnsPoly::Params;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    /**
     * Default constructor.
     */
    KeySwitchHybrid() = default;

    /**
     * Virtual destructor.
     */
    virtual ~KeySwitchHybrid() = default;

    /**
     * Generates a hybrid key switching key from old_private_key to new_private_key: one (b_j, a_j) pair modulo QP per
     * digit, with b_j = -a_j * sB + noise_scale_value * e_j + P * [sA]_{Q_j}. The new key is extended from Q to QP for this
     * purpose.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_private_key private key the switched ciphertexts should decrypt under
     * @return the key switching key
     */
    EvalKey<RnsPoly> key_switch_gen_internal(const PrivateKey<RnsPoly> old_private_key,
                                           const PrivateKey<RnsPoly> new_private_key) const override;

    /**
     * Generates a hybrid key switching key from old_private_key to new_private_key reusing the "a" components of
     * eval_key (threshold FHE); see KeySwitchBase::key_switch_gen_internal.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_private_key private key the switched ciphertexts should decrypt under
     * @param eval_key key switching key whose "a" components are reused; if null, fresh components are sampled
     * @return the key switching key
     */
    EvalKey<RnsPoly> key_switch_gen_internal(const PrivateKey<RnsPoly> old_private_key,
                                           const PrivateKey<RnsPoly> new_private_key,
                                           const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Generates a hybrid key switching key from old_private_key to the secret key of new_public_key by encrypting
     * P * [sA]_{Q_j} for every digit with the public key, modulo QP (proxy re-encryption).
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_public_key public key of the party the switched ciphertexts should decrypt for
     * @return the key switching key
     */
    EvalKey<RnsPoly> key_switch_gen_internal(const PrivateKey<RnsPoly> old_private_key,
                                           const PublicKey<RnsPoly> new_public_key) const override;

    /**
     * Key switches a ciphertext in place; see KeySwitchBase::key_switch_in_place.
     *
     * @param ciphertext ciphertext to be key switched; holds the result
     * @param eval_key key switching key
     */
    void key_switch_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Raises a ciphertext from basis Ql to the extended basis QlP by multiplying its elements by P; see
     * KeySwitchBase::key_switch_ext.
     *
     * @param ciphertext ciphertext in basis Ql
     * @param add_first if true, the first element c0 is raised as well; if false, it is set to zero
     * @return the ciphertext in basis QlP
     */
    Ciphertext<RnsPoly> key_switch_ext(ConstCiphertext<RnsPoly> ciphertext, bool add_first) const override;

    /**
     * Divides a two-element ciphertext in basis QlP by P with rounding, returning it in basis Ql; see
     * KeySwitchBase::key_switch_down.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the ciphertext in basis Ql
     */
    Ciphertext<RnsPoly> key_switch_down(ConstCiphertext<RnsPoly> ciphertext) const override;

    /**
     * Divides the first element of a ciphertext in basis QlP by P with rounding, returning it in basis Ql.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the first element switched to basis Ql
     */
    RnsPoly key_switch_down_first_element(ConstCiphertext<RnsPoly> ciphertext) const override;

    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
     * Key switches a single ring element: digit decomposition, inner products with the key, and division by P.
     *
     * @param a ring element to be key switched, in basis Ql
     * @param eval_key key switching key
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<RnsPoly> key_switch_core(const RnsPoly& a, const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Splits a ring element into its digits and extends every digit from its own limbs to the whole basis QlP. The
     * number of digits is ceil(size_ql / alpha), capped by the number of digits of the key; the last digit may hold
     * fewer than alpha limbs at lower levels. The basis extension is the approximate (non-exact) CRT conversion,
     * whose small overflow is accounted for in the noise analysis.
     *
     * @param c ring element to be decomposed, in basis Ql
     * @param crypto_params_base crypto parameters holding the partition of Q into digits and the extension tables
     * @return the digits of c, each in basis QlP
     */
    std::shared_ptr<std::vector<RnsPoly>> eval_key_switch_precompute_core(
            const RnsPoly& c, std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params_base) const override;

    /**
     * Computes the inner products of the digits with the two key vectors modulo QlP (eval_fast_key_switch_core_ext) and
     * divides the two results by P with rounding to return them in basis Ql.
     *
     * @param digits digits of the element computed by eval_key_switch_precompute_core
     * @param eval_key key switching key
     * @param params_ql parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<RnsPoly> eval_fast_key_switch_core(const std::shared_ptr<std::vector<RnsPoly>> digits,
                                                const EvalKey<RnsPoly> eval_key,
                                                const std::shared_ptr<ParmType> params_ql) const override;

    /**
     * Computes the inner products of the digits with the two key vectors modulo QlP and leaves the result in the
     * extended basis; only the limbs of the key that correspond to Ql and P are used. See
     * KeySwitchBase::eval_fast_key_switch_core_ext for how the result is accumulated and switched down.
     *
     * @param digits digits of the element computed by eval_key_switch_precompute_core
     * @param eval_key key switching key
     * @param params_ql parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis QlP such that b' + a' * sB = P * a * sA + noise
     */
    std::vector<RnsPoly> eval_fast_key_switch_core_ext(const std::shared_ptr<std::vector<RnsPoly>> digits,
                                                   const EvalKey<RnsPoly> eval_key,
                                                   const std::shared_ptr<ParmType> params_ql) const override;

    /////////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////////

    /**
     * Serializes the object (no state of its own beyond the base class).
     *
     * @param ar archive to write to
     */
    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<RnsKeySwitch>(this));
    }

    /**
     * Deserializes the object.
     *
     * @param ar archive to read from
     */
    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<RnsKeySwitch>(this));
    }

    /**
     * Name used to identify the class in serialized objects.
     *
     * @return the name of the class
     */
    std::string serialized_object_name() const override {
        return "KeySwitchHYBRID";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_KEYSWITCH_HYBRID_H_
