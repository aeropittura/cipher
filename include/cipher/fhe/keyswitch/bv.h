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

#ifndef CIPHER_FHE_KEYSWITCH_BV_H_
#define CIPHER_FHE_KEYSWITCH_BV_H_

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
 * @brief RNS variant of the Brakerski-Vaikuntanathan (BV) key switching method.
 *
 * The method was introduced in [Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent
 * Messages](https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf); see Appendix B of
 * https://eprint.iacr.org/2021/204 for the RNS description used here.
 *
 * The element to be switched is decomposed digit by digit and the digits are multiplied by encryptions of the
 * corresponding multiples of the old secret key, so that the noise added by the key switching is proportional to
 * the size of a digit instead of the size of the ciphertext modulus. In RNS the digits are the CRT residues of the
 * element (one digit per RNS limb q_i of the current modulus Ql), and the key holds one (b_i, a_i) pair per limb of
 * Q, where b_i encrypts the i-th CRT component of the old key under the new key. Following
 * https://eprint.iacr.org/2018/117, the factors (Q/q_i)^{-1} mod q_i of the decomposition are folded into the key, so
 * the digits are obtained for free. When the crypto parameters set a digit size, every residue is further
 * decomposed in radix base 2^digit_size, which reduces the noise at the cost of more key components and more NTTs.
 *
 * Key switching runs entirely in the basis Ql (no auxiliary modulus P), so it does not reduce the usable ciphertext
 * modulus, but it costs a quadratic number of NTTs in the number of limbs, which makes it slower than hybrid key
 * switching for large parameters. The extended-basis operations (key_switch_ext, key_switch_down,
 * eval_fast_key_switch_core_ext) are not supported.
 */
class KeySwitchBv : public RnsKeySwitch {
    using ParmType = typename RnsPoly::Params;
    using DugType = typename RnsPoly::DugType;
    using DggType = typename RnsPoly::DggType;
    using TugType = typename RnsPoly::TugType;

  public:
    /**
     * Default constructor.
     */
    KeySwitchBv() = default;

    /**
     * Virtual destructor.
     */
    virtual ~KeySwitchBv() = default;

    /**
     * Generates a BV key switching key from old_private_key to new_private_key. The key has one (b_i, a_i) pair per RNS
     * limb of the old key (or per radix digit of every limb when a digit size is set), with a_i uniformly random and
     * b_i = -a_i * sB + noise_scale_value * e_i + [sA]_{q_i} placed in limb i.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_private_key private key the switched ciphertexts should decrypt under
     * @return the key switching key
     */
    EvalKey<RnsPoly> key_switch_gen_internal(const PrivateKey<RnsPoly> old_private_key,
                                             const PrivateKey<RnsPoly> new_private_key) const override;

    /**
     * Generates a BV key switching key from old_private_key to new_private_key reusing the "a" components of eval_key
     * (threshold FHE); see BaseKeySwitch::key_switch_gen_internal.
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
     * Generates a BV key switching key from old_private_key to the secret key of new_public_key by encrypting every CRT
     * component of the old key with the public key (proxy re-encryption).
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_public_key public key of the party the switched ciphertexts should decrypt for
     * @return the key switching key
     */
    EvalKey<RnsPoly> key_switch_gen_internal(const PrivateKey<RnsPoly> old_private_key,
                                             const PublicKey<RnsPoly> new_public_key) const override;

    /**
     * Key switches a ciphertext in place; see BaseKeySwitch::key_switch_in_place.
     *
     * @param ciphertext ciphertext to be key switched; holds the result
     * @param eval_key key switching key
     */
    void key_switch_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key) const override;

    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
     * Key switches a single ring element: digit decomposition followed by eval_fast_key_switch_core.
     *
     * @param a ring element to be key switched, in basis Ql
     * @param eval_key key switching key
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<RnsPoly> key_switch_core(const RnsPoly& a, const EvalKey<RnsPoly> eval_key) const override;

    /**
     * Computes the BV digits of a ring element: its CRT decomposition (one digit per RNS limb, each extended to the
     * whole basis Ql), further split in radix base 2^digit_size when the crypto parameters set a digit size.
     *
     * @param c ring element to be decomposed, in basis Ql
     * @param crypto_params_base crypto parameters (used for the digit size)
     * @return the digits of c
     */
    std::shared_ptr<std::vector<RnsPoly>> eval_key_switch_precompute_core(
            const RnsPoly& c, std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params_base) const override;

    /**
     * Computes the inner products of the digits with the two component vectors of the key switching key, limb by
     * limb in the basis Ql. Only the key components that correspond to the limbs of Ql are used.
     *
     * @param digits digits of the element computed by eval_key_switch_precompute_core
     * @param eval_key key switching key
     * @param params_ql parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<RnsPoly> eval_fast_key_switch_core(const std::shared_ptr<std::vector<RnsPoly>> digits,
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
        return "KeySwitchBV";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_KEYSWITCH_BV_H_
