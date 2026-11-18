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
  Base class for key switching algorithms.
 */

#ifndef CIPHER_FHE_KEYSWITCH_BASE_H_
#define CIPHER_FHE_KEYSWITCH_BASE_H_

#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/private_key_fwd.h"
#include "cipher/fhe/key/public_key_fwd.h"
#include "cipher/fhe/base/crypto_params.h"
#include "cipher/util/exception.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Abstract interface for key switching.
 *
 * Key switching transforms a ciphertext (c0, c1) with c0 + c1 * sA = m + noise, i.e., decryptable under a secret
 * key sA, into a ciphertext (c0', c1') decryptable under another secret key sB without changing the message. It is
 * the building block of relinearization (sA = s^2 after a homomorphic multiplication) and of the automorphisms used
 * for rotations and conjugation (sA = s(X^k)). Multiplying c1 directly by an encryption
 * (b, a) = (-a * sB + t * e + sA, a) of sA under sB would add the noise c1 * e, which is too large, so the
 * implementations decompose c1 into small digits (BV), temporarily extend the ciphertext modulus Q by an auxiliary
 * modulus P and divide by P afterwards (GHS), or combine both (HYBRID). See Appendix B of
 * https://eprint.iacr.org/2021/204 for the description and the noise analysis of the three variants and of their
 * RNS instantiations.
 *
 * The high-level operations key_switch and key_switch_in_place are composed of three core steps that are also exposed
 * separately. This lets callers hoist the expensive, key-independent digit decomposition of an element and reuse it
 * for several key switchings (fast rotations), and, for hybrid key switching, accumulate several key switched terms
 * in the extended basis QP before a single division by P:
 *   1. eval_key_switch_precompute_core: digit decomposition of the element to be switched;
 *   2. eval_fast_key_switch_core or eval_fast_key_switch_core_ext: inner product of the digits with the key switching key;
 *   3. key_switch_down: division by P for results left in the extended basis (hybrid only).
 *
 * @tparam Element ring element type (RnsPoly for the RNS instantiations)
 */
template <class Element>
class KeySwitchBase {
    using ParmType = typename Element::Params;

    constexpr static std::string_view NOT_SUPPORTED_ERROR = "This function is not supported";

  public:
    /**
     * Default constructor.
     */
    KeySwitchBase() = default;

    /**
     * Virtual destructor.
     */
    virtual ~KeySwitchBase() = default;

    /**
     * Generates a key switching key from old_private_key to new_private_key, i.e., an encryption of the old secret key
     * under the new one. The layout of the key (number of components and their modulus) depends on the key switching
     * method; see the derived classes.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_private_key private key the switched ciphertexts should decrypt under
     * @return the key switching key
     */
    virtual EvalKey<Element> key_switch_gen_internal(const PrivateKey<Element> old_private_key,
                                                     const PrivateKey<Element> new_private_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Generates a key switching key from old_private_key to new_private_key reusing the uniformly random "a" components
     * of an existing key switching key. This is used in threshold FHE, where every party has to generate its share of
     * the joint key with respect to the same "a" components so that the shares can be added.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_private_key private key the switched ciphertexts should decrypt under
     * @param eval_key key switching key whose "a" components are reused; if null, fresh components are sampled
     * @return the key switching key
     */
    virtual EvalKey<Element> key_switch_gen_internal(const PrivateKey<Element> old_private_key,
                                                     const PrivateKey<Element> new_private_key,
                                                     const EvalKey<Element> eval_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Generates a key switching key from old_private_key to the secret key of new_public_key using only the public key of
     * the target, i.e., the components of the old secret key are encrypted with the public-key encryption procedure.
     * This is how re-encryption keys are generated for proxy re-encryption.
     *
     * @param old_private_key private key the ciphertexts to be switched are encrypted under
     * @param new_public_key public key of the party the switched ciphertexts should decrypt for
     * @return the key switching key
     */
    virtual EvalKey<Element> key_switch_gen_internal(const PrivateKey<Element> old_private_key,
                                                     const PublicKey<Element> new_public_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Key switches a ciphertext to the key of eval_key and returns the result as a new ciphertext; the input is
     * copied and key_switch_in_place is applied to the copy.
     *
     * @param ciphertext ciphertext to be key switched
     * @param eval_key key switching key
     * @return the key switched ciphertext (two elements)
     */
    virtual Ciphertext<Element> key_switch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> eval_key) const;

    /**
     * Key switches a ciphertext in place. The last element of the ciphertext (c1 for a two-element ciphertext, c2
     * after a homomorphic multiplication) is key switched with key_switch_core, and the two resulting elements are
     * added to c0 and c1 (c1 is replaced when the ciphertext has only two elements). The result has two elements.
     *
     * @param ciphertext ciphertext to be key switched; holds the result
     * @param eval_key key switching key
     */
    virtual void key_switch_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element> eval_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Raises a ciphertext from its current basis Ql to the extended basis QlP of hybrid key switching by multiplying
     * every element by P (the residues for the P moduli are zero). The result can be added to the output of
     * eval_fast_key_switch_core_ext, so that the original ciphertext and several key switched terms are accumulated in the
     * extended basis and divided by P only once with key_switch_down. Supported by hybrid key switching only.
     *
     * @param ciphertext ciphertext in basis Ql
     * @param add_first if true, the first element c0 is raised as well; if false, it is set to zero and only the
     * remaining elements are raised (used when c0 is handled separately, e.g., in hoisted rotations)
     * @return the ciphertext in basis QlP
     */
    virtual Ciphertext<Element> key_switch_ext(ConstCiphertext<Element> ciphertext, bool add_first) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Switches a two-element ciphertext in the extended basis QlP back to basis Ql by dividing it by P with rounding,
     * which is the last step of hybrid key switching. For BGV the rounding is done so that the message modulo the
     * plaintext modulus is preserved. Supported by hybrid key switching only.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the ciphertext in basis Ql
     */
    virtual Ciphertext<Element> key_switch_down(ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Same as key_switch_down, but only for the first element c0 of the ciphertext. Supported by hybrid key switching
     * only.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the first element switched to basis Ql
     */
    virtual Element key_switch_down_first_element(ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }
    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
     * Key switches a single ring element a (typically c1 or c2 of a ciphertext): computes the digit decomposition of a
     * with eval_key_switch_precompute_core and its inner product with the key switching key with eval_fast_key_switch_core.
     *
     * @param a ring element to be key switched, in basis Ql
     * @param eval_key key switching key
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    virtual std::vector<Element> key_switch_core(const Element& a, const EvalKey<Element> eval_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the digit decomposition of a ring element, i.e., the key-independent part of key switching that
     * dominates its cost (for hybrid key switching it includes the basis extension of every digit to QlP). The digits
     * can be reused for key switching the same element with several keys, e.g., for computing several rotations of
     * one ciphertext (hoisting).
     *
     * @param c ring element to be decomposed, in basis Ql
     * @param crypto_params_base crypto parameters holding the key switching precomputations
     * @return the digits of c
     */
    virtual std::shared_ptr<std::vector<Element>> eval_key_switch_precompute_core(
            const Element& c, std::shared_ptr<BaseCryptoParams<Element>> crypto_params_base) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Completes the key switching of an element from its digits: computes the inner products of the digits with the
     * two component vectors of the key switching key and, for hybrid key switching, divides the results by P.
     *
     * @param digits digits of the element computed by eval_key_switch_precompute_core
     * @param eval_key key switching key
     * @param params_ql parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    virtual std::vector<Element> eval_fast_key_switch_core(const std::shared_ptr<std::vector<Element>> digits,
                                                           const EvalKey<Element> eval_key,
                                                           const std::shared_ptr<ParmType> params_ql) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Same as eval_fast_key_switch_core, but leaves the result in the extended basis QlP, i.e., without dividing by P.
     * This allows summing the results of several key switchings (and the original ciphertext raised with
     * key_switch_ext) before a single key_switch_down, which saves the divisions by P and reduces noise. Supported by
     * hybrid key switching only.
     *
     * @param digits digits of the element computed by eval_key_switch_precompute_core
     * @param eval_key key switching key
     * @param params_ql parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis QlP such that b' + a' * sB = P * a * sA + noise
     */
    virtual std::vector<Element> eval_fast_key_switch_core_ext(const std::shared_ptr<std::vector<Element>> digits,
                                                               const EvalKey<Element> eval_key,
                                                               const std::shared_ptr<ParmType> params_ql) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_KEYSWITCH_BASE_H_
