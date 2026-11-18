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

#ifndef CIPHER_FHE_BASE_SCHEME_H_
#define CIPHER_FHE_BASE_SCHEME_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/fhe/keyswitch/base.h"
#include "cipher/fhe/config/switching_params.h"
#include "cipher/fhe/base/advanced_she.h"
#include "cipher/fhe/base/fhe.h"
#include "cipher/fhe/base/leveled_she.h"
#include "cipher/fhe/base/multiparty.h"
#include "cipher/fhe/base/param_gen.h"
#include "cipher/fhe/base/pke.h"
#include "cipher/fhe/base/pre.h"
#include "cipher/util/caller_info.h"
#include "cipher/util/exception.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

template <typename Element>
class KeyPair;

// TODO: fix RnsPoly passed by value

/**
 * @brief Abstract interface for public key encryption schemes
 *
 * SchemeBase is a dispatcher rather than an implementation: it owns one object per family of operations, and
 * every public operation forwards to the same-named method of the object implementing that family after checking
 * that the family has been enabled. The families and the members holding them are
 *  - params_gen_ (BaseParamGen): parameter generation (params_gen_bfvrns, params_gen_ckksrns,
 *    params_gen_bgvrns);
 *  - pke_ (BasePke): key generation, encryption and decryption, including the encrypt_zero_core and decrypt_core
 *    building blocks;
 *  - key_switch_ (KeySwitchBase): key-switching key generation and key switching, including the core operations
 *    and the extended-basis (Ext) variants described below;
 *  - pre_ (BasePre): proxy re-encryption (re_key_gen, re_encrypt);
 *  - leveled_she_ (BaseLeveledShe): leveled homomorphic arithmetic: negation, addition, subtraction,
 *    multiplication and relinearization, automorphisms and rotations, modulus/level reduction and the level and
 *    scaling adjustment helpers;
 *  - advanced_she_ (BaseAdvancedShe): operations built on the leveled ones: linear weighted sums, polynomial and
 *    Chebyshev series evaluation, eval_sum/eval_sum_rows/eval_sum_cols and inner products;
 *  - multiparty_ (BaseMultiparty): threshold key generation, distributed decryption and the interactive
 *    multiparty bootstrapping protocol (IntMPBoot*);
 *  - fhe_ (BaseFhe): CKKS bootstrapping and functional bootstrapping (eval_bootstrap*, eval_fbt*, eval_mvb*,
 *    eval_fe_func_bootstrap*) together with their precomputation caches;
 *  - scheme_switch_ (BaseFhe): CKKS <-> FHEW scheme switching (eval_ckks_to_fhew*, eval_fhew_to_ckks*,
 *    eval_compare_scheme_switching, eval_min_scheme_switching, eval_max_scheme_switching and related calls).
 *
 * A family is enabled with enable(PkeSchemeFeature), which the concrete schemes (CkksRnsScheme, BfvRnsScheme,
 * BgvRnsScheme) override to instantiate the corresponding member; enable(uint32_t) accepts a bit mask of
 * features, and get_enabled()/is_feature_enabled() report the current state. Calling an operation of a family that
 * is not enabled throws an exception from the corresponding Verify*Enabled() helper naming the operation and the
 * feature that must be enabled.
 *
 * Because the forwarding methods add no behavior of their own, they are not documented individually in this
 * header. The semantics of every operation are documented on the implementing interfaces in the base-*.h and
 * keyswitch-base.h headers (base-parametergeneration.h, base-pke.h, keyswitch-base.h, base-pre.h,
 * base-leveledshe.h, base-advancedshe.h, base-multiparty.h, base-fhe.h) and on the user-facing wrappers in
 * cryptocontext.h. The methods that do more than forward are documented below: the key-generation wrappers
 * implemented in base-scheme.cpp stamp the returned keys with the key tag of the secret key they belong to (or
 * with the caller-supplied key_id in the multiparty variants), a few wrappers validate their arguments or return
 * early, and the serialization methods keep backward compatibility with older serialized contexts.
 *
 * Key switching is exposed at three granularities. key_switch and key_switch_in_place switch a whole ciphertext.
 * The core operations split the work so that the expensive, key-independent digit decomposition can be reused:
 * eval_key_switch_precompute_core decomposes a ring element into digits, eval_fast_key_switch_core multiplies precomputed
 * digits by an evaluation key and returns the result in the basis Q, and key_switch_core performs both steps.
 * eval_fast_rotation_precompute and eval_fast_rotation build hoisted rotations on the same digits, so several
 * rotations of one ciphertext share a single decomposition. The Ext variants (eval_fast_key_switch_core_ext,
 * eval_fast_rotation_ext, key_switch_ext, key_switch_down, key_switch_down_first_element), supported by hybrid key switching
 * only, keep intermediate results in the extended basis P*Q, so that many key-switched or rotated terms can be
 * accumulated before a single scale-down from P*Q to Q.
 *
 * @tparam Element a ring element.
 */
template <typename Element>
class SchemeBase {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

  public:
    SchemeBase() = default;

    virtual ~SchemeBase() = default;

    /**
     * Compares two scheme objects. The base implementation throws an exception; every concrete scheme overrides
     * it (ContextFactory relies on it to deduplicate crypto contexts).
     *
     * @param sch the scheme to compare with
     * @return true if the schemes are equal
     */
    virtual bool operator==(const SchemeBase& sch) const {
        CIPHER_THROW("operator== is not supported");
    }

    /**
     * Inequality of scheme objects: negation of operator==.
     *
     * @param sch the scheme to compare with
     * @return true if the schemes differ
     */
    virtual bool operator!=(const SchemeBase& sch) const {
        return !(*this == sch);
    }

    /**
     * Enable features with a bit mask of PkeSchemeFeature codes
     * @param mask bitwise OR of PkeSchemeFeature codes to enable
     */
    void enable(uint32_t mask) {
        if (mask & PKE)
            enable(PKE);
        if (mask & KEYSWITCH)
            enable(KEYSWITCH);
        if (mask & LEVELEDSHE)
            enable(LEVELEDSHE);
        if (mask & ADVANCEDSHE)
            enable(ADVANCEDSHE);
        if (mask & PRE)
            enable(PRE);
        if (mask & MULTIPARTY)
            enable(MULTIPARTY);
        if (mask & FHE)
            enable(FHE);
        if (mask & SCHEMESWITCH)
            enable(SCHEMESWITCH);
    }

    /**
     * Returns the enabled features, i.e., the families whose implementing object has been instantiated.
     *
     * @return bitwise OR of the PkeSchemeFeature codes of the enabled features
     */
    uint32_t get_enabled() const {
        uint32_t flag = 0;
        if (pke_ != nullptr)
            flag |= PKE;
        if (key_switch_ != nullptr)
            flag |= KEYSWITCH;
        if (leveled_she_ != nullptr)
            flag |= LEVELEDSHE;
        if (advanced_she_ != nullptr)
            flag |= ADVANCEDSHE;
        if (pre_ != nullptr)
            flag |= PRE;
        if (multiparty_ != nullptr)
            flag |= MULTIPARTY;
        if (fhe_ != nullptr)
            flag |= FHE;
        if (scheme_switch_ != nullptr)
            flag |= SCHEMESWITCH;
        return flag;
    }

    /**
     * Checks whether a single feature has been enabled.
     *
     * @param feature the feature to check; an unknown value causes an exception
     * @return true if the object implementing the feature has been instantiated
     */
    bool is_feature_enabled(PkeSchemeFeature feature) {
        switch (feature) {
            case PKE:
                return (pke_ != nullptr);
            case KEYSWITCH:
                return (key_switch_ != nullptr);
            case LEVELEDSHE:
                return (leveled_she_ != nullptr);
            case ADVANCEDSHE:
                return (advanced_she_ != nullptr);
            case PRE:
                return (pre_ != nullptr);
            case MULTIPARTY:
                return (multiparty_ != nullptr);
            case FHE:
                return (fhe_ != nullptr);
            case SCHEMESWITCH:
                return (scheme_switch_ != nullptr);
            default:
                CIPHER_THROW("Unknown PKESchemeFeature " + std::to_string(feature));
        }
    }

    /**
     * Enables a single feature by instantiating the object implementing it. The base implementation throws an
     * exception; every concrete scheme overrides it.
     *
     * @param feature the feature to enable
     */
    // instantiated in the scheme implementation class
    virtual void enable(PkeSchemeFeature feature) {
        CIPHER_THROW("Enable is not implemented");
    }

    //------------------------------------------------------------------------------
    // PARAMETER GENERATION WRAPPER
    // The three methods below forward to params_gen_, which the concrete scheme sets in its constructor,
    // and throw if it has not been set. Their parameters are documented in base-parametergeneration.h.
    //------------------------------------------------------------------------------

    bool params_gen_bfvrns(std::shared_ptr<BaseCryptoParams<Element>> crypto_params, uint32_t eval_add_count,
                           uint32_t multiplicative_depth, uint32_t key_switch_count, size_t dcrt_bits, uint32_t n,
                           uint32_t num_part_q) const {
        if (!params_gen_)
            CIPHER_THROW("m_ParamsGen is nullptr");
        return params_gen_->params_gen_bfvrns_internal(crypto_params, eval_add_count, multiplicative_depth,
                                                       key_switch_count, dcrt_bits, n, num_part_q);
    }

    bool params_gen_ckksrns(std::shared_ptr<BaseCryptoParams<Element>> crypto_params, uint32_t cycl_order,
                            uint32_t num_primes_value, uint32_t scaling_mod_size, uint32_t first_mod_size_value,
                            uint32_t num_part_q, CompressionLevel m_p_int_boot_ciphertext_compression_level) const {
        if (!params_gen_)
            CIPHER_THROW("m_ParamsGen is nullptr");
        return params_gen_->params_gen_ckksrns_internal(crypto_params, cycl_order, num_primes_value, scaling_mod_size,
                                                        first_mod_size_value, num_part_q,
                                                        m_p_int_boot_ciphertext_compression_level);
    }

    bool params_gen_bgvrns(std::shared_ptr<BaseCryptoParams<Element>> crypto_params, uint32_t eval_add_count,
                           uint32_t key_switch_count, uint32_t cycl_order, uint32_t num_primes_value,
                           uint32_t first_mod_size_value, uint32_t dcrt_bits, uint32_t num_part_q,
                           uint32_t pre_num_hops) const {
        if (!params_gen_)
            CIPHER_THROW("m_ParamsGen is nullptr");
        return params_gen_->params_gen_bgvrns_internal(crypto_params, eval_add_count, key_switch_count, cycl_order,
                                                       num_primes_value, first_mod_size_value, dcrt_bits, num_part_q,
                                                       pre_num_hops);
    }

    /////////////////////////////////////////
    // PKE WRAPPER
    /////////////////////////////////////////

    virtual KeyPair<Element> key_gen(CryptoContext<Element> cc, bool make_sparse_value) const {
        verify_pke_enabled(__func__);
        return pke_->key_gen_internal(cc, make_sparse_value);
    }

    virtual Ciphertext<Element> encrypt(const Element& plaintext, const PrivateKey<Element> private_key) const {
        verify_pke_enabled(__func__);
        return pke_->encrypt(plaintext, private_key);
    }

    virtual Ciphertext<Element> encrypt(const Element& plaintext, const PublicKey<Element> public_key) const {
        verify_pke_enabled(__func__);
        return pke_->encrypt(plaintext, public_key);
    }

    virtual DecryptResult decrypt(ConstCiphertext<Element>& ciphertext, const PrivateKey<Element> private_key,
                                  NativePoly* plaintext) const {
        verify_pke_enabled(__func__);
        return pke_->decrypt(ciphertext, private_key, plaintext);
    }

    virtual DecryptResult decrypt(ConstCiphertext<Element>& ciphertext, const PrivateKey<Element> private_key,
                                  Poly* plaintext) const {
        verify_pke_enabled(__func__);
        return pke_->decrypt(ciphertext, private_key, plaintext);
    }

    std::shared_ptr<std::vector<Element>> encrypt_zero_core(const PrivateKey<Element> private_key) const {
        verify_pke_enabled(__func__);
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        return pke_->encrypt_zero_core(private_key, nullptr);
    }

    std::shared_ptr<std::vector<Element>> encrypt_zero_core(const PublicKey<Element> public_key) const {
        verify_pke_enabled(__func__);
        if (!public_key)
            CIPHER_THROW("Input public key is nullptr");
        return pke_->encrypt_zero_core(public_key, nullptr);
    }

    Element decrypt_core(ConstCiphertext<Element>& ciphertext, const PrivateKey<Element> private_key) const {
        verify_pke_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        return pke_->decrypt_core(ciphertext->get_elements(), private_key);
    }

    /////////////////////////////////////////
    // KEY SWITCH WRAPPER
    // Forwarders to key_switch_; the core and Ext methods additionally reject null or empty arguments.
    // See the class description for how the core, fast-rotation and Ext operations relate.
    /////////////////////////////////////////

    virtual EvalKey<Element> key_switch_gen(const PrivateKey<Element> old_private_key,
                                            const PrivateKey<Element> new_private_key) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_gen_internal(old_private_key, new_private_key);
    }

    virtual EvalKey<Element> key_switch_gen(const PrivateKey<Element> old_private_key,
                                            const PrivateKey<Element> new_private_key,
                                            const EvalKey<Element> eval_key) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_gen_internal(old_private_key, new_private_key, eval_key);
    }

    virtual EvalKey<Element> key_switch_gen(const PrivateKey<Element> old_private_key,
                                            const PublicKey<Element> new_public_key) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_gen_internal(old_private_key, new_public_key);
    }

    virtual Ciphertext<Element> key_switch(ConstCiphertext<Element>& ciphertext,
                                           const EvalKey<Element> eval_key) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch(ciphertext, eval_key);
    }

    virtual void key_switch_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element> eval_key) const {
        verify_key_switch_enabled(__func__);
        key_switch_->key_switch_in_place(ciphertext, eval_key);
    }

    virtual Ciphertext<Element> key_switch_down(ConstCiphertext<Element>& ciphertext) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_down(ciphertext);
    }

    virtual std::shared_ptr<std::vector<Element>> eval_key_switch_precompute_core(
            const Element& c, std::shared_ptr<BaseCryptoParams<Element>> crypto_params_base) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->eval_key_switch_precompute_core(c, crypto_params_base);
    }

    virtual std::vector<Element> eval_fast_key_switch_core_ext(const std::shared_ptr<std::vector<Element>> digits,
                                                               const EvalKey<Element> eval_key,
                                                               const std::shared_ptr<ParmType> params) const {
        verify_key_switch_enabled(__func__);
        if (nullptr == digits)
            CIPHER_THROW("Input digits is nullptr");
        if (digits->size() == 0)
            CIPHER_THROW("Input digits size is 0");
        if (!eval_key)
            CIPHER_THROW("Input evaluation key is nullptr");
        if (!params)
            CIPHER_THROW("Input params is nullptr");
        return key_switch_->eval_fast_key_switch_core_ext(digits, eval_key, params);
    }

    virtual std::vector<Element> eval_fast_key_switch_core(const std::shared_ptr<std::vector<Element>> digits,
                                                           const EvalKey<Element> eval_key,
                                                           const std::shared_ptr<ParmType> params) const {
        verify_key_switch_enabled(__func__);
        if (nullptr == digits)
            CIPHER_THROW("Input digits is nullptr");
        if (digits->size() == 0)
            CIPHER_THROW("Input digits size is 0");
        if (!eval_key)
            CIPHER_THROW("Input evaluation key is nullptr");
        if (!params)
            CIPHER_THROW("Input params is nullptr");
        return key_switch_->eval_fast_key_switch_core(digits, eval_key, params);
    }

    virtual std::vector<Element> key_switch_core(const Element& a, const EvalKey<Element> eval_key) const {
        verify_key_switch_enabled(__func__);
        if (!eval_key)
            CIPHER_THROW("Input evaluation key is nullptr");
        return key_switch_->key_switch_core(a, eval_key);
    }

    /////////////////////////////////////////
    // PRE WRAPPER
    /////////////////////////////////////////

    /**
     * Generates a proxy re-encryption key from old_private_key to new_public_key via pre_ and tags it with the key tag
     * of new_public_key, so that re-encrypted ciphertexts are associated with the new key.
     *
     * @param old_private_key secret key the ciphertexts are currently encrypted under
     * @param new_public_key public key of the new recipient
     * @return the re-encryption key
     */
    virtual EvalKey<Element> re_key_gen(const PrivateKey<Element> old_private_key,
                                        const PublicKey<Element> new_public_key) const;

    /**
     * Re-encrypts a ciphertext to the recipient of the re-encryption key via pre_ and sets the key tag of the
     * result to the tag of eval_key (that of the new public key).
     *
     * @param ciphertext the ciphertext to re-encrypt
     * @param eval_key the re-encryption key
     * @param public_key public key of the recipient, used by the PRE modes that re-randomize the result with a fresh
     *        encryption of zero (may be null in the other modes)
     * @return the re-encrypted ciphertext
     */
    virtual Ciphertext<Element> re_encrypt(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> eval_key,
                                           const PublicKey<Element> public_key) const;

    /////////////////////////////////////////
    // SHE NEGATION WRAPPER
    /////////////////////////////////////////

    virtual Ciphertext<Element> eval_negate(ConstCiphertext<Element>& ciphertext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_negate(ciphertext);
    }

    virtual void eval_negate_in_place(Ciphertext<Element>& ciphertext) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_negate_in_place(ciphertext);
    }

    /////////////////////////////////////////
    // SHE ADDITION Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add(ciphertext1, ciphertext2);
    }

    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_in_place(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext1,
                                                 Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add_mutable(ciphertext1, ciphertext2);
    }

    virtual void eval_add_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_mutable_in_place(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add(ciphertext, plaintext);
    }

    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_in_place(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add_mutable(ciphertext, plaintext);
    }

    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, NativeInteger constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_in_place(ciphertext, constant);
    }

    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add(ciphertext, constant);
    }

    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_in_place(ciphertext, constant);
    }

    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, std::complex<double> constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_add(ciphertext, constant);
    }

    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, std::complex<double> constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_add_in_place(ciphertext, constant);
    }

    /////////////////////////////////////////
    // SHE SUBTRACTION Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub(ciphertext1, ciphertext2);
    }

    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_sub_in_place(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext1,
                                                 Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub_mutable(ciphertext1, ciphertext2);
    }

    virtual void eval_sub_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_sub_mutable_in_place(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub(ciphertext, plaintext);
    }

    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_sub_in_place(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub_mutable(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, NativeInteger constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub(ciphertext, constant);
    }

    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, NativeInteger constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_sub_in_place(ciphertext, constant);
    }

    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_sub(ciphertext, constant);
    }

    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_sub_in_place(ciphertext, constant);
    }

    /////////////////////////////////////////
    // SHE MULTIPLICATION Wrapper
    /////////////////////////////////////////

    /**
     * Generates the relinearization key (from s^2 to s) via leveled_she_ and tags it with the key tag of private_key.
     *
     * @param private_key the secret key
     * @return the relinearization key
     */
    virtual EvalKey<Element> eval_mult_key_gen(const PrivateKey<Element> private_key) const;

    /**
     * Generates the relinearization keys for s^2, s^3, ... (used for ciphertexts of more than two elements) via
     * leveled_she_ and tags each of them with the key tag of private_key.
     *
     * @param private_key the secret key
     * @return the vector of relinearization keys
     */
    virtual std::vector<EvalKey<Element>> eval_mult_keys_gen(const PrivateKey<Element> private_key) const;

    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext1,
                                          ConstCiphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult_mutable(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> eval_square(ConstCiphertext<Element>& ciphertext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_square(ciphertext);
    }

    virtual Ciphertext<Element> eval_square_mutable(Ciphertext<Element>& ciphertext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_square_mutable(ciphertext);
    }

    /////////////////////////////////////////
    // MULTIPLICATION With Eval Key
    /////////////////////////////////////////

    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                          const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult(ciphertext1, ciphertext2, eval_key);
    }

    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                    const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_mult_in_place(ciphertext1, ciphertext2, eval_key);
    }

    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                  const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult_mutable(ciphertext1, ciphertext2, eval_key);
    }

    virtual void eval_mult_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                            const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_mult_mutable_in_place(ciphertext1, ciphertext2, eval_key);
    }

    virtual Ciphertext<Element> eval_square(ConstCiphertext<Element>& ciphertext,
                                            const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_square(ciphertext, eval_key);
    }

    virtual void eval_square_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_square_in_place(ciphertext, eval_key);
    }

    virtual Ciphertext<Element> eval_square_mutable(Ciphertext<Element>& ciphertext,
                                                    const EvalKey<Element> eval_key) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_square_mutable(ciphertext, eval_key);
    }

    virtual Ciphertext<Element> eval_mult_and_relinearize(ConstCiphertext<Element>& ciphertext1,
                                                          ConstCiphertext<Element>& ciphertext2,
                                                          const std::vector<EvalKey<Element>>& eval_key_vec) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult_and_relinearize(ciphertext1, ciphertext2, eval_key_vec);
    }

    virtual Ciphertext<Element> relinearize(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<EvalKey<Element>>& eval_key_vec) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->relinearize(ciphertext, eval_key_vec);
    }

    virtual void relinearize_in_place(Ciphertext<Element>& ciphertext,
                                      const std::vector<EvalKey<Element>>& eval_key_vec) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->relinearize_in_place(ciphertext, eval_key_vec);
    }

    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult(ciphertext, plaintext);
    }

    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_mult_in_place(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult_mutable(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> mult_by_monomial(ConstCiphertext<Element>& ciphertext, uint32_t power) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->mult_by_monomial(ciphertext, power);
    }

    virtual void mult_by_monomial_in_place(Ciphertext<Element>& ciphertext, uint32_t power) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        leveled_she_->mult_by_monomial_in_place(ciphertext, power);
    }

    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult(ciphertext, constant);
    }

    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, double constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_mult_in_place(ciphertext, constant);
    }

    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, std::complex<double> constant) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->eval_mult(ciphertext, constant);
    }

    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, std::complex<double> constant) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->eval_mult_in_place(ciphertext, constant);
    }

    virtual Ciphertext<Element> mult_by_integer(ConstCiphertext<Element>& ciphertext, uint64_t integer) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->mult_by_integer(ciphertext, integer);
    }

    virtual void mult_by_integer_in_place(Ciphertext<Element>& ciphertext, uint64_t integer) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        leveled_she_->mult_by_integer_in_place(ciphertext, integer);
    }

    /////////////////////////////////////////
    // SHE AUTOMORPHISM Wrapper
    /////////////////////////////////////////

    /**
     * Generates the automorphism (key-switching) keys for the given automorphism indices via leveled_she_ and tags
     * each of them with the key tag of private_key.
     *
     * @param private_key the secret key
     * @param index_list automorphism indices (elements of the Galois group) to generate keys for
     * @return map from automorphism index to key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_automorphism_key_gen(
            const PrivateKey<Element> private_key, const std::vector<uint32_t>& index_list) const;

    virtual Ciphertext<Element> eval_automorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                                  const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                                  CALLER_INFO_ARGS_HDR) const {
        if (leveled_she_) {
            if (!ciphertext)
                CIPHER_THROW("Input ciphertext is nullptr");
            if (!eval_key_map.size())
                CIPHER_THROW("Input evaluation key map is empty");

            return leveled_she_->eval_automorphism(ciphertext, i, eval_key_map);
        }
        std::string error_msg(std::string("EvalAutomorphism operation has not been enabled") + CALLER_INFO);
        CIPHER_THROW(error_msg);
    }

    virtual Ciphertext<Element> eval_fast_rotation(ConstCiphertext<Element>& ciphertext, const uint32_t index,
                                                   const uint32_t m,
                                                   const std::shared_ptr<std::vector<Element>> digits) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->eval_fast_rotation(ciphertext, index, m, digits);
    }

    virtual std::shared_ptr<std::vector<Element>> eval_fast_rotation_precompute(
            ConstCiphertext<Element> ciphertext) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->eval_fast_rotation_precompute(ciphertext);
    }

    virtual Ciphertext<Element> eval_automorphism_core(ConstCiphertext<Element>& ciphertext, uint32_t auto_index,
                                                       const std::shared_ptr<std::vector<Element>>& digits,
                                                       const EvalKey<Element>& eval_key) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->eval_automorphism_core(ciphertext, auto_index, digits, eval_key);
    }

    /**
     * Only supported for hybrid key switching.
     * Performs fast (hoisted) rotation and returns the results
     * in the extended CRT basis P*Q
     *
     * @param ciphertext input ciphertext
     * @param index the rotation index.
     * @param digits the precomputed digits for the ciphertext
     * @param add_first if true, the first element c0 is also computed (otherwise ignored)
     * @param eval_keys the map of automorphism keys
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_fast_rotation_ext(ConstCiphertext<Element>& ciphertext, uint32_t index,
                                                       const std::shared_ptr<std::vector<Element>> digits,
                                                       bool add_first,
                                                       const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->eval_fast_rotation_ext(ciphertext, index, digits, add_first, eval_keys);
    }

    /**
     * Only supported for hybrid key switching.
     * Scales down the polynomial c0 from extended basis P*Q to Q.
     *
     * @param ciphertext input ciphertext in the extended basis
     * @return resulting polynomial
     */
    Element key_switch_down_first_element(ConstCiphertext<Element>& ciphertext) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_down_first_element(ciphertext);
    }

    virtual Ciphertext<Element> key_switch_ext(ConstCiphertext<Element>& ciphertext, bool add_first) const {
        verify_key_switch_enabled(__func__);
        return key_switch_->key_switch_ext(ciphertext, add_first);
    }

    /**
     * Generates the rotation keys for the given rotation indices via leveled_she_ and tags each of them with the
     * key tag of private_key.
     *
     * @param private_key the secret key
     * @param index_list rotation indices (positive for left, negative for right rotations)
     * @return map from automorphism index to key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_at_index_key_gen(
            const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list) const;

    virtual Ciphertext<Element> eval_at_index(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
        verify_leveled_she_enabled(__func__);
        if (!eval_key_map.size())
            CIPHER_THROW("Input evaluation key map is empty");
        return leveled_she_->eval_at_index(ciphertext, i, eval_key_map);
    }

    virtual uint32_t find_automorphism_index(uint32_t index, uint32_t m) {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->find_automorphism_index(index, m);
    }

    /////////////////////////////////////////
    // SHE Leveled Methods Wrapper
    /////////////////////////////////////////

    /**
     * Multiplies two ciphertexts, relinearizes and rescales the product via leveled_she_, and sets the key tag of
     * the result to the tag of eval_key.
     *
     * @param ciphertext1 first operand
     * @param ciphertext2 second operand
     * @param eval_key the relinearization key
     * @return the relinearized and rescaled product
     */
    virtual Ciphertext<Element> composed_eval_mult(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2,
                                                   const EvalKey<Element> eval_key) const;

    /**
     * Rescales a ciphertext by the given number of levels via leveled_she_; the result keeps the key tag of the
     * input.
     *
     * @param ciphertext the ciphertext to rescale
     * @param levels number of levels (RNS limbs) to drop
     * @return the rescaled ciphertext
     */
    virtual Ciphertext<Element> mod_reduce(ConstCiphertext<Element>& ciphertext, size_t levels) const;

    virtual void mod_reduce_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->mod_reduce_in_place(ciphertext, levels);
    }

    virtual Ciphertext<Element> mod_reduce_internal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->mod_reduce_internal(ciphertext, levels);
    }

    /**
     * Rescales a ciphertext in place by the given number of levels via leveled_she_; does nothing for levels == 0.
     *
     * @param ciphertext the ciphertext to rescale
     * @param levels number of levels (RNS limbs) to drop
     */
    virtual void mod_reduce_internal_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        verify_leveled_she_enabled(__func__);
        if (levels > 0)
            leveled_she_->mod_reduce_internal_in_place(ciphertext, levels);
    }

    virtual Ciphertext<Element> level_reduce(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> eval_key,
                                             size_t levels) const {
        verify_leveled_she_enabled(__func__);
        auto result = leveled_she_->level_reduce(ciphertext, eval_key, levels);
        result->set_key_tag(ciphertext->get_key_tag());
        return result;
    }

    virtual void level_reduce_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element> eval_key,
                                       size_t levels) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->level_reduce_in_place(ciphertext, eval_key, levels);
    }

    virtual Ciphertext<Element> level_reduce_internal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return leveled_she_->level_reduce_internal(ciphertext, levels);
    }

    virtual void level_reduce_internal_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        verify_leveled_she_enabled(__func__);
        leveled_she_->level_reduce_internal_in_place(ciphertext, levels);
    }

    virtual Ciphertext<Element> compress(ConstCiphertext<Element>& ciphertext, size_t towers_left,
                                         size_t noise_scale_deg) const {
        verify_leveled_she_enabled(__func__);
        return leveled_she_->compress(ciphertext, towers_left, noise_scale_deg);
    }

    virtual void adjust_levels_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext1)
            CIPHER_THROW("Input ciphertext1 is nullptr");
        if (!ciphertext2)
            CIPHER_THROW("Input ciphertext2 is nullptr");
        leveled_she_->adjust_levels_in_place(ciphertext1, ciphertext2);
    }

    virtual void adjust_levels_and_depth_in_place(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext1)
            CIPHER_THROW("Input ciphertext1 is nullptr");
        if (!ciphertext2)
            CIPHER_THROW("Input ciphertext2 is nullptr");
        leveled_she_->adjust_levels_and_depth_in_place(ciphertext1, ciphertext2);
    }

    virtual void adjust_levels_and_depth_to_one_in_place(Ciphertext<Element>& ciphertext1,
                                                         Ciphertext<Element>& ciphertext2) const {
        verify_leveled_she_enabled(__func__);
        if (!ciphertext1)
            CIPHER_THROW("Input ciphertext1 is nullptr");
        if (!ciphertext2)
            CIPHER_THROW("Input ciphertext2 is nullptr");
        leveled_she_->adjust_levels_and_depth_to_one_in_place(ciphertext1, ciphertext2);
    }

    /////////////////////////////////////////
    // Advanced SHE Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> eval_add_many(const std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_add_many(ciphertext_vec);
    }

    virtual Ciphertext<Element> eval_add_many_in_place(std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_add_many_in_place(ciphertext_vec);
    }

    virtual Ciphertext<Element> eval_mult_many(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                               const std::vector<EvalKey<Element>>& eval_key_vec) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_mult_many(ciphertext_vec, eval_key_vec);
    }

    /////////////////////////////////////
    // Advanced SHE LINEAR WEIGHTED SUM
    /////////////////////////////////////

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum(std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec,
                                          const std::vector<VectorDataType>& constant_vec) const {
        verify_advanced_she_enabled(__func__);
        if (!ciphertext_vec.size())
            CIPHER_THROW("Input ciphertext vector is empty");
        return advanced_she_->eval_linear_w_sum(ciphertext_vec, constant_vec);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum_mutable(std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                  const std::vector<VectorDataType>& constant_vec) const {
        verify_advanced_she_enabled(__func__);
        if (!ciphertext_vec.size())
            CIPHER_THROW("Input ciphertext vector is empty");
        return advanced_she_->eval_linear_w_sum_mutable(ciphertext_vec, constant_vec);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL POLYNOMIAL
    /////////////////////////////////////

    template <typename VectorDataType = double>
    std::shared_ptr<SeriesPowers<Element>> eval_powers(ConstCiphertext<Element>& ciphertext,
                                                       const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_powers(ciphertext, coefficients);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly(ConstCiphertext<Element>& ciphertext,
                                  const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_poly(ciphertext, coefficients);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_with_precomp(std::shared_ptr<SeriesPowers<Element>> powers,
                                               const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_poly_with_precomp(powers, coefficients);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_linear(ConstCiphertext<Element>& ciphertext,
                                         const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_poly_linear(ciphertext, coefficients);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_ps(ConstCiphertext<Element>& ciphertext,
                                     const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_poly_ps(ciphertext, coefficients);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL CHEBYSHEV SERIES
    /////////////////////////////////////

    template <typename VectorDataType = double>
    std::shared_ptr<SeriesPowers<Element>> eval_cheby_polys(ConstCiphertext<Element>& ciphertext,
                                                            const std::vector<VectorDataType>& coefficients, double a,
                                                            double b) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_cheby_polys(ciphertext, coefficients, a, b);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series(ConstCiphertext<Element>& ciphertext,
                                              const std::vector<VectorDataType>& coefficients, double a,
                                              double b) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_chebyshev_series(ciphertext, coefficients, a, b);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_with_precomp(std::shared_ptr<SeriesPowers<Element>> polys,
                                                           const std::vector<VectorDataType>& coefficients) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_chebyshev_series_with_precomp(polys, coefficients);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_linear(ConstCiphertext<Element>& ciphertext,
                                                     const std::vector<VectorDataType>& coefficients, double a,
                                                     double b) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_chebyshev_series_linear(ciphertext, coefficients, a, b);
    }

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_ps(ConstCiphertext<Element>& ciphertext,
                                                 const std::vector<VectorDataType>& coefficients, double a,
                                                 double b) const {
        verify_advanced_she_enabled(__func__);
        return advanced_she_->eval_chebyshev_series_ps(ciphertext, coefficients, a, b);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL SUM
    /////////////////////////////////////

    /**
     * Generates the rotation keys needed by eval_sum via advanced_she_ and tags each of them with the key tag of
     * private_key.
     *
     * @param private_key the secret key
     * @return map from automorphism index to key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_gen(
            const PrivateKey<Element> private_key) const;

    /**
     * Generates the rotation keys needed by eval_sum_rows via advanced_she_ and tags each of them with the key tag
     * of private_key.
     *
     * @param private_key the secret key
     * @param row_size number of slots per row of the packed matrix
     * @param subring_dim subring dimension (0 selects the cyclotomic order)
     * @param indices receives the automorphism indices the keys were generated for
     * @return map from automorphism index to key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_rows_key_gen(
            const PrivateKey<Element> private_key, uint32_t row_size, uint32_t subring_dim,
            std::vector<uint32_t>& indices) const;

    /**
     * Generates the rotation keys needed by eval_sum_cols via advanced_she_ and tags each of them with the key tag
     * of private_key.
     *
     * @param private_key the secret key
     * @param indices receives the automorphism indices the keys were generated for
     * @return map from automorphism index to key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_cols_key_gen(
            const PrivateKey<Element> private_key, std::vector<uint32_t>& indices) const;

    virtual Ciphertext<Element> eval_sum(ConstCiphertext<Element> ciphertext, uint32_t batch_size,
                                         const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
        verify_advanced_she_enabled(__func__);
        if (!eval_key_map.size())
            CIPHER_THROW("Input evaluation key map is empty");
        return advanced_she_->eval_sum(ciphertext, batch_size, eval_key_map);
    }

    virtual Ciphertext<Element> eval_sum_rows(ConstCiphertext<Element>& ciphertext, uint32_t row_size,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                              uint32_t subring_dim) const {
        verify_advanced_she_enabled(__func__);
        if (!eval_key_map.size())
            CIPHER_THROW("Input evaluation key map is empty");
        return advanced_she_->eval_sum_rows(ciphertext, row_size, eval_key_map, subring_dim);
    }

    virtual Ciphertext<Element> eval_sum_cols(ConstCiphertext<Element>& ciphertext, uint32_t batch_size,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                              const std::map<uint32_t, EvalKey<Element>>& right_eval_key_map) const {
        verify_advanced_she_enabled(__func__);
        if (!eval_key_map.size())
            CIPHER_THROW("Input first evaluation key map is empty");
        if (!right_eval_key_map.size())
            CIPHER_THROW("Input second evaluation key map is empty");
        return advanced_she_->eval_sum_cols(ciphertext, batch_size, eval_key_map, right_eval_key_map);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL INNER PRODUCT
    /////////////////////////////////////

    /**
     * Computes the inner product of two packed ciphertexts via advanced_she_ after checking that the summation key
     * map is not empty and the relinearization key is not null; the result is tagged with the key tag of the
     * summation keys.
     *
     * @param ciphertext1 first operand
     * @param ciphertext2 second operand
     * @param batch_size number of slots to sum over
     * @param eval_sum_key_map rotation keys generated by eval_sum_key_gen
     * @param eval_mult_key the relinearization key
     * @return ciphertext with the inner product in every slot
     */
    virtual Ciphertext<Element> eval_inner_product(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2, uint32_t batch_size,
                                                   const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map,
                                                   const EvalKey<Element> eval_mult_key) const;

    virtual Ciphertext<Element> eval_inner_product(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext,
                                                   uint32_t batch_size,
                                                   const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map) const {
        verify_advanced_she_enabled(__func__);
        if (!eval_sum_key_map.size())
            CIPHER_THROW("Input evaluation key map is empty");
        return advanced_she_->eval_inner_product(ciphertext, plaintext, batch_size, eval_sum_key_map);
    }

    virtual Ciphertext<Element> add_random_noise(ConstCiphertext<Element> ciphertext) const {
        verify_advanced_she_enabled(__func__);
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return advanced_she_->add_random_noise(ciphertext);
    }

    virtual Ciphertext<Element> eval_merge(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                           const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const {
        verify_advanced_she_enabled(__func__);
        if (!eval_key_map.size())
            CIPHER_THROW("Input evaluation key map is empty");
        return advanced_she_->eval_merge(ciphertext_vec, eval_key_map);
    }

    /////////////////////////////////////////
    // MULTIPARTY WRAPPER
    /////////////////////////////////////////

    /**
     * Threshold key generation from the secret keys of several parties via multiparty_. Checks that the context
     * and the key vector are not empty and sets the key tag of the joint public key to that of the joint secret key.
     *
     * @param cc the crypto context
     * @param private_key_vec secret keys of the participating parties
     * @param make_sparse_value use ring reduction (no longer supported)
     * @return the joint key pair
     */
    virtual KeyPair<Element> multiparty_key_gen(CryptoContext<Element> cc,
                                                const std::vector<PrivateKey<Element>>& private_key_vec,
                                                bool make_sparse_value);

    /**
     * Threshold key generation for one party given the joint public key of the previous parties, via multiparty_.
     * Checks that the context and the public key are not null and sets the key tag of the returned public key to
     * that of the returned secret key.
     *
     * @param cc the crypto context
     * @param public_key joint public key of the prior parties
     * @param make_sparse_value use ring reduction (no longer supported)
     * @param PRE true if proxy re-encryption or the star topology is used in the multiparty protocol, in which case
     *        a fresh public key is generated instead of a joint one
     * @return this party's key pair
     */
    virtual KeyPair<Element> multiparty_key_gen(CryptoContext<Element> cc, const PublicKey<Element> public_key,
                                                bool make_sparse_value, bool PRE);

    /**
     * Computes a non-lead party's partial decryption via multiparty_ after checking that the ciphertext has at
     * most two elements.
     *
     * @param ciphertext the ciphertext to partially decrypt
     * @param private_key this party's secret key share
     * @return the partial decryption
     */
    virtual Ciphertext<Element> multiparty_decrypt_main(ConstCiphertext<Element>& ciphertext,
                                                        const PrivateKey<Element> private_key) const;

    /**
     * Computes the lead party's partial decryption via multiparty_ after checking that the ciphertext has at most
     * two elements.
     *
     * @param ciphertext the ciphertext to partially decrypt
     * @param private_key the lead party's secret key share
     * @return the partial decryption
     */
    virtual Ciphertext<Element> multiparty_decrypt_lead(ConstCiphertext<Element>& ciphertext,
                                                        const PrivateKey<Element> private_key) const;

    virtual DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                    NativePoly* plaintext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->multiparty_decrypt_fusion(ciphertext_vec, plaintext);
    }

    virtual DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                    Poly* plaintext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->multiparty_decrypt_fusion(ciphertext_vec, plaintext);
    }

    /**
     * Generates this party's share of a key-switching key (used for joint relinearization keys) via multiparty_
     * and tags it with the key tag of new_private_key.
     *
     * @param old_private_key this party's share of the original secret key
     * @param new_private_key this party's share of the new secret key
     * @param eval_key the key-switching key accumulated so far by the previous parties
     * @return the updated key-switching key
     */
    virtual EvalKey<Element> multi_key_switch_gen(const PrivateKey<Element> old_private_key,
                                                  const PrivateKey<Element> new_private_key,
                                                  const EvalKey<Element> eval_key) const;

    /**
     * Adds this party's share to the joint automorphism keys via multiparty_ and tags every returned key with
     * key_id.
     *
     * @param private_key this party's secret key share
     * @param eval_auto_key_map automorphism keys accumulated so far by the previous parties
     * @param index_list automorphism indices to generate keys for
     * @param key_id key tag assigned to the returned keys
     * @return map from automorphism index to the updated key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_automorphism_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_auto_key_map,
            const std::vector<uint32_t>& index_list, const std::string& key_id);

    /**
     * Adds this party's share to the joint rotation keys via multiparty_ and tags every returned key with key_id.
     *
     * @param private_key this party's secret key share
     * @param eval_auto_key_map rotation keys accumulated so far by the previous parties
     * @param index_list rotation indices to generate keys for
     * @param key_id key tag assigned to the returned keys
     * @return map from automorphism index to the updated key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_at_index_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_auto_key_map,
            const std::vector<int32_t>& index_list, const std::string& key_id);

    /**
     * Adds this party's share to the joint eval_sum keys via multiparty_ and tags every returned key with key_id.
     *
     * @param private_key this party's secret key share
     * @param eval_sum_key_map summation keys accumulated so far by the previous parties
     * @param key_id key tag assigned to the returned keys
     * @return map from automorphism index to the updated key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_sum_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map,
            const std::string& key_id = "");

    /**
     * Adds two evaluation (key-switching) key shares via multiparty_ and tags the sum with key_id.
     *
     * @param eval_key1 first key share
     * @param eval_key2 second key share
     * @param key_id key tag assigned to the result
     * @return the summed key
     */
    virtual EvalKey<Element> multi_add_eval_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                                 const std::string& key_id);

    /**
     * Multiplies an evaluation key by this party's secret key share (a step of the joint relinearization key
     * generation) via multiparty_ and tags the result with key_id.
     *
     * @param private_key this party's secret key share
     * @param eval_key the evaluation key to multiply
     * @param key_id key tag assigned to the result
     * @return the resulting key
     */
    virtual EvalKey<Element> multi_mult_eval_key(PrivateKey<Element> private_key, EvalKey<Element> eval_key,
                                                 const std::string& key_id);

    /**
     * Adds two maps of eval_sum key shares index by index via multiparty_ and tags every resulting key with key_id.
     *
     * @param eval_sum_key_map1 first map of key shares
     * @param eval_sum_key_map2 second map of key shares
     * @param key_id key tag assigned to the resulting keys
     * @return map from automorphism index to the summed key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_sum_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map2, const std::string& key_id);

    /**
     * Adds two maps of automorphism key shares index by index via multiparty_ and tags every resulting key with
     * key_id.
     *
     * @param eval_sum_key_map1 first map of key shares
     * @param eval_sum_key_map2 second map of key shares
     * @param key_id key tag assigned to the resulting keys
     * @return map from automorphism index to the summed key
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_automorphism_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_map2, const std::string& key_id);

    /**
     * Adds two public key shares via multiparty_ and tags the joint public key with key_id.
     *
     * @param public_key1 first public key share
     * @param public_key2 second public key share
     * @param key_id key tag assigned to the result
     * @return the joint public key
     */
    virtual PublicKey<Element> multi_add_pub_keys(PublicKey<Element> public_key1, PublicKey<Element> public_key2,
                                                  const std::string& key_id);

    /**
     * Adds two relinearization key shares via multiparty_ and tags the sum with key_id.
     *
     * @param eval_key1 first relinearization key share
     * @param eval_key2 second relinearization key share
     * @param key_id key tag assigned to the result
     * @return the joint relinearization key
     */
    virtual EvalKey<Element> multi_add_eval_mult_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                                      const std::string& key_id);

    Ciphertext<Element> int_boot_adjust_scale(ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_boot_adjust_scale(ciphertext);
    }

    Ciphertext<Element> int_boot_decrypt(const PrivateKey<Element> private_key,
                                         ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_boot_decrypt(private_key, ciphertext);
    }

    Ciphertext<Element> int_boot_encrypt(const PublicKey<Element> public_key,
                                         ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_boot_encrypt(public_key, ciphertext);
    }

    Ciphertext<Element> int_boot_add(ConstCiphertext<Element> ciphertext1,
                                     ConstCiphertext<Element>& ciphertext2) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_boot_add(ciphertext1, ciphertext2);
    }

    Ciphertext<Element> int_mp_boot_adjust_scale(ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_adjust_scale(ciphertext);
    }

    Ciphertext<Element> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> crypto_parameters,
                                                       const PublicKey<Element> public_key) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_random_element_gen(crypto_parameters, public_key);
    }

    Ciphertext<Element> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> crypto_parameters,
                                                       ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_random_element_gen(crypto_parameters, ciphertext);
    }

    std::vector<Ciphertext<Element>> int_mp_boot_decrypt(const PrivateKey<Element> private_key,
                                                         ConstCiphertext<Element> ciphertext,
                                                         ConstCiphertext<Element> a) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_decrypt(private_key, ciphertext, a);
    }

    std::vector<Ciphertext<Element>> int_mp_boot_add(
            std::vector<std::vector<Ciphertext<Element>>>& shares_pair_vec) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_add(shares_pair_vec);
    }

    Ciphertext<Element> int_mp_boot_encrypt(const PublicKey<Element> public_key,
                                            const std::vector<Ciphertext<Element>>& shares_pair,
                                            ConstCiphertext<Element>& a, ConstCiphertext<Element>& ciphertext) const {
        verify_multiparty_enabled(__func__);
        return multiparty_->int_mp_boot_encrypt(public_key, shares_pair, a, ciphertext);
    }

    // FHE METHODS

    // TODO Andrey: do we need this method?
    //  const std::shared_ptr<BasePke<Element>> getAlgorithm() const { return pke_; }

    void eval_bootstrap_setup(const CryptoContextImpl<Element>& cc, const std::vector<uint32_t>& level_budget = {5, 4},
                              const std::vector<uint32_t>& dim1 = {0, 0}, uint32_t slots = 0,
                              uint32_t correction_factor = 0, bool precompute = true, bool bt_slots_encoding = false) {
        verify_fhe_enabled(__func__);
        fhe_->eval_bootstrap_setup(cc, level_budget, dim1, slots, correction_factor, precompute, bt_slots_encoding);
    }

    // Cache teardown is best-effort and must stay noexcept: a scheme that never enabled the
    // feature simply holds nothing to clear, so these are no-ops rather than errors.
    /**
     * Drops the bootstrapping precomputations cached by the FHE object; a no-op if FHE has not been enabled.
     */
    void clear_bootstrap_precom() noexcept {
        if (fhe_)
            fhe_->clear_bootstrap_precom();
    }

    /**
     * Drops the scheme-switching precomputations cached by the scheme-switching object; a no-op if SCHEMESWITCH has
     * not been enabled.
     */
    void clear_scheme_switch_precom() noexcept {
        if (scheme_switch_)
            scheme_switch_->clear_scheme_switch_precom();
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_bootstrap_key_gen(const PrivateKey<Element> private_key,
                                                                                 uint32_t slots) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_bootstrap_key_gen(private_key, slots);
    }

    std::vector<uint32_t> eval_bootstrap_key_map_indices(const CryptoContext<Element>& cc, uint32_t slots) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_bootstrap_key_map_indices(cc, slots);
    }

    void eval_bootstrap_precompute(const CryptoContextImpl<Element>& cc, uint32_t slots = 0) {
        verify_fhe_enabled(__func__);
        fhe_->eval_bootstrap_precompute(cc, slots);
    }

    Ciphertext<Element> eval_bootstrap(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations = 1,
                                       uint32_t precision = 0) const {
        verify_fhe_enabled(__func__);
        return fhe_->eval_bootstrap(ciphertext, num_iterations, precision);
    }

    Ciphertext<Element> eval_bootstrap_st_c_first(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations = 1,
                                                  uint32_t precision = 0) const {
        verify_fhe_enabled(__func__);
        return fhe_->eval_bootstrap_st_c_first(ciphertext, num_iterations, precision);
    }

    void eval_fe_func_bootstrap_setup(const CryptoContextImpl<Element>& cc,
                                      const std::vector<uint32_t>& level_budget = {5, 4},
                                      const std::vector<uint32_t>& dim1 = {0, 0}, uint32_t slots = 0) {
        verify_fhe_enabled(__func__);
        fhe_->eval_fe_func_bootstrap_setup(cc, level_budget, dim1, slots);
    }

    Ciphertext<Element> eval_fe_func_bootstrap(ConstCiphertext<Element>& ciphertext,
                                               const std::vector<std::complex<double>>& coefficients) const {
        verify_fhe_enabled(__func__);
        return fhe_->eval_fe_func_bootstrap(ciphertext, coefficients);
    }

    std::shared_ptr<SeriesPowers<Element>> eval_fe_func_bootstrap_precompute(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        verify_fhe_enabled(__func__);
        return fhe_->eval_fe_func_bootstrap_precompute(ciphertext, coefficients);
    }

    Ciphertext<Element> eval_fe_func_bootstrap_with_precomp(
            const std::shared_ptr<SeriesPowers<Element>>& powers,
            const std::vector<std::complex<double>>& coefficients) const {
        verify_fhe_enabled(__func__);
        return fhe_->eval_fe_func_bootstrap_with_precomp(powers, coefficients);
    }

    template <typename VectorDataType>
    void eval_fbt_setup(const CryptoContextImpl<Element>& cc, const std::vector<VectorDataType>& coeffs,
                        uint32_t num_slots, const BigInteger& p_in, const BigInteger& P_out, const BigInteger& bigq,
                        const PublicKey<RnsPoly>& pub_key, const std::vector<uint32_t>& dim1,
                        const std::vector<uint32_t>& level_budget, uint32_t lvls_after_boot = 0,
                        uint32_t depth_leveled_computation = 0, size_t order = 1) {
        verify_fhe_enabled(__func__);
        fhe_->eval_fbt_setup(cc, coeffs, num_slots, p_in, P_out, bigq, pub_key, dim1, level_budget, lvls_after_boot,
                             depth_leveled_computation, order);
    }

    template <typename VectorDataType>
    Ciphertext<Element> eval_fbt(ConstCiphertext<Element>& ciphertext, const std::vector<VectorDataType>& coeffs,
                                 uint32_t digit_bit_size, const BigInteger& initial_scaling, uint64_t post_scaling,
                                 uint32_t level_to_reduce = 0, size_t order = 1) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_fbt(ciphertext, coeffs, digit_bit_size, initial_scaling, post_scaling, level_to_reduce,
                              order);
    }

    template <typename VectorDataType>
    Ciphertext<Element> eval_fbt_no_decoding(ConstCiphertext<Element>& ciphertext,
                                             const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                             const BigInteger& initial_scaling, size_t order = 1) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_fbt_no_decoding(ciphertext, coeffs, digit_bit_size, initial_scaling, order);
    }

    Ciphertext<Element> eval_hom_decoding(ConstCiphertext<Element>& ciphertext, uint64_t post_scaling,
                                          uint32_t level_to_reduce = 0) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_hom_decoding(ciphertext, post_scaling, level_to_reduce);
    }

    template <typename VectorDataType>
    std::shared_ptr<SeriesPowers<Element>> eval_mvb_precompute(ConstCiphertext<Element>& ciphertext,
                                                               const std::vector<VectorDataType>& coeffs,
                                                               uint32_t digit_bit_size,
                                                               const BigInteger& initial_scaling, size_t order = 1) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_mvb_precompute(ciphertext, coeffs, digit_bit_size, initial_scaling, order);
    }

    template <typename VectorDataType>
    Ciphertext<Element> eval_mvb(const std::shared_ptr<SeriesPowers<Element>> ciphertexts,
                                 const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                 uint64_t post_scaling, uint32_t level_to_reduce = 0, size_t order = 1) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_mvb(ciphertexts, coeffs, digit_bit_size, post_scaling, level_to_reduce, order);
    }

    template <typename VectorDataType>
    Ciphertext<Element> eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<Element>> ciphertexts,
                                             const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                             size_t order = 1) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_mvb_no_decoding(ciphertexts, coeffs, digit_bit_size, order);
    }

    template <typename VectorDataType>
    Ciphertext<Element> eval_hermite_trig_series(ConstCiphertext<Element>& ciphertext,
                                                 const std::vector<std::complex<double>>& coefficients_cheb, double a,
                                                 double b, const std::vector<VectorDataType>& coefficients_herm,
                                                 size_t precomp = 0) {
        verify_fhe_enabled(__func__);
        return fhe_->eval_hermite_trig_series(ciphertext, coefficients_cheb, a, b, coefficients_herm, precomp);
    }

    uint32_t get_ckks_boot_correction_factor() {
        verify_fhe_enabled(__func__);
        return fhe_->get_ckks_boot_correction_factor();
    }

    void set_ckks_boot_correction_factor(uint32_t cf) {
        verify_fhe_enabled(__func__);
        return fhe_->set_ckks_boot_correction_factor(cf);
    }

    // SCHEMESWITCHING methods

    LwePrivateKey eval_ckks_to_fhew_setup(const SchSwchParams& params) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_ckks_to_fhew_setup(params);
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_ckks_to_fhew_key_gen(const KeyPair<Element>& key_pair,
                                                                                    ConstLwePrivateKey& lwesk) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_ckks_to_fhew_key_gen(key_pair, lwesk);
    }

    void eval_ckks_to_fhew_precompute(const CryptoContextImpl<Element>& cc, double scale = 1.0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_ckks_to_fhew_precompute(cc, scale);
    }

    std::vector<std::shared_ptr<LweCiphertextImpl>> eval_ckks_to_fhew(ConstCiphertext<Element>& ciphertext,
                                                                      uint32_t num_ctxts = 0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_ckks_to_fhew(ciphertext, num_ctxts);
    }

    void eval_fhew_to_ckks_setup(const CryptoContextImpl<Element>& cc_ckks,
                                 const std::shared_ptr<BooleanContext>& cc_lwe, uint32_t num_slots_ckks = 0,
                                 uint32_t log_q = 25) {
        verify_scheme_switch_enabled(__func__);
        scheme_switch_->eval_fhew_to_ckks_setup(cc_ckks, cc_lwe, num_slots_ckks, log_q);
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_fhew_to_ckks_key_gen(const KeyPair<Element>& key_pair,
                                                                                    ConstLwePrivateKey& lwesk,
                                                                                    uint32_t num_slots = 0,
                                                                                    uint32_t num_ctxts = 0,
                                                                                    uint32_t dim1 = 0, uint32_t L = 0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_fhew_to_ckks_key_gen(key_pair, lwesk, num_slots, num_ctxts, dim1, L);
    }

    void eval_compare_switch_precompute(const CryptoContextImpl<Element>& cc_ckks, uint32_t p_lwe = 0,
                                        double scale_sign = 1.0, bool unit = false) {
        verify_scheme_switch_enabled(__func__);
        scheme_switch_->eval_compare_switch_precompute(cc_ckks, p_lwe, scale_sign, unit);
    }

    Ciphertext<Element> eval_fhew_to_ckks(std::vector<std::shared_ptr<LweCiphertextImpl>>& lwe_ciphertexts,
                                          uint32_t num_ctxts = 0, uint32_t num_slots = 0, uint32_t p = 4,
                                          double pmin = 0.0, double pmax = 2.0, uint32_t dim1 = 0) const {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_fhew_to_ckks(lwe_ciphertexts, num_ctxts, num_slots, p, pmin, pmax, dim1);
    }

    LwePrivateKey eval_scheme_switching_setup(const SchSwchParams& params) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_scheme_switching_setup(params);
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_scheme_switching_key_gen(
            const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_scheme_switching_key_gen(key_pair, lwesk);
    }

    Ciphertext<Element> eval_compare_scheme_switching(ConstCiphertext<Element>& ciphertext1,
                                                      ConstCiphertext<Element>& ciphertext2, uint32_t num_ctxts = 0,
                                                      uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                      double scale_sign = 1.0, bool unit = false) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_compare_scheme_switching(ciphertext1, ciphertext2, num_ctxts, num_slots, p_lwe,
                                                             scale_sign, unit);
    }

    std::vector<Ciphertext<Element>> eval_min_scheme_switching(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element> public_key, uint32_t num_values = 0,
                                                               uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                               double scale_sign = 1.0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_min_scheme_switching(ciphertext, public_key, num_values, num_slots, p_lwe,
                                                         scale_sign);
    }

    std::vector<Ciphertext<Element>> eval_min_scheme_switching_alt(ConstCiphertext<Element>& ciphertext,
                                                                   PublicKey<Element> public_key,
                                                                   uint32_t num_values = 0, uint32_t num_slots = 0,
                                                                   uint32_t p_lwe = 0, double scale_sign = 1.0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_min_scheme_switching_alt(ciphertext, public_key, num_values, num_slots, p_lwe,
                                                             scale_sign);
    }

    std::vector<Ciphertext<Element>> eval_max_scheme_switching(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element> public_key, uint32_t num_values = 0,
                                                               uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                               double scale_sign = 1.0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_max_scheme_switching(ciphertext, public_key, num_values, num_slots, p_lwe,
                                                         scale_sign);
    }

    std::vector<Ciphertext<Element>> eval_max_scheme_switching_alt(ConstCiphertext<Element>& ciphertext,
                                                                   PublicKey<Element> public_key,
                                                                   uint32_t num_values = 0, uint32_t num_slots = 0,
                                                                   uint32_t p_lwe = 0, double scale_sign = 1.0) {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->eval_max_scheme_switching_alt(ciphertext, public_key, num_values, num_slots, p_lwe,
                                                             scale_sign);
    }

    std::shared_ptr<cipher::BooleanContext> get_bin_cc_for_scheme_switch() {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->get_bin_cc_for_scheme_switch();
    }

    void set_bin_cc_for_scheme_switch(std::shared_ptr<cipher::BooleanContext> cc_lwe) {
        verify_scheme_switch_enabled(__func__);
        scheme_switch_->set_bin_cc_for_scheme_switch(cc_lwe);
    }

    Ciphertext<Element> get_swk_fc() {
        verify_scheme_switch_enabled(__func__);
        return scheme_switch_->get_swk_fc();
    }

    void set_swk_fc(Ciphertext<Element> fhew_to_ckks_swk) {
        verify_scheme_switch_enabled(__func__);
        scheme_switch_->set_swk_fc(fhew_to_ckks_swk);
    }

    /**
     * Serializes the scheme: only the FHE and scheme-switching objects (which carry precomputed data) and the mask
     * of enabled features are written; the other family objects are stateless and are recreated by enable() on
     * load.
     *
     * @param ar the archive to write to
     * @param version serialized version of the object
     */
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        // TODO (dsuponit): should we serialize all feature pointers???
        // if (is_feature_enabled()) {
        // }
        // ar(::cereal::make_nvp("params", params_gen_));
        // ar(::cereal::make_nvp("pke", pke_));
        // ar(::cereal::make_nvp("keyswitch", key_switch_));
        // ar(::cereal::make_nvp("pre", pre_));
        // ar(::cereal::make_nvp("lvldshe", leveled_she_));
        // ar(::cereal::make_nvp("advshe", advanced_she_));
        ar(::cereal::make_nvp("fhe", fhe_));
        ar(::cereal::make_nvp("schswitch", scheme_switch_));
        ar(::cereal::make_nvp("enabled", get_enabled()));
    }

    /**
     * Deserializes the scheme: reads the FHE and scheme-switching objects, tolerating archives written before
     * these fields existed (JSON encoding only; the fields are then left null), then re-enables every feature in
     * the serialized mask through enable().
     *
     * @param ar the archive to read from
     * @param version serialized version of the object; must not exceed serialized_version()
     */
    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }

        // ar(::cereal::make_nvp("params", params_gen_));
        // ar(::cereal::make_nvp("pke", pke_));
        // ar(::cereal::make_nvp("keyswitch", key_switch_));
        // ar(::cereal::make_nvp("pre", pre_));
        // ar(::cereal::make_nvp("lvldshe", leveled_she_));
        // ar(::cereal::make_nvp("advshe", advanced_she_));

        // try-catch is used for backwards compatibility down to 1.0.x
        // only works for JSON encoding
        // fhe_ was added in v1.1.2
        try {
            ar(::cereal::make_nvp("fhe", fhe_));
        } catch (cereal::Exception&) {
            fhe_ = nullptr;
        }

        // try-catch is used for backwards compatibility down to 1.0.x
        // only works for JSON encoding
        // scheme_switch_ was added in v1.1.3
        try {
            ar(::cereal::make_nvp("schswitch", scheme_switch_));
        } catch (cereal::Exception&) {
            scheme_switch_ = nullptr;
        }

        uint32_t enabled = 0;
        ar(::cereal::make_nvp("enabled", enabled));
        enable(enabled);
    }

    virtual std::string serialized_object_name() const {
        return "SchemeBase";
    }

    static uint32_t serialized_version() {
        return 1;
    }

    //=================================================================================================================
    // Functions to check enabled features in the cryptocontext
    //=================================================================================================================
    /**
     * @brief verify_advanced_she_enabled is to check if enable(ADVANCEDSHE) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_advanced_she_enabled(const std::string& function_name) const {
        if (advanced_she_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(ADVANCEDSHE) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_multiparty_enabled is to check if enable(MULTIPARTY) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_multiparty_enabled(const std::string& function_name) const {
        if (multiparty_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(MULTIPARTY) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_leveled_she_enabled is to check if enable(LEVELEDSHE) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_leveled_she_enabled(const std::string& function_name) const {
        if (leveled_she_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(LEVELEDSHE) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_pke_enabled is to check if enable(PKE) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_pke_enabled(const std::string& function_name) const {
        if (pke_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(PKE) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_pre_enabled is to check if enable(PRE) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_pre_enabled(const std::string& function_name) const {
        if (pre_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(PRE) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_key_switch_enabled is to check if enable(KEYSWITCH) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_key_switch_enabled(const std::string& function_name) const {
        if (key_switch_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(KEYSWITCH) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }
    /**
     * @brief verify_fhe_enabled is to check if enable(FHE) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_fhe_enabled(const std::string& function_name) const {
        if (fhe_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(FHE) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }

    /**
     * @brief verify_scheme_switch_enabled is to check if enable(SCHEMESWITCH) has been called and if it has not
     *        it will throw an exception
     * @param function_name is the calling function name. __func__ can be used instead
     */
    inline void verify_scheme_switch_enabled(const std::string& function_name) const {
        if (scheme_switch_ == nullptr) {
            std::string err_msg = std::string(function_name) +
                                  " operation has not been enabled. Enable(SCHEMESWITCH) must be called to enable it.";
            CIPHER_THROW(err_msg);
        }
    }

    /**
     * Prints the dynamic type of the scheme and, for every family, the dynamic type of the implementing object or
     * "none" if the family is not enabled.
     *
     * @param out the output stream
     * @param s the scheme to print
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& out, const SchemeBase<Element>& s) {
        out << typeid(s).name() << ":";
        out << " ParamsGen " << (s.params_gen_ == 0 ? "none" : typeid(*s.params_gen_).name());
        out << ", PKE " << (s.pke_ == 0 ? "none" : typeid(*s.pke_).name());
        out << ", KeySwitch " << (s.key_switch_ == 0 ? "none" : typeid(*s.key_switch_).name());
        out << ", PRE " << (s.pre_ == 0 ? "none" : typeid(*s.pre_).name());
        out << ", LeveledSHE " << (s.leveled_she_ == 0 ? "none" : typeid(*s.leveled_she_).name());
        out << ", AdvancedSHE " << (s.advanced_she_ == 0 ? "none" : typeid(*s.advanced_she_).name());
        out << ", Multiparty " << (s.multiparty_ == 0 ? "none" : typeid(*s.multiparty_).name());
        out << ", FHE " << (s.fhe_ == 0 ? "none" : typeid(*s.fhe_).name());
        out << ", SchemeSwitch " << (s.scheme_switch_ == 0 ? "none" : typeid(*s.scheme_switch_).name());
        return out;
    }

  protected:
    /** parameter generation; set by the concrete scheme's constructor */
    std::shared_ptr<BaseParamGen<Element>> params_gen_;
    /** key generation, encryption and decryption; set by enable(PKE) */
    std::shared_ptr<BasePke<Element>> pke_;
    /** key switching; set by enable(KEYSWITCH) */
    std::shared_ptr<KeySwitchBase<Element>> key_switch_;
    /** proxy re-encryption; set by enable(PRE) */
    std::shared_ptr<BasePre<Element>> pre_;
    /** leveled homomorphic arithmetic; set by enable(LEVELEDSHE) */
    std::shared_ptr<BaseLeveledShe<Element>> leveled_she_;
    /** polynomial evaluation, summation and inner products; set by enable(ADVANCEDSHE) */
    std::shared_ptr<BaseAdvancedShe<Element>> advanced_she_;
    /** threshold key generation and decryption; set by enable(MULTIPARTY) */
    std::shared_ptr<BaseMultiparty<Element>> multiparty_;
    /** CKKS bootstrapping and functional bootstrapping; set by enable(FHE) */
    std::shared_ptr<BaseFhe<Element>> fhe_;
    /** CKKS <-> FHEW scheme switching; set by enable(SCHEMESWITCH) */
    std::shared_ptr<BaseFhe<Element>> scheme_switch_;

    /**
     * Throws an exception if the ciphertext has more than two elements, since multiparty decryption requires a
     * relinearized ciphertext. The remaining (macro-supplied) parameters identify the caller for the error message.
     *
     * @param ciphertext the ciphertext to check
     */
    inline void check_multiparty_decrypt_compatibility(ConstCiphertext<Element>& ciphertext,
                                                       CALLER_INFO_ARGS_HDR) const {
        if (ciphertext->number_ciphertext_elements() > 2) {
            std::string error_msg(std::string("ciphertext's number of elements is [") +
                                  std::to_string(ciphertext->number_ciphertext_elements()) +
                                  "]. Must be 2 or less for Multiparty Decryption." + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_SCHEME_H_
