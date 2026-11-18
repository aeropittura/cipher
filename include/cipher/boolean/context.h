//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Header file for BooleanContext class, which is used for Boolean circuit FHE schemes
 */

#ifndef CIPHER_BOOLEAN_CONTEXT_H_
#define CIPHER_BOOLEAN_CONTEXT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/boolean/base_scheme.h"
#include "cipher/ring/standard_params.h"
#include "cipher/util/memory.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Custom parameter set for BooleanContext::generate_boolean_context(const BooleanContextParams&, BINFHE_METHOD)
 *
 * The RingGSW/RLWE modulus Q is derived as the largest number_bits-bit prime congruent to 1 mod cycl_order, and the
 * ring dimension N as cycl_order / 2.
 */
struct BooleanContextParams {
    uint32_t number_bits;    ///< bit size of the intermediate prime Q, the RingGSW/RLWE modulus used in bootstrapping
    uint32_t cycl_order;     ///< cyclotomic order 2N of the RingGSW/RLWE ring
    uint32_t lattice_param;  ///< lattice parameter n (dimension) of the additive LWE scheme
    uint32_t mod_value;           ///< modulus q for additive LWE
    uint32_t mod_ks;         ///< modulus for key switching; zero selects the intermediate prime Q
    uint32_t base_ks;        ///< base for key switching
    uint32_t gadget_base;    ///< gadget base used in bootstrapping (also for the automorphism keys in LMKCDEY)
    uint32_t base_rk;        ///< base for the refreshing key (AP bootstrapping)
    uint32_t num_auto_keys;   ///< number of automorphism keys for LMKCDEY (> 0)
    SecretKeyDist key_dist;  ///< secret key distribution
    double std_dev_value;          ///< standard deviation of the error distribution
    std::map<uint32_t, uint32_t> gadget_base_map;  ///< number of LWE secret-key coefficients assigned to each gadget
                                                 ///< base, in ascending base order; empty means gadget_base for all
};

/**
 * @brief BooleanContext
 *
 * The wrapper class for Boolean circuit FHE
 */
class BooleanContext : public Serializable {
  public:
    BooleanContext() = default;

    /**
     * Creates a crypto context using custom parameters.
     * Should be used with care (only for advanced users familiar with LWE
     * parameter selection).
     *
     * @param n lattice parameter for additive LWE scheme
     * @param N ring dimension for RingGSW/RLWE used in bootstrapping
     * @param q modulus for additive LWE
     * @param Q modulus for RingGSW/RLWE used in bootstrapping
     * @param std standard deviation
     * @param base_ks the base used for key switching
     * @param base_g the gadget base used in bootstrapping
     * @param base_r the base used for refreshing
     * @param key_dist secret key distribution
     * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
     * @param num_auto_keys number of automorphism keys in LMKCDEY bootstrapping
     */
    void generate_boolean_context(uint32_t n, uint32_t N, NativeInteger q, NativeInteger Q, double std, uint32_t base_ks,
                               uint32_t base_g, uint32_t base_r, SecretKeyDist key_dist = UNIFORM_TERNARY,
                               BINFHE_METHOD method = GINX, uint32_t num_auto_keys = 10);

    /**
     * Creates a crypto context using custom parameters.
     * Should be used with care (only for advanced users familiar with LWE
     * parameter selection).
     *
     * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants, see binfhe_constants.h
     * @param arb_func whether need to evaluate an arbitrary function using functional bootstrapping
     * @param log_q log(input ciphertext modulus)
     * @param N ring dimension for RingGSW/RLWE used in bootstrapping
     * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
     * @param time_optimization whether to use dynamic bootstrapping technique
     */
    void generate_boolean_context(BINFHE_PARAMSET set, bool arb_func, uint32_t log_q = 11, uint32_t N = 0,
                               BINFHE_METHOD method = GINX, bool time_optimization = false);

    /**
     * Creates a crypto context using predefined parameters sets. Recommended for
     * most users.
     *
     * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants, see binfhe_constants.h
     * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
     */
    void generate_boolean_context(BINFHE_PARAMSET set, BINFHE_METHOD method = GINX);

    /**
     * Creates a crypto context using custom parameters.
     *
     * @param params the parameter context
     * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
     */
    void generate_boolean_context(const BooleanContextParams& params, BINFHE_METHOD method = GINX);

    /**
     * Gets the refresh key at the width the context holds it. Null when the 32-bit internal form
     * is the resident one, so serialize get_bt_key() rather than this.
     *
     * @return a shared pointer to the refresh key
     */
    const RingGswAccKey& get_refresh_key() const {
        return bt_key_.b_skey;
    }

    /**
     * Gets the switching key at the width the context holds it, with the same caveat as
     * get_refresh_key().
     *
     * @return a shared pointer to the switching key
     */
    const LweSwitchingKey& get_switch_key() const {
        return bt_key_.ks_key;
    }

    /**
     * Gets both bootstrapping keys and the public key, each at the width the context holds it.
     * This is what serialization takes: the archive records whichever width was resident, and
     * bt_key_load() restores it, narrowing or widening only if the caller asks for the other one.
     *
     * @return the bootstrapping keys
     */
    const RingGswBtKey& get_bt_key() const {
        return bt_key_;
    }

    /**
     * Gets the public key (used for serialization).
     *
     * @return a shared pointer to the public key
     */
    const LwePublicKey& get_public_key() const {
        return bt_key_.pkey;
    }

    /**
     * Checks whether the refreshing key is held in the 32-bit internal form. Unlike the serialization getters, this
     * never widens, so it is safe for introspection and memory accounting
     *
     * @return true if the resident refreshing key is the 32-bit one; always false in a 32-bit CIPHER_NATIVE_INT build
     */
    bool has_internal32_refresh_key() const {
#if CIPHER_NATIVE_INT != 32
        return bt_key_.b_skey32 != nullptr;
#else
        return false;
#endif
    }

    /**
     * Checks whether the key switching key is held in the 32-bit internal form, without widening it
     *
     * @return true if the resident switching key is the 32-bit one; always false in a 32-bit CIPHER_NATIVE_INT build
     */
    bool has_internal32_switch_key() const {
#if CIPHER_NATIVE_INT != 32
        return bt_key_.ks_key32 != nullptr;
#else
        return false;
#endif
    }

    /**
     * Gets the bootstrapping key map (used for serialization).
     *
     * @return a shared pointer to the bootstrapping key map
     */
    const std::shared_ptr<std::map<uint32_t, RingGswBtKey>> get_bt_key_map() const {
        return std::make_shared<std::map<uint32_t, RingGswBtKey>>(bt_key_map_);
    }

    /**
     * Generates a secret key for the main LWE scheme
     *
     * @return a shared pointer to the secret key
     */
    LwePrivateKey key_gen() const;

    /**
     * Generates a public key, secret key pair for the main LWE scheme
     *
     * @return a shared pointer to the public key, secret key pair
     */
    LweKeyPair key_gen_pair() const;

    /**
     * Generates a public key for a secret key for the main LWE scheme
     *
     * @param sk the secret key
     * @return a shared pointer to the public key
     */
    LwePublicKey pub_key_gen(ConstLwePrivateKey& sk) const;

    /**
     * Generates a secret key used in bootstrapping
     * @return a shared pointer to the secret key
     */
    LwePrivateKey key_gen_n() const;

    /**
     * Encrypts a bit or integer using a secret key (symmetric key encryption)
     *
     * @param sk the secret key
     * @param m the plaintext
     * @param output SMALL_DIM to generate fresh ciphertext (default), LARGE_DIM to
     * generate a refreshed ciphertext
     * @param p plaintext modulus
     * @param mod the ciphertext modulus to encrypt with; by default q_ in params
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext encrypt(ConstLwePrivateKey& sk, LwePlaintext m, BINFHE_OUTPUT output = SMALL_DIM,
                          LwePlaintextModulus p = 4, NativeInteger mod_value = 0) const;

    /**
     * Encrypts a bit or integer using a public key (public key encryption)
     *
     * @param pk the public key
     * @param m the plaintext
     * @param output SMALL_DIM to generate ciphertext with dimension n (default). LARGE_DIM to generate ciphertext with dimension N
     * @param p plaintext modulus
     * @param mod the ciphertext modulus to encrypt with; by default q_ in params
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext encrypt(ConstLwePublicKey& pk, LwePlaintext m, BINFHE_OUTPUT output = SMALL_DIM,
                          LwePlaintextModulus p = 4, NativeInteger mod_value = 0) const;

    /**
     * Converts a ciphertext (public key encryption) with modulus Q and dimension N to ciphertext with q and n
     *
     * @param ksk the key switching key from secret key of dimension N to secret key of dimension n
     * @param ct the ciphertext to convert
     * @return a shared pointer to the ciphertext
     */
    LweCiphertext switch_c_ttoqn(ConstLweSwitchingKey& ksk, ConstLweCiphertext& ct) const;

    /**
     * Decrypts a ciphertext using a secret key
     *
     * @param sk the secret key
     * @param ct the ciphertext
     * @param result plaintext result
     * @param p plaintext modulus
     */
    void decrypt(ConstLwePrivateKey& sk, ConstLweCiphertext& ct, LwePlaintext* result, LwePlaintextModulus p = 4) const;

    /**
     * Generates a switching key to go from a secret key with (Q,N) to a secret
     * key with (q,n)
     *
     * @param sk new secret key
     * @param sk_n old secret key
     * @return a shared pointer to the switching key
     */
    LweSwitchingKey key_switch_gen(ConstLwePrivateKey& sk, ConstLwePrivateKey& sk_n) const;

    /**
     * Generates boostrapping keys
     *
     * @param sk secret key
     * @param keygen_mode key generation mode for symmetric or public encryption
     * @param internal32 generate the keys directly in their 32-bit internal form where they
     *        qualify. Qualification is per key and automatic: a key whose moduli do not fit is
     *        generated in the 64-bit form instead.
     */
    void bt_key_gen(ConstLwePrivateKey& sk, KEYGEN_MODE keygen_mode = SYM_ENCRYPT, bool internal32 = true);

    /**
     * Loads bootstrapping keys in the context (typically after deserializing)
     *
     * @param key struct with the bootstrapping keys
     * @param internal32 convert the loaded keys to the 32-bit internal form where they qualify,
     *        release the 64-bit copies and return the freed pages to the OS. Any handles the
     *        caller still holds keep the 64-bit copies resident; drop them and call alloc_trim()
     *        to finish the release.
     */
    void bt_key_load(const RingGswBtKey& key, bool internal32 = true) {
        bt_key_ = key;
#if CIPHER_NATIVE_INT != 32
        if (internal32) {
            if (bt_key_.b_skey != nullptr)
                params_->get_ring_gsw_params()->ensure_monomials();
            if (compress_bt_keys()) {
                release_monomials_if_all32();
                alloc_trim();
            }
            return;
        }
        // the caller asked for the native width, so widen whatever arrived narrow
        if (bt_key_.b_skey == nullptr && bt_key_.b_skey32 != nullptr)
            bt_key_.b_skey = bt_key_.b_skey32->widen(params_->get_ring_gsw_params());
        if (bt_key_.ks_key == nullptr && bt_key_.ks_key32 != nullptr)
            bt_key_.ks_key = bt_key_.ks_key32->widen(*params_->get_lwe_params());
        bt_key_.b_skey32 = nullptr;
        bt_key_.ks_key32 = nullptr;
#else
        (void)internal32;
#endif
        if (bt_key_.b_skey != nullptr)
            params_->get_ring_gsw_params()->ensure_monomials();
    }

    /**
     * Loads a bootstrapping key map element in the context (typically after deserializing)
     *
     * @param base_g base_g corresponding to the given key
     * @param key struct with the bootstrapping keys
     */
    void bt_key_map_load_single_element(uint32_t base_g, const RingGswBtKey& key) {
        if (key.b_skey != nullptr)
            params_->get_ring_gsw_params()->ensure_monomials();
        bt_key_map_[base_g] = key;
    }

    /**
     * Clear the bootstrapping keys in the current context
     */
    void clear_bt_keys() {
        bt_key_.b_skey.reset();
        bt_key_.ks_key.reset();
        bt_key_.pkey.reset();
#if CIPHER_NATIVE_INT != 32
        bt_key_.b_skey32.reset();
        bt_key_.ks_key32.reset();
#endif
        bt_key_map_.clear();
    }

    /**
     * Evaluates a binary gate (calls bootstrapping as a subroutine)
     *
     * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
     * @param ct1 first ciphertext
     * @param ct2 second ciphertext
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_bin_gate(BINGATE gate, ConstLweCiphertext& ct1, ConstLweCiphertext& ct2,
                              bool extended = false) const;

    /**
     * Evaluates a binary gate on vector of ciphertexts (calls bootstrapping as a subroutine)
     *
     * @param gate the gate; can be MAJORITY, AND3, OR3, AND4, OR4, or CMUX
     * @param ctvector vector of ciphertexts
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_bin_gate(BINGATE gate, const std::vector<LweCiphertext>& ctvector, bool extended = false) const;

    /**
     * Bootstraps a ciphertext (without peforming any operation)
     *
     * @param ct ciphertext to be bootstrapped
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext bootstrap(ConstLweCiphertext& ct, bool extended = false) const;

    /**
     * Evaluate an arbitrary function
     *
     * @param ct ciphertext to be bootstrapped
     * @param LUT the look-up table of the to-be-evaluated function
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_func(ConstLweCiphertext& ct, const std::vector<NativeInteger>& LUT) const;

    /**
     * Generate the LUT for the to-be-evaluated function
     *
     * @param f the to-be-evaluated function on an integer message and a plaintext modulus
     * @param p plaintext modulus
     * @return the look-up table (vector of function values) for the function
     */
    std::vector<NativeInteger> generate_lut_via_function(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                      NativeInteger p);

    /**
     * Evaluate a round down function
     *
     * @param ct ciphertext to be bootstrapped
     * @param roundbits number of bits to be rounded
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_floor(ConstLweCiphertext& ct, uint32_t roundbits = 0) const;

    /**
     * Evaluate a sign function over large precisions
     *
     * @param ct ciphertext to be bootstrapped
     * @param scheme_switch flag that indicates if it should be compatible to scheme switching
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_sign(ConstLweCiphertext& ct, bool scheme_switch = false);

    /**
     * Evaluate ciphertext decomposition
     *
     * @param ct ciphertext to be bootstrapped
     * @return a vector of shared pointers to the resulting ciphertexts
     */
    std::vector<LweCiphertext> eval_decomp(ConstLweCiphertext& ct);

    /**
     * Evaluates NOT gate
     *
     * @param ct the input ciphertext
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_not(ConstLweCiphertext& ct) const;

    /**
     * Evaluates constant gate
     *
     * @param value the Boolean value to output
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_constant(bool value) const;

    /**
     * Getter for params
     * @return a shared pointer to the BinFHE crypto parameters
     */
    const std::shared_ptr<BooleanCryptoParams>& get_params() {
        return params_;
    }

    /**
     * Getter for LWE scheme
     * @return a shared pointer to the LWE encryption scheme
     */
    const std::shared_ptr<LweEncryptionScheme>& get_lwe_scheme() {
        return lwe_scheme_;
    }

    /**
     * Getter for BinFHE scheme
     * @return a shared pointer to the BinFHE scheme
     */
    const std::shared_ptr<BooleanScheme>& get_boolean_scheme() {
        return binfhescheme_;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("params", params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("params", params_));
        binfhescheme_ = std::make_shared<BooleanScheme>(params_->get_ring_gsw_params()->get_method());
    }

    std::string serialized_object_name() const override {
        return "BinFHEContext";
    }

    static uint32_t serialized_version() {
        return 1;
    }

    /**
     * Getter for maximum plaintext modulus
     * @return the maximum plaintext modulus supported by the parameters
     */
    NativeInteger get_max_plaintext_space() const {
        // Under our parameter choices, beta = 128 is enough, and therefore plaintext = q/2beta
        return params_->get_lwe_params()->get_q() / (this->get_beta() << 1);
    }

    /**
     * Getter for the beta security parameter
     * @return the error bound beta
     */
    constexpr NativeInteger get_beta() const {
        return NativeInteger(128);
    }

  private:
#if CIPHER_NATIVE_INT != 32
    /**
     * Convert the refreshing and switching keys to their 32-bit internal forms and release the
     * originals, halving resident key material and running the blind rotation and key switch on
     * 32-bit words. Each key converts only when its modulus qualifies. Peak memory holds both
     * forms during the conversion, and the released pages return to the OS only after a
     * follow-up alloc_trim().
     *
     * Callers select this through bt_key_gen and bt_key_load rather than here: false means the keys
     * were already narrowed as well as that they do not qualify, which is not a distinction an
     * application should have to make.
     *
     * @return true if a key was converted
     */
    bool compress_bt_keys() {
        bool converted = false;
        if (bt_key_.b_skey != nullptr) {
            const auto& rgsw_params = params_->get_ring_gsw_params();
            if (bt_key_.b_skey32 == nullptr && RingGswAccKey32Impl::fits(*rgsw_params))
                bt_key_.b_skey32 = std::make_shared<RingGswAccKey32Impl>(rgsw_params, *bt_key_.b_skey);
            if (bt_key_.b_skey32 != nullptr) {
                // the map entry for the active base_g aliases bt_key_; release its copy too or
                // the 64-bit key stays resident through it
                for (auto& [base_g, key] : bt_key_map_) {
                    if (key.b_skey == bt_key_.b_skey) {
                        key.b_skey32 = bt_key_.b_skey32;
                        key.b_skey.reset();
                    }
                }
                bt_key_.b_skey.reset();
                converted = true;
            }
        }
        if (bt_key_.ks_key != nullptr) {
            const auto& lwe_params = params_->get_lwe_params();
            if (bt_key_.ks_key32 == nullptr && LweSwitchingKey32Impl::fits(*lwe_params))
                bt_key_.ks_key32 = std::make_shared<LweSwitchingKey32Impl>(*lwe_params, *bt_key_.ks_key);
            if (bt_key_.ks_key32 != nullptr) {
                for (auto& [base_g, key] : bt_key_map_) {
                    if (key.ks_key == bt_key_.ks_key) {
                        key.ks_key32 = bt_key_.ks_key32;
                        key.ks_key.reset();
                    }
                }
                bt_key_.ks_key.reset();
                converted = true;
            }
        }
        return converted;
    }
#endif

#if CIPHER_NATIVE_INT != 32
    // release the 64-bit monomial table when every held key runs on the 32-bit internal path
    // (which keeps its own); rebuilt on demand if a 64-bit key is generated or loaded later
    void release_monomials_if_all32() {
        if (bt_key_.b_skey != nullptr || bt_key_.b_skey32 == nullptr)
            return;
        for (const auto& [base_g, key] : bt_key_map_)
            if (key.b_skey != nullptr)
                return;
        params_->get_ring_gsw_params()->clear_monomials();
    }
#endif

    // Shared pointer to Ring GSW + LWE parameters
    std::shared_ptr<BooleanCryptoParams> params_{nullptr};

    // Shared pointer to the underlying additive LWE scheme
    std::shared_ptr<LweEncryptionScheme> lwe_scheme_{std::make_shared<LweEncryptionScheme>()};

    // Shared pointer to the underlying RingGSW/RLWE scheme
    std::shared_ptr<BooleanScheme> binfhescheme_{nullptr};

    // Struct containing the bootstrapping keys
    RingGswBtKey bt_key_ = {0};

    std::map<uint32_t, RingGswBtKey> bt_key_map_;

    // Whether to optimize time for sign eval
    bool time_optimization_{false};
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_CONTEXT_H_
