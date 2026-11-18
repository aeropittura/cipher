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

#ifndef CIPHER_BOOLEAN_BASE_SCHEME_H_
#define CIPHER_BOOLEAN_BASE_SCHEME_H_

#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/boolean/base_params.h"
#include "cipher/boolean/lwe_pke.h"
#include "cipher/boolean/rgsw_acc_cggi.h"
#include "cipher/boolean/rgsw_acc_dm.h"
#include "cipher/boolean/rgsw_acc_lmkcdey.h"
#include "cipher/boolean/rgsw_acc.h"
#include "cipher/boolean/rgsw_acc_key.h"
#include "cipher/boolean/rgsw_acc_key32.h"
#include "cipher/boolean/rlwe_ciphertext.h"

namespace cipher {

/**
 * @brief The struct for storing bootstrapping keys
 *
 * The 32-bit members hold the internal forms generated directly by key_gen with internal32 requested, or narrowed by
 * bt_key_gen or bt_key_load. When one is set, the corresponding 64-bit member stays null (or is released) and the
 * 32-bit copy is the only resident one, so the key material is half size.
 */
struct RingGswBtKey {
    RingGswAccKey b_skey;    ///< refreshing key (64-bit form)
    LweSwitchingKey ks_key;  ///< switching key (64-bit form)
    LwePublicKey pkey;      ///< public key
#if CIPHER_NATIVE_INT != 32
    RingGswAccKey32 b_skey32;    ///< refreshing key in the 32-bit internal form, null when b_skey is resident
    LweSwitchingKey32 ks_key32;  ///< switching key in the 32-bit internal form, null when ks_key is resident
#endif

    /**
     * Checks whether a refreshing key is present in either representation
     *
     * @return true if the 64-bit or the 32-bit refreshing key is set
     */
    bool has_refresh_key() const {
#if CIPHER_NATIVE_INT != 32
        return (b_skey != nullptr) || (b_skey32 != nullptr);
#else
        return b_skey != nullptr;
#endif
    }

    // Each key is written in whichever width the context holds it at, and the null members say
    // which that was, so the archive needs no separate discriminator.
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("bs", b_skey));
        ar(::cereal::make_nvp("ks", ks_key));
        ar(::cereal::make_nvp("pk", pkey));
#if CIPHER_NATIVE_INT != 32
        ar(::cereal::make_nvp("bs32", b_skey32));
        ar(::cereal::make_nvp("ks32", ks_key32));
#endif
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("bs", b_skey));
        ar(::cereal::make_nvp("ks", ks_key));
        ar(::cereal::make_nvp("pk", pkey));
#if CIPHER_NATIVE_INT != 32
        ar(::cereal::make_nvp("bs32", b_skey32));
        ar(::cereal::make_nvp("ks32", ks_key32));
#endif
    }

    std::string serialized_object_name() const {
        return "RingGSWBTKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }
};

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class BooleanScheme {
  public:
    BooleanScheme() = default;

    /**
     * Constructs the scheme for a bootstrapping method, instantiating the matching accumulator (DM for AP, CGGI for
     * GINX, and LMKCDEY)
     *
     * @param method the bootstrapping method; any other value throws
     */
    explicit BooleanScheme(BINFHE_METHOD method) {
        if (method == AP)
            acc_scheme = std::make_shared<RingGswAccumulatorDm>();
        else if (method == GINX)
            acc_scheme = std::make_shared<RingGswAccumulatorCggi>();
        else if (method == LMKCDEY)
            acc_scheme = std::make_shared<RingGswAccumulatorLmkcdey>();
        else
            CIPHER_THROW("method is invalid");
    }

    /**
     * Generates a refresh key
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param LWE_sk a shared pointer to the secret key of the underlying additive
     * @param keygen_mode enum to indicate generation of secret key only (SYM_ENCRYPT) or
     * secret key, public key pair (PUB_ENCRYPT)
     * @param internal32 generate the keys directly in their 32-bit internal form where they qualify;
     * a key whose moduli do not fit is generated in the 64-bit form instead
     * @return a shared pointer to the refresh key
     */
    RingGswBtKey key_gen(const std::shared_ptr<BooleanCryptoParams>& params, ConstLwePrivateKey& LWE_sk,
                        KEYGEN_MODE keygen_mode, bool internal32) const;

    /**
     * Evaluates a binary gate (calls bootstrapping as a subroutine)
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct1 first ciphertext
     * @param ct2 second ciphertext
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_bin_gate(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate, const RingGswBtKey& EK,
                              ConstLweCiphertext& ct1, ConstLweCiphertext& ct2, bool extended = false) const;

    /**
     * Evaluates a binary gate on a vector of ciphertexts (calls bootstrapping as a subroutine).
     * The evaluation of the gates in this function is specific to 3 input and 4 input
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param gate the gate; can be for 3-input: AND3, OR3, MAJORITY, CMUX, for 4-input: AND4, OR4
     * @param EK a shared pointer to the bootstrapping keys
     * @param ctvector vector of ciphertexts
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_bin_gate(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate, const RingGswBtKey& EK,
                              const std::vector<LweCiphertext>& ctvector, bool extended = false) const;

    /**
     * Evaluates NOT gate
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ct the input ciphertext
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_not(const std::shared_ptr<BooleanCryptoParams>& params, ConstLweCiphertext& ct) const;

    /**
     * Bootstraps a fresh ciphertext
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param extended if true, the result is returned before key switching (modulus Q, dimension N)
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext bootstrap(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                            ConstLweCiphertext& ct, bool extended = false) const;

    /**
     * Evaluate an arbitrary function
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param LUT the look-up table of the to-be-evaluated function
     * @param beta the error bound
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_func(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                           ConstLweCiphertext& ct, const std::vector<NativeInteger>& LUT, NativeInteger beta) const;

    /**
     * Evaluate a round down function
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param beta the error bound
     * @param roundbits by how many bits to round down
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_floor(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                            ConstLweCiphertext& ct, NativeInteger beta, uint32_t roundbits = 0) const;

    /**
     * Evaluate a sign function over large precision
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param e_ks a shared pointer to the bootstrapping keys map
     * @param ct input ciphertext
     * @param beta the error bound
     * @param scheme_switch flag that indicates if it should be compatible to scheme switching
     * @return a shared pointer to the resulting ciphertext
     */
    LweCiphertext eval_sign(const std::shared_ptr<BooleanCryptoParams>& params,
                           const std::map<uint32_t, RingGswBtKey>& e_ks, ConstLweCiphertext& ct, NativeInteger beta,
                           bool scheme_switch = false) const;

    /**
     * Evaluate digit decomposition over a large precision LWE ciphertext
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param e_ks a shared pointer to the bootstrapping keys map
     * @param ct input ciphertext
     * @param beta the error bound
     * @return a shared pointer to the resulting ciphertext
     */
    std::vector<LweCiphertext> eval_decomp(const std::shared_ptr<BooleanCryptoParams>& params,
                                          const std::map<uint32_t, RingGswBtKey>& e_ks, ConstLweCiphertext& ct,
                                          NativeInteger beta) const;

  private:
    /**
     * Core bootstrapping operation
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @return the output RingLWE accumulator
     */
    RlweCiphertext bootstrap_gate_core(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate,
                                     const RingGswBtKey& EK, ConstLweCiphertext& ct) const;

    // Arbitrary function evaluation purposes

    /**
     * Core bootstrapping operation
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param f function to evaluate in the functional bootstrapping
     * @param fmod modulus over which the function is defined
     * @return the output RingLWE accumulator
     */
    template <typename Func>
    RlweCiphertext bootstrap_func_core(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                     ConstLweCiphertext& ct, const Func f, NativeInteger fmod) const;

    /**
     * Bootstraps a ciphertext while evaluating a function on it (functional bootstrapping)
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param f function to evaluate in the functional bootstrapping
     * @param fmod modulus over which the function is defined
     * @return a shared pointer to the resulting ciphertext
     */
    template <typename Func>
    LweCiphertext bootstrap_func(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                ConstLweCiphertext& ct, const Func f, NativeInteger fmod) const;

    // dispatch to the key representation EK actually holds
    LweCiphertext switch_c_ttoqn(const std::shared_ptr<LweCryptoParams>& params, const RingGswBtKey& EK,
                               ConstLweCiphertext& ct) const;

    LweCiphertext key_switch(const std::shared_ptr<LweCryptoParams>& params, const RingGswBtKey& EK,
                            ConstLweCiphertext& ct) const;

  protected:
    std::shared_ptr<LweEncryptionScheme> lwe_scheme{std::make_shared<LweEncryptionScheme>()};  ///< the LWE scheme
    std::shared_ptr<RingGswAccumulator> acc_scheme{nullptr};  ///< the accumulator selected by the bootstrapping method

    /**
     * Checks type of input function
     *
     * @param lut look up table for the input function
     * @param mod modulus over which the function is defined
     * @return the function type: 0 for negacyclic, 1 for periodic, 2 for arbitrary
     */
    static uint32_t check_input_function(const std::vector<NativeInteger>& lut, NativeInteger mod_value) {
        size_t mid{lut.size() / 2};
        if (lut[0] == (mod_value - lut[mid])) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != (mod_value - lut[mid + i]))
                    return 2;
            return 0;
        }
        if (lut[0] == lut[mid]) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != lut[mid + i])
                    return 2;
            return 1;
        }
        return 2;
    }
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_BASE_SCHEME_H_
