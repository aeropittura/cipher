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

#ifndef CIPHER_FHE_CKKS_SCHEME_SWITCHING_H_
#define CIPHER_FHE_CKKS_SCHEME_SWITCHING_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/fhe/constants.h"
#include "cipher/boolean/lwe_ciphertext.h"
#include "cipher/boolean/lwe_pke.h"
#include "cipher/fhe/config/switching_params.h"
#include "cipher/fhe/rns/fhe.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief CKKS implementation of scheme switching between CKKS and FHEW (Boolean) ciphertexts.
 *
 * Provides the setup, key generation, precomputation and evaluation of the CKKS to FHEW switching (a
 * homomorphic linear transform followed by the extraction of LWE ciphertexts), of the FHEW to CKKS switching
 * (homomorphic decryption of LWE ciphertexts inside CKKS), and of the comparison, minimum and maximum
 * operations that combine both directions. The precomputations and the FHEW cryptocontext are stored in this
 * object, one instance per CKKS cryptocontext.
 */
class CkksRnsSchemeSwitching : public RnsFhe {
    using ParmType = typename RnsPoly::Params;

  public:
    virtual ~CkksRnsSchemeSwitching() = default;

    /**
     * Clear cached CKKS/FHEW scheme-switch data held by this object.
     * Any shared object already returned to the caller stays alive until released.
     */
    void clear_scheme_switch_precom() noexcept override {
        std::vector<ReadOnlyPlaintext>().swap(u0_pre_);
        cc_lwe_.reset();
        cc_ks_.reset();
        ckks_to_fhew_swk_.reset();
        fhew_to_ckks_swk_.reset();
        ctxt_ks_.reset();
    }

    //------------------------------------------------------------------------------
    // Scheme Switching Wrappers
    //------------------------------------------------------------------------------

    LwePrivateKey eval_ckks_to_fhew_setup(const SchSwchParams& params) override;

    std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> eval_ckks_to_fhew_key_gen(const KeyPair<RnsPoly>& key_pair,
                                                                                ConstLwePrivateKey& lwesk) override;

    void eval_ckks_to_fhew_precompute(const CryptoContextImpl<RnsPoly>& cc, double scale) override;

    std::vector<std::shared_ptr<LweCiphertextImpl>> eval_ckks_to_fhew(ConstCiphertext<RnsPoly> ciphertext,
                                                                   uint32_t num_ctxts) override;

    void eval_fhew_to_ckks_setup(const CryptoContextImpl<RnsPoly>& cc_ckks, const std::shared_ptr<BooleanContext>& cc_lwe,
                             uint32_t num_slots_ckks, uint32_t log_q) override;

    std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> eval_fhew_to_ckks_key_gen(const KeyPair<RnsPoly>& key_pair,
                                                                                ConstLwePrivateKey& lwesk,
                                                                                uint32_t num_slots, uint32_t num_ctxts,
                                                                                uint32_t dim1, uint32_t L) override;

    Ciphertext<RnsPoly> eval_fhew_to_ckks(std::vector<std::shared_ptr<LweCiphertextImpl>>& lwe_ciphertexts,
                                        uint32_t num_ctxts, uint32_t num_slots, uint32_t p, double pmin, double pmax,
                                        uint32_t dim1) const override;

    LwePrivateKey eval_scheme_switching_setup(const SchSwchParams& params) override;

    std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> eval_scheme_switching_key_gen(
            const KeyPair<RnsPoly>& key_pair, ConstLwePrivateKey& lwesk) override;

    void eval_compare_switch_precompute(const CryptoContextImpl<RnsPoly>& cc_ckks, uint32_t p_lwe, double scale_sign,
                                     bool unit) override;

    Ciphertext<RnsPoly> eval_compare_scheme_switching(ConstCiphertext<RnsPoly> ciphertext1,
                                                    ConstCiphertext<RnsPoly> ciphertext2, uint32_t num_ctxts,
                                                    uint32_t num_slots, uint32_t p_lwe, double scale_sign,
                                                    bool unit) override;

    std::vector<Ciphertext<RnsPoly>> eval_min_scheme_switching(ConstCiphertext<RnsPoly> ciphertext,
                                                             PublicKey<RnsPoly> public_key, uint32_t num_values,
                                                             uint32_t num_slots, uint32_t p_lwe,
                                                             double scale_sign) override;

    std::vector<Ciphertext<RnsPoly>> eval_min_scheme_switching_alt(ConstCiphertext<RnsPoly> ciphertext,
                                                                PublicKey<RnsPoly> public_key, uint32_t num_values,
                                                                uint32_t num_slots, uint32_t p_lwe,
                                                                double scale_sign) override;

    std::vector<Ciphertext<RnsPoly>> eval_max_scheme_switching(ConstCiphertext<RnsPoly> ciphertext,
                                                             PublicKey<RnsPoly> public_key, uint32_t num_values,
                                                             uint32_t num_slots, uint32_t p_lwe,
                                                             double scale_sign) override;

    std::vector<Ciphertext<RnsPoly>> eval_max_scheme_switching_alt(ConstCiphertext<RnsPoly> ciphertext,
                                                                PublicKey<RnsPoly> public_key, uint32_t num_values,
                                                                uint32_t num_slots, uint32_t p_lwe,
                                                                double scale_sign) override;

    /**
     * Gets the FHEW (binary FHE) cryptocontext used for scheme switching.
     *
     * @return the FHEW cryptocontext
     */
    std::shared_ptr<cipher::BooleanContext> get_bin_cc_for_scheme_switch() override {
        return cc_lwe_;
    }

    /**
     * Sets the FHEW (binary FHE) cryptocontext used for scheme switching (e.g., after deserialization).
     *
     * @param cc_lwe the FHEW cryptocontext
     */
    void set_bin_cc_for_scheme_switch(std::shared_ptr<cipher::BooleanContext> cc_lwe) override {
        cc_lwe_ = cc_lwe;
    }

    /**
     * Gets the FHEW to CKKS switching key, i.e., the CKKS encryption of the FHEW secret key.
     *
     * @return the switching key
     */
    Ciphertext<RnsPoly> get_swk_fc() override {
        return fhew_to_ckks_swk_;
    }

    /**
     * Sets the FHEW to CKKS switching key, i.e., the CKKS encryption of the FHEW secret key (it is not serialized
     * with this object, so it has to be restored after deserialization).
     *
     * @param fhew_to_ckks_swk the switching key
     */
    void set_swk_fc(Ciphertext<RnsPoly> fhew_to_ckks_swk) override {
        fhew_to_ckks_swk_ = fhew_to_ckks_swk;
    }

    /**
     * Gets the number of values (LWE ciphertexts) the scheme switching was set up for.
     *
     * @return the number of ciphertexts to switch
     */
    uint32_t get_num_ctxts_to_switch() {
        return num_ctxts_;
    }

    /**
     * Gets the LWE ciphertext modulus the CKKS ciphertexts are switched to.
     *
     * @return the LWE modulus
     */
    NativeInteger get_modulus_lwe_to_switch() {
        return modulus_lwe_;
    }

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<RnsFhe>(this));
        ar(cereal::make_nvp("QLWE", modulus_lwe_));
        ar(cereal::make_nvp("QCKKS1", modulus_ckks_initial_));
        ar(cereal::make_nvp("QCKKS2", modulus_ckks_from_));
        ar(cereal::make_nvp("slots", num_slots_ckks_));
        ar(cereal::make_nvp("ctxts", num_ctxts_));
        ar(cereal::make_nvp("bCF", dim1_cf_));
        ar(cereal::make_nvp("bFC", dim1_fc_));
        ar(cereal::make_nvp("lCF", lcf_));
        ar(cereal::make_nvp("lFC", lfc_));
        ar(cereal::make_nvp("argmin", argmin_));
        ar(cereal::make_nvp("oneHot", one_hot_));
        ar(cereal::make_nvp("alt", alt_));
        ar(cereal::make_nvp("swkCF", ckks_to_fhew_swk_));
        // ar(cereal::make_nvp("swkFC", fhew_to_ckks_swk_)); // Avoid a circular issue when deserializing
        ar(cereal::make_nvp("ctKS", ctxt_ks_));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<RnsFhe>(this));
        ar(cereal::make_nvp("QLWE", modulus_lwe_));
        ar(cereal::make_nvp("QCKKS1", modulus_ckks_initial_));
        ar(cereal::make_nvp("QCKKS2", modulus_ckks_from_));
        ar(cereal::make_nvp("slots", num_slots_ckks_));
        ar(cereal::make_nvp("ctxts", num_ctxts_));
        ar(cereal::make_nvp("bCF", dim1_cf_));
        ar(cereal::make_nvp("bFC", dim1_fc_));
        ar(cereal::make_nvp("lCF", lcf_));
        ar(cereal::make_nvp("lFC", lfc_));
        ar(cereal::make_nvp("argmin", argmin_));
        ar(cereal::make_nvp("oneHot", one_hot_));
        ar(cereal::make_nvp("alt", alt_));
        ar(cereal::make_nvp("swkCF", ckks_to_fhew_swk_));
        // ar(cereal::make_nvp("swkFC", fhew_to_ckks_swk_)); // Avoid a circular issue when deserializing
        ar(cereal::make_nvp("ctKS", ctxt_ks_));
    }

    std::string serialized_object_name() const {
        return "SWITCHCKKSRNS";
    }

  private:
    std::vector<ReadOnlyPlaintext> eval_lt_precompute_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                          const std::vector<std::vector<std::complex<double>>>& A,
                                                          uint32_t dim1, uint32_t L, double scale) const;

    std::vector<ReadOnlyPlaintext> eval_lt_precompute_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                          const std::vector<std::vector<std::complex<double>>>& A,
                                                          const std::vector<std::vector<std::complex<double>>>& B,
                                                          uint32_t dim1, uint32_t L, double scale) const;

    Ciphertext<RnsPoly> eval_lt_with_precompute_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                    ConstCiphertext<RnsPoly> ctxt,
                                                    const std::vector<ReadOnlyPlaintext>& A, uint32_t dim1,
                                                    bool ext = false) const;

    Ciphertext<RnsPoly> eval_lt_rect_with_precompute_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                        const std::vector<std::vector<std::complex<double>>>& A,
                                                        ConstCiphertext<RnsPoly> ct, bool wide, uint32_t dim1,
                                                        uint32_t L) const;

    Ciphertext<RnsPoly> eval_slots_to_coeffs_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                 ConstCiphertext<RnsPoly> ciphertext) const;

    Ciphertext<RnsPoly> eval_partial_hom_decryption(const CryptoContextImpl<RnsPoly>& cc,
                                                  const std::vector<std::vector<std::complex<double>>>& A,
                                                  ConstCiphertext<RnsPoly> ct, uint32_t dim1, double scale,
                                                  uint32_t L) const;

    //------------------------------------------------------------------------------
    // Complex Plaintext Functions, copied from ckksrns-fhe. TODO: fix this
    //------------------------------------------------------------------------------

    Plaintext make_aux_plaintext(const CryptoContextImpl<RnsPoly>& cc, const std::shared_ptr<ParmType> params,
                               const std::vector<std::complex<double>>& value, size_t noise_scale_deg, uint32_t level,
                               uint32_t slots) const;

    Ciphertext<RnsPoly> eval_mult_ext(ConstCiphertext<RnsPoly> ciphertext, ConstPlaintext plaintext) const;

    void eval_add_ext_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly> ciphertext2) const;

    Ciphertext<RnsPoly> eval_add_ext(ConstCiphertext<RnsPoly> ciphertext1, ConstCiphertext<RnsPoly> ciphertext2) const;

    EvalKey<RnsPoly> conjugate_key_gen(const PrivateKey<RnsPoly> private_key) const;

    Ciphertext<RnsPoly> Conjugate(ConstCiphertext<RnsPoly> ciphertext,
                                   const std::map<uint32_t, EvalKey<RnsPoly>>& eval_keys) const;

#if CIPHER_NATIVE_INT == 128
    /**
     * Set modulus and recalculates the vector values to fit the modulus
     *
     * @param ring_dim ring dimension (number of coefficients to fit).
     * @param vec input vector
     * @param big_bound big bound of the vector values.
     * @param native_vec output native vector (its modulus is used to fit the values).
     */
    void fit_to_native_vector(uint32_t ring_dim, const std::vector<__int128>& vec, __int128 big_bound,
                           NativeVector* native_vec) const;

#else  // CIPHER_NATIVE_INT == 64
    /**
     * Set modulus and recalculates the vector values to fit the modulus
     *
     * @param ring_dim ring dimension (number of coefficients to fit).
     * @param vec input vector
     * @param big_bound big bound of the vector values.
     * @param native_vec output native vector (its modulus is used to fit the values).
     */
    void fit_to_native_vector(uint32_t ring_dim, const std::vector<int64_t>& vec, int64_t big_bound,
                           NativeVector* native_vec) const;
#endif

    //------------------------------------------------------------------------------
    // Private members
    //------------------------------------------------------------------------------

    // the associated ciphertext modulus Q for the LWE cryptocontext
    NativeInteger modulus_lwe_;
    // the target ciphertext modulus Q for the CKKS cryptocontext. We assume the switching goes to the same initial cryptocontext
    NativeInteger modulus_ckks_initial_;
    // the ciphertext modulus Q' for the CKKS cryptocontext that is secure for the LWE ring dimension
    NativeInteger modulus_ckks_from_;
    // number of slots encoded in the CKKS ciphertext
    uint32_t num_slots_ckks_;
    // number of ciphertexts to switch, different logic for argmin (i.e., it starts from number of ciphertexts / 2)
    uint32_t num_ctxts_;
    // baby-step dimensions for linear transform for CKKS->FHEW, FHEW->CKKS
    uint32_t dim1_cf_;
    uint32_t dim1_fc_;
    // starting levels for linear transforms
    uint32_t lcf_;
    uint32_t lfc_;
    // flags indicating type of argmin computation
    bool argmin_;
    bool one_hot_;
    bool alt_;
    // the LWE cryptocontext to generate when scheme switching from CKKS
    std::shared_ptr<BooleanContext> cc_lwe_;
    // the CKKS cryptocontext for the intermediate modulus switching in CKKS to FHEW
    CryptoContext<RnsPoly> cc_ks_;
    // switching key from CKKS to FHEW
    EvalKey<RnsPoly> ckks_to_fhew_swk_;
    // switching key from FHEW to CKKS
    Ciphertext<RnsPoly> fhew_to_ckks_swk_;
    // a ciphertext under the intermediate cryptocontext
    Ciphertext<RnsPoly> ctxt_ks_;
    // Precomputed matrix for CKKS to FHEW switching
    std::vector<ReadOnlyPlaintext> u0_pre_;
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_SCHEME_SWITCHING_H_
