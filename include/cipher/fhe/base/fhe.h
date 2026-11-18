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

#ifndef CIPHER_FHE_BASE_FHE_H_
#define CIPHER_FHE_BASE_FHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/context_fwd.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/fhe/key/private_key_fwd.h"
#include "cipher/fhe/config/switching_params.h"
#include "cipher/util/exception.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Abstract interface class for LBC FHE (bootstrapping and scheme switching) algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class BaseFhe {
    // TODO: should we use just one error message instead of a few (see below)
    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_ERROR = "Not supported for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_SIMPLE_ERROR = "Not supported";

  public:
    virtual ~BaseFhe() = default;

    /**
     * Clear scheme-level bootstrap precomputations, if this FHE component
     * caches any. The default implementation is a no-op.
     */
    virtual void clear_bootstrap_precom() noexcept {}

    /**
     * Clear scheme-switch precomputations, if this FHE component owns any.
     * The default implementation is a no-op.
     */
    virtual void clear_scheme_switch_precom() noexcept {}

    /**
     * Bootstrap functionality:
     * There are three methods that have to be called in this specific order:
     * 1. eval_bootstrap_setup: computes and encodes the coefficients for encoding and
     * decoding and stores the necessary parameters
     * 2. eval_bootstrap_key_gen: computes and stores the keys for rotations and conjugation
     * 3. eval_bootstrap: refreshes the given ciphertext
     */

    /**
     * Sets all parameters for both the linear and the FFT-like bootstrapping methods
     *
     * @param cc the crypto context the bootstrapping parameters are set up for
     * @param level_budget - vector of budgets for the amount of levels in encoding
     * and decoding
     * @param dim1 - vector of inner dimension in the baby-step giant-step routine
     * for encoding and decoding
     * @param slots - number of slots to be bootstrapped
     * @param correction_factor - value to rescale message by to improve precision. If set to 0, we use the default
     * logic. This value is only used when NATIVE_SIZE=64
     * @param precompute - flag specifying whether to precompute the plaintexts for encoding and decoding.
     * @param bt_slots_encoding - flag specifying whether the approximate modular reduction happens over the message
     * being in slots or coefficients.
     */
    virtual void eval_bootstrap_setup(const CryptoContextImpl<Element>& cc, std::vector<uint32_t> level_budget,
                                    std::vector<uint32_t> dim1, uint32_t slots, uint32_t correction_factor,
                                    bool precompute, bool bt_slots_encoding) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Virtual function to define the generation of all automorphism keys for EvalBT (with FFT evaluation).
     * EvalBTKeyGen uses the baby-step/giant-step strategy.
     *
     * @param private_key private key.
     * @param slots - number of slots to be bootstrapped
     * @return the map of generated evaluation keys.
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_bootstrap_key_gen(
            const PrivateKey<Element> private_key, uint32_t slots) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Returns the eval-key map indices required to serialize bootstrap keys.
     *
     * @param cc crypto context.
     * @param slots - number of slots to be bootstrapped
     * @return the list of eval-key map indices.
     */
    virtual std::vector<uint32_t> eval_bootstrap_key_map_indices(const CryptoContext<Element>& cc, uint32_t slots) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Computes the plaintexts for encoding and decoding for both linear and FFT-like methods. Supported in CKKS only.
     *
     * @param cc the crypto context the precomputation is done for
     * @param slots - number of slots to be bootstrapped
     */
    virtual void eval_bootstrap_precompute(const CryptoContextImpl<Element>& cc, uint32_t slots) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Defines the bootstrapping evaluation of ciphertext
     *
     * The flavor of bootstrapping that uses the num_iterations and precision parameters is described
     * in the Meta-BTS paper.
     * Source: Bae Y., Cheon J., Cho W., Kim J., and Kim T. META-BTS: Bootstrapping Precision
     * Beyond the Limit. Cryptology ePrint Archive, Report
     * 2022/1167. (https://eprint.iacr.org/2022/1167.pdf)
     *
     * @param ciphertext the input ciphertext.
     * @param num_iterations number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations
     * increases the precision of bootstrapping.
     * @param precision precision of initial bootstrapping algorithm. This value is
     * determined by the user experimentally by first running eval_bootstrap with num_iterations = 1 and
     * precision = 0 (unused).
     * @return the refreshed ciphertext.
     */
    virtual Ciphertext<Element> eval_bootstrap(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations,
                                              uint32_t precision) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Bootstrapping variant that runs SlotsToCoeffs first and then the modulus raise, CoeffsToSlots and
     * the approximate modular reduction, so that the modular reduction is applied to the message as encoded
     * in the slots rather than in the coefficients (the bt_slots_encoding mode of eval_bootstrap_setup).
     * eval_bootstrap dispatches here when the precomputation was set up with bt_slots_encoding = true.
     * Supported in CKKS only.
     *
     * @param ciphertext the input ciphertext.
     * @param num_iterations number of iterations to run iterative bootstrapping (Meta-BTS); 1 or 2.
     * @param precision precision of the initial bootstrapping algorithm (used only when num_iterations = 2).
     * @return the refreshed ciphertext.
     */
    virtual Ciphertext<Element> eval_bootstrap_st_c_first(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations,
                                                      uint32_t precision) const {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Precomputes the encoding/decoding plaintexts for FE (Fourier extension) functional bootstrapping.
     * Supported only in CKKS, with HYBRID key switching. Shares the bootstrapping precomputation slot
     * for \p num_slots with eval_bootstrap_setup and eval_fbt_setup.
     *
     * @param cc the crypto context the precomputation is done for.
     * @param level_budget levels spent on CoeffsToSlots and SlotsToCoeffs.
     * @param dim1 baby-step dimensions for the two linear transforms (0 = choose automatically).
     * @param num_slots number of slots to be bootstrapped (0 = full packing).
     */
    virtual void eval_fe_func_bootstrap_setup(const CryptoContextImpl<RnsPoly>& cc,
                                          const std::vector<uint32_t>& level_budget, const std::vector<uint32_t>& dim1,
                                          uint32_t num_slots) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Refreshes a ciphertext and evaluates a function on it in one pass, by evaluating the Fourier
     * extension of the function over the bootstrapped message. The input slot values must lie in
     * [-1/2, 1/2) and the result is real-valued. Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext, with slot values in [-1/2, 1/2).
     * @param coefficients Fourier coefficients c_j of the target function, c_0 first.
     * @return the refreshed ciphertext holding the function values.
     */
    virtual Ciphertext<Element> eval_fe_func_bootstrap(ConstCiphertext<Element>& ciphertext,
                                                    const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Runs the function-independent part of FE functional bootstrapping (SlotsToCoeffs, modulus raise,
     * CoeffsToSlots and the complex exponential) and returns the powers of the complex exponential, so
     * that several functions can be evaluated on one bootstrapped ciphertext with
     * eval_fe_func_bootstrap_with_precomp. Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext, with slot values in [-1/2, 1/2).
     * @param coefficients Fourier coefficients of the longest series to be evaluated, c_0 first; they fix
     * the Paterson-Stockmeyer shape and thus the maximum degree of the series evaluated later.
     * @return the powers of the complex exponential.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_fe_func_bootstrap_precompute(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Evaluates the Fourier series of one function against the powers returned by
     * eval_fe_func_bootstrap_precompute. Supported only in CKKS.
     *
     * @param powers the powers returned by eval_fe_func_bootstrap_precompute.
     * @param coefficients Fourier coefficients c_j of this function, c_0 first.
     * @return the refreshed ciphertext holding the function values.
     */
    virtual Ciphertext<Element> eval_fe_func_bootstrap_with_precomp(
            const std::shared_ptr<SeriesPowers<Element>>& powers,
            const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Sets up CKKS functional bootstrapping of an RLWE ciphertext with plaintext modulus p_in that was
     * converted to a CKKS ciphertext (SchemeletRlweMp::convert_rlwe_to_ckks): precomputes the homomorphic
     * encoding/decoding (CoeffsToSlots/SlotsToCoeffs) plaintexts for num_slots slots, including the
     * scalings needed to interpret the input and produce the output modulus. This overload takes
     * complex interpolation coefficients. Supported only in CKKS with HYBRID key switching.
     *
     * @param cc the crypto context the precomputation is done for.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function to evaluate
     * (from get_hermite_trig_coefficients, or [f(1), f(0)-f(1)] for a first-order Boolean function);
     * they determine the depth of the bootstrapping.
     * @param num_slots number of slots (0 = full packing).
     * @param p_in plaintext modulus of the input RLWE ciphertext.
     * @param P_out plaintext modulus of the output.
     * @param Bigq ciphertext modulus of the input RLWE ciphertext.
     * @param pub_key public key of the CKKS crypto context (its element parameters are used).
     * @param dim1 baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = choose automatically).
     * @param level_budget levels spent on CoeffsToSlots and SlotsToCoeffs.
     * @param lvls_after_boot number of levels that remain available after bootstrapping.
     * @param depth_leveled_computation depth of the leveled computation applied between
     * eval_fbt_no_decoding (or eval_mvb_no_decoding) and eval_hom_decoding.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     */
    virtual void eval_fbt_setup(const CryptoContextImpl<Element>& cc, const std::vector<std::complex<double>>& coeffs,
                              uint32_t num_slots, const BigInteger& p_in, const BigInteger& P_out, const BigInteger& bigq,
                              const PublicKey<RnsPoly>& pub_key, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& level_budget, uint32_t lvls_after_boot = 0,
                              uint32_t depth_leveled_computation = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Sets up CKKS functional bootstrapping of an RLWE ciphertext with plaintext modulus p_in that was
     * converted to a CKKS ciphertext (SchemeletRlweMp::convert_rlwe_to_ckks): precomputes the homomorphic
     * encoding/decoding (CoeffsToSlots/SlotsToCoeffs) plaintexts for num_slots slots, including the
     * scalings needed to interpret the input and produce the output modulus. This overload takes
     * integer interpolation coefficients. Supported only in CKKS with HYBRID key switching.
     *
     * @param cc the crypto context the precomputation is done for.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function to evaluate
     * (from get_hermite_trig_coefficients, or [f(1), f(0)-f(1)] for a first-order Boolean function);
     * they determine the depth of the bootstrapping.
     * @param num_slots number of slots (0 = full packing).
     * @param p_in plaintext modulus of the input RLWE ciphertext.
     * @param P_out plaintext modulus of the output.
     * @param Bigq ciphertext modulus of the input RLWE ciphertext.
     * @param pub_key public key of the CKKS crypto context (its element parameters are used).
     * @param dim1 baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = choose automatically).
     * @param level_budget levels spent on CoeffsToSlots and SlotsToCoeffs.
     * @param lvls_after_boot number of levels that remain available after bootstrapping.
     * @param depth_leveled_computation depth of the leveled computation applied between
     * eval_fbt_no_decoding (or eval_mvb_no_decoding) and eval_hom_decoding.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     */
    virtual void eval_fbt_setup(const CryptoContextImpl<Element>& cc, const std::vector<int64_t>& coeffs,
                              uint32_t num_slots, const BigInteger& p_in, const BigInteger& P_out, const BigInteger& bigq,
                              const PublicKey<RnsPoly>& pub_key, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& level_budget, uint32_t lvls_after_boot = 0,
                              uint32_t depth_leveled_computation = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Functional bootstrapping of a CKKS ciphertext obtained from an RLWE ciphertext with complex interpolation
     * coefficients: modulus raise, CoeffsToSlots, complex exponential and its powers, evaluation of the
     * trigonometric Hermite interpolation of the function, SlotsToCoeffs and the final scalings.
     * Supported only in CKKS; requires eval_fbt_setup.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param post_scaling integer the result is multiplied by after decoding (typically the scale by
     * which the Hermite coefficients were divided).
     * @param level_to_reduce number of levels to drop before SlotsToCoeffs.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext encrypting the function values in its coefficients.
     */
    virtual Ciphertext<Element> eval_fbt(ConstCiphertext<RnsPoly>& ciphertext,
                                        const std::vector<std::complex<double>>& coeffs, uint32_t digit_bit_size,
                                        const BigInteger& initial_scaling, uint64_t post_scaling,
                                        uint32_t level_to_reduce = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Functional bootstrapping of a CKKS ciphertext obtained from an RLWE ciphertext with integer interpolation
     * coefficients: modulus raise, CoeffsToSlots, complex exponential and its powers, evaluation of the
     * trigonometric Hermite interpolation of the function, SlotsToCoeffs and the final scalings.
     * Supported only in CKKS; requires eval_fbt_setup.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param post_scaling integer the result is multiplied by after decoding (typically the scale by
     * which the Hermite coefficients were divided).
     * @param level_to_reduce number of levels to drop before SlotsToCoeffs.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext encrypting the function values in its coefficients.
     */
    virtual Ciphertext<Element> eval_fbt(ConstCiphertext<RnsPoly>& ciphertext, const std::vector<int64_t>& coeffs,
                                        uint32_t digit_bit_size, const BigInteger& initial_scaling, uint64_t post_scaling,
                                        uint32_t level_to_reduce = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Functional bootstrapping with complex interpolation coefficients that stops before SlotsToCoeffs: the
     * function values are left in the slots (bit-reversed if several levels are used for encoding) so that
     * a leveled computation can be applied before eval_hom_decoding. Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext with the function values in its slots.
     */
    virtual Ciphertext<Element> eval_fbt_no_decoding(ConstCiphertext<RnsPoly>& ciphertext,
                                                  const std::vector<std::complex<double>>& coeffs,
                                                  uint32_t digit_bit_size, const BigInteger& initial_scaling,
                                                  size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Functional bootstrapping with integer interpolation coefficients that stops before SlotsToCoeffs: the
     * function values are left in the slots (bit-reversed if several levels are used for encoding) so that
     * a leveled computation can be applied before eval_hom_decoding. Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext with the function values in its slots.
     */
    virtual Ciphertext<Element> eval_fbt_no_decoding(ConstCiphertext<RnsPoly>& ciphertext,
                                                  const std::vector<int64_t>& coeffs, uint32_t digit_bit_size,
                                                  const BigInteger& initial_scaling, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Homomorphic decoding step of functional bootstrapping: drops \p level_to_reduce levels if requested,
     * applies SlotsToCoeffs, multiplies by \p post_scaling and rescales to noise scale degree 1, producing
     * a ciphertext with the values in its coefficients (the RLWE convention). Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext with the values in its slots.
     * @param post_scaling integer the result is multiplied by after decoding (typically the scale by
     * which the Hermite coefficients were divided).
     * @param level_to_reduce number of levels to drop before SlotsToCoeffs.
     * @return the ciphertext encrypting the values in its coefficients.
     */
    virtual Ciphertext<Element> eval_hom_decoding(ConstCiphertext<RnsPoly>& ciphertext, uint64_t post_scaling,
                                                uint32_t level_to_reduce = 0) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Function-independent part of multi-value functional bootstrapping with complex interpolation coefficients:
     * modulus raise, CoeffsToSlots, complex exponential and its powers, which are shared by all functions
     * later evaluated with eval_mvb or eval_mvb_no_decoding. Those functions must be interpolated with the same
     * shape (plaintext modulus and order; for degree < 5 also the same sparsity) as \p coeffs.
     * Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients fixing the shape of the series.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the powers of the complex exponential.
     */
    virtual std::shared_ptr<SeriesPowers<RnsPoly>> eval_mvb_precompute(ConstCiphertext<RnsPoly>& ciphertext,
                                                                      const std::vector<std::complex<double>>& coeffs,
                                                                      uint32_t digit_bit_size,
                                                                      const BigInteger& initial_scaling,
                                                                      size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Function-independent part of multi-value functional bootstrapping with integer interpolation coefficients:
     * modulus raise, CoeffsToSlots, complex exponential and its powers, which are shared by all functions
     * later evaluated with eval_mvb or eval_mvb_no_decoding. Those functions must be interpolated with the same
     * shape (plaintext modulus and order; for degree < 5 also the same sparsity) as \p coeffs.
     * Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext (from SchemeletRlweMp::convert_rlwe_to_ckks).
     * @param coeffs trigonometric Hermite interpolation coefficients fixing the shape of the series.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param initial_scaling scaling at which the input coefficients are given (the modulus of the
     * imported RLWE ciphertext).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the powers of the complex exponential.
     */
    virtual std::shared_ptr<SeriesPowers<RnsPoly>> eval_mvb_precompute(ConstCiphertext<RnsPoly>& ciphertext,
                                                                      const std::vector<int64_t>& coeffs,
                                                                      uint32_t digit_bit_size,
                                                                      const BigInteger& initial_scaling,
                                                                      size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Evaluates one function with complex interpolation coefficients on the powers of the complex exponential
     * returned by eval_mvb_precompute and applies the homomorphic decoding (eval_hom_decoding).
     * Supported only in CKKS.
     *
     * @param ciphertexts the powers of the complex exponential returned by eval_mvb_precompute.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param post_scaling integer the result is multiplied by after decoding (typically the scale by
     * which the Hermite coefficients were divided).
     * @param level_to_reduce number of levels to drop before SlotsToCoeffs.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext encrypting the function values in its coefficients.
     */
    virtual Ciphertext<Element> eval_mvb(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                        const std::vector<std::complex<double>>& coeffs, uint32_t digit_bit_size,
                                        const uint64_t post_scaling, uint32_t level_to_reduce = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Evaluates one function with integer interpolation coefficients on the powers of the complex exponential
     * returned by eval_mvb_precompute and applies the homomorphic decoding (eval_hom_decoding).
     * Supported only in CKKS.
     *
     * @param ciphertexts the powers of the complex exponential returned by eval_mvb_precompute.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param post_scaling integer the result is multiplied by after decoding (typically the scale by
     * which the Hermite coefficients were divided).
     * @param level_to_reduce number of levels to drop before SlotsToCoeffs.
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext encrypting the function values in its coefficients.
     */
    virtual Ciphertext<Element> eval_mvb(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                        const std::vector<int64_t>& coeffs, uint32_t digit_bit_size,
                                        const uint64_t post_scaling, uint32_t level_to_reduce = 0, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Evaluates one function with complex interpolation coefficients on the powers of the complex exponential
     * returned by eval_mvb_precompute, leaving the function values in the slots for a leveled computation
     * before eval_hom_decoding. Supported only in CKKS.
     *
     * @param ciphertexts the powers of the complex exponential returned by eval_mvb_precompute.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext with the function values in its slots.
     */
    virtual Ciphertext<Element> eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                                  const std::vector<std::complex<double>>& coeffs,
                                                  uint32_t digit_bit_size, size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Evaluates one function with integer interpolation coefficients on the powers of the complex exponential
     * returned by eval_mvb_precompute, leaving the function values in the slots for a leveled computation
     * before eval_hom_decoding. Supported only in CKKS.
     *
     * @param ciphertexts the powers of the complex exponential returned by eval_mvb_precompute.
     * @param coeffs trigonometric Hermite interpolation coefficients of the function.
     * @param digit_bit_size bit size of the input plaintext modulus (or of the digit being processed in
     * chained multi-precision evaluation).
     * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return the ciphertext with the function values in its slots.
     */
    virtual Ciphertext<Element> eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<RnsPoly>> ciphertexts,
                                                  const std::vector<int64_t>& coeffs, uint32_t digit_bit_size,
                                                  size_t order = 1) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Evaluates a trigonometric Hermite interpolation with complex coefficients: approximates exp(i*Pi*x/2) on
     * [a,b] with the Chebyshev series \p coefficients_cheb, squares twice (double-angle) to obtain
     * exp(2*Pi*i*x), evaluates the power series \p coefficients_herm in it and takes the real part.
     * Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext.
     * @param coefficients_cheb Chebyshev coefficients of exp(i*Pi*x/2) on [a,b].
     * @param a lower bound of the argument for which the Chebyshev coefficients were found.
     * @param b upper bound of the argument for which the Chebyshev coefficients were found.
     * @param coefficients_herm coefficients of the Hermite power series in exp(2*Pi*i*x) (divided by 2).
     * @param precomp reuse of the complex exponential cached in the bootstrapping precomputation: 0 or 1
     * compute it and store it in the first or second cache entry; 2 reuses the first entry and any other
     * value reuses the second entry without recomputing it.
     * @return the result of the evaluation.
     */
    virtual Ciphertext<RnsPoly> eval_hermite_trig_series(ConstCiphertext<RnsPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficients_cheb,
                                                       double a, double b,
                                                       const std::vector<std::complex<double>>& coefficients_herm,
                                                       size_t precomp = 0) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
     * Evaluates a trigonometric Hermite interpolation with integer coefficients: approximates exp(i*Pi*x/2) on
     * [a,b] with the Chebyshev series \p coefficients_cheb, squares twice (double-angle) to obtain
     * exp(2*Pi*i*x), evaluates the power series \p coefficients_herm in it and takes the real part.
     * Supported only in CKKS.
     *
     * @param ciphertext the input ciphertext.
     * @param coefficients_cheb Chebyshev coefficients of exp(i*Pi*x/2) on [a,b].
     * @param a lower bound of the argument for which the Chebyshev coefficients were found.
     * @param b upper bound of the argument for which the Chebyshev coefficients were found.
     * @param coefficients_herm coefficients of the Hermite power series in exp(2*Pi*i*x) (divided by 2).
     * @param precomp reuse of the complex exponential cached in the bootstrapping precomputation: 0 or 1
     * compute it and store it in the first or second cache entry; 2 reuses the first entry and any other
     * value reuses the second entry without recomputing it.
     * @return the result of the evaluation.
     */
    virtual Ciphertext<RnsPoly> eval_hermite_trig_series(ConstCiphertext<RnsPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficients_cheb,
                                                       double a, double b, const std::vector<int64_t>& coefficients_herm,
                                                       size_t precomp = 0) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Returns the correction factor by which the message is scaled during CKKS bootstrapping to improve
     * precision (see eval_bootstrap_setup).
     *
     * @return the correction factor.
     */
    virtual uint32_t get_ckks_boot_correction_factor() const {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Sets the correction factor by which the message is scaled during CKKS bootstrapping to improve
     * precision (see eval_bootstrap_setup).
     *
     * @param cf the correction factor.
     */
    virtual void set_ckks_boot_correction_factor(uint32_t cf) {
        CIPHER_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
     * Sets all parameters for switching from CKKS to FHEW
     *
     * @param params object holding all necessary parameters
     * @return the FHEW secret key
     */
    virtual LwePrivateKey eval_ckks_to_fhew_setup(const SchSwchParams& params) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Virtual function to define the generation of all keys for scheme switching between CKKS and FHEW:
     * the rotation keys for the baby-step/giant-step strategy,
     * conjugation keys, switching key from CKKS to FHEW
     * @param key_pair CKKS key pair
     * @param lwesk FHEW secret key
     * @return the map of generated automorphism keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_ckks_to_fhew_key_gen(const KeyPair<Element>& key_pair,
                                                                                       ConstLwePrivateKey& lwesk) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than eval_ckks_to_fhew_setup
     * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
     *
     * @param cc the CKKS cryptocontext from which to switch
     * @param scale factor with which to scale the matrix in the linear transform
     */
    virtual void eval_ckks_to_fhew_precompute(const CryptoContextImpl<Element>& cc, double scale) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Performs the scheme switching on a CKKS ciphertext
     * @param ciphertext CKKS ciphertext to switch
     * @param num_ctxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to
     * number of slots
     * @return a vector of LWE ciphertexts of length the num_ctxts
     */
    virtual std::vector<std::shared_ptr<LweCiphertextImpl>> eval_ckks_to_fhew(ConstCiphertext<Element> ciphertext,
                                                                           uint32_t num_ctxts) {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Sets all parameters for switching from FHEW to CKKS. The CKKS cryptocontext to switch to is
     * already generated.
     *
     * @param cc_ckks the CKKS cryptocontext to switch to
     * @param cc_lwe the FHEW cryptocontext from which to switch
     * @param num_slots_ckks number of FHEW ciphertexts that becomes the number of slots in CKKS encryption
     * @param log_q the logarithm of a ciphertext modulus in FHEW
     */
    virtual void eval_fhew_to_ckks_setup(const CryptoContextImpl<Element>& cc_ckks,
                                     const std::shared_ptr<BooleanContext>& cc_lwe, uint32_t num_slots_ckks,
                                     uint32_t log_q) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
     * in the linear transform for the partial decryption, the switching key from FHEW to CKKS
     *
     * @param key_pair CKKS key pair
     * @param lwesk FHEW secret key
     * @param num_slots number of slots for the CKKS encryption of the FHEW secret key
     * @param num_ctxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
     * @param dim1 baby-step for the linear transform
     * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the
     * last level
     * @return the map of generated automorphism keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_fhew_to_ckks_key_gen(
            const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk, uint32_t num_slots = 0, uint32_t num_ctxts = 0,
            uint32_t dim1 = 0, uint32_t L = 0) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than
     * eval_scheme_switching_setup
     * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
     *
     * @param cc_ckks the CKKS cryptocontext from which to switch
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
     * the resulting FHEW ciphertexts will encrypt values modulo p_lwe, so scale_sign should account for this
     * @param unit whether the input messages are normalized to the unit circle
     */
    virtual void eval_compare_switch_precompute(const CryptoContextImpl<Element>& cc_ckks, uint32_t p_lwe, double scale_sign,
                                             bool unit) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Performs the scheme switching on a vector of FHEW ciphertexts
     *
     * @param lwe_ciphertexts FHEW/LWE ciphertexts to switch
     * @param num_ctxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
     * @param num_slots number of slots to encode in the new CKKS/RLWE ciphertext
     * @param p plaintext modulus to use to decide postscaling, by default p = 4
     * @param pmin lower bound of the plaintext space of the resulting messages (by default 0, assuming
     * the LWE ciphertext had plaintext modulus p = 4 and only bits were encrypted)
     * @param pmax upper bound of the plaintext space of the resulting messages (by default 2)
     * @param dim1 baby-step for the linear transform, necessary only for argmin
     * @return a CKKS ciphertext encrypting in its slots the messages in the LWE ciphertexts
     */
    virtual Ciphertext<Element> eval_fhew_to_ckks(std::vector<std::shared_ptr<LweCiphertextImpl>>& lwe_ciphertexts,
                                               uint32_t num_ctxts, uint32_t num_slots, uint32_t p, double pmin,
                                               double pmax, uint32_t dim1) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Sets all parameters for switching from CKKS to FHEW and back
     *
     * @param params object holding all necessary parameters
     * @return the FHEW secret key
     * TODO: add an overload for when BooleanContext is already generated and fed as a parameter
     */
    virtual LwePrivateKey eval_scheme_switching_setup(const SchSwchParams& params) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
     * in the linear transform for the homomorphic encoding and partial decryption, the switching key from
     * FHEW to CKKS
     *
     * @param key_pair CKKS key pair
     * @param lwesk FHEW secret key
     * @return the map of generated automorphism keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_scheme_switching_key_gen(
            const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Performs the scheme switching on the difference of two CKKS ciphertexts to compare, evaluates the sign function
     * over the resulting FHEW ciphertexts, then performs the scheme switching back to a CKKS ciphertext
     *
     * @param ciphertext1 first CKKS ciphertext of messages that need to be compared
     * @param ciphertext2 second CKKS ciphertext of messages that need to be compared
     * @param num_ctxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to
     * number of slots
     * @param num_slots number of slots to encode the new CKKS ciphertext with
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts. If it is zero, it defaults to the
     * large precision
     * plaintext modulus Q/2beta
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
     * the resulting FHEW ciphertexts will encrypt values modulo p_lwe, so scale_sign should account for this
     * @param unit whether the input messages are normalized to the unit circle
     * @return a CKKS ciphertext encrypting in its slots the sign of  messages in the LWE ciphertexts
     */
    virtual Ciphertext<Element> eval_compare_scheme_switching(ConstCiphertext<Element> ciphertext1,
                                                           ConstCiphertext<Element> ciphertext2, uint32_t num_ctxts,
                                                           uint32_t num_slots, uint32_t p_lwe, double scale_sign,
                                                           bool unit) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the minimum and argument of the first num_values packed in a CKKS ciphertext via repeated
     * scheme switchings to FHEW and back.
     *
     * @param ciphertext CKKS ciphertexts of values that need to be compared
     * @param public_key public key of the CKKS cryptocontext
     * @param num_values number of values to extract from the CKKS ciphertext. We always assume for the moment
     * num_values is a power of two
     * @param num_slots number of slots to encode the new CKKS ciphertext with
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
     * the resulting FHEW ciphertexts will encrypt values modulo p_lwe, so scale_sign should account for this
     * p_lwe and scale_sign are given here only if the homomorphic decoding matrix is not scaled with the desired values
     * @return a vector of two CKKS ciphertexts where the first encrypts the minimum value and the second encrypts the
     * index (in the representation specified by one_hot). The ciphertexts have junk after the first slot in the
     * first ciphertext
     * and after num_values in the second ciphertext if one_hot=true and after the first slot if one_hot=false.
     */
    virtual std::vector<Ciphertext<Element>> eval_min_scheme_switching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> public_key, uint32_t num_values,
                                                                    uint32_t num_slots, uint32_t p_lwe,
                                                                    double scale_sign) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the minimum and argument of the first num_values packed in a CKKS ciphertext.
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
     *
     * @param ciphertext CKKS ciphertext of values that need to be compared
     * @param public_key public key of the CKKS cryptocontext
     * @param num_values number of values to extract from the CKKS ciphertext
     * @param num_slots number of slots to encode the new CKKS ciphertext with
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW
     * @return a vector of two CKKS ciphertexts: [min, argmin]
     */
    virtual std::vector<Ciphertext<Element>> eval_min_scheme_switching_alt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> public_key, uint32_t num_values,
                                                                       uint32_t num_slots, uint32_t p_lwe,
                                                                       double scale_sign) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the maximum and argument of the first num_values packed in a CKKS ciphertext via repeated
     * scheme switchings to FHEW and back.
     *
     * @param ciphertext CKKS ciphertexts of values that need to be compared
     * @param public_key public key of the CKKS cryptocontext
     * @param num_values number of values to extract from the CKKS ciphertext. We always assume for the moment
     * num_values is a power of two
     * @param num_slots number of slots to encode the new CKKS ciphertext with
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
     * the resulting FHEW ciphertexts will encrypt values modulo p_lwe, so scale_sign should account for this
     * p_lwe and scale_sign are given here only if the homomorphic decoding matrix is not scaled with the desired values
     * @return a vector of two CKKS ciphertexts where the first encrypts the maximum value and the second encrypts the
     * index (in the representation specified by one_hot). The ciphertexts have junk after the first slot in the
     * first ciphertext
     * and after num_values in the second ciphertext if one_hot=true and after the first slot if one_hot=false.
     */
    virtual std::vector<Ciphertext<Element>> eval_max_scheme_switching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> public_key, uint32_t num_values,
                                                                    uint32_t num_slots, uint32_t p_lwe,
                                                                    double scale_sign) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the maximum and argument of the first num_values packed in a CKKS ciphertext.
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
     *
     * @param ciphertext CKKS ciphertext of values that need to be compared
     * @param public_key public key of the CKKS cryptocontext
     * @param num_values number of values to extract from the CKKS ciphertext
     * @param num_slots number of slots to encode the new CKKS ciphertext with
     * @param p_lwe the desired plaintext modulus for the new FHEW ciphertexts
     * @param scale_sign factor to multiply the CKKS ciphertext when switching to FHEW
     * @return a vector of two CKKS ciphertexts: [max, argmax]
     */
    virtual std::vector<Ciphertext<Element>> eval_max_scheme_switching_alt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> public_key, uint32_t num_values,
                                                                       uint32_t num_slots, uint32_t p_lwe,
                                                                       double scale_sign) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Returns the BinFHE crypto context used in scheme switching.
     *
     * @return the BinFHE crypto context.
     */
    virtual std::shared_ptr<cipher::BooleanContext> get_bin_cc_for_scheme_switch() {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Sets the BinFHE crypto context used in scheme switching.
     *
     * @param cc_lwe the BinFHE crypto context.
     */
    virtual void set_bin_cc_for_scheme_switch(std::shared_ptr<cipher::BooleanContext> cc_lwe) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Returns the FHEW-to-CKKS switching key, stored as a CKKS ciphertext.
     *
     * @return the switching key ciphertext.
     */
    virtual Ciphertext<Element> get_swk_fc() {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Sets the FHEW-to-CKKS switching key, stored as a CKKS ciphertext.
     *
     * @param fhew_to_ckks_swk the switching key ciphertext.
     */
    virtual void set_swk_fc(Ciphertext<Element> fhew_to_ckks_swk) {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {}

    template <class Archive>
    void load(Archive& ar) {}
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_FHE_H_
