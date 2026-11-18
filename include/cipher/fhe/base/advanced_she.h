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

#ifndef CIPHER_FHE_BASE_ADVANCED_SHE_H_
#define CIPHER_FHE_BASE_ADVANCED_SHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/encoding/plaintext_fwd.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/private_key_fwd.h"
#include "cipher/fhe/key/public_key_fwd.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

template <class Element>
class BaseMultiparty;

/**
 * @brief Abstract interface for the advanced SHE operations built on top of the leveled SHE primitives:
 * multi-operand additions and multiplications, linear weighted sums, polynomial and Chebyshev series
 * evaluation, eval_sum over packed slots (all slots, rows or columns), inner products and merging.
 * @tparam Element a ring element.
 */
template <class Element>
class BaseAdvancedShe {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";

    friend class BaseMultiparty<Element>;

  public:
    virtual ~BaseAdvancedShe() = default;

    /**
     * Virtual function for evaluating addition of a list of ciphertexts.
     *
     * @param ciphertext_vec is the ciphertext list.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> eval_add_many(const std::vector<Ciphertext<Element>>& ciphertext_vec) const;

    /**
     * Virtual function for evaluating addition of a list of ciphertexts.
     * This version uses no additional space, other than the vector provided.
     *
     * @param ciphertext_vec  is the ciphertext list (modified in place to store intermediate results).
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> eval_add_many_in_place(std::vector<Ciphertext<Element>>& ciphertext_vec) const;

    /**
     * Virtual function for evaluating multiplication of a ciphertext list which
     * each multiplication is followed by relinearization operation.
     *
     * @param ciphertext_vec  is the ciphertext list.
     * @param eval_key_vec are the evaluation keys to make the new ciphertext
     *  decryptable by the same secret key as that of ciphertext list.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> eval_mult_many(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                               const std::vector<EvalKey<Element>>& eval_key_vec) const;

    //------------------------------------------------------------------------------
    // LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
     * Virtual function for computing the linear weighted sum of a
     * vector of ciphertexts.
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum(std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec,
                                                  const std::vector<int64_t>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Virtual function for computing the linear weighted sum of a vector of ciphertexts
     * with real weights (CKKS).
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum(std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec,
                                                  const std::vector<double>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Virtual function for computing the linear weighted sum of a vector of ciphertexts
     * with complex weights (CKKS).
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum(std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec,
                                                  const std::vector<std::complex<double>>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Function for computing the linear weighted sum of a
     * vector of ciphertexts. This is a mutable method,
     * meaning that the level/depth of input ciphertexts may change.
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum_mutable(std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                          const std::vector<int64_t>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Function for computing the linear weighted sum of a vector of ciphertexts with real weights (CKKS).
     * This is a mutable method, meaning that the level/depth of input ciphertexts may change.
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum_mutable(std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                          const std::vector<double>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Function for computing the linear weighted sum of a vector of ciphertexts with complex weights (CKKS).
     * This is a mutable method, meaning that the level/depth of input ciphertexts may change.
     *
     * @param ciphertext_vec vector of input ciphertexts.
     * @param weights vector containing the weights.
     * @return A ciphertext containing the linear weighted sum.
     */
    virtual Ciphertext<Element> eval_linear_w_sum_mutable(std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                          const std::vector<std::complex<double>>& weights) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
     * Method for computing the powers of a ciphertext to be used when evaluating a polynomial
     * represented in the power series. Uses a binary tree computation of the powers for low
     * polynomial degrees (degree < 5), or the Paterson-Stockmeyer power basis for higher degrees.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the resulting data structure of powers.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_powers(ConstCiphertext<Element>& ciphertext,
                                                               const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for computing the powers of a ciphertext to be used when evaluating a polynomial
     * represented in the power series with real coefficients; see the int64_t overload for the algorithm.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the resulting data structure of powers.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_powers(ConstCiphertext<Element>& ciphertext,
                                                               const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for computing the powers of a ciphertext to be used when evaluating a polynomial
     * represented in the power series with complex coefficients; see the int64_t overload for the algorithm.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the resulting data structure of powers.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_powers(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for polynomial evaluation for polynomials represented in the power series.
     * Uses eval_poly_linear() for low polynomial degrees (degree < 5), or eval_poly_ps() for higher degrees.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly(ConstCiphertext<Element>& ciphertext,
                                          const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power series with real coefficients.
     * Uses eval_poly_linear() for low polynomial degrees (degree < 5), or eval_poly_ps() for higher degrees.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly(ConstCiphertext<Element>& ciphertext,
                                          const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power series with complex coefficients.
     * Uses eval_poly_linear() for low polynomial degrees (degree < 5), or eval_poly_ps() for higher degrees.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly(ConstCiphertext<Element>& ciphertext,
                                          const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for evaluating a polynomial with integer coefficients in the power basis from the powers
     * precomputed by eval_powers, so that several polynomials can be evaluated on the same input.
     *
     * @param powers the powers of the input ciphertext returned by eval_powers (computed for a polynomial
     * of at least the same degree and, for degree < 5, the same sparsity pattern of the coefficients).
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_with_precomp(std::shared_ptr<SeriesPowers<Element>> powers,
                                                       const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a polynomial with real coefficients in the power basis from the powers
     * precomputed by eval_powers, so that several polynomials can be evaluated on the same input.
     *
     * @param powers the powers of the input ciphertext returned by eval_powers (computed for a polynomial
     * of at least the same degree and, for degree < 5, the same sparsity pattern of the coefficients).
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_with_precomp(std::shared_ptr<SeriesPowers<Element>> powers,
                                                       const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a polynomial with complex coefficients in the power basis from the powers
     * precomputed by eval_powers, so that several polynomials can be evaluated on the same input.
     *
     * @param powers the powers of the input ciphertext returned by eval_powers (computed for a polynomial
     * of at least the same degree and, for degree < 5, the same sparsity pattern of the coefficients).
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_with_precomp(std::shared_ptr<SeriesPowers<Element>> powers,
                                                       const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series. This uses a binary tree computation of
     * the polynomial powers.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_linear(ConstCiphertext<Element>& ciphertext,
                                                 const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series with real coefficients. This uses a binary tree computation of
     * the polynomial powers.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_linear(ConstCiphertext<Element>& ciphertext,
                                                 const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series with complex coefficients. This uses a binary tree computation of
     * the polynomial powers.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_linear(ConstCiphertext<Element>& ciphertext,
                                                 const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series. This uses the Paterson-Stockmeyer algorithm.
     *
     * @param x input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_ps(ConstCiphertext<Element>& x,
                                             const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series with real coefficients. This uses the Paterson-Stockmeyer algorithm.
     *
     * @param x input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_ps(ConstCiphertext<Element>& x,
                                             const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for polynomial evaluation for polynomials represented in the power
     * series with complex coefficients. This uses the Paterson-Stockmeyer algorithm.
     *
     * @param x input ciphertext
     * @param coefficients is the vector of coefficients in the polynomial; the
     * size of the vector is the degree of the polynomial + 1
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_poly_ps(ConstCiphertext<Element>& x,
                                             const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
     * Method for computing the Chebyshev polynomials to be used in polynomial interpolation via the Chebyshev series.
     * Uses a binary tree computation of the Chebyshev polynomials for low degrees (degree < 5),
     * or the Paterson-Stockmeyer Chebyshev basis for higher degrees.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the Chebyshev series; the
     * size of the vector is the degree of the polynomial + 1
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the resulting data structure of Chebyshev polynomials.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_cheby_polys(ConstCiphertext<Element>& ciphertext,
                                                                    const std::vector<int64_t>& coefficients, double a,
                                                                    double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for computing the Chebyshev polynomials to be used in polynomial interpolation via the
     * Chebyshev series with real coefficients; see the int64_t overload for the algorithm.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the Chebyshev series; the
     * size of the vector is the degree of the polynomial + 1
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the resulting data structure of Chebyshev polynomials.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_cheby_polys(ConstCiphertext<Element>& ciphertext,
                                                                    const std::vector<double>& coefficients, double a,
                                                                    double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for computing the Chebyshev polynomials to be used in polynomial interpolation via the
     * Chebyshev series with complex coefficients; see the int64_t overload for the algorithm.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in the Chebyshev series; the
     * size of the vector is the degree of the polynomial + 1
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the resulting data structure of Chebyshev polynomials.
     */
    virtual std::shared_ptr<SeriesPowers<Element>> eval_cheby_polys(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients, double a,
            double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for evaluating Chebyshev polynomial interpolation;
     * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
     * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
     * eval_chebyshev_series_linear, otherwise, use eval_chebyshev_series_ps.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<int64_t>& coefficients, double a,
                                                      double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating Chebyshev polynomial interpolation with real coefficients;
     * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
     * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
     * eval_chebyshev_series_linear, otherwise, use eval_chebyshev_series_ps.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<double>& coefficients, double a,
                                                      double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating Chebyshev polynomial interpolation with complex coefficients;
     * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
     * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
     * eval_chebyshev_series_linear, otherwise, use eval_chebyshev_series_ps.
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<std::complex<double>>& coefficients, double a,
                                                      double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for evaluating a Chebyshev series with integer coefficients from the Chebyshev polynomials
     * precomputed by eval_cheby_polys, so that several series can be evaluated on the same input.
     *
     * @param polys the Chebyshev polynomials of the input ciphertext returned by eval_cheby_polys (computed
     * for a series of at least the same degree and, for degree < 5, the same sparsity of the coefficients).
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_with_precomp(std::shared_ptr<SeriesPowers<Element>> polys,
                                                                   const std::vector<int64_t>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with real coefficients from the Chebyshev polynomials
     * precomputed by eval_cheby_polys, so that several series can be evaluated on the same input.
     *
     * @param polys the Chebyshev polynomials of the input ciphertext returned by eval_cheby_polys (computed
     * for a series of at least the same degree and, for degree < 5, the same sparsity of the coefficients).
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_with_precomp(std::shared_ptr<SeriesPowers<Element>> polys,
                                                                   const std::vector<double>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with complex coefficients from the Chebyshev polynomials
     * precomputed by eval_cheby_polys, so that several series can be evaluated on the same input.
     *
     * @param polys the Chebyshev polynomials of the input ciphertext returned by eval_cheby_polys (computed
     * for a series of at least the same degree and, for degree < 5, the same sparsity of the coefficients).
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_with_precomp(
            std::shared_ptr<SeriesPowers<Element>> polys, const std::vector<std::complex<double>>& coefficients) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for evaluating a Chebyshev series with integer coefficients of degree less than 5 using
     * a binary tree computation of the Chebyshev polynomials, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_linear(ConstCiphertext<Element>& ciphertext,
                                                             const std::vector<int64_t>& coefficients, double a,
                                                             double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with real coefficients of degree less than 5 using
     * a binary tree computation of the Chebyshev polynomials, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_linear(ConstCiphertext<Element>& ciphertext,
                                                             const std::vector<double>& coefficients, double a,
                                                             double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with complex coefficients of degree less than 5 using
     * a binary tree computation of the Chebyshev polynomials, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_linear(ConstCiphertext<Element>& ciphertext,
                                                             const std::vector<std::complex<double>>& coefficients,
                                                             double a, double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Method for evaluating a Chebyshev series with integer coefficients using the Paterson-Stockmeyer
     * algorithm in the Chebyshev basis, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_ps(ConstCiphertext<Element>& ciphertext,
                                                         const std::vector<int64_t>& coefficients, double a,
                                                         double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with real coefficients using the Paterson-Stockmeyer
     * algorithm in the Chebyshev basis, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_ps(ConstCiphertext<Element>& ciphertext,
                                                         const std::vector<double>& coefficients, double a,
                                                         double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * Method for evaluating a Chebyshev series with complex coefficients using the Paterson-Stockmeyer
     * algorithm in the Chebyshev basis, after mapping the range [a,b] to [-1,1].
     *
     * @param ciphertext input ciphertext
     * @param coefficients is the vector of coefficients in Chebyshev expansion
     * @param a - lower bound of argument for which the coefficients were found
     * @param b - upper bound of argument for which the coefficients were found
     * @return the result of polynomial evaluation.
     */
    virtual Ciphertext<Element> eval_chebyshev_series_ps(ConstCiphertext<Element>& ciphertext,
                                                         const std::vector<std::complex<double>>& coefficients,
                                                         double a, double b) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL SUM
    //------------------------------------------------------------------------------

    /**
     * Virtual function to generate the automorphism keys for eval_sum; works
     * only for packed encoding
     *
     * @param private_key private key.
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_key_gen(
            const PrivateKey<Element> private_key) const;

    /**
     * Virtual function to generate the automorphism keys for eval_sum_rows; works
     * only for packed encoding
     *
     * @param private_key private key.
     * @param row_size size of rows in the matrix
     * @param subring_dim subring dimension (set to cyclotomic order if set to 0)
     * @param indices automorphism indices to generate keys for; the indices needed for
     * eval_sum_rows are appended to it
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_rows_key_gen(
            const PrivateKey<Element> private_key, uint32_t row_size, uint32_t subring_dim,
            std::vector<uint32_t>& indices) const;

    /**
     * Virtual function to generate the automorphism keys for eval_sum_cols; works
     * only for packed encoding
     *
     * @param private_key private key.
     * @param indices automorphism indices to generate keys for; the indices needed for
     * eval_sum_cols and eval_sum are appended to it
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_cols_key_gen(
            const PrivateKey<Element> private_key, std::vector<uint32_t>& indices) const;

    /**
     * @brief Sums all elements in log (batch size) time - works only with packed encoding
     * @param ciphertext the input ciphertext.
     * @param batch_size size of the batch to be summed up
     * @param eval_sum_key_map - reference to the map of evaluation keys generated by eval_sum_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_sum(ConstCiphertext<Element> ciphertext, uint32_t batch_size,
                                         const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map) const;

    /**
     * @brief Sums all elements over row-vectors in a matrix - works only with packed encoding.
     * @param ciphertext the input ciphertext.
     * @param num_rows number of rows in the matrix
     * @param eval_sum_keys - reference to the map of evaluation keys generated by eval_sum_rows_key_gen.
     * @param subring_dim the current cyclotomic order/subring dimension. If set to 0, we use the full cyclotomic order.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_sum_rows(ConstCiphertext<Element> ciphertext, uint32_t num_rows,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_sum_keys,
                                              uint32_t subring_dim) const;

    /**
     * @brief Sums all elements over column-vectors in a matrix - works only with packed encoding. The code is
     *        implemented according to the specifications in https://eprint.iacr.org/2018/662.pdf
     * @param ciphertext the input ciphertext.
     * @param num_cols number of columns in the matrix
     * @param eval_sum_keys - reference to the map of evaluation keys generated by eval_sum_key_gen.
     * @param right_eval_keys - reference to the map of evaluation keys generated by eval_sum_cols_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_sum_cols(ConstCiphertext<Element> ciphertext, uint32_t num_cols,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_sum_keys,
                                              const std::map<uint32_t, EvalKey<Element>>& right_eval_keys) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
     * @brief Evaluates inner product in batched encoding
     * @param ciphertext1 first vector.
     * @param ciphertext2 second vector.
     * @param batch_size size of the batch to be summed up
     * @param eval_key_map - reference to the map of evaluation keys generated by eval_sum_key_gen.
     * @param eval_mult_key - reference to the evaluation key generated by eval_mult_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_inner_product(ConstCiphertext<Element> ciphertext1,
                                                   ConstCiphertext<Element> ciphertext2, uint32_t batch_size,
                                                   const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                                   const EvalKey<Element> eval_mult_key) const;

    /**
     * @brief Evaluates inner product in batched encoding
     * @param ciphertext first vector.
     * @param plaintext plaintext.
     * @param batch_size size of the batch to be summed up
     * @param eval_key_map - reference to the map of evaluation keys generated by eval_sum_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_inner_product(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
                                                   uint32_t batch_size,
                                                   const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Function to add random noise to all plaintext slots except for the first
     * one; used in eval_inner_product
     *
     * @param ciphertext the input ciphertext.
     * @return modified ciphertext
     */
    virtual Ciphertext<Element> add_random_noise(ConstCiphertext<Element> ciphertext) const;

    /**
     * Merges multiple ciphertexts with encrypted results in slot 0 into a
     * single ciphertext The slot assignment is done based on the order of
     * ciphertexts in the vector
     *
     * @param ciphertext_vector vector of ciphertexts to be merged.
     * @param eval_key_map - reference to the map of evaluation keys generated by
     * eval_automorphism_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_merge(const std::vector<Ciphertext<Element>>& ciphertext_vector,
                                           const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    //------------------------------------------------------------------------------
    // LINEAR TRANSFORMATION
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // Other Methods for Bootstrap
    //------------------------------------------------------------------------------

  protected:
    /**
     * Automorphism indices needed by eval_sum for real (BGV/BFV) packing in a power-of-two cyclotomic ring:
     * the radix fold generated by 5 over batch_size slots when 2*batch_size < m, otherwise the fold over
     * batch_size/2 slots plus the index m-1 (the conjugation that adds the two halves of the slots).
     *
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_indices_2n(uint32_t batch_size, uint32_t m);

    /**
     * Automorphism indices needed by eval_sum for CKKS packing in a power-of-two cyclotomic ring:
     * the radix fold generated by 5 over batch_size slots.
     *
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_indices2n_complex(uint32_t batch_size, uint32_t m);

    /**
     * Automorphism indices needed by eval_sum_rows for CKKS packing: the radix fold generated by
     * 5^row_size mod m over the m/(4*row_size) rows of the matrix.
     *
     * @param row_size the number of columns of the matrix (size of a row).
     * @param m the cyclotomic order (or subring dimension).
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_indices2n_complex_rows(uint32_t row_size, uint32_t m);

    /**
     * Automorphism indices needed by eval_sum_cols for CKKS packing: the radix fold generated by
     * 5^-1 mod m over batch_size slots.
     *
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_indices2n_complex_cols(uint32_t batch_size, uint32_t m);

    /**
     * Automorphism-index set of the radix-configured eval_sum fold (compile-time
     * CIPHER_PARTIAL_SUM_RADIX): {g0^(i*radix^level) mod m : i in [1, radix)}, bounded so the
     * fold covers size slots. Power-of-two m only.
     *
     * @param g0 generator of the automorphism group used by the fold (5, 5^row_size or 5^-1 mod m).
     * @param size the number of slots the fold covers.
     * @param m the cyclotomic order (power of two).
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_eval_sum_indices(uint32_t g0, uint32_t size, uint32_t m);

    /**
     * Radix-configured eval_sum rotation fold (compile-time CIPHER_PARTIAL_SUM_RADIX): per level,
     * one hoisted digit decomposition is shared by the level's up to radix-1 automorphisms
     * of the running sum. Generator g0 selects the flavor (5, 5^row_size, or 5^-1 mod m);
     * covers size slots. Power-of-two m only.
     *
     * @param ciphertext the input ciphertext.
     * @param g0 generator of the automorphism group used by the fold (5, 5^row_size or 5^-1 mod m).
     * @param size the number of slots the fold covers.
     * @param m the cyclotomic order (power of two).
     * @param eval_key_map the map of automorphism keys, containing the indices of generate_eval_sum_indices.
     * @return the ciphertext with the partial sums.
     */
    Ciphertext<Element> eval_sum_radix_fold(ConstCiphertext<Element>& ciphertext, uint32_t g0, uint32_t size,
                                            uint32_t m, const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Automorphism indices needed by eval_sum for the batch size and cyclotomic order of the crypto
     * parameters of the private key: generate_indices2n_complex (CKKS) or generate_indices_2n for power-of-two
     * cyclotomics, and the successive squares of the plaintext generator for arbitrary cyclotomics.
     *
     * @param private_key the private key the eval_sum keys are generated for.
     * @return the set of automorphism indices.
     */
    static std::set<uint32_t> generate_index_list_for_eval_sum(const PrivateKey<Element>& private_key);

    /**
     * Sums batch_size slots of a ciphertext with real (BGV/BFV) packing in a power-of-two cyclotomic ring:
     * the radix fold generated by 5, followed by the addition of the conjugate (automorphism m-1) when the
     * batch spans both halves of the slots (2*batch_size == m).
     *
     * @param ciphertext the input ciphertext.
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @param eval_key_map the map of automorphism keys generated with generate_indices_2n.
     * @return the ciphertext with the sum in every slot.
     */
    Ciphertext<Element> eval_sum_2n(ConstCiphertext<Element> ciphertext, uint32_t batch_size, uint32_t m,
                                    const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Sums batch_size slots of a ciphertext with CKKS packing: the radix fold generated by 5.
     *
     * @param ciphertext the input ciphertext.
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @param eval_key_map the map of automorphism keys generated with generate_indices2n_complex.
     * @return the ciphertext with the sum in every slot.
     */
    Ciphertext<Element> eval_sum2n_complex(ConstCiphertext<Element> ciphertext, uint32_t batch_size, uint32_t m,
                                           const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Sums the rows of a matrix with row_size columns packed in CKKS slots: the radix fold generated by
     * 5^row_size mod m over the m/(4*row_size) rows.
     *
     * @param ciphertext the input ciphertext.
     * @param row_size the number of columns of the matrix (size of a row).
     * @param m the cyclotomic order (or subring dimension).
     * @param eval_key_map the map of automorphism keys generated with generate_indices2n_complex_rows.
     * @return the ciphertext with the row sums.
     */
    Ciphertext<Element> eval_sum2n_complex_rows(ConstCiphertext<Element> ciphertext, uint32_t row_size, uint32_t m,
                                                const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Sums over the columns of a matrix packed in CKKS slots: the radix fold generated by 5^-1 mod m
     * over batch_size slots.
     *
     * @param ciphertext the input ciphertext.
     * @param batch_size the number of slots to be summed.
     * @param m the cyclotomic order.
     * @param eval_key_map the map of automorphism keys generated with generate_indices2n_complex_cols.
     * @return the ciphertext with the column sums.
     */
    Ciphertext<Element> eval_sum2n_complex_cols(ConstCiphertext<Element> ciphertext, uint32_t batch_size, uint32_t m,
                                                const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_ADVANCED_SHE_H_
