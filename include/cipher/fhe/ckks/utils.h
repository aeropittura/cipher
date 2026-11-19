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

#ifndef CIPHER_FHE_CKKS_UTILS_H_
#define CIPHER_FHE_CKKS_UTILS_H_

#include <stdint.h>

#include <complex>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <vector>

#include "cipher/util/exception.h"

/*
 * Subroutines used by the linear transformation homomorphic capability
 */

namespace cipher {

/**
 * @brief Quotient and remainder of a polynomial long division (long_division_poly, long_division_chebyshev).
 */
template <typename VecDType>
struct LongDiv {
    std::vector<VecDType> q;  ///< coefficients of the quotient
    std::vector<VecDType> r;  ///< coefficients of the remainder
    LongDiv() = default;
    /**
     * Constructs the result from the quotient and remainder coefficients.
     *
     * @param q0 coefficients of the quotient
     * @param r0 coefficients of the remainder
     */
    LongDiv(const std::vector<VecDType>& q0, const std::vector<VecDType>& r0) : q(q0), r(r0) {}
};

/**
 * Checks whether a real value differs from 1 by more than a tolerance.
 *
 * @param v the value
 * @param delta the tolerance
 * @return true if |v - 1| > delta
 */
inline bool is_not_equal_one(double v, double delta = 0x1p-44) {
    return std::abs(v - 1.0) > delta;
}
/**
 * Checks whether a real value differs from 0 by more than a tolerance.
 *
 * @param v the value
 * @param delta the tolerance
 * @return true if |v| > delta
 */
inline bool is_not_equal_zero(double v, double delta = 0x1p-44) {
    return std::abs(v) > delta;
}
/**
 * Checks whether a real value differs from -1 by more than a tolerance.
 *
 * @param v the value
 * @param delta the tolerance
 * @return true if |v + 1| > delta
 */
inline bool is_not_equal_neg_one(double v, double delta = 0x1p-44) {
    return std::abs(v + 1.0) > delta;
}
/**
 * Checks whether a complex value differs from 1 by more than a tolerance in its real or imaginary part.
 *
 * @param val the value
 * @param delta the tolerance
 * @return true if |Re(val) - 1| > delta or |Im(val)| > delta
 */
inline bool is_not_equal_one(std::complex<double> val, double delta = 0x1p-44) {
    return is_not_equal_one(val.real(), delta) || is_not_equal_zero(val.imag(), delta);
}
/**
 * Checks whether a complex value differs from 0 by more than a tolerance in its real or imaginary part.
 *
 * @param val the value
 * @param delta the tolerance
 * @return true if |Re(val)| > delta or |Im(val)| > delta
 */
inline bool is_not_equal_zero(std::complex<double> val, double delta = 0x1p-44) {
    return is_not_equal_zero(val.real(), delta) || is_not_equal_zero(val.imag(), delta);
}

/**
 * Converts a coefficient to a real number (identity for doubles); used by the templated coefficient utilities.
 *
 * @param val the value
 * @return the value itself
 */
inline double to_real(double val) {
    return val;
}
/**
 * Converts an integer coefficient to a real number.
 *
 * @param val the value
 * @return the value as a double
 */
inline double to_real(int64_t val) {
    return static_cast<double>(val);
}
/**
 * Converts a complex coefficient to a real number by taking its real part.
 *
 * @param val the value
 * @return the real part of the value
 */
inline double to_real(std::complex<double> val) {
    return val.real();
}

/**
 * @brief Gets the degree of a polynomial specified by its coefficients, which is the index of
 * the last non-zero element in the coefficients. If all the coefficients are zero, it returns 0.
 * @param coefficients vector of coefficients of a polynomial (can not be empty)
 * @param delta tolerance below which a coefficient is treated as zero (0 = exact comparison).
 * @return the integer degree of the polynomial.
 */
template <typename VecDType>
uint32_t effective_degree(const std::vector<VecDType>& coefficients, double delta = 0.0) {
    uint32_t i = coefficients.size();
    if (i == 0)
        CIPHER_THROW("Coefficients vector can not be empty");
    while (i > 0) {
        if (is_not_equal_zero(coefficients[--i], delta))
            break;
    }
    return i;
}

/**
 * Computes the quotient and remainder of the long division of two polynomials in the power series basis.
 *
 * @param f the vector of coefficients of the dividend.
 * @param g the vector of coefficients of the divisor.
 * @return a struct with the coefficients for the quotient and remainder.
 */
template <typename VecDType>
std::shared_ptr<LongDiv<VecDType>> long_division_poly(const std::vector<VecDType>& f, const std::vector<VecDType>& g);

/**
 * Computes the quotient and remainder of the long division of two polynomials in the Chebyshev series basis
 *
 * @param f the vector of coefficients of the dividend.
 * @param g the vector of coefficients of the divisor.
 * @return a struct with the coefficients for the quotient and remainder.
 */
template <typename VecDType>
std::shared_ptr<LongDiv<VecDType>> long_division_chebyshev(const std::vector<VecDType>& f,
                                                           const std::vector<VecDType>& g);

/**
 * Computes the values of the internal degrees k and m needed in the Paterson-Stockmeyer algorithm
 * such that k(2^m - 1) > n and k close to sqrt(n/2).
 *
 * @param n the degree of a polynomial.
 * @return a vector containing k and m.
 */
std::vector<uint32_t> compute_degrees_ps(uint32_t n);

/**
 * Gets the multiplicative depth of evaluating a polynomial of the given degree from a table that covers degrees
 * up to 261631 (see examples/fhe/FUNCTION_EVALUATION.md): degrees below 5 are evaluated with a binary tree
 * of powers, higher degrees with the Paterson-Stockmeyer algorithm.
 *
 * @param degree degree of the polynomial
 * @return the multiplicative depth
 */
uint32_t get_depth_by_degree(size_t degree);

/**
 * Get the depth for a given vector of coefficients for the Paterson-Stockmeyer algorithm.
 * The functions is based on the table described in examples/fhe/FUNCTION_EVALUATION.md
 *
 * @param vec vector of coefficients
 * @param is_normalized true if the vector normalized. false is the default value
 * @return multiplicative depth
 */
template <typename VecDType>
uint32_t get_multiplicative_depth_by_coeff_vector(const std::vector<VecDType>& vec, bool is_normalized = false) {
    if (vec.size() == 0)
        CIPHER_THROW("Cannot perform operation on empty vector. vec.size() == 0");
    return get_depth_by_degree(vec.size() - 1) - is_normalized;
}

/**
 * Extracts shifted diagonal of matrix A.
 *
 * @param A square linear map.
 * @param i the index by which the diagonal is shifted.
 *
 * @return the vector corresponding to the shifted diagonal
 */
std::vector<std::complex<double>> extract_shifted_diagonal(const std::vector<std::vector<std::complex<double>>>& A,
                                                           int i);

/**
 * Rotates a vector by an index - left rotation
 *
 * @param a input vector.
 * @param index rotation index.
 *
 * @return the rotated vector
 */
template <typename VecDType>
std::vector<VecDType> rotate_slots(const std::vector<VecDType>& a, int32_t index);

/**
 * Rotates each half of a vector separately by an index - left rotation
 *
 * @param a input vector.
 * @param index rotation index.
 *
 * @return the rotated vector, mimicking the BFV subring rotations
 */
template <typename VecDType>
std::vector<VecDType> rotate_two_halves(const std::vector<VecDType>& a, int32_t index);

/**
 * Clones the current vector up to the size indicated by the 'slots' variable
 *
 * @param a input vector.
 * @param slots the new size of the vector.
 *
 * @return the vector with cloned values
 */
template <typename VecDType = std::vector<std::complex<double>>>
std::vector<VecDType> fill_slots(const std::vector<VecDType>& a, uint32_t slots);

/**
 * Clones the values of an initializer list up to the size indicated by the 'slots' variable
 *
 * @param a input values.
 * @param slots the new size of the vector.
 *
 * @return the vector with cloned values
 */
template <typename VecDType = std::vector<std::complex<double>>>
std::vector<VecDType> fill_slots(std::initializer_list<VecDType> a, uint32_t slots);

/*
template <typename VecDType = std::complex<double>>
std::vector<VecDType> fill_slots(const std::vector<VecDType>& a, uint32_t slots);
*/

/**
 * Computes the coefficients for the FFT encoding for coeff_encoding_collapse such that every
 * iteration occupies one level.
 *
 * @param pows vector of roots of unity powers.
 * @param rot_group rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param flag_i flag that is 0 when we compute the coefficients for conj(U_0^T) and is 1 for conj(i*U_0^T).
 * @return the coefficients of each layer of the iFFT (one vector per layer)
 */
std::vector<std::vector<std::complex<double>>> coeff_encoding_one_level(const std::vector<std::complex<double>>& pows,
                                                                        const std::vector<uint32_t>& rot_group,
                                                                        bool flag_i);

/**
 * Computes the coefficients for the FFT decoding for coeff_decoding_collapse such that every
 * iteration occupies one level.
 *
 * @param pows vector of roots of unity powers.
 * @param rot_group rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param flag_i flag that is 0 when we compute the coefficients for U_0 and is 1 for i*U_0.
 * @return the coefficients of each layer of the FFT (one vector per layer)
 */
std::vector<std::vector<std::complex<double>>> coeff_decoding_one_level(const std::vector<std::complex<double>>& pows,
                                                                        const std::vector<uint32_t>& rot_group,
                                                                        bool flag_i);

/**
 * Computes the coefficients for the given level budget for the FFT encoding. Needed in
 * EvalLTFFTPrecomputeEncoding.
 *
 * @param pows vector of roots of unity powers.
 * @param rot_group rotation group indices to appropriately choose the elements of pows to compute iFFT.
 * @param level_budget the user specified budget for levels.
 * @param flag_i flag that is 0 when we compute the coefficients for conj(U_0^T) and is 1 for conj(i*U_0^T).
 * @return the coefficients of each level of the collapsed iFFT (one vector of diagonals per level)
 */
std::vector<std::vector<std::vector<std::complex<double>>>> coeff_encoding_collapse(
        const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rot_group, uint32_t level_budget,
        bool flag_i);

/**
 * Computes the coefficients for the given level budget for the FFT decoding. Needed in
 * EvalLTFFTPrecomputeDecoding.
 *
 * @param pows vector of roots of unity powers.
 * @param rot_group rotation group indices to appropriately choose the elements of pows to compute FFT.
 * @param level_budget the user specified budget for levels.
 * @param flag_i flag that is 0 when we compute the coefficients for U_0 and is 1 for i*U_0.
 * @return the coefficients of each level of the collapsed FFT (one vector of diagonals per level)
 */
std::vector<std::vector<std::vector<std::complex<double>>>> coeff_decoding_collapse(
        const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rot_group, uint32_t level_budget,
        bool flag_i);

/**
 * Ensures that the index for rotation is positive and between 0 and slots - 1.
 *
 * @param index signed rotation amount.
 * @param slots number of slots and size of vector that is rotated.
 * @return the equivalent non-negative rotation index modulo slots
 */
uint32_t reduce_rotation(int32_t index, uint32_t slots);

/**
 * @brief Parameters of the homomorphic encoding or decoding (FFT-like linear transform) in bootstrapping.
 */
struct ckks_boot_params {
    uint32_t lvlb;               ///< level budget
    uint32_t layers_collapse;    ///< layers to collapse in one level
    uint32_t rem_collapse;       ///< remaining layers to collapse
    uint32_t num_rotations;      ///< number of rotations in one level
    uint32_t b;                  ///< baby step in the baby-step giant-step strategy
    uint32_t g;                  ///< giant step in the baby-step giant-step strategy
    uint32_t num_rotations_rem;  ///< number of rotations in the remaining level
    uint32_t b_rem;              ///< baby step in the baby-step giant-step strategy for the remaining level
    uint32_t g_rem;              ///< giant step in the baby-step giant-step strategy for the remaining level
};

/**
 * Computes all parameters needed for the homomorphic encoding and decoding in the bootstrapping
 * operation and returns them as a struct: how many FFT layers are collapsed in each level of the budget (the
 * last level takes the remainder), the number of rotations per level, and the baby and giant steps.
 *
 * @param slots number of slots
 * @param level_budget the allocated level budget for the computation.
 * @param dim1 the value for the inner dimension in the baby-step giant-step strategy (0 = chosen automatically)
 * @return struct with parameters for the homomorphic encoding and decoding in bootstrapping
 */
struct ckks_boot_params get_collapsed_fft_params(uint32_t slots, uint32_t level_budget = 4, uint32_t dim1 = 0);

/**
 *  Gets inner loop dimension for baby step giant step algorithm for linear transform,
 * taking into account the cost efficiency of hoisted automorphisms.
 * @param slots number of slots.
 * @return the value for the inner dimension in the baby-step giant-step strategy
 */
uint32_t get_ratio_bsgslt(uint32_t slots);

/**
 * Assembles a list of rotation indices necessary to perform the
 * linear transform in scheme switching (needs to be ran once to each LT).
 * @param dim1 baby-step dimension
 * @param m cyclotomic order
 * @param block_dimension dimension related to the linear transform computation matrix
 * @return vector of rotation indices necessary
 */
std::vector<int32_t> find_lt_rotation_indices_switch(uint32_t dim1, uint32_t m, uint32_t block_dimension);

/**
 * Assembles a list of rotation indices necessary to perform all the
 * linear transforms in argmin.
 * @param m cyclotomic order
 * @param block_dimension dimension related to the linear transform computation matrix
 * @param cols dimension of columns of the linear transform
 * @return vector of rotation indices necessary
 */
std::vector<int32_t> find_lt_rotation_indices_switch_argmin(uint32_t m, uint32_t block_dimension, uint32_t cols);

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_UTILS_H_
