//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code contains the discrete fourier transform definitions
 */

#ifndef CIPHER_MATH_DFT_H_
#define CIPHER_MATH_DFT_H_

#include <complex>
#include <cstdint>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

#ifndef M_PI
    #define M_PI 3.14159265358979323846
#endif

namespace cipher {

/**
 * @brief Discrete Fourier Transform FFT implementation.
 */
class DiscreteFourierTransform {
  public:
    /**
     * FFT forward transform.
     *
     * @param A is the element to perform the transform on.
     * @return is the output result of the transform.
     */
    static std::vector<std::complex<double>> fft_forward_transform(std::vector<std::complex<double>>& A);

    /**
     * FFT inverse transform.
     *
     * @param A is the element to perform the inverse transform on.
     * @return is the output result of the inverse transform.
     */
    static std::vector<std::complex<double>> fft_inverse_transform(std::vector<std::complex<double>>& A);

    /**
     * Forward transform.
     *
     * @param A is the element to perform the transform on.
     * @return is the output result of the transform.
     */
    static std::vector<std::complex<double>> forward_transform(std::vector<std::complex<double>> A);

    /**
     * Inverse transform.
     *
     * @param A is the element to perform the inverse transform on.
     * @return is the output result of the inverse transform.
     */
    static std::vector<std::complex<double>> inverse_transform(std::vector<std::complex<double>> A);

    /**
     * In-place FFT-like algorithm used in CKKS encoding. For more details,
     * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
     *
     * @param vals is a vector of complex numbers.
     * @param cycl_order is the cyclotomic order for which initialize() precomputed the tables.
     */
    static void fft_special_inv(std::vector<std::complex<double>>& vals, uint32_t cycl_order);

    /**
     * In-place FFT-like algorithm used in CKKS decoding. For more details,
     * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
     *
     * @param vals is a vector of complex numbers.
     * @param cycl_order is the cyclotomic order for which initialize() precomputed the tables.
     */
    static void fft_special(std::vector<std::complex<double>>& vals, uint32_t cycl_order);

    /**
     * Reset cached values for the transform to empty.
     */
    static void reset();

    /**
     * Resets and rebuilds the table of the s complex roots of unity exp(-2*pi*i*j/s),
     * j = 0..s-1.
     *
     * @param s is the size of the table (the transform length).
     */
    static void pre_compute_table(uint32_t s);

    /**
     * Precomputes, once per cyclotomic order, the rotation group, the powers of the primitive
     * m-th root of unity, and the per-stage butterfly twiddles used by fft_special() and
     * fft_special_inv() on vectors of length nh. Thread-safe; a no-op if the order is already
     * initialized.
     *
     * @param m is the cyclotomic order.
     * @param nh is the number of slots (half the ring dimension), the length of the vectors
     * passed to fft_special() and fft_special_inv().
     */
    static void initialize(uint32_t m, uint32_t nh);

  private:
    static std::complex<double>* root_of_unity_table;

    // structure to keep values precomputed by initialize() for every cyclotomic order value
    struct PrecomputedValues {
        // cyclotomic order
        uint32_t M_;
        uint32_t nh_;
        // rotation group indexes
        std::vector<uint32_t> rot_group_;
        // ksi powers
        std::vector<std::complex<double>> ksi_pows_;
        // per-stage butterfly twiddles for fft_special/fft_special_inv, stored contiguously:
        // the stage with half-length lenh (a power of two <= Nh/2) occupies [lenh - 1, 2*lenh - 1)
        std::vector<std::complex<double>> fwd_tw_;
        std::vector<std::complex<double>> inv_tw_;

        PrecomputedValues(uint32_t m, uint32_t nh);
    };
    // precomputed_values: key - cyclotomic order, data - values precomputed for the given cyclotomic order
    static std::unordered_map<uint32_t, PrecomputedValues> precomputed_values;

    // guards precomputed_values; map nodes are reference-stable, so readers may use the
    // returned reference after the shared lock is released
    static std::shared_mutex& precomp_mutex();
    static const PrecomputedValues& get_precomp(uint32_t cycl_order);

    static void bit_reverse_permute(std::vector<std::complex<double>>& vals);
};

}  // namespace cipher

#endif  // CIPHER_MATH_DFT_H_
