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
  Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf.
 */

#ifndef CIPHER_RING_TRAPDOOR_IMPL_H_
#define CIPHER_RING_TRAPDOOR_IMPL_H_

#include <cmath>
#include <cstdint>
#include <memory>

#include "cipher/ring/backend.h"
#include "cipher/ring/trapdoor.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/util/debug.h"

namespace cipher {

// On-line stage of pre-image sampling (includes only G-sampling)

template <class Element>
Matrix<Element> RlweTrapdoorUtility<Element>::gauss_samp_online(size_t n, size_t k, const Matrix<Element>& A,
                                                                const RlweTrapdoorPair<Element>& T, const Element& u,
                                                                DggType& dgg,
                                                                const std::shared_ptr<Matrix<Element>> p_hat,
                                                                int64_t base) {
    const std::shared_ptr<ParmType> params = u.get_params();
    auto zero_alloc = Element::allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    const IntType& modulus = A(0, 0).get_modulus();

    // It is assumed that A has dimension 1 x (k + 2) and p_hat has the dimension
    // of (k + 2) x 1 perturbed_syndrome is in the Format::EVALUATION
    // representation
    Element perturbed_syndrome = u - (A.mult(*p_hat))(0, 0);

    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);

    perturbed_syndrome.set_format(Format::COEFFICIENT);

    LatticeGaussSampUtility<Element>::gauss_samp_gq_arb_base(perturbed_syndrome, c, k, modulus, base, dgg, &z_hat_bbi);

    // Convert z_hat from a matrix of integers to a vector of Element ring elements
    // z_hat is in the coefficient representation
    Matrix<Element> z_hat = split_int64_alt_into_elements<Element>(z_hat_bbi, n, params);
    // Now converting it to the Format::EVALUATION representation before
    // multiplication
    z_hat.set_format(Format::EVALUATION);

    Matrix<Element> z_hat_prime(zero_alloc, k + 2, 1);

    z_hat_prime(0, 0) = (*p_hat)(0, 0) + T.e_.mult(z_hat)(0, 0);
    z_hat_prime(1, 0) = (*p_hat)(1, 0) + T.r_.mult(z_hat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        z_hat_prime(row, 0) = (*p_hat)(row, 0) + z_hat(row - 2, 0);

    return z_hat_prime;
}

// Offline stage of pre-image sampling (perturbation sampling)

template <class Element>
std::shared_ptr<Matrix<Element>> RlweTrapdoorUtility<Element>::gauss_samp_offline(
        size_t n, size_t k, const RlweTrapdoorPair<Element>& T, DggType& dgg, DggType& dgg_large_sigma, int64_t base) {
    const std::shared_ptr<ParmType> params = T.e_(0, 0).get_params();
    auto zero_alloc = Element::allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    // perturbation vector in evaluation representation
    auto result = std::make_shared<Matrix<Element>>(zero_alloc, k + 2, 1);
    z_sample_sigma_p(n, s, c, T, dgg, dgg_large_sigma, result);

    return result;
}

/**
 * @brief Perturbation generation (Algorithm 4 of https://eprint.iacr.org/2017/844.pdf) specialized for RnsPoly:
 * the covariance polynomials and the trapdoor products are computed on the first CRT tower as NativePoly, and the
 * sampled integer vectors are split back into RnsPoly elements.
 * @param n ring dimension
 * @param s spectral bound (Gaussian parameter of the preimage)
 * @param sigma standard deviation of the trapdoor noise, (base + 1) * SIGMA
 * @param Tprime trapdoor pair (r, e)
 * @param dgg discrete Gaussian generator for the 2x2 sampling and for Karney sampling above KARNEY_THRESHOLD
 * @param dgg_large_sigma discrete Gaussian generator with parameter sqrt(s^2 - sigma^2), used for the k lower
 * entries when that parameter is at most KARNEY_THRESHOLD
 * @param perturbation_vector output: (k + 2) x 1 perturbation vector in evaluation representation
 */
template <>
inline void RlweTrapdoorUtility<RnsPoly>::z_sample_sigma_p(size_t n, double s, double sigma,
                                                           const RlweTrapdoorPair<RnsPoly>& tprime,
                                                           const RnsPoly::DggType& dgg,
                                                           const RnsPoly::DggType& dgg_large_sigma,
                                                           std::shared_ptr<Matrix<RnsPoly>> perturbation_vector) {
    CIPHER_DEBUG_FLAG(false);
    TimeVar t1, t1_tot;

    TIC(t1);
    TIC(t1_tot);
    Matrix<RnsPoly> tprime0 = tprime.e_;
    Matrix<RnsPoly> tprime1 = tprime.r_;
    // k is the bit length
    size_t k = tprime0.get_cols();

    const std::shared_ptr<RnsPoly::Params> params = tprime0(0, 0).get_params();

    CIPHER_DEBUG("z1a: " << TOC(t1));  // 0
    TIC(t1);
    // all three Polynomials are initialized with "0" coefficients
    NativePoly va((*params)[0], Format::EVALUATION, 1);
    NativePoly vb((*params)[0], Format::EVALUATION, 1);
    NativePoly vd((*params)[0], Format::EVALUATION, 1);

    for (size_t i = 0; i < k; i++) {
        va += (NativePoly)tprime0(0, i).get_element_at_index(0) * tprime0(0, i).transposed().get_element_at_index(0);
        vb += (NativePoly)tprime1(0, i).get_element_at_index(0) * tprime0(0, i).transposed().get_element_at_index(0);
        vd += (NativePoly)tprime1(0, i).get_element_at_index(0) * tprime1(0, i).transposed().get_element_at_index(0);
    }
    CIPHER_DEBUG("z1b: " << TOC(t1));  // 9
    TIC(t1);

    // Switch the ring elements (Polynomials) to coefficient representation
    va.set_format(Format::COEFFICIENT);
    vb.set_format(Format::COEFFICIENT);
    vd.set_format(Format::COEFFICIENT);

    CIPHER_DEBUG("z1c: " << TOC(t1));  // 5
    TIC(t1);

    // Create field elements from ring elements
    Field2n a(va), b(vb), d(vd);

    double scalar_factor = -s * s * sigma * sigma / (s * s - sigma * sigma);

    a = a.scalar_mult(scalar_factor);
    b = b.scalar_mult(scalar_factor);
    d = d.scalar_mult(scalar_factor);

    a = a + s * s;
    d = d + s * s;
    CIPHER_DEBUG("z1d: " << TOC(t1));  // 0
    TIC(t1);

    // converts the field elements to DFT representation
    a.set_format(Format::EVALUATION);
    b.set_format(Format::EVALUATION);
    d.set_format(Format::EVALUATION);
    CIPHER_DEBUG("z1e: " << TOC(t1));  // 0
    TIC(t1);

    Matrix<int64_t> p2_z_vector([]() { return 0; }, n * k, 1);

    double sigma_large = std::sqrt(s * s - sigma * sigma);

    // for distribution parameters up to KARNEY_THRESHOLD (experimentally found
    // threshold) use the Peikert's inversion method otherwise, use Karney's
    // method
    if (sigma_large > KARNEY_THRESHOLD) {
        // Karney rejection sampling method
        for (size_t i = 0; i < n * k; i++) {
            p2_z_vector(i, 0) = dgg.generate_integer_karney(0, sigma_large);
        }
    } else {
        // Peikert's inversion sampling method
        auto dgg_vector = dgg_large_sigma.generate_int_vector(n * k);
        for (size_t i = 0; i < n * k; i++)
            p2_z_vector(i, 0) = dgg_vector[i];
    }
    CIPHER_DEBUG("z1f1: " << TOC(t1));
    TIC(t1);

    // create k ring elements in coefficient representation
    Matrix<RnsPoly> p2 = split_int64_into_elements<RnsPoly>(p2_z_vector, n, params);
    CIPHER_DEBUG("z1f2: " << TOC(t1));
    TIC(t1);

    // now converting to Format::EVALUATION representation before multiplication
    p2.set_format(Format::EVALUATION);

    CIPHER_DEBUG("z1g: " << TOC(t1));  // 17

    TIC(t1);

    auto zero_alloc = NativePoly::allocator((*params)[0], Format::EVALUATION);
    Matrix<NativePoly> tp2(zero_alloc, 2, 1);
    for (unsigned int i = 0; i < k; i++) {
        tp2(0, 0) += tprime0(0, i).get_element_at_index(0) * (NativePoly)p2(i, 0).get_element_at_index(0);
        tp2(1, 0) += tprime1(0, i).get_element_at_index(0) * (NativePoly)p2(i, 0).get_element_at_index(0);
    }

    CIPHER_DEBUG("z1h2: " << TOC(t1));
    TIC(t1);
    // change to coefficient representation before converting to field elements
    tp2.set_format(Format::COEFFICIENT);
    CIPHER_DEBUG("z1h3: " << TOC(t1));
    TIC(t1);

    Matrix<Field2n> c([]() { return Field2n(); }, 2, 1);

    c(0, 0) = Field2n(tp2(0, 0)).scalar_mult(-sigma * sigma / (s * s - sigma * sigma));
    c(1, 0) = Field2n(tp2(1, 0)).scalar_mult(-sigma * sigma / (s * s - sigma * sigma));

    auto p1_z_vector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * 2, 1);
    CIPHER_DEBUG("z1i: " << TOC(t1));
    TIC(t1);

    LatticeGaussSampUtility<RnsPoly>::z_sample_sigma2x2(a, b, d, c, dgg, p1_z_vector);
    CIPHER_DEBUG("z1j1: " << TOC(t1));  // 14
    TIC(t1);

    // create 2 ring elements in coefficient representation
    Matrix<RnsPoly> p1 = split_int64_into_elements<RnsPoly>(*p1_z_vector, n, params);
    CIPHER_DEBUG("z1j2: " << TOC(t1));
    TIC(t1);

    p1.set_format(Format::EVALUATION);
    CIPHER_DEBUG("z1j3: " << TOC(t1));
    TIC(t1);

    *perturbation_vector = p1.v_stack(p2);
    CIPHER_DEBUG("z1j4: " << TOC(t1));
    TIC(t1);
    CIPHER_DEBUG("z1tot: " << TOC(t1_tot));
}

}  // namespace cipher

#endif  // CIPHER_RING_TRAPDOOR_IMPL_H_
