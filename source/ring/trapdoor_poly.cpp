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
  Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf.
 */

#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>

#include "cipher/ring/gaussian_sampling_impl.h"
#include "cipher/ring/backend.h"
#include "cipher/ring/trapdoor_impl.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/util/debug.h"

namespace cipher {

template <>
std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> RlweTrapdoorUtility<Poly>::trapdoor_gen(
        std::shared_ptr<typename Poly::Params> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc = Poly::allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::make_discrete_gaussian_coefficient_allocator(params, COEFFICIENT, stddev);
    auto uniform_alloc = Poly::make_discrete_uniform_allocator(params, EVALUATION);

    double val = params->get_modulus().convert_to_double();
    double n_bits = std::floor(std::log2(val - 1.0) + 1.0);

    size_t k = std::ceil(n_bits / std::log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<Poly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<Poly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.set_format(Format::EVALUATION);
    e.set_format(Format::EVALUATION);

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).gadget_vector(base);

    Matrix<Poly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>>(A, RlweTrapdoorPair<Poly>(r, e));
}

template <>
std::pair<Matrix<NativePoly>, RlweTrapdoorPair<NativePoly>> RlweTrapdoorUtility<NativePoly>::trapdoor_gen(
        std::shared_ptr<typename NativePoly::Params> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc = NativePoly::allocator(params, EVALUATION);
    auto gaussian_alloc = NativePoly::make_discrete_gaussian_coefficient_allocator(params, COEFFICIENT, stddev);
    auto uniform_alloc = NativePoly::make_discrete_uniform_allocator(params, EVALUATION);

    double val = params->get_modulus().convert_to_double();
    double n_bits = std::floor(std::log2(val - 1.0) + 1.0);

    size_t k = std::ceil(n_bits / std::log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<NativePoly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<NativePoly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.set_format(Format::EVALUATION);
    e.set_format(Format::EVALUATION);

    Matrix<NativePoly> g = Matrix<NativePoly>(zero_alloc, 1, k).gadget_vector(base);

    Matrix<NativePoly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<NativePoly>, RlweTrapdoorPair<NativePoly>>(A, RlweTrapdoorPair<NativePoly>(r, e));
}

template <>
std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>> RlweTrapdoorUtility<Poly>::trapdoor_gen_square_mat(
        std::shared_ptr<typename Poly::Params> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc = Poly::allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::make_discrete_gaussian_coefficient_allocator(params, COEFFICIENT, stddev);
    auto uniform_alloc = Poly::make_discrete_uniform_allocator(params, EVALUATION);

    double val = params->get_modulus().convert_to_double();
    double n_bits = std::ceil(std::log2(val));

    size_t k = std::ceil(n_bits / std::log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<Poly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<Poly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<Poly> abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.set_format(Format::EVALUATION);
    E.set_format(Format::EVALUATION);

    Matrix<Poly> G = Matrix<Poly>(zero_alloc, d, d * k).gadget_vector(base);

    Matrix<Poly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<Poly> A1 = G - (abar * R + E);

    A.h_stack(A1);

    return std::pair<Matrix<Poly>, RlweTrapdoorPair<Poly>>(A, RlweTrapdoorPair<Poly>(R, E));
}

template <>
std::pair<Matrix<NativePoly>, RlweTrapdoorPair<NativePoly>> RlweTrapdoorUtility<NativePoly>::trapdoor_gen_square_mat(
        std::shared_ptr<typename NativePoly::Params> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc = NativePoly::allocator(params, EVALUATION);
    auto gaussian_alloc = NativePoly::make_discrete_gaussian_coefficient_allocator(params, COEFFICIENT, stddev);
    auto uniform_alloc = NativePoly::make_discrete_uniform_allocator(params, EVALUATION);

    double val = params->get_modulus().convert_to_double();
    double n_bits = std::ceil(std::log2(val));

    size_t k = std::ceil(n_bits / std::log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<NativePoly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<NativePoly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<NativePoly> abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.set_format(Format::EVALUATION);
    E.set_format(Format::EVALUATION);

    Matrix<NativePoly> G = Matrix<NativePoly>(zero_alloc, d, d * k).gadget_vector(base);

    Matrix<NativePoly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<NativePoly> A1 = G - (abar * R + E);

    A.h_stack(A1);

    return std::pair<Matrix<NativePoly>, RlweTrapdoorPair<NativePoly>>(A, RlweTrapdoorPair<NativePoly>(R, E));
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<Poly> RlweTrapdoorUtility<Poly>::gauss_samp(size_t n, size_t k, const Matrix<Poly>& A,
                                                   const RlweTrapdoorPair<Poly>& T, const Poly& u,
                                                   typename Poly::DggType& dgg, typename Poly::DggType& dgg_large_sigma,
                                                   int64_t base) {
    CIPHER_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<typename Poly::Params> params = u.get_params();
    auto zero_alloc = Poly::allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename Poly::Integer& modulus = A(0, 0).get_modulus();

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    CIPHER_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<Poly>>(zero_alloc, k + 2, 1);
    CIPHER_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    z_sample_sigma_p(n, s, c, T, dgg, dgg_large_sigma, p_hat);
    CIPHER_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and p_hat has the dimension
    // of (k + 2) x 1 perturbed_syndrome is in the evaluation representation
    Poly perturbed_syndrome = u - (A.mult(*p_hat))(0, 0);

    CIPHER_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);
    CIPHER_DEBUG("t1d: " << TOC(t1));     // takes 0
    CIPHER_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbed_syndrome.set_format(Format::COEFFICIENT);
    CIPHER_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);
    LatticeGaussSampUtility<Poly>::gauss_samp_gq_arb_base(perturbed_syndrome, c, k, modulus, base, dgg, &z_hat_bbi);
    CIPHER_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert z_hat from a matrix of BBI to a vector of Element ring elements
    // z_hat is in the coefficient representation
    Matrix<Poly> z_hat = split_int64_alt_into_elements<Poly>(z_hat_bbi, n, params);

    CIPHER_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    z_hat.set_format(Format::EVALUATION);
    CIPHER_DEBUG("t2d: " << TOC(t2));  // takes 17
    CIPHER_DEBUG("t2: " << TOC(t2_tot));
    // TIC(t3); seems trivial
    Matrix<Poly> z_hat_prime(zero_alloc, k + 2, 1);

    z_hat_prime(0, 0) = (*p_hat)(0, 0) + T.e_.mult(z_hat)(0, 0);
    z_hat_prime(1, 0) = (*p_hat)(1, 0) + T.r_.mult(z_hat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        z_hat_prime(row, 0) = (*p_hat)(row, 0) + z_hat(row - 2, 0);

    return z_hat_prime;
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<NativePoly> RlweTrapdoorUtility<NativePoly>::gauss_samp(size_t n, size_t k, const Matrix<NativePoly>& A,
                                                               const RlweTrapdoorPair<NativePoly>& T,
                                                               const NativePoly& u, typename NativePoly::DggType& dgg,
                                                               typename NativePoly::DggType& dgg_large_sigma,
                                                               int64_t base) {
    CIPHER_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<typename NativePoly::Params> params = u.get_params();
    auto zero_alloc = NativePoly::allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename NativePoly::Integer& modulus = A(0, 0).get_modulus();

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    CIPHER_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<NativePoly>>(zero_alloc, k + 2, 1);
    CIPHER_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    z_sample_sigma_p(n, s, c, T, dgg, dgg_large_sigma, p_hat);
    CIPHER_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and p_hat has the dimension
    // of (k + 2) x 1 perturbed_syndrome is in the evaluation representation
    NativePoly perturbed_syndrome = u - (A.mult(*p_hat))(0, 0);

    CIPHER_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);
    CIPHER_DEBUG("t1d: " << TOC(t1));     // takes 0
    CIPHER_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbed_syndrome.set_format(Format::COEFFICIENT);
    CIPHER_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);
    LatticeGaussSampUtility<NativePoly>::gauss_samp_gq_arb_base(perturbed_syndrome, c, k, modulus, base, dgg,
                                                                &z_hat_bbi);
    CIPHER_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert z_hat from a matrix of BBI to a vector of Element ring elements
    // z_hat is in the coefficient representation
    Matrix<NativePoly> z_hat = split_int64_alt_into_elements<NativePoly>(z_hat_bbi, n, params);

    CIPHER_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    z_hat.set_format(Format::EVALUATION);
    CIPHER_DEBUG("t2d: " << TOC(t2));  // takes 17
    CIPHER_DEBUG("t2: " << TOC(t2_tot));
    // TIC(t3); seems trivial
    Matrix<NativePoly> z_hat_prime(zero_alloc, k + 2, 1);

    z_hat_prime(0, 0) = (*p_hat)(0, 0) + T.e_.mult(z_hat)(0, 0);
    z_hat_prime(1, 0) = (*p_hat)(1, 0) + T.r_.mult(z_hat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        z_hat_prime(row, 0) = (*p_hat)(row, 0) + z_hat(row - 2, 0);

    return z_hat_prime;
}

// Gaussian sampling as described in "Implementing Token-Based Obfuscation under
// Ring (LWE)"

template <>
Matrix<Poly> RlweTrapdoorUtility<Poly>::gauss_samp_square_mat(size_t n, size_t k, const Matrix<Poly>& A,
                                                              const RlweTrapdoorPair<Poly>& T, const Matrix<Poly>& U,
                                                              typename Poly::DggType& dgg,
                                                              typename Poly::DggType& dgg_large_sigma, int64_t base) {
    const std::shared_ptr<typename Poly::Params> params = U(0, 0).get_params();
    auto zero_alloc = Poly::allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename Poly::Integer& modulus = A(0, 0).get_modulus();

    size_t d = T.r_.get_rows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<Poly>>(zero_alloc, d * (k + 2), d);

    sample_pert_square_mat(n, s, c, T, dgg, dgg_large_sigma, p_hat);

    // It is assumed that A has dimension d x d*(k + 2) and p_hat has the dimension
    // of d*(k + 2) x d perturbed_syndrome is in the evaluation representation
    Matrix<Poly> perturbed_syndrome = U - (A.mult(*p_hat));

    perturbed_syndrome.set_format(Format::COEFFICIENT);

    Matrix<Poly> z_hat_mat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);

            LatticeGaussSampUtility<Poly>::gauss_samp_gq_arb_base(perturbed_syndrome(i, j), c, k, modulus, base, dgg,
                                                                  &z_hat_bbi);

            // Convert z_hat from a matrix of BBI to a vector of Poly ring elements
            // z_hat is in the coefficient representation
            Matrix<Poly> z_hat = split_int64_alt_into_elements<Poly>(z_hat_bbi, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            z_hat.set_format(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                z_hat_mat(i * k + p, j) = z_hat(p, 0);
        }
    }

    Matrix<Poly> z_hat_prime(zero_alloc, d * (k + 2), d);

    Matrix<Poly> r_zhat = T.r_.mult(z_hat_mat);  // d x d
    Matrix<Poly> e_zhat = T.e_.mult(z_hat_mat);  // d x d

    for (size_t j = 0; j < d; j++) {  // columns
        for (size_t i = 0; i < d; i++) {
            z_hat_prime(i, j) = (*p_hat)(i, j) + r_zhat(i, j);
            z_hat_prime(i + d, j) = (*p_hat)(i + d, j) + e_zhat(i, j);

            for (size_t p = 0; p < k; p++) {
                z_hat_prime(i * k + p + 2 * d, j) = (*p_hat)(i * k + p + 2 * d, j) + z_hat_mat(i * k + p, j);
            }
        }
    }

    return z_hat_prime;
}

template <>
Matrix<NativePoly> RlweTrapdoorUtility<NativePoly>::gauss_samp_square_mat(
        size_t n, size_t k, const Matrix<NativePoly>& A, const RlweTrapdoorPair<NativePoly>& T,
        const Matrix<NativePoly>& U, typename NativePoly::DggType& dgg, typename NativePoly::DggType& dgg_large_sigma,
        int64_t base) {
    const std::shared_ptr<typename NativePoly::Params> params = U(0, 0).get_params();
    auto zero_alloc = NativePoly::allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename NativePoly::Integer& modulus = A(0, 0).get_modulus();

    size_t d = T.r_.get_rows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<NativePoly>>(zero_alloc, d * (k + 2), d);

    sample_pert_square_mat(n, s, c, T, dgg, dgg_large_sigma, p_hat);

    // It is assumed that A has dimension d x d*(k + 2) and p_hat has the dimension
    // of d*(k + 2) x d perturbed_syndrome is in the evaluation representation
    Matrix<NativePoly> perturbed_syndrome = U - (A.mult(*p_hat));

    perturbed_syndrome.set_format(Format::COEFFICIENT);

    Matrix<NativePoly> z_hat_mat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);

            LatticeGaussSampUtility<NativePoly>::gauss_samp_gq_arb_base(perturbed_syndrome(i, j), c, k, modulus, base,
                                                                        dgg, &z_hat_bbi);

            // Convert z_hat from a matrix of BBI to a vector of NativePoly ring
            // elements z_hat is in the coefficient representation
            Matrix<NativePoly> z_hat = split_int64_alt_into_elements<NativePoly>(z_hat_bbi, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            z_hat.set_format(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                z_hat_mat(i * k + p, j) = z_hat(p, 0);
        }
    }

    Matrix<NativePoly> z_hat_prime(zero_alloc, d * (k + 2), d);

    Matrix<NativePoly> r_zhat = T.r_.mult(z_hat_mat);  // d x d
    Matrix<NativePoly> e_zhat = T.e_.mult(z_hat_mat);  // d x d

    for (size_t j = 0; j < d; j++) {  // columns
        for (size_t i = 0; i < d; i++) {
            z_hat_prime(i, j) = (*p_hat)(i, j) + r_zhat(i, j);
            z_hat_prime(i + d, j) = (*p_hat)(i + d, j) + e_zhat(i, j);

            for (size_t p = 0; p < k; p++) {
                z_hat_prime(i * k + p + 2 * d, j) = (*p_hat)(i * k + p + 2 * d, j) + z_hat_mat(i * k + p, j);
            }
        }
    }

    return z_hat_prime;
}

template class LatticeGaussSampUtility<Poly>;
template class RlweTrapdoorPair<Poly>;
template class RlweTrapdoorUtility<Poly>;

template class LatticeGaussSampUtility<NativePoly>;
template class RlweTrapdoorPair<NativePoly>;
template class RlweTrapdoorUtility<NativePoly>;

}  // namespace cipher
