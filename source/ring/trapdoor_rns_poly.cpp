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

#include <cstdint>
#include <memory>
#include <utility>

#include "cipher/ring/gaussian_sampling_impl.h"
#include "cipher/ring/backend.h"
#include "cipher/ring/trapdoor_impl.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/util/debug.h"

namespace cipher {

// Trapdoor generation method as described in Algorithm 1 of
// https://eprint.iacr.org/2017/844.pdf and
// "Implementing Token-Based Obfuscation under (Ring) LWE"
template <>
std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>> RlweTrapdoorUtility<RnsPoly>::trapdoor_gen(
        std::shared_ptr<ParmType> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc = RnsPoly::allocator(params, Format::EVALUATION);
    auto gaussian_alloc = RnsPoly::make_discrete_gaussian_coefficient_allocator(params, Format::COEFFICIENT, stddev);
    auto uniform_alloc = RnsPoly::make_discrete_uniform_allocator(params, Format::EVALUATION);

    NativeInteger q = params->get_params()[0]->get_modulus();

    size_t digit_count = get_digit_count(q.convert_to_int(), static_cast<uint64_t>(base));

    size_t k = params->get_params().size() * digit_count;

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<RnsPoly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<RnsPoly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.set_format(Format::EVALUATION);
    e.set_format(Format::EVALUATION);

    Matrix<RnsPoly> g = Matrix<RnsPoly>(zero_alloc, 1, k).gadget_vector(base);

    Matrix<RnsPoly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>>(A, RlweTrapdoorPair<RnsPoly>(r, e));
}

template <>
std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>> RlweTrapdoorUtility<RnsPoly>::trapdoor_gen_square_mat(
        std::shared_ptr<ParmType> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc = RnsPoly::allocator(params, Format::EVALUATION);
    auto gaussian_alloc = RnsPoly::make_discrete_gaussian_coefficient_allocator(params, Format::COEFFICIENT, stddev);
    auto uniform_alloc = RnsPoly::make_discrete_uniform_allocator(params, Format::EVALUATION);

    NativeInteger q = params->get_params()[0]->get_modulus();

    size_t digit_count = get_digit_count(q.convert_to_int(), static_cast<uint64_t>(base));

    size_t k = params->get_params().size() * digit_count;

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<RnsPoly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<RnsPoly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<RnsPoly> abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.set_format(Format::EVALUATION);
    E.set_format(Format::EVALUATION);

    Matrix<RnsPoly> G = Matrix<RnsPoly>(zero_alloc, d, d * k).gadget_vector(base);

    Matrix<RnsPoly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<RnsPoly> A1 = G - (abar * R + E);

    A.h_stack(A1);

    return std::pair<Matrix<RnsPoly>, RlweTrapdoorPair<RnsPoly>>(A, RlweTrapdoorPair<RnsPoly>(R, E));
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<RnsPoly> RlweTrapdoorUtility<RnsPoly>::gauss_samp(size_t n, size_t k, const Matrix<RnsPoly>& A,
                                                         const RlweTrapdoorPair<RnsPoly>& T, const RnsPoly& u,
                                                         DggType& dgg, DggType& dgg_large_sigma, int64_t base) {
    CIPHER_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<ParmType> params = u.get_params();
    auto zero_alloc = RnsPoly::allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    CIPHER_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<RnsPoly>>(zero_alloc, k + 2, 1);
    CIPHER_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    z_sample_sigma_p(n, s, c, T, dgg, dgg_large_sigma, p_hat);
    CIPHER_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and p_hat has the dimension
    // of (k + 2) x 1 perturbed_syndrome is in the evaluation representation
    RnsPoly perturbed_syndrome = u - (A.mult(*p_hat))(0, 0);

    CIPHER_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    CIPHER_DEBUG("t1d: " << TOC(t1));  // takes 0
    Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);
    CIPHER_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbed_syndrome.set_format(Format::COEFFICIENT);
    CIPHER_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);

    size_t size = perturbed_syndrome.get_num_of_elements();

    for (size_t u = 0; u < size; u++) {
        uint32_t k_res = k / size;

        NativeInteger qu = params->get_params()[u]->get_modulus();

        Matrix<int64_t> digits([]() { return 0; }, k_res, n);
        LatticeGaussSampUtility<NativePoly>::gauss_samp_gq_arb_base(perturbed_syndrome.get_element_at_index(u), c,
                                                                    k_res, qu, base, dgg, &digits);
        for (size_t p = 0; p < k_res; p++) {
            for (size_t j = 0; j < n; j++) {
                z_hat_bbi(p + u * k_res, j) = digits(p, j);
            }
        }
    }

    CIPHER_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert z_hat from a matrix of BBI to a vector of Element ring elements
    // z_hat is in the coefficient representation
    Matrix<RnsPoly> z_hat = split_int64_alt_into_elements<RnsPoly>(z_hat_bbi, n, params);

    CIPHER_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    z_hat.set_format(Format::EVALUATION);
    CIPHER_DEBUG("t2d: " << TOC(t2));  // takes 17
    CIPHER_DEBUG("t2: " << TOC(t2_tot));

    Matrix<RnsPoly> z_hat_prime(zero_alloc, k + 2, 1);

    z_hat_prime(0, 0) = (*p_hat)(0, 0) + T.e_.mult(z_hat)(0, 0);
    z_hat_prime(1, 0) = (*p_hat)(1, 0) + T.r_.mult(z_hat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        z_hat_prime(row, 0) = (*p_hat)(row, 0) + z_hat(row - 2, 0);

    return z_hat_prime;
}

// Gaussian sampling as described in "Implementing Token-Based Obfuscation under
// Ring (LWE)"

template <>
Matrix<RnsPoly> RlweTrapdoorUtility<RnsPoly>::gauss_samp_square_mat(size_t n, size_t k, const Matrix<RnsPoly>& A,
                                                                    const RlweTrapdoorPair<RnsPoly>& T,
                                                                    const Matrix<RnsPoly>& U, DggType& dgg,
                                                                    DggType& dgg_large_sigma, int64_t base) {
    const std::shared_ptr<ParmType> params = U(0, 0).get_params();
    auto zero_alloc = RnsPoly::allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    size_t d = T.r_.get_rows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto p_hat = std::make_shared<Matrix<RnsPoly>>(zero_alloc, d * (k + 2), d);

    sample_pert_square_mat(n, s, c, T, dgg, dgg_large_sigma, p_hat);

    // It is assumed that A has dimension d x d*(k + 2) and p_hat has the dimension
    // of d*(k + 2) x d perturbed_syndrome is in the evaluation representation
    Matrix<RnsPoly> perturbed_syndrome = U - (A.mult(*p_hat));

    perturbed_syndrome.set_format(Format::COEFFICIENT);

    size_t size = perturbed_syndrome(0, 0).get_num_of_elements();

    Matrix<RnsPoly> z_hat_mat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> z_hat_bbi([]() { return 0; }, k, n);

            for (size_t u = 0; u < size; u++) {
                uint32_t k_res = k / size;

                NativeInteger qu = params->get_params()[u]->get_modulus();

                Matrix<int64_t> digits([]() { return 0; }, k_res, n);

                LatticeGaussSampUtility<NativePoly>::gauss_samp_gq_arb_base(
                        perturbed_syndrome(i, j).get_element_at_index(u), c, k_res, qu, base, dgg, &digits);

                for (size_t p = 0; p < k_res; p++) {
                    for (size_t jj = 0; jj < n; jj++) {
                        z_hat_bbi(p + u * k_res, jj) = digits(p, jj);
                    }
                }
            }

            // Convert z_hat from a matrix of BBI to a vector of RnsPoly ring elements
            // z_hat is in the coefficient representation
            Matrix<RnsPoly> z_hat = split_int64_alt_into_elements<RnsPoly>(z_hat_bbi, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            z_hat.set_format(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                z_hat_mat(i * k + p, j) = z_hat(p, 0);
        }
    }

    Matrix<RnsPoly> z_hat_prime(zero_alloc, d * (k + 2), d);

    Matrix<RnsPoly> r_zhat = T.r_.mult(z_hat_mat);  // d x d
    Matrix<RnsPoly> e_zhat = T.e_.mult(z_hat_mat);  // d x d

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

template class LatticeGaussSampUtility<RnsPoly>;
template class RlweTrapdoorPair<RnsPoly>;
template class RlweTrapdoorUtility<RnsPoly>;

}  // namespace cipher
