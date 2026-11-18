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
  Provides detailed algorithms for G-sampling and perturbation sampling as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf
 */

#ifndef CIPHER_RING_GAUSSIAN_SAMPLING_IMPL_H_
#define CIPHER_RING_GAUSSIAN_SAMPLING_IMPL_H_

#include <cmath>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "cipher/ring/gaussian_sampling.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/parallel.h"

namespace cipher {

// Gaussian sampling from lattice for gagdet matrix G, syndrome u, and arbitrary
// modulus q Discrete sampling variant As described in Figure 2 of
// https://eprint.iacr.org/2017/308.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::gauss_samp_gq(const Element& syndrome, double stddev, size_t k,
                                                     const typename Element::Integer& q, int64_t base,
                                                     typename Element::DggType& dgg, Matrix<int64_t>* z) {
    // If DCRT is used, the polynomial is first converted from DCRT to large
    // polynomial (in COEFFICIENT representation)
    typename Element::PolyLargeType u = syndrome.crt_interpolate();

    const typename Poly::Integer& modulus = u.get_params()->get_modulus();
    double sigma = stddev / (base + 1);

    std::vector<int64_t> digits_ = *(get_digits(modulus, base, k));

    // main diagonal of matrix L
    std::vector<double> l(k);
    // upper diagonal of matrix L
    std::vector<double> h(k);

    // Matrix<double> a([]() { return 0.0; }, k, 1);
    Matrix<double> c([]() { return 0.0; }, k, 1);

    //  set the values of matrix L
    // (double) is added to avoid integer division
    l[0] = std::sqrt(base * (1 + 1 / k) + 1);
    for (size_t i = 1; i < k; i++)
        l[i] = std::sqrt(base * (1 + 1 / static_cast<double>(k - i)));

    h[0] = 0;
    // (double) is added to avoid integer division
    for (size_t i = 1; i < k; i++)
        h[i] = std::sqrt(base * (1 - 1 / static_cast<double>(k - (i - 1))));

    // c can be pre-computed as it only depends on the modulus
    // (double) is added to avoid integer division
    c(0, 0) = digits_[0] / static_cast<double>(base);

    for (size_t i = 1; i < k; i++)
        c(i, 0) = (c(i - 1, 0) + digits_[i]) / base;

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(u.get_length()))
    for (size_t j = 0; j < u.get_length(); j++) {
        typename Element::Integer v(u.at(j));

        std::vector<int64_t> p(k);

        LatticeGaussSampUtility<Element>::perturb(sigma, k, u.get_length(), l, h, base, dgg, &p);

        Matrix<double> a([]() { return 0.0; }, k, 1);

        std::vector<int64_t> v_digits = *(get_digits(v, base, k));

        // int64_t cast is needed here as get_digit_at_index_for_base returns an unsigned
        // int when the result is negative, a(0,0) gets values close to 2^64 if the
        // cast is not used (double) is added to avoid integer division
        a(0, 0) = ((int64_t)(v_digits[0]) - p[0]) / static_cast<double>(base);

        for (size_t t = 1; t < k; t++) {
            a(t, 0) = (a(t - 1, 0) + (int64_t)(v_digits[t]) - p[t]) / base;
        }
        std::vector<int64_t> zj(k);

        LatticeGaussSampUtility<Element>::sample_c(c, k, u.get_length(), sigma, dgg, &a, &zj);

        (*z)(0, j) = base * zj[0] + (int64_t)(digits_[0]) * zj[k - 1] + (int64_t)(v_digits[0]);

        for (size_t t = 1; t < k - 1; t++) {
            (*z)(t, j) = base * zj[t] - zj[t - 1] + (int64_t)(digits_[t]) * zj[k - 1] + (int64_t)(v_digits[t]);
        }
        (*z)(k - 1, j) = (int64_t)(digits_[k - 1]) * zj[k - 1] - zj[k - 2] + (int64_t)(v_digits[k - 1]);
    }
}

// Gaussian sampling from lattice for gagdet matrix G, syndrome u, and arbitrary
// modulus q Continuous sampling variant As described in Algorithm 3 of
// https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::gauss_samp_gq_arb_base(const Element& syndrome, double stddev, size_t k,
                                                              const typename Element::Integer& q, int64_t base,
                                                              typename Element::DggType& dgg, Matrix<int64_t>* z) {
    // If DCRT is used, the polynomial is first converted from DCRT to large
    // polynomial (in Format::COEFFICIENT representation)
    typename Element::PolyLargeType u = syndrome.crt_interpolate();

    const typename Poly::Integer& modulus = u.get_params()->get_modulus();
    double sigma = stddev / (base + 1);

    std::vector<int64_t> digits_ = *(get_digits(modulus, base, k));

    // main diagonal of matrix L
    std::vector<double> l(k);
    // upper diagonal of matrix L
    std::vector<double> h(k);

    // Matrix<double> a([]() { return 0.0; }, k, 1);
    Matrix<double> c([]() { return 0.0; }, k, 1);

    //  set the values of matrix L
    // (double) is added to avoid integer division
    l[0] = std::sqrt(base * (1 + 1 / k) + 1);
    for (size_t i = 1; i < k; i++)
        l[i] = std::sqrt(base * (1 + 1 / static_cast<double>(k - i)));

    h[0] = 0;
    // (double) is added to avoid integer division
    for (size_t i = 1; i < k; i++)
        h[i] = std::sqrt(base * (1 - 1 / static_cast<double>(k - (i - 1))));

    // c can be pre-computed as it only depends on the modulus
    // (double) is added to avoid integer division
    c(0, 0) = ((int64_t)digits_[0]) / static_cast<double>(base);

    for (size_t i = 1; i < k; i++)
        c(i, 0) = (c(i - 1, 0) + (int64_t)digits_[i]) / static_cast<double>(base);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(u.get_length()))
    for (size_t j = 0; j < u.get_length(); j++) {
        typename Element::Integer v(u.at(j));

        std::vector<int64_t> v_digits = *(get_digits(v, base, k));

        std::vector<double> p(k);

        LatticeGaussSampUtility<Element>::perturb_float(sigma, k, u.get_length(), l, h, base, dgg, &p);

        Matrix<double> a([]() { return 0.0; }, k, 1);

        // int64_t cast is needed here as get_digit_at_index_for_base returns an unsigned
        // int when the result is negative, a(0,0) gets values close to 2^64 if the
        // cast is not used (double) is added to avoid integer division
        a(0, 0) = ((int64_t)(v_digits[0]) - p[0]) / static_cast<double>(base);

        for (size_t t = 1; t < k; t++) {
            a(t, 0) = (a(t - 1, 0) + (int64_t)(v_digits[t]) - p[t]) / static_cast<double>(base);
        }
        std::vector<int64_t> zj(k);

        LatticeGaussSampUtility<Element>::sample_c(c, k, u.get_length(), sigma, dgg, &a, &zj);

        (*z)(0, j) = base * zj[0] + (int64_t)(digits_[0]) * zj[k - 1] + (int64_t)(v_digits[0]);

        for (size_t t = 1; t < k - 1; t++) {
            (*z)(t, j) = base * zj[t] - zj[t - 1] + (int64_t)(digits_[t]) * zj[k - 1] + (int64_t)(v_digits[t]);
        }
        (*z)(k - 1, j) = (int64_t)(digits_[k - 1]) * zj[k - 1] - zj[k - 2] + (int64_t)(v_digits[k - 1]);
    }
}

// subroutine used by gauss_samp_gq
// Discrete sampling variant
// As described in Figure 2 of https://eprint.iacr.org/2017/308.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::perturb(double sigma, size_t k, size_t n, const std::vector<double>& l,
                                               const std::vector<double>& h, int64_t base,
                                               typename Element::DggType& dgg, std::vector<int64_t>* p) {
    std::vector<int32_t> z(k);
    double d = 0;

    for (size_t i = 0; i < k; i++) {
        z[i] = dgg.generate_integer_karney(d / l[i], sigma / l[i]);
        d = -z[i] * h[i];
    }

    (*p)[0] = (2 * base + 1) * z[0] + base * z[1];
    for (size_t i = 1; i < k - 1; i++)
        (*p)[i] = base * (z[i - 1] + 2 * z[i] + z[i + 1]);
    (*p)[k - 1] = base * (z[k - 2] + 2 * z[k - 1]);
}

// subroutine used by gauss_samp_gq_arb_base
// Continuous sampling variant
// As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::perturb_float(double sigma, size_t k, size_t n, const std::vector<double>& l,
                                                     const std::vector<double>& h, int64_t base,
                                                     typename Element::DggType& dgg, std::vector<double>* p) {
    std::normal_distribution<> d(0, sigma);

    PRNG& g = PseudoRandomNumberGenerator::get_prng();

    std::vector<double> z(k);

    // Generate a vector using continuous Gaussian distribution
    for (size_t i = 0; i < k; i++)
        z[i] = d(g);

    // Compute matrix-vector product Lz (apply linear transformation)
    for (size_t i = 0; i < k - 1; i++) {
        p->at(i) = l[i] * z[i] + h[i + 1] * z[i + 1];
    }

    p->at(k - 1) = h[k - 1] * z[k - 1];
}

// subroutine used by gauss_samp_gq
// As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::sample_c(const Matrix<double>& c, size_t k, size_t n, double sigma,
                                                typename Element::DggType& dgg, Matrix<double>* a,
                                                std::vector<int64_t>* z) {
    (*z)[k - 1] = dgg.generate_integer_karney(-(*a)(k - 1, 0) / c(k - 1, 0), sigma / c(k - 1, 0));
    *a = *a + (static_cast<double>((*z)[k - 1])) * c;

    for (size_t i = 0; i < k - 1; i++) {
        (*z)[i] = dgg.generate_integer_karney(-(*a)(i, 0), sigma);
    }
}

// Subroutine used by z_sample_sigma_p as described Algorithm 4 in
// https://eprint.iacr.org/2017/844.pdf a - field element in DFT format b -
// field element in DFT format d - field element in DFT format c - vector of
// field elements in Format::COEFFICIENT format
template <class Element>
void LatticeGaussSampUtility<Element>::z_sample_sigma2x2(const Field2n& a, const Field2n& b, const Field2n& d,
                                                         const Matrix<Field2n>& c, const typename Element::DggType& dgg,
                                                         std::shared_ptr<Matrix<int64_t>> q) {
    // size of the the lattice
    size_t n = a.Size();

    Field2n d_coeff = d;
    d_coeff.set_format(Format::COEFFICIENT);

    std::shared_ptr<Matrix<int64_t>> q2_int = z_sample_f(d_coeff, c(1, 0), dgg, n);
    Field2n q2(*q2_int);

    Field2n q2_minusc2 = q2 - c(1, 0);
    // Convert to DFT representation prior to multiplication
    q2_minusc2.switch_format();

    Field2n product = b * d.inverse() * q2_minusc2;
    product.set_format(Format::COEFFICIENT);

    // Computes c1 in Format::COEFFICIENT format
    Field2n c1 = c(0, 0) + product;

    Field2n f = a - b * d.inverse() * b.transposed();
    f.set_format(Format::COEFFICIENT);

    std::shared_ptr<Matrix<int64_t>> q1_int = z_sample_f(f, c1, dgg, n);

    for (size_t i = 0; i < q1_int->get_rows(); i++) {
        (*q)(i, 0) = (*q1_int)(i, 0);
    }

    for (size_t i = 0; i < q2_int->get_rows(); i++) {
        (*q)(i + q1_int->get_rows(), 0) = (*q2_int)(i, 0);
    }
}

// Subroutine used by sample_pert_square_mat as described in "Implementing
// Token-Based Obfuscation under (Ring) LWE"

template <class Element>
void LatticeGaussSampUtility<Element>::sample_mat(const Matrix<Field2n>& A, const Matrix<Field2n>& B,
                                                  const Matrix<Field2n>& D, const Matrix<Field2n>& C,
                                                  const typename Element::DggType& dgg,
                                                  std::shared_ptr<Matrix<int64_t>> p) {
    size_t d = C.get_rows();

    if (d == 2) {
        z_sample_sigma2x2(A(0, 0), B(0, 0), D(0, 0), C, dgg, p);
        return;
    }

    size_t n = D(0, 0).Size();

    size_t dim_a = A.get_rows();
    size_t dim_d = D.get_rows();

    auto q1 = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * dim_d, 1);
    Matrix<Field2n> c0([]() { return Field2n(Format::COEFFICIENT); }, dim_a, 1);
    Matrix<Field2n> c1([]() { return Field2n(Format::COEFFICIENT); }, dim_d, 1);
    Matrix<Field2n> q_f1([]() { return Field2n(Format::COEFFICIENT); }, dim_d, 1);

    Matrix<Field2n> dinverse([]() { return Field2n(Format::EVALUATION); }, dim_d, dim_d);

    if (dim_d == 1) {
        Field2n d_eval = D(0, 0);
        d_eval.set_format(Format::COEFFICIENT);
        c1(0, 0) = C(d - 1, 0);
        c0 = C.extract_rows(0, d - 2);

        q1 = z_sample_f(d_eval, c1(0, 0), dgg, d_eval.Size());

        dinverse(0, 0) = D(0, 0).inverse();

        q_f1(0, 0) = Field2n(*q1);
    } else if (dim_d == 2) {  // dim_d == 2
        c1 = C.extract_rows(dim_a, d - 1);
        c0 = C.extract_rows(0, dim_a - 1);

        z_sample_sigma2x2(D(0, 0), D(0, 1), D(1, 1), c1, dgg, q1);

        for (size_t i = 0; i < dim_d; i++)
            q_f1(i, 0) = Field2n(q1->extract_rows(i * n, i * n + n - 1));

        Field2n det = D(0, 0) * D(1, 1) - D(0, 1) * D(1, 0);
        Field2n det_inverse = det.inverse();

        dinverse(0, 0) = D(1, 1) * det_inverse;
        dinverse(0, 1) = -D(0, 1) * det_inverse;
        dinverse(1, 0) = -D(1, 0) * det_inverse;
        dinverse(1, 1) = D(0, 0) * det_inverse;
    } else {  // dim_d > 2
        c1 = C.extract_rows(dim_a, d - 1);
        c0 = C.extract_rows(0, dim_a - 1);

        size_t new_dim_a = static_cast<size_t>(std::ceil(static_cast<double>(dim_d) / 2));
        size_t new_dim_d = static_cast<size_t>(std::floor(static_cast<double>(dim_d) / 2));

        Matrix<Field2n> new_a([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_a, new_dim_a);
        Matrix<Field2n> new_b([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_a, new_dim_d);
        Matrix<Field2n> new_d([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_d, new_dim_d);

        for (size_t i = 0; i < new_dim_a; i++)
            for (size_t j = 0; j < new_dim_a; j++)
                new_a(i, j) = D(i, j);

        for (size_t i = 0; i < new_dim_a; i++)
            for (size_t j = 0; j < new_dim_d; j++)
                new_b(i, j) = D(i, j + new_dim_a);

        for (size_t i = 0; i < new_dim_d; i++)
            for (size_t j = 0; j < new_dim_d; j++)
                new_d(i, j) = D(i + new_dim_a, j + new_dim_a);

        sample_mat(new_a, new_b, new_d, c1, dgg, q1);

        for (size_t i = 0; i < dim_d; i++)
            q_f1(i, 0) = Field2n(q1->extract_rows(i * n, i * n + n - 1));

        Field2n det(n, Format::EVALUATION, true);
        D.determinant(&det);

        Field2n det_inverse = det.inverse();

        dinverse = (D.cofactor_matrix()).transposed() * det_inverse;
    }

    Matrix<Field2n> sigma = A - B * dinverse * (B.transposed());

    Matrix<Field2n> diff = q_f1 - c1;
    diff.set_format(Format::EVALUATION);
    c0.set_format(Format::EVALUATION);

    Matrix<Field2n> c_new = c0 + B * dinverse * diff;

    c_new.set_format(Format::COEFFICIENT);

    size_t new_dim_a = static_cast<size_t>(std::ceil(static_cast<double>(dim_a) / 2));
    size_t new_dim_d = static_cast<size_t>(std::floor(static_cast<double>(dim_a) / 2));

    Matrix<Field2n> new_a([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_a, new_dim_a);
    Matrix<Field2n> new_b([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_a, new_dim_d);
    Matrix<Field2n> new_d([&]() { return Field2n(n, Format::EVALUATION, true); }, new_dim_d, new_dim_d);

    for (size_t i = 0; i < new_dim_a; i++)
        for (size_t j = 0; j < new_dim_a; j++)
            new_a(i, j) = sigma(i, j);

    for (size_t i = 0; i < new_dim_a; i++)
        for (size_t j = 0; j < new_dim_d; j++)
            new_b(i, j) = sigma(i, j + new_dim_a);

    for (size_t i = 0; i < new_dim_d; i++)
        for (size_t j = 0; j < new_dim_d; j++)
            new_d(i, j) = sigma(i + new_dim_a, j + new_dim_a);

    auto q0 = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * dim_a, 1);

    sample_mat(new_a, new_b, new_d, c_new, dgg, q0);

    *p = *q0;

    p->v_stack(*q1);

    return;
}

// Subroutine used by z_sample_sigma2x2 as described Algorithm 4 in
// https://eprint.iacr.org/2017/844.pdf f is in Format::COEFFICIENT
// representation c is in Format::COEFFICIENT representation
template <class Element>
std::shared_ptr<Matrix<int64_t>> LatticeGaussSampUtility<Element>::z_sample_f(const Field2n& f, const Field2n& c,
                                                                              const typename Element::DggType& dgg,
                                                                              size_t n) {
    if (f.Size() == 1) {
        auto p = std::make_shared<Matrix<int64_t>>([]() { return 0; }, 1, 1);
        (*p)(0, 0) = dgg.generate_integer_karney(c[0].real(), std::sqrt(f[0].real()));
        return p;
    }

    Field2n f0 = f.extract_even();
    Field2n f1 = f.extract_odd();

    f0.set_format(Format::EVALUATION);
    f1.set_format(Format::EVALUATION);

    uint32_t f0_size = f0.Size();

    auto q_z_vector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, f0_size * 2, 1);

    Matrix<Field2n> c_permuted([]() { return Field2n(); }, 2, 1);

    c_permuted(0, 0) = c.extract_even();
    c_permuted(1, 0) = c.extract_odd();
    LatticeGaussSampUtility<Element>::z_sample_sigma2x2(f0, f1, f0, c_permuted, dgg, q_z_vector);
    inverse_permute(q_z_vector);

    return q_z_vector;
}

// subroutine earlier used by z_sample_f
// Algorithm utilizes the same permutation algorithm as discussed in
// https://eprint.iacr.org/2017/844.pdf
template <class Element>
Matrix<int32_t> LatticeGaussSampUtility<Element>::permute(Matrix<int32_t>* p) {
    int even_ptr = 0;
    int odd_ptr = p->get_rows() / 2;
    Matrix<int32_t> permuted([]() { return 0; }, p->get_rows(), 1);
    for (uint32_t i = 0; i < p->get_rows(); i++) {
        if (i % 2 == 0) {
            permuted(even_ptr, 0) = (*p)(i, 0);
            even_ptr++;
        } else {
            permuted(odd_ptr, 0) = (*p)(i, 0);
            odd_ptr++;
        }
    }
    return permuted;
}

// subroutine used by z_sample_f
// Algorithm utilizes the same permutation algorithm as discussed in
// https://eprint.iacr.org/2017/844.pdf
template <class Element>
void LatticeGaussSampUtility<Element>::inverse_permute(std::shared_ptr<Matrix<int64_t>> p) {
    // a vector of int64_t is used for intermediate storage because it is faster
    // than a Matrix of unique pointers to int64_t

    std::vector<int64_t> vector_permuted(p->get_rows());

    size_t even_ptr = 0;
    size_t odd_ptr = vector_permuted.size() / 2;
    for (size_t i = 0; even_ptr < vector_permuted.size() / 2; i += 2) {
        vector_permuted[i] = (*p)(even_ptr, 0);
        vector_permuted[i + 1] = (*p)(odd_ptr, 0);
        even_ptr++;
        odd_ptr++;
    }

    for (size_t i = 0; i < vector_permuted.size(); i++) {
        (*p)(i, 0) = vector_permuted[i];
    }
}

}  // namespace cipher

#endif  // CIPHER_RING_GAUSSIAN_SAMPLING_IMPL_H_
