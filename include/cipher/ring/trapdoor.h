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
  Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf.
 */

#ifndef CIPHER_RING_TRAPDOOR_H_
#define CIPHER_RING_TRAPDOOR_H_

#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>

#include "cipher/ring/gaussian_sampling.h"
#include "cipher/ring/field2n.h"
#include "cipher/math/matrix.h"
#include "cipher/util/debug.h"

namespace cipher {

/**
 * @brief Class to store a lattice trapdoor pair generated using construction 1
 * in section 3.2 of https://eprint.iacr.org/2013/297.pdf This construction is
 * based on the hardness of Ring-LWE problem
 */
template <class Element>
class RlweTrapdoorPair {
  public:
    /** 1 x k row of discrete Gaussian polynomials r; the public key columns are g_i - (a * r_i + e_i) */
    Matrix<Element> r_;
    /** 1 x k row of discrete Gaussian polynomials e; the public key columns are g_i - (a * r_i + e_i) */
    Matrix<Element> e_;
    // CTOR with empty trapdoor pair for deserialization
    RlweTrapdoorPair()
        : r_(Matrix<Element>([]() { return Element(); }, 0, 0)),
          e_(Matrix<Element>([]() { return Element(); }, 0, 0)) {}

    /**
     * @brief Constructs the trapdoor pair from the two rows sampled by trapdoor_gen.
     * @param r row of noise polynomials r
     * @param e row of noise polynomials e
     */
    RlweTrapdoorPair(const Matrix<Element>& r, const Matrix<Element>& e) : r_(r), e_(e) {}

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::make_nvp("m_r", r_));
        ar(cereal::make_nvp("m_e", e_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::make_nvp("m_r", r_));
        ar(cereal::make_nvp("m_e", e_));
    }
};

/**
 * @brief Static class implementing lattice trapdoor construction in Algorithm 1
 * of https://eprint.iacr.org/2017/844.pdf
 */
template <class Element>
class RlweTrapdoorUtility {
    using ParmType = typename Element::Params;
    using DggType = typename Element::DggType;
    using IntType = typename Element::Integer;

  public:
    /**
     * Trapdoor generation method as described in Algorithm 1 of
     * https://eprint.iacr.org/2017/844.pdf
     *
     * @param params ring element parameters
     * @param stddev distribution parameter used in sampling noise polynomials
     * of the trapdoor
     * @param base base of gadget matrix
     * @param bal flag for balanced (true) versus not-balanced (false) digit
     * representation
     * @return the trapdoor pair including the public key (matrix of rings)
     * and trapdoor itself
     */
    static std::pair<Matrix<Element>, RlweTrapdoorPair<Element>> trapdoor_gen(std::shared_ptr<ParmType> params,
                                                                             double stddev, int64_t base = 2,
                                                                             bool bal = false);

    /**
     * Generalized trapdoor generation method (described in "Implementing
     * Token-Based Obfuscation under (Ring) LWE")
     *
     * @param params ring element parameters
     * @param stddev distribution parameter used in sampling noise polynomials of
     * the trapdoor
     * @param dimension dimension of the square matrix
     * @param base base of gadget matrix
     * @param bal flag for balanced (true) versus not-balanced (false) digit
     * representation
     * @return the trapdoor pair including the public key (matrix of rings) and
     * trapdoor itself
     */
    static std::pair<Matrix<Element>, RlweTrapdoorPair<Element>> trapdoor_gen_square_mat(std::shared_ptr<ParmType> params,
                                                                                      double stddev, size_t dimension,
                                                                                      int64_t base = 2,
                                                                                      bool bal = false);

    /**
     * Gaussian sampling as described in Alogorithm 2 of
     * https://eprint.iacr.org/2017/844.pdf
     *
     * @param n ring dimension
     * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
     * @param A public key of the trapdoor pair
     * @param T trapdoor itself
     * @param u syndrome vector where gaussian that Gaussian sampling is centered
     * around
     * @param dgg discrete Gaussian generator for integers
     * @param dgg_large_sigma discrete Gaussian generator for perturbation vector
     * sampling (only used in Peikert's method)
     * @param base base of gadget matrix
     * @return the sampled vector (matrix)
     */
    static Matrix<Element> gauss_samp(size_t n, size_t k, const Matrix<Element>& A, const RlweTrapdoorPair<Element>& T,
                                     const Element& u, DggType& dgg, DggType& dgg_large_sigma, int64_t base = 2);

    /**
     * Gaussian sampling (described in "Implementing Token-Based Obfuscation under
     * (Ring) LWE")
     *
     * @param n ring dimension
     * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
     * @param A public key of the trapdoor pair
     * @param T trapdoor itself
     * @param U syndrome matrix that Gaussian sampling is centered around
     * @param dgg discrete Gaussian generator for integers
     * @param dgg_large_sigma discrete Gaussian generator for perturbation vector
     * sampling (only used in Peikert's method)
     * @param base base of gadget matrix
     * @return the sampled vector (matrix)
     */
    static Matrix<Element> gauss_samp_square_mat(size_t n, size_t k, const Matrix<Element>& A,
                                              const RlweTrapdoorPair<Element>& T, const Matrix<Element>& U,
                                              DggType& dgg, DggType& dgg_large_sigma, int64_t base = 2);

    /**
     * On-line stage of pre-image sampling (includes only G-sampling)
     *
     * @param n ring dimension
     * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
     * @param A public key of the trapdoor pair
     * @param T trapdoor itself
     * @param u syndrome vector where gaussian that Gaussian sampling is centered
     * around
     * @param dgg discrete Gaussian generator for integers
     * @param perturbation_vector perturbation vector generated during the offline
     * stage
     * @param base base for G-lattice
     * @return the sampled vector (matrix)
     */
    static Matrix<Element> gauss_samp_online(size_t n, size_t k, const Matrix<Element>& A,
                                           const RlweTrapdoorPair<Element>& T, const Element& u, DggType& dgg,
                                           const std::shared_ptr<Matrix<Element>> perturbation_vector, int64_t base = 2);

    /**
     * Offline stage of pre-image sampling (perturbation sampling)
     *
     * @param n ring dimension
     * @param k matrix sample dimension; k = logq + 2
     * @param T trapdoor itself
     * @param dgg discrete Gaussian generator for integers
     * @param dgg_large_sigma discrete Gaussian generator for perturbation vector
     * sampling
     * @param base base for G-lattice
     * @return the sampled vector (matrix)
     */
    static std::shared_ptr<Matrix<Element>> gauss_samp_offline(size_t n, size_t k, const RlweTrapdoorPair<Element>& T,
                                                             DggType& dgg, DggType& dgg_large_sigma, int64_t base = 2);

    /**
     * Method for perturbation generation as described in Algorithm 4 of
     *https://eprint.iacr.org/2017/844.pdf
     *
     *@param n ring dimension
     *@param s parameter Gaussian distribution
     *@param sigma standard deviation
     *@param Tprime compact trapdoor matrix
     *@param dgg discrete Gaussian generator for error sampling
     *@param dgg_large_sigma discrete Gaussian generator for perturbation vector
     *sampling
     *@param perturbation_vector perturbation vector;output of the function
     */
    static void z_sample_sigma_p(size_t n, double s, double sigma, const RlweTrapdoorPair<Element>& tprime,
                              const DggType& dgg, const DggType& dgg_large_sigma,
                              std::shared_ptr<Matrix<Element>> perturbation_vector) {
        CIPHER_DEBUG_FLAG(false);
        TimeVar t1, t1_tot;

        TIC(t1);
        TIC(t1_tot);
        Matrix<Element> tprime0 = tprime.e_;
        Matrix<Element> tprime1 = tprime.r_;

        // k is the bit length
        size_t k = tprime0.get_cols();

        const std::shared_ptr<ParmType> params = tprime0(0, 0).get_params();
        CIPHER_DEBUG("z1a: " << TOC(t1));  // 0
        TIC(t1);
        // all three Polynomials are initialized with "0" coefficients
        Element va(params, Format::EVALUATION, 1);
        Element vb(params, Format::EVALUATION, 1);
        Element vd(params, Format::EVALUATION, 1);

        for (size_t i = 0; i < k; i++) {
            va += tprime0(0, i) * tprime0(0, i).transposed();
            vb += tprime1(0, i) * tprime0(0, i).transposed();
            vd += tprime1(0, i) * tprime1(0, i).transposed();
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

        // for distribution parameters up to 3e5 (experimentally found threshold)
        // use the Peikert's inversion method otherwise, use Karney's method

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
        Matrix<Element> p2 = split_int64_into_elements<Element>(p2_z_vector, n, va.get_params());
        CIPHER_DEBUG("z1f2: " << TOC(t1));
        TIC(t1);

        // now converting to Format::EVALUATION representation before multiplication
        p2.set_format(Format::EVALUATION);

        CIPHER_DEBUG("z1g: " << TOC(t1));  // 17

        TIC(t1);

        // the dimension is 2x1 - a vector of 2 ring elements
        auto zero_alloc = Element::allocator(params, Format::EVALUATION);
        Matrix<Element> tp2(zero_alloc, 2, 1);
        tp2(0, 0) = (tprime0 * p2)(0, 0);
        tp2(1, 0) = (tprime1 * p2)(0, 0);

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
        LatticeGaussSampUtility<Element>::z_sample_sigma2x2(a, b, d, c, dgg, p1_z_vector);
        CIPHER_DEBUG("z1j1: " << TOC(t1));  // 14
        TIC(t1);

        // create 2 ring elements in coefficient representation
        Matrix<Element> p1 = split_int64_into_elements<Element>(*p1_z_vector, n, va.get_params());
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

    /**
     * Method for perturbation generation as described in "Implementing
     *Token-Based Obfuscation under (Ring) LWE"
     *
     *@param n ring dimension
     *@param s spectral norm
     *@param sigma standard deviation
     *@param Tprime compact trapdoor matrix
     *@param dgg discrete Gaussian generator for error sampling
     *@param dgg_large_sigma discrete Gaussian generator for perturbation vector
     *sampling
     *@param perturbation_vector perturbation vector;output of the function
     */
    static void sample_pert_square_mat(size_t n, double s, double sigma, const RlweTrapdoorPair<Element>& tprime,
                                    const DggType& dgg, const DggType& dgg_large_sigma,
                                    std::shared_ptr<Matrix<Element>> perturbation_vector) {
        Matrix<Element> R = tprime.r_;
        Matrix<Element> E = tprime.e_;

        const std::shared_ptr<ParmType> params = R(0, 0).get_params();

        // k is the bit length
        size_t k = R.get_cols();
        size_t d = R.get_rows();

        Matrix<int64_t> p2_z_vector([]() { return 0; }, n * k, d);

        double sigma_large = std::sqrt(s * s - sigma * sigma);

        // for distribution parameters up to the experimentally found threshold, use
        // the Peikert's inversion method otherwise, use Karney's method
        if (sigma_large > KARNEY_THRESHOLD) {
            // Karney rejection sampling method
            for (size_t i = 0; i < n * k; i++) {
                for (size_t j = 0; j < d; j++) {
                    p2_z_vector(i, j) = dgg.generate_integer_karney(0, sigma_large);
                }
            }
        } else {
            // Peikert's inversion sampling method
            auto dgg_vector = dgg_large_sigma.generate_int_vector(n * k * d);
            for (size_t i = 0; i < n * k; i++) {
                for (size_t j = 0; j < d; j++) {
                    p2_z_vector(i, j) = dgg_vector[i * d + j];
                }
            }
        }

        // create a matrix of d*k x d ring elements in coefficient representation
        Matrix<Element> p2 = split_int64_into_elements<Element>(p2_z_vector.extract_col(0), n, params);
        for (size_t i = 1; i < d; i++) {
            p2.h_stack(split_int64_into_elements<Element>(p2_z_vector.extract_col(i), n, params));
        }

        // now converting to Format::EVALUATION representation before multiplication
        p2.set_format(Format::EVALUATION);

        auto zero_alloc = Element::allocator(params, Format::EVALUATION);

        Matrix<Element> A = R * (R.transposed());  // d x d
        Matrix<Element> B = R * (E.transposed());  // d x d
        Matrix<Element> D = E * (E.transposed());  // d x d

        // Switch the ring elements (Polynomials) to coefficient representation
        A.set_format(Format::COEFFICIENT);
        B.set_format(Format::COEFFICIENT);
        D.set_format(Format::COEFFICIENT);

        Matrix<Field2n> AF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);
        Matrix<Field2n> BF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);
        Matrix<Field2n> DF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);

        double scalar_factor = -sigma * sigma;

        for (size_t i = 0; i < d; i++) {
            for (size_t j = 0; j < d; j++) {
                AF(i, j) = Field2n(A(i, j));
                AF(i, j) = AF(i, j).scalar_mult(scalar_factor);
                BF(i, j) = Field2n(B(i, j));
                BF(i, j) = BF(i, j).scalar_mult(scalar_factor);
                DF(i, j) = Field2n(D(i, j));
                DF(i, j) = DF(i, j).scalar_mult(scalar_factor);
                if (i == j) {
                    AF(i, j) = AF(i, j) + s * s;
                    DF(i, j) = DF(i, j) + s * s;
                }
            }
        }

        // converts the field elements to DFT representation
        AF.set_format(Format::EVALUATION);
        BF.set_format(Format::EVALUATION);
        DF.set_format(Format::EVALUATION);

        // the dimension is 2d x d
        Matrix<Element> tp2 = (R.v_stack(E)) * p2;

        // change to coefficient representation before converting to field elements
        tp2.set_format(Format::COEFFICIENT);

        Matrix<Element> p1(zero_alloc, 1, 1);

        for (size_t j = 0; j < d; j++) {
            Matrix<Field2n> c([&]() { return Field2n(n, Format::COEFFICIENT); }, 2 * d, 1);

            for (size_t i = 0; i < d; i++) {
                c(i, 0) = Field2n(tp2(i, j)).scalar_mult(-sigma * sigma / (s * s - sigma * sigma));
                c(i + d, 0) = Field2n(tp2(i + d, j)).scalar_mult(-sigma * sigma / (s * s - sigma * sigma));
            }

            auto p1_z_vector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * 2 * d, 1);

            LatticeGaussSampUtility<Element>::sample_mat(AF, BF, DF, c, dgg, p1_z_vector);

            if (j == 0)
                p1 = split_int64_into_elements<Element>(*p1_z_vector, n, params);
            else
                p1.h_stack(split_int64_into_elements<Element>(*p1_z_vector, n, params));
        }

        p1.set_format(Format::EVALUATION);

        *perturbation_vector = p1.v_stack(p2);

        p1.set_format(Format::COEFFICIENT);
    }
};

}  // namespace cipher

#endif  // CIPHER_RING_TRAPDOOR_H_
