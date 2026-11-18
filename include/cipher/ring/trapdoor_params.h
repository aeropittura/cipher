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
  Parameter definitions for trapdoor-related schemes (GPV signature, IBE, ABE)
 */

#ifndef CIPHER_RING_TRAPDOOR_PARAMS_H_
#define CIPHER_RING_TRAPDOOR_PARAMS_H_

#include <cmath>
#include <cstdint>
#include <memory>

#include "cipher/ring/trapdoor.h"
#include "cipher/math/matrix.h"

namespace cipher {
/**
 * @brief Base class for the parameters shared by the trapdoor-based schemes (GPV signature, IBE, ABE):
 * the ring element parameters, the discrete Gaussian generator, and its distribution parameter.
 * @tparam Element ring element
 */
template <class Element>
class TrapdoorParams {
    using ParmType = typename Element::Params;
    using DggType = typename Element::DggType;

  public:
    /**
     * @brief Default destructor
     */
    virtual ~TrapdoorParams() = default;
    /**
     * @brief Default constructor; sets the distribution parameter to 0 and leaves the ring element parameters unset.
     */
    TrapdoorParams() : stddev_(0), elemparams_(nullptr), dgg_(0) {}
    /**
     * @brief Constructor for trapdoor parameters
     * @param elemparams parameters of the ring element
     * @param dgg discrete Gaussian generator used for sampling; copied into the object
     * @param stddev distribution parameter (standard deviation) of the Gaussian generator
     */
    TrapdoorParams(std::shared_ptr<ParmType> elemparams, DggType& dgg, double stddev)
        : stddev_(stddev), elemparams_(elemparams), dgg_(dgg) {}
    /**
     * @brief Accessor function for the ring element parameters
     * @return the ring element parameters
     */
    const std::shared_ptr<ParmType>& get_elem_params() const {
        return elemparams_;
    }
    /**
     * @brief Mutator function for the ring element parameters
     * @param elemparams ring element parameters
     */
    void set_elem_params(std::shared_ptr<ParmType>& elemparams) {
        elemparams_ = elemparams;
    }
    /**
     * @brief Accessor function for the discrete Gaussian generator
     * @return the discrete Gaussian generator
     */
    DggType& get_dgg() {
        return dgg_;
    }
    /**
     * @brief Mutator function for the discrete Gaussian generator
     * @param dgg discrete Gaussian generator to be set
     */
    void set_dgg(DggType& dgg) {
        dgg_ = dgg;
    }
    /**
     * @brief Accessor function for the distribution parameter
     * @return the distribution parameter (standard deviation) of the Gaussian generator
     */
    double get_std_dev() {
        return stddev_;
    }
    /**
     * @brief Sets the distribution parameter and applies it to the stored discrete Gaussian generator as well.
     * @param stddev distribution parameter (standard deviation) to be set
     */
    void set_std_dev(double stddev) {
        stddev_ = stddev;
        dgg_.set_std(stddev);
    }

  protected:
    /** distribution parameter (standard deviation) of the discrete Gaussian generator */
    double stddev_;
    /** parameters of the ring element */
    std::shared_ptr<ParmType> elemparams_;
    /** discrete Gaussian generator used for sampling */
    DggType dgg_;
};
/**
 * @brief Trapdoor parameters for the RLWE (Ring Learning With Errors) setting; adds the gadget base, the number
 * of gadget digits k, the ring dimension n, and the large-sigma Gaussian generator used for perturbation sampling.
 * @tparam Element ring element
 */
template <class Element>
class RlweTrapdoorParams : public TrapdoorParams<Element> {
    using ParmType = typename Element::Params;
    using DggType = typename Element::DggType;

  public:
    /**
     * @brief Default destructor
     */
    ~RlweTrapdoorParams() override = default;
    /**
     * @brief Default constructor; all numeric parameters are set to 0.
     */
    RlweTrapdoorParams() : TrapdoorParams<Element>(), base_(0), k_(0), bal_(0), n_(0), dgg_large_sigma_(0) {}
    /**
     * @brief Constructs the RLWE trapdoor parameters and derives the dependent quantities: the ring dimension
     * n = cyclotomic order / 2, the number of gadget digits k = floor(log_base(q - 1)) + 1, and the large-sigma
     * generator with standard deviation sqrt(s^2 - c^2), where c = SIGMA * (base + 1) and s = SPECTRAL_BOUND(n, k, base).
     * When that standard deviation exceeds KARNEY_THRESHOLD, a copy of dgg is stored instead (Karney sampling is
     * used for the perturbation vector in that case).
     * @param elemparams parameters of the ring element (modulus q and cyclotomic order)
     * @param dgg discrete Gaussian generator used for sampling
     * @param stddev distribution parameter (standard deviation) of the Gaussian generator
     * @param base base of the gadget matrix
     * @param bal true for balanced digit representation in the gadget decomposition
     */
    RlweTrapdoorParams(std::shared_ptr<ParmType>& elemparams, DggType& dgg, double stddev, int64_t base,
                       bool bal = false)
        : TrapdoorParams<Element>(elemparams, dgg, stddev),
          base_(base),
          k_(0),
          bal_(bal),
          n_(elemparams->get_cyclotomic_order() >> 1),
          dgg_large_sigma_(0) {
        auto val = elemparams->get_modulus().convert_to_double();
        auto log_two = std::log(val - 1.0) / std::log(base) + 1.0;
        k_ = static_cast<size_t>(std::floor(log_two));

        auto c = static_cast<double>(SIGMA * (base_ + 1));
        auto s = static_cast<double>(SPECTRAL_BOUND(n_, k_, base));
        auto t = std::sqrt(s * s - c * c);
        dgg_large_sigma_ = (t <= KARNEY_THRESHOLD) ? DggType(t) : dgg;
    }
    /**
     * @brief Accessor function for the gadget matrix base
     * @return base of the gadget matrix
     */
    int64_t get_base() {
        return base_;
    }
    /**
     * @brief Sets the gadget matrix base; k and the large-sigma generator are not recomputed.
     * @param base base of the gadget matrix to be set
     */
    void set_base(int64_t base) {
        base_ = base;
    }
    /**
     * @brief Accessor function for the balanced digit representation flag
     * @return true if balanced digit representation is used
     */
    bool is_bal() {
        return bal_;
    }
    /**
     * @brief Mutator function for the balanced digit representation flag
     * @param bal true to use balanced digit representation
     */
    void set_bal(bool bal) {
        bal_ = bal;
    }
    /**
     * @brief Accessor function for the number of gadget digits k = floor(log_base(q - 1)) + 1
     * @return number of gadget digits
     */
    size_t get_K() {
        return k_;
    }
    /**
     * @brief Accessor function for the ring dimension n (half the cyclotomic order)
     * @return ring dimension
     */
    uint32_t get_N() {
        return n_;
    }
    /**
     * @brief Accessor function for the discrete Gaussian generator with the large distribution parameter used for
     * perturbation sampling
     * @return the large-sigma discrete Gaussian generator
     */
    DggType& get_dgg_large_sigma() {
        return dgg_large_sigma_;
    }
    /**
     * @brief Mutator function for the discrete Gaussian generator with the large distribution parameter
     * @param dgg_large_sigma discrete Gaussian generator to be set
     */
    void set_dgg_large_sigma(DggType& dgg_large_sigma) {
        dgg_large_sigma_ = dgg_large_sigma;
    }

  protected:
    /** base of the gadget matrix */
    int64_t base_;
    /** number of gadget digits, floor(log_base(q - 1)) + 1 */
    size_t k_;
    /** true if balanced digit representation is used in the gadget decomposition */
    bool bal_;
    /** ring dimension (half the cyclotomic order) */
    uint32_t n_;
    /** discrete Gaussian generator with the large distribution parameter used for perturbation sampling */
    DggType dgg_large_sigma_;
    //    DggType dgg_large_sigma_ = DggType(0);
};
/**
 * @brief Container for the perturbation vector produced by the offline stage of trapdoor sampling
 * (RlweTrapdoorUtility::gauss_samp_offline) and consumed by the online stage (gauss_samp_online).
 * @tparam Element ring element
 */
template <class Element>
class PerturbationVector {
  public:
    /**
     * @brief Default constructor; holds no vector.
     */
    PerturbationVector() : pvector_(nullptr) {};
    /**
     * @brief Constructor for the perturbation vector
     * @param pvector column matrix of ring elements holding the perturbation vector
     */
    explicit PerturbationVector(std::shared_ptr<Matrix<Element>>& pvector) : pvector_(pvector) {}
    /**
     * @brief Mutator for the perturbation vector
     * @param pvector column matrix of ring elements holding the perturbation vector
     */
    void set_vector(std::shared_ptr<Matrix<Element>>& pvector) {
        pvector_ = pvector;
    }
    /**
     * @brief Accessor for the perturbation vector
     * @return column matrix of ring elements holding the perturbation vector
     */
    const std::shared_ptr<Matrix<Element>>& get_vector() const {
        return pvector_;
    }

  private:
    // Perturbation vector represented as a vector of ring elements
    std::shared_ptr<Matrix<Element>> pvector_;
};
}  // namespace cipher

#endif  // CIPHER_RING_TRAPDOOR_PARAMS_H_
