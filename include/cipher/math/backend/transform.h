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
  This file contains the interface for the transforms in each math backend
 */

#ifndef CIPHER_MATH_BACKEND_TRANSFORM_H_
#define CIPHER_MATH_BACKEND_TRANSFORM_H_

#include <complex>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "cipher/util/inttypes.h"

#ifndef M_PI
    #define M_PI 3.14159265358979323846
#endif

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Golden Chinese Remainder Transform FFT implementation.
 */
template <typename VecType>
class ChineseRemainderTransformFttInterface {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Copies \p element into \p result and calls NumberTheoreticTransform::forward_transform_to_bit_reverse_in_place()
     *
     * Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param root_of_unity_value is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If root_of_unity_value == 0 or 1, then the
     * result == input.
     * @param cyclo_order_value is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw of error occurs.
     * @see NumberTheoreticTransform::forward_transform_to_bit_reverse_in_place()
     */
    virtual void forward_transform_to_bit_reverse(const VecType& element, const IntType& root_of_unity_value,
                                              const uint32_t cyclo_order_value, VecType* result) = 0;

    /**
     * In-place Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param root_of_unity_value is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If root_of_unity_value == 0 or 1, then the
     * result == input.
     * @param cyclo_order_value is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[in,out] element is the input to the transform of type VecType and length n.
     * @see NumberTheoreticTransform::forward_transform_to_bit_reverse_in_place()
     */
    virtual void forward_transform_to_bit_reverse_in_place(const IntType& root_of_unity_value, const uint32_t cyclo_order_value,
                                                     VecType* element) = 0;

    /**
     * Copies \p element into \p result and calls NumberTheoreticTransform::inverse_transform_from_bit_reverse_in_place()
     *
     * Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param root_of_unity_value is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If root_of_unity_value == 0 or 1, then the
     * result == input.
     * @param cyclo_order_value is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see NumberTheoreticTransform::inverse_transform_from_bit_reverse_in_place()
     */
    virtual void inverse_transform_from_bit_reverse(const VecType& element, const IntType& root_of_unity_value,
                                                const uint32_t cyclo_order_value, VecType* result) = 0;

    /**
     * In-place Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param root_of_unity_value is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If root_of_unity_value == 0 or 1, then the
     * result == input.
     * @param cyclo_order_value is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     * @see NumberTheoreticTransform::inverse_transform_from_bit_reverse_in_place()
     */
    virtual void inverse_transform_from_bit_reverse_in_place(const IntType& root_of_unity_value, const uint32_t cyclo_order_value,
                                                       VecType* element) = 0;

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param root_of_unity_value is the 2n-th root of unity in Z_q used to precompute
     * the root of unity tables.
     * @param cyclo_order_value is a power-of-two, equal to 2n.
     * @param modulus is q, the prime modulus
     */
    virtual void pre_compute(const IntType& root_of_unity_value, const uint32_t cyclo_order_value, const IntType& modulus) = 0;

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param root_of_unity_value is the vector of 2n-th roots of unity, one per modulus
     * in moduli_chain, used to precompute the root of unity tables.
     * @param cyclo_order_value is a power-of-two, equal to 2n.
     * @param moduli_chain is the vector of prime moduli qi such that 2n|qi-1
     */
    virtual void pre_compute(std::vector<IntType>& root_of_unity_value, const uint32_t cyclo_order_value,
                            std::vector<IntType>& moduli_chain) = 0;

    /**
     * Reset cached values for the root of unity tables to empty.
     */
    virtual void reset() = 0;
};

/**
 * @brief Chinese Remainder Transform for arbitrary cyclotomics.
 */
template <typename VecType>
class ChineseRemainderTransformArbInterface {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Sets the cyclotomic polynomial.
     *
     * @param poly is the cyclotomic polynomial.
     * @param mod is the modulus of the polynomial ring.
     */
    virtual void set_cylotomic_polynomial(const VecType& poly, const IntType& mod_value) = 0;

    /**
     * Forward transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param big_mod is the additional modulus needed for NTT operation.
     * @param big_root is the additional root of unity w.r.t big_mod needed for NTT
     * operation.
     * @param cyclo_order is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    virtual VecType forward_transform(const VecType& element, const IntType& root, const IntType& big_mod,
                                     const IntType& big_root, const uint32_t cyclo_order) = 0;

    /**
     * Inverse transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param big_mod is the additional modulus needed for NTT operation.
     * @param big_root is the additional root of unity w.r.t big_mod needed for NTT
     * operation.
     * @param cyclo_order is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    virtual VecType inverse_transform(const VecType& element, const IntType& root, const IntType& big_mod,
                                     const IntType& big_root, const uint32_t cyclo_order) = 0;

    /**
     * Reset cached values for the transform to empty.
     */
    virtual void reset() = 0;

    /**
     * @brief Precomputes the root of unity and modulus needed for NTT operation
     * in forward Bluestein transform.
     * @param cycloto_order is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     */
    virtual void pre_compute(const uint32_t cycloto_order, const IntType& modulus) = 0;

    /**
     * @brief Sets the precomputed root of unity and modulus needed for NTT
     * operation in forward Bluestein transform.
     * @param cycloto_order is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     * @param ntt_mod is the modulus needed for the NTT operation in forward
     * Bluestein transform.
     * @param ntt_root is the root of unity needed for the NTT operation in forward
     * Bluestein transform.
     */
    virtual void set_pre_computed_ntt_modulus(uint32_t cycloto_order, const IntType& modulus, const IntType& ntt_mod,
                                          const IntType& ntt_root) = 0;

    /**
     * @brief Sets the precomputed root of unity and modulus needed for NTT
     * operation and computes m_cyclotomicPolyReveseNTTMap,cyclotomic_poly_ntt_map_.
     * Always called after setting the cyclotomic polynomial.
     * @param cycloto_order is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     * @param ntt_mod is the modulus needed for the NTT operation in forward
     * Bluestein transform.
     * @param ntt_root is the root of unity needed for the NTT operation in forward
     * Bluestein transform.
     */
    virtual void set_pre_computed_ntt_division_modulus(uint32_t cycloto_order, const IntType& modulus, const IntType& ntt_mod,
                                                  const IntType& ntt_root) = 0;

    /**
     * @brief Computes the inverse of the cyclotomic polynomial using
     * Newton-Iteration method.
     * @param cyclo_poly is the cyclotomic polynomial.
     * @param modulus is the modulus of the polynomial ring.
     * @param power is the number of coefficients of the result; the inverse is computed modulo x^power.
     * @return inverse polynomial.
     */
    virtual VecType inverse_poly_mod(const VecType& cyclo_poly, const IntType& modulus, uint32_t power) = 0;

  private:
    /**
     * @brief Padding zeroes to a vector
     * @param element is the input of type VecType to be padded with zeros.
     * @param cyclo_order is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform padding.
     * @return is result vector with &element values with padded zeros to it
     */
    virtual VecType pad(const VecType& element, const uint32_t cyclo_order, bool forward) = 0;

    /**
     * @brief Dropping elements from a vector
     * @param element is the input of type VecType.
     * @param cyclo_order is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform dropping.
     * @param big_mod is a modulus used to precompute the root of unity tables if
     * needed. The tables are used in the inverse dropping computations
     * @param big_root is a root of unity used to precompute the root of unity
     * tables if needed. The tables are used in the inverse dropping computations
     * @return is result vector with &element values with dropped elements from it
     */
    virtual VecType drop(const VecType& element, const uint32_t cyclo_order, bool forward, const IntType& big_mod,
                         const IntType& big_root) = 0;
};
}  // namespace cipher

#endif  // CIPHER_MATH_BACKEND_TRANSFORM_H_
