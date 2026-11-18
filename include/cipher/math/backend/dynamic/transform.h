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
  This file contains the linear transform interface functionality for the dynamic math backend
 */

#ifndef CIPHER_MATH_BACKEND_DYNAMIC_TRANSFORM_H_
#define CIPHER_MATH_BACKEND_DYNAMIC_TRANSFORM_H_

#include <cstdint>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include <map>
    #include <mutex>
    #include <unordered_map>
    #include <utility>
    #include <vector>

    #include "cipher/math/backend/dynamic/mod_vector.h"
    #include "cipher/math/backend/dynamic/integer.h"
    #include "cipher/math/backend/transform.h"

/**
 * @namespace bigintdyn
 * The namespace of bigintdyn
 */
namespace dynamic_int {

/**
 * @brief Number Theoretic Transform implementation
 */
template <typename VecType>
class NumberTheoreticTransformDyn {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Forward transform in the ring Z_q[X]/(X^n-1).
     *
     * @param element is the input to the transform of type VecType and length n
     * s.t. n|q-1.
     * @param root_of_unity_table is the table with the root of unity powers.
     * @param[out] result is the result of the transform, a VecType that should be of the same
     * size as input or a throw if an error occurs.
     */
    void forward_transform_iterative(const VecType& element, const VecType& root_of_unity_table, VecType* result);

    /**
     * Inverse transform in the ring Z_q[X]/(X^n-1) with prime q and power-of-two
     * n s.t. n|q-1.
     *
     * @param element is the input to the transform of type VecType and length n.
     * @param root_of_unity_inverse_table is the table with the inverse n-th root of unity
     * powers.
     * @param[out] result is the result of the transform, a VecType that should be of the same
     * size as input or a throw if an error occurs.
     */
    void inverse_transform_iterative(const VecType& element, const VecType& root_of_unity_inverse_table,
                                     VecType* result);

    /**
     * Copies \p element into \p result and calls forward_transform_to_bit_reverse_in_place()
     *
     * Forward transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param root_of_unity_table is the table with the n-th root of unity powers in
     * bit reverse order.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see forward_transform_to_bit_reverse_in_place()
     */
    void forward_transform_to_bit_reverse(const VecType& element, const VecType& root_of_unity_table, VecType* result);
    /**
     * In-place forward transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param root_of_unity_table is the table with the n-th root of unity powers in
     * bit reverse order.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     */
    void forward_transform_to_bit_reverse_in_place(const VecType& root_of_unity_table, VecType* element);

    /**
     * Copies \p element into \p result and calls forward_transform_to_bit_reverse_in_place()
     *
     * Forward transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes. The method works for the
     * NativeInteger case based on NTL's modular multiplication. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param element is the input to the transform of type VecType and length n.
     * @param root_of_unity_table is the table with the root of unity powers in bit
     * reverse order.
     * @param precon_root_of_unity_table is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see forward_transform_to_bit_reverse_in_place()
     */
    void forward_transform_to_bit_reverse(const VecType& element, const VecType& root_of_unity_table,
                                          const VecType& precon_root_of_unity_table, VecType* result);

    /**
     * In-place forward transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. The method works for the
     * NativeInteger case based on NTL's modular multiplication. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param root_of_unity_table is the table with the root of unity powers in bit
     * reverse order.
     * @param precon_root_of_unity_table is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     */
    void forward_transform_to_bit_reverse_in_place(const VecType& root_of_unity_table,
                                                   const VecType& precon_root_of_unity_table, VecType* element);

    /**
     * Copies \p element into \p result and calls inverse_transform_from_bit_reverse_in_place()
     *
     * Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 2 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param element is the input to the transform of type VecType and length n.
     * @param root_of_unity_inverse_table is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param cyclo_order_inv is inverse of n modulo q
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see inverse_transform_from_bit_reverse_in_place()
     */
    void inverse_transform_from_bit_reverse(const VecType& element, const VecType& root_of_unity_inverse_table,
                                            const IntType& cyclo_order_inv, VecType* result);

    /**
     * In-place inverse transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 2 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param root_of_unity_inverse_table is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param cyclo_order_inv is inverse of n modulo q
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     */
    void inverse_transform_from_bit_reverse_in_place(const VecType& root_of_unity_inverse_table,
                                                     const IntType& cyclo_order_inv, VecType* element);

    /**
     * Copies \p element into \p result and calls inverse_transform_from_bit_reverse_in_place()
     *
     * Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes. The method works for the
     * NativeInteger case based on NTL's modular multiplication. [Algorithm 2 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param element is the input to the transform of type VecType and length n.
     * @param root_of_unity_inverse_table is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param precon_root_of_unity_inverse_table is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param cyclo_order_inv is inverse of n modulo q
     * @param precon_cyclo_order_inv is NTL-specific precomputations for optimized
     * NativeInteger modulo multiplications.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see inverse_transform_from_bit_reverse_in_place()
     */
    void inverse_transform_from_bit_reverse(const VecType& element, const VecType& root_of_unity_inverse_table,
                                            const VecType& precon_root_of_unity_inverse_table,
                                            const IntType& cyclo_order_inv, const IntType& precon_cyclo_order_inv,
                                            VecType* result);

    /**
     * In-place Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. The method works for the
     * NativeInteger case based on NTL's modular multiplication. [Algorithm 2 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param root_of_unity_inverse_table is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param precon_root_of_unity_inverse_table is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param cyclo_order_inv is inverse of n modulo q
     * @param precon_cyclo_order_inv is NTL-specific precomputations for optimized
     * NativeInteger modulo multiplications.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     */
    void inverse_transform_from_bit_reverse_in_place(const VecType& root_of_unity_inverse_table,
                                                     const VecType& precon_root_of_unity_inverse_table,
                                                     const IntType& cyclo_order_inv,
                                                     const IntType& precon_cyclo_order_inv, VecType* element);
};

/**
 * @brief Golden Chinese Remainder Transform FFT implementation.
 */
template <typename VecType>
class ChineseRemainderTransformFttDyn final : public cipher::ChineseRemainderTransformFttInterface<VecType> {
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
    void forward_transform_to_bit_reverse(const VecType& element, const IntType& root_of_unity_value,
                                          const uint32_t cyclo_order_value, VecType* result);

    /**
     * In-place Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param root_of_unity_value is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If root_of_unity_value == 0 or 1, then the
     * result == input.
     * @param cyclo_order_value is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     * @see NumberTheoreticTransform::forward_transform_to_bit_reverse_in_place()
     */
    void forward_transform_to_bit_reverse_in_place(const IntType& root_of_unity_value, const uint32_t cyclo_order_value,
                                                   VecType* element);

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
    void inverse_transform_from_bit_reverse(const VecType& element, const IntType& root_of_unity_value,
                                            const uint32_t cyclo_order_value, VecType* result);

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
    void inverse_transform_from_bit_reverse_in_place(const IntType& root_of_unity_value,
                                                     const uint32_t cyclo_order_value, VecType* element);

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param root_of_unity_value is the 2n-th root of unity in Z_q used to compute
     * the root of unity tables.
     * @param cyclo_order_value is a power-of-two, equal to 2n.
     * @param modulus is q, the prime modulus
     */
    void pre_compute(const IntType& root_of_unity_value, const uint32_t cyclo_order_value, const IntType& modulus);

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param root_of_unity_value is the vector of 2n-th roots of unity, one per modulus in
     * moduli_chain, used to compute the root of unity tables.
     * @param cyclo_order_value is a power-of-two, equal to 2n.
     * @param moduli_chain is the vector of prime moduli qi such that 2n|qi-1
     */
    void pre_compute(std::vector<IntType>& root_of_unity_value, const uint32_t cyclo_order_value,
                     std::vector<IntType>& moduli_chain);

    /**
     * Reset cached values for the root of unity tables to empty.
     */
    void reset();

    /// map to store the cyclo order inverse with modulus as a key
    /// For inverse FTT, we also need #cyclo_order_inverse_precon_table_by_modulus_ (this is to use an N-size NTT for FTT instead of 2N-size NTT).
    static std::map<IntType, VecType> cyclo_order_inverse_table_by_modulus_;

    /// map to store the cyclo order inverse preconditioned with modulus as a key
    /// Shoup's precomputation of above #cyclo_order_inverse_table_by_modulus_
    static std::map<IntType, VecType> cyclo_order_inverse_precon_table_by_modulus_;

    /// map to store the forward roots of Unity for NTT, with bits reversed, with modulus as a key (aka twiddle factors)
    static std::map<IntType, VecType> root_of_unity_reverse_table_by_modulus_;

    /// map to store inverse roots of unity for iNTT, with bits reversed, with modulus as a key (aka inverse twiddle factors)
    static std::map<IntType, VecType> root_of_unity_inverse_reverse_table_by_modulus_;

    /// map to store Shoup's precomputations of forward roots of unity for NTT, with bits reversed, with modulus as a key
    static std::map<IntType, VecType> root_of_unity_precon_reverse_table_by_modulus_;

    /// map to store Shoup's precomputations of inverse rou for iNTT, with bits reversed, with modulus as a key
    static std::map<IntType, VecType> root_of_unity_inverse_precon_reverse_table_by_modulus_;
};

// struct used as a key in BlueStein transform
template <typename IntType>
using ModulusRoot = std::pair<IntType, IntType>;

template <typename IntType>
using ModulusRootPair = std::pair<ModulusRoot<IntType>, ModulusRoot<IntType>>;

/**
 * @brief Bluestein Fast Fourier Transform implementation
 */
template <typename VecType>
class BluesteinFftDyn {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Forward transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t. the modulus of element, where m is the cyclotomic order.
     * @param cyclo_order is the cyclotomic order.
     * @return is the output result of the transform.
     */
    VecType forward_transform(const VecType& element, const IntType& root, const uint32_t cyclo_order);
    VecType forward_transform(const VecType& element, const IntType& root, const uint32_t cyclo_order,
                              const ModulusRoot<IntType>& ntt_modulus_root);

    /**
     *
     * @param a is the input vector to be padded with zeros.
     * @param final_size is the length of the output vector.
     * @return output vector padded with (final_size - initial size)additional
     * zeros.
     */
    VecType pad_zeros(const VecType& a, const uint32_t final_size);

    /**
     *
     * @param a is the input vector to be resized.
     * @param lo is lower coefficient index.
     * @param hi is higher coefficient index.
     * @return output vector s.t output vector = a[lo]...a[hi].
     */
    VecType Resize(const VecType& a, uint32_t lo, uint32_t hi);

    // void PreComputeNTTModulus(uint32_t cyclo_order, const std::vector<IntType>
    // &modulii);

    /**
     * @brief Precomputes the modulus needed for NTT operation in forward
     * Bluestein transform.
     * @param cyclo_order is the cyclotomic order of the polynomial.
     * @param modulus is the modulus of the polynomial.
     */
    void pre_compute_default_ntt_modulus_root(uint32_t cyclo_order, const IntType& modulus);

    /**
     * @brief Precomputes the root of unity table needed for NTT operation in
     * forward Bluestein transform.
     * @param cyclo_order is the cyclotomic order of the polynomial ring.
     * @param ntt_modulus_root is the (modulus, root of unity) pair used for the NTT operation.
     */
    void pre_compute_root_table_for_ntt(uint32_t cyclo_order, const ModulusRoot<IntType>& ntt_modulus_root);

    /**
     * @brief precomputes the powers of root used in forward Bluestein transform.
     * @param cyclo_order is the cyclotomic order of the polynomial ring.
     * @param modulus_root is the (modulus, root) pair, where modulus is the modulus of the
     * polynomial ring and root is the root of unity s.t. root^2m = 1.
     */
    void pre_compute_powers(uint32_t cyclo_order, const ModulusRoot<IntType>& modulus_root);

    /**
     * @brief precomputes the NTT transform of the power of root of unity used in
     * the Bluestein transform.
     * @param cyclo_order is the cyclotomic order of the polynomial ring.
     * @param modulus_root_pair is the pair of (modulus, root) pairs: the first holds the modulus of
     * the polynomial ring and the root of unity s.t. root^2m = 1; the second holds the modulus and
     * root of unity required for the NTT transform.
     */
    void pre_compute_rb_table(uint32_t cyclo_order, const ModulusRootPair<IntType>& modulus_root_pair);

    /**
     * Reset cached values for the transform to empty.
     */
    void reset();

    // map to store the root of unity table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> root_of_unity_table_by_modulus_root_;

    // map to store the root of unity inverse table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> root_of_unity_inverse_table_by_modulus_root_;

    // map to store the power of roots as a table with modulus + root of unity as
    // key.
    static std::map<ModulusRoot<IntType>, VecType> powers_table_by_modulus_root_;

    // map to store the forward transform of power table with modulus + root of
    // unity as key.
    static std::map<ModulusRootPair<IntType>, VecType> rb_table_by_modulus_root_pair_;

  private:
    // map to store the precomputed NTT modulus with modulus as key.
    static std::map<IntType, ModulusRoot<IntType>> default_ntt_modulus_root_;
};

/**
 * @brief Chinese Remainder Transform for arbitrary cyclotomics.
 */
template <typename VecType>
class ChineseRemainderTransformArbDyn final : public cipher::ChineseRemainderTransformArbInterface<VecType> {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Sets the cyclotomic polynomial.
     *
     * @param poly is the cyclotomic polynomial.
     * @param mod is the modulus of the polynomial ring; used as the key under which poly is stored.
     */
    void set_cylotomic_polynomial(const VecType& poly, const IntType& mod_value);

    /**
     * Forward transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param big_mod is the addtional modulus needed for NTT operation.
     * @param big_root is the addtional root of unity w.r.t big_mod needed for NTT
     * operation.
     * @param cyclo_order is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    VecType forward_transform(const VecType& element, const IntType& root, const IntType& big_mod,
                              const IntType& big_root, const uint32_t cyclo_order);

    /**
     * Inverse transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param big_mod is the addtional modulus needed for NTT operation.
     * @param big_root is the addtional root of unity w.r.t big_mod needed for NTT
     * operation.
     * @param cyclo_order is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    VecType inverse_transform(const VecType& element, const IntType& root, const IntType& big_mod,
                              const IntType& big_root, const uint32_t cyclo_order);

    /**
     * Reset cached values for the transform to empty.
     */
    void reset();

    /**
     * @brief Precomputes the root of unity and modulus needed for NTT operation
     * in forward Bluestein transform.
     * @param cycloto_order is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     */
    void pre_compute(const uint32_t cycloto_order, const IntType& modulus);

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
    void set_pre_computed_ntt_modulus(uint32_t cycloto_order, const IntType& modulus, const IntType& ntt_mod,
                                      const IntType& ntt_root);

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
    void set_pre_computed_ntt_division_modulus(uint32_t cycloto_order, const IntType& modulus, const IntType& ntt_mod,
                                               const IntType& ntt_root);

    /**
     * @brief Computes the inverse of the cyclotomic polynomial using
     * Newton-Iteration method.
     * @param cyclo_poly is the cyclotomic polynomial.
     * @param modulus is the modulus of the polynomial ring.
     * @param power is the number of coefficients of the inverse, i.e., the inverse is computed modulo x^power.
     * @return inverse polynomial.
     */
    VecType inverse_poly_mod(const VecType& cyclo_poly, const IntType& modulus, uint32_t power);

  private:
    /**
     * @brief Padding zeroes to a vector
     * @param element is the input of type VecType to be padded with zeros.
     * @param cyclo_order is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform padding.
     * @return is result vector with element values with padded zeros to it
     */
    VecType pad(const VecType& element, const uint32_t cyclo_order, bool forward);

    /**
     * @brief Dropping elements from a vector
     * @param element is the input of type VecType.
     * @param cyclo_order is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform dropping.
     * @param big_mod is a modulus used to precompute the root of unity tables if
     * needed. The tables are used in the inverse dropping computations
     * @param big_root is a root of unity used to precompute the root of unity
     * tables if needed. The tables are used in the inverse dropping computations
     * @return is result vector with element values with dropped elements from it
     */
    VecType drop(const VecType& element, const uint32_t cyclo_order, bool forward, const IntType& big_mod,
                 const IntType& big_root);

    // map to store the cyclotomic polynomial with polynomial ring's modulus as
    // key.
    static std::map<IntType, VecType> cyclotomic_poly_map_;

    // map to store the forward NTT transform of the inverse of cyclotomic
    // polynomial with polynomial ring's modulus as key.
    static std::map<IntType, VecType> cyclotomic_poly_reverse_ntt_map_;

    // map to store the forward NTT transform of the cyclotomic polynomial with
    // polynomial ring's modulus as key.
    static std::map<IntType, VecType> cyclotomic_poly_ntt_map_;

    // map to store the root of unity table used in NTT based polynomial division.
    static std::map<IntType, VecType> root_of_unity_division_table_by_modulus_;

    // map to store the root of unity table for computing forward NTT of inverse
    // cyclotomic polynomial used in NTT based polynomial division.
    static std::map<IntType, VecType> root_of_unity_division_inverse_table_by_modulus_;

    // modulus used in NTT based polynomial division.
    static std::map<IntType, IntType> division_ntt_modulus_;

    // root of unity used in NTT based polynomial division.
    static std::map<IntType, IntType> division_ntt_root_of_unity_;

    // dimension of the NTT transform in NTT based polynomial division.
    static std::map<uint32_t, uint32_t> ntt_division_dim_;
};

}  // namespace dynamic_int

// Compiled once in be4-math-impl.cpp; these declarations suppress implicit instantiation in every
// other TU so all users link the library's copy (same pattern as transformnat.h).
extern template class dynamic_int::NumberTheoreticTransformDyn<dynamic_int::BigVector>;
extern template class dynamic_int::ChineseRemainderTransformFttDyn<dynamic_int::BigVector>;
extern template class dynamic_int::BluesteinFftDyn<dynamic_int::BigVector>;
extern template class dynamic_int::ChineseRemainderTransformArbDyn<dynamic_int::BigVector>;
#endif

#endif  // CIPHER_MATH_BACKEND_DYNAMIC_TRANSFORM_H_
