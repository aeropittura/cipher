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
  Defines an interface that any DCRT Polynomial implmentation must implement in order to work in OpenFHE.
 */

#ifndef CIPHER_RING_BACKEND_RNS_POLY_INTERFACE_H_
#define CIPHER_RING_BACKEND_RNS_POLY_INTERFACE_H_

#include <algorithm>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend/standard/rns_params.h"
#include "cipher/ring/element.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * @brief Ideal lattice for the double-CRT interface representation.
 * The interface contains a methods required for computations on lattices
 * The double-CRT representation of polynomials is a common optimization for
 * lattice encryption operations. Basically, it allows large-modulus polynomials
 * to be represented as multiple smaller-modulus polynomials.  The double-CRT
 * representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology –
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 *
 *
 * @tparam DerivedType Curiously-Recurring-Template-Pattern
 * @tparam BigVecType The Vector type before decomposing the polynomial into CRT
 * @tparam LilVecType The underlaying RNS data structure, a vectors type structure, that will compose the CRT data
 * @tparam RNSContainer The container of LilVecType, a cipher::PolyImpl or vector typically
 *
 * example for the default DerivedType the template types would be...
 *    DerivedType       - RnsPolyImpl<BigVector>
 *    BigVecType        - BigVector
 *    LilVecType        - NativeVector
 *    RNSContainer<LVT> - PolyImpl
 */

// TODO: CRTP with RingElement to remove virtual overhead

template <typename DerivedType, typename BigVecType, typename LilVecType,
          template <typename LVT> typename RnsContainerType>
class RnsPolyInterface : public RingElement<DerivedType, BigVecType> {
    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "This function is not implemented for DCRTPoly";

  public:
    using BigIntType = typename BigVecType::Integer;
    using Params = RnsParams<BigIntType>;
    using LilIntType = typename LilVecType::Integer;
    using TowerType = RnsContainerType<LilVecType>;
    using PolyLargeType = RnsContainerType<BigVecType>;
    using DggType = DiscreteGaussianGeneratorImpl<LilVecType>;
    using DugType = DiscreteUniformGeneratorImpl<LilVecType>;
    using TugType = TernaryUniformGeneratorImpl<LilVecType>;
    using BugType = BinaryUniformGeneratorImpl<LilVecType>;

    // measured team widths for the loops over the ring dimension
    /** OpenMP team width for the ring-dimension loops of the scale_and_round overloads that output a native polynomial */
    static constexpr uint32_t THREADS_SCALE_TO_POLY{8};
    /** OpenMP team width for the ring-dimension loops of crt_interpolate, switch_crt_basis, the scale-and-round
     *  methods over a CRT basis and the format switches beside them */
    static constexpr uint32_t THREADS_CRT_BASIS_SWITCH{16};
    /** largest OpenMP team width used by approx_switch_crt_basis */
    static constexpr uint32_t THREADS_APPROX_CRT_BASIS_SWITCH{36};
    /** smallest OpenMP team width used by approx_switch_crt_basis */
    static constexpr uint32_t THREADS_APPROX_CRT_BASIS_SWITCH_MIN{8};
    /** inner-loop iterations (ring dimension x size_q x size_p) per thread used to size the approx_switch_crt_basis team */
    static constexpr uint64_t APPROX_CRT_BASIS_SWITCH_WORK_PER_THREAD{1u << 17};

    /**
     * @brief Computes the OpenMP team width for approx_switch_crt_basis and the format switches beside it from the
     * work in its inner loop: ring_dim * size_q * size_p / APPROX_CRT_BASIS_SWITCH_WORK_PER_THREAD, clamped to
     * [THREADS_APPROX_CRT_BASIS_SWITCH_MIN, THREADS_APPROX_CRT_BASIS_SWITCH].
     *
     * @param ring_dim the ring dimension.
     * @param size_q the number of towers in the source basis Q.
     * @param size_p the number of towers in the target basis P.
     * @return the number of threads to request.
     */
    static uint32_t approx_switch_crt_basis_threads(uint32_t ring_dim, uint32_t size_q, uint32_t size_p) {
        const uint64_t threads =
                static_cast<uint64_t>(ring_dim) * size_q * size_p / APPROX_CRT_BASIS_SWITCH_WORK_PER_THREAD;
        return static_cast<uint32_t>(
                std::clamp<uint64_t>(threads, THREADS_APPROX_CRT_BASIS_SWITCH_MIN, THREADS_APPROX_CRT_BASIS_SWITCH));
    }

    /**
     * @brief Get the Derived object, this is apart of the CRTP software design pattern
     * it allows the base class (this one) to implement methods that call the derived
     * objects implementation.
     *
     * See Chapter 21.2 "C++ Templates The Complete Guide" by David Vandevoorde and Nicolai M. Josuttis
     * http://www.informit.com/articles/article.asp?p=31473
     *
     * @return DerivedType&
     */
    DerivedType& get_derived() {
        return static_cast<DerivedType&>(*this);
    }

    /**
     * @brief Const version of get_derived().
     *
     * @return const reference to this object as the derived type.
     */
    const DerivedType& get_derived() const {
        return static_cast<DerivedType const&>(*this);
    }

    /**
     * @brief Create lambda that allocates a zeroed element for the case when it
     * is called from a templated class
     *
     * @param params the params to use.
     * @param format - EVALUATION or COEFFICIENT
     * @return a lambda that creates a zero-initialized element with the given parameters and format.
     */
    static std::function<DerivedType()> allocator(const std::shared_ptr<Params>& params, Format format) {
        return [=]() {
            return DerivedType(params, format, true);
        };
    }

    /**
     * @brief Allocator for discrete Gaussian distribution.
     *
     * @param params Params instance that is is passed.
     * @param result_format result_format for the polynomials generated.
     * @param stddev standard deviation for the discrete gaussian generator.
     * @return a lambda that generates a discrete Gaussian element.
     */
    static std::function<DerivedType()> make_discrete_gaussian_coefficient_allocator(const std::shared_ptr<Params>& params,
                                                                                 Format result_format, double stddev) {
        return [=]() {
            DggType dgg(stddev);
            return DerivedType(dgg, params, result_format);
        };
    }

    /**
     * @brief Allocator for discrete uniform distribution.
     *
     * @param params Params instance that is is passed.
     * @param format format for the polynomials generated.
     * @return a lambda that generates a discrete uniform element.
     */
    static std::function<DerivedType()> make_discrete_uniform_allocator(const std::shared_ptr<Params>& params,
                                                                     Format format) {
        return [=]() {
            DugType dug;
            return DerivedType(dug, params, format);
        };
    }

    /**
     * @brief Makes a copy of the RnsPoly, but it includes only a sequential
     * subset of the towers that the original holds.
     *
     * @param start_tower The index number of the first tower to clone
     * @param end_tower The index number of the last tower to clone
     * @return new Element
     */
    DerivedType clone_towers(uint32_t start_tower, uint32_t end_tower) {
        return this->get_derived().clone_towers(start_tower, end_tower);
    }

    /**
     * @brief Makes a copy of this element.
     *
     * @return the copy.
     */
    DerivedType clone() const final {
        return DerivedType(this->get_derived());
    }

    /**
     * @brief Creates a default-constructed element of the derived type: default parameters and no towers.
     *
     * @return the empty element.
     */
    DerivedType clone_empty() const final {
        return DerivedType();
    }

    /**
     * @brief Creates an element with this element's parameters and format whose tower values are left unallocated.
     *
     * @return the new element.
     */
    DerivedType clone_parameters_only() const final {
        return DerivedType(this->get_derived().get_params(), this->get_derived().get_format());
    }

    /**
     * @brief Clone with noise.  This method creates a new RnsPoly and clones the
     * params. The tower values will be filled up with noise based on the discrete
     * gaussian.
     *
     * @param dgg the input discrete Gaussian generator. The dgg will be the seed
     * to populate the towers of the RnsPoly with random numbers.
     * @param format the format of the resulting element; the noise is sampled as
     * coefficients and then converted to this format.
     * @return the new element.
     */
    DerivedType clone_with_noise(const DiscreteGaussianGeneratorImpl<BigVecType>& dgg, Format format) const override = 0;

    /**
     * @brief Get method of the format.
     *
     * @return the format, either COEFFICIENT or EVALUATION
     */
    Format get_format() const override = 0;

    /**
     * @brief returns the element's cyclotomic order
     * @return returns the cyclotomic order of the element.
     */
    uint32_t get_cyclotomic_order() const final {
        return this->get_derived().get_params()->get_cyclotomic_order();
    }

    /**
     * @brief returns the element's ring dimension
     * @return returns the ring dimension of the element.
     */
    uint32_t get_ring_dimension() const {
        return this->get_derived().get_params()->get_ring_dimension();
    }

    /**
     * @brief returns the element's modulus
     * @return returns the modulus of the element.
     */
    const BigIntType& get_modulus() const final {
        return this->get_derived().get_params()->get_modulus();
    }

    /**
     * @brief returns the element's root of unity.
     * @return the element's root of unity.
     */
    const BigIntType& get_root_of_unity() const {
        return this->get_derived().get_params()->get_root_of_unity();
    }

    /**
     * @brief Get method for length of each component element.
     * NOTE assumes all components are the same size. (Ring Dimension)
     *
     * @return length of the component element
     */
    uint32_t get_length() const final {
        return this->get_derived().get_params()->get_ring_dimension();
    }

    /**
     * @brief Get interpolated value of elements at all tower index i.
     * Note this operation is computationally intense. Does bound checking
     * @param i the coefficient index.
     * @return interpolated value at index i.
     */
    BigIntType& at(uint32_t i) final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * @brief Const version of at(); not implemented for double-CRT elements and always throws.
     * @param i the coefficient index.
     * @return never returns; an exception is thrown.
     */
    const BigIntType& at(uint32_t i) const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Get interpolated value of element at index i.
     * Note this operation is computationally intense. No bound checking
     * @param i the coefficient index.
     * @return interpolated value at index i.
     */
    BigIntType& operator[](uint32_t i) final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }
    /**
     * @brief Const version of operator[](); not implemented for double-CRT elements and always throws.
     * @param i the coefficient index.
     * @return never returns; an exception is thrown.
     */
    const BigIntType& operator[](uint32_t i) const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Get method that returns a vector of all component elements.
     *
     * @returns a vector of the component elements.
     */
    const std::vector<TowerType>& get_all_elements() const {
        return this->get_derived().get_all_elements();
    }
    /**
     * @brief Mutable access to the vector of all component elements (towers).
     *
     * @return a reference to the vector of towers.
     */
    std::vector<TowerType>& get_all_elements() {
        return this->get_derived().get_all_elements();
    }

    /**
     * @brief Get method of the number of component elements, also known as the
     * number of towers.
     *
     * @return the number of component elements.
     */
    uint32_t get_num_of_elements() const {
        return this->get_derived().get_all_elements().size();
    }

    /**
     * @brief Get method of individual tower of elements.
     * Note this behavior is different than poly
     * @param i index of tower to be returned.
     * @returns a reference to the returned tower
     */
    const TowerType& get_element_at_index(uint32_t i) const {
        return this->get_derived().get_all_elements()[i];
    }

    /**
     * @brief Sets element at index
     *
     * @param index where the element should be set
     * @param element The element to store
     */
    void set_element_at_index(uint32_t index, const TowerType& element) {
        return this->get_derived().set_element_at_index(index, element);
    }

    /**
     * @brief Sets element at index
     *
     * @param index where the element should be set
     * @param element The element to store
     */
    void set_element_at_index(uint32_t index, TowerType&& element) {
        return this->get_derived().set_element_at_index(index, std::move(element));
    }

    /***********************************************************************
     * Yuriy and I stopped here!
     **********************************************************************/

    /**
     * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base}
     * \rfloor} {(base^i u_i)} \f$ and return the vector of \f$ \left\{u_0,
     * u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil
     * {\log q/base} \rceil}} \f$; This is used as a subroutine in the
     * relinearization procedure.
     *
     * @param base_bits is the number of bits in the base, i.e., \f$ base =
     * 2^{base_bits} \f$.
     * @param eval_mode_answer if true, the digits are returned in EVALUATION format; otherwise in COEFFICIENT format.
     * @return is the pointer where the base decomposition vector is stored
     *
     * @warning not efficient and  not fast, uses multiprecision arithmetic and
     *          will be removed in future. Use @see RnsPolyInterface::crt_decompose instead.
     */
    std::vector<DerivedType> base_decompose(uint32_t base_bits, bool eval_mode_answer) const override = 0;

    /**
     * @brief Generate a vector of PolyImpl's as \f$ \left\{x, {base}*x,
     * {base}^2*x, ..., {base}^{\lfloor {\log q/{base}} \rfloor} \right\}*x \f$,
     * where \f$ x \f$ is the current PolyImpl object;
     * used as a subroutine in the relinearization procedure to get powers of a
     * certain "base" for the secret key element.
     *
     * @param base_bits is the number of bits in the base, i.e., \f$ base =
     * 2^{base_bits} \f$.
     * @return is the pointer where the base decomposition vector is stored
     *
     * @warning not efficient and  not fast, uses multiprecision arithmetic and
     *          will be removed in future. Use @see RnsPolyInterface::crt_decompose instead.
     */
    std::vector<DerivedType> powers_of_base(uint32_t base_bits) const override = 0;

    /**
     * CRT basis decomposition of c as [c qi/q]_qi
     *
     * @param base_bits bits in the base for additional digit decomposition if
     * base > 0
     * @return is the pointer where the resulting vector is stored
     */
    std::vector<DerivedType> crt_decompose(uint32_t base_bits) const {
        return this->get_derived().crt_decompose(base_bits);
    }

    /**
     * @brief Assigns a single-tower (native) polynomial: rhs becomes the first tower and copies of it switched
     * (centered) to each remaining tower modulus become the other towers; if rhs is empty, all towers are empty.
     *
     * @param rhs the native polynomial, with the modulus of the first tower.
     * @return the resulting element.
     */
    DerivedType& operator=(const TowerType& rhs) {
        return this->get_derived().operator=(rhs);
    }

    /**
     * @brief Assignment Operator.
     *
     * @param rhs the copied element.
     * @return the resulting element.
     */
    DerivedType& operator=(const DerivedType& rhs) override = 0;

    /**
     * @brief Move Assignment Operator.
     *
     * @param rhs the copied element.
     * @return the resulting element.
     */
    DerivedType& operator=(DerivedType&& rhs) override = 0;

    /**
     * @brief Initalizer list
     *
     * @param rhs the list to initalized the element.
     * @return the resulting element.
     */
    DerivedType& operator=(std::initializer_list<uint64_t> rhs) override = 0;

    /**
     * @brief Assigns the constant val to every entry of every tower; the element and each tower become EVALUATION, as
     * in PolyImpl::operator=(uint64_t).
     *
     * @param val the value to assign.
     * @return the resulting element.
     */
    DerivedType& operator=(uint64_t val) {
        return this->get_derived().operator=(val);
    }

    /**
     * @brief Creates a Poly from a vector of signed integers (used for trapdoor
     * sampling)
     *
     * @param rhs the vector to set the PolyImpl to.
     * @return the resulting PolyImpl.
     */
    DerivedType& operator=(const std::vector<int64_t>& rhs) {
        return this->get_derived().operator=(rhs);
    }

    /**
     * @brief Creates a Poly from a vector of signed integers (used for trapdoor
     * sampling)
     *
     * @param rhs the vector to set the PolyImpl to.
     * @return the resulting PolyImpl.
     */
    DerivedType& operator=(const std::vector<int32_t>& rhs) {
        return this->get_derived().operator=(rhs);
    }

    /**
     * @brief Initalizer list
     *
     * @param rhs the list to set the PolyImpl to.
     * @return the resulting PolyImpl.
     */
    DerivedType& operator=(std::initializer_list<std::string> rhs) {
        return this->get_derived().operator=(rhs);
    }

    /**
     * @brief Unary minus on a element.
     * @return additive inverse of the an element.
     */
    DerivedType operator-() const override = 0;

    /**
     * @brief Equality operator.
     *
     * @param rhs is the specified element to be compared with this element.
     * @return true if this element represents the same values as the specified
     * element, false otherwise.
     */
    bool operator==(const DerivedType& rhs) const override = 0;

    /**
     * @brief Performs an entry-wise addition over all elements of each tower with
     * the towers of the element on the right hand side.
     *
     * @param rhs is the element to add with.
     * @return is the result of the addition.
     */
    DerivedType& operator+=(const DerivedType& rhs) override = 0;

    /**
     * @brief Performs an entry-wise subtraction over all elements of each tower
     * with the towers of the element on the right hand side.
     *
     * @param rhs is the element to subtract.
     * @return is the result of the subtraction.
     */
    DerivedType& operator-=(const DerivedType& rhs) override = 0;

    /**
     * @brief Permutes coefficients in a polynomial. Moves the ith index to the
     * first one, it only supports odd indices.
     *
     * @param i is the automorphism index (an odd integer) to apply.
     * @return is the result of the automorphism transform.
     */
    DerivedType automorphism_transform(uint32_t i) const override = 0;

    /**
     * @brief Performs an automorphism transform operation using precomputed bit
     * reversal indices.
     *
     * @param i is the automorphism index (an odd integer) to apply.
     * @param vec a vector with precomputed indices
     * @return is the result of the automorphism transform.
     */
    DerivedType automorphism_transform(uint32_t i, const std::vector<uint32_t>& vec) const override = 0;

    /**
     * @brief Transpose the ring element using the automorphism operation
     *
     * @return is the result of the transposition.
     */
    DerivedType transposed() const final {
        if (this->get_derived().get_format() == Format::COEFFICIENT)
            CIPHER_THROW("Transposition is currently implemented only in the Evaluation representation.");
        return this->get_derived().automorphism_transform(this->get_derived().get_cyclotomic_order() - 1);
    }

    /**
     * @brief Performs an addition operation and returns the result.
     *
     * @param rhs is the element to add with.
     * @return is the result of the addition.
     */
    DerivedType plus_impl(const DerivedType& rhs) const override = 0;

    /**
     * @brief Performs a multiplication operation and returns the result.
     *
     * @param rhs is the element to multiply with.
     * @return is the result of the multiplication.
     */
    DerivedType Times(const DerivedType& rhs) const override = 0;

    /**
     * @brief Performs a subtraction operation and returns the result.
     *
     * @param rhs is the element to subtract.
     * @return is the result of the subtraction.
     */
    DerivedType minus_impl(const DerivedType& rhs) const override = 0;

    /**
     * @brief Scalar addition - add an integer to the first coefficient of each tower in
     * COEFFICIENT format, or to all entries of each tower in EVALUATION format.
     *
     * @param rhs is the integer to add.
     * @return is the result of the addition operation.
     */
    DerivedType plus_impl(const BigIntType& rhs) const override = 0;

    /**
     * @brief Scalar addition for elements in CRT format.
     * CRT elements are represented as vector of integer elements which
     * correspond to the represented number modulo the primes in the
     * tower chain (in same order).
     *
     * @param rhs is the element to add entry-wise.
     * @return is the result of the addition operation.
     */
    DerivedType plus_impl(const std::vector<BigIntType>& rhs) const {
        return this->get_derived().plus_impl(rhs);
    }

    /**
     * @brief Scalar subtraction - subtract an element to all entries.
     *
     * @param rhs is the element to subtract entry-wise.
     * @return is the return value of the minus operation.
     */
    DerivedType minus_impl(const BigIntType& rhs) const override = 0;

    /**
     * @brief Scalar subtraction for elements in CRT format.
     * CRT elements are represented as vector of integer elements which
     * correspond to the represented number modulo the primes in the
     * tower chain (in same order).
     *
     * @param rhs is the element to subtract entry-wise.
     * @return is the result of the subtraction operation.
     */
    DerivedType minus_impl(const std::vector<BigIntType>& rhs) const {
        return this->get_derived().minus_impl(rhs);
    }

    /**
     * @brief Scalar multiplication - multiply all entries.
     *
     * @param rhs is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     */
    DerivedType Times(const BigIntType& rhs) const override = 0;

    /**
     * @brief Scalar multiplication - multiply by a signed integer
     *
     * @param rhs is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     */
    DerivedType Times(NativeInteger::SignedNativeInt rhs) const override = 0;

#if CIPHER_NATIVE_INT != 64
    /**
     * @brief Scalar multiplication - multiply by a signed integer
     *
     * @param rhs is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     *
     * @note this is need for 128-bit so that the 64-bit inputs can be used.
     */
    DerivedType Times(int64_t rhs) const {
        return this->get_derived().Times(rhs);
    }
#endif

    /**
     * @brief Scalar multiplication by an integer represented in CRT Basis.
     *
     * @param rhs is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     */
    DerivedType Times(const std::vector<NativeInteger>& rhs) const {
        return this->get_derived().Times(rhs);
    }

    /**
     * @brief Performs a multiplication operation even when the multiplicands
     * have a different number of towers.
     *
     * @param rhs is the element to multiply with.
     * @return is the result of the multiplication.
     */
    DerivedType times_no_check(const std::vector<NativeInteger>& rhs) const {
        return this->get_derived().times_no_check(rhs);
    }

    /**
     * @brief Scalar modular multiplication by an integer represented in CRT
     * Basis.
     *
     * @param rhs is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     *
     * @warning Should remove this, data is truncated to native-word size.
     */
    DerivedType Times(const std::vector<BigIntType>& rhs) const {
        return this->get_derived().Times(rhs);
    }

    /**
     * @brief Scalar multiplication followed by division and rounding operation -
     * operation on all entries.
     *
     * @param p is the element to multiply entry-wise.
     * @param q is the element to divide entry-wise.
     * @return is the return value of the multiply, divide and followed by
     * rounding operation.
     *
     * @warning Will remove, this is only inplace because of BFV
     */
    DerivedType multiply_and_round(const BigIntType& p, const BigIntType& q) const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Scalar division followed by rounding operation - operation on all
     * entries.
     *
     * @param q is the element to divide entry-wise.
     * @return is the return value of the divide, followed by rounding operation.
     *
     * @warning Will remove, this is only inplace because of BFV
     */
    DerivedType divide_and_round(const BigIntType& q) const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Performs a negation operation and returns the result.
     *
     * @return is the result of the negation.
     */
    virtual DerivedType negate() const = 0;

    /**
     * @brief Scalar addition in place: rhs (converted to a native integer) is added to the first coefficient of each
     * tower in COEFFICIENT format, or to all entries of each tower in EVALUATION format.
     *
     * @param rhs the integer to add.
     * @return the resulting element.
     */
    DerivedType& operator+=(const BigIntType& rhs) override = 0;
    /**
     * @brief Scalar addition in place by a native integer: rhs is added to the first coefficient of each tower in
     * COEFFICIENT format, or to all entries of each tower in EVALUATION format.
     *
     * @param rhs the native integer to add.
     * @return the resulting element.
     */
    virtual DerivedType& operator+=(const LilIntType& rhs) = 0;

    /**
     * @brief Performs a subtraction operation and returns the result.
     *
     * @param rhs is the element to subtract.
     * @return is the result of the subtraction.
     */
    DerivedType& operator-=(const BigIntType& rhs) override = 0;
    /**
     * @brief Scalar subtraction in place by a native integer: rhs is subtracted from all entries of each tower.
     *
     * @param rhs the native integer to subtract.
     * @return the resulting element.
     */
    virtual DerivedType& operator-=(const LilIntType& rhs) = 0;

    /**
     * @brief Performs a multiplication operation and returns the result.
     *
     * @param rhs is the element to multiply by.
     * @return is the result of the multiplication.
     */
    DerivedType& operator*=(const BigIntType& rhs) override = 0;
    /**
     * @brief Scalar multiplication in place by a native integer: all entries of each tower are multiplied by rhs.
     *
     * @param rhs the native integer to multiply by.
     * @return the resulting element.
     */
    virtual DerivedType& operator*=(const LilIntType& rhs) = 0;

    /**
     * @brief Performs a multiplication operation and returns the result.
     *
     * @param rhs is the element to multiply with.
     * @return is the result of the multiplication.
     */
    DerivedType& operator*=(const DerivedType& rhs) override = 0;

    // multiplicative inverse operation
    /**
     * @brief Performs a multiplicative inverse operation and returns the result.
     *
     * @return is the result of the multiplicative inverse.
     */
    DerivedType multiplicative_inverse() const override = 0;

    /**
     * @brief Perform a modulus by 2 operation.  Returns the least significant
     * bit.
     *
     * @return is the resulting value.
     *
     * @warning Doesn't make sense for DCRT
     */
    DerivedType mod_by_two() const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Modulus - perform a modulus operation. Does proper mapping of
     * [-modulus/2, modulus/2) to [0, modulus)
     *
     * @param modulus is the modulus to use.
     * @return is the return value of the modulus.
     *
     * @warning Doesn't make sense for DCRT
     */
    DerivedType mod(const BigIntType& modulus) const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Get method that should not be used
     *
     * @return will throw an error.
     *
     * @warning Doesn't make sense for DCRT
     */
    const BigVecType& get_values() const final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Set method that should not be used, will throw an error.
     *
     * @param values ignored; the method always throws.
     * @param format ignored; the method always throws.
     *
     * @warning Doesn't make sense for DCRT
     */
    void set_values(const BigVecType& values, Format format) {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Sets all values of element to zero.
     */
    virtual void set_values_to_zero() = 0;

    /**
     * @brief Sets values with a different modulus: the single tower of element is scaled
     * from its modulus to the given modulus (with rounding) and stored in this element.
     * @param element the single-tower source element whose values are switched.
     * @param modulus the new modulus.
     */
    virtual void set_values_mod_switch(const DerivedType& element, const NativeInteger& modulus) = 0;

    /**
     * @brief Adds "1" to every entry in every tower.
     */
    void add_il_element_one() override = 0;

    /**
     * @brief Add uniformly random values to all components except for the first
     * one
     *
     * @param modulus the modulus for the random values.
     * @return never returns; an exception is thrown.
     * @warning Doesn't make sense for DCRT
     */
    DerivedType add_random_noise(const BigIntType& modulus) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Make RnsPoly Sparse. Sets every index of each tower not equal to
     * zero mod the w_factor to zero.
     *
     * @param w_factor ratio between the sparse and none-sparse values.
     *
     * @warning Only used by RingSwitching, which is no longer supported. Will be removed in future.
     */
    void make_sparse(uint32_t w_factor) final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Returns true if ALL the tower(s) are empty.
     * @return true if all towers are empty
     */
    bool is_empty() const override = 0;

    /**
     * @brief Drops the last element in the double-CRT representation. The
     * resulting RnsPoly element will have one less tower.
     */
    virtual void drop_last_element() = 0;

    /**
     * @brief Drops the last i elements in the double-CRT representation.
     * @param i the number of towers to drop.
     */
    virtual void drop_last_elements(size_t i) = 0;

    /**
     * @brief Drops the last element in the double-CRT representation and scales
     * down by the last CRT modulus, computing round(x/q_l) as
     * (x - [x]_{q_l}) * [q_l^{-1}]_{q_i}. The resulting RnsPoly element will
     * have one less tower and is always in EVALUATION format.
     * @param ql_inv_modq precomputed values for [q_l^{-1}]_{q_i}
     */
    virtual void drop_last_element_and_scale(const std::vector<NativeInteger>& ql_inv_modq) = 0;

    /**
     * @brief ModReduces reduces the RnsPoly element's composite modulus by
     * dropping the last modulus from the chain of moduli as well as dropping the
     * last tower.
     *
     * @param t is the plaintext_modulus used for the RnsPoly
     * @param t_modq_precon NTL-specific precomputations for [t]_{q_i}
     * @param negt_inv_modq precomputed values for [-t^{-1}]_{q_i}
     * @param negt_inv_modq_precon NTL-specific precomputations for [-t^{-1}]_{q_i}
     * @param ql_inv_modq precomputed values for [q_{l}^{-1}]_{q_i}
     * @param ql_inv_modq_precon NTL-specific precomputations for [q_{l}^{-1}]_{q_i}
     */
    virtual void mod_reduce(const NativeInteger& t, const std::vector<NativeInteger>& t_modq_precon,
                           const NativeInteger& negt_inv_modq, const NativeInteger& negt_inv_modq_precon,
                           const std::vector<NativeInteger>& ql_inv_modq,
                           const std::vector<NativeInteger>& ql_inv_modq_precon) = 0;

    /**
     * @brief Interpolates the RnsPoly to a Poly based on the Chinese Remainder
     * Transform Interpolation. and then returns a Poly with that single element
     *
     * @return the interpolated ring element as a Poly object.
     */
    virtual PolyLargeType crt_interpolate() const = 0;

    /**
     * @brief Interpolates the towers to a single polynomial modulo the composite modulus Q, maps each coefficient
     * from the centered range [-Q/2, Q/2) to [0, ptm) and returns the result as a native polynomial with modulus ptm;
     * this produces the plaintext polynomial at decryption.
     *
     * @param ptm the plaintext modulus.
     * @return the native polynomial of the reduced coefficients, in this element's format.
     */
    virtual TowerType decryption_crt_interpolate(PlaintextModulus ptm) const = 0;

    /**
     * @brief If the values are small enough this is used for efficiency
     *
     * @return NativePoly
     *
     * @warning This will be replaced with a non-member utility function.
     */
    virtual TowerType to_native_poly() const = 0;

    /**
     * @brief Interpolates the RnsPoly to a Poly based on the Chinese Remainder
     * Transform Interpolation, only at element index i, all other elements are
     * zero. and then returns a Poly with that single element
     *
     * @param i the coefficient index to interpolate.
     * @return the interpolated ring element as a Poly object.
     */
    virtual PolyLargeType crt_interpolate_index(uint32_t i) const = 0;

    /**
     * @brief Computes and returns the product of primes in the current moduli
     * chain. Compared to get_modulus, which always returns the product of all
     * primes in the crypto parameters, this method will return a different
     * modulus, based on the towers/moduli that are currently in the chain (some
     * towers are dropped along the way).
     *
     * @return the product of moduli in the current towers.
     */
    virtual BigIntType get_working_modulus() const = 0;

    /**
     * @brief Returns the element parameters for RnsPoly elements in an extended
     * CRT basis, which is the concatenation of the towers currently in "this"
     * RnsPoly, and the moduli in ParamsP.
     *
     * @param params_p element parameters for the moduli to append to the current towers.
     * @return element parameters of the extended basis.
     */
    virtual std::shared_ptr<Params> get_extended_crt_basis(const std::shared_ptr<Params>& params_p) const = 0;

    /**
     * @brief Scales the element by Q/t in place, as used to encode a BFV plaintext into a ciphertext: each coefficient
     * m (assumed reduced modulo t) of every tower becomes [[m*(-Q)]_t * t^{-1}]_{q_i}, which equals ceil(Q*m/t) mod
     * q_i, where Q is the product of the current tower moduli and t the plaintext modulus.
     *
     * @param params_q element parameters of the basis Q (not used by the default implementation, whose current
     * towers define the basis).
     * @param t_inv_modq precomputed values for [t^{-1}]_{q_i}.
     * @param t the plaintext modulus.
     * @param neg_q_modt precomputed value for [-Q]_t.
     * @param neg_q_modt_precon NTL-specific precomputation for neg_q_modt.
     */
    virtual void times_qovert(const std::shared_ptr<Params>& params_q, const std::vector<NativeInteger>& t_inv_modq,
                             const NativeInteger& t, const NativeInteger& neg_q_modt,
                             const NativeInteger& neg_q_modt_precon) = 0;

    /**
     * @brief Performs approximate CRT basis switching:
     * {X}_{Q} -> {X'}_{P}
     * X' = X + alpha*Q for small alpha
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * [X']_{p_j} = [sum over i of [x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)]_{p_j}
     *
     * Source: "A full RNS variant of approximate homomorphic encryption" by
     * Cheon, et. al.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}
     * @param q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values
     * @return the representation of {X + alpha*Q} in basis {P}.
     */
    virtual DerivedType approx_switch_crt_basis(const std::shared_ptr<Params>& params_q,
                                             const std::shared_ptr<Params>& params_p,
                                             const std::vector<NativeInteger>& q_hat_inv_modq,
                                             const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                             const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                             const std::vector<DoubleNativeInt>& modp_barrett_mu) const = 0;

    /**
     * @brief Performs approximate modulus raising:
     * {X}_{Q} -> {X'}_{Q,P}.
     * X' = X + alpha*Q for small alpha
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * {X}_{Q} -> {X'}_Q : trivial
     * {X}_{Q} -> {X'}_P : use RnsPoly::approx_switch_crt_basis
     *
     * Source: "A full RNS variant of approximate homomorphic encryption" by
     * Cheon, et. al.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param params_qp parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}
     * @param q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for
     * p_j
     * The element is replaced in place by the representation of {X + alpha*Q} in basis {Q,P}.
     */
    virtual void approx_mod_up(const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
                             const std::shared_ptr<Params>& params_qp, const std::vector<NativeInteger>& q_hat_inv_modq,
                             const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                             const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                             const std::vector<DoubleNativeInt>& modp_barrett_mu) = 0;

    /**
     * @brief Performs approximate modulus reduction:
     * {X}_{Q,P} -> {approximately X/P}_{Q}.
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * 1) use RnsPoly::approx_switch_crt_basis : {X}_{P} -> {X'}_{Q}
     * 2) compute : {(X-X') * P^{-1}}_{Q}
     *
     * Source: "A full RNS variant of approximate homomorphic encryption" by
     * Cheon, et. al.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param P_inv_modq precomputed values for (P^{-1} mod q_j)
     * @param p_inv_modq_precon NTL-specific precomputations
     * @param p_hat_inv_modp precomputed values for [(P/p_j)^{-1}]_{p_j}
     * @param p_hat_inv_modp_precon NTL-specific precomputations
     * @param p_hat_modq precomputed values for [P/p_j]_{q_i}
     * @param modq_barrett_mu 128-bit Barrett reduction precomputed values for
     * q_i
     * @param t_inv_modp precomputed values for [t^{-1}]_{p_j}
     * used in BGVrns
     * @param t_inv_modp_precon NTL-specific precomputations
     * @param t often corresponds to the plaintext modulus
     * used in BGVrns
     * @param t_modq_precon NTL-specific precomputations for t modulo q_i
     * @return the representation of approximately X/P in basis {Q}
     */
    virtual DerivedType approx_mod_down(
            const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
            const std::vector<NativeInteger>& P_inv_modq, const std::vector<NativeInteger>& p_inv_modq_precon,
            const std::vector<NativeInteger>& p_hat_inv_modp, const std::vector<NativeInteger>& p_hat_inv_modp_precon,
            const std::vector<std::vector<NativeInteger>>& p_hat_modq, const std::vector<DoubleNativeInt>& modq_barrett_mu,
            const std::vector<NativeInteger>& t_inv_modp, const std::vector<NativeInteger>& t_inv_modp_precon,
            const NativeInteger& t, const std::vector<NativeInteger>& t_modq_precon) const = 0;

    /**
     * @brief Performs CRT basis switching:
     * {X}_{Q} -> {X}_{P}
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * 1) X = sum over i of [x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i) - alpha*Q
     * 2) compute round[[x_i*(Q/q_i)^{-1}]_{q_i} / q_i] to find alpha
     * 3) [X]_{p_j} = [sum over i of [x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)]_{p_j} - [alpha*Q]_{p_j}
     *
     * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
     * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
     * 2018/117. (https://eprint.iacr.org/2018/117)
     *
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}
     * @param q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for
     * p_j
     * @param q_inv precomputed values for 1/q_i
     * @return the representation of {X}_{P}
     */
    virtual DerivedType switch_crt_basis(const std::shared_ptr<Params>& params_p,
                                       const std::vector<NativeInteger>& q_hat_inv_modq,
                                       const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                       const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                       const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                       const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                       const std::vector<double>& q_inv) const = 0;

    /**
     * @brief Performs modulus raising:
     * {X}_{Q} -> {X}_{Q,P}
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * {X}_{Q} -> {X}_P : use RnsPoly::switch_crt_basis
     * combine {X}_{Q} and {X}_{P}
     * Outputs the resulting polynomial in CRT/RNS
     *
     * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
     * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
     * 2018/117. (https://eprint.iacr.org/2018/117)
     *
     * @param params_qp parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param q_hat_inv_modq precomputed values for [QInv_i]_{q_i}
     * @param q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modp precomputed values for [QHat_i]_{p_j}
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for
     * p_j
     * @param q_inv precomputed values for 1/q_i
     * @param result_format Specifies the format we want the result to be in
     *
     */
    virtual void expand_crt_basis(const std::shared_ptr<Params>& params_qp, const std::shared_ptr<Params>& params_p,
                                const std::vector<NativeInteger>& q_hat_inv_modq,
                                const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                const std::vector<DoubleNativeInt>& modp_barrett_mu, const std::vector<double>& q_inv,
                                Format result_format) = 0;

    /**
     * @brief Performs modulus raising in reverse order:
     * {X}_{Q} -> {X}_{P,Q}
     *
     * @param params_qp parameters for the CRT basis {p_1,...,p_k,q_1,...,q_l}
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}
     * @param q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j
     * @param q_inv precomputed values for 1/q_i
     * @param result_format Specifies the format we want the result to be in
     */
    virtual void expand_crt_basis_reverse_order(const std::shared_ptr<Params>& params_qp,
                                            const std::shared_ptr<Params>& params_p,
                                            const std::vector<NativeInteger>& q_hat_inv_modq,
                                            const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                            const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                            const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                            const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                            const std::vector<double>& q_inv, Format result_format) = 0;

    /**
     * @brief Precomputed constants for fast_expand_crt_basis_plover_q, the switch of an element from its current basis
     * (with product Q) to the extended basis {Q_l, P_l} used by the BFV HPSPOVERQ multiplication variants, with
     * {Q_l} = {q_1,...,q_l} and {P_l} = {p_1,...,p_k}.
     */
    struct CrtBasisExtensionPrecomputations {
        // TODO (dsuponit) and (pascoec): make the data members private to enforce their constantness and add getters.
        /** element parameters of the extended basis {Q_l, P_l} */
        std::shared_ptr<Params> params_ql_pl;
        /** element parameters of the basis {P_l} */
        std::shared_ptr<Params> params_pl;
        /** element parameters of the basis {Q_l} */
        std::shared_ptr<Params> params_ql;
        /** precomputed values for [-P_l*(Q/q_i)^{-1}]_{q_i} */
        std::vector<NativeInteger> m_pl_q_hat_inv_modq;
        /** NTL-specific precomputations for m_pl_q_hat_inv_modq */
        std::vector<NativeInteger> m_pl_q_hat_inv_modq_precon;
        /** precomputed values for [q_i^{-1}]_{p_j} */
        std::vector<std::vector<NativeInteger>> q_inv_modp;
        /** 128-bit Barrett reduction precomputed values for p_j */
        std::vector<DoubleNativeInt> modp_barrett_mu;
        /** precomputed values for [(P_l/p_j)^{-1}]_{p_j} */
        std::vector<NativeInteger> pl_hat_inv_modp;
        /** NTL-specific precomputations for pl_hat_inv_modp */
        std::vector<NativeInteger> pl_hat_inv_modp_precon;
        /** precomputed values for [P_l/p_j]_{q_i} */
        std::vector<std::vector<NativeInteger>> pl_hat_modq;
        /** precomputed values for [alpha*P_l]_{q_i} */
        std::vector<std::vector<NativeInteger>> alpha_pl_modq;
        /** 128-bit Barrett reduction precomputed values for q_i */
        std::vector<DoubleNativeInt> modq_barrett_mu;
        /** precomputed values for 1/p_j */
        std::vector<double> p_inv;

        // clang-format off
        /**
       * @brief Constructs the precomputation set from its components.
       * @param params_ql_pl0 element parameters of the extended basis {Q_l, P_l}.
       * @param params_pl0 element parameters of the basis {P_l}.
       * @param params_ql0 element parameters of the basis {Q_l}.
       * @param m_pl_q_hat_inv_modq0 precomputed values for [-P_l*(Q/q_i)^{-1}]_{q_i}.
       * @param m_pl_q_hat_inv_modq_precon0 NTL-specific precomputations for m_pl_q_hat_inv_modq0.
       * @param q_inv_modp0 precomputed values for [q_i^{-1}]_{p_j}.
       * @param modp_barrett_mu0 128-bit Barrett reduction precomputed values for p_j.
       * @param pl_hat_inv_modp0 precomputed values for [(P_l/p_j)^{-1}]_{p_j}.
       * @param pl_hat_inv_modp_precon0 NTL-specific precomputations for pl_hat_inv_modp0.
       * @param pl_hat_modq0 precomputed values for [P_l/p_j]_{q_i}.
       * @param alpha_pl_modq0 precomputed values for [alpha*P_l]_{q_i}.
       * @param modq_barrett_mu0 128-bit Barrett reduction precomputed values for q_i.
       * @param p_inv0 precomputed values for 1/p_j.
       */
        CrtBasisExtensionPrecomputations(
            const std::shared_ptr<Params>& params_ql_pl0,
            const std::shared_ptr<Params>& params_pl0,
            const std::shared_ptr<Params>& params_ql0,
            const std::vector<NativeInteger>& m_pl_q_hat_inv_modq0,
            const std::vector<NativeInteger>& m_pl_q_hat_inv_modq_precon0,
            const std::vector<std::vector<NativeInteger>>& q_inv_modp0,
            const std::vector<DoubleNativeInt>& modp_barrett_mu0,
            const std::vector<NativeInteger>& pl_hat_inv_modp0,
            const std::vector<NativeInteger>& pl_hat_inv_modp_precon0,
            const std::vector<std::vector<NativeInteger>>& pl_hat_modq0,
            const std::vector<std::vector<NativeInteger>>& alpha_pl_modq0,
            const std::vector<DoubleNativeInt>& modq_barrett_mu0,
            const std::vector<double>& p_inv0)
            : params_ql_pl(params_ql_pl0),
              params_pl(params_pl0),
              params_ql(params_ql0),
              m_pl_q_hat_inv_modq(m_pl_q_hat_inv_modq0),
              m_pl_q_hat_inv_modq_precon(m_pl_q_hat_inv_modq_precon0),
              q_inv_modp(q_inv_modp0),
              modp_barrett_mu(modp_barrett_mu0),
              pl_hat_inv_modp(pl_hat_inv_modp0),
              pl_hat_inv_modp_precon(pl_hat_inv_modp_precon0),
              pl_hat_modq(pl_hat_modq0),
              alpha_pl_modq(alpha_pl_modq0),
              modq_barrett_mu(modq_barrett_mu0),
              p_inv(p_inv0) {}
        // clang-format on
    };
    typedef struct CrtBasisExtensionPrecomputations CrtBasisExtensionPrecomputations;

    /**
     * @brief Scales the element by P_l/Q and expands it to the basis {Q_l, P_l} in place (the "P over Q" step of the
     * BFV HPSPOVERQ multiplication variants):
     * {X}_{Q} -> {approximately P_l/Q * X}_{Q_l,P_l}
     * {Q} = the current towers, with product Q
     * {Q_l} = {q_1,...,q_l}
     * {P_l} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * 1) approx_switch_crt_basis with the constants [-P_l*(Q/q_i)^{-1}]_{q_i} and [q_i^{-1}]_{p_j} yields
     *    Y = (P_l*X + sum over i of [-P_l*x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)) / Q in basis {P_l}, i.e. P_l/Q * X
     *    plus an error in [0, l)
     * 2) switch_crt_basis converts {Y}_{P_l} exactly to {Y}_{Q_l}
     * 3) the towers of {Y}_{Q_l} followed by those of {Y}_{P_l} form the result in basis {Q_l, P_l}
     *
     * @param precomputed the precomputed constants for the bases Q, Q_l and P_l.
     */
    virtual void fast_expand_crt_basis_plover_q(const CrtBasisExtensionPrecomputations& precomputed) = 0;

    /**
     * @brief Expands the element from the basis {Q_l} = {q_1,...,q_l} back to the full basis {Q} = {q_1,...,q_L}
     * while multiplying it by Q/Q_l, in place:
     * {X}_{Q_l} -> {X * Q/Q_l}_{Q}
     * Each existing tower is multiplied by [Q/Q_l]_{q_i}; the towers for q_{l+1},...,q_L are zero because Q/Q_l
     * vanishes modulo them. Used by the HPSPOVERQLEVELED BFV multiplication variant.
     *
     * @param params_q element parameters of the full basis {Q}.
     * @param ql_hat_modq precomputed values for [Q/Q_l]_{q_i}, i = 1,...,l.
     * @param ql_hat_modq_precon NTL-specific precomputations for ql_hat_modq.
     * @param size_q the number of towers L in the full basis {Q}.
     */
    virtual void expand_crt_basis_ql_hat(const std::shared_ptr<Params>& params_q,
                                     const std::vector<NativeInteger>& ql_hat_modq,
                                     const std::vector<NativeInteger>& ql_hat_modq_precon, const uint32_t size_q) = 0;

    /**
     * @brief Performs scale and round:
     * {X}_{Q} -> {round(t/Q*X)}_t
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * [sum over i of x_i*[t*QHatInv_i/q_i]_t + Round(sum over i of x_i*{t*QHatInv_i/q_i})]_t
     *
     * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
     * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
     * 2018/117. (https://eprint.iacr.org/2018/117)
     *
     * @param t often corresponds to the plaintext modulus
     * @param t_q_hat_inv_modq_divq_modt precomputed values for
     * [Floor{t*QHatInv_i/q_i}]_t
     * @param t_q_hat_inv_modq_divq_modt_precon NTL-specific precomputations
     * @param t_q_hat_inv_modq_b_divq_modt precomputed values for
     * [Floor{t*QHatInv_i*B/q_i}]_t used when CRT moduli are 45..60 bits long
     * @param t_q_hat_inv_modq_b_divq_modt_precon NTL-specific precomputations
     * used when CRT moduli are 45..60 bits long
     * @param t_q_hat_inv_modq_divq_frac precomputed values for Frac{t*QHatInv_i/q_i}
     * @param t_q_hat_inv_modq_b_divq_frac precomputed values for Frac{t*QHatInv_i*B/q_i}
     * used when CRT moduli are 45..60 bits long
     * @return the result of computation as a polynomial with native 64-bit
     * coefficients
     */
    virtual TowerType scale_and_round(const NativeInteger& t, const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt,
                                    const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt_precon,
                                    const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt,
                                    const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt_precon,
                                    const std::vector<double>& t_q_hat_inv_modq_divq_frac,
                                    const std::vector<double>& t_q_hat_inv_modq_b_divq_frac) const = 0;

    /**
     * @brief Computes approximate scale and round:
     * {X}_{Q,P} -> {approximately t/Q * X}_{P}
     * {Q} = {q_1,...,q_l}
     * {P} = {p_1,...,p_k}
     *
     * Brief algorithm:
     * Let S = {Q,P}
     * 1) [sum over k of x_k * alpha_k]_{p_j}
     * 2) alpha_k = [Floor[t*P*[[SHatInv_k]_{s_k}/s_k]]_{p_j}
     *
     * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
     * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
     * 2018/117. (https://eprint.iacr.org/2018/117)
     *
     * @param params_p parameters for the CRT basis {p_1,...,p_k}
     * @param t_ps_hat_inv_mods_divs_modp precomputed values for
     * [floor[t*P*[[SHatInv_k]_{s_k}/s_k]]_{p_j}
     * @param modp_barret_mu 128-bit Barrett reduction precomputed values for
     * p_j
     * @return the result {approximately t/Q * X}_{P}
     */
    virtual DerivedType approx_scale_and_round(const std::shared_ptr<Params>& params_p,
                                            const std::vector<std::vector<NativeInteger>>& t_ps_hat_inv_mods_divs_modp,
                                            const std::vector<DoubleNativeInt>& modp_barret_mu) const = 0;

    /**
     * @brief Computes scale and round:
     * {X}_{I,O} -> {t/I * X}_{O}
     * {I} = {i_1,...,i_l}
     * {O} = {o_1,...,o_k}
     * O, the output modulus can be either P or Q, and I is the other one.
     *
     * Brief algorithm:
     * Let S = {I,O}
     * 1) [sum over k of x_k * alpha_k + Round(sum over k of beta_k * x_k)]_{o_j}
     * 2) alpha_k = [Floor[t*O*[[SHatInv_k]_{s_k}/s_k]]_{o_j}
     * 3) beta_k = {t*O*[[SHatInv_k]_{s_k}/s_k}
     *
     * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
     * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
     * 2018/117. (https://eprint.iacr.org/2018/117)
     *
     * @param params_output parameters for the CRT basis {o_1,...,o_k}.
     * @param t_os_hat_inv_mods_divs_modo precomputed values for
     * [floor[t*O*[[SHatInv_k]_{s_k}/s_k]]_{o_j}
     * @param t_os_hat_inv_mods_divs_frac precomputed values for
     * {t*O*[[SHatInv_k]_{s_k}/s_k}
     * @param modo_barret_mu 128-bit Barrett reduction precomputed values for
     * o_j
     * @return the result {t/I * X}_{O}
     */
    virtual DerivedType scale_and_round(const std::shared_ptr<Params>& params_output,
                                      const std::vector<std::vector<NativeInteger>>& t_os_hat_inv_mods_divs_modo,
                                      const std::vector<double>& t_os_hat_inv_mods_divs_frac,
                                      const std::vector<DoubleNativeInt>& modo_barret_mu) const = 0;

    /**
     * @brief Computes scale and round for fast rounding:
     * {X}_{Q} -> {round(t/Q * X)}_t
     * {Q} = {q_1,...,q_l}
     *
     * Brief algorithm:
     *
     * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
     * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
     * Schemes. Cryptology ePrint Archive: Report 2016/510.
     * (https://eprint.iacr.org/2016/510)
     *
     * @param moduli_q moduli {q_1,...,q_l}
     * @param t often corresponds to the plaintext modulus
     * @param tgamma t * gamma : t * 2^26 reduction
     * @param tgamma_q_hat_modq [t*gamma*(Q/q_i)]_{q_i}
     * @param tgamma_q_hat_modq_precon NTL-specific precomputations
     * @param neg_invq_modtgamma [-q^{-1}]_{t*gamma}
     * @param neg_invq_modtgamma_precon NTL-specific precomputations
     * @return the result of computation as a polynomial with native 64-bit coefficients
     */
    virtual TowerType scale_and_round(const std::vector<NativeInteger>& moduli_q, const NativeInteger& t,
                                    const NativeInteger& tgamma, const std::vector<NativeInteger>& tgamma_q_hat_modq,
                                    const std::vector<NativeInteger>& tgamma_q_hat_modq_precon,
                                    const std::vector<NativeInteger>& neg_invq_modtgamma,
                                    const std::vector<NativeInteger>& neg_invq_modtgamma_precon) const = 0;

    /**
     * @brief Computes scale and round for BFV encryption mode EXTENDED:
     * {X}_{Qp} -> {round(1/p * X)}_Q
     * {Q} = {q_1,...,q_l}
     *
     * Source: Andrey Kim and Yuriy Polyakov and Vincent Zucca. Revisiting Homomorphic Encryption
     * Schemes for Finite Fields. Cryptology ePrint Archive: Report 2021/204.
     * (https://eprint.iacr.org/2021/204.pdf)
     *
     * @param params_q Parameters for moduli {q_1,...,q_l}
     * @param p_inv_modq p^{-1}_{q_i}
     */
    virtual void scale_and_round_p_over_q(const std::shared_ptr<Params>& params_q,
                                     const std::vector<NativeInteger>& p_inv_modq) = 0;

    /**
     * @brief Expands basis:
     * {X}_{Q} -> {X}_{Q,Bsk,mtilde}
     * mtilde is a redundant modulus used to remove q overflows generated from
     * fast conversion. Outputs the resulting polynomial in CRT/RNS
     * {Q} = {q_1,...,q_l}
     * {Bsk} = {bsk_1,...,bsk_k}
     *
     *
     * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
     * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
     * Schemes. Cryptology ePrint Archive: Report 2016/510.
     * (https://eprint.iacr.org/2016/510)
     *
     * @param params_q_bsk: container of QBsk moduli and roots on unity
     * @param moduli_q: basis {Q} = {q_1,q_2,...,q_l}
     * @param moduli_bsk: basis {Bsk U mtilde} ...
     * @param modbsk_barrett_mu: 128-bit Barrett reduction precomputed values for
     * bsk_j
     * @param mtilde_q_hat_inv_modq: [mtilde*(Q/q_i)^{-1}]_{q_i}
     * @param mtilde_q_hat_inv_modq_precon NTL-specific precomputations
     * @param q_hat_modbsk: [Q/q_i]_{bsk_j}
     * @param q_hat_modmtilde: [Q/q_i]_{mtilde}
     * @param q_modbsk: [Q]_{bsk_j}
     * @param q_modbsk_precon NTL-specific precomputations
     * @param neg_q_inv_modmtilde: [-Q^{-1}]_{mtilde}
     * @param mtilde_inv_modbsk: [mtilde^{-1}]_{bsk_j}
     * @param mtilde_inv_modbsk_precon NTL-specific precomputations
     */
    virtual void fast_base_convq_to_bsk_montgomery(
            const std::shared_ptr<Params>& params_q_bsk, const std::vector<NativeInteger>& moduli_q,
            const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
            const std::vector<NativeInteger>& mtilde_q_hat_inv_modq,
            const std::vector<NativeInteger>& mtilde_q_hat_inv_modq_precon,
            const std::vector<std::vector<NativeInteger>>& q_hat_modbsk, const std::vector<uint64_t>& q_hat_modmtilde,
            const std::vector<NativeInteger>& q_modbsk, const std::vector<NativeInteger>& q_modbsk_precon,
            uint64_t neg_q_inv_modmtilde, const std::vector<NativeInteger>& mtilde_inv_modbsk,
            const std::vector<NativeInteger>& mtilde_inv_modbsk_precon) = 0;

    /**
     * @brief Computes scale and floor:
     * {X}_{Q,Bsk} -> {floor(t/Q * X)}_{Bsk}
     * {Q} = {q_1,...,q_l}
     * {Bsk} = {bsk_1,...,bsk_k}
     * Outputs the resulting polynomial in CRT/RNS
     *
     * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
     * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
     * Schemes. Cryptology ePrint Archive: Report 2016/510.
     * (https://eprint.iacr.org/2016/510)
     *
     * @param t: plaintext modulus
     * @param moduli_q: {Q} = {q_1,...,q_l}
     * @param moduli_bsk: {Bsk} = {bsk_1,...,bsk_k}
     * @param modbsk_barrett_mu: 128-bit Barrett reduction precomputed values for
     * bsk_j
     * @param t_q_hat_inv_modq: [(Q/q_i)^{-1}]_{q_i}
     * @param t_q_hat_inv_modq_precon: NTL-specific precomputations
     * @param q_hat_modbsk: [Q/q_i]_{bsk_i}
     * @param q_inv_modbsk: [(q_i)^{-1}]_{bsk_j}
     * @param t_q_inv_modbsk: [t*Q^{-1}]_{bsk_j}
     * @param t_q_inv_modbsk_precon: NTL-specific precomputations
     */
    virtual void fast_rns_floorq(const NativeInteger& t, const std::vector<NativeInteger>& moduli_q,
                               const std::vector<NativeInteger>& moduli_bsk,
                               const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
                               const std::vector<NativeInteger>& t_q_hat_inv_modq,
                               const std::vector<NativeInteger>& t_q_hat_inv_modq_precon,
                               const std::vector<std::vector<NativeInteger>>& q_hat_modbsk,
                               const std::vector<std::vector<NativeInteger>>& q_inv_modbsk,
                               const std::vector<NativeInteger>& t_q_inv_modbsk,
                               const std::vector<NativeInteger>& t_q_inv_modbsk_precon) = 0;

    /**
     * @brief Converts basis:
     * {X}_{Q,Bsk} -> {X}_{Q}
     * {Q} = {q_1,...,q_l}
     * {Bsk} = {bsk_1,...,bsk_k}
     * using Shenoy Kumaresan method: the Q towers are recomputed from the Bsk
     * towers, which are then dropped.
     * Outputs the resulting polynomial in CRT/RNS
     *
     * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
     * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
     * Schemes. Cryptology ePrint Archive: Report 2016/510.
     * (https://eprint.iacr.org/2016/510)
     *
     * Note in the source paper, B is referred to by M.
     *
     * @param params_q: Params for Q
     * @param modq_barrett_mu precomputed Barrett Mu for q_i
     * @param moduli_bsk: basis {Bsk} = {bsk_1,...,bsk_k}
     * @param modbsk_barrett_mu: precomputed Barrett Mu for bsk_j
     * @param b_hat_inv_modb: [(B/b_j)^{-1}]_{b_j}
     * @param b_hat_inv_modb_precon NTL precomptations for [(B/b_j)^{-1}]_{b_j}
     * @param b_hat_modmsk: [B/b_j]_{msk}
     * @param b_inv_modmsk: [B^{-1}]_{msk}
     * @param b_inv_modmsk_precon NTL precomptation for [B^{-1}]_{msk}
     * @param b_hat_modq: [B/b_j]_{q_i}
     * @param b_modq: [B]_{q_i}
     * @param b_modq_precon NTL precomptations for [B]_{q_i}
     */
    virtual void fast_base_conv_sk(
            const std::shared_ptr<Params>& params_q, const std::vector<DoubleNativeInt>& modq_barrett_mu,
            const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
            const std::vector<NativeInteger>& b_hat_inv_modb, const std::vector<NativeInteger>& b_hat_inv_modb_precon,
            const std::vector<NativeInteger>& b_hat_modmsk, const NativeInteger& b_inv_modmsk,
            const NativeInteger& b_inv_modmsk_precon, const std::vector<std::vector<NativeInteger>>& b_hat_modq,
            const std::vector<NativeInteger>& b_modq, const std::vector<NativeInteger>& b_modq_precon) = 0;

    /**
     * @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
     *
     * @param thread_limit upper bound on the number of OpenMP threads for the loop over the towers; 0 means up to
     * one thread per tower.
     * @warning use @see set_format(format) instead
     */
    void switch_format(uint32_t thread_limit = 0) override = 0;

    /**
     * @brief Sets format to value without performing NTT. Only use if you know what you're doing.
     *
     * @param f the format to record.
     */
    virtual void override_format(const Format f) = 0;

    /**
     * @brief Switch modulus and adjust the values
     *
     * @param modulus is the modulus to be set
     * @param root_of_unity_value is the corresponding root of unity for the modulus
     * @param modulus_arb is the modulus used for arbitrary cyclotomics CRT
     * @param root_of_unity_arb is the corresponding root of unity for the modulus
     * ASSUMPTION: This method assumes that the caller provides the correct
     * root_of_unity_value for the modulus
     */
    void switch_modulus(const BigIntType& modulus, const BigIntType& root_of_unity_value, const BigIntType& modulus_arb,
                       const BigIntType& root_of_unity_arb) final {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * @brief Switch modulus at tower i and adjust the values
     *
     * @param index is the index for the tower
     * @param modulus is the modulus to be set
     * @param root_of_unity_value is the corresponding root of unity for the modulus
     * ASSUMPTION: This method assumes that the caller provides the correct
     * root_of_unity_value for the modulus
     */
    virtual void switch_modulus_at_index(size_t index, const BigIntType& modulus, const BigIntType& root_of_unity_value) = 0;

    /**
     * @brief Determines if inverse exists
     *
     * @return is the Boolean representation of the existence of multiplicative
     * inverse.
     */
    bool inverse_exists() const override = 0;

    /**
     * @brief Returns the infinity norm, basically the largest value in the ring
     * element.
     *
     * @return is the largest value in the ring element.
     */
    //    virtual double norm() const override = 0;
    double norm() const final {
        return PolyLargeType(this->get_derived().crt_interpolate()).norm();
    }

    /**
     * @brief Returns the name of the derived element type, e.g. "RnsPolyImpl".
     *
     * @return the element type name.
     */
    const std::string get_element_name() const {
        return this->get_derived().get_element_name();
    }

  protected:
    /**
     * @brief ostream operator
     * @param os the input preceding output stream
     * @param vec the element to add to the output stream.
     * @return a resulting concatenated output stream
     */
    friend inline std::ostream& operator<<(std::ostream& os, const DerivedType& vec) {
        // os << (vec.format_ == EVALUATION ? "EVAL: " : "COEF: ");
        for (uint32_t i = 0; i < vec.get_all_elements().size(); i++) {
            if (i != 0)
                os << std::endl;
            os << i << ": ";
            os << vec.get_all_elements()[i];
        }
        return os;
    }

    /**
     * @brief Element-element addition operator.
     * @param a first element to add.
     * @param b second element to add.
     * @return the result of the addition operation.
     */
    friend inline DerivedType operator+(const DerivedType& a, const DerivedType& b) {
        return a.plus_impl(b);
    }
    /**
     * @brief Element-integer addition operator.
     * @param a first element to add.
     * @param b integer to add.
     * @return the result of the addition operation.
     */
    friend inline DerivedType operator+(const DerivedType& a, const BigIntType& b) {
        return a.plus_impl(b);
    }

    /**
     * @brief BigIntType-element addition operator.
     * @param a integer to add.
     * @param b element to add.
     * @return the result of the addition operation.
     */
    friend inline DerivedType operator+(const BigIntType& a, const DerivedType& b) {
        return b.plus_impl(a);
    }

    /**
     * @brief Element-integer addition operator with CRT integer.
     * @param a first element to add.
     * @param b integer to add.
     * @return the result of the addition operation.
     */
    friend inline DerivedType operator+(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.plus_impl(b);
    }

    /**
     * @brief BigIntType-element addition operator with CRT integer.
     * @param a integer to add.
     * @param b element to add.
     * @return the result of the addition operation.
     */
    friend inline DerivedType operator+(const std::vector<BigIntType>& a, const DerivedType& b) {
        return b.plus_impl(a);
    }

    /**
     * @brief Element-element subtraction operator.
     * @param a element to subtract from.
     * @param b element to subtract.
     * @return the result of the subtraction operation.
     */
    friend inline DerivedType operator-(const DerivedType& a, const DerivedType& b) {
        return a.minus_impl(b);
    }

    /**
     * @brief Element-integer subtraction operator with CRT integer.
     * @param a element to subtract from.
     * @param b integer to subtract.
     * @return the result of the subtraction operation.
     */
    friend inline DerivedType operator-(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.minus_impl(b);
    }

    /**
     * @brief BigIntType-element subtraction operator with CRT integer.
     * @param a integer to subtract from.
     * @param b element to subtract.
     * @return the result of the subtraction operation.
     */
    friend inline DerivedType operator-(const std::vector<BigIntType>& a, const DerivedType& b) {
        return b.minus_impl(a);
    }

    /**
     * @brief Element-integer subtraction operator.
     * @param a element to subtract from.
     * @param b integer to subtract.
     * @return the result of the subtraction operation.
     */
    friend inline DerivedType operator-(const DerivedType& a, const BigIntType& b) {
        return a.minus_impl(b);
    }

    /**
     * @brief Element-element multiplication operator.
     * @param a element to multiply.
     * @param b element to multiply.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(const DerivedType& a, const DerivedType& b) {
        return a.Times(b);
    }

    /**
     * @brief Element-integer multiplication operator.
     * @param a element to multiply.
     * @param b integer to multiply.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(const DerivedType& a, const BigIntType& b) {
        return a.Times(b);
    }

    /**
     * @brief Element-CRT number multiplication operator.
     * @param a element to multiply.
     * @param b integer to multiply, in CRT format.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.Times(b);
    }

    /**
     * @brief BigIntType-element multiplication operator.
     * @param a integer to multiply.
     * @param b element to multiply.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(const BigIntType& a, const DerivedType& b) {
        return b.Times(a);
    }

    /**
     * @brief Element-signed-integer multiplication operator.
     * @param a element to multiply.
     * @param b integer to multiply.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(const DerivedType& a, int64_t b) {
        return a.Times((NativeInteger::SignedNativeInt)b);
    }

    /**
     * @brief signed-BigIntType-element multiplication operator.
     * @param a integer to multiply.
     * @param b element to multiply.
     * @return the result of the multiplication operation.
     */
    friend inline DerivedType operator*(int64_t a, const DerivedType& b) {
        return b.Times((NativeInteger::SignedNativeInt)a);
    }
};

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_RNS_POLY_INTERFACE_H_
