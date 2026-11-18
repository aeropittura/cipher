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
  Represents and defines integer lattice element objects in Cipher
 */

#ifndef CIPHER_RING_ELEMENT_H_
#define CIPHER_RING_ELEMENT_H_

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/backend/native_int_backend.h"  // NativeInteger
#include "cipher/math/number_theory.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Interface for ideal lattices
 *
 * Every lattice must implement these pure virtuals in order to properly
 * interoperate with Cipher PKE. Element is the return type for all of these
 * virtual functions. There is no constructor here in the base class; it
 * contains no data to construct.
 */
template <typename Element, typename VecType>
class RingElement : public Serializable {
    using IntType = typename VecType::Integer;

  public:
    /**
     * @brief Clone the object by making a copy of it and returning the copy
     * @return new Element
     */
    virtual Element clone() const = 0;

    /**
     * @brief Clone the object, but have it contain nothing
     * @return new Element
     */
    virtual Element clone_empty() const = 0;

    /**
     * @brief Clones the element's parameters, leaves vector initialized to 0
     * @return new Element
     */
    virtual Element clone_parameters_only() const = 0;

    /**
     * @brief Clones the element with parameters and with noise for the vector
     * @param dgg the discrete Gaussian generator used to sample the noise
     * @param format the format of the resulting element
     * @return new Element
     */
    virtual Element clone_with_noise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const = 0;

    /**
     * @brief Standard destructor
     */
    virtual ~RingElement() = default;

    // Assignment operators
    /**
     * @brief Assignment operator that copies elements.
     * @param rhs the element to copy
     * @return the resulting element.
     */
    virtual const Element& operator=(const Element& rhs) = 0;
    /**
     * @brief Move assignment operator.
     * @param rhs the element to move from
     * @return the resulting element.
     */
    virtual const Element& operator=(Element&& rhs) = 0;
    /**
     * @brief Assignment operator from an initializer list of values.
     * @param rhs the list of values to assign
     * @return the resulting element.
     */
    virtual const Element& operator=(std::initializer_list<uint64_t> rhs) = 0;

    // GETTERS
    /**
     * @brief Get format of the element
     *
     * @return Format is either COEFFICIENT or EVALUATION
     */
    virtual Format get_format() const = 0;

    /**
     * @brief Get the length of the element.
     *
     * @return length
     */
    virtual uint32_t get_length() const = 0;

    /**
     * @brief Get modulus of the element
     *
     * @return the modulus.
     */
    virtual const IntType& get_modulus() const = 0;

    /**
     * @brief Get the values for the element
     *
     * @return the vector.
     */
    virtual const VecType& get_values() const = 0;

    /**
     * @brief Get the cyclotomic order
     *
     * @return order
     */
    virtual uint32_t get_cyclotomic_order() const = 0;

    /**
     * @brief Gets the Value in the Element that is At Index and returns it.
     * This is only implemented for some derived classes, so the default
     * implementation throws an exception
     *
     * @param i is the index.
     * @return will throw an error.
     */
    virtual IntType& at(uint32_t i) {
        CIPHER_THROW("at() not implemented");
    }
    /**
     * @brief Const version of at(); the default implementation throws an exception.
     *
     * @param i is the index.
     * @return will throw an error.
     */
    virtual const IntType& at(uint32_t i) const {
        CIPHER_THROW("const at() not implemented");
    }
    /**
     * @brief Unchecked access to the value at index i; the default implementation throws an exception.
     *
     * @param i is the index.
     * @return will throw an error.
     */
    virtual IntType& operator[](uint32_t i) {
        CIPHER_THROW("[] not implemented");
    }
    /**
     * @brief Const version of operator[](); the default implementation throws an exception.
     *
     * @param i is the index.
     * @return will throw an error.
     */
    virtual const IntType& operator[](uint32_t i) const {
        CIPHER_THROW("const [] not implemented");
    }

    //  virtual NativePoly decryption_crt_interpolate(PlaintextModulus ptm) const
    //= 0;

    // OPERATORS
    /**
     * @brief Unary negation on a lattice
     * @return -lattice
     */
    virtual Element operator-() const = 0;

    /**
     * @brief Scalar addition - add an integer to the first index only in
     * COEFFICIENT format, or to all entries in EVALUATION format.
     *
     * @param element is the integer to add.
     * @return is the return of the addition operation.
     */
    virtual Element plus_impl(const IntType& element) const = 0;

    /**
     * @brief Scalar subtraction - subtract an element from all entries.
     *
     * @param element is the element to subtract entry-wise.
     * @return is the return value of the minus operation.
     */
    virtual Element minus_impl(const IntType& element) const = 0;

    /**
     * @brief Scalar multiplication - multiply all entries.
     *
     * @param element is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     */
    virtual Element Times(const IntType& element) const = 0;

    /**
     * @brief Scalar multiplication - multiply by a signed integer
     *
     * @param element is the element to multiply entry-wise.
     * @return is the return value of the times operation.
     */
    virtual Element Times(NativeInteger::SignedNativeInt element) const = 0;

    /**
     * @brief Performs an addition operation and returns the result.
     *
     * @param element is the element to add with.
     * @return is the result of the addition.
     */
    virtual Element plus_impl(const Element& element) const = 0;

    /**
     * @brief Performs a subtraction operation and returns the result.
     *
     * @param element is the element to subtract with.
     * @return is the result of the subtraction.
     */
    virtual Element minus_impl(const Element& element) const = 0;

    /**
     * @brief Performs a multiplication operation and returns the result.
     *
     * @param element is the element to multiply with.
     * @return is the result of the multiplication.
     */
    virtual Element Times(const Element& element) const = 0;

    // overloaded op= operators
    /**
     * @brief Performs += operation with a BigInteger and returns the result.
     *
     * @param element is the element to add
     * @return is the result of the addition.
     */
    virtual const Element& operator+=(const IntType& element) = 0;

    /**
     * @brief Performs -= operation with a BigInteger and returns the result.
     *
     * @param element is the element to subtract
     * @return is the result of the subtraction.
     */
    virtual const Element& operator-=(const IntType& element) = 0;

    /**
     * @brief Performs *= operation with a BigInteger and returns the result.
     *
     * @param element is the element to multiply by
     * @return is the result of the multiplication.
     */
    virtual const Element& operator*=(const IntType& element) = 0;

    /**
     * @brief Performs an addition operation and returns the result.
     *
     * @param element is the element to add
     * @return is the result of the addition.
     */
    virtual const Element& operator+=(const Element& element) = 0;

    /**
     * @brief Performs a subtraction operation and returns the result.
     *
     * @param element is the element to subtract
     * @return is the result of the subtraction.
     */
    virtual const Element& operator-=(const Element& element) = 0;

    /**
     * @brief Performs an multiplication operation and returns the result.
     *
     * @param element is the element to multiply by
     * @return is the result of the multiplication.
     */
    virtual const Element& operator*=(const Element& element) = 0;

    /**
     * @brief Equality operator.  Compares values of element to be compared to.
     * @param element the element to compare to.
     * @return true if the elements are equal, false otherwise.
     */
    virtual bool operator==(const Element& element) const = 0;

    /**
     * @brief Inequality operator.  Compares values of element to be compared to.
     * @param element the element to compare to.
     * @return true if the elements differ, false otherwise.
     */
    inline bool operator!=(const Element& element) const {
        return !(*this == element);
    }

    /**
     * @brief Adds one to every entry of the Element, in place
     */
    virtual void add_il_element_one() = 0;

    /**
     * @brief Performs an automorphism transform operation and returns the result.
     *
     * @param i is the automorphism index (an odd integer) to apply.
     * @return is the result of the automorphism transform.
     */
    virtual Element automorphism_transform(uint32_t i) const = 0;

    /**
     * @brief Performs an automorphism transform operation using precomputed bit
     * reversal indices.
     *
     * @param i is the automorphism index (an odd integer) to apply.
     * @param vec a vector with precomputed indices
     * @return is the result of the automorphism transform.
     */
    virtual Element automorphism_transform(uint32_t i, const std::vector<uint32_t>& vec) const = 0;

    /**
     * @brief Transpose the ring element using the automorphism operation
     *
     * @return is the result of the transposition.
     */
    virtual Element transposed() const = 0;

    /**
     * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base}
     * \rfloor} {(base^i u_i)} \f$ and return the vector of \f$ \left\{u_0,
     * u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil
     * {\log q/base} \rceil}} \f$; This is used as a subroutine in the
     * relinearization procedure.
     *
     * @param base_bits is the number of bits in the base, i.e., base = 2^base_bits
     * @param eval_mode_answer - if true, convert the resultant polynomials to
     * evaluation mode
     * @result is the pointer where the base decomposition vector is stored
     */
    virtual std::vector<Element> base_decompose(uint32_t base_bits, bool eval_mode_answer) const = 0;

    /**
     * @brief Scalar division followed by rounding operation - operation on all
     * entries.
     *
     * @param q is the element to divide entry-wise.
     * @return is the return value of the divide, followed by rounding operation.
     */
    virtual Element divide_and_round(const IntType& q) const = 0;

    /**
     * @brief Determines if inverse exists
     *
     * @return true if there exists a multiplicative inverse.
     */
    virtual bool inverse_exists() const = 0;

    /**
     * @brief Returns the infinity norm, basically the largest value in the ring
     * element.
     *
     * @return the largest value in the ring element.
     */
    virtual double norm() const = 0;

    /**
     * @brief Returns true if the vector is empty/ values_==nullptr
     *
     * @return true if the vector is empty and all values nullptr.  false
     * otherwise.
     */
    virtual bool is_empty() const = 0;

    /**
     * @brief Make the element Sparse for SHE key_gen operations.
     * Sets every index not equal to zero mod the w_factor to zero.
     *
     * @param w_factor ratio between the original element's ring dimension and the
     * new ring dimension.
     */
    virtual void make_sparse(uint32_t w_factor) = 0;

    /**
     * @brief Calculate Element mod 2
     *
     * @return result of performing a mod-2 operation on the element.
     */
    virtual Element mod_by_two() const = 0;

    /**
     * @brief Calculate and return the Multiplicative Inverse of the element
     * @return the multiplicative inverse of the element, if it exists.
     */
    virtual Element multiplicative_inverse() const = 0;

    /**
     * @brief Scalar multiplication followed by division and rounding operation -
     * operation on all entries.
     *
     * @param p is the integer muliplicand.
     * @param q is the integer divisor.
     * @return is the return value of the multiply, divide and followed by
     * rounding operation.
     */
    virtual Element multiply_and_round(const IntType& p, const IntType& q) const = 0;

    /**
     * @brief Calculate a vector of elements by raising the base element to
     * successive powers
     *
     * @param base_bits is the number of bits in the base, i.e., base = 2^base_bits
     * @return the vector of elements {x, base*x, base^2*x, ...}
     */
    virtual std::vector<Element> powers_of_base(uint32_t base_bits) const = 0;

    /**
     * @brief Mod - perform a modulus operation.
     * Does proper mapping of [-modulus/2, modulus/2) to [0, modulus).
     *
     * @param modulus is the modulus to use.
     * @return is the return value of the modulus.
     */
    virtual Element mod(const IntType& modulus) const = 0;

    /**
     * @brief Switch modulus and adjust the values
     *
     * @param modulus is the modulus to be set.
     * @param root_of_unity_value is the corresponding root of unity for the modulus
     * @param modulus_arb is the modulus used for arbitrary cyclotomics CRT
     * @param root_of_unity_arb is the corresponding root of unity for the modulus
     * ASSUMPTION: This method assumes that the caller provides the correct
     * root_of_unity_value for the modulus.
     */
    virtual void switch_modulus(const IntType& modulus, const IntType& root_of_unity_value, const IntType& modulus_arb,
                                const IntType& root_of_unity_arb) = 0;

    /**
     * @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
     * @param thread_limit number of threads to request for the per-tower loop; 0 requests one per tower.
     */
    virtual void switch_format(uint32_t thread_limit = 0) = 0;

    /**
     * @brief Sets the format/representation of the element.
     * @param format the format/representation to set.
     * @param thread_limit number of threads to request for the per-tower loop; 0 requests one per tower.
     */
    inline void set_format(const Format format, uint32_t thread_limit = 0) {
        if (this->get_format() != format) {
            this->switch_format(thread_limit);
        }
    }
};

}  // namespace cipher

#endif  // CIPHER_RING_ELEMENT_H_
