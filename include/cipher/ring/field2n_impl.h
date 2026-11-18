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
  implementation of the power-of-2 fields
 */

#ifndef CIPHER_RING_FIELD2N_IMPL_H_
#define CIPHER_RING_FIELD2N_IMPL_H_

#include <complex>
#include <cstdint>
#include <vector>

#include "cipher/ring/field2n.h"
#include "cipher/ring/backend.h"
#include "cipher/math/dft.h"
#include "cipher/math/backend.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

// Constructor from ring element
Field2n::Field2n(const Poly& element) : format(Format::COEFFICIENT) {
    if (element.get_format() != Format::COEFFICIENT)
        CIPHER_THROW("Poly not in Format::COEFFICIENT representation");
    size_t size = element.get_length();
    this->std::vector<std::complex<double>>::reserve(size);
    BigInteger negative_threshold(element.get_modulus() / Poly::Integer(2));
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negative_threshold)
            this->std::vector<std::complex<double>>::push_back(-(element.get_modulus() - element[i]).convert_to_double());
        else
            this->std::vector<std::complex<double>>::push_back(element[i].convert_to_double());
    }
}

// Constructor from ring element
Field2n::Field2n(const NativePoly& element) : format(Format::COEFFICIENT) {
    if (element.get_format() != Format::COEFFICIENT)
        CIPHER_THROW("Poly not in Format::COEFFICIENT representation");
    size_t size = element.get_length();
    this->std::vector<std::complex<double>>::reserve(size);
    NativeInteger negative_threshold(element.get_modulus() / 2);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negative_threshold)
            this->std::vector<std::complex<double>>::push_back(-(element.get_modulus() - element[i]).convert_to_double());
        else
            this->std::vector<std::complex<double>>::push_back(element[i].convert_to_double());
    }
}

// Constructor from RnsPoly ring element
Field2n::Field2n(const RnsPoly& dcrt_element) : format(Format::COEFFICIENT) {
    if (dcrt_element.get_format() != Format::COEFFICIENT)
        CIPHER_THROW("DCRTPoly not in Format::COEFFICIENT representation");
    // get_element_at_index() is unchecked, so reject an empty RnsPoly before indexing into it.
    if (dcrt_element.get_num_of_elements() == 0)
        CIPHER_THROW("DCRTPoly has no towers to convert");
    // Reading only the first tower is exact while every centered coefficient fits inside it, which
    // is what this constructor's callers produce (products of small trapdoor samples). Check that
    // against the remaining towers rather than assuming it, and interpolate when it does not hold.
    const typename RnsPoly::PolyType& element = dcrt_element.get_element_at_index(0);
    const NativeInteger& q0 = element.get_modulus();
    const NativeInteger negative_threshold(q0 / 2);
    size_t size = element.get_length();
    for (uint32_t t = 1; t < dcrt_element.get_num_of_elements(); ++t) {
        const typename RnsPoly::PolyType& tower = dcrt_element.get_element_at_index(t);
        const NativeInteger& qt = tower.get_modulus();
        for (size_t i = 0; i < size; ++i) {
            bool negative = element[i] > negative_threshold;
            NativeInteger residue((negative ? q0 - element[i] : element[i]).mod(qt));
            if (negative && residue > NativeInteger(0))
                residue = qt - residue;
            if (tower[i] != residue) {
                *this = Field2n(dcrt_element.crt_interpolate());
                return;
            }
        }
    }
    this->std::vector<std::complex<double>>::reserve(size);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negative_threshold)
            this->std::vector<std::complex<double>>::push_back(-(q0 - element[i]).convert_to_double());
        else
            this->std::vector<std::complex<double>>::push_back(element[i].convert_to_double());
    }
}

// Constructor from a ring element matrix
Field2n::Field2n(const Matrix<int64_t>& element) : format(Format::COEFFICIENT) {
    size_t size = element.get_rows();
    this->std::vector<std::complex<double>>::reserve(size);
    for (size_t i = 0; i < size; ++i)
        this->std::vector<std::complex<double>>::push_back(element(i, 0));
}

// Inverse operation for the field elements
Field2n Field2n::inverse() const {
    if (format == Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::EVALUATION representation");
    Field2n inverse_value(*this);
    for (size_t i = 0; i < inverse_value.size(); ++i) {
        auto real{inverse_value[i].real()};
        auto imag{inverse_value[i].imag()};
        auto quotient{real * real + imag * imag};
        inverse_value[i] = std::complex<double>(real / quotient, -imag / quotient);
    }
    return inverse_value;
}

// Addition operation for field elements
Field2n Field2n::plus_impl(const Field2n& rhs) const {
    if (format != rhs.get_format())
        CIPHER_THROW("Operands are not in the same format");
    Field2n sum(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        sum[i] += rhs[i];
    return sum;
}

// Scalar addition operation for field elements
Field2n Field2n::plus_impl(double scalar) const {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Field2n scalar addition is currently supported only for Format::COEFFICIENT representation");
    Field2n sum(*this);
    sum.at(0) += scalar;
    return sum;
}

// Substraction operation for field elements
Field2n Field2n::minus_impl(const Field2n& rhs) const {
    if (format != rhs.get_format())
        CIPHER_THROW("Operands are not in the same format");
    Field2n difference(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        difference[i] -= rhs[i];
    return difference;
}

// Multiplication operation for field elements
Field2n Field2n::Times(const Field2n& rhs) const {
    if (format != Format::EVALUATION && rhs.get_format() != Format::EVALUATION)
        CIPHER_THROW("At least one of the polynomials is not in Format::EVALUATION representation");
    Field2n result(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        result[i] *= rhs[i];
    return result;
}

// Right shift operation for the field element
Field2n Field2n::shift_right() {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::COEFFICIENT representation");
    Field2n result(*this);
    size_t i = this->std::vector<std::complex<double>>::size() - 1;
    auto tmp = std::complex<double>(-1., 0.) * result[i];
    for (; i != 0; --i)
        result[i] = result[i - 1];
    result[i] = tmp;
    return result;
}

// Performs an automorphism transform operation and returns the result.
Field2n Field2n::automorphism_transform(size_t i) const {
    if (format != Format::EVALUATION)
        CIPHER_THROW("Field2n Automorphism is only implemented for Format::EVALUATION format");
    if (i % 2 == 0)
        CIPHER_THROW("automorphism index should be odd\n");
    Field2n result(*this);
    size_t m = this->std::vector<std::complex<double>>::size() * 2;
    for (size_t j = 1; j < m; j += 2) {
        size_t idx{(j * i) % m};
        result[(idx + 1) / 2 - 1] = this->std::vector<std::complex<double>>::operator[]((j + 1) / 2 - 1);
    }
    return result;
}

// Transpose operation defined in section VI.B4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::transposed() const {
    size_t size = this->std::vector<std::complex<double>>::size();
    if (format != Format::COEFFICIENT)
        return automorphism_transform(size * 2 - 1);
    constexpr auto negone = std::complex<double>(-1., 0.);
    Field2n transpose(size, Format::COEFFICIENT, true);
    transpose[0] = this->std::vector<std::complex<double>>::operator[](0);
    for (size_t i = 1; i < size; ++i)
        transpose[i] = negone * this->std::vector<std::complex<double>>::operator[](size - i);
    return transpose;
}

// Function for extracting odd factors of the field element
Field2n Field2n::extract_odd() const {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->std::vector<std::complex<double>>::size();
    Field2n odds(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < odds.size(); ++i)
        odds[i] = this->std::vector<std::complex<double>>::operator[](1 + 2 * i);
    return odds;
}

// Function for extracting even factors of the field element
Field2n Field2n::extract_even() const {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->std::vector<std::complex<double>>::size();
    Field2n evens(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < evens.size(); ++i)
        evens[i] = this->std::vector<std::complex<double>>::operator[](0 + 2 * i);
    return evens;
}

// Permutation operation defined in Algorithm 4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::permute() const {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n permuted(size, Format::COEFFICIENT, true);
    size_t even_ptr{0}, odd_ptr{size / 2};
    for (size_t i = 0; i < size;) {
        permuted[even_ptr++] = this->std::vector<std::complex<double>>::operator[](i++);
        permuted[odd_ptr++] = this->std::vector<std::complex<double>>::operator[](i++);
    }
    return permuted;
}

// Inverse operation for permutation operation defined in
// Algorithm 4 of https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::inverse_permute() const {
    if (format != Format::COEFFICIENT)
        CIPHER_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n invpermuted(size, Format::COEFFICIENT, true);
    size_t even_ptr{0}, odd_ptr{size / 2};
    for (size_t i = 0; i < size;) {
        invpermuted[i++] = this->std::vector<std::complex<double>>::operator[](even_ptr++);
        invpermuted[i++] = this->std::vector<std::complex<double>>::operator[](odd_ptr++);
    }
    return invpermuted;
}

// Operation for scalar multiplication
Field2n Field2n::scalar_mult(double d) {
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n scaled(size, format, true);
    for (size_t i = 0; i < size; ++i)
        scaled[i] = d * this->std::vector<std::complex<double>>::operator[](i);
    return scaled;
}

// Method for switching format of the field elements
void Field2n::switch_format() {
    auto r = (format == Format::COEFFICIENT) ? DiscreteFourierTransform::forward_transform(*this) :
                                               DiscreteFourierTransform::inverse_transform(*this);
    format = (format == Format::COEFFICIENT) ? Format::EVALUATION : Format::COEFFICIENT;
    for (size_t i = 0; i < r.size(); ++i)
        this->std::vector<std::complex<double>>::operator[](i) = r[i];
}

}  // namespace cipher

#endif  // CIPHER_RING_FIELD2N_IMPL_H_
