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
  matrix class implementations and type specific implementations
 */

#ifndef CIPHER_RING_RING_MATRIX_IMPL_H_
#define CIPHER_RING_RING_MATRIX_IMPL_H_

#include <cstdint>
#include <memory>

#include "cipher/math/matrix_impl.h"
#include "cipher/math/matrix_utils.h"
#include "cipher/util/parallel.h"

// this is the implementation of matrixes of things that are in core
// and that need template specializations

namespace cipher {

template <typename Element>
Matrix<typename Element::Integer> rotate_matrix(Matrix<Element> const& in_mat) {
    Matrix<Element> mat(in_mat);
    mat.set_format(Format::COEFFICIENT);
    size_t n = mat(0, 0).get_length();
    typename Element::Integer const& modulus = mat(0, 0).get_modulus();
    size_t rows = mat.get_rows() * n;
    size_t cols = mat.get_cols() * n;
    Matrix<typename Element::Integer> result(Element::Integer::allocator, rows, cols);
    for (size_t row = 0; row < mat.get_rows(); ++row) {
        for (size_t col = 0; col < mat.get_cols(); ++col) {
            for (size_t rot_row = 0; rot_row < n; ++rot_row) {
                for (size_t rot_col = 0; rot_col < n; ++rot_col) {
                    result(row * n + rot_row, col * n + rot_col) =
                            mat(row, col).get_values().at((rot_row - rot_col + n) % n);
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rot_row < rot_col) {
                        result(row * n + rot_row, col * n + rot_col) =
                                modulus.mod_sub(result(row * n + rot_row, col * n + rot_col), modulus);
                    }
                }
            }
        }
    }
    return result;
}

/**
 *  Each element becomes a square matrix with columns of that element's
 *  rotations in Format::COEFFICIENT form.
 */
template <typename Element>
Matrix<typename Element::Vector> rotate_vec_result(Matrix<Element> const& in_mat) {
    Matrix<Element> mat(in_mat);
    mat.set_format(Format::COEFFICIENT);
    size_t n = mat(0, 0).get_length();
    typename Element::Integer const& modulus = mat(0, 0).get_modulus();
    typename Element::Vector zero(1, modulus);
    size_t rows = mat.get_rows() * n;
    size_t cols = mat.get_cols() * n;
    auto single_elem_bin_vec_alloc = [=]() {
        return typename Element::Vector(1, modulus);
    };
    Matrix<typename Element::Vector> result(single_elem_bin_vec_alloc, rows, cols);
    for (size_t row = 0; row < mat.get_rows(); ++row) {
        for (size_t col = 0; col < mat.get_cols(); ++col) {
            for (size_t rot_row = 0; rot_row < n; ++rot_row) {
                for (size_t rot_col = 0; rot_col < n; ++rot_col) {
                    typename Element::Vector& elem = result(row * n + rot_row, col * n + rot_col);
                    elem.at(0) = mat(row, col).get_values().at((rot_row - rot_col + n) % n);
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rot_row < rot_col) {
                        result(row * n + rot_row, col * n + rot_col) = zero.mod_sub(elem);
                    }
                }
            }
        }
    }
    return result;
}

template <typename Element>
void Matrix<Element>::set_format(Format format) {
    if (data[0][0].get_format() != format)
        this->switch_format();
}

template <typename Element>
void Matrix<Element>::switch_format() {
    if (rows == 1) {
        // TODO: figure out why this is causing a segfault with GCC10
        // #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(cols))
        for (size_t col = 0; col < cols; ++col) {
            data[0][col].switch_format();
        }
    } else {
        // #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(rows))
        for (size_t row = 0; row < rows; ++row) {
            for (size_t col = 0; col < cols; ++col) {
                data[row][col].switch_format();
            }
        }
    }
}

/**
 * @brief Converts a matrix of integers modulo q to their centered representatives in (-q/2, q/2] as int32_t.
 *
 * @param input the matrix of integers in [0, q).
 * @param modulus the modulus q.
 * @return the matrix of centered representatives; throws if one does not fit in an int32_t.
 */
template <typename T>
Matrix<int32_t> convert_to_int32(const Matrix<T>& input, const T& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32ConverterImpl<T> converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j]);
        }
    }
    return result;
}

/**
 * @brief Converts a matrix of vectors modulo q to the centered representatives in (-q/2, q/2] of their first
 * entries, as int32_t.
 *
 * @param input the matrix of vectors with entries in [0, q); only entry 0 of each vector is used.
 * @param modulus the modulus q.
 * @return the matrix of centered representatives; throws if one does not fit in an int32_t.
 */
template <typename V>
Matrix<int32_t> convert_to_int32(const Matrix<V>& input, const typename V::Integer& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32ConverterImpl<typename V::Integer> converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j][0]);
        }
    }
    return result;
}

}  // namespace cipher

#endif  // CIPHER_RING_RING_MATRIX_IMPL_H_
