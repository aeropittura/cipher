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

#ifndef CIPHER_MATH_MATRIX_CPP
#define CIPHER_MATH_MATRIX_CPP

#include <cmath>
#include <cstdint>

#include "cipher/math/backend.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/math/matrix_utils.h"
#include "cipher/util/exception.h"
#include "cipher/util/parallel.h"

// this is the implementation of matrixes of things that are in core
// and that need template specializations

namespace cipher {

#define MODEQ_FOR_TYPE(T)                             \
    template <>                                       \
    Matrix<T>& Matrix<T>::mod_eq(const T& element) {  \
        for (size_t row = 0; row < rows; ++row) {     \
            for (size_t col = 0; col < cols; ++col) { \
                data[row][col].mod_eq(element);       \
            }                                         \
        }                                             \
        return *this;                                 \
    }

MODEQ_FOR_TYPE(NativeInteger)
MODEQ_FOR_TYPE(BigInteger)

#define MODSUBEQ_FOR_TYPE(T)                                                 \
    template <>                                                              \
    Matrix<T>& Matrix<T>::mod_sub_eq(Matrix<T> const& b, const T& element) { \
        for (size_t row = 0; row < rows; ++row) {                            \
            for (size_t col = 0; col < cols; ++col) {                        \
                data[row][col].mod_sub_eq(b.data[row][col], element);        \
            }                                                                \
        }                                                                    \
        return *this;                                                        \
    }

MODSUBEQ_FOR_TYPE(NativeInteger)
MODSUBEQ_FOR_TYPE(BigInteger)

// YSP removed the Matrix class because it is not defined for all possible data
// types needs to be checked to make sure input matrix is used in the right
// places the assumption is that covariance matrix does not have large
// coefficients because it is formed by discrete gaussians e and s; this implies
// int32_t can be used This algorithm can be further improved - see the
// Darmstadt paper section 4.4
Matrix<double> cholesky(const Matrix<int32_t>& input) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.get_rows() != input.get_cols()) {
        CIPHER_THROW("not square");
    }
    size_t rows = input.get_rows();
    Matrix<double> result([]() { return 0; }, rows, rows);

    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < rows; ++j) {
            result(i, j) = input(i, j);
        }
    }

    for (size_t k = 0; k < rows; ++k) {
        result(k, k) = std::sqrt(result(k, k));
        // result(k, k) = sqrt(input(k, k));
        for (size_t i = k + 1; i < rows; ++i) {
            // result(i, k) = input(i, k) / result(k, k);
            result(i, k) = result(i, k) / result(k, k);
            //  zero upper-right triangle
            result(k, i) = 0;
        }
        for (size_t j = k + 1; j < rows; ++j) {
            for (size_t i = j; i < rows; ++i) {
                if (result(i, k) != 0 && result(j, k) != 0) {
                    result(i, j) = result(i, j) - result(i, k) * result(j, k);
                    // result(i, j) = input(i, j) - result(i, k) * result(j, k);
                }
            }
        }
    }
    return result;
}

void cholesky(const Matrix<int32_t>& input, Matrix<double>& result) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.get_rows() != input.get_cols()) {
        CIPHER_THROW("not square");
    }
    size_t rows = input.get_rows();
    if (result.get_rows() != rows || result.get_cols() != rows) {
        CIPHER_THROW("result must have the dimensions of input");
    }

    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < rows; ++j) {
            result(i, j) = input(i, j);
        }
    }

    for (size_t k = 0; k < rows; ++k) {
        result(k, k) = std::sqrt(result(k, k));

        for (size_t i = k + 1; i < rows; ++i) {
            // result(i, k) = input(i, k) / result(k, k);
            result(i, k) = result(i, k) / result(k, k);
            //  zero upper-right triangle
            result(k, i) = 0;
        }
        for (size_t j = k + 1; j < rows; ++j) {
            for (size_t i = j; i < rows; ++i) {
                if (result(i, k) != 0 && result(j, k) != 0) {
                    result(i, j) = result(i, j) - result(i, k) * result(j, k);
                    // result(i, j) = input(i, j) - result(i, k) * result(j, k);
                }
            }
        }
    }
}

//  Convert from Z_q to (-q/2, q/2]
Matrix<int32_t> convert_to_int32(const Matrix<BigInteger>& input, const BigInteger& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32Converter converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j]);
        }
    }
    return result;
}

Matrix<int32_t> convert_to_int32(const Matrix<BigVector>& input, const BigInteger& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32Converter converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j][0]);
        }
    }
    return result;
}

template class Matrix<double>;
template class Matrix<int>;
template class Matrix<int64_t>;

}  // namespace cipher

#endif
