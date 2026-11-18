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
  matrix strassen operations
 */

#ifndef CIPHER_MATH_MATRIX_STRASSEN_IMPL_H_
#define CIPHER_MATH_MATRIX_STRASSEN_IMPL_H_

#include <assert.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/math/matrix_utils.h"
#include "cipher/math/matrix_strassen.h"
#include "cipher/util/diagnostic_output.h"
#include "cipher/util/parallel.h"

namespace cipher {

template <class Element>
MatrixStrassen<Element>::MatrixStrassen(alloc_func alloc_zero, size_t rows, size_t cols, alloc_func alloc_gen)
    : data(), rows(rows), cols(cols), alloc_zero(alloc_zero) {
    data.resize(rows);
    for (auto& row : data) {
        row.reserve(cols);
        for (size_t col = 0; col < cols; ++col) {
            row.push_back(alloc_gen());
        }
    }
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::operator=(const MatrixStrassen<Element>& other) {
    rows = other.rows;
    cols = other.cols;
    deep_copy_data(other.data);
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::ones() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = 1;
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::Fill(const Element& val) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = val;
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::identity() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            if (row == col) {
                data[row][col] = 1;
            } else {
                data[row][col] = 0;
            }
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::gadget_vector(int32_t base) const {
    MatrixStrassen<Element> g(alloc_zero, rows, cols);
    // auto two = alloc_zero();
    auto base_matrix = alloc_zero();
    *base_matrix = base;
    g(0, 0) = 1;
    for (size_t col = 1; col < cols; ++col) {
        //  g(0, col) = g(0, col-1) * *two;
        g(0, col) = g(0, col - 1) * *base_matrix;
    }
    return g;
}

template <class Element>
double MatrixStrassen<Element>::norm() const {
    double ret_val = 0.0;
    double loc_val = 0.0;

    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            loc_val = data[row][col]->norm();
            if (loc_val > ret_val) {
                ret_val = loc_val;
            }
        }
    }

    return ret_val;
}

template <class Element>
void MatrixStrassen<Element>::set_format(Format format) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col].set_format(format);
        }
    }
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::operator+=(MatrixStrassen<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        CIPHER_THROW("Addition operands have incompatible dimensions");
    }
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(cols))
    for (size_t j = 0; j < cols; ++j) {
        for (size_t i = 0; i < rows; ++i) {
            data[i][j] += other.data[i][j];
        }
    }
    return *this;
}

template <class Element>
inline MatrixStrassen<Element>& MatrixStrassen<Element>::operator-=(MatrixStrassen<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        CIPHER_THROW("Subtraction operands have incompatible dimensions");
    }
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(cols))
    for (size_t j = 0; j < cols; ++j) {
        for (size_t i = 0; i < rows; ++i) {
            data[i][j] -= other.data[i][j];
        }
    }

    return *this;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::transposed() const {
    MatrixStrassen<Element> result(alloc_zero, cols, rows);
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            result(col, row) = (*this)(row, col);
        }
    }
    return result;
}

// YSP The signature of this method needs to be changed in the future
// Laplace's formula is used to find the determinant
// Complexity is O(d!), where d is the dimension
// The determinant of a matrix is expressed in terms of its minors
// recursive implementation
// There are O(d^3) decomposition algorithms that can be implemented to support
// larger dimensions. Examples include the LU decomposition, the QR
// decomposition or the Cholesky decomposition(for positive definite matrices).
template <class Element>
void MatrixStrassen<Element>::determinant(Element* determinant_value) const {
    if (rows != cols)
        CIPHER_THROW("Supported only for square matrix");
    // auto determinant = *alloc_zero();
    if (rows < 1)
        CIPHER_THROW("Dimension should be at least one");

    if (rows == 1) {
        *determinant_value = *data[0][0];
    } else if (rows == 2) {
        *determinant_value = *data[0][0] * (*data[1][1]) - *data[1][0] * (*data[0][1]);
    } else {
        size_t j1, j2;
        size_t n = rows;

        MatrixStrassen<Element> result(alloc_zero, rows - 1, cols - 1);

        // for each column in sub-matrix
        for (j1 = 0; j1 < n; j1++) {
            // build sub-matrix with minor elements excluded
            for (size_t i = 1; i < n; i++) {
                j2 = 0;  // start at first sum-matrix column position
                // loop to copy source matrix less one column
                for (size_t j = 0; j < n; j++) {
                    if (j == j1)
                        continue;  // don't copy the minor column element

                    *result.data[i - 1][j2] = *data[i][j];  // copy source element into new sub-matrix
                                                            // i-1 because new sub-matrix is one row
                                                            // (and column) smaller with excluded minors
                    j2++;                                   // move to next sub-matrix column position
                }
            }

            auto temp_determinant = *alloc_zero();
            result.determinant(&temp_determinant);

            if (j1 % 2 == 0)
                *determinant_value = *determinant_value + (*data[0][j1]) * temp_determinant;
            else
                *determinant_value = *determinant_value - (*data[0][j1]) * temp_determinant;

            // if (j1 % 2 == 0)
            //  determinant = determinant + (*data[0][j1]) *
            // result.determinant(); else   determinant = determinant -
            // (*data[0][j1]) * result.determinant();
        }
    }
    // return determinant;
    return;
}

// The cofactor matrix is the matrix of determinants of the minors A_{ij}
// multiplied by -1^{i+j} The determinant subroutine is used
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::cofactor_matrix_strassen() const {
    if (rows != cols)
        CIPHER_THROW("Supported only for square matrix");

    size_t ii, jj, i_new, j_new;

    size_t n = rows;

    MatrixStrassen<Element> result(alloc_zero, rows, cols);

    for (size_t j = 0; j < n; j++) {
        for (size_t i = 0; i < n; i++) {
            MatrixStrassen<Element> c(alloc_zero, rows - 1, cols - 1);

            /* Form the adjoint a_ij */
            i_new = 0;
            for (ii = 0; ii < n; ii++) {
                if (ii == i)
                    continue;
                j_new = 0;
                for (jj = 0; jj < n; jj++) {
                    if (jj == j)
                        continue;
                    *c.data[i_new][j_new] = *data[ii][jj];
                    j_new++;
                }
                i_new++;
            }

            /* Calculate the determinant */
            auto determinant_value = alloc_zero();
            c.determinant(&determinant_value);
            // auto determinant = c.determinant();

            /* Fill in the elements of the cofactor */
            if ((i + j) % 2 == 0)
                result.data[i][j] = determinant_value;
            else
                result.data[i][j] = -determinant_value;
        }
    }

    return result;
}

//  add rows to bottom of the matrix
template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::v_stack(MatrixStrassen<Element> const& other) {
    if (cols != other.cols) {
        CIPHER_THROW("VStack rows not equal size");
    }
    for (size_t row = 0; row < other.rows; ++row) {
        std::vector<std::unique_ptr<Element>> row_elems;
        for (auto elem : other.data[row]) {
            row_elems.push_back(Element(*elem));
        }
        data.push_back(std::move(row_elems));
    }
    rows += other.rows;
    return *this;
}

//  add cols to right of the matrix
template <class Element>
inline MatrixStrassen<Element>& MatrixStrassen<Element>::h_stack(MatrixStrassen<Element> const& other) {
    if (rows != other.rows) {
        CIPHER_THROW("HStack cols not equal size");
    }
    for (size_t row = 0; row < rows; ++row) {
        std::vector<std::unique_ptr<Element>> row_elems;
        for (auto elem = other.data[row].begin(); elem != other.data[row].end(); ++elem) {
            row_elems.push_back(Element(*elem));
        }
        move_append(data[row], row_elems);
    }
    cols += other.cols;
    return *this;
}

template <class Element>
void MatrixStrassen<Element>::switch_format() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col].switch_format();
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::linearize_data_caps(lineardata_t* lineardata_ptr) const {
    lineardata_ptr->clear();

    for (size_t row = 0; row < data.size(); ++row) {
        for (auto elem = data[row].begin(); elem != data[row].end(); ++elem) {
            lineardata_ptr->push_back(std::move(*elem));
        }
        data[row].clear();
        // Now add the padded columns for each row
        for (int i = 0; i < colpad; i++) {
            lineardata_ptr->push_back(zero_unique_ptr);  // Should point to 0
        }
    }
    // Now add the padded rows
    int numelem = rowpad * (cols + colpad);

    for (int i = 0; i < numelem; i++) {
        lineardata_ptr->push_back(zero_unique_ptr);  // Should point to 0
    }
}

template <class Element>
void MatrixStrassen<Element>::unlinearize_data_caps(lineardata_t* lineardata_ptr) const {
    int datasize = cols;

    size_t row = 0;
    int counter = 0;
    data[row].clear();
    data[row].reserve(datasize);
    for (auto elem = lineardata_ptr->begin(); elem != lineardata_ptr->end(); ++elem) {
        data[row].push_back(std::move(*elem));

        counter++;
        if (counter % rows == 0) {
            // Eat next colpad elements
            for (int i = 0; i < colpad; i++) {
                ++elem;
            }

            row++;
            if (row < rows) {
                data[row].clear();
                data[row].reserve(datasize);
            } else {
                break;  // Get rid of padded rows
            }
        }
    }
    lineardata_ptr->clear();
}

template <class Element>
void MatrixStrassen<Element>::deep_copy_data(data_t const& src) {
    data.clear();
    data.resize(src.size());
    for (size_t row = 0; row < src.size(); ++row) {
        for (auto elem = src[row].begin(); elem != src[row].end(); ++elem) {
            data[row].push_back(Element(*elem));
        }
    }
}

inline MatrixStrassen<BigInteger> Rotate(MatrixStrassen<Poly> const& in_mat) {
    MatrixStrassen<Poly> mat(in_mat);
    mat.set_format(Format::COEFFICIENT);
    size_t n = mat(0, 0).get_length();
    BigInteger const& modulus = mat(0, 0).get_modulus();
    size_t rows = mat.get_rows() * n;
    size_t cols = mat.get_cols() * n;
    MatrixStrassen<BigInteger> result(BigInteger::allocator, rows, cols);
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
MatrixStrassen<BigVector> rotate_vec_result(MatrixStrassen<Poly> const& in_mat) {
    MatrixStrassen<Poly> mat(in_mat);
    mat.set_format(Format::COEFFICIENT);
    size_t n = mat(0, 0).get_length();
    BigInteger const& modulus = mat(0, 0).get_modulus();
    BigVector zero(1, modulus);
    size_t rows = mat.get_rows() * n;
    size_t cols = mat.get_cols() * n;
    auto single_elem_bin_vec_alloc = [=]() {
        return BigVector(1, modulus);
    };
    MatrixStrassen<BigVector> result(single_elem_bin_vec_alloc, rows, cols);
    for (size_t row = 0; row < mat.get_rows(); ++row) {
        for (size_t col = 0; col < mat.get_cols(); ++col) {
            for (size_t rot_row = 0; rot_row < n; ++rot_row) {
                for (size_t rot_col = 0; rot_col < n; ++rot_col) {
                    BigVector& elem = result(row * n + rot_row, col * n + rot_col);
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

template <class Element>
inline std::ostream& operator<<(std::ostream& os, const MatrixStrassen<Element>& m) {
    os << "[ ";
    for (size_t row = 0; row < m.get_rows(); ++row) {
        os << "[ ";
        for (size_t col = 0; col < m.get_cols(); ++col) {
            os << m(row, col) << " ";
        }
        os << "]\n";
    }
    os << " ]\n";
    return os;
}

// YSP removed the MatrixStrassen class because it is not defined for all
// possible data types needs to be checked to make sure input matrix is used in
// the right places the assumption is that covariance matrix does not have large
// coefficients because it is formed by discrete gaussians e and s; this implies
// int32_t can be used This algorithm can be further improved - see the
// Darmstadt paper section 4.4
MatrixStrassen<double> cholesky(const MatrixStrassen<int32_t>& input) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.get_rows() != input.get_cols()) {
        CIPHER_THROW("not square");
    }
    size_t rows = input.get_rows();
    MatrixStrassen<double> result([]() { return 0; }, rows, rows);

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
    return result;
}

//  Convert from Z_q to (-q/2, q/2]
MatrixStrassen<int32_t> convert_to_int32(const MatrixStrassen<BigInteger>& input, const BigInteger& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    MatrixStrassen<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32Converter converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j]);
        }
    }
    return result;
}

MatrixStrassen<int32_t> convert_to_int32(const MatrixStrassen<BigVector>& input, const BigInteger& modulus) {
    size_t rows = input.get_rows();
    size_t cols = input.get_cols();
    MatrixStrassen<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32Converter converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& input_row = input.get_data()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.convert(input_row[j][0]);
        }
    }
    return result;
}

//  split a vector of int32_t into a vector of ring elements with ring dimension
//  n
MatrixStrassen<Poly> split_int32_into_poly_elements(MatrixStrassen<int32_t> const& other, size_t n,
                                                    const std::shared_ptr<PolyParams> params) {
    auto zero_alloc = Poly::allocator(params, Format::COEFFICIENT);

    size_t rows = other.get_rows() / n;

    MatrixStrassen<Poly> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
        BigVector temp_bbv(n, params->get_modulus());

        for (size_t i = 0; i < n; ++i) {
            BigInteger temp_bbi;
            uint32_t temp_integer;
            if (other(row * n + i, 0) < 0) {
                temp_integer = -other(row * n + i, 0);
                temp_bbi = params->get_modulus() - BigInteger(temp_integer);
            } else {
                temp_integer = other(row * n + i, 0);
                temp_bbi = BigInteger(temp_integer);
            }
            temp_bbv.at(i) = temp_bbi;
        }

        result(row, 0).set_values(std::move(temp_bbv), Format::COEFFICIENT);
    }

    return result;
}

//  split a vector of BBI into a vector of ring elements with ring dimension n
MatrixStrassen<Poly> split_int32_alt_into_poly_elements(MatrixStrassen<int32_t> const& other, size_t n,
                                                        const std::shared_ptr<PolyParams> params) {
    auto zero_alloc = Poly::allocator(params, Format::COEFFICIENT);

    size_t rows = other.get_rows();

    MatrixStrassen<Poly> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
        BigVector temp_bbv(n, params->get_modulus());

        for (size_t i = 0; i < n; ++i) {
            BigInteger temp_bbi;
            uint32_t temp_integer;
            if (other(row, i) < 0) {
                temp_integer = -other(row, i);
                temp_bbi = params->get_modulus() - BigInteger(temp_integer);
            } else {
                temp_integer = other(row, i);
                temp_bbi = BigInteger(temp_integer);
            }

            temp_bbv.at(i) = temp_bbi;
        }

        result(row, 0).set_values(std::move(temp_bbv), Format::COEFFICIENT);
    }

    return result;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::mult(MatrixStrassen<Element> const& other, int nrec,
                                                      int pad_value) const {
    int allrows = rows;

    NUM_THREADS = cipher_parallel_controls.get_num_threads();

    if (pad_value == -1) {
        // int allcols = cols;

        /*
         * Calculate the optimal number of padding rows and padding columns.  (Note
         * that these do not need to be the same, allowing rectangular matrices to
         * be handled.)
         *
         * The amount of padding in a dimension needs to support the number of
         * levels of recursion that are passed to this routine.  For instance, if
         * the original number of columns is 93, and nrec = 1. then only 1 column of
         * padding must be added.  (93 + 1)/2 is an integer. However, (93 + 1)/2/2
         * is not an integer, so a single column of padding will not support 2
         * levels of recursion.  The algorithm given here will determine that a
         * 93x93 matrix needs to be padded to 96x96 to support 2 levels of
         * recursion, as 96/(2^2) is an integer.
         */
        double powtemp = std::pow(2, nrec);
        rowpad = std::ceil(rows / powtemp) * static_cast<int>(powtemp) - rows;
        colpad = std::ceil(cols / powtemp) * static_cast<int>(powtemp) - cols;
        allrows = rows + rowpad;
        // allcols = cols + colpad;
    } else {
        /* Apply the indicated padding rows and columns.  (For now they are equal,
         * assuming square matrices.  Note that the dimension of the matrix after
         * padding must support the number of levels of recursion.  For instance, if
         * a 93x93 matrix is padded out to 94x94, this supports only 1 level of
         * recursion, since 94/2 is integral, while 47/2 is not.  The assertions
         * catch this problem.  Note that the user should not need to provide a
         * padding value, as setting the padding value to -1 will cause this code to
         * caluclate the optimal padding for the number of levels of recursion.
         */

        rowpad = pad_value;
        colpad = pad_value;
        allrows = rows + pad_value;
        // allrows/(2^nrec) and allcols/(2^nrec) must be integers
#if !defined(NDEBUG)
        int allcols = cols + pad_value;
        double temp = allrows / std::pow(2, nrec);
        assert(static_cast<int>(temp) == std::ceil(temp));
        temp = allcols / std::pow(2, nrec);
        assert(static_cast<int>(temp) == std::ceil(temp));
#endif
    }

    num_add = 0;
    num_sub = 0;
    num_mult = 0;

    size_t len = (allrows * allrows);
    desc.lda = static_cast<int>(allrows);
    desc.nrec = nrec;
    desc.bs = 1;
    desc.nproc = 1;
    desc.nproc_summa = 1;
    desc.nprocc = 1;
    desc.nprocr = 1;

    MatrixStrassen<Element> result(alloc_zero, rows, other.cols);

    other.rowpad = rowpad;
    result.rowpad = rowpad;
    other.colpad = colpad;
    result.colpad = colpad;
    lineardata_t lineardata_ptr;
    lineardata_t otherlineardata_ptr;
    lineardata_t resultlineardata_ptr;
    this->linearize_data_caps(&lineardata_ptr);
    other.linearize_data_caps(&otherlineardata_ptr);
    result.linearize_data_caps(&resultlineardata_ptr);

    lineardata_t thisdata;
    lineardata_t otherdata;
    lineardata_t resultdata;
    lineardata_t tempdata;

    for (size_t elem = 0; elem < len; ++elem) {
        resultdata.push_back(alloc_zero());
    }

    tempdata.resize(len);
    thisdata.resize(len);
    otherdata.resize(len);

    distribute_from1_proc_caps(desc, thisdata.begin(), lineardata_ptr.begin());

    distribute_from1_proc_caps(desc, otherdata.begin(), otherlineardata_ptr.begin());

    // multiply_internal_caps(otherdata.begin(), thisdata.begin(),
    // resultdata.begin() /*,&(result.lineardata[0])*/, desc,
    // (it_lineardata_t)0);//&(result.lineardata[0])
    multiply_internal_caps(otherdata.begin(), thisdata.begin(), resultdata.begin() /*,&(result.lineardata[0])*/, desc,
                           lineardata_ptr.begin());  // &(result.lineardata[0])

    collect_to1_proc_caps(desc, resultlineardata_ptr.begin(), resultdata.begin());
    resultdata.clear();

    result.unlinearize_data_caps(&resultlineardata_ptr);
    resultlineardata_ptr.clear();

    collect_to1_proc_caps(desc, lineardata_ptr.begin(), thisdata.begin());
    thisdata.clear();

    this->unlinearize_data_caps(&lineardata_ptr);
    lineardata_ptr.clear();

    collect_to1_proc_caps(desc, otherlineardata_ptr.begin(), otherdata.begin());
    otherdata.clear();

    other.unlinearize_data_caps(&otherlineardata_ptr);
    otherlineardata_ptr.clear();

    return result;
}

// nproc is the number of processors that share the matrices, and will be
// involved in the multiplication
template <class Element>
void MatrixStrassen<Element>::multiply_internal_caps(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                                     MatDescriptor desc, it_lineardata_t work) const {
    // (planned) out of recursion in the data layout, do a regular matrix
    // multiply.  The matrix is now in a 2d block cyclic layout
    if (desc.nrec == 0) {
        // A 2d block cyclic layout with 1 processor still has blocks to deal with
        // run a 1-proc non-strassen
        block_multiply_caps(A, B, C, desc, work);
    } else {
        if (pattern == nullptr) {
            strassen_dfscaps(A, B, C, desc, work);
        } else {
            if (pattern[0] == 'D' || pattern[0] == 'd') {
                pattern++;

                strassen_dfscaps(A, B, C, desc, work);
                pattern--;
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::add_matrices_caps(int num_entries, it_lineardata_t C, it_lineardata_t A,
                                                it_lineardata_t B) const {
#pragma omp parallel for schedule(static, (num_entries + NUM_THREADS - 1) / NUM_THREADS) \
        num_threads(cipher_parallel_controls.get_thread_limit(num_entries))
    for (int i = 0; i < num_entries; i++) {
        smart_addition_caps(C + i, A + i, B + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::sub_matrices_caps(int num_entries, it_lineardata_t C, it_lineardata_t A,
                                                it_lineardata_t B) const {
#pragma omp parallel for schedule(static, (num_entries + NUM_THREADS - 1) / NUM_THREADS) \
        num_threads(cipher_parallel_controls.get_thread_limit(num_entries))
    for (int i = 0; i < num_entries; i++) {
        smart_subtraction_caps(C + i, A + i, B + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::smart_subtraction_caps(it_lineardata_t result, it_lineardata_t A,
                                                     it_lineardata_t B) const {
    Element temp;

    if (*A != zero_unique_ptr && *B != zero_unique_ptr) {
        temp = *A - *B;
        num_sub++;
    } else if (*A == zero_unique_ptr && *B != zero_unique_ptr) {
        temp = zero_unique_ptr - *B;
        num_sub++;
    } else if (*A != zero_unique_ptr && *B == zero_unique_ptr) {
        temp = *A;
    } else {
        temp = zero_unique_ptr;
    }

    *result = temp;
    return;
}

template <class Element>
void MatrixStrassen<Element>::smart_addition_caps(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const {
    Element temp;

    if (*A != zero_unique_ptr && *B != zero_unique_ptr) {
        temp = *A + *B;
        num_add++;
    } else if (*A == zero_unique_ptr && *B != zero_unique_ptr) {
        temp = *B;
    } else if (*A != zero_unique_ptr && *B == zero_unique_ptr) {
        temp = *A;
    } else {
        temp = zero_unique_ptr;
    }

    *result = temp;
    return;
}
// useful to improve cache behavior if there is some overlap.  It is safe for
// T_i to be the same as S_j* as long as i<j.  That is, operations will happen
// in the order specified
template <class Element>
void MatrixStrassen<Element>::triple_sub_matrices_caps(int num_entries, it_lineardata_t T1, it_lineardata_t S11,
                                                       it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                       it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31,
                                                       it_lineardata_t S32) const {
#pragma omp parallel for schedule(static, (num_entries + NUM_THREADS - 1) / NUM_THREADS) \
        num_threads(cipher_parallel_controls.get_thread_limit(num_entries))
    for (int i = 0; i < num_entries; i++) {
        smart_subtraction_caps(T1 + i, S11 + i, S12 + i);

        smart_subtraction_caps(T2 + i, S21 + i, S22 + i);

        smart_subtraction_caps(T3 + i, S31 + i, S32 + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::triple_add_matrices_caps(int num_entries, it_lineardata_t T1, it_lineardata_t S11,
                                                       it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                       it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31,
                                                       it_lineardata_t S32) const {
#pragma omp parallel for schedule(static, (num_entries + NUM_THREADS - 1) / NUM_THREADS) \
        num_threads(cipher_parallel_controls.get_thread_limit(num_entries))
    for (int i = 0; i < num_entries; i++) {
        smart_addition_caps(T1 + i, S11 + i, S12 + i);

        smart_addition_caps(T2 + i, S21 + i, S22 + i);

        smart_addition_caps(T3 + i, S31 + i, S32 + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::add_sub_matrices_caps(int num_entries, it_lineardata_t T1, it_lineardata_t S11,
                                                    it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                    it_lineardata_t S22) const {
#pragma omp parallel for schedule(static, (num_entries + NUM_THREADS - 1) / NUM_THREADS) \
        num_threads(cipher_parallel_controls.get_thread_limit(num_entries))
    for (int i = 0; i < num_entries; i++) {
        smart_addition_caps(T1 + i, S11 + i, S12 + i);

        smart_subtraction_caps(T2 + i, S21 + i, S22 + i);
    }
    // COUNTERS stopTimer(TIMER_ADD);
}

template <class Element>
void MatrixStrassen<Element>::strassen_dfscaps(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                               MatDescriptor desc, it_lineardata_t work_pass_through) const {
#ifdef SANITY_CHECKS
    verify_descriptor(desc);
#endif
    MatDescriptor half_desc = desc;
    half_desc.lda /= 2;
    half_desc.nrec -= 1;
#ifdef SANITY_CHECKS
    verify_descriptor(half_desc);
#endif

    // submatrices; these are described by half_desc;
    size_t num_entries_half = num_entries_per_proc(half_desc);

    // printf("num_entries_half = %lld\n",num_entries_half);
    it_lineardata_t A11 = A;
    it_lineardata_t A21 = A + num_entries_half;
    it_lineardata_t A12 = A + 2 * num_entries_half;
    it_lineardata_t A22 = A + 3 * num_entries_half;
    it_lineardata_t B11 = B;
    it_lineardata_t B21 = B + num_entries_half;
    it_lineardata_t B12 = B + 2 * num_entries_half;
    it_lineardata_t B22 = B + 3 * num_entries_half;
    it_lineardata_t C11 = C;
    it_lineardata_t C21 = C + num_entries_half;
    it_lineardata_t C12 = C + 2 * num_entries_half;
    it_lineardata_t C22 = C + 3 * num_entries_half;

    lineardata_t r2data;
    lineardata_t r5data;

    for (size_t elem = 0; elem < num_entries_half; ++elem) {
        r2data.push_back(alloc_zero());

        r5data.push_back(alloc_zero());
    }

    // six registers.  half_desc is the descriptor for these
    it_lineardata_t R1 = C21;
    it_lineardata_t R2 = r2data.begin();
    it_lineardata_t R3 = C11;
    it_lineardata_t R4 = C22;
    it_lineardata_t R5 = r5data.begin();
    it_lineardata_t R6 = C12;

    it_lineardata_t S5 = R1;
    it_lineardata_t S3 = R2;
    it_lineardata_t S4 = R3;
    triple_sub_matrices_caps(num_entries_half, S5, B22, B12, S3, B12, B11, S4, B22, S3);
    it_lineardata_t T5 = R4;
    it_lineardata_t T3 = R6;  // was R1
    add_sub_matrices_caps(num_entries_half, T3, A21, A22, T5, A11, A21);
    it_lineardata_t Q5 = R5;
    multiply_internal_caps(T5, S5, Q5, half_desc, work_pass_through);
    it_lineardata_t Q3 = R4;
    multiply_internal_caps(T3, S3, Q3, half_desc, work_pass_through);
    it_lineardata_t T4 = R6;
    sub_matrices_caps(num_entries_half, T4, T3, A11);
    it_lineardata_t Q4 = R2;
    multiply_internal_caps(T4, S4, Q4, half_desc, work_pass_through);
    it_lineardata_t T6 = R6;
    sub_matrices_caps(num_entries_half, T6, A12, T4);
    it_lineardata_t S7 = R3;
    sub_matrices_caps(num_entries_half, S7, S4, B21);
    it_lineardata_t Q7 = R1;
    multiply_internal_caps(A22, S7, Q7, half_desc, work_pass_through);
    it_lineardata_t Q1 = R3;
    multiply_internal_caps(A11, B11, Q1, half_desc, work_pass_through);
    it_lineardata_t U1 = R2;
    it_lineardata_t U2 = R5;
    it_lineardata_t U3 = R2;
    triple_add_matrices_caps(num_entries_half, U1, Q1, Q4, U2, U1, Q5, U3, U1, Q3);
    add_sub_matrices_caps(num_entries_half, C22, U2, Q3, C21, U2, Q7);
    it_lineardata_t Q2 = R5;
    multiply_internal_caps(A12, B21, Q2, half_desc, work_pass_through);
    add_matrices_caps(num_entries_half, C11, Q1, Q2);
    it_lineardata_t Q6 = R5;
    multiply_internal_caps(T6, B22, Q6, half_desc, work_pass_through);
    add_matrices_caps(num_entries_half, C12, U3, Q6);

    r2data.clear();
    r5data.clear();
}

template <class Element>
void MatrixStrassen<Element>::block_multiply_caps(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                                  MatDescriptor d, it_lineardata_t work) const {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(d.lda))
    for (int32_t row = 0; row < d.lda; row++) {
        Element aval;
        Element bval_value;
        for (int32_t col = 0; col < d.lda; col++) {
            Element temp;
            int uninitialized_temp = 1;

            for (int32_t i = 0; i < d.lda; i++) {
                it_lineardata_t aelem = A + row + i * d.lda;
                it_lineardata_t belem = B + i + d.lda * col;

                if (*aelem == zero_unique_ptr) {
                    continue;
                }
                if (*belem == zero_unique_ptr) {
                    continue;
                }
                aval = *(A + row + i * d.lda);        // **(A + d.lda * row + i);
                bval_value = *(B + i + d.lda * col);  //  **(B + i * d.lda + col);
                num_mult++;
                if (uninitialized_temp == 1) {
                    uninitialized_temp = 0;
                    temp = (aval * bval_value);
                } else {
                    num_add++;
                    temp += (aval * bval_value);
                }
            }

            if (uninitialized_temp == 1) {  // Because of nulls, temp never got value.
                *(C + row + d.lda * col) = 0;
            } else {
                *(C + row + d.lda * col) = temp;
            }
        }
    }
}

// get the communicators used for gather and scatter when collapsing/expanding a
// column or a row

template <class Element>
void MatrixStrassen<Element>::send_block_caps(
        /*MPI_Comm comm,*/ int rank, int target, it_lineardata_t O, int bs, int source, it_lineardata_t I,
        int ldi) const {
    if (source == target) {
        if (rank == source) {
            for (int c = 0; c < bs; c++) {
                for (int i = 0; i < bs; i++) {
                    *O = std::move(*I);
                    O++;  // New
                    I++;
                }

                I += ldi - bs;  // New
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::receive_block_caps(int rank, int target, it_lineardata_t O, int bs, int source,
                                                 it_lineardata_t I, int ldo) const {
    if (source == target) {
        if (rank == source) {
            for (int c = 0; c < bs; c++) {
                for (int i = 0; i < bs; i++) {
                    *O = std::move(*I);

                    I++;
                    O++;  // New
                }

                O += ldo - bs;  // New
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::distribute_from1_proc_rec_caps(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I,
                                                             int ldi) const {
    if (desc.nrec == 0) {  // base case; put the matrix block-cyclic layout
        // MPI_Comm comm = getComm();
        int rank = get_rank();
        int bs = desc.bs;
        int num_blocks = desc.lda / bs;
        assert(num_blocks % desc.nprocr == 0);
        assert(num_blocks % desc.nprocc == 0);
        assert((num_blocks / desc.nprocr) % desc.nproc_summa == 0);
        int n_blocks_per_proc_row = num_blocks / desc.nprocr / desc.nproc_summa;
        int n_blocks_per_proc_col = num_blocks / desc.nprocc;
        int n_blocks_per_base = num_blocks / desc.nproc_summa;

        for (int sp = 0; sp < desc.nproc_summa; sp++) {
            for (int i = 0; i < n_blocks_per_proc_row; i++) {
                for (int rproc = 0; rproc < desc.nprocr; rproc++) {
                    for (int j = 0; j < n_blocks_per_proc_col; j++) {
                        for (int cproc = 0; cproc < desc.nprocc; cproc++) {
                            int source = 0;
                            int target = cproc + rproc * desc.nprocc + sp * base;
                            // row and column of the beginning of the block in I
                            int row = j * (desc.nprocc * bs) + cproc * bs;
                            int col = i * (desc.nprocr * bs) + rproc * bs + sp * n_blocks_per_base * bs;
                            int offset_source = row + col * ldi;
                            int offset_target = (j + i * n_blocks_per_proc_col) * bs * bs;
                            send_block_caps(/*comm,*/ rank, target, O + offset_target, bs, source, I + offset_source,
                                            ldi);
                        }
                    }
                }
            }
        }
    } else {  // recursively call on each of four submatrices
        desc.nrec -= 1;
        desc.lda /= 2;
        int entries_per_quarter = num_entries_per_proc(desc);
        // top left
        distribute_from1_proc_rec_caps(desc, O, I, ldi);
        // bottom left
        distribute_from1_proc_rec_caps(desc, O + entries_per_quarter, I + desc.lda, ldi);
        // top right
        distribute_from1_proc_rec_caps(desc, O + 2 * entries_per_quarter, I + desc.lda * ldi, ldi);
        // bottom right
        distribute_from1_proc_rec_caps(desc, O + 3 * entries_per_quarter, I + desc.lda * ldi + desc.lda, ldi);
    }
}

template <class Element>
void MatrixStrassen<Element>::distribute_from1_proc_caps(MatDescriptor desc, it_lineardata_t O,
                                                         it_lineardata_t I) const {
    distribute_from1_proc_rec_caps(desc, O, I, desc.lda);
}

template <class Element>
void MatrixStrassen<Element>::collect_to1_proc_rec_caps(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I,
                                                        int ldo) const {
    if (desc.nrec == 0) {  // base case; put the matrix block-cyclic layout
        // MPI_Comm comm = getComm();
        int rank = get_rank();
        int bs = desc.bs;
        int num_blocks = desc.lda / bs;
        assert(num_blocks % desc.nprocr == 0);
        assert(num_blocks % desc.nprocc == 0);
        assert((num_blocks / desc.nprocr) % desc.nproc_summa == 0);
        int n_blocks_per_proc_row = num_blocks / desc.nprocr / desc.nproc_summa;
        int n_blocks_per_proc_col = num_blocks / desc.nprocc;
        int n_blocks_per_base = num_blocks / desc.nproc_summa;
        for (int sp = 0; sp < desc.nproc_summa; sp++) {
            for (int i = 0; i < n_blocks_per_proc_row; i++) {
                for (int rproc = 0; rproc < desc.nprocr; rproc++) {
                    for (int j = 0; j < n_blocks_per_proc_col; j++) {
                        for (int cproc = 0; cproc < desc.nprocc; cproc++) {
                            int target = 0;
                            int source = cproc + rproc * desc.nprocc + sp * base;
                            // row and column of the beginning of the block in I
                            int row = j * (desc.nprocc * bs) + cproc * bs;
                            int col = i * (desc.nprocr * bs) + rproc * bs + sp * n_blocks_per_base * bs;
                            int offset_target = row + col * ldo;
                            int offset_source = (j + i * n_blocks_per_proc_col) * bs * bs;
                            receive_block_caps(
                                    /*comm,*/ rank, target, O + offset_target, bs, source, I + offset_source, ldo);
                        }
                    }
                }
            }
        }
    } else {  // recursively call on each of four submatrices
        desc.nrec -= 1;
        desc.lda /= 2;
        int entries_per_quarter = num_entries_per_proc(desc);
        // top left
        collect_to1_proc_rec_caps(desc, O, I, ldo);
        // bottom left
        collect_to1_proc_rec_caps(desc, O + desc.lda, I + entries_per_quarter, ldo);
        // top right
        collect_to1_proc_rec_caps(desc, O + desc.lda * ldo, I + 2 * entries_per_quarter, ldo);
        // bottom right
        collect_to1_proc_rec_caps(desc, O + desc.lda * ldo + desc.lda, I + 3 * entries_per_quarter, ldo);
    }
}

template <class Element>
void MatrixStrassen<Element>::collect_to1_proc_caps(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I) const {
    collect_to1_proc_rec_caps(desc, O, I, desc.lda);
}

template <class Element>
void MatrixStrassen<Element>::get_data_impl(const data_t& adata, const data_t& bdata, const data_t& cdata, int row,
                                            int inner, int col) const {
    CIPHER_DIAGNOSTIC_OUT << "Adata[3][0] = " << static_cast<int>(*adata[3][0]) << std::endl;
    CIPHER_DIAGNOSTIC_OUT << "Bdata[3][0] = " << static_cast<int>(*bdata[3][0]) << std::endl;
    CIPHER_DIAGNOSTIC_OUT << "Cdata[3][0] = " << static_cast<int>(*cdata[3][0]) << std::endl;
    CIPHER_DIAGNOSTIC_OUT << "row = " << row << " inner = " << inner << " col = " << col << std::endl;

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(row))
    for (int i = 0; i < row; i++) {
        for (int k = 0; k < inner; k++) {
            for (int j = 0; j < col; j++) {
                *(cdata[i][j]) += *(adata[i][k]) * *(bdata[k][j]);
            }
        }
    }
}

/*
 * Multiply the matrix by a vector of 1's, which is the same as adding all the
 * elements in the row together.
 * Return a vector that is a rows x 1 matrix.
 */
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::mult_by_unity_vector() const {
    MatrixStrassen<Element> result(alloc_zero, rows, 1);

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(result.rows))
    for (int32_t row = 0; row < result.rows; ++row) {
        for (int32_t col = 0; col < cols; ++col) {
            *result.data[row][0] += *data[row][col];
        }
    }

    return result;
}

/*
 * Multiply the matrix by a vector of random 1's and 0's, which is the same as
 * adding select elements in each row together. Return a vector that is a rows x
 * 1 matrix.
 */
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::mult_by_random_vector(std::vector<int> ranvec) const {
    MatrixStrassen<Element> result(alloc_zero, rows, 1);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(result.rows))
    for (int32_t row = 0; row < result.rows; ++row) {
        for (int32_t col = 0; col < cols; ++col) {
            if (ranvec[col] == 1)
                *result.data[row][0] += *data[row][col];
        }
    }
    return result;
}

template <class Element>
int MatrixStrassen<Element>::get_rank() const {
    return rank;
}

template <class Element>
void MatrixStrassen<Element>::verify_descriptor(MatDescriptor desc) {
    assert(desc.lda % ((1 << desc.nrec) * desc.bs * desc.nprocr) == 0);
    assert(desc.lda % ((1 << desc.nrec) * desc.bs * desc.nprocc) == 0);
    assert(desc.nprocr * desc.nprocc == desc.nproc);
}

template <class Element>
long long MatrixStrassen<Element>::num_entries_per_proc(MatDescriptor desc) const {  // NOLINT
    long long lda = desc.lda;                                                        // NOLINT
    return ((lda * lda) / desc.nproc / desc.nproc_summa);
}

}  // namespace cipher

#endif  // CIPHER_MATH_MATRIX_STRASSEN_IMPL_H_
