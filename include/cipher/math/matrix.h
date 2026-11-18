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
  This code provide a templated matrix implementation
 */

#ifndef CIPHER_MATH_MATRIX_H_
#define CIPHER_MATH_MATRIX_H_

#include <cmath>
#include <cstdint>
#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/memory.h"
#include "cipher/util/parallel.h"
#include "cipher/util/serializable.h"
#include "cipher/util/utilities.h"

namespace cipher {

// Forward declaration
class Field2n;

/**
 * @brief Dense row-major matrix of Element values. Elements are created through a
 * caller-supplied zero allocator so that ring elements carrying parameters can be
 * constructed; arithmetic is element-wise or the usual matrix product, and the class
 * provides the gadget, rotation, stacking, and decomposition helpers of the lattice
 * trapdoor code.
 * @tparam Element the element type (integer, floating point, or ring element)
 */
template <class Element>
class Matrix : public Serializable {
  public:
    /// storage: a vector of rows
    typedef std::vector<std::vector<Element>> data_t;
    /// one row of the matrix
    typedef std::vector<Element> data_row_t;
    /// function returning a freshly allocated element (typically zero)
    typedef std::function<Element(void)> alloc_func;

    /**
     * Constructor that initializes matrix values using a zero allocator
     *
     * @param alloc_zero lambda function for zero initialization.
     * @param rows number of rows.
     * @param cols number of columns.
     */
    Matrix(alloc_func alloc_zero, size_t rows, size_t cols) : data(), rows(rows), cols(cols), alloc_zero(alloc_zero) {
        data.resize(rows);
        for (auto row = data.begin(); row != data.end(); ++row) {
            row->reserve(cols);
            for (size_t col = 0; col < cols; ++col) {
                row->push_back(alloc_zero());
            }
        }
    }

    // TODO: add Clear();

    /**
     * Constructor that initializes matrix values using a distribution generation
     * allocator
     *
     * @param alloc_zero lambda function for zero initialization (used for
     * initializing derived matrix objects)
     * @param rows number of rows.
     * @param cols number of columns.
     * @param alloc_gen lambda function for initialization using a distribution
     * generator.
     */
    Matrix(alloc_func alloc_zero, size_t rows, size_t cols, alloc_func alloc_gen);

    /**
     * Constructor of an empty matrix.
     * set_size must be called on this matrix to use it
     * SetAlloc needs to be called if 0 passed to constructor
     * This mostly exists to support deserializing
     *
     * @param alloc_zero lambda function for zero initialization.
     */
    explicit Matrix(alloc_func alloc_zero = 0) : data(), rows(0), cols(0), alloc_zero(alloc_zero) {}

    /**
     * Set the size of a matrix, elements are zeroed out
     *
     * @param rows number of rows
     * @param cols number of columns
     */

    void set_size(size_t rows, size_t cols) {
        if (this->rows != 0 || this->cols != 0) {
            CIPHER_THROW("You cannot SetSize on a non-empty matrix");
        }

        this->rows = rows;
        this->cols = cols;

        data.resize(rows);
        for (auto row = data.begin(); row != data.end(); ++row) {
            row->reserve(cols);
            for (size_t col = 0; col < cols; ++col) {
                row->push_back(alloc_zero());
            }
        }
    }

    /**
     * set_allocator - set the function to allocate a zero;
     * basically only required for deserializer
     *
     * @param alloc_zero lambda function for zero initialization
     */
    void set_allocator(alloc_func alloc_zero) {
        this->alloc_zero = alloc_zero;
    }

    /**
     * Copy constructor
     *
     * @param other the matrix object to be copied
     */
    Matrix(const Matrix<Element>& other) : data(), rows(other.rows), cols(other.cols), alloc_zero(other.alloc_zero) {
        deep_copy_data(other.data);
    }

    /**
     * Assignment operator
     *
     * @param other the matrix object whose values are to be copied
     * @return the resulting matrix
     */
    Matrix<Element>& operator=(const Matrix<Element>& other);

    /**
     * In-place change of the current matrix to a matrix of all ones
     *
     * @return the resulting matrix
     */
    Matrix<Element>& ones() {
        for (size_t row = 0; row < rows; ++row) {
            for (size_t col = 0; col < cols; ++col) {
                data[row][col] = 1;
            }
        }
        return *this;
    }

    /**
     * In-place modulo reduction
     *
     * @param modulus the modulus to reduce by
     * @return the resulting matrix (same object)
     */
    Matrix<Element>& mod_eq(const Element& modulus);

    /**
     * In-place modular subtraction
     *
     * @param b the matrix to be subtracted
     * @param modulus the modulus to reduce by
     * @return the resulting matrix (same object)
     */
    Matrix<Element>& mod_sub_eq(Matrix<Element> const& b, const Element& modulus);

    /**
     * Fill matrix using the same element
     *
     * @param val the element the matrix is filled by
     *
     * @return the resulting matrix
     */
    Matrix<Element>& Fill(const Element& val);

    /**
     * In-place change of the current matrix to Identity matrix
     *
     * @return the resulting matrix
     */
    Matrix<Element>& identity() {
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

    /**
     * Sets the first row to be powers of two for when the base is two
     *
     * @param base is the base the digits of the matrix are represented in
     * @return the resulting matrix
     */
    template <typename T = Element,
              typename std::enable_if<!std::is_same<T, M2RnsPoly>::value && !std::is_same<T, M4RnsPoly>::value &&
                                              !std::is_same<T, M6RnsPoly>::value,
                                      bool>::type = true>
    Matrix<T> gadget_vector(int64_t base = 2) const {
        Matrix<T> g(alloc_zero, rows, cols);
        auto base_matrix = alloc_zero();
        size_t k = cols / rows;
        base_matrix = base;
        g(0, 0) = 1;
        for (size_t i = 1; i < k; i++) {
            g(0, i) = g(0, i - 1) * base_matrix;
        }
        for (size_t row = 1; row < rows; row++) {
            for (size_t i = 0; i < k; i++) {
                g(row, i + row * k) = g(0, i);
            }
        }
        return g;
    }

    /**
     * Gadget matrix for RnsPoly elements: the digits of every CRT modulus are handled
     * separately, so the first row holds, for each tower i, the powers of the base embedded
     * in tower i only; the other rows are shifted copies of the first row.
     *
     * @param base is the base the digits of the matrix are represented in
     * @return the resulting matrix
     */
    template <typename T = Element,
              typename std::enable_if<std::is_same<T, M2RnsPoly>::value || std::is_same<T, M4RnsPoly>::value ||
                                              std::is_same<T, M6RnsPoly>::value,
                                      bool>::type = true>
    Matrix<T> gadget_vector(int64_t base = 2) const {
        Matrix<T> g(alloc_zero, rows, cols);
        auto base_matrix = alloc_zero();
        base_matrix = base;
        size_t bk = 1;

        auto params = g(0, 0).get_params()->get_params();

        uint64_t digit_count = get_digit_count(params[0]->get_modulus().convert_to_int(), static_cast<uint64_t>(base));

        for (size_t k = 0; k < digit_count; k++) {
            for (size_t i = 0; i < params.size(); i++) {
                NativePoly temp(params[i]);
                temp = bk;
                g(0, k + i * digit_count).set_element_at_index(i, std::move(temp));
            }
            bk *= base;
        }

        size_t k_cols = cols / rows;
        for (size_t row = 1; row < rows; row++) {
            for (size_t i = 0; i < k_cols; i++) {
                g(row, i + row * k_cols) = g(0, i);
            }
        }
        return g;
    }

    /**
     * Computes the infinity norm; not defined for scalar (double, int, int64_t) and Field2n
     * element types, for which this overload always throws.
     *
     * @return never returns; throws.
     */
    template <typename T = Element,
              typename std::enable_if<std::is_same<T, double>::value || std::is_same<T, int>::value ||
                                              std::is_same<T, int64_t>::value || std::is_same<T, Field2n>::value,
                                      bool>::type = true>
    double norm() const {
        CIPHER_THROW("Norm not defined for this type");
    }

    /**
     * Computes the infinity norm: the largest norm() over all elements
     *
     * @return the norm in double format
     */
    template <typename T = Element,
              typename std::enable_if<!std::is_same<T, double>::value && !std::is_same<T, int>::value &&
                                              !std::is_same<T, int64_t>::value && !std::is_same<T, Field2n>::value,
                                      bool>::type = true>
    double norm() const {
        double ret_val = 0.0;
        double loc_val = 0.0;
        for (size_t row = 0; row < rows; ++row) {
            for (size_t col = 0; col < cols; ++col) {
                loc_val = data[row][col].norm();
                if (loc_val > ret_val) {
                    ret_val = loc_val;
                }
            }
        }
        return ret_val;
    }

    /**
     * Matrix multiplication
     *
     * @param other the multiplier matrix
     * @return the result of multiplication
     */
    Matrix<Element> mult(Matrix<Element> const& other) const;

    /**
     * Operator for matrix multiplication
     *
     * @param other the multiplier matrix
     * @return the result of multiplication
     */
    Matrix<Element> operator*(Matrix<Element> const& other) const {
        return mult(other);
    }

    /**
     * Multiplication of matrix by a scalar
     *
     * @param other the multiplier element
     * @return the result of multiplication
     */
    Matrix<Element> scalar_mult(Element const& other) const {
        Matrix<Element> result(*this);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(result.cols))
        for (size_t col = 0; col < result.cols; ++col) {
            for (size_t row = 0; row < result.rows; ++row) {
                result.data[row][col] = result.data[row][col] * other;
            }
        }

        return result;
    }

    /**
     * Operator for scalar multiplication
     *
     * @param other the multiplier element
     * @return the result of multiplication
     */
    Matrix<Element> operator*(Element const& other) const {
        return scalar_mult(other);
    }

    /**
     * Equality check
     *
     * @param other the matrix object to compare to
     * @return the boolean result
     */
    bool equal_impl(Matrix<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            return false;
        }

        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                if (data[i][j] != other.data[i][j]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Operator for equality check
     *
     * @param other the matrix object to compare to
     * @return the boolean result
     */
    bool operator==(Matrix<Element> const& other) const {
        return equal_impl(other);
    }

    /**
     * Operator for non-equality check
     *
     * @param other the matrix object to compare to
     * @return the boolean result
     */
    bool operator!=(Matrix<Element> const& other) const {
        return !equal_impl(other);
    }

    /**
     * Get property to access the data as a vector of vectors
     *
     * @return the data as vector of vectors
     */
    const data_t& get_data() const {
        return data;
    }

    /**
     * Get property to access the number of rows in the matrix
     *
     * @return the number of rows
     */
    size_t get_rows() const {
        return rows;
    }

    /**
     * Get property to access the number of columns in the matrix
     *
     * @return the number of columns
     */
    size_t get_cols() const {
        return cols;
    }

    /**
     * Get property to access the zero allocator for the matrix
     *
     * @return the lambda function corresponding to the element zero allocator
     */
    alloc_func get_allocator() const {
        return alloc_zero;
    }

    /**
     * Sets the evaluation or coefficient representation for all ring elements
     * that support the set_format method
     *
     * @param format the enum value corresponding to coefficient or evaluation
     * representation
     */
    void set_format(Format format);

    /**
     * Matrix addition
     *
     * @param other the matrix to be added
     * @return the resulting matrix
     */
    Matrix<Element> add(Matrix<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            CIPHER_THROW("Addition operands have incompatible dimensions");
        }
        Matrix<Element> result(*this);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(cols))
        for (size_t j = 0; j < cols; ++j) {
            for (size_t i = 0; i < rows; ++i) {
                result.data[i][j] += other.data[i][j];
            }
        }
        return result;
    }

    /**
     * Operator for matrix addition
     *
     * @param other the matrix to be added
     * @return the resulting matrix
     */
    Matrix<Element> operator+(Matrix<Element> const& other) const {
        return this->add(other);
    }

    /**
     * Operator for in-place addition
     *
     * @param other the matrix to be added
     * @return the resulting matrix (same object)
     */
    Matrix<Element>& operator+=(Matrix<Element> const& other);

    /**
     * Matrix subtraction
     *
     * @param other the matrix to be subtracted
     * @return the resulting matrix
     */
    Matrix<Element> sub(Matrix<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            CIPHER_THROW("Subtraction operands have incompatible dimensions");
        }
        Matrix<Element> result(alloc_zero, rows, other.cols);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(cols))
        for (size_t j = 0; j < cols; ++j) {
            for (size_t i = 0; i < rows; ++i) {
                result.data[i][j] = data[i][j] - other.data[i][j];
            }
        }

        return result;
    }

    /**
     * Operator for matrix subtraction
     *
     * @param other the matrix to be subtracted
     * @return the resulting matrix
     */
    Matrix<Element> operator-(Matrix<Element> const& other) const {
        return this->sub(other);
    }

    /**
     * Operator for in-place matrix subtraction
     *
     * @param other the matrix to be subtracted
     * @return the resulting matrix (same object)
     */
    Matrix<Element>& operator-=(Matrix<Element> const& other);

    /**
     * Matrix transposition
     *
     * @return the resulting matrix
     */
    Matrix<Element> transposed() const;

    // YSP The signature of this method needs to be changed in the future
    /**
     * Matrix determinant - found using Laplace formula with complexity O(d!),
     * where d is the dimension
     *
     * @param result where the result is stored
     */
    void determinant(Element* result) const;
    // Element determinant() const;

    /**
     * Cofactor matrix - the matrix of determinants of the minors A_{ij}
     * multiplied by -1^{i+j}
     *
     * @return the cofactor matrix for the given matrix
     */
    Matrix<Element> cofactor_matrix() const;

    /**
     * Add rows to bottom of the matrix
     *
     * @param other the matrix to be added to the bottom of current matrix
     * @return the resulting matrix
     */
    Matrix<Element>& v_stack(Matrix<Element> const& other);

    /**
     * Add columns the right of the matrix
     *
     * @param other the matrix to be added to the right of current matrix
     * @return the resulting matrix
     */
    Matrix<Element>& h_stack(Matrix<Element> const& other);

    /**
     * Matrix indexing operator - writeable instance of the element
     *
     * @param row row index
     * @param col column index
     * @return the element at the index
     */
    Element& operator()(size_t row, size_t col) {
        return data[row][col];
    }

    /**
     * Matrix indexing operator - read-only instance of the element
     *
     * @param row row index
     * @param col column index
     * @return the element at the index
     */
    Element const& operator()(size_t row, size_t col) const {
        return data[row][col];
    }

    /**
     * Matrix row extractor
     *
     * @param row row index
     * @return the row at the index
     */
    Matrix<Element> extract_row(size_t row) const {
        Matrix<Element> result(this->alloc_zero, 1, this->cols);
        int i = 0;
        for (auto& elem : this->get_data()[row]) {
            result(0, i) = elem;
            i++;
        }
        return result;
        // return *this;
    }

    /**
     * Matrix column extractor
     *
     * @param col col index
     * @return the col at the index
     */
    Matrix<Element> extract_col(size_t col) const {
        Matrix<Element> result(this->alloc_zero, this->rows, 1);
        for (size_t i = 0; i < this->rows; i++) {
            result(i, 0) = data[i][col];
        }
        return result;
        // return *this;
    }

    /**
     * Matrix rows extractor in a range from row_start to row_end; inclusive
     *
     * @param row_start index of the first row to extract
     * @param row_end index of the last row to extract
     * @return the rows in the range delimited by indices inclusive
     */
    inline Matrix<Element> extract_rows(size_t row_start, size_t row_end) const {
        Matrix<Element> result(this->alloc_zero, row_end - row_start + 1, this->cols);

        for (uint32_t row = row_start; row < row_end + 1; row++) {
            int i = 0;

            for (auto elem = this->get_data()[row].begin(); elem != this->get_data()[row].end(); ++elem) {
                result(row - row_start, i) = *elem;
                i++;
            }
        }

        return result;
    }

    friend std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m) {
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

    /**
     * Call switch format for each (ring) element
     *
     */
    void switch_format();
#define NOT_AN_ELEMENT_MATRIX(T)                   \
    template <>                                    \
    void Matrix<T>::switch_format() {               \
        CIPHER_THROW("Not a matrix of Elements"); \
    }

    /**
     * Multiply the matrix by a vector whose elements are all 1's.  This causes
     * the elements of each row of the matrix to be added and placed into the
     * corresponding position in the output vector.
     *
     * @return the rows x 1 matrix of row sums
     */
    Matrix<Element> mult_by_unity_vector() const;

    /**
     * Multiply the matrix by a vector of random 1's and 0's, which is the same as
     * adding select elements in each row together. Return a vector that is a rows
     * x 1 matrix.
     *
     * @param ranvec the 0/1 vector of length cols selecting the columns to add
     * @return the rows x 1 matrix of selected row sums
     */
    Matrix<Element> mult_by_random_vector(std::vector<int> ranvec) const;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("d", data));
        ar(::cereal::make_nvp("r", rows));
        ar(::cereal::make_nvp("c", cols));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("d", data));
        ar(::cereal::make_nvp("r", rows));
        ar(::cereal::make_nvp("c", cols));

        // users will need to set_allocator for any newly deserialized matrix
    }

    std::string serialized_object_name() const override {
        return "Matrix";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  private:
    data_t data;
    uint32_t rows;
    uint32_t cols;
    alloc_func alloc_zero;
    // mutable int NUM_THREADS = 1;

    // deep copy of data - used for copy constructor
    void deep_copy_data(data_t const& src) {
        data = src;
    }
};

/**
 * Operator for scalar multiplication of matrix
 *
 * @param e element
 * @param M matrix
 * @return the resulting matrix
 */
template <class Element>
Matrix<Element> operator*(Element const& e, Matrix<Element> const& M) {
    return M.scalar_mult(e);
}

/**
 * Generates a matrix of rotations. See pages 7-8 of
 * https://eprint.iacr.org/2013/297
 *
 * @param in_mat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary integers
 */
template <typename Element>
Matrix<typename Element::Integer> Rotate(Matrix<Element> const& in_mat);

/**
 *  Each element becomes a square matrix with columns of that element's
 *  rotations in coefficient form. See pages 7-8 of
 * https://eprint.iacr.org/2013/297
 *
 * @param in_mat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary vectors
 */
template <typename Element>
Matrix<typename Element::Vector> rotate_vec_result(Matrix<Element> const& in_mat);

/**
 *  Stream output operator
 *
 * @param os stream
 * @param m matrix to be outputted
 * @return the chained stream
 */
template <class Element>
std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m);

/**
 * Gives the Cholesky decomposition of the input matrix.
 * The assumption is that covariance matrix does not have large coefficients
 * because it is formed by discrete gaussians e and s; this implies int32_t can
 * be used This algorithm can be further improved - see the Darmstadt paper
 * section 4.4 http://eprint.iacr.org/2013/297.pdf
 *
 * @param input the matrix for which the Cholesky decomposition is to be
 * computed
 * @return the resulting matrix of floating-point numbers
 */
Matrix<double> cholesky(const Matrix<int32_t>& input);

/**
 * Gives the Cholesky decomposition of the input matrix, writing the lower-triangular factor
 * into a caller-provided matrix of the same size (the upper triangle is zeroed). See the
 * single-argument overload for the assumptions.
 *
 * @param input the square matrix for which the Cholesky decomposition is to be computed
 * @param result the preallocated rows x rows matrix receiving the factor
 */
void cholesky(const Matrix<int32_t>& input, Matrix<double>& result);

/**
 * Convert a matrix of integers from BigInteger to int32_t
 * Convert from Z_q to (-q/2, q/2]
 *
 * @param input the input matrix
 * @param modulus the ring modulus
 * @return the resulting matrix of int32_t
 * @throws CipherException if a centered value cannot be represented as int32_t
 */
Matrix<int32_t> convert_to_int32(const Matrix<BigInteger>& input, const BigInteger& modulus);

/**
 * Convert a matrix of BigVector to int32_t
 * Convert from Z_q to (-q/2, q/2]
 *
 * @param input the input matrix
 * @param modulus the ring modulus
 * @return the resulting matrix of int32_t
 * @throws CipherException if a centered value cannot be represented as int32_t
 */
Matrix<int32_t> convert_to_int32(const Matrix<BigVector>& input, const BigInteger& modulus);

/**
 * Split a vector of int64_t into a vector of ring elements with ring dimension
 * n
 *
 * @param other the input matrix
 * @param n the ring dimension
 * @param params Poly element params
 * @return the resulting matrix of Poly
 */
template <typename Element>
Matrix<Element> split_int64_into_elements(Matrix<int64_t> const& other, size_t n,
                                       const std::shared_ptr<typename Element::Params> params);

#define SPLIT64_FOR_TYPE(T)                                                              \
    template <>                                                                          \
    Matrix<T> split_int64_into_elements(Matrix<int64_t> const& other, size_t n,             \
                                     const std::shared_ptr<typename T::Params> params) { \
        auto zero_alloc = T::allocator(params, Format::COEFFICIENT);                     \
        size_t rows = other.get_rows() / n;                                               \
        Matrix<T> result(zero_alloc, rows, 1);                                           \
        for (size_t row = 0; row < rows; ++row) {                                        \
            std::vector<int64_t> values(n);                                              \
            for (size_t i = 0; i < n; ++i)                                               \
                values[i] = other(row * n + i, 0);                                       \
            result(row, 0) = values;                                                     \
        }                                                                                \
        return result;                                                                   \
    }

/**
 * Another method for splitting a vector of int32_t into a vector of ring
 * elements with ring dimension n
 *
 * @param other the input matrix
 * @param n the ring dimension
 * @param params Poly element params
 * @return the resulting matrix of Poly
 */
template <typename Element>
Matrix<Element> split_int32_alt_into_elements(Matrix<int32_t> const& other, size_t n,
                                          const std::shared_ptr<typename Element::Params> params);

#define SPLIT32ALT_FOR_TYPE(T)                                                              \
    template <>                                                                             \
    Matrix<T> split_int32_alt_into_elements(Matrix<int32_t> const& other, size_t n,             \
                                        const std::shared_ptr<typename T::Params> params) { \
        auto zero_alloc = T::allocator(params, Format::COEFFICIENT);                        \
        size_t rows = other.get_rows();                                                      \
        Matrix<T> result(zero_alloc, rows, 1);                                              \
        for (size_t row = 0; row < rows; ++row) {                                           \
            std::vector<int32_t> values(n);                                                 \
            for (size_t i = 0; i < n; ++i)                                                  \
                values[i] = other(row, i);                                                  \
            result(row, 0) = values;                                                        \
        }                                                                                   \
        return result;                                                                      \
    }

/**
 * Split a vector of int64_t into a vector of ring elements with ring dimension
 * n
 *
 * @param other the input matrix
 * @param n the ring dimension
 * @param params Poly element params
 * @return the resulting matrix of Poly
 */
template <typename Element>
Matrix<Element> split_int64_alt_into_elements(Matrix<int64_t> const& other, size_t n,
                                          const std::shared_ptr<typename Element::Params> params);

#define SPLIT64ALT_FOR_TYPE(T)                                                              \
    template <>                                                                             \
    Matrix<T> split_int64_alt_into_elements(Matrix<int64_t> const& other, size_t n,             \
                                        const std::shared_ptr<typename T::Params> params) { \
        auto zero_alloc = T::allocator(params, Format::COEFFICIENT);                        \
        size_t rows = other.get_rows();                                                      \
        Matrix<T> result(zero_alloc, rows, 1);                                              \
        for (size_t row = 0; row < rows; ++row) {                                           \
            std::vector<int64_t> values(n);                                                 \
            for (size_t i = 0; i < n; ++i)                                                  \
                values[i] = other(row, i);                                                  \
            result(row, 0) = values;                                                        \
        }                                                                                   \
        return result;                                                                      \
    }

}  // namespace cipher
#endif  // CIPHER_MATH_MATRIX_H_
