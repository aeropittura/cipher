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

#ifndef CIPHER_MATH_BACKEND_FIXED_TRANSFORM_IMPL_H_
#define CIPHER_MATH_BACKEND_FIXED_TRANSFORM_IMPL_H_

// ATTENTION: this file contains implementations of the functions
//            declared in math/bigintfxd/transformfxd.h and
//            MUST be included in the end of math/bigintfxd/transformfxd.h ONLY
//            and nowhere else

#include <cmath>
#include <cstdint>
#include <map>
#include <vector>

#include "cipher/math/number_theory.h"
#include "cipher/util/exception.h"
#include "cipher/util/utilities.h"

namespace fixed_int {

using namespace cipher;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::cyclo_order_inverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::cyclo_order_inverse_precon_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::root_of_unity_reverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::root_of_unity_inverse_reverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::root_of_unity_precon_reverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformFttFxd<VecType>::root_of_unity_inverse_precon_reverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbFxd<VecType>::cyclotomic_poly_map_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbFxd<VecType>::cyclotomic_poly_reverse_ntt_map_;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbFxd<VecType>::cyclotomic_poly_ntt_map_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftFxd<VecType>::root_of_unity_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
        BluesteinFftFxd<VecType>::root_of_unity_inverse_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFftFxd<VecType>::powers_table_by_modulus_root_;

template <typename VecType>
std::map<ModulusRootPair<typename VecType::Integer>, VecType> BluesteinFftFxd<VecType>::rb_table_by_modulus_root_pair_;

template <typename VecType>
std::map<typename VecType::Integer, ModulusRoot<typename VecType::Integer>>
        BluesteinFftFxd<VecType>::default_ntt_modulus_root_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbFxd<VecType>::root_of_unity_division_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
        ChineseRemainderTransformArbFxd<VecType>::root_of_unity_division_inverse_table_by_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
        ChineseRemainderTransformArbFxd<VecType>::division_ntt_modulus_;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
        ChineseRemainderTransformArbFxd<VecType>::division_ntt_root_of_unity_;

template <typename VecType>
std::map<uint32_t, uint32_t> ChineseRemainderTransformArbFxd<VecType>::ntt_division_dim_;

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::forward_transform_iterative(const VecType& element,
                                                                       const VecType& root_of_unity_table,
                                                                       VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n) {
        CIPHER_THROW("size of input element and size of output element not of same size");
    }

    auto modulus = element.get_modulus();
    IntType mu = modulus.compute_mu();
    result->set_modulus(modulus);

    uint32_t msb = get_msb64(n - 1);
    for (size_t i = 0; i < n; i++) {
        (*result)[i] = element[reverse_bits(i, msb)];
    }

    IntType omega, omega_factor, odd_val, even_val;
    uint32_t logm, i, j, index_even, index_odd;

    uint32_t logn = get_msb64(n - 1);
    for (logm = 1; logm <= logn; logm++) {
        // calculate the i indexes into the root table one time per loop
        std::vector<uint32_t> indexes(1 << (logm - 1));
        for (i = 0; i < (uint32_t)(1 << (logm - 1)); i++) {
            indexes[i] = (i << (logn - logm));
        }

        for (j = 0; j < n; j = j + (1 << logm)) {
            for (i = 0; i < (uint32_t)(1 << (logm - 1)); i++) {
                omega = root_of_unity_table[indexes[i]];
                index_even = j + i;
                index_odd = index_even + (1 << (logm - 1));
                odd_val = (*result)[index_odd];

                omega_factor = omega.mod_mul(odd_val, modulus, mu);
                even_val = (*result)[index_even];
                odd_val = even_val;
                odd_val += omega_factor;
                if (odd_val >= modulus) {
                    odd_val -= modulus;
                }

                if (even_val < omega_factor) {
                    even_val += modulus;
                }
                even_val -= omega_factor;

                (*result)[index_even] = odd_val;
                (*result)[index_odd] = even_val;
            }
        }
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::inverse_transform_iterative(const VecType& element,
                                                                       const VecType& root_of_unity_inverse_table,
                                                                       VecType* result) {
    uint32_t n = element.get_length();

    IntType modulus = element.get_modulus();
    IntType mu = modulus.compute_mu();

    NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(element, root_of_unity_inverse_table, result);
    IntType cyclo_order_inv(IntType(n).mod_inverse(modulus));
    for (uint32_t i = 0; i < n; i++) {
        (*result)[i].mod_mul_eq(cyclo_order_inv, modulus, mu);
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::forward_transform_to_bit_reverse_in_place(const VecType& root_of_unity_table,
                                                                                     VecType* element) {
    uint32_t n = element->get_length();
    IntType modulus = element->get_modulus();
    IntType mu = modulus.compute_mu();

    uint32_t i, m, j1, j2, index_omega, index_lo, index_hi;
    IntType omega, omega_factor, lo_val, hi_val, zero(0);

    uint32_t t = (n >> 1);
    uint32_t logt1 = get_msb64(t);
    for (m = 1; m < n; m <<= 1) {
        for (i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_table[index_omega];
            for (index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;
                lo_val = (*element)[index_lo];
                omega_factor = (*element)[index_hi];
                omega_factor.mod_mul_fast_eq(omega, modulus, mu);

                hi_val = lo_val + omega_factor;
                if (hi_val >= modulus) {
                    hi_val -= modulus;
                }

                if (lo_val < omega_factor) {
                    lo_val += modulus;
                }
                lo_val -= omega_factor;

                (*element)[index_lo] = hi_val;
                (*element)[index_hi] = lo_val;
            }
        }
        t >>= 1;
        logt1--;
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                            const VecType& root_of_unity_table,
                                                                            VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n) {
        CIPHER_THROW("size of input element and size of output element not of same size");
    }

    IntType modulus = element.get_modulus();
    IntType mu = modulus.compute_mu();
    result->set_modulus(modulus);

    uint32_t i, m, j1, j2, index_omega, index_lo, index_hi;
    IntType omega, omega_factor, lo_val, hi_val, zero(0);

    for (i = 0; i < n; ++i) {
        (*result)[i] = element[i];
    }

    uint32_t t = (n >> 1);
    uint32_t logt1 = get_msb64(t);
    for (m = 1; m < n; m <<= 1) {
        for (i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_table[index_omega];
            for (index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;
                lo_val = (*result)[index_lo];
                omega_factor = (*result)[index_hi];
                if (omega_factor != zero) {
                    omega_factor.mod_mul_fast_eq(omega, modulus, mu);

                    hi_val = lo_val + omega_factor;
                    if (hi_val >= modulus) {
                        hi_val -= modulus;
                    }

                    if (lo_val < omega_factor) {
                        lo_val += modulus;
                    }
                    lo_val -= omega_factor;

                    (*result)[index_lo] = hi_val;
                    (*result)[index_hi] = lo_val;
                } else {
                    (*result)[index_hi] = lo_val;
                }
            }
        }
        t >>= 1;
        logt1--;
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::forward_transform_to_bit_reverse_in_place(
        const VecType& root_of_unity_table, const VecType& precon_root_of_unity_table, VecType* element) {
    uint32_t n = element->get_length();
    IntType modulus = element->get_modulus();

    uint32_t index_omega, index_hi;
    IntType precon_omega;
    IntType omega, omega_factor, lo_val, hi_val, zero(0);

    uint32_t t = (n >> 1);
    uint32_t logt1 = get_msb64(t);
    for (uint32_t m = 1; m < n; m <<= 1, t >>= 1, --logt1) {
        uint32_t j1, j2;
        for (uint32_t i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_table[index_omega];
            precon_omega = precon_root_of_unity_table[index_omega];
            for (uint32_t index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;
                lo_val = (*element)[index_lo];
                omega_factor = (*element)[index_hi];
                omega_factor.mod_mul_fast_const_eq(omega, modulus, precon_omega);

                hi_val = lo_val + omega_factor;
                if (hi_val >= modulus) {
                    hi_val -= modulus;
                }

                if (lo_val < omega_factor) {
                    lo_val += modulus;
                }
                lo_val -= omega_factor;

                (*element)[index_lo] = hi_val;
                (*element)[index_hi] = lo_val;
            }
        }
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                            const VecType& root_of_unity_table,
                                                                            const VecType& precon_root_of_unity_table,
                                                                            VecType* result) {
    uint32_t n = element.get_length();

    if (result->get_length() != n) {
        CIPHER_THROW("size of input element and size of output element not of same size");
    }

    IntType modulus = element.get_modulus();

    result->set_modulus(modulus);

    for (uint32_t i = 0; i < n; ++i) {
        (*result)[i] = element[i];
    }

    uint32_t index_omega, index_hi;
    IntType precon_omega;
    IntType omega, omega_factor, lo_val, hi_val, zero(0);

    uint32_t t = (n >> 1);
    uint32_t logt1 = get_msb64(t);
    for (uint32_t m = 1; m < n; m <<= 1, t >>= 1, --logt1) {
        uint32_t j1, j2;
        for (uint32_t i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_table[index_omega];
            precon_omega = precon_root_of_unity_table[index_omega];
            for (uint32_t index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;
                lo_val = (*result)[index_lo];
                omega_factor = (*result)[index_hi];
                if (omega_factor != zero) {
                    omega_factor.mod_mul_fast_const_eq(omega, modulus, precon_omega);

                    hi_val = lo_val + omega_factor;
                    if (hi_val >= modulus) {
                        hi_val -= modulus;
                    }

                    if (lo_val < omega_factor) {
                        lo_val += modulus;
                    }
                    lo_val -= omega_factor;

                    (*result)[index_lo] = hi_val;
                    (*result)[index_hi] = lo_val;
                } else {
                    (*result)[index_hi] = lo_val;
                }
            }
        }
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::inverse_transform_from_bit_reverse_in_place(
        const VecType& root_of_unity_inverse_table, const IntType& cyclo_order_inv, VecType* element) {
    uint32_t n = element->get_length();
    IntType modulus = element->get_modulus();
    IntType mu = modulus.compute_mu();

    IntType lo_val, hi_val, omega, omega_factor;
    uint32_t i, m, j1, j2, index_omega, index_lo, index_hi;

    uint32_t t = 1;
    uint32_t logt1 = 1;
    for (m = (n >> 1); m >= 1; m >>= 1) {
        for (i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_inverse_table[index_omega];

            for (index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;

                hi_val = (*element)[index_hi];
                lo_val = (*element)[index_lo];

                omega_factor = lo_val;
                if (omega_factor < hi_val) {
                    omega_factor += modulus;
                }

                omega_factor -= hi_val;

                lo_val += hi_val;
                if (lo_val >= modulus) {
                    lo_val -= modulus;
                }

                omega_factor.mod_mul_fast_eq(omega, modulus, mu);

                (*element)[index_lo] = lo_val;
                (*element)[index_hi] = omega_factor;
            }
        }
        t <<= 1;
        logt1++;
    }

    for (i = 0; i < n; i++) {
        (*element)[i].mod_mul_fast_eq(cyclo_order_inv, modulus, mu);
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::inverse_transform_from_bit_reverse(
        const VecType& element, const VecType& root_of_unity_inverse_table, const IntType& cyclo_order_inv,
        VecType* result) {
    uint32_t n = element.get_length();

    if (result->get_length() != n) {
        CIPHER_THROW("size of input element and size of output element not of same size");
    }

    result->set_modulus(element.get_modulus());

    for (uint32_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }
    inverse_transform_from_bit_reverse_in_place(root_of_unity_inverse_table, cyclo_order_inv, result);
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::inverse_transform_from_bit_reverse_in_place(
        const VecType& root_of_unity_inverse_table, const VecType& precon_root_of_unity_inverse_table,
        const IntType& cyclo_order_inv, const IntType& precon_cyclo_order_inv, VecType* element) {
    uint32_t n = element->get_length();

    IntType modulus = element->get_modulus();

    IntType lo_val, hi_val, omega, omega_factor;
    IntType precon_omega;
    uint32_t i, m, j1, j2, index_omega, index_lo, index_hi;

    uint32_t t = 1;
    uint32_t logt1 = 1;
    for (m = (n >> 1); m >= 1; m >>= 1) {
        for (i = 0; i < m; ++i) {
            j1 = i << logt1;
            j2 = j1 + t;
            index_omega = m + i;
            omega = root_of_unity_inverse_table[index_omega];
            precon_omega = precon_root_of_unity_inverse_table[index_omega];

            for (index_lo = j1; index_lo < j2; ++index_lo) {
                index_hi = index_lo + t;

                hi_val = (*element)[index_hi];
                lo_val = (*element)[index_lo];

                omega_factor = lo_val;
                if (omega_factor < hi_val) {
                    omega_factor += modulus;
                }

                omega_factor -= hi_val;

                lo_val += hi_val;
                if (lo_val >= modulus) {
                    lo_val -= modulus;
                }

                omega_factor.mod_mul_fast_const_eq(omega, modulus, precon_omega);

                (*element)[index_lo] = lo_val;
                (*element)[index_hi] = omega_factor;
            }
        }
        t <<= 1;
        logt1++;
    }

    for (i = 0; i < n; i++) {
        (*element)[i].mod_mul_fast_const_eq(cyclo_order_inv, modulus, precon_cyclo_order_inv);
    }
}

template <typename VecType>
void NumberTheoreticTransformFxd<VecType>::inverse_transform_from_bit_reverse(
        const VecType& element, const VecType& root_of_unity_inverse_table,
        const VecType& precon_root_of_unity_inverse_table, const IntType& cyclo_order_inv,
        const IntType& precon_cyclo_order_inv, VecType* result) {
    uint32_t n = element.get_length();
    if (result->get_length() != n) {
        CIPHER_THROW("size of input element and size of output element not of same size");
    }

    result->set_modulus(element.get_modulus());

    for (uint32_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }
    inverse_transform_from_bit_reverse_in_place(root_of_unity_inverse_table, precon_root_of_unity_inverse_table,
                                                cyclo_order_inv, precon_cyclo_order_inv, result);

    return;
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::forward_transform_to_bit_reverse_in_place(
        const IntType& root_of_unity_value, const uint32_t cyclo_order_value, VecType* element) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        return;
    }

    if (!is_power_of_two(cyclo_order_value)) {
        CIPHER_THROW("CyclotomicOrder is not a power of two");
    }

    uint32_t cyclo_order_hf = (cyclo_order_value >> 1);
    if (element->get_length() != cyclo_order_hf) {
        CIPHER_THROW("element size must be equal to CyclotomicOrder / 2");
    }

    IntType modulus = element->get_modulus();

    auto map_search = root_of_unity_reverse_table_by_modulus_.find(modulus);
    if (map_search == root_of_unity_reverse_table_by_modulus_.end() ||
        map_search->second.get_length() != cyclo_order_hf) {
        pre_compute(root_of_unity_value, cyclo_order_value, modulus);
    }

    // if (typeid(IntType) == typeid(NativeInteger)) {
    //    NumberTheoreticTransformFxd<VecType>().forward_transform_to_bit_reverse_in_place(
    //           root_of_unity_reverse_table_by_modulus_[modulus],
    //           root_of_unity_precon_reverse_table_by_modulus_[modulus], element);
    // } else {
    NumberTheoreticTransformFxd<VecType>().forward_transform_to_bit_reverse_in_place(
            root_of_unity_reverse_table_by_modulus_[modulus], element);
    // }
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::forward_transform_to_bit_reverse(const VecType& element,
                                                                                const IntType& root_of_unity_value,
                                                                                const uint32_t cyclo_order_value,
                                                                                VecType* result) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        *result = element;
        return;
    }

    if (!is_power_of_two(cyclo_order_value)) {
        CIPHER_THROW("CyclotomicOrder is not a power of two");
    }

    uint32_t cyclo_order_hf = (cyclo_order_value >> 1);
    if (result->get_length() != cyclo_order_hf) {
        CIPHER_THROW("result size must be equal to CyclotomicOrder / 2");
    }

    IntType modulus = element.get_modulus();

    auto map_search = root_of_unity_reverse_table_by_modulus_.find(modulus);
    if (map_search == root_of_unity_reverse_table_by_modulus_.end() ||
        map_search->second.get_length() != cyclo_order_hf) {
        pre_compute(root_of_unity_value, cyclo_order_value, modulus);
    }

    // if (typeid(IntType) == typeid(NativeInteger)) {
    //   NumberTheoreticTransformFxd<VecType>().forward_transform_to_bit_reverse(
    //           element, root_of_unity_reverse_table_by_modulus_[modulus],
    //           root_of_unity_precon_reverse_table_by_modulus_[modulus], result);
    // } else {
    NumberTheoreticTransformFxd<VecType>().forward_transform_to_bit_reverse(
            element, root_of_unity_reverse_table_by_modulus_[modulus], result);
    // }

    return;
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::inverse_transform_from_bit_reverse_in_place(
        const IntType& root_of_unity_value, const uint32_t cyclo_order_value, VecType* element) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        return;
    }

    if (!is_power_of_two(cyclo_order_value)) {
        CIPHER_THROW("CyclotomicOrder is not a power of two");
    }

    uint32_t cyclo_order_hf = (cyclo_order_value >> 1);
    if (element->get_length() != cyclo_order_hf) {
        CIPHER_THROW("element size must be equal to CyclotomicOrder / 2");
    }

    IntType modulus = element->get_modulus();

    auto map_search = root_of_unity_reverse_table_by_modulus_.find(modulus);
    if (map_search == root_of_unity_reverse_table_by_modulus_.end() ||
        map_search->second.get_length() != cyclo_order_hf) {
        pre_compute(root_of_unity_value, cyclo_order_value, modulus);
    }

    uint32_t msb = get_msb64(cyclo_order_hf - 1);
    // if (typeid(IntType) == typeid(NativeInteger)) {
    //   NumberTheoreticTransformFxd<VecType>().inverse_transform_from_bit_reverse_in_place(
    //           root_of_unity_inverse_reverse_table_by_modulus_[modulus],
    //           root_of_unity_inverse_precon_reverse_table_by_modulus_[modulus],
    //           cyclo_order_inverse_table_by_modulus_[modulus][msb],
    //           cyclo_order_inverse_precon_table_by_modulus_[modulus][msb], element);
    // } else {
    NumberTheoreticTransformFxd<VecType>().inverse_transform_from_bit_reverse_in_place(
            root_of_unity_inverse_reverse_table_by_modulus_[modulus],
            cyclo_order_inverse_table_by_modulus_[modulus][msb], element);
    // }
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::inverse_transform_from_bit_reverse(const VecType& element,
                                                                                  const IntType& root_of_unity_value,
                                                                                  const uint32_t cyclo_order_value,
                                                                                  VecType* result) {
    if (root_of_unity_value == IntType(1) || root_of_unity_value == IntType(0)) {
        *result = element;
        return;
    }

    if (!cipher::is_power_of_two(cyclo_order_value)) {
        CIPHER_THROW("CyclotomicOrder is not a power of two");
    }

    uint32_t cyclo_order_hf = (cyclo_order_value >> 1);
    if (result->get_length() != cyclo_order_hf) {
        CIPHER_THROW("result size must be equal to CyclotomicOrder / 2");
    }

    IntType modulus = element.get_modulus();

    auto map_search = root_of_unity_reverse_table_by_modulus_.find(modulus);
    if (map_search == root_of_unity_reverse_table_by_modulus_.end() ||
        map_search->second.get_length() != cyclo_order_hf) {
        pre_compute(root_of_unity_value, cyclo_order_value, modulus);
    }

    uint32_t n = element.get_length();
    result->set_modulus(element.get_modulus());
    for (uint32_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }

    uint32_t msb = cipher::get_msb64(cyclo_order_hf - 1);
    // if (typeid(IntType) == typeid(NativeInteger)) {
    //   NumberTheoreticTransformFxd<VecType>().inverse_transform_from_bit_reverse_in_place(
    //           root_of_unity_inverse_reverse_table_by_modulus_[modulus],
    //           root_of_unity_inverse_precon_reverse_table_by_modulus_[modulus],
    //           cyclo_order_inverse_table_by_modulus_[modulus][msb],
    //           cyclo_order_inverse_precon_table_by_modulus_[modulus][msb], result);
    // } else {
    NumberTheoreticTransformFxd<VecType>().inverse_transform_from_bit_reverse_in_place(
            root_of_unity_inverse_reverse_table_by_modulus_[modulus],
            cyclo_order_inverse_table_by_modulus_[modulus][msb], result);
    // }

    return;
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::pre_compute(const IntType& root_of_unity_value,
                                                           const uint32_t cyclo_order_value, const IntType& modulus) {
    // Half of cyclo order
    uint32_t cyclo_order_hf = (cyclo_order_value >> 1);

    auto map_search = root_of_unity_reverse_table_by_modulus_.find(modulus);
    if (map_search == root_of_unity_reverse_table_by_modulus_.end() ||
        map_search->second.get_length() != cyclo_order_hf) {
#pragma omp critical
        {
            IntType x(1), xinv(1);
            uint32_t msb = cipher::get_msb64(cyclo_order_hf - 1);
            IntType mu = modulus.compute_mu();
            VecType table_value(cyclo_order_hf, modulus);
            VecType table_i(cyclo_order_hf, modulus);
            IntType root_of_unity_inverse = root_of_unity_value.mod_inverse(modulus);
            uint32_t iinv;
            for (uint32_t i = 0; i < cyclo_order_hf; i++) {
                iinv = cipher::reverse_bits(i, msb);
                table_value[iinv] = x;
                table_i[iinv] = xinv;
                x.mod_mul_eq(root_of_unity_value, modulus, mu);
                xinv.mod_mul_eq(root_of_unity_inverse, modulus, mu);
            }
            root_of_unity_reverse_table_by_modulus_[modulus] = table_value;
            root_of_unity_inverse_reverse_table_by_modulus_[modulus] = table_i;

            VecType table_coi(msb + 1, modulus);
            for (uint32_t i = 0; i < msb + 1; i++) {
                IntType co_inv(IntType(1 << i).mod_inverse(modulus));
                table_coi[i] = co_inv;
            }
            cyclo_order_inverse_table_by_modulus_[modulus] = table_coi;

            // if (typeid(IntType) == typeid(NativeInteger)) {
            //   NativeInteger nativeModulus = modulus.convert_to_int();
            //   VecType precon_table(cyclo_order_hf, nativeModulus);
            //   VecType precon_table_i(cyclo_order_hf, nativeModulus);

            //   for (uint32_t i = 0; i < cyclo_order_hf; i++) {
            //     precon_table[i] =
            //         NativeInteger(
            //             root_of_unity_reverse_table_by_modulus_[modulus][i].convert_to_int())
            //             .prep_mod_mul_const(nativeModulus);
            //     precon_table_i[i] =
            //         NativeInteger(
            //             root_of_unity_inverse_reverse_table_by_modulus_[modulus][i]
            //                 .convert_to_int())
            //             .prep_mod_mul_const(nativeModulus);
            //   }

            //   VecType precon_table_coi(msb + 1, nativeModulus);
            //   for (uint32_t i = 0; i < msb + 1; i++) {
            //     precon_table_coi[i] =
            //         NativeInteger(
            //             cyclo_order_inverse_table_by_modulus_[modulus][i].convert_to_int())
            //             .prep_mod_mul_const(nativeModulus);
            //   }

            //   root_of_unity_precon_reverse_table_by_modulus_[modulus] = precon_table;
            //   root_of_unity_inverse_precon_reverse_table_by_modulus_[modulus] = precon_table_i;
            //   cyclo_order_inverse_precon_table_by_modulus_[modulus] = precon_table_coi;
            // }
        }
    }
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::pre_compute(std::vector<IntType>& root_of_unity_value,
                                                           const uint32_t cyclo_order_value,
                                                           std::vector<IntType>& modulii_chain) {
    uint32_t num_of_root_u = root_of_unity_value.size();
    uint32_t num_modulii = modulii_chain.size();

    if (num_of_root_u != num_modulii) {
        CIPHER_THROW("size of root of unity and size of moduli chain not of same size");
    }

    for (uint32_t i = 0; i < num_of_root_u; ++i) {
        IntType current_root(root_of_unity_value[i]);
        IntType current_mod(modulii_chain[i]);
        pre_compute(current_root, cyclo_order_value, current_mod);
    }
}

template <typename VecType>
void ChineseRemainderTransformFttFxd<VecType>::reset() {
    cyclo_order_inverse_table_by_modulus_.clear();
    cyclo_order_inverse_precon_table_by_modulus_.clear();
    root_of_unity_reverse_table_by_modulus_.clear();
    root_of_unity_inverse_reverse_table_by_modulus_.clear();
    root_of_unity_precon_reverse_table_by_modulus_.clear();
    root_of_unity_inverse_precon_reverse_table_by_modulus_.clear();
}

template <typename VecType>
void BluesteinFftFxd<VecType>::pre_compute_default_ntt_modulus_root(uint32_t cyclo_order, const IntType& modulus) {
    uint32_t ntt_dim = std::pow(2, std::ceil(std::log2(2 * cyclo_order - 1)));
    const auto ntt_modulus = last_prime<IntType>(std::log2(ntt_dim) + 2 * modulus.get_msb(), ntt_dim);
    const auto ntt_root = root_of_unity(ntt_dim, ntt_modulus);
    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    default_ntt_modulus_root_[modulus] = ntt_modulus_root;

    pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
}

template <typename VecType>
void BluesteinFftFxd<VecType>::pre_compute_root_table_for_ntt(uint32_t cycloto_order,
                                                              const ModulusRoot<IntType>& ntt_modulus_root) {
    uint32_t ntt_dim = std::pow(2, std::ceil(std::log2(2 * cycloto_order - 1)));
    const auto& ntt_modulus = ntt_modulus_root.first;
    const auto& ntt_root = ntt_modulus_root.second;

    IntType root(ntt_root);

    auto root_inv = root.mod_inverse(ntt_modulus);

    uint32_t ntt_dim_hf = (ntt_dim >> 1);
    VecType root_table(ntt_dim_hf, ntt_modulus);
    VecType root_table_inverse(ntt_dim_hf, ntt_modulus);

    IntType x(1);
    for (uint32_t i = 0; i < ntt_dim_hf; i++) {
        root_table[i] = x;
        x = x.mod_mul(root, ntt_modulus);
    }

    x = 1;
    for (uint32_t i = 0; i < ntt_dim_hf; i++) {
        root_table_inverse[i] = x;
        x = x.mod_mul(root_inv, ntt_modulus);
    }

    root_of_unity_table_by_modulus_root_[ntt_modulus_root] = root_table;
    root_of_unity_inverse_table_by_modulus_root_[ntt_modulus_root] = root_table_inverse;
}

template <typename VecType>
void BluesteinFftFxd<VecType>::pre_compute_powers(uint32_t cyclo_order, const ModulusRoot<IntType>& modulus_root) {
    const auto& modulus = modulus_root.first;
    const auto& root = modulus_root.second;

    VecType powers(cyclo_order, modulus);
    powers[0] = 1;
    for (uint32_t i = 1; i < cyclo_order; i++) {
        auto i_sqr = (i * i) % (2 * cyclo_order);
        auto val = root.mod_exp(IntType(i_sqr), modulus);
        powers[i] = val;
    }
    powers_table_by_modulus_root_[modulus_root] = powers;
}

template <typename VecType>
void BluesteinFftFxd<VecType>::pre_compute_rb_table(uint32_t cyclo_order,
                                                    const ModulusRootPair<IntType>& modulus_root_pair) {
    const auto& modulus_root = modulus_root_pair.first;
    const auto& modulus = modulus_root.first;
    const auto& root = modulus_root.second;
    const auto root_inv = root.mod_inverse(modulus);

    const auto& ntt_modulus_root = modulus_root_pair.second;
    const auto& ntt_modulus = ntt_modulus_root.first;
    // const auto &ntt_root = ntt_modulus_root.second;
    // assumes root_table is precomputed
    const auto& root_table = root_of_unity_table_by_modulus_root_[ntt_modulus_root];
    uint32_t ntt_dim = std::pow(2, std::ceil(std::log2(2 * cyclo_order - 1)));

    VecType b(2 * cyclo_order - 1, modulus);
    b[cyclo_order - 1] = 1;
    for (uint32_t i = 1; i < cyclo_order; i++) {
        auto i_sqr = (i * i) % (2 * cyclo_order);
        auto val = root_inv.mod_exp(IntType(i_sqr), modulus);
        b[cyclo_order - 1 + i] = val;
        b[cyclo_order - 1 - i] = val;
    }

    auto rb = pad_zeros(b, ntt_dim);
    rb.set_modulus(ntt_modulus);

    VecType RB(ntt_dim);
    NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(rb, root_table, &RB);
    rb_table_by_modulus_root_pair_[modulus_root_pair] = RB;
}

template <typename VecType>
VecType BluesteinFftFxd<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                    const uint32_t cyclo_order) {
    const auto& modulus = element.get_modulus();
    const auto& ntt_modulus_root = default_ntt_modulus_root_[modulus];

    return forward_transform(element, root, cyclo_order, ntt_modulus_root);
}

template <typename VecType>
VecType BluesteinFftFxd<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                    const uint32_t cyclo_order,
                                                    const ModulusRoot<IntType>& ntt_modulus_root) {
    if (element.get_length() != cyclo_order) {
        CIPHER_THROW("expected size of element vector should be equal to cyclotomic order");
    }

    const auto& modulus = element.get_modulus();
    const ModulusRoot<IntType> modulus_root = {modulus, root};
    const VecType& powers = powers_table_by_modulus_root_[modulus_root];

    const auto& ntt_modulus = ntt_modulus_root.first;
    // assumes root_table is precomputed
    const auto& root_table = root_of_unity_table_by_modulus_root_[ntt_modulus_root];
    const auto& root_table_inverse = root_of_unity_inverse_table_by_modulus_root_
            [ntt_modulus_root];  // assumes root_table_inverse is precomputed
    VecType x = element.mod_mul(powers);

    uint32_t ntt_dim = std::pow(2, std::ceil(std::log2(2 * cyclo_order - 1)));
    auto ra = pad_zeros(x, ntt_dim);
    ra.set_modulus(ntt_modulus);
    VecType RA(ntt_dim);
    NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(ra, root_table, &RA);

    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root, ntt_modulus_root};
    const auto& RB = rb_table_by_modulus_root_pair_[modulus_root_pair];

    auto RC = RA.mod_mul(RB);
    VecType rc(ntt_dim);
    NumberTheoreticTransformFxd<VecType>().inverse_transform_iterative(RC, root_table_inverse, &rc);
    auto resize_rc = resize_range(rc, cyclo_order - 1, 2 * (cyclo_order - 1));
    resize_rc.set_modulus(modulus);
    resize_rc.mod_eq(modulus);
    auto result = resize_rc.mod_mul(powers);

    return result;
}

template <typename VecType>
VecType BluesteinFftFxd<VecType>::pad_zeros(const VecType& a, const uint32_t final_size) {
    uint32_t s = a.get_length();
    VecType result(final_size, a.get_modulus());

    for (uint32_t i = 0; i < s; i++) {
        result[i] = a[i];
    }

    for (uint32_t i = a.get_length(); i < final_size; i++) {
        result[i] = IntType(0);
    }

    return result;
}

template <typename VecType>
VecType BluesteinFftFxd<VecType>::resize_range(const VecType& a, uint32_t lo, uint32_t hi) {
    VecType result(hi - lo + 1, a.get_modulus());

    for (uint32_t i = lo, j = 0; i <= hi; i++, j++) {
        result[j] = a[i];
    }

    return result;
}

template <typename VecType>
void BluesteinFftFxd<VecType>::reset() {
    root_of_unity_table_by_modulus_root_.clear();
    root_of_unity_inverse_table_by_modulus_root_.clear();
    powers_table_by_modulus_root_.clear();
    rb_table_by_modulus_root_pair_.clear();
    default_ntt_modulus_root_.clear();
}

template <typename VecType>
void ChineseRemainderTransformArbFxd<VecType>::set_cylotomic_polynomial(const VecType& poly, const IntType& mod_value) {
    cyclotomic_poly_map_[mod_value] = poly;
}

template <typename VecType>
void ChineseRemainderTransformArbFxd<VecType>::pre_compute(const uint32_t cycloto_order, const IntType& modulus) {
    BluesteinFftFxd<VecType>().pre_compute_default_ntt_modulus_root(cycloto_order, modulus);
}

template <typename VecType>
void ChineseRemainderTransformArbFxd<VecType>::set_pre_computed_ntt_modulus(uint32_t cycloto_order,
                                                                            const IntType& modulus,
                                                                            const IntType& ntt_modulus,
                                                                            const IntType& ntt_root) {
    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    BluesteinFftFxd<VecType>().pre_compute_root_table_for_ntt(cycloto_order, ntt_modulus_root);
}

template <typename VecType>
void ChineseRemainderTransformArbFxd<VecType>::set_pre_computed_ntt_division_modulus(uint32_t cycloto_order,
                                                                                     const IntType& modulus,
                                                                                     const IntType& ntt_mod,
                                                                                     const IntType& ntt_root_big) {
    uint32_t n = get_totient(cycloto_order);
    uint32_t power = cycloto_order - n;
    ntt_division_dim_[cycloto_order] = 2 * std::pow(2, std::ceil(std::log2(power)));

    uint32_t ntt_dim_big = std::pow(2, std::ceil(std::log2(2 * cycloto_order - 1)));

    // Computes the root of unity for the division NTT based on the root of unity
    // for regular NTT
    IntType ntt_root = ntt_root_big.mod_exp(IntType(ntt_dim_big / ntt_division_dim_[cycloto_order]), ntt_mod);

    division_ntt_modulus_[modulus] = ntt_mod;
    division_ntt_root_of_unity_[modulus] = ntt_root;
    // part0 setting of root_table and inverse root_table
    uint32_t ntt_dim = ntt_division_dim_[cycloto_order];
    IntType root(ntt_root);
    auto root_inv = root.mod_inverse(ntt_mod);

    uint32_t ntt_dim_hf = (ntt_dim >> 1);
    VecType root_table(ntt_dim_hf, ntt_mod);
    VecType root_table_inverse(ntt_dim_hf, ntt_mod);

    IntType x(1);
    for (uint32_t i = 0; i < ntt_dim_hf; i++) {
        root_table[i] = x;
        x = x.mod_mul(root, ntt_mod);
    }

    x = 1;
    for (uint32_t i = 0; i < ntt_dim_hf; i++) {
        root_table_inverse[i] = x;
        x = x.mod_mul(root_inv, ntt_mod);
    }

    root_of_unity_division_table_by_modulus_[ntt_mod] = root_table;
    root_of_unity_division_inverse_table_by_modulus_[ntt_mod] = root_table_inverse;

    // end of part0
    // part1
    const auto& rev_cpm = inverse_poly_mod(cyclotomic_poly_map_[modulus], modulus, power);
    auto rev_cpm_padded = BluesteinFftFxd<VecType>().pad_zeros(rev_cpm, ntt_dim);
    rev_cpm_padded.set_modulus(ntt_mod);
    // end of part1

    VecType RA(ntt_dim);
    NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(rev_cpm_padded, root_table, &RA);
    cyclotomic_poly_reverse_ntt_map_[modulus] = RA;

    const auto& cyclo_poly = cyclotomic_poly_map_[modulus];

    VecType q_forward_transform(ntt_dim, ntt_mod);
    for (uint32_t i = 0; i < cyclo_poly.get_length(); i++) {
        q_forward_transform[i] = cyclo_poly[i];
    }

    VecType q_fwd_result(ntt_dim);
    NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(q_forward_transform, root_table, &q_fwd_result);

    cyclotomic_poly_ntt_map_[modulus] = q_fwd_result;
}

template <typename VecType>
VecType ChineseRemainderTransformArbFxd<VecType>::inverse_poly_mod(const VecType& cyclo_poly, const IntType& modulus,
                                                                   uint32_t power) {
    VecType result(power, modulus);
    uint32_t r = std::ceil(std::log2(power));
    VecType h(1, modulus);  // h is a unit polynomial
    h[0] = 1;

    // Precompute the Barrett mu parameter
    IntType mu = modulus.compute_mu();

    for (uint32_t i = 0; i < r; i++) {
        uint32_t q_degree = std::pow(2, i + 1);
        VecType q(q_degree + 1, modulus);  // q = x^(2^i+1)
        q[q_degree] = 1;
        auto h_square = polynomial_multiplication(h, h);

        auto a = h * IntType(2);
        auto b = polynomial_multiplication(h_square, cyclo_poly);
        // b = 2h - gh^2
        for (uint32_t j = 0; j < b.get_length(); j++) {
            if (j < a.get_length()) {
                b[j] = a[j].mod_sub(b[j], modulus, mu);
            } else {
                b[j] = modulus.mod_sub(b[j], modulus, mu);
            }
        }
        h = poly_mod(b, q, modulus);
    }
    // take modulo x^power
    for (uint32_t i = 0; i < power; i++) {
        result[i] = h[i];
    }

    return result;
}

template <typename VecType>
VecType ChineseRemainderTransformArbFxd<VecType>::forward_transform(const VecType& element, const IntType& root,
                                                                    const IntType& ntt_modulus, const IntType& ntt_root,
                                                                    const uint32_t cyclo_order) {
    uint32_t phim = get_totient(cyclo_order);
    if (element.get_length() != phim) {
        CIPHER_THROW("element size should be equal to phim");
    }

    const auto& modulus = element.get_modulus();
    const ModulusRoot<IntType> modulus_root = {modulus, root};

    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root, ntt_modulus_root};

#pragma omp critical
    {
        if (BluesteinFftFxd<VecType>::root_of_unity_table_by_modulus_root_[ntt_modulus_root].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
        }

        if (BluesteinFftFxd<VecType>::powers_table_by_modulus_root_[modulus_root].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_powers(cyclo_order, modulus_root);
        }

        if (BluesteinFftFxd<VecType>::rb_table_by_modulus_root_pair_[modulus_root_pair].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_rb_table(cyclo_order, modulus_root_pair);
        }
    }

    VecType input_to_bluestein = pad(element, cyclo_order, true);
    auto output_bluestein =
            BluesteinFftFxd<VecType>().forward_transform(input_to_bluestein, root, cyclo_order, ntt_modulus_root);

    VecType output = drop(output_bluestein, cyclo_order, true, ntt_modulus, ntt_root);

    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbFxd<VecType>::inverse_transform(const VecType& element, const IntType& root,
                                                                    const IntType& ntt_modulus, const IntType& ntt_root,
                                                                    const uint32_t cyclo_order) {
    uint32_t phim = get_totient(cyclo_order);
    if (element.get_length() != phim) {
        CIPHER_THROW("element size should be equal to phim");
    }

    const auto& modulus = element.get_modulus();
    auto root_inverse(root.mod_inverse(modulus));
    const ModulusRoot<IntType> modulus_root_inverse = {modulus, root_inverse};

    const ModulusRoot<IntType> ntt_modulus_root = {ntt_modulus, ntt_root};
    const ModulusRootPair<IntType> modulus_root_pair = {modulus_root_inverse, ntt_modulus_root};

#pragma omp critical
    {
        if (BluesteinFftFxd<VecType>::root_of_unity_table_by_modulus_root_[ntt_modulus_root].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_root_table_for_ntt(cyclo_order, ntt_modulus_root);
        }

        if (BluesteinFftFxd<VecType>::powers_table_by_modulus_root_[modulus_root_inverse].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_powers(cyclo_order, modulus_root_inverse);
        }

        if (BluesteinFftFxd<VecType>::rb_table_by_modulus_root_pair_[modulus_root_pair].get_length() == 0) {
            BluesteinFftFxd<VecType>().pre_compute_rb_table(cyclo_order, modulus_root_pair);
        }
    }
    VecType input_to_bluestein = pad(element, cyclo_order, false);
    auto output_bluestein = BluesteinFftFxd<VecType>().forward_transform(input_to_bluestein, root_inverse, cyclo_order,
                                                                         ntt_modulus_root);

    auto cyclotomic_inverse((IntType(cyclo_order)).mod_inverse(modulus));
    output_bluestein = output_bluestein * cyclotomic_inverse;
    VecType output = drop(output_bluestein, cyclo_order, false, ntt_modulus, ntt_root);
    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbFxd<VecType>::pad(const VecType& element, const uint32_t cyclo_order,
                                                      bool forward) {
    uint32_t n = get_totient(cyclo_order);

    const auto& modulus = element.get_modulus();
    VecType input_to_bluestein(cyclo_order, modulus);

    if (forward) {  // Forward transform padding
        for (uint32_t i = 0; i < n; i++) {
            input_to_bluestein[i] = element[i];
        }
    } else {  // Inverse transform padding
        auto t_list = get_totient_list(cyclo_order);
        uint32_t i = 0;
        for (auto& coprime : t_list) {
            input_to_bluestein[coprime] = element[i++];
        }
    }

    return input_to_bluestein;
}

template <typename VecType>
VecType ChineseRemainderTransformArbFxd<VecType>::drop(const VecType& element, const uint32_t cyclo_order, bool forward,
                                                       const IntType& big_mod, const IntType& big_root) {
    uint32_t n = get_totient(cyclo_order);

    const auto& modulus = element.get_modulus();
    VecType output(n, modulus);

    if (forward) {  // Forward transform drop
        auto t_list = get_totient_list(cyclo_order);
        for (uint32_t i = 0; i < n; i++) {
            output[i] = element[t_list[i]];
        }
    } else {  // Inverse transform drop
        if ((n + 1) == cyclo_order) {
            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter
            // cyclo_order is prime: Reduce mod Phi_{n+1}(x)
            // Reduction involves subtracting the coeff of x^n from all terms
            auto coeff_n = element[n];
            for (uint32_t i = 0; i < n; i++) {
                output[i] = element[i].mod_sub(coeff_n, modulus, mu);
            }
        } else if ((n + 1) * 2 == cyclo_order) {
            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter
            // cyclo_order is 2*prime: 2 Step reduction
            // First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
            // Subtract co-efficient of x^(i+n+1) from x^(i)
            for (uint32_t i = 0; i < n; i++) {
                auto coeff_i = element[i];
                auto coeff_ip = element[i + n + 1];
                output[i] = coeff_i.mod_sub(coeff_ip, modulus, mu);
            }
            auto coeff_n = element[n].mod_sub(element[2 * n + 1], modulus, mu);
            // Now reduce mod Phi_{2*(n+1)}(x)
            // Similar to the prime case but with alternating signs
            for (uint32_t i = 0; i < n; i++) {
                if (i % 2 == 0) {
                    output[i].mod_sub_eq(coeff_n, modulus, mu);
                } else {
                    output[i].mod_add_eq(coeff_n, modulus, mu);
                }
            }
        } else {
            // precompute root of unity tables for division NTT
            if ((root_of_unity_division_table_by_modulus_[big_mod].get_length() == 0) ||
                (division_ntt_modulus_[modulus] != big_mod)) {
                set_pre_computed_ntt_division_modulus(cyclo_order, modulus, big_mod, big_root);
            }

            // cyclo_order is arbitrary
            // auto output = poly_mod(element, this->cyclotomic_poly_map_[modulus],
            // modulus);

            const auto& ntt_mod = division_ntt_modulus_[modulus];
            const auto& root_table = root_of_unity_division_table_by_modulus_[ntt_mod];
            VecType a_padded2(ntt_division_dim_[cyclo_order], ntt_mod);
            // perform mod operation
            uint32_t power = cyclo_order - n;
            for (uint32_t i = n; i < element.get_length(); i++) {
                a_padded2[power - (i - n) - 1] = element[i];
            }
            VecType A(ntt_division_dim_[cyclo_order]);
            NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(a_padded2, root_table, &A);
            auto AB = A * cyclotomic_poly_reverse_ntt_map_[modulus];
            const auto& root_table_inverse = root_of_unity_division_inverse_table_by_modulus_[ntt_mod];
            VecType a(ntt_division_dim_[cyclo_order]);
            NumberTheoreticTransformFxd<VecType>().inverse_transform_iterative(AB, root_table_inverse, &a);

            VecType quotient(ntt_division_dim_[cyclo_order], modulus);
            for (uint32_t i = 0; i < power; i++) {
                quotient[i] = a[i];
            }
            quotient.mod_eq(modulus);
            quotient.set_modulus(ntt_mod);

            VecType new_quotient(ntt_division_dim_[cyclo_order]);
            NumberTheoreticTransformFxd<VecType>().forward_transform_iterative(quotient, root_table, &new_quotient);
            new_quotient *= cyclotomic_poly_ntt_map_[modulus];

            VecType new_quotient2(ntt_division_dim_[cyclo_order]);
            NumberTheoreticTransformFxd<VecType>().inverse_transform_iterative(new_quotient, root_table_inverse,
                                                                               &new_quotient2);
            new_quotient2.set_modulus(modulus);
            new_quotient2.mod_eq(modulus);

            IntType mu = modulus.compute_mu();  // Precompute the Barrett mu parameter

            for (uint32_t i = 0; i < n; i++) {
                output[i] = element[i].mod_sub(new_quotient2[cyclo_order - 1 - i], modulus, mu);
            }
        }
    }
    return output;
}

template <typename VecType>
void ChineseRemainderTransformArbFxd<VecType>::reset() {
    cyclotomic_poly_map_.clear();
    cyclotomic_poly_reverse_ntt_map_.clear();
    cyclotomic_poly_ntt_map_.clear();
    root_of_unity_division_table_by_modulus_.clear();
    root_of_unity_division_inverse_table_by_modulus_.clear();
    division_ntt_modulus_.clear();
    division_ntt_root_of_unity_.clear();
    ntt_division_dim_.clear();
    BluesteinFftFxd<VecType>().reset();
}

}  // namespace fixed_int

#endif  // CIPHER_MATH_BACKEND_FIXED_TRANSFORM_IMPL_H_
