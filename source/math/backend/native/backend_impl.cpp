//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  This file contains template instantiations for all math classes & functions using math native
 */

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "cipher/math/binary_uniform_gen_impl.h"
#include "cipher/math/discrete_gaussian_gen_impl.h"
#include "cipher/math/discrete_uniform_gen_impl.h"
#include "cipher/math/backend/transform.h"
#include "cipher/math/backend.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/math/number_theory_impl.h"
#include "cipher/math/ternary_uniform_gen_impl.h"

#ifdef TRANSFORM_IMPLEMENTATION
    #include TRANSFORM_IMPLEMENTATION
#endif

namespace cipher {

template class DiscreteGaussianGeneratorImpl<NativeVector>;
template class BinaryUniformGeneratorImpl<NativeVector>;
template class TernaryUniformGeneratorImpl<NativeVector>;
template class DiscreteUniformGeneratorImpl<NativeVector>;

#if CIPHER_NATIVE_INT != 32
// samplers at the 32-bit width, for the native 32-bit BinFHE key generation
template class DiscreteGaussianGeneratorImpl<NativeVector32>;
template class DiscreteUniformGeneratorImpl<NativeVector32>;
#endif

template NativeInteger root_of_unity<NativeInteger>(uint32_t m, const NativeInteger& modulo);
template std::vector<NativeInteger> roots_of_unity(uint32_t m, const std::vector<NativeInteger>& moduli);
template NativeInteger greatest_common_divisor(const NativeInteger& a, const NativeInteger& b);
template bool miller_rabin_primality_test(const NativeInteger& p, const uint32_t niter);
template const NativeInteger pollard_rho_factorization(const NativeInteger& n);
template void prime_factorize(NativeInteger n, std::set<NativeInteger>& prime_factors);
template NativeInteger first_prime(uint32_t n_bits, uint64_t m);
template NativeInteger last_prime(uint32_t n_bits, uint64_t m);
template NativeInteger next_prime(const NativeInteger& q, uint64_t m);
template NativeInteger previous_prime(const NativeInteger& q, uint64_t m);

template std::vector<NativeInteger> get_totient_list(const NativeInteger& n);
template std::vector<uint32_t> get_totient_list(const uint32_t& n);

template NativeVector poly_mod(const NativeVector& dividend, const NativeVector& divisor, const NativeInteger& modulus);
template NativeVector polynomial_multiplication(const NativeVector& a, const NativeVector& b);
template NativeVector get_cyclotomic_polynomial(uint32_t m, const NativeInteger& modulus);
template NativeInteger synthetic_remainder(const NativeVector& dividend, const NativeInteger& a,
                                           const NativeInteger& modulus);
template NativeVector synthetic_poly_remainder(const NativeVector& dividend, const NativeVector& a_list,
                                               const NativeInteger& modulus);
template NativeVector polynomial_power<NativeVector>(const NativeVector& input, uint32_t power);
template NativeVector synthetic_polynomial_division(const NativeVector& dividend, const NativeInteger& a,
                                                    const NativeInteger& modulus);
template NativeInteger find_generator_cyclic(const NativeInteger& modulo);
template bool is_generator(const NativeInteger& g, const NativeInteger& modulo);
template std::shared_ptr<std::vector<int64_t>> get_digits(const NativeInteger& u, uint64_t base, uint32_t k);

template class Matrix<NativeInteger>;
template class Matrix<NativeVector>;

}  // namespace cipher

CEREAL_CLASS_VERSION(NativeInteger, NativeInteger::serialized_version());
CEREAL_CLASS_VERSION(NativeVector, NativeVector::serialized_version());

#ifdef TRANSFORM_IMPLEMENTATION
MAKE_TRANSFORM_TYPES
    #if CIPHER_NATIVE_INT != 32
MAKE_TRANSFORM_TYPES32
    #endif
#endif
