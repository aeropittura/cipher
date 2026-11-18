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

/*
  This file contains template instantiations for all math classes & functions using math be2
 */

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE2

    #include "cipher/math/binary_uniform_gen_impl.h"
    #include "cipher/math/discrete_gaussian_gen_impl.h"
    #include "cipher/math/discrete_uniform_gen_impl.h"
    #include "cipher/math/backend/fixed/transform_impl.h"
    #include "cipher/math/backend.h"
    #include "cipher/math/matrix_impl.h"
    #include "cipher/math/number_theory_impl.h"
    #include "cipher/math/ternary_uniform_gen_impl.h"

template class fixed_int::NumberTheoreticTransformFxd<fixed_int::BigVector>;
template class fixed_int::ChineseRemainderTransformFttFxd<fixed_int::BigVector>;
template class fixed_int::BluesteinFftFxd<fixed_int::BigVector>;
template class fixed_int::ChineseRemainderTransformArbFxd<fixed_int::BigVector>;

namespace cipher {

template class DiscreteGaussianGeneratorImpl<M2Vector>;
template class BinaryUniformGeneratorImpl<M2Vector>;
template class TernaryUniformGeneratorImpl<M2Vector>;
template class DiscreteUniformGeneratorImpl<M2Vector>;

template M2Integer root_of_unity<M2Integer>(uint32_t m, const M2Integer& modulo);
template std::vector<M2Integer> roots_of_unity(uint32_t m, const std::vector<M2Integer>& moduli);
template M2Integer greatest_common_divisor(const M2Integer& a, const M2Integer& b);
template bool miller_rabin_primality_test(const M2Integer& p, const uint32_t niter);
template const M2Integer pollard_rho_factorization(const M2Integer& n);
template void prime_factorize(M2Integer n, std::set<M2Integer>& prime_factors);
template M2Integer first_prime(uint32_t n_bits, uint64_t m);
template M2Integer last_prime(uint32_t n_bits, uint64_t m);
template M2Integer next_prime(const M2Integer& q, uint64_t m);
template M2Integer previous_prime(const M2Integer& q, uint64_t m);
template std::vector<M2Integer> get_totient_list(const M2Integer& n);
template M2Vector poly_mod(const M2Vector& dividend, const M2Vector& divisor, const M2Integer& modulus);
template M2Vector polynomial_multiplication(const M2Vector& a, const M2Vector& b);
template M2Vector get_cyclotomic_polynomial(uint32_t m, const M2Integer& modulus);
template M2Integer synthetic_remainder(const M2Vector& dividend, const M2Integer& a, const M2Integer& modulus);
template M2Vector synthetic_poly_remainder(const M2Vector& dividend, const M2Vector& a_list, const M2Integer& modulus);
template M2Vector polynomial_power<M2Vector>(const M2Vector& input, uint32_t power);
template M2Vector synthetic_polynomial_division(const M2Vector& dividend, const M2Integer& a, const M2Integer& modulus);
template M2Integer find_generator_cyclic(const M2Integer& modulo);
template bool is_generator(const M2Integer& g, const M2Integer& modulo);
template std::shared_ptr<std::vector<int64_t>> get_digits(const M2Integer& u, uint64_t base, uint32_t k);

template class Matrix<M2Integer>;
template class Matrix<M2Vector>;

}  // namespace cipher

CEREAL_CLASS_VERSION(M2Integer, M2Integer::serialized_version());
CEREAL_CLASS_VERSION(M2Vector, M2Vector::serialized_version());

#endif
