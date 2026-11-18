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
  This file contains template instantiations for all math classes & functions using math be4
 */

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include "cipher/math/binary_uniform_gen_impl.h"
    #include "cipher/math/discrete_gaussian_gen_impl.h"
    #include "cipher/math/discrete_uniform_gen_impl.h"
    #include "cipher/math/backend/dynamic/transform_impl.h"
    #include "cipher/math/backend.h"
    #include "cipher/math/matrix_impl.h"
    #include "cipher/math/number_theory_impl.h"
    #include "cipher/math/ternary_uniform_gen_impl.h"

template class dynamic_int::NumberTheoreticTransformDyn<dynamic_int::BigVector>;
template class dynamic_int::ChineseRemainderTransformFttDyn<dynamic_int::BigVector>;
template class dynamic_int::BluesteinFftDyn<dynamic_int::BigVector>;
template class dynamic_int::ChineseRemainderTransformArbDyn<dynamic_int::BigVector>;

namespace cipher {

template class DiscreteGaussianGeneratorImpl<M4Vector>;
template class BinaryUniformGeneratorImpl<M4Vector>;
template class TernaryUniformGeneratorImpl<M4Vector>;
template class DiscreteUniformGeneratorImpl<M4Vector>;

template M4Integer root_of_unity<M4Integer>(uint32_t m, const M4Integer& modulo);
template std::vector<M4Integer> roots_of_unity(uint32_t m, const std::vector<M4Integer>& moduli);
template M4Integer greatest_common_divisor(const M4Integer& a, const M4Integer& b);
template bool miller_rabin_primality_test(const M4Integer& p, const uint32_t niter);
template const M4Integer pollard_rho_factorization(const M4Integer& n);
template void prime_factorize(M4Integer n, std::set<M4Integer>& prime_factors);
template M4Integer first_prime(uint32_t n_bits, uint64_t m);
template M4Integer last_prime(uint32_t n_bits, uint64_t m);
template M4Integer next_prime(const M4Integer& q, uint64_t m);
template M4Integer previous_prime(const M4Integer& q, uint64_t m);
template std::vector<M4Integer> get_totient_list(const M4Integer& n);
template M4Vector poly_mod(const M4Vector& dividend, const M4Vector& divisor, const M4Integer& modulus);
template M4Vector polynomial_multiplication(const M4Vector& a, const M4Vector& b);
template M4Vector get_cyclotomic_polynomial(uint32_t m, const M4Integer& modulus);
template M4Integer synthetic_remainder(const M4Vector& dividend, const M4Integer& a, const M4Integer& modulus);
template M4Vector synthetic_poly_remainder(const M4Vector& dividend, const M4Vector& a_list, const M4Integer& modulus);
template M4Vector polynomial_power<M4Vector>(const M4Vector& input, uint32_t power);
template M4Vector synthetic_polynomial_division(const M4Vector& dividend, const M4Integer& a, const M4Integer& modulus);
template M4Integer find_generator_cyclic(const M4Integer& modulo);
template bool is_generator(const M4Integer& g, const M4Integer& modulo);
template std::shared_ptr<std::vector<int64_t>> get_digits(const M4Integer& u, uint64_t base, uint32_t k);

template class Matrix<M4Integer>;
template class Matrix<M4Vector>;

}  // namespace cipher

CEREAL_CLASS_VERSION(M4Integer, M4Integer::serialized_version());
CEREAL_CLASS_VERSION(M4Vector, M4Vector::serialized_version());

#endif
