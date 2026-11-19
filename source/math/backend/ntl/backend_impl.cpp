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
  This file contains template instantiations for all math classes & functions using math be6
 */

//==================================================================================
// This file is included only if CIPHER_WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "cipher/config.h"
#ifdef CIPHER_WITH_NTL

    #include "cipher/math/binary_uniform_gen_impl.h"
    #include "cipher/math/discrete_gaussian_gen_impl.h"
    #include "cipher/math/discrete_uniform_gen_impl.h"
    #include "cipher/math/backend/ntl/transform_impl.h"
    #include "cipher/math/backend.h"
    #include "cipher/math/matrix_impl.h"
    #include "cipher/math/number_theory_impl.h"
    #include "cipher/math/ternary_uniform_gen_impl.h"

template class NTL::NumberTheoreticTransformNtl<NTL::BigVector>;
template class NTL::ChineseRemainderTransformFttNtl<NTL::BigVector>;
template class NTL::BluesteinFftNtl<NTL::BigVector>;
template class NTL::ChineseRemainderTransformArbNtl<NTL::BigVector>;

namespace cipher {

template class DiscreteGaussianGeneratorImpl<M6Vector>;
template class BinaryUniformGeneratorImpl<M6Vector>;
template class TernaryUniformGeneratorImpl<M6Vector>;
template class DiscreteUniformGeneratorImpl<M6Vector>;

template M6Integer root_of_unity<M6Integer>(uint32_t m, const M6Integer& modulo);
template std::vector<M6Integer> roots_of_unity(uint32_t m, const std::vector<M6Integer>& moduli);
template M6Integer greatest_common_divisor(const M6Integer& a, const M6Integer& b);
template bool miller_rabin_primality_test(const M6Integer& p, const uint32_t niter);
template const M6Integer pollard_rho_factorization(const M6Integer& n);
template void prime_factorize(M6Integer n, std::set<M6Integer>& prime_factors);
template M6Integer first_prime(uint32_t n_bits, uint64_t m);
template M6Integer last_prime(uint32_t n_bits, uint64_t m);
template M6Integer next_prime(const M6Integer& q, uint64_t m);
template M6Integer previous_prime(const M6Integer& q, uint64_t m);
template std::vector<M6Integer> get_totient_list(const M6Integer& n);
template M6Vector poly_mod(const M6Vector& dividend, const M6Vector& divisor, const M6Integer& modulus);
template M6Vector polynomial_multiplication(const M6Vector& a, const M6Vector& b);
template M6Vector get_cyclotomic_polynomial(uint32_t m, const M6Integer& modulus);
template M6Integer synthetic_remainder(const M6Vector& dividend, const M6Integer& a, const M6Integer& modulus);
template M6Vector synthetic_poly_remainder(const M6Vector& dividend, const M6Vector& a_list, const M6Integer& modulus);
template M6Vector polynomial_power<M6Vector>(const M6Vector& input, uint32_t power);
template M6Vector synthetic_polynomial_division(const M6Vector& dividend, const M6Integer& a, const M6Integer& modulus);
template M6Integer find_generator_cyclic(const M6Integer& modulo);
template bool is_generator(const M6Integer& g, const M6Integer& modulo);
template std::shared_ptr<std::vector<int64_t>> get_digits(const M6Integer& u, uint64_t base, uint32_t k);

template class Matrix<M6Integer>;
template class Matrix<M6Vector>;

}  // namespace cipher

CEREAL_CLASS_VERSION(M6Integer, M6Integer::serialized_version());
CEREAL_CLASS_VERSION(M6Vector, M6Vector::serialized_version());

#endif  // CIPHER_WITH_NTL
