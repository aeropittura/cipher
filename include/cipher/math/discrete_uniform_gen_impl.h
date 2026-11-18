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
  This code provides generation of uniform distributions of discrete values. Discrete uniform generator relies on
  the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef CIPHER_MATH_DISCRETE_UNIFORM_GEN_IMPL_H_
#define CIPHER_MATH_DISCRETE_UNIFORM_GEN_IMPL_H_

#include <cstdint>
#include <random>

#include "cipher/math/discrete_uniform_gen.h"
#include "cipher/math/distribution_gen.h"
#include "cipher/util/exception.h"

namespace cipher {

template <typename VecType>
DiscreteUniformGeneratorImpl<VecType>::DiscreteUniformGeneratorImpl(const typename VecType::Integer& modulus) {
    set_modulus(modulus);
}

template <typename VecType>
void DiscreteUniformGeneratorImpl<VecType>::set_modulus(const typename VecType::Integer& modulus) {
    modulus_ = modulus;
    if (modulus_ == typename VecType::Integer(0)) {
        chunks_ = 0;  // generate_integer/generate_vector throw on a zero modulus before sampling
        return;
    }
    chunks_ = (modulus_.get_msb() + DUG_CHUNK_WIDTH - 1) / DUG_CHUNK_WIDTH;

    // all-ones over the draw domain;
    typename VecType::Integer dmax{DUG_CHUNK_MAX};
    for (uint32_t i{1}; i < chunks_; ++i)
        dmax = (dmax << DUG_CHUNK_WIDTH) + typename VecType::Integer{DUG_CHUNK_MAX};
    limit_ = (dmax / modulus_) * modulus_;
}

template <typename VecType>
typename VecType::Integer DiscreteUniformGeneratorImpl<VecType>::generate_integer_with(
        PRNG& prng, std::uniform_int_distribution<uint32_t>& dist) const {
    // Draw ceil(MSB/32) raw 32-bit words, reject draws at or above the largest contained
    // multiple of the modulus, and reduce: every residue then appears exactly
    // floor(2^(32c)/q) times, so the result is exactly uniform. The rejection probability
    // (2^(32c) mod q) / 2^(32c) is at most a few percent and a retry is just another cheap
    // draw; raw full-range words avoid the per-sample division a bounded top-chunk draw
    // pays inside std::uniform_int_distribution.
    while (true) {
        typename VecType::Integer x{};
        for (uint32_t i{0}, shift{0}; i < chunks_; ++i, shift += DUG_CHUNK_WIDTH)
            x += typename VecType::Integer{dist(prng)} << shift;
        if (x < limit_)
            return x.mod_eq(modulus_);
    }
}

template <typename VecType>
typename VecType::Integer DiscreteUniformGeneratorImpl<VecType>::generate_integer() const {
    if (modulus_ == typename VecType::Integer(0))
        CIPHER_THROW("0 modulus?");
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
    return generate_integer_with(PseudoRandomNumberGenerator::get_prng(), dist);
}

template <typename VecType>
VecType DiscreteUniformGeneratorImpl<VecType>::generate_vector(const uint32_t size) const {
    if (modulus_ == typename VecType::Integer(0))
        CIPHER_THROW("0 modulus?");
    VecType v(size, modulus_);
    auto& prng = PseudoRandomNumberGenerator::get_prng();
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
    for (uint32_t i = 0; i < size; ++i)
        v[i] = generate_integer_with(prng, dist);
    return v;
}

template <typename VecType>
VecType DiscreteUniformGeneratorImpl<VecType>::generate_vector(const uint32_t size,
                                                               const typename VecType::Integer& modulus) {
    set_modulus(modulus);
    return generate_vector(size);
}

}  // namespace cipher

#endif  // CIPHER_MATH_DISCRETE_UNIFORM_GEN_IMPL_H_
