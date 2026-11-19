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
#define _USE_MATH_DEFINES
#include <complex>
#include <cstdint>
#include <random>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/math/dft.h"
#include "cipher/math/distribution_gen.h"

using namespace cipher;

/**
 * generate_rand_number_vector generates a vector of real values in the range (-1,1)
 * @param vec_size is number of elements in the returned vector
 * @return generated vector
 */
std::vector<std::complex<double>> generate_rand_number_vector(size_t vec_size) {
    std::vector<std::complex<double>> result(vec_size);

    std::uniform_real_distribution<double> uniform_real(-1.0, 1.0);
    for (size_t i = 0; i < vec_size; ++i) {
        result[i] = std::complex<double>(uniform_real(PseudoRandomNumberGenerator::get_prng()), 0);
    }

    return result;
}

//=====================================================================================================================
void fft_special_ring_dim4096(benchmark::State& state) {
    const uint32_t ring_dim = 4096;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_ring_dim4096)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void fft_special_inv_ring_dim4096(benchmark::State& state) {
    const uint32_t ring_dim = 4096;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special_inv(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_inv_ring_dim4096)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void fft_special_ring_dim16384(benchmark::State& state) {
    const uint32_t ring_dim = 16384;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_ring_dim16384)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void fft_special_inv_ring_dim16384(benchmark::State& state) {
    const uint32_t ring_dim = 16384;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special_inv(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_inv_ring_dim16384)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void fft_special_ring_dim65536(benchmark::State& state) {
    const uint32_t ring_dim = 65536;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_ring_dim65536)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void fft_special_inv_ring_dim65536(benchmark::State& state) {
    const uint32_t ring_dim = 65536;
    std::vector<std::complex<double>> vals = generate_rand_number_vector(ring_dim / 4);
    DiscreteFourierTransform::initialize(ring_dim * 2, ring_dim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::fft_special_inv(vals, ring_dim * 2);
    }
}
BENCHMARK(fft_special_inv_ring_dim65536)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================

BENCHMARK_MAIN();
