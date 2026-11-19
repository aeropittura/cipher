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
  This file contains the discrete fourier transform implementation.
 */

#include "cipher/math/dft.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cipher/math/number_theory.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/parallel.h"

namespace cipher {

std::complex<double>* DiscreteFourierTransform::root_of_unity_table = nullptr;
std::unordered_map<uint32_t, DiscreteFourierTransform::PrecomputedValues> DiscreteFourierTransform::precomputed_values;

DiscreteFourierTransform::PrecomputedValues::PrecomputedValues(uint32_t m, uint32_t nh) {
    M_ = m;
    nh_ = nh;

    rot_group_.resize(nh_);
    uint32_t five_pows = 1;
    for (size_t i = 0; i < nh_; ++i) {
        rot_group_[i] = five_pows;
        five_pows *= 5;
        five_pows %= M_;
    }

    ksi_pows_.resize(M_ + 1);
    for (size_t j = 0; j < M_; ++j) {
        double angle = 2.0 * M_PI * j / M_;
        ksi_pows_[j].real(cos(angle));
        ksi_pows_[j].imag(sin(angle));
    }

    ksi_pows_[M_] = ksi_pows_[0];

    fwd_tw_.resize(nh_ > 0 ? nh_ - 1 : 0);
    inv_tw_.resize(fwd_tw_.size());
    for (uint32_t lenh = 1; lenh <= nh_ / 2; lenh <<= 1) {
        uint32_t lenq = lenh << 3;
        uint32_t gap = M_ / lenq;
        auto* fwd = &fwd_tw_[lenh - 1];
        auto* inv = &inv_tw_[lenh - 1];
        for (uint32_t j = 0; j < lenh; ++j) {
            uint32_t rg = rot_group_[j] % lenq;
            fwd[j] = ksi_pows_[rg * gap];
            inv[j] = ksi_pows_[(lenq - rg) * gap];
        }
    }
}

std::shared_mutex& DiscreteFourierTransform::precomp_mutex() {
    static std::shared_mutex mtx;
    return mtx;
}

const DiscreteFourierTransform::PrecomputedValues& DiscreteFourierTransform::get_precomp(uint32_t cycl_order) {
    std::shared_lock<std::shared_mutex> lock(precomp_mutex());
    const auto it = precomputed_values.find(cycl_order);
    if (it == precomputed_values.end()) {
        std::string err_msg("DiscreteFourierTransform::initialize() must be called for cycl_order = ");
        err_msg += std::to_string(cycl_order);
        CIPHER_THROW(err_msg);
    }
    return it->second;
}

void DiscreteFourierTransform::reset() {
    if (root_of_unity_table) {
        delete[] root_of_unity_table;
        root_of_unity_table = nullptr;
    }
}

void DiscreteFourierTransform::initialize(uint32_t m, uint32_t nh) {
    // add a PrecomputedValues object to the map of precomputed_values only if it doesn't already exist for the given cyclotomic order
    std::unique_lock<std::shared_mutex> lock(precomp_mutex());
    precomputed_values.try_emplace(m, m, nh);
}

void DiscreteFourierTransform::pre_compute_table(uint32_t s) {
    reset();

    root_of_unity_table = new std::complex<double>[s];
    for (size_t j = 0; j < s; j++) {
        root_of_unity_table[j] = std::polar(1.0, -2 * M_PI * j / s);
    }
}

std::vector<std::complex<double>> DiscreteFourierTransform::fft_forward_transform(
        std::vector<std::complex<double>>& A) {
    uint32_t m = A.size();
    std::vector<std::complex<double>> B(A);
    uint32_t l = std::floor(std::log2(m));

    // static uint32_t max_m_cached(262144);
    static uint32_t LOGM_MAX(18);  // maximum supported is 2^18 = 262144
    static std::vector<uint32_t> cached_m(LOGM_MAX + 1, 0);
    static std::vector<std::vector<double>> cos_table(LOGM_MAX + 1);
    static std::vector<std::vector<double>> sin_table(LOGM_MAX + 1);

#pragma omp critical
    {
        if (m != cached_m[l]) {
            cached_m[l] = m;
            sin_table[l].resize(m / 2);
            cos_table[l].resize(m / 2);
            for (uint32_t i = 0; i < m / 2; i++) {
                cos_table[l][i] = cos(2 * M_PI * i / m);
                sin_table[l][i] = sin(2 * M_PI * i / m);
            }
        }
    }

    // Bit-reversed addressing permutation
    for (uint32_t i = 0; i < m; i++) {
        uint32_t j = reverse_bits(i, 32) >> (32 - l);
        if (j > i) {
            double temp = B[i].real();
            B[i].real(B[j].real());
            B[j].real(temp);
            temp = B[i].imag();
            B[i].imag(B[j].imag());
            B[j].imag(temp);
        }
    }

    // Cooley-Tukey decimation-in-time radix-2 FFT
    for (uint32_t size = 2; size <= m; size *= 2) {
        uint32_t halfsize = size / 2;
        uint32_t tablestep = m / size;
        for (uint32_t i = 0; i < m; i += size) {
            for (uint32_t j = i, k = 0; j < i + halfsize; j++, k += tablestep) {
                double tpre = B[j + halfsize].real() * cos_table[l][k] + B[j + halfsize].imag() * sin_table[l][k];
                double tpim = -B[j + halfsize].real() * sin_table[l][k] + B[j + halfsize].imag() * cos_table[l][k];
                B[j + halfsize].real(B[j].real() - tpre);
                B[j + halfsize].imag(B[j].imag() - tpim);
                B[j].real(B[j].real() + tpre);
                B[j].imag(B[j].imag() + tpim);
            }
        }
        if (size == m)  // Prevent overflow in 'size *= 2'
            break;
    }

    return B;
}

std::vector<std::complex<double>> DiscreteFourierTransform::fft_inverse_transform(
        std::vector<std::complex<double>>& A) {
    std::vector<std::complex<double>> result = DiscreteFourierTransform::fft_forward_transform(A);
    double n = result.size() / 2;
    for (int i = 0; i < n; i++) {
        result[i] = std::complex<double>(result[i].real() / n, result[i].imag() / n);
    }
    return result;
}

std::vector<std::complex<double>> DiscreteFourierTransform::forward_transform(std::vector<std::complex<double>> A) {
    int n = A.size();
    A.resize(2 * n);
    for (int i = 0; i < n; i++) {
        A[n + i] = 0;
    }
    // if (root_of_unity_table == nullptr) {
    //   pre_compute_table(2 * n);
    // }
    std::vector<std::complex<double>> dft = fft_forward_transform(A);
    std::vector<std::complex<double>> dft_remainder(dft.size() / 2);
    size_t k = 0;
    for (int i = dft.size() - 1; i > 0; i--) {
        if (i % 2 != 0) {
            dft_remainder[k] = dft[i];
            k++;
            // dft_remainder.push_back(dft[i]);
        }
    }
    return dft_remainder;
}

std::vector<std::complex<double>> DiscreteFourierTransform::inverse_transform(std::vector<std::complex<double>> A) {
    size_t n = A.size();
    std::vector<std::complex<double>> dft(2 * n);
    for (size_t i = 0; i < n; i++) {
        dft[2 * i] = 0;
        dft[2 * i + 1] = A[i];
    }
    std::vector<std::complex<double>> inv_dft = fft_inverse_transform(dft);
    std::vector<std::complex<double>> inv_dft_remainder(inv_dft.size() / 2);
    for (size_t i = 0; i < inv_dft.size() / 2; i++) {
        inv_dft_remainder[i] = inv_dft[i];
    }
    return inv_dft_remainder;
}

void DiscreteFourierTransform::fft_special_inv(std::vector<std::complex<double>>& vals, uint32_t cycl_order) {
    const PrecomputedValues& pv = get_precomp(cycl_order);

    const size_t vals_size = vals.size();
    for (size_t len = vals_size; len >= 2; len >>= 1) {
        const size_t lenh = len >> 1;
        const auto* tw = &pv.inv_tw_[lenh - 1];
        for (size_t i = 0; i < vals_size; i += len) {
            auto* lo = &vals[i];
            auto* hi = lo + lenh;
            for (size_t j = 0; j < lenh; ++j) {
                const double ur = lo[j].real() + hi[j].real();
                const double ui = lo[j].imag() + hi[j].imag();
                const double vr = lo[j].real() - hi[j].real();
                const double vi = lo[j].imag() - hi[j].imag();
                const double wr = tw[j].real();
                const double wi = tw[j].imag();
                lo[j] = {ur, ui};
                hi[j] = {vr * wr - vi * wi, vr * wi + vi * wr};
            }
        }
    }
    bit_reverse_permute(vals);

    const double inv = 1.0 / static_cast<double>(vals_size);
    for (size_t i = 0; i < vals_size; ++i) {
        vals[i] *= inv;
    }
}

void DiscreteFourierTransform::fft_special(std::vector<std::complex<double>>& vals, uint32_t cycl_order) {
    const PrecomputedValues& pv = get_precomp(cycl_order);

    bit_reverse_permute(vals);
    const size_t vals_size = vals.size();
    for (size_t len = 2; len <= vals_size; len <<= 1) {
        const size_t lenh = len >> 1;
        const auto* tw = &pv.fwd_tw_[lenh - 1];
        for (size_t i = 0; i < vals_size; i += len) {
            auto* lo = &vals[i];
            auto* hi = lo + lenh;
            for (size_t j = 0; j < lenh; ++j) {
                const double wr = tw[j].real();
                const double wi = tw[j].imag();
                const double vr = hi[j].real() * wr - hi[j].imag() * wi;
                const double vi = hi[j].real() * wi + hi[j].imag() * wr;
                const double ur = lo[j].real();
                const double ui = lo[j].imag();
                lo[j] = {ur + vr, ui + vi};
                hi[j] = {ur - vr, ui - vi};
            }
        }
    }
}

void DiscreteFourierTransform::bit_reverse_permute(std::vector<std::complex<double>>& vals) {
    uint32_t size = vals.size();
    for (size_t i = 1, j = 0; i < size; ++i) {
        size_t bit = size >> 1;
        for (; j >= bit; bit >>= 1) {
            j -= bit;
        }
        j += bit;
        if (i < j) {
            swap(vals[i], vals[j]);
        }
    }
}

}  // namespace cipher
