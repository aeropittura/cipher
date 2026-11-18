//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
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

#ifndef CIPHER_MATH_MATRIX_UTILS_H_
#define CIPHER_MATH_MATRIX_UTILS_H_

#include <cstdint>
#include <limits>
#include <string>

#include "cipher/math/backend.h"
#include "cipher/util/exception.h"

namespace cipher {

/**
 * @brief Converts elements of Z_q to their centered representatives in (-q/2, q/2] as int32_t.
 *
 * The modulus-dependent bounds are computed once, at construction; convert() then performs at
 * most two comparisons and one subtraction per element and throws if the centered representative
 * does not fit in an int32_t. Every representative fits if q <= 2^32 - 1. For an even q the
 * class q/2 has the two representatives -q/2 and q/2; the representable one is returned.
 */
template <typename IntType>
class CenteredToInt32ConverterImpl {
  public:
    /**
     * Precomputes the bounds of the representable centered values for a modulus.
     *
     * @param modulus the ring modulus q
     */
    explicit CenteredToInt32ConverterImpl(const IntType& modulus)
        : modulus_(modulus), native_(modulus.get_msb() <= 64) {
        const IntType int32_max(int32_max_value);
        const IntType negative_threshold(modulus / IntType(2));

        // the largest value mapping to a non-negative int32_t
        max_positive_ = (negative_threshold > int32_max) ? int32_max : negative_threshold;

        // the smallest value mapping to a negative int32_t
        min_negative_ = negative_threshold + IntType(1);
        if (modulus > IntType(int32_min_magnitude)) {
            const IntType lowest_negative(modulus - IntType(int32_min_magnitude));
            if (lowest_negative > min_negative_)
                min_negative_ = lowest_negative;
        }

        if (native_) {
            modulus64_ = modulus.template convert_to_int<uint64_t>();
            max_positive64_ = max_positive_.template convert_to_int<uint64_t>();
        }
    }

    /**
     * Maps a residue in Z_q to its centered representative.
     *
     * @param value the residue in [0, q)
     * @return the representative in (-q/2, q/2] as int32_t; throws if it does not fit
     */
    int32_t convert(const IntType& value) const {
        if (native_) {
            //  q <= 2^64: both bounds and the magnitude fit in a native word, so the comparisons
            //  and the subtraction need no big-integer temporary. A value outside Z_q wraps the
            //  subtraction, which the magnitude bound then rejects
            const uint64_t v{value.template convert_to_int<uint64_t>()};
            if (v <= max_positive64_)
                return static_cast<int32_t>(v);
            const uint64_t magnitude{modulus64_ - v};
            if (magnitude <= int32_min_magnitude)
                return static_cast<int32_t>(-static_cast<int64_t>(magnitude));
        } else {
            if (value <= max_positive_)
                return static_cast<int32_t>(value.template convert_to_int<uint64_t>());
            if (value >= min_negative_ && value < modulus_)
                return static_cast<int32_t>(
                        -static_cast<int64_t>((modulus_ - value).template convert_to_int<uint64_t>()));
        }
        CIPHER_THROW("The centered representative of " + value.to_string() + " mod " + modulus_.to_string() +
                     " cannot be represented as int32_t");
    }

  private:
    static constexpr uint64_t int32_max_value{static_cast<uint64_t>(std::numeric_limits<int32_t>::max())};
    static constexpr uint64_t int32_min_magnitude{int32_max_value + 1};  // abs(INT32_MIN)

    IntType modulus_;
    IntType max_positive_;
    IntType min_negative_;
    uint64_t modulus64_{0};
    uint64_t max_positive64_{0};
    bool native_{false};
};

/// converter for the BigInteger backend
using CenteredToInt32Converter = CenteredToInt32ConverterImpl<BigInteger>;

}  // namespace cipher

#endif  // CIPHER_MATH_MATRIX_UTILS_H_
