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

#include "cipher/fhe/encoding/ckks_packed.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <limits>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/math/dft.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

namespace cipher {

std::vector<std::complex<double>> conjugate_values(const std::vector<std::complex<double>>& vec) {
    uint32_t n = vec.size();
    std::vector<std::complex<double>> result(n);
    for (uint32_t i = 1; i < n; ++i) {
        result[i] = {-vec[n - i].imag(), -vec[n - i].real()};
    }
    result[0] = {vec[0].real(), -vec[0].imag()};
    return result;
}

// Estimate standard deviation using the imaginary part of decoded vector z
// Compute m(X) - m(1/X) as a proxy for z - Conj(z) = 2*Im(z)
// vec is m(X) corresponding to z
// conjugate is m(1/X) corresponding to Conj(z)

double std_dev(const std::vector<std::complex<double>>& vec, const std::vector<std::complex<double>>& conjugate) {
    uint32_t slots = vec.size();
    if (1 == slots) {
        return vec[0].imag();
    }
    // ring dimension
    uint32_t dslots = slots * 2;

    // extract the complex part using identity z - Conj(z) == 2*Im(z)
    // here we actually compute m(X) - m(1/X) corresponding to 2*Im(z).
    // we only need first Nh/2 + 1 components of the imaginary part
    // as the remaining Nh/2 - 1 components have a symmetry
    // w.r.t. components from 1 to Nh/2 - 1
    std::vector<std::complex<double>> complex_values(slots / 2 + 1);
    for (size_t i = 0; i < slots / 2 + 1; ++i) {
        complex_values[i] = vec[i] - conjugate[i];
    }

    // Calculate the mean
    auto mean_func = [](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() + val.imag());
    };

    // use the symmetry condition
    double mean = 2 * std::accumulate(complex_values.begin() + 1, complex_values.begin() + slots / 2, 0.0, mean_func);
    // and then add values at indices 0 and Nh/2
    mean += complex_values[0].imag();
    mean += 2 * complex_values[slots / 2].real();
    // exclude the real part at index 0 as it is always 0
    mean /= static_cast<double>(dslots) - 1.0;

    // Now calculate the variance
    auto variance_func = [&mean](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() - mean) * (val.real() - mean) + (val.imag() - mean) * (val.imag() - mean);
    };

    // use the symmetry condition
    double variance =
            2 * accumulate(complex_values.begin() + 1, complex_values.begin() + slots / 2, 0.0, variance_func);
    // and then add values at indices 0 and Nh/2
    variance += (complex_values[0].imag() - mean) * (complex_values[0].imag() - mean);
    variance += 2 * (complex_values[slots / 2].real() - mean) * (complex_values[slots / 2].real() - mean);
    // exclude the real part at index 0 as it is always 0
    variance /= static_cast<double>(dslots) - 2.0;
    // scale down by 2 as we have worked with 2*Im(z) up to this point
    return 0.5 * std::sqrt(variance);
}

bool CKKSPackedEncoding::encode() {
    if (is_encoded_)
        return true;

    if (type_flag != IsRnsPoly)
        CIPHER_THROW("Only RnsPoly is supported for CKKS.");

    if (slots < value.size()) {
        std::string err_msg = std::string("The number of slots [") + std::to_string(slots) +
                              "] is less than the size of data [" + std::to_string(value.size()) + "]";
        CIPHER_THROW(err_msg);
    }

    auto inverse_value{value};
    inverse_value.resize(slots);

    uint32_t ring_dim = get_element_ring_dimension();
    DiscreteFourierTransform::fft_special_inv(inverse_value, ring_dim * 2);

#if CIPHER_NATIVE_INT == 128
    uint64_t p_bits = encoding_params->get_plaintext_modulus();
    uint32_t precision = 52;

    double pow_p = std::pow(2, precision);
    int32_t p_current = p_bits - precision;

    // the idea is to break down real and imaginary parts
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    std::vector<int128_t> temp(2 * slots);
    int128_t max_bit_value = max128_bit_value();
    for (uint32_t i = 0; i < slots; ++i) {
        // Check for possible overflow in llround function
        int32_t n1 = 0;
        // extract the mantissa of real part and multiply it by 2^52
        double dre = static_cast<double>(std::frexp(inverse_value[i].real(), &n1) * pow_p);
        int32_t n2 = 0;
        // extract the mantissa of imaginary part and multiply it by 2^52
        double dim = static_cast<double>(std::frexp(inverse_value[i].imag(), &n2) * pow_p);
        if (is128_bit_overflow(dre) || is128_bit_overflow(dim)) {
            CIPHER_THROW("Overflow, try to decrease scaling factor");
        }

        int128_t re = CKKSPackedEncoding::scale_by_power_of_two(std::llround(dre), p_current + n1);
        int128_t im = CKKSPackedEncoding::scale_by_power_of_two(std::llround(dim), p_current + n2);

        temp[i] = (re < 0) ? max_bit_value + re : re;
        temp[i + slots] = (im < 0) ? max_bit_value + im : im;

        if (is128_bit_overflow(temp[i]) || is128_bit_overflow(temp[i + slots])) {
            CIPHER_THROW("Overflow, try to decrease scaling factor");
        }
    }
    RnsPoly::Integer int_pow_p = NativeInteger(1) << p_bits;
#else  // CIPHER_NATIVE_INT == 64
    double max_abs = 0.;
    for (uint32_t i = 0; i < slots; ++i) {
        inverse_value[i] *= scaling_factor;
        const double re = std::abs(inverse_value[i].real());
        const double im = std::abs(inverse_value[i].imag());
        if (max_abs < re)
            max_abs = re;
        if (max_abs < im)
            max_abs = im;
    }
    int32_t logc = (max_abs == 0.) ? 0 : static_cast<int32_t>(std::ceil(std::log2(max_abs)));
    if (logc < 0)
        CIPHER_THROW("Scaling factor too small");

    // Compute approx_factor, a value to scale down by in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = LargeScalingFactorConstants::MAX_BITS_IN_WORD;

    int32_t log_valid = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t log_approx = logc - log_valid;
    double approx_factor = std::pow(2, log_approx);
    double inv_len = static_cast<double>(slots);

    std::vector<int64_t> temp(2 * slots);
    int64_t max_bit_value = max64_bit_value();
    for (uint32_t i = 0; i < slots; ++i) {
        // Scale down by approx_factor in case the value exceeds a 64-bit integer.
        double dre = inverse_value[i].real() / approx_factor;
        double dim = inverse_value[i].imag() / approx_factor;

        // Check for possible overflow
        if (is64_bit_overflow(dre) || is64_bit_overflow(dim)) {
            // IFFT formula:
            // x[n] = (1/N) * \Sum^(N-1)_(k=0) X[k] * exp( j*2*pi*n*k/N )
            // n is i
            // k is idx below
            // N is inverse.size()
            //
            // In the following, we switch to original data domain,
            // and we identify the component that has the maximum
            // contribution to the values in the iFFT domain. We do
            // this to report it to the user, so they can identify
            // large inputs.

            DiscreteFourierTransform::fft_special(inverse_value, ring_dim * 2);

            double factor = 2 * M_PI * i;
            double real_max = -1, imag_max = -1;
            uint32_t real_max_idx = -1, imag_max_idx = -1;

            for (uint32_t idx = 0; idx < slots; ++idx) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> exp_factor = {cos((factor * idx) / inv_len), sin((factor * idx) / inv_len)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prod_factor = inverse_value[idx] * exp_factor;

                double real_val = prod_factor.real();
                double imag_val = prod_factor.imag();

                if (real_val > real_max) {
                    real_max = real_val;
                    real_max_idx = idx;
                }
                if (imag_val > imag_max) {
                    imag_max = imag_val;
                    imag_max_idx = idx;
                }
            }

            auto scaled_input_size = std::ceil(std::log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << real_max_idx << "]: " << real_max << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imag_max_idx << "]: " << imag_max << std::endl;
            buffer << "Scaling factor is " << std::ceil(std::log2(scaling_factor)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaled_input_size << " bits " << std::endl;
            CIPHER_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        int64_t im = std::llround(dim);

        temp[i] = (re < 0) ? max_bit_value + re : re;
        temp[i + slots] = (im < 0) ? max_bit_value + im : im;
    }
    RnsPoly::Integer int_pow_p(static_cast<uint64_t>(std::llround(scaling_factor)));
#endif

    auto native_params = encoded_vector_dcrt.get_params()->get_params();
    uint32_t num_towers = native_params.size();
    std::vector<RnsPoly::Integer> moduli(num_towers);
    for (uint32_t i = 0; i < num_towers; i++) {
        moduli[i] = native_params[i]->get_modulus();
        NativeVector native_vec(ring_dim, native_params[i]->get_modulus());
        fit_to_native_vector(temp, max_bit_value, &native_vec);
        NativePoly element = get_element<RnsPoly>().get_element_at_index(i);
        element.set_values(std::move(native_vec), Format::COEFFICIENT);  // output was in coefficient format
        encoded_vector_dcrt.set_element_at_index(i, std::move(element));
    }

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and curr_pow_p already is 2^p.
    std::vector<RnsPoly::Integer> crt_pow_p(num_towers, int_pow_p);
    auto curr_pow_p = crt_pow_p;
    for (size_t i = 2; i < noise_scale_deg; ++i)
        curr_pow_p = CKKSPackedEncoding::crt_mult(curr_pow_p, crt_pow_p, moduli);

    if (noise_scale_deg > 1)
        encoded_vector_dcrt = encoded_vector_dcrt.Times(curr_pow_p);

#if CIPHER_NATIVE_INT == 64
    // Scale back up by the approx_factor to get the correct encoding.
    int32_t MAX_LOG_STEP = 60;
    if (log_approx > 0) {
        int32_t log_step = (log_approx <= MAX_LOG_STEP) ? log_approx : MAX_LOG_STEP;
        RnsPoly::Integer int_step = static_cast<uint64_t>(1) << log_step;
        std::vector<RnsPoly::Integer> crt_approx(num_towers, int_step);
        log_approx -= log_step;

        while (log_approx > 0) {
            int32_t log_step = (log_approx <= MAX_LOG_STEP) ? log_approx : MAX_LOG_STEP;
            RnsPoly::Integer int_step = static_cast<uint64_t>(1) << log_step;
            std::vector<RnsPoly::Integer> crt_sf(num_towers, int_step);
            crt_approx = crt_mult(crt_approx, crt_sf, moduli);
            log_approx -= log_step;
        }
        encoded_vector_dcrt = encoded_vector_dcrt.Times(crt_approx);
    }
#endif

    get_element<RnsPoly>().set_format(Format::EVALUATION);
    scaling_factor = std::pow(scaling_factor, noise_scale_deg);
    return is_encoded_ = true;
}

bool CKKSPackedEncoding::decode(size_t noise_scale_deg, double scaling_factor, ScalingTechnique scal_tech,
                                ExecutionMode execution_mode) {
    double p = encoding_params->get_plaintext_modulus();
    double pow_p = 0.0;
    uint32_t nh_value = get_element_ring_dimension() / 2;
    uint32_t gap = nh_value / slots;
    value.clear();
    std::vector<std::complex<double>> cur_values(slots);

    if (type_flag == IsNativePoly) {
        if (scal_tech == FLEXIBLEAUTO || scal_tech == FLEXIBLEAUTOEXT || scal_tech == COMPOSITESCALINGAUTO ||
            scal_tech == COMPOSITESCALINGMANUAL)
            pow_p = std::pow(scaling_factor, -1);
        else
            pow_p = std::pow(2, -p);

        NativeInteger q = get_element_modulus().convert_to_int();
        NativeInteger q_half = q >> 1;

        for (uint32_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (get_element<NativePoly>()[idx] > q_half)
                cur.real(-((q - get_element<NativePoly>()[idx])).convert_to_double());
            else
                cur.real((get_element<NativePoly>()[idx]).convert_to_double());

            if (get_element<NativePoly>()[idx + nh_value] > q_half)
                cur.imag(-((q - get_element<NativePoly>()[idx + nh_value])).convert_to_double());
            else
                cur.imag((get_element<NativePoly>()[idx + nh_value]).convert_to_double());

            cur_values[i] = cur;
        }

        // clears the values containing information about the noise
        get_element<NativePoly>().set_values_to_zero();
    } else {
        pow_p = std::pow(2, -p);

        // we will bring down the scaling factor to 2^p
        double scaling_factor_pre = 0.0;
        if (scal_tech == FLEXIBLEAUTO || scal_tech == FLEXIBLEAUTOEXT || scal_tech == COMPOSITESCALINGAUTO ||
            scal_tech == COMPOSITESCALINGMANUAL)
            scaling_factor_pre = std::pow(scaling_factor, -1) * std::pow(2, p);
        else
            scaling_factor_pre = std::pow(2, -p * (noise_scale_deg - 1));

        const BigInteger& q = get_element_modulus();
        BigInteger q_half = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (get_element<Poly>()[idx] > q_half)
                cur.real(-((q - get_element<Poly>()[idx])).convert_to_double() * scaling_factor_pre);
            else
                cur.real((get_element<Poly>()[idx]).convert_to_double() * scaling_factor_pre);

            if (get_element<Poly>()[idx + nh_value] > q_half)
                cur.imag(-((q - get_element<Poly>()[idx + nh_value])).convert_to_double() * scaling_factor_pre);
            else
                cur.imag((get_element<Poly>()[idx + nh_value]).convert_to_double() * scaling_factor_pre);

            cur_values[i] = cur;
        }

        // clears the values containing information about the noise
        get_element<Poly>().set_values_to_zero();
    }

    // the code below adds a Gaussian noise to the decrypted result
    // to prevent key recovery attacks.
    // The standard deviation of the Gaussian noise is sqrt(M+1)*stddev,
    // where stddev is the standard deviation estimated using the imaginary
    // component and M is the extra factor that increases the number of decryption
    // attacks that is needed to average out the added Gaussian noise (after the
    // noise is removed, the attacker still has to find the secret key using the
    // real part only, which requires another attack). By default (M = 1), stddev
    // requires at least 128 decryption queries (in practice the values are
    // typically closer to 10,000 or so). Then M can be used to increase this
    // number further by M^2 (as desired for a given application). By default we
    // we set M to 1.

    // compute m(1/X) corresponding to Conj(z), where z is the decoded vector
    auto conjugate = conjugate_values(cur_values);

    // Estimate standard deviation from 1/2 (m(X) - m(1/x)),
    // which corresponds to Im(z)
    double stddev = std_dev(cur_values, conjugate);

    double logstd = std::log2(stddev);

    if (execution_mode == EXEC_NOISE_ESTIMATION) {
        log_error_ = logstd;
    } else {
        // if stddev < sqrt{N}/8 (minimum approximation error that can be achieved)
        if (stddev < 0.125 * std::sqrt(get_element_ring_dimension())) {
            stddev = 0.125 * std::sqrt(get_element_ring_dimension());
        }

        // if stddev < sqrt{N}/4 (minimum approximation error that can be achieved)
        // if (stddev < 0.125 * std::sqrt(get_element_ring_dimension())) {
        //   if (noise_scale_deg <= 1) {
        //    CIPHER_THROW(
        //                   "The decryption failed because the approximation error is
        //                   " "too small. Check the protocol used. ");
        //  } else {  // noise_scale_deg > 1 and no rescaling operations have been applied yet
        //    stddev = 0.125 * std::sqrt(get_element_ring_dimension());
        //  }
        // }

        if (ckks_data_type == REAL) {
            //   If less than 5 bits of precision is observed
            if (logstd > p - 5.0)
                CIPHER_THROW(
                        "The decryption failed because the approximation error is "
                        "too high. Check the parameters. ");
        }

        // real values
        std::vector<std::complex<double>> real_values(slots);

        // CIPHER_CKKS_M_FACTOR is a compile-level parameter
        // set to 1 by default
        stddev = std::sqrt(CIPHER_CKKS_M_FACTOR + 1) * stddev;

        double scale = (ckks_data_type == REAL) ? 0.5 * pow_p : pow_p;

        // TODO temporary removed errors
        std::normal_distribution<> d(0, stddev);
        PRNG& g = PseudoRandomNumberGenerator::get_prng();
        // Alternative way to do Gaussian sampling
        // DiscreteGaussianGenerator dgg;

        // TODO we can sample Nh integers instead of 2*Nh
        // We would add sampling only for even indices of i.
        // This change should be done together with the one below.
        for (size_t i = 0; i < slots; ++i) {
            double real = scale * cur_values[i].real();
            double imag = scale * cur_values[i].imag();
            if (ckks_data_type == REAL) {
                real += scale * conjugate[i].real() + pow_p * d(g);
                // real += pow_p * dgg.generate_integer_karney(0.0, stddev);
                imag += scale * conjugate[i].imag() + pow_p * d(g);
                // imag += pow_p * dgg.generate_integer_karney(0.0, stddev);
            }
            real_values[i].real(real);
            real_values[i].imag(imag);
        }

        // TODO we can half the dimension for the FFT by decoding in
        // Z[X + 1/X]/(X^n + 1). This would change the complexity from n*logn to
        // roughly (n/2)*log(n/2). This change should be done together with the one
        // above.
        DiscreteFourierTransform::fft_special(real_values, get_element_ring_dimension() * 2);

        if (ckks_data_type == REAL) {
            // clears all imaginary values for security reasons
            for (auto& val : real_values) {
                val.imag(0.0);
            }

            // sets an estimate of the approximation error
            log_error_ = std::round(std::log2(stddev * std::sqrt(2 * slots)));
        } else {
            log_error_ = 0;
        }

        value = real_values;
    }

    return true;
}

void CKKSPackedEncoding::destroy() {}

void CKKSPackedEncoding::fit_to_native_vector(const std::vector<int64_t>& vec, int64_t big_bound,
                                              NativeVector* native_vec) const {
    NativeInteger big_value_hf(big_bound >> 1);
    NativeInteger modulus(native_vec->get_modulus());
    NativeInteger diff = big_bound - modulus;
    uint32_t ring_dim = get_element_ring_dimension();
    uint32_t dslots = vec.size();
    uint32_t gap = ring_dim / dslots;
#if defined(CIPHER_HAVE_INT128) && CIPHER_NATIVE_INT == 64
    // word-scaled-reciprocal reduction (one multiply per element instead of a divide);
    // unlike compute_mu/mod_mu Barrett it is valid for the full 64-bit input range.
    // The biased values are nonnegative, so the int64 -> uint64 conversion is value-preserving.
    const uint64_t q{modulus.convert_to_int<uint64_t>()};
    const int64_t e{static_cast<int64_t>(cipher::get_msb(q)) - 2};
    if (e >= 1) {
        const uint64_t half{static_cast<uint64_t>(big_bound) >> 1};
        const uint64_t diff_r{(static_cast<uint64_t>(big_bound) - q) % q};
        const uint64_t mu{static_cast<uint64_t>((static_cast<unsigned __int128>(1) << (64 + e)) / q)};
        for (uint32_t i = 0; i < dslots; ++i) {
            const uint64_t v{static_cast<uint64_t>(vec[i])};
            uint64_t av{v};
            if (av >= q) {
                av -= static_cast<uint64_t>((static_cast<unsigned __int128>(v) * mu) >> 64 >> e) * q;
                if (av >= q)
                    av -= q;
            }
            uint64_t t{av - (diff_r & (0 - static_cast<uint64_t>(v > half)))};
            t += q & (0 - (t >> 63));
            (*native_vec)[gap * i] = t;
        }
        return;
    }
#endif
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n(vec[i]);
        if (n > big_value_hf) {
            (*native_vec)[gap * i] = n.mod_sub(diff, modulus);
        } else {
            (*native_vec)[gap * i] = n.mod(modulus);
        }
    }
}

#if CIPHER_NATIVE_INT == 128
void CKKSPackedEncoding::fit_to_native_vector(const std::vector<int128_t>& vec, int128_t big_bound,
                                              NativeVector* native_vec) const {
    NativeInteger big_value_hf((uint128_t)big_bound >> 1);
    NativeInteger modulus(native_vec->get_modulus());
    NativeInteger diff = NativeInteger((uint128_t)big_bound) - modulus;
    uint32_t ring_dim = get_element_ring_dimension();
    uint32_t dslots = vec.size();
    uint32_t gap = ring_dim / dslots;
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > big_value_hf) {
            (*native_vec)[gap * i] = n.mod_sub(diff, modulus);
        } else {
            (*native_vec)[gap * i] = n.mod(modulus);
        }
    }
}
#endif

}  // namespace cipher
