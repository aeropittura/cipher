//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#include "cipher/fhe/ckks/leveled_she.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/math/backend/basic_int.h"
#include "cipher/fhe/ckks/crypto_params.h"
#include "cipher/fhe/base/scheme.h"

namespace cipher {

/////////////////////////////////////////
// SHE ADDITION CONSTANT
/////////////////////////////////////////

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_add(ConstCiphertext<RnsPoly>& ciphertext, double operand) const {
    auto result = ciphertext->clone();
    eval_add_in_place(result, operand);
    return result;
}

void CkksRnsLeveledShe::eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const {
    auto elmnts = get_element_for_eval_add_or_sub(ciphertext, operand);
    auto& polys = ciphertext->get_elements()[0].get_all_elements();

    const uint32_t limit = polys.size();
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
    for (uint32_t i = 0; i < limit; ++i)
        polys[i] += elmnts[i];
}

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_add(ConstCiphertext<RnsPoly>& ciphertext,
                                                std::complex<double> operand) const {
    auto result = ciphertext->clone();
    eval_add_in_place(result, operand);
    return result;
}

void CkksRnsLeveledShe::eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const {
    auto& cv = ciphertext->get_elements();
    auto elems_re = get_element_for_eval_add_or_sub(ciphertext, std::fabs(operand.real()));
    auto elems_im = get_element_for_eval_add_or_sub(ciphertext, std::fabs(operand.imag()));
    uint32_t N = cv[0].get_length();
    uint32_t nhalf = N >> 1;
    auto posreal = operand.real() > 0.;
    auto posimag = operand.imag() > 0.;

    RnsPoly elems_complex(cv[0].get_params(), Format::COEFFICIENT, true);
    const uint32_t size_ql = elems_complex.get_num_of_elements();
    for (uint32_t i = 0; i < size_ql; ++i) {
        auto element = cv[0].get_element_at_index(i);
        auto modulus = element.get_modulus();
        NativeVector vec(N, modulus);
        vec[0] = posreal ? NativeInteger(elems_re[i].mod(modulus)) : modulus.mod_sub(elems_re[i], modulus);
        vec[nhalf] = posimag ? NativeInteger(elems_im[i].mod(modulus)) : modulus.mod_sub(elems_im[i], modulus);
        element.set_values(std::move(vec), Format::COEFFICIENT);
        elems_complex.set_element_at_index(i, std::move(element));
    }
    elems_complex.set_format(Format::EVALUATION);

    cv[0] += elems_complex;
}

/////////////////////////////////////////
// SHE SUBTRACTION CONSTANT
/////////////////////////////////////////

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_sub(ConstCiphertext<RnsPoly>& ciphertext, double operand) const {
    auto result = ciphertext->clone();
    eval_sub_in_place(result, operand);
    return result;
}

void CkksRnsLeveledShe::eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const {
    auto elmnts = get_element_for_eval_add_or_sub(ciphertext, operand);
    auto& polys = ciphertext->get_elements()[0].get_all_elements();

    const uint32_t limit = polys.size();
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(limit))
    for (uint32_t i = 0; i < limit; ++i)
        polys[i] -= elmnts[i];
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext, double operand) const {
    auto result = ciphertext->clone();
    eval_mult_in_place(result, operand);
    return result;
}

void CkksRnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    if (crypto_params->get_scaling_technique() != FIXEDMANUAL) {
        if (ciphertext->get_noise_scale_deg() == 2)
            mod_reduce_internal_in_place(ciphertext, crypto_params->get_composite_degree());
    }
    eval_mult_core_in_place(ciphertext, operand);
}

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext,
                                                 std::complex<double> operand) const {
    auto result = ciphertext->clone();
    eval_mult_in_place(result, operand);
    return result;
}

void CkksRnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    if (crypto_params->get_scaling_technique() != FIXEDMANUAL) {
        if (ciphertext->get_noise_scale_deg() == 2)
            mod_reduce_internal_in_place(ciphertext, crypto_params->get_composite_degree());
    }
    eval_mult_core_in_place(ciphertext, operand);
}

void CkksRnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    RnsLeveledShe::eval_mult_in_place(ciphertext, plaintext);
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    auto scal_tech = crypto_params->get_scaling_technique();
    if (scal_tech == FLEXIBLEAUTO || scal_tech == FLEXIBLEAUTOEXT || scal_tech == COMPOSITESCALINGAUTO ||
        scal_tech == COMPOSITESCALINGMANUAL) {
        // For FLEXIBLE*/COMPOSITESCALING*, set the post-multiply scaling factor from the precomputed table
        // (the canonical "big" scaling factor for this level) rather than squaring the ciphertext's tracked
        // scaling factor on the fly. The plaintext was encoded at the canonical get_scaling_factor_real(level),
        // so the product's scale is that canonical value squared; squaring the *tracked* SF instead compounds
        // any accumulated drift (composite scaling) into a multiplicative value error that grows with depth.
        ciphertext->set_scaling_factor(crypto_params->get_scaling_factor_real_big(ciphertext->get_level()));
    } else if (scal_tech != NORESCALE) {
        // FIXEDMANUAL / FIXEDAUTO use a fixed scaling factor; keep the original on-the-fly behavior.
        ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() * ciphertext->get_scaling_factor());
    }
}

/////////////////////////////////////////
// SHE MULTIPLICATION PLAINTEXT
/////////////////////////////////////////

/////////////////////////////////////
// Mod Reduce
/////////////////////////////////////

void CkksRnsLeveledShe::mod_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto& cv = ciphertext->get_elements();

    size_t size_q = crypto_params->get_element_params()->get_params().size();
    size_t size_ql = cv[0].get_num_of_elements();
    size_t diff_ql = size_q - size_ql;

    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() - levels / crypto_params->get_composite_degree());
    ciphertext->set_level(ciphertext->get_level() + levels);

    for (size_t i = 0; i < levels; ++i) {
        for (auto& rns_poly : cv)
            rns_poly.drop_last_element_and_scale(crypto_params->get_ql_inv_modq(diff_ql + i));
        double mod_reduce_factor = crypto_params->get_mod_reduce_factor(size_ql - 1 - i);
        ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() / mod_reduce_factor);
    }
}

/////////////////////////////////////
// Level Reduce
/////////////////////////////////////

void CkksRnsLeveledShe::level_reduce_internal_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const {
    for (auto& element : ciphertext->get_elements())
        element.drop_last_elements(levels);
    ciphertext->set_level(ciphertext->get_level() + levels);
}

/////////////////////////////////////
// Compress
/////////////////////////////////////

/////////////////////////////////////
// CKKS Core
/////////////////////////////////////

namespace {
// Brings the degree-1 encoding of a constant to the scale of a degree-d ciphertext by multiplying it
// (d - 1) times by the per-degree factor. For FIXEDMANUAL and FIXEDAUTO that factor is the modulus of the
// tower dropped by the corresponding rescale rather than the scaling factor Delta: the rescale divides by
// the actual prime q_l, so a constant encoded as c * Delta^d would come out as c * Delta / q_l. The residual
// (about 2^-33 for 50-bit primes) is a constant shift of T_2 = 2x^2 - 1 that the squaring chain of the
// Paterson-Stockmeyer giant steps amplifies by roughly the square of the degree.
std::vector<RnsPoly::Integer> scale_constant_to_degree(std::vector<RnsPoly::Integer> constant,
                                                       const std::vector<RnsPoly::Integer>& crt_sc_factor,
                                                       const std::vector<RnsPoly::Integer>& moduli,
                                                       uint32_t noise_scale_deg, bool fixed_scaling) {
    const uint32_t num_towers = moduli.size();
    for (uint32_t i = 1; i < noise_scale_deg; ++i) {
        if (fixed_scaling && i < num_towers) {
            std::vector<RnsPoly::Integer> crt_q(num_towers);
            for (uint32_t j = 0; j < num_towers; ++j)
                crt_q[j] = moduli[num_towers - i].mod(moduli[j]);
            constant = CKKSPackedEncoding::crt_mult(constant, crt_q, moduli);
        } else {
            constant = CKKSPackedEncoding::crt_mult(constant, crt_sc_factor, moduli);
        }
    }
    return constant;
}
}  // namespace

#if CIPHER_NATIVE_INT == 128
namespace {
// Returns (value * 2^shift) mod modulus for any shift >= 0. Applying the power of two in
// steps keeps every intermediate inside one 128-bit word, so scalars whose scaled
// representation needs more than 128 bits no longer shift out of range or wrap silently.
RnsPoly::Integer mod_shift_left(const RnsPoly::Integer& value, int32_t shift, const RnsPoly::Integer& modulus) {
    constexpr int32_t max_log_step = LargeScalingFactorConstants::MAX_LOG_STEP;
    RnsPoly::Integer result(value.mod(modulus));
    for (; shift > 0; shift -= max_log_step) {
        int32_t log_step = std::min(shift, max_log_step);
        result = result.mod_mul(RnsPoly::Integer(1) << log_step, modulus);
    }
    return result;
}
}  // namespace

std::vector<RnsPoly::Integer> CkksRnsLeveledShe::get_element_for_eval_add_or_sub(ConstCiphertext<RnsPoly>& ciphertext,
                                                                                 double operand) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    uint32_t precision = 52;
    double pow_p = std::pow(2, precision);

    const auto& cv = ciphertext->get_elements();
    uint32_t num_towers = cv[0].get_num_of_elements();
    std::vector<RnsPoly::Integer> moduli(num_towers);

    for (uint32_t i = 0; i < num_towers; ++i)
        moduli[i] = cv[0].get_element_at_index(i).get_modulus();

    // the idea is to break down real numbers
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    int32_t n1 = 0;
    int64_t scaled64 = std::llround(static_cast<double>(std::frexp(operand, &n1)) * pow_p);

    int32_t p_current = crypto_params->get_plaintext_modulus() - precision;
    int32_t p_remaining = p_current + n1;

    // The operand is non-negative here: CryptoContext turns eval_add of a negative scalar into
    // eval_sub of its magnitude and vice versa, and the complex overloads pass std::fabs.
    std::vector<RnsPoly::Integer> curr_pow_p(num_towers);
    if (p_remaining < 0) {
        // Discard scalars below the integer precision without an out-of-range shift.
        RnsPoly::Integer scaled_constant(p_remaining <= -64 ? static_cast<uint64_t>(0) :
                                                              static_cast<uint64_t>(scaled64) >> (-p_remaining));
        curr_pow_p.assign(num_towers, scaled_constant);
    } else {
        // scaled64 * 2^p_remaining needs more than 128 bits once the operand is large, so the
        // power of two is applied modulo each tower rather than to scaled64 itself.
        for (uint32_t i = 0; i < num_towers; ++i)
            curr_pow_p[i] = mod_shift_left(RnsPoly::Integer(static_cast<uint64_t>(scaled64)), p_remaining, moduli[i]);
    }

    // 2^precision * 2^p_current, reduced per tower: crt_mult below uses mod_mul_fast, which assumes
    // both operands are already below the modulus, and 2^p_current exceeds some towers.
    uint64_t powp64 = (static_cast<uint64_t>(1)) << precision;
    std::vector<RnsPoly::Integer> crt_pow_p(num_towers);
    if (p_current < 0) {
        // p_current is bounded below by -precision, so this shift count stays in range.
        RnsPoly::Integer int_pow_p(powp64 >> (-p_current));
        for (uint32_t i = 0; i < num_towers; ++i)
            crt_pow_p[i] = int_pow_p.mod(moduli[i]);
    } else {
        for (uint32_t i = 0; i < num_towers; ++i)
            crt_pow_p[i] = mod_shift_left(RnsPoly::Integer(powp64), p_current, moduli[i]);
    }

    // multiply c*pow_p with the per-degree factor a total of (depth-1) times
    const auto scal_tech = crypto_params->get_scaling_technique();
    return scale_constant_to_degree(std::move(curr_pow_p), crt_pow_p, moduli, ciphertext->get_noise_scale_deg(),
                                    scal_tech == FIXEDMANUAL || scal_tech == FIXEDAUTO);
}
#else  // CIPHER_NATIVE_INT == 64
std::vector<RnsPoly::Integer> CkksRnsLeveledShe::get_element_for_eval_add_or_sub(ConstCiphertext<RnsPoly>& ciphertext,
                                                                                 double operand) const {
    const auto& polys = ciphertext->get_elements()[0].get_all_elements();
    const uint32_t size_ql = polys.size();
    std::vector<RnsPoly::Integer> moduli(size_ql);
    for (uint32_t i = 0; i < size_ql; ++i)
        moduli[i] = polys[i].get_modulus();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    double sc_factor = 0;
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT && ciphertext->get_level() == 0) {
        sc_factor = crypto_params->get_scaling_factor_real_big(ciphertext->get_level());
    } else {
        sc_factor = crypto_params->get_scaling_factor_real(ciphertext->get_level());
    }

    // Compute approx_factor, a value to scale down by, in case the value exceeds a 64-bit integer.

    // the logic below was added as the code crashes when linked with clang++ in the Debug mode and
    // with the following flags and res is ZERO:
    // -O2
    // -g
    // -fsanitize-trap=all
    // -fsanitize=alignment,return,returns-nonnull-attribute,vla-bound,unreachable,float-cast-overflow
    // -fsanitize=null
    // -gz=zlib
    // -fno-asynchronous-unwind-tables
    // -fno-optimize-sibling-calls
    // -fsplit-dwarf-inlining
    // -gsimple-template-names
    // -gsplit-dwarf
    int32_t log_approx = 0;
    // Duhyeong: We need to take account the 64-bit overflow for both operand * sc_factor and sc_factor
    double res = std::fabs(operand * sc_factor);
    if (crypto_params->get_scaling_technique() == COMPOSITESCALINGAUTO ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGMANUAL) {
        res = std::max(res, std::fabs(sc_factor));
    }
    if (res > 0) {
        int32_t log_sf = static_cast<int32_t>(std::ceil(std::log2(res)));
        int32_t log_valid = (log_sf <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                                    log_sf :
                                    LargeScalingFactorConstants::MAX_BITS_IN_WORD;
        log_approx = log_sf - log_valid;
    }
    int32_t log_approx_cp = log_approx;
    double approx_factor = std::pow(2, log_approx);

    RnsPoly::Integer sc_constant = static_cast<uint64_t>(operand * sc_factor / approx_factor + 0.5);
    std::vector<RnsPoly::Integer> crt_constant(size_ql, sc_constant);

    // Scale back up by approx_factor within the CRT multiplications.
    if (log_approx > 0) {
        int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                   log_approx :
                                   LargeScalingFactorConstants::MAX_LOG_STEP;
        auto int_step = static_cast<RnsPoly::Integer>(1) << log_step;
        std::vector<RnsPoly::Integer> crt_approx(size_ql, int_step);
        log_approx -= log_step;

        while (log_approx > 0) {
            int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                       log_approx :
                                       LargeScalingFactorConstants::MAX_LOG_STEP;
            auto int_step = static_cast<RnsPoly::Integer>(1) << log_step;
            std::vector<RnsPoly::Integer> crt_sf(size_ql, int_step);
            crt_approx = CKKSPackedEncoding::crt_mult(crt_approx, crt_sf, moduli);
            log_approx -= log_step;
        }
        crt_constant = CKKSPackedEncoding::crt_mult(crt_constant, crt_approx, moduli);
    }

    // In FLEXIBLEAUTOEXT mode at level 0, we don't use the depth to calculate the scaling factor,
    // so we return the value before taking the depth into account.
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT && ciphertext->get_level() == 0) {
        return crt_constant;
    }

    // COMPOSITESCALING support to 128-bit scaling factor
    if (crypto_params->get_scaling_technique() == COMPOSITESCALINGAUTO ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGMANUAL) {
        int32_t log_sf_cp = static_cast<int32_t>(std::ceil(std::log2(res)));
        if (log_sf_cp < 64) {
            RnsPoly::Integer int_sc_factor = static_cast<uint64_t>(sc_factor + 0.5);
            std::vector<RnsPoly::Integer> crt_sc_factor(size_ql, int_sc_factor);
            for (uint32_t i = 1; i < ciphertext->get_noise_scale_deg(); ++i)
                crt_constant = CKKSPackedEncoding::crt_mult(crt_constant, crt_sc_factor, moduli);
        } else {
            // Multiply sc_factor in two steps: sc_factor / approx_factor and then approx_factor
            RnsPoly::Integer int_sc_factor = static_cast<uint64_t>(sc_factor / approx_factor + 0.5);
            std::vector<RnsPoly::Integer> crt_sc_factor(size_ql, int_sc_factor);
            for (uint32_t i = 1; i < ciphertext->get_noise_scale_deg(); ++i)
                crt_constant = CKKSPackedEncoding::crt_mult(crt_constant, crt_sc_factor, moduli);
            if (log_approx_cp > 0) {
                int32_t log_step = (log_approx_cp <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                           log_approx_cp :
                                           LargeScalingFactorConstants::MAX_LOG_STEP;
                auto int_step = RnsPoly::Integer(1) << log_step;
                std::vector<RnsPoly::Integer> crt_approx(size_ql, int_step);
                log_approx_cp -= log_step;

                while (log_approx_cp > 0) {
                    int32_t log_step = (log_approx_cp <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                               log_approx_cp :
                                               LargeScalingFactorConstants::MAX_LOG_STEP;
                    auto int_step = RnsPoly::Integer(1) << log_step;
                    std::vector<RnsPoly::Integer> crt_sf(size_ql, int_step);
                    crt_approx = CKKSPackedEncoding::crt_mult(crt_approx, crt_sf, moduli);
                    log_approx_cp -= log_step;
                }
                for (uint32_t i = 1; i < ciphertext->get_noise_scale_deg(); ++i)
                    crt_constant = CKKSPackedEncoding::crt_mult(crt_constant, crt_approx, moduli);
            }
        }
    } else {
        RnsPoly::Integer int_sc_factor = static_cast<uint64_t>(sc_factor + 0.5);
        std::vector<RnsPoly::Integer> crt_sc_factor(size_ql, int_sc_factor);
        const auto scal_tech = crypto_params->get_scaling_technique();
        crt_constant = scale_constant_to_degree(std::move(crt_constant), crt_sc_factor, moduli,
                                                ciphertext->get_noise_scale_deg(),
                                                scal_tech == FIXEDMANUAL || scal_tech == FIXEDAUTO);
    }

    return crt_constant;
}
#endif

#if CIPHER_NATIVE_INT == 128
std::vector<RnsPoly::Integer> CkksRnsLeveledShe::get_element_for_eval_mult(ConstCiphertext<RnsPoly>& ciphertext,
                                                                           double operand) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    uint32_t precision = 52;
    double pow_p = std::pow(2, precision);

    // the idea is to break down real numbers
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    int32_t n1 = 0;
    int64_t scaled64 = std::llround(static_cast<double>(std::frexp(operand, &n1)) * pow_p);
    int32_t p_current = crypto_params->get_plaintext_modulus() - precision;
    int32_t p_remaining = p_current + n1;

    // Unlike eval_add/eval_sub, the operand keeps its sign here, so it is split into sign and
    // magnitude: the magnitude is applied modulo each tower below and the sign is restored
    // afterwards. The negation goes through uint64_t because std::llround returns an
    // unspecified value when the operand is non-finite or out of range, and negating the
    // signed minimum would be undefined behaviour.
    const bool is_negative = (scaled64 < 0);
    uint64_t magnitude =
            is_negative ? static_cast<uint64_t>(0) - static_cast<uint64_t>(scaled64) : static_cast<uint64_t>(scaled64);

    if (p_remaining < 0) {
        // Scalars below the integer precision truncate toward zero for either sign instead of
        // shifting by an out-of-range count.
        magnitude = (p_remaining <= -64) ? 0 : magnitude >> (-p_remaining);
        p_remaining = 0;
    }

    const auto& cv = ciphertext->get_elements();
    uint32_t num_towers = cv[0].get_num_of_elements();
    std::vector<RnsPoly::Integer> factors(num_towers);

    for (uint32_t i = 0; i < num_towers; i++) {
        RnsPoly::Integer modulus = cv[0].get_element_at_index(i).get_modulus();
        RnsPoly::Integer reduced_unsigned = mod_shift_left(RnsPoly::Integer(magnitude), p_remaining, modulus);
        // mod_sub rather than (modulus - reduced_unsigned) so that a magnitude divisible by the
        // modulus yields 0 instead of an unreduced modulus.
        factors[i] = is_negative ? modulus.mod_sub(reduced_unsigned, modulus) : reduced_unsigned;
    }
    return factors;
}
#else  // CIPHER_NATIVE_INT == 64
std::vector<RnsPoly::Integer> CkksRnsLeveledShe::get_element_for_eval_mult(ConstCiphertext<RnsPoly>& ciphertext,
                                                                           double operand) const {
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    uint32_t num_towers = cv[0].get_num_of_elements();
    std::vector<RnsPoly::Integer> moduli(num_towers);
    for (uint32_t i = 0; i < num_towers; ++i)
        moduli[i] = cv[0].get_element_at_index(i).get_modulus();

    double sc_factor = crypto_params->get_scaling_factor_real(ciphertext->get_level());

    #if defined(CIPHER_HAVE_INT128)
    typedef int128_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = 125;
    #else
    typedef int64_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = LargeScalingFactorConstants::MAX_BITS_IN_WORD;
    #endif

    // Compute approx_factor, a value to scale down by, in case the value exceeds a 64-bit integer.

    // the logic below was added as the code crashes when linked with clang++ in the Debug mode and
    // with the following flags and res is ZERO:
    // -O2
    // -g
    // -fsanitize-trap=all
    // -fsanitize=alignment,return,returns-nonnull-attribute,vla-bound,unreachable,float-cast-overflow
    // -fsanitize=null
    // -gz=zlib
    // -fno-asynchronous-unwind-tables
    // -fno-optimize-sibling-calls
    // -fsplit-dwarf-inlining
    // -gsimple-template-names
    // -gsplit-dwarf
    int32_t log_approx = 0;
    const double res = std::fabs(operand * sc_factor);
    if (res > 0) {
        int32_t log_sf = static_cast<int32_t>(std::ceil(std::log2(res)));
        int32_t log_valid = (log_sf <= MAX_BITS_IN_WORD_LOCAL) ? log_sf : MAX_BITS_IN_WORD_LOCAL;
        log_approx = log_sf - log_valid;
    }
    double approx_factor = std::pow(2, log_approx);

    DoubleInteger large = static_cast<DoubleInteger>(operand / approx_factor * sc_factor + 0.5);
    DoubleInteger large_abs = (large < 0 ? -large : large);
    DoubleInteger bound = static_cast<DoubleInteger>(std::numeric_limits<int64_t>::max());

    std::vector<RnsPoly::Integer> factors(num_towers);

    if (large_abs > bound) {
        for (uint32_t i = 0; i < num_towers; i++) {
            DoubleInteger reduced = large % moduli[i].convert_to_int();

            factors[i] = (reduced < 0) ? static_cast<uint64_t>(reduced + moduli[i].convert_to_int()) :
                                         static_cast<uint64_t>(reduced);
        }
    } else {
        int64_t sc_constant = static_cast<int64_t>(large);
        for (uint32_t i = 0; i < num_towers; i++) {
            int64_t reduced = sc_constant % static_cast<int64_t>(moduli[i].convert_to_int());

            factors[i] = (reduced < 0) ? reduced + moduli[i].convert_to_int() : reduced;
        }
    }

    // Scale back up by approx_factor within the CRT multiplications.
    if (log_approx > 0) {
        int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                   log_approx :
                                   LargeScalingFactorConstants::MAX_LOG_STEP;
        RnsPoly::Integer int_step = static_cast<uint64_t>(1) << log_step;
        std::vector<RnsPoly::Integer> crt_approx(num_towers, int_step);
        log_approx -= log_step;

        while (log_approx > 0) {
            int32_t log_step = (log_approx <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                       log_approx :
                                       LargeScalingFactorConstants::MAX_LOG_STEP;
            auto int_step = RnsPoly::Integer(1) << log_step;
            std::vector<RnsPoly::Integer> crt_sf(num_towers, int_step);
            crt_approx = CKKSPackedEncoding::crt_mult(crt_approx, crt_sf, moduli);
            log_approx -= log_step;
        }
        factors = CKKSPackedEncoding::crt_mult(factors, crt_approx, moduli);
    }

    return factors;
}

#endif

Ciphertext<RnsPoly> CkksRnsLeveledShe::eval_fast_rotation_ext(
        ConstCiphertext<RnsPoly>& ciphertext, uint32_t index, const std::shared_ptr<std::vector<RnsPoly>> digits,
        bool add_first, const std::map<uint32_t, EvalKey<RnsPoly>>& eval_keys) const {
    //  if (index == 0) {
    //    Ciphertext<RnsPoly> result = ciphertext->clone();
    //    return result;
    //  }

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    const uint32_t M = crypto_params->get_element_params()->get_cyclotomic_order();

    // Find the automorphism index that corresponds to rotation index index.
    const uint32_t auto_index = find_automorphism_index2n_complex(index, M);

    // Retrieve the automorphism key that corresponds to the auto index.
    auto eval_key_iterator = eval_keys.find(auto_index);
    if (eval_key_iterator == eval_keys.end())
        CIPHER_THROW("EvalKey for index [" + std::to_string(auto_index) + "] is not found.");
    auto& eval_key = eval_key_iterator->second;

    const auto& cv = ciphertext->get_elements();
    const auto params_ql = cv[0].get_params();

    const auto cc = ciphertext->get_crypto_context();
    auto c_tilda = cc->get_scheme()->eval_fast_key_switch_core_ext(digits, eval_key, params_ql);

    if (add_first) {
        RnsPoly psi_c0(c_tilda[0].get_params(), Format::EVALUATION, true);
        auto c_mult = cv[0].times_no_check(crypto_params->get_p_modq());

        const uint32_t size_ql = params_ql->get_params().size();
        for (uint32_t i = 0; i < size_ql; ++i)
            psi_c0.set_element_at_index(i, std::move(c_mult.get_element_at_index(i)));

        c_tilda[0] += psi_c0;
    }

    const uint32_t N = crypto_params->get_element_params()->get_ring_dimension();
    std::vector<uint32_t> vec(N);
    precompute_auto_map(N, auto_index, &vec);

    c_tilda[0] = c_tilda[0].automorphism_transform(auto_index, vec);
    c_tilda[1] = c_tilda[1].automorphism_transform(auto_index, vec);

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(c_tilda));
    return result;
}

Ciphertext<RnsPoly> CkksRnsLeveledShe::mult_by_integer(ConstCiphertext<RnsPoly>& ciphertext, uint64_t integer) const {
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();

    std::vector<RnsPoly> result_dcrt;
    result_dcrt.reserve(cv.size());
    for (const auto& elem : cv)
        result_dcrt.push_back(elem.Times(NativeInteger(integer)));

    auto result = ciphertext->clone_empty();
    result->set_elements(std::move(result_dcrt));
    return result;
}

void CkksRnsLeveledShe::mult_by_integer_in_place(Ciphertext<RnsPoly>& ciphertext, uint64_t integer) const {
    auto& cv = ciphertext->get_elements();
    for (uint32_t i = 0; i < cv.size(); ++i)
        cv[i] = cv[i].Times(NativeInteger(integer));
}

void CkksRnsLeveledShe::adjust_levels_and_depth_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                         Ciphertext<RnsPoly>& ciphertext2) const {
    const uint32_t c1lvl = ciphertext1->get_level();
    const uint32_t c2lvl = ciphertext2->get_level();
    const uint32_t c1depth = ciphertext1->get_noise_scale_deg();
    const uint32_t c2depth = ciphertext2->get_noise_scale_deg();
    const uint32_t size_ql1 = ciphertext1->get_elements()[0].get_num_of_elements();
    const uint32_t size_ql2 = ciphertext2->get_elements()[0].get_num_of_elements();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext1->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();

    const auto scal_tech = crypto_params->get_scaling_technique();
    if ((scal_tech == FIXEDMANUAL || scal_tech == FIXEDAUTO) && c1depth == c2depth) {
        // The FIXED techniques use the scaling factor Delta at every level, so operands of equal noise scale
        // degree only have to agree on the number of towers: both carry the same power of Delta, and the
        // eventual rescale divides both by the same dropped prime. Multiplying by Delta and rescaling instead
        // (the FLEXIBLE* maneuver below) would leave a Delta / q_l residual on the value and spend a scalar
        // multiplication and a rescale for nothing.
        if (c1lvl < c2lvl)
            level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl);
        else if (c2lvl < c1lvl)
            level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl);
        return;
    }

    if (scal_tech == FIXEDAUTO) {
        // A noise scale degree mismatch under FIXEDAUTO (equal degrees were handled above). A degree-2
        // ciphertext is rescaled when the other operand has degree 1 and more towers dropped; otherwise the
        // degree-1 ciphertext is multiplied by the modulus of the target's last tower, which the eventual
        // rescale divides out exactly. A degree mismatch under FIXEDMANUAL is left to the general path below.
        auto raise_degree = [&](Ciphertext<RnsPoly>& ciphertext, const Ciphertext<RnsPoly>& target) {
            const auto& target_poly = target->get_elements()[0];
            const auto q = target_poly.get_element_at_index(target_poly.get_num_of_elements() - 1).get_modulus();
            const auto& polys = ciphertext->get_elements()[0].get_all_elements();
            std::vector<RnsPoly::Integer> crt_q(polys.size());
            for (uint32_t i = 0; i < polys.size(); ++i)
                crt_q[i] = q.mod(polys[i].get_modulus());
            for (auto& element : ciphertext->get_elements())
                element = element.Times(crt_q);
            ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);
            ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() *
                                           crypto_params->get_scaling_factor_real(ciphertext->get_level()));
        };
        if (c1lvl == c2lvl) {
            if (c1depth < c2depth)
                raise_degree(ciphertext1, ciphertext2);
            else
                raise_degree(ciphertext2, ciphertext1);
            return;
        }
        auto& lower = (c1lvl < c2lvl) ? ciphertext1 : ciphertext2;
        auto& higher = (c1lvl < c2lvl) ? ciphertext2 : ciphertext1;
        if (lower->get_noise_scale_deg() == 2)
            mod_reduce_internal_in_place(lower, BASE_NUM_LEVELS_TO_DROP);
        else
            raise_degree(lower, higher);
        if (lower->get_level() < higher->get_level())
            level_reduce_internal_in_place(lower, higher->get_level() - lower->get_level());
        return;
    }

    if (c1lvl < c2lvl) {
        if (c1depth == 2) {
            if (c2depth == 2) {
                double scf1 = ciphertext1->get_scaling_factor();
                double scf2 = ciphertext2->get_scaling_factor();
                double scf = crypto_params->get_scaling_factor_real(c1lvl);
                double q1 = crypto_params->get_mod_reduce_factor(size_ql1 - 1);
                for (uint32_t j = 1; j < composite_degree; ++j)
                    q1 *= crypto_params->get_mod_reduce_factor(size_ql1 - j - 1);
                eval_mult_core_in_place(ciphertext1, scf2 / scf1 * q1 / scf);
                mod_reduce_internal_in_place(ciphertext1, composite_degree);
                if (c1lvl + composite_degree < c2lvl)
                    level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - composite_degree);
                ciphertext1->set_scaling_factor(ciphertext2->get_scaling_factor());
            } else {
                if (c1lvl + composite_degree == c2lvl) {
                    mod_reduce_internal_in_place(ciphertext1, composite_degree);
                } else {
                    double scf1 = ciphertext1->get_scaling_factor();
                    double scf2 = crypto_params->get_scaling_factor_real_big(c2lvl - composite_degree);
                    double scf = crypto_params->get_scaling_factor_real(c1lvl);
                    double q1 = crypto_params->get_mod_reduce_factor(size_ql1 - 1);
                    for (uint32_t j = 1; j < composite_degree; ++j)
                        q1 *= crypto_params->get_mod_reduce_factor(size_ql1 - j - 1);
                    eval_mult_core_in_place(ciphertext1, scf2 / scf1 * q1 / scf);
                    mod_reduce_internal_in_place(ciphertext1, composite_degree);
                    if (c1lvl + 2 * composite_degree < c2lvl)
                        level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - 2 * composite_degree);
                    mod_reduce_internal_in_place(ciphertext1, composite_degree);
                    ciphertext1->set_scaling_factor(ciphertext2->get_scaling_factor());
                }
            }
        } else {
            if (c2depth == 2) {
                double scf1 = ciphertext1->get_scaling_factor();
                double scf2 = ciphertext2->get_scaling_factor();
                double scf = crypto_params->get_scaling_factor_real(c1lvl);
                eval_mult_core_in_place(ciphertext1, scf2 / scf1 / scf);
                level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl);
                ciphertext1->set_scaling_factor(scf2);
            } else {
                double scf1 = ciphertext1->get_scaling_factor();
                double scf2 = crypto_params->get_scaling_factor_real_big(c2lvl - composite_degree);
                double scf = crypto_params->get_scaling_factor_real(c1lvl);
                eval_mult_core_in_place(ciphertext1, scf2 / scf1 / scf);
                if (c1lvl + composite_degree < c2lvl)
                    level_reduce_internal_in_place(ciphertext1, c2lvl - c1lvl - composite_degree);
                mod_reduce_internal_in_place(ciphertext1, composite_degree);
                ciphertext1->set_scaling_factor(ciphertext2->get_scaling_factor());
            }
        }
    } else if (c1lvl > c2lvl) {
        if (c2depth == 2) {
            if (c1depth == 2) {
                double scf2 = ciphertext2->get_scaling_factor();
                double scf1 = ciphertext1->get_scaling_factor();
                double scf = crypto_params->get_scaling_factor_real(c2lvl);
                double q2 = crypto_params->get_mod_reduce_factor(size_ql2 - 1);
                for (uint32_t j = 1; j < composite_degree; ++j)
                    q2 *= crypto_params->get_mod_reduce_factor(size_ql2 - j - 1);
                eval_mult_core_in_place(ciphertext2, scf1 / scf2 * q2 / scf);
                mod_reduce_internal_in_place(ciphertext2, composite_degree);
                if (c2lvl + composite_degree < c1lvl)
                    level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - composite_degree);
                ciphertext2->set_scaling_factor(ciphertext1->get_scaling_factor());
            } else {
                if (c2lvl + composite_degree == c1lvl) {
                    mod_reduce_internal_in_place(ciphertext2, composite_degree);
                } else {
                    double scf2 = ciphertext2->get_scaling_factor();
                    double scf1 = crypto_params->get_scaling_factor_real_big(c1lvl - composite_degree);
                    double scf = crypto_params->get_scaling_factor_real(c2lvl);
                    double q2 = crypto_params->get_mod_reduce_factor(size_ql2 - 1);
                    for (uint32_t j = 1; j < composite_degree; ++j)
                        q2 *= crypto_params->get_mod_reduce_factor(size_ql2 - j - 1);
                    eval_mult_core_in_place(ciphertext2, scf1 / scf2 * q2 / scf);
                    mod_reduce_internal_in_place(ciphertext2, composite_degree);
                    if (c2lvl + 2 * composite_degree < c1lvl)
                        level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - 2 * composite_degree);
                    mod_reduce_internal_in_place(ciphertext2, composite_degree);
                    ciphertext2->set_scaling_factor(ciphertext1->get_scaling_factor());
                }
            }
        } else {
            if (c1depth == 2) {
                double scf2 = ciphertext2->get_scaling_factor();
                double scf1 = ciphertext1->get_scaling_factor();
                double scf = crypto_params->get_scaling_factor_real(c2lvl);
                eval_mult_core_in_place(ciphertext2, scf1 / scf2 / scf);
                level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl);
                ciphertext2->set_scaling_factor(scf1);
            } else {
                double scf2 = ciphertext2->get_scaling_factor();
                double scf1 = crypto_params->get_scaling_factor_real_big(c1lvl - composite_degree);
                double scf = crypto_params->get_scaling_factor_real(c2lvl);
                eval_mult_core_in_place(ciphertext2, scf1 / scf2 / scf);
                if (c2lvl + composite_degree < c1lvl)
                    level_reduce_internal_in_place(ciphertext2, c1lvl - c2lvl - composite_degree);
                mod_reduce_internal_in_place(ciphertext2, composite_degree);
                ciphertext2->set_scaling_factor(ciphertext1->get_scaling_factor());
            }
        }
    } else {
        if (c1depth < c2depth) {
            eval_mult_core_in_place(ciphertext1, 1.0);
        } else if (c2depth < c1depth) {
            eval_mult_core_in_place(ciphertext2, 1.0);
        }
    }
}

void CkksRnsLeveledShe::adjust_levels_and_depth_to_one_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                                                Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_levels_and_depth_in_place(ciphertext1, ciphertext2);

    if (ciphertext1->get_noise_scale_deg() == 2) {
        const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext1->get_crypto_parameters());
        mod_reduce_internal_in_place(ciphertext1, crypto_params->get_composite_degree());
        if (ciphertext2 != ciphertext1)
            mod_reduce_internal_in_place(ciphertext2, crypto_params->get_composite_degree());
    }
}

void CkksRnsLeveledShe::eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, double operand) const {
    auto& cv = ciphertext->get_elements();
    auto factors = get_element_for_eval_mult(ciphertext, operand);
    for (uint32_t i = 0; i < cv.size(); ++i)
        cv[i] = cv[i] * factors;

    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);

    auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    double sc_factor = crypto_params->get_scaling_factor_real(ciphertext->get_level());
    ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() * sc_factor);
}

void CkksRnsLeveledShe::eval_mult_core_in_place(Ciphertext<RnsPoly>& ciphertext, std::complex<double> operand) const {
    auto& cv = ciphertext->get_elements();

    // mult_by_monomial_in_place
    const auto& elem_params = cv[0].get_params();
    NativePoly monomial(elem_params->get_params()[0], Format::COEFFICIENT, true);
    monomial[elem_params->get_cyclotomic_order() >> 2] = NativeInteger(1);

    RnsPoly monomial_dcrt(elem_params, Format::COEFFICIENT, true);
    monomial_dcrt = monomial;
    monomial_dcrt.set_format(Format::EVALUATION);

    auto factors_re = get_element_for_eval_mult(ciphertext, operand.real());
    auto factors_im = monomial_dcrt * get_element_for_eval_mult(ciphertext, operand.imag());

    for (uint32_t i = 0; i < cv.size(); ++i)
        cv[i] = (cv[i] * factors_re) + (cv[i] * factors_im);

    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + 1);

    auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());
    double sc_factor = crypto_params->get_scaling_factor_real(ciphertext->get_level());
    ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() * sc_factor);
}

uint32_t CkksRnsLeveledShe::find_automorphism_index(uint32_t index, uint32_t m) const {
    return find_automorphism_index2n_complex(index, m);
}

}  // namespace cipher
