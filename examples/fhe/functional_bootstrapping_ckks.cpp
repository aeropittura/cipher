//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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
  Examples for functional bootstrapping for RLWE ciphertexts using CKKS.
 */

#include <algorithm>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <utility>
#include <vector>

#include "cipher/math/hermite.h"
#include "cipher/cipher.h"
#include "cipher/fhe/schemelet/rlwe_mp.h"

using namespace cipher;

const BigInteger QBFVINIT(BigInteger(1) << 60);
const BigInteger QBFVINITLARGE(BigInteger(1) << 80);

void arbitrary_lut(BigInteger qbfv_init, BigInteger p_input, BigInteger p_output, BigInteger Q, BigInteger bigq,
                  uint64_t scale_thi, size_t order, uint32_t num_slots, uint32_t ring_dim,
                  std::function<int64_t(int64_t)> func);
void multi_value_bootstrapping(BigInteger qbfv_init, BigInteger p_input, BigInteger p_output, BigInteger Q, BigInteger bigq,
                             uint64_t scale_thi, size_t order, uint32_t num_slots, uint32_t ring_dim,
                             uint32_t level_computation);
void multi_precision_sign(BigInteger qbfv_init, BigInteger p_input, BigInteger p_digit, BigInteger Q, BigInteger bigq,
                        uint64_t scale_thi, uint64_t scale_step_thi, size_t order, uint32_t num_slots, uint32_t ring_dim);

int main() {
    std::cerr << "\n*1.* Compute the function (x % PInput - POutput / 2) % POutput." << std::endl << std::endl;
    // Boolean LUT
    std::cerr << "=====Boolean LUT order 1 sparsely packed=====" << std::endl << std::endl;
    arbitrary_lut(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 1, 8, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    std::cerr << "=====Boolean LUT order 2 sparsely packed=====" << std::endl << std::endl;
    arbitrary_lut(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 2, 8, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    std::cerr << "=====Boolean LUT order 1 fully packed=====" << std::endl << std::endl;
    arbitrary_lut(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 1, 1024, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    // LUT with 8-bit input and 4-bit output
    std::cerr << "=====8-to-4 bit LUT order 1 sparsely packed=====" << std::endl << std::endl;
    arbitrary_lut(QBFVINIT, BigInteger(256), BigInteger(16), (BigInteger(1) << 47), (BigInteger(1) << 47), 32, 1, 8,
                 4096, [](int64_t x) { return (x % 256 - 16 / 2) % 16; });

    std::cerr << "\n\n*2.* Compute multiple functions over the same ciphertext." << std::endl << std::endl;
    // Two LUTs with 8-bit input and 8-bit output and intermediate leveled computations
    std::cerr << "=====Multivalue bootstrapping for two 8-to-8 bit LUTs order 1 fully packed=====" << std::endl
              << std::endl;
    multi_value_bootstrapping(QBFVINIT, BigInteger(256), BigInteger(256), (BigInteger(1) << 47), (BigInteger(1) << 47),
                            32, 1, 256, 2048, 1);

    std::cerr << "\n\n*3.* Homomorphically evaluate the sign." << std::endl << std::endl;
    // Compute the sign of a 12-bit input using 1-bit and 4-bit digits
    // The following needs to hold true: log2(p_input) - log2(p_digit) = log2(Q) - log2(Bigq)
    std::cerr << "=====Sign evaluation of a 12-bit input using 1-bit digits order 1 sparsely packed=====" << std::endl
              << std::endl;
    multi_precision_sign(QBFVINIT, BigInteger(4096), BigInteger(2), (BigInteger(1) << 46), (BigInteger(1) << 35), 1, 1, 1,
                       32, 2048);
    std::cerr << "=====Sign evaluation of a 12-bit input using 4-bit digits order 1 fully packed=====" << std::endl
              << std::endl;
    multi_precision_sign(QBFVINIT, BigInteger(4096), BigInteger(16), (BigInteger(1) << 48), (BigInteger(1) << 40), 32, 8,
                       1, 64, 2048);
    std::cerr << "=====Sign evaluation of a 32-bit input using 8-bit digits order 1 fully packed=====" << std::endl
              << std::endl;
    multi_precision_sign(QBFVINITLARGE, BigInteger(1) << 32, BigInteger(256), BigInteger(1) << 71, BigInteger(1) << 47,
                       256, 32, 1, 64, 2048);

    return 0;
}

void arbitrary_lut(BigInteger qbfv_init, BigInteger p_input, BigInteger p_output, BigInteger Q, BigInteger bigq,
                  uint64_t scale_thi, size_t order, uint32_t num_slots, uint32_t ring_dim,
                  std::function<int64_t(int64_t)> func) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * num_slots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flag_sp = (num_slots <= ring_dim / 2);  // sparse packing
    auto num_slots_ckks = flag_sp ? num_slots : num_slots / 2;

    /* 2. Input */
    std::vector<int64_t> x = {
            (p_input.convert_to_int<int64_t>() / 2), (p_input.convert_to_int<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (p_input.convert_to_int<int64_t>() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << num_slots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < num_slots)
        x = Fill<int64_t>(x, num_slots);

    /* 3. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binary_lut = (p_input.convert_to_int() == 2) && (order == 1);

    if (binary_lut) {
        coeffint = {
                func(1),
                func(0) -
                        func(1)};  // those are coefficients for [1, cos^2(pi x)], not [1, cos(2pi x)] as in the general case.
    } else {
        coeffcomp = get_hermite_trig_coefficients(func, p_input.convert_to_int(), order, scale_thi);  // divided by 2
    }

    /* 4. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
     * The secret key distribution for CKKS should be SPARSE_ENCAPSULATED (recommended; probability of
     * failure below 2^-128), UNIFORM_TERNARY (if uniform ternary secrets are required for compliance with
     * security guidelines; probability of failure 2^-73 for N = 2^16 and 2^-30 for N = 2^17 with full
     * packing, at the cost of 5 more levels of multiplicative depth and larger scaling factors), or
     * SPARSE_TERNARY (discouraged; about 2^-23 for N = 2^16, but less noise).
     * The supported rescaling techniques are FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT,
     * COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL.
     * The FLEXIBLEAUTO and FLEXIBLEAUTOEXT techniques track the exact level-specific scaling factors,
     * hence they yield less noise than the FIXED* techniques for the same parameters.
     */
    uint32_t dcrt_bits = bigq.get_msb() - 1;
    uint32_t first_mod = bigq.get_msb() - 1;
    uint32_t levels_available_after_bootstrap = 0;
    uint32_t levels_available_before_bootstrap = 0;
    uint32_t dnum = 3;
    SecretKeyDist secret_key_dist = SPARSE_ENCAPSULATED;
    ScalingTechnique scal_tech = FLEXIBLEAUTO;
    std::vector<uint32_t> lvlb = {3, 3};

    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(scal_tech);
    parameters.set_first_mod_size(first_mod);
    parameters.set_num_large_digits(dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(ring_dim);

    uint32_t depth = levels_available_after_bootstrap;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffint, p_input, order, secret_key_dist);
    else
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffcomp, p_input, order, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << ", a multiplicative depth of "
              << depth << " and the " << scal_tech << " rescaling technique" << std::endl
              << std::endl;

    /* 5. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    auto key_pair = cc->key_gen();

    if (binary_lut)
        cc->eval_fbt_setup(coeffint, num_slots_ckks, p_input, p_output, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, 0, order);
    else
        cc->eval_fbt_setup(coeffcomp, num_slots_ckks, p_input, p_output, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, 0, order);

    cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
    cc->eval_mult_key_gen(key_pair.secret_key);

    /* 6. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth - (levels_available_before_bootstrap > 0));

    auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, qbfv_init, p_input, key_pair.secret_key, ep);

    SchemeletRlweMp::mod_switch(ctxt_bfv, Q, qbfv_init);

    /* 7. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
     */
    auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, bigq, num_slots_ckks,
                                                   depth - (levels_available_before_bootstrap > 0));

    /* 8. Apply the LUT over the ciphertext.
     */
    Ciphertext<RnsPoly> ctxt_after_fbt;
    if (binary_lut)
        ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, p_input.get_msb() - 1, ep->get_modulus(), scale_thi, 0, order);
    else
        ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, p_input.get_msb() - 1, ep->get_modulus(), scale_thi, 0, order);

    /* 9. Convert the result back to RLWE.
     */
    auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, Q);

    auto computed = SchemeletRlweMp::decrypt_coeff(polys, Q, p_output, key_pair.secret_key, ep, num_slots_ckks, num_slots);

    std::cerr << "First 8 elements of the obtained output % POutput: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
        return (func(elem) > p_output.convert_to_double() / 2.) ? func(elem) - p_output.convert_to_int() : func(elem);
    });

    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
    std::transform(exact.begin(), exact.end(), exact.begin(),
                   [&](int64_t elem) { return (std::abs(elem)) % (p_output.convert_to_int()); });
    auto max_error_it = std::max_element(exact.begin(), exact.end());
    std::cerr << "Max absolute error obtained: " << *max_error_it << std::endl << std::endl;
}

void multi_value_bootstrapping(BigInteger qbfv_init, BigInteger p_input, BigInteger p_output, BigInteger Q, BigInteger bigq,
                             uint64_t scale_thi, size_t order, uint32_t num_slots, uint32_t ring_dim,
                             uint32_t levels_computation) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * num_slots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flag_sp = (num_slots <= ring_dim / 2);  // sparse packing
    auto num_slots_ckks = flag_sp ? num_slots : num_slots / 2;

    /* 2. Distinct functions to compute over the same input. */
    auto a = p_input.convert_to_int<int64_t>();
    auto b = p_output.convert_to_int<int64_t>();
    auto func1 = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    auto func2 = [a, b](int64_t x) -> int64_t {
        return (x % a) % b;
    };

    /* 3. Input */
    std::vector<int64_t> x = {
            (p_input.convert_to_int<int64_t>() / 2), (p_input.convert_to_int<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (p_input.convert_to_int<int64_t>() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << num_slots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < num_slots)
        x = Fill<int64_t>(x, num_slots);

    /* 4. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffint1;
    std::vector<int64_t> coeffint2;
    std::vector<std::complex<double>> coeffcomp1;
    std::vector<std::complex<double>> coeffcomp2;
    bool binary_lut = (p_input.convert_to_int() == 2) && (order == 1);

    if (binary_lut) {
        coeffint1 = {func1(1), func1(0) - func1(1)};
        coeffint2 = {func2(1), func2(0) - func2(1)};
    } else {
        coeffcomp1 = get_hermite_trig_coefficients(func1, p_input.convert_to_int(), order, scale_thi);
        coeffcomp2 = get_hermite_trig_coefficients(func2, p_input.convert_to_int(), order, scale_thi);
    }

    /* 5. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
     * The secret key distribution for CKKS should be SPARSE_ENCAPSULATED (recommended; probability of
     * failure below 2^-128), UNIFORM_TERNARY (if uniform ternary secrets are required for compliance with
     * security guidelines; probability of failure 2^-73 for N = 2^16 and 2^-30 for N = 2^17 with full
     * packing, at the cost of 5 more levels of multiplicative depth and larger scaling factors), or
     * SPARSE_TERNARY (discouraged; about 2^-23 for N = 2^16, but less noise).
     * The supported rescaling techniques are FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT,
     * COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL.
     * The FLEXIBLEAUTO and FLEXIBLEAUTOEXT techniques track the exact level-specific scaling factors,
     * hence they yield less noise than the FIXED* techniques for the same parameters.
     */
    uint32_t dcrt_bits = bigq.get_msb() - 1;
    uint32_t first_mod = bigq.get_msb() - 1;
    uint32_t levels_available_after_bootstrap = 0;
    uint32_t levels_available_before_bootstrap = 0;
    uint32_t dnum = 3;
    SecretKeyDist secret_key_dist = SPARSE_ENCAPSULATED;
    ScalingTechnique scal_tech = FIXEDMANUAL;
    std::vector<uint32_t> lvlb = {3, 3};

    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(scal_tech);
    parameters.set_first_mod_size(first_mod);
    parameters.set_num_large_digits(dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(ring_dim);

    uint32_t depth = levels_available_after_bootstrap + levels_computation;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffint1, p_input, order, secret_key_dist);
    else
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffcomp1, p_input, order, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << ", a multiplicative depth of "
              << depth << " and the " << scal_tech << " rescaling technique" << std::endl
              << std::endl;

    /* 6. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    auto key_pair = cc->key_gen();

    if (binary_lut)
        cc->eval_fbt_setup(coeffint1, num_slots_ckks, p_input, p_output, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, levels_computation, order);
    else
        cc->eval_fbt_setup(coeffcomp1, num_slots_ckks, p_input, p_output, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, levels_computation, order);

    cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);
    cc->eval_mult_key_gen(key_pair.secret_key);
    cc->eval_at_index_key_gen(key_pair.secret_key, std::vector<int32_t>({-2}));

    auto mask_real = Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, num_slots);

    // The mask level is counted on the full modulus chain, which has an extra modulus for FLEXIBLEAUTOEXT
    const uint32_t ext_off = (scal_tech == FLEXIBLEAUTOEXT) ? 1 : 0;

    // Note that the corresponding plaintext mask for full packing can be just real, as real times complex multiplies both real and imaginary parts
    Plaintext ptxt_mask = cc->make_ckks_packed_plaintext(
            Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, num_slots_ckks), 1,
            depth + ext_off - lvlb[1] - levels_available_after_bootstrap - levels_computation, nullptr, num_slots_ckks);

    /* 7. When leveled computations (multiplications, rotations) are desired to be performed while in
     * slot-packed CKKS (before returning to RLWE coefficient packing), and the FFT method is used
     * for the homomorphic encoding and decoding during functional bootstrapping, the inputs in RLWE
     * should be encoded in a bit reversed order. This bit reverse order will be cancelled during
     * the homomorphic encoding, therefore the slots in CKKS will be in natural order.
     * Both the RLWE encryption and RLWE decryption should specify this flag.
     */
    bool flag_br = (lvlb[0] != 1 || lvlb[1] != 1);

    /* 8. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth - (levels_available_before_bootstrap > 0));

    auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, qbfv_init, p_input, key_pair.secret_key, ep, flag_br);

    SchemeletRlweMp::mod_switch(ctxt_bfv, Q, qbfv_init);

    /* 9. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
     */
    auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, ctxt_bfv, key_pair.public_key, bigq, num_slots_ckks,
                                                   depth - (levels_available_before_bootstrap > 0));

    /* 10. Apply the LUTs over the ciphertext.
     * First, compute the complex exponential and its powers to reuse.
     * Second, apply multiple LUTs over these powers. All LUTs which reuse the precomputations must be interpolated
     * with the same shape (same p_input and order) as the coefficients used for the precomputation.
     */
    std::vector<Ciphertext<RnsPoly>> complex_exp;
    Ciphertext<RnsPoly> ctxt_after_fbt1, ctxt_after_fbt2;

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
        return (func1(elem) > p_output.convert_to_double() / 2.) ? func1(elem) - p_output.convert_to_int() : func1(elem);
    });

    auto exact2(x);
    std::transform(x.begin(), x.end(), exact2.begin(), [&](int64_t elem) {
        return (func2(elem) > p_output.convert_to_double() / 2.) ? func2(elem) - p_output.convert_to_int() : func2(elem);
    });

    if (binary_lut) {
        auto complex_exp_powers = cc->eval_mvb_precompute(ctxt, coeffint1, p_input.get_msb() - 1, ep->get_modulus(), order);

        ctxt_after_fbt1 =
                cc->eval_mvb(complex_exp_powers, coeffint1, p_input.get_msb() - 1, scale_thi, levels_computation, order);

        ctxt_after_fbt2 = cc->eval_mvb_no_decoding(complex_exp_powers, coeffint2, p_input.get_msb() - 1, order);

        // Apply a rotation
        ctxt_after_fbt2 = cc->eval_rotate(ctxt_after_fbt2, -2);
        exact2 = flag_sp ? Rotate(exact2, -2) : rotate_two_halves(exact2, -2);

        // Apply a multiplicative mask
        ctxt_after_fbt2 = cc->eval_mult(ctxt_after_fbt2, ptxt_mask);
        cc->mod_reduce_in_place(ctxt_after_fbt2);

        std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

        // Back to coefficient encoding
        ctxt_after_fbt2 = cc->eval_hom_decoding(ctxt_after_fbt2, scale_thi, levels_computation - 1);
    } else {
        auto complex_exp_powers = cc->eval_mvb_precompute(ctxt, coeffcomp1, p_input.get_msb() - 1, ep->get_modulus(), order);

        ctxt_after_fbt1 =
                cc->eval_mvb(complex_exp_powers, coeffcomp1, p_input.get_msb() - 1, scale_thi, levels_computation, order);

        ctxt_after_fbt2 = cc->eval_mvb_no_decoding(complex_exp_powers, coeffcomp2, p_input.get_msb() - 1, order);

        // Apply a rotation
        ctxt_after_fbt2 = cc->eval_rotate(ctxt_after_fbt2, -2);
        exact2 = flag_sp ? Rotate(exact2, -2) : rotate_two_halves(exact2, -2);

        // Apply a multiplicative mask
        ctxt_after_fbt2 = cc->eval_mult(ctxt_after_fbt2, ptxt_mask);
        cc->mod_reduce_in_place(ctxt_after_fbt2);

        std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

        // Back to coefficient encoding

        ctxt_after_fbt2 = cc->eval_hom_decoding(ctxt_after_fbt2, scale_thi, levels_computation - 1);
    }

    auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt1, Q);

    /* 11. Convert the results back to RLWE.
     */
    auto computed =
            SchemeletRlweMp::decrypt_coeff(polys, Q, p_output, key_pair.secret_key, ep, num_slots_ckks, num_slots, flag_br);

    std::cerr << "First 8 elements of the obtained output = (input % PInput - POutput / 2) % POutput: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
    std::transform(exact.begin(), exact.end(), exact.begin(),
                   [&](int64_t elem) { return (std::abs(elem)) % (p_output.convert_to_int()); });
    auto max_error_it = std::max_element(exact.begin(), exact.end());
    std::cerr << "Max absolute error obtained in the first LUT: " << *max_error_it << std::endl << std::endl;

    polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt2, Q);

    computed = SchemeletRlweMp::decrypt_coeff(polys, Q, p_output, key_pair.secret_key, ep, num_slots_ckks, num_slots, flag_br);

    std::cerr << "First 8 elements of the obtained output = (input % PInput) % POutput, rotated by -2 and masked: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    std::transform(exact2.begin(), exact2.end(), computed.begin(), exact2.begin(), std::minus<int64_t>());
    std::transform(exact2.begin(), exact2.end(), exact2.begin(),
                   [&](int64_t elem) { return (std::abs(elem)) % (p_output.convert_to_int()); });
    max_error_it = std::max_element(exact2.begin(), exact2.end());
    std::cerr << "Max absolute error obtained in the second LUT: " << *max_error_it << std::endl << std::endl;
}

void multi_precision_sign(BigInteger qbfv_init, BigInteger p_input, BigInteger p_digit, BigInteger Q, BigInteger bigq,
                        uint64_t scale_thi, uint64_t scale_step_thi, size_t order, uint32_t num_slots, uint32_t ring_dim) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * num_slots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flag_sp = (num_slots <= ring_dim / 2);  // sparse packing
    auto num_slots_ckks = flag_sp ? num_slots : num_slots / 2;

    /* 2. Functions necessary for the sign evaluation. */
    auto a = p_input.convert_to_int<int64_t>();
    auto b = p_digit.convert_to_int<int64_t>();

    auto func_mod = [b](int64_t x) -> int64_t {
        return (x % b);
    };
    auto func_step = [a, b](int64_t x) -> int64_t {
        return (x % a) >= (b / 2);
    };

    /* 3. Input. */
    std::vector<int64_t> x = {static_cast<int64_t>(p_input.convert_to_int() / 2),
                              static_cast<int64_t>(p_input.convert_to_int() / 2) + 1,
                              0,
                              3,
                              16,
                              33,
                              64,
                              static_cast<int64_t>(p_input.convert_to_int() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << num_slots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < num_slots)
        x = Fill<int64_t>(x, num_slots);

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(),
                   [&](int64_t elem) { return (elem >= p_input.convert_to_double() / 2.); });

    /* 4. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffint_mod;
    std::vector<std::complex<double>> coeffcomp_mod;
    std::vector<std::complex<double>> coeffcomp_step;
    bool binary_lut = (p_digit.convert_to_int() == 2) && (order == 1);

    if (binary_lut) {
        coeffint_mod = {func_mod(1), func_mod(0) - func_mod(1)};
    } else {
        coeffcomp_mod = get_hermite_trig_coefficients(func_mod, p_digit.convert_to_int(), order, scale_thi);  // divided by 2
        coeffcomp_step = get_hermite_trig_coefficients(func_step, p_digit.convert_to_int(), order,
                                                   scale_step_thi);  // divided by 2
    }

    /* 5. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus corresponding to the digit.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
     * The secret key distribution for CKKS should be SPARSE_ENCAPSULATED (recommended; probability of
     * failure below 2^-128), UNIFORM_TERNARY (if uniform ternary secrets are required for compliance with
     * security guidelines; probability of failure 2^-73 for N = 2^16 and 2^-30 for N = 2^17 with full
     * packing, at the cost of 5 more levels of multiplicative depth and larger scaling factors), or
     * SPARSE_TERNARY (discouraged; about 2^-23 for N = 2^16, but less noise).
     * The supported rescaling techniques are FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT,
     * COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL.
     * The FLEXIBLEAUTO and FLEXIBLEAUTOEXT techniques track the exact level-specific scaling factors,
     * hence they yield less noise than the FIXED* techniques for the same parameters.
     */
    uint32_t dcrt_bits = bigq.get_msb() - 1;
    uint32_t first_mod = bigq.get_msb() - 1;
    uint32_t levels_available_after_bootstrap = 0;
    uint32_t levels_available_before_bootstrap = 0;
    uint32_t dnum = 3;
    SecretKeyDist secret_key_dist = SPARSE_ENCAPSULATED;
    ScalingTechnique scal_tech = FIXEDMANUAL;
    std::vector<uint32_t> lvlb = {3, 3};

    ContextParams<CkksRnsContext> parameters;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(scal_tech);
    parameters.set_first_mod_size(first_mod);
    parameters.set_num_large_digits(dnum);
    parameters.set_batch_size(num_slots_ckks);
    parameters.set_ring_dim(ring_dim);

    uint32_t depth = levels_available_after_bootstrap;
    if (binary_lut)
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffint_mod, p_digit, order, secret_key_dist);
    else
        depth += CkksRnsFhe::get_fbt_depth(lvlb, coeffcomp_mod, p_digit, order, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    auto key_pair = cc->key_gen();

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << ", a multiplicative depth of "
              << depth << " and the " << scal_tech << " rescaling technique" << std::endl
              << std::endl;

    /* 6. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    cc->eval_mult_key_gen(key_pair.secret_key);

    if (binary_lut)
        cc->eval_fbt_setup(coeffint_mod, num_slots_ckks, p_digit, p_input, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, 0, order);
    else
        cc->eval_fbt_setup(coeffcomp_mod, num_slots_ckks, p_digit, p_input, bigq, key_pair.public_key, {0, 0}, lvlb,
                         levels_available_after_bootstrap, 0, order);

    cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots_ckks);

    /* 7. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRlweMp::get_element_params(key_pair.secret_key, depth - (levels_available_before_bootstrap > 0));

    auto ctxt_bfv = SchemeletRlweMp::encrypt_coeff(x, qbfv_init, p_input, key_pair.secret_key, ep);

    SchemeletRlweMp::mod_switch(ctxt_bfv, Q, qbfv_init);
    uint32_t qbfv_bits = Q.get_msb() - 1;

    /* 8. Set up the sign loop parameters. */
    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    if (binary_lut)
        coeffint = coeffint_mod;
    else
        coeffcomp = coeffcomp_mod;

    const bool checkeq2 = p_digit.convert_to_int() == 2;
    const bool checkgt2 = p_digit.convert_to_int() > 2;
    const uint32_t p_digit_bits = p_digit.get_msb() - 1;

    BigInteger Q_new;
    BigInteger p_orig = p_input;

    bool step = false;
    bool go = qbfv_bits > dcrt_bits;
    size_t levels_to_drop = 0;
    uint32_t post_scaling_bits = 0;

    /* 9. Start the sign loop. For arbitrary digit size, pNew > 2, the last iteration needs
     * to evaluate step pNew not mod pNew.
     * Currently this only works when log(pNew) divides log(p).
     */
    while (go) {
        auto encrypted_digit = ctxt_bfv;

        /* 9.1. Apply mod Bigq to extract the digit and convert it from RLWE to CKKS. */
        encrypted_digit[0].switch_modulus(bigq, 1, 0, 0);
        encrypted_digit[1].switch_modulus(bigq, 1, 0, 0);

        auto ctxt = SchemeletRlweMp::convert_rlwe_to_ckks(*cc, encrypted_digit, key_pair.public_key, bigq, num_slots_ckks,
                                                       depth - (levels_available_before_bootstrap > 0));

        /* 9.2 Bootstrap the digit.*/
        Ciphertext<RnsPoly> ctxt_after_fbt;
        if (binary_lut)
            ctxt_after_fbt = cc->eval_fbt(ctxt, coeffint, p_digit_bits, ep->get_modulus(), scale_thi * (1 << post_scaling_bits),
                                       levels_to_drop, order);
        else
            ctxt_after_fbt = cc->eval_fbt(ctxt, coeffcomp, p_digit_bits, ep->get_modulus(), scale_thi * (1 << post_scaling_bits),
                                       levels_to_drop, order);

        /* 9.3 Convert the result back to RLWE and update the
         * plaintext and ciphertext modulus of the ciphertext for the next iteration.
         */
        auto polys = SchemeletRlweMp::convert_ckks_to_rlwe(ctxt_after_fbt, Q);

        if (!step) {
            /* 9.4 If not in the last iteration, subtract the digit from the ciphertext. */
            ctxt_bfv[0] = ctxt_bfv[0] - polys[0];
            ctxt_bfv[1] = ctxt_bfv[1] - polys[1];

            /* 9.5 Do modulus switching from Q to Q_new for the RLWE ciphertext. */
            Q_new = Q >> p_digit_bits;
            ctxt_bfv[0] = ctxt_bfv[0].multiply_and_round(Q_new, Q);
            ctxt_bfv[0].switch_modulus(Q_new, 1, 0, 0);
            ctxt_bfv[1] = ctxt_bfv[1].multiply_and_round(Q_new, Q);
            ctxt_bfv[1].switch_modulus(Q_new, 1, 0, 0);
            Q >>= p_digit_bits;
            p_input >>= p_digit_bits;
            qbfv_bits -= p_digit_bits;
            post_scaling_bits += p_digit_bits;
        } else {
            /* 9.6 If in the last iteration, return the digit. */
            ctxt_bfv[0] = std::move(polys[0]);
            ctxt_bfv[1] = std::move(polys[1]);
        }

        /* 9.7 If in the last iteration, decrypt and assess correctness. */
        go = qbfv_bits > dcrt_bits;
        if (step || (checkeq2 && !go)) {
            auto computed =
                    SchemeletRlweMp::decrypt_coeff(ctxt_bfv, Q, p_input, key_pair.secret_key, ep, num_slots_ckks, num_slots);

            std::cerr << "First 8 elements of the obtained sign: [";
            std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
            std::cerr << "]" << std::endl;

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (p_orig.convert_to_int()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            std::cerr << "\nMax absolute error obtained: " << *max_error_it << std::endl << std::endl;
        }

        /* 9.8 Determine whether it is the last iteration and if not, update the parameters for the next iteration. */
        if (checkgt2 && !go && !step) {
            if (!binary_lut)
                coeffcomp = coeffcomp_step;
            scale_thi = scale_step_thi;
            step = true;
            go = true;
            if (coeffcomp_mod.size() > 4 && get_multiplicative_depth_by_coeff_vector(coeffcomp_mod, true) >
                                                   get_multiplicative_depth_by_coeff_vector(coeffcomp_step, true)) {
                levels_to_drop = get_multiplicative_depth_by_coeff_vector(coeffcomp_mod, true) -
                               get_multiplicative_depth_by_coeff_vector(coeffcomp_step, true);
            }
        }
    }
}
