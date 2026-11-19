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
  Advanced examples CKKS
 */

// Define PROFILE to enable TIC-TOC timing measurements
#define PROFILE

#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void automatic_rescale_demo(ScalingTechnique scal_tech);
void manual_rescale_demo(ScalingTechnique scal_tech);
void hybrid_key_switching_demo1();
void hybrid_key_switching_demo2();
void fast_rotations_demo1();
void fast_rotations_demo2();

int main(int argc, char* argv[]) {
    /*
     * Our implementation of CKKS includes four rescaling methods called
     * "FIXEDMANUAL*, *FIXEDAUTO*, "FLEXIBLEAUTO", and "FLEXIBLEAUTOEXT".
     * THese rescaling methods are explained in the CKKS section of
     * https://eprint.iacr.org/2022/915.
     *
     * Before we start, we need to say a few words about the rescale
     * operation, which is central in CKKS. Whenever we multiply two
     * ciphertexts c1 and c2 which encrypt numbers m1*D and m2*D
     * respectively, we get a result that looks like m1*m2*D^2. Since the
     * scaling factor of this number is D^2, we say that the result is of
     * depth 2. It is clear that a ciphertext of depth 2 cannot be added
     * to ciphertexts of depth 1, because their scaling factors are
     * different. Rescaling takes a ciphertext of depth 2, and makes it of
     * depth 1 by an operation that looks a lot like dividing by D=2^p.
     *
     * For efficiency reasons, our implementation of CKKS works in the
     * RNS space, which means that we avoid working with big numbers and
     * we only work with native integers. One complication that arises
     * from this is that we can only rescale by dividing by certain prime
     * numbers and not D=2^p.
     *
     * There are two ways to deal with this. The first is to choose prime
     * numbers as close to 2^p as possible, and assume that the scaling
     * factor remains the same. This inevitably incurs some approximation
     * error, and there are two variants for this scenario: FLEXIBLEAUTO
     * and FLEXIBLEAUTOEXT.
     *
     * The second way of dealing with this is to track how the scaling
     * factor changes and try to adjust for it. This is what we do for the
     * FLEXIBLEAUTO and FLEXIBALEAUTOEXT variants of CKKS. The tradeoff is
     * that FLEXIBLEAUTO*    * computations are typically somewhat slower (based on our experience
     * the slowdown is around 5-35% depending on the complexity of the
     * computation), because of the adjustment of values that need to
     * take place.
     *
     * We have designed FLEXIBLEAUTO(EXT) so it hides all the nuances of
     * tracking the depth of ciphertexts and having to call the rescale
     * operation. Therefore, FLEXIBLEAUTO(EXT) is more appropriate for users
     * who do not want to get into the details of the underlying crypto
     * and math, or who want to put together a quick prototype. On the
     * contrary, FIXEDMANUAL is more appropriate for production
     * applications that have been optimized by experts.
     *
     * The first two parts of this demo implement the same computation, i.e, the function
     * f(x) = x^18 + x^9 + 1, using all four methods.
     *
     */
    automatic_rescale_demo(FLEXIBLEAUTO);
    // default
    automatic_rescale_demo(FLEXIBLEAUTOEXT);
    automatic_rescale_demo(FIXEDAUTO);
    manual_rescale_demo(FIXEDMANUAL);

    /*
     * Our implementation of CKKS supports two different algorithms
     * for key switching, namely BV and HYBRID. BV corresponds to
     * a technique also known as digit decomposition (both RNS and based
     * on a digit size). GHS (not implemented separately anymore) corresponds to ciphertext
     * modulus doubling, and HYBRID combines the characteristics of both
     * BV and GHS. Please refer to the documentation of key_switch_gen in
     * keyswitch-bv.h/cpp and keyswitch-hybrid.h/cpp for more
     * details about the different key switch techniques.
     *
     * For most cases, HYBRID will be the most appropriate and efficient
     * key switching technique, and this is why we devote the third and
     * fourth part of this demo to HYBRID key switching.
     */
    hybrid_key_switching_demo1();
    hybrid_key_switching_demo2();

    /*
     * The final parts of this demo showcase our implementation of an
     * optimization technique called hoisting. The idea is simple - when
     * we want to perform multiple different rotations to the same
     * ciphertext, we can compute one part of the rotation algorithm once,
     * and reuse it multiple times. Please refer to the documentation of
     * eval_fast_rotation_precompute in keyswitch-bv.h/cpp and keyswitch-hybrid.h/cpp
     * for more details on hoisting in BV and HYBRID key switching.
     */
    fast_rotations_demo1();
    fast_rotations_demo2();

    return 0;
}

void automatic_rescale_demo(ScalingTechnique scal_tech) {
    /* Please read comments in main() for an introduction to what the
     * rescale operation is. Knowing about rescale() is not necessary
     * to use the FLEXIBLEAUTO CKKS variant, it is however needed to
     * understand what's happening underneath.
     *
     * FLEXIBLEAUTO is a variant of CKKS that has two main features:
     * 1 - It automatically performs rescaling before every multiplication.
     *    This is done to make it easier for users to write FHE
     *    computations without worrying about the depth of ciphertexts
     *    or rescaling.
     * 2 - It tracks the exact scaling factor of all ciphertexts.
     *    This means that computations in FLEXIBLEAUTO will be more
     *    accurate than the same computations in FIXEDMANUAL. Keep
     *    in mind that this difference only becomes apparent when
     *    dealing with computations of large multiplicative depth; this
     *    is because a large multiplicative depth means we need to find
     *    more prime numbers sufficiently close to D=2^p, and this
     *    becomes harder and harder as the multiplicative depth
     *    increases.
     */
    if (scal_tech == FLEXIBLEAUTO) {
        std::cout << std::endl << std::endl << std::endl << " ===== FlexibleAutoDemo ============= " << std::endl;
    } else if (scal_tech == FLEXIBLEAUTOEXT) {
        std::cout << std::endl << std::endl << std::endl << " ===== FlexibleAutoExtDemo ============= " << std::endl;
    } else {
        std::cout << std::endl << std::endl << std::endl << " ===== FixedAutoDemo ============= " << std::endl;
    }

    uint32_t batch_size = 8;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(5);
    parameters.set_scaling_mod_size(50);
    parameters.set_scaling_technique(scal_tech);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(ptxt, keys.public_key);

    /* Computing f(x) = x^18 + x^9 + 1
     *
     * In the following we compute f(x) with a computation
     * that has a multiplicative depth of 5.
     *
     * The result is correct, even though there is no call to
     * the rescale() operation.
     */
    auto c2 = cc->eval_mult(c, c);                          // x^2
    auto c4 = cc->eval_mult(c2, c2);                        // x^4
    auto c8 = cc->eval_mult(c4, c4);                        // x^8
    auto c16 = cc->eval_mult(c8, c8);                       // x^16
    auto c9 = cc->eval_mult(c8, c);                         // x^9
    auto c18 = cc->eval_mult(c16, c2);                      // x^18
    auto c_res = cc->eval_add(cc->eval_add(c18, c9), 1.0);  // Final result

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(c_res, keys.secret_key, &result);
    result->set_length(batch_size);
    std::cout << "x^18 + x^9 + 1 = " << result << std::endl;

    /*
     * Users interested in how FLEXIBLEAUTO works under the
     * hood, are welcome to change the line below to "#if 1"
     * and observe the changes in scaling factors and depths.
     */

    // #if 0
    // const auto crypto_params_ckks =
    //     std::dynamic_pointer_cast<CkksRnsCryptoParams>(
    //         cc->get_crypto_parameters());

    // std::cout << std::fixed;
    // std::cout.precision(2);
    // // We have designed FLEXIBLEAUTO so that ciphertexts of a
    // // given level have a specific scaling factor.
    // std::cout << "\nScaling factors of levels: " << std::endl;
    // for (uint32_t i = 0; i < parameters.get_multiplicative_depth(); i++) {
    //   std::cout << "Level " << i << ": "
    //             << crypto_params_ckks->get_scaling_factor_real(i) << std::endl;
    // }

    // std::cout << std::endl;

    // // The initial ciphertext has level 0 and depth 1.
    // // One can use additional arguments in
    // // cc->make_ckks_packed_plaintext(x, depth, level) create
    // // plaintexts/ciphertexts at any desired depth/level.
    // // Also, in all of the following, notice that scaling
    // // factors change at every level and they match the
    // // ones printed above.
    // std::cout << "Ciphertext c:" << std::endl;
    // std::cout << "\t scaling factor: " << c->get_scaling_factor() << std::endl;
    // std::cout << "\t scaling factor degree: " << c->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c->get_level() << std::endl;

    // // Notice how the result of eval_mult(c,c) is of depth 2.
    // // This is because the Rescale operation is performed lazily,
    // // i.e., only when we want to multiply ciphertexts of depth > 1.
    // // Level is still 0 because no rescale operation has been run.
    // std::cout << "Ciphertext c2:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c2->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c2->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c2->get_level() << std::endl;

    // // Here, the c2 inputs where of depth 2, so they had to be rescaled
    // // before computing c4. Hence, the level has become 1. Again,
    // // rescaling happens lazily, so depth of the result is 2.
    // std::cout << "Ciphertext c4:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c4->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c4->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c4->get_level() << std::endl;

    // std::cout << "Ciphertext c8:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c8->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c8->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c8->get_level() << std::endl;

    // std::cout << "Ciphertext c16:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c16->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c16->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c16->get_level() << std::endl;

    // // c9 is the result of eval_mult between c8 (depth:2, level:2) and
    // // c (depth: 1, level: 0). Inputs are automatically brought to the
    // // correct depth and level before the operation and the user does
    // // not need to care about these low level details.
    // std::cout << "Ciphertext c9:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c9->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c9->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c9->get_level() << std::endl;

    // std::cout << "Ciphertext c18:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c18->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c18->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c18->get_level() << std::endl;

    // // The result has the same depth and level as c18 because
    // // additions do not require any rescaling.
    // std::cout << "Ciphertext c_res:" << std::endl;
    // std::cout << "\t scaling factor: (" << sqrt(c_res->get_scaling_factor()) << ")^2"
    //           << std::endl;
    // std::cout << "\t scaling factor degree: " << c_res->get_noise_scale_deg() << std::endl;
    // std::cout << "\t level: " << c_res->get_level() << std::endl;

    // std::cout << std::defaultfloat;
    // std::cout.precision(8);
    // #endif
}

void manual_rescale_demo(ScalingTechnique scal_tech) {
    /* Please read comments in main() for an introduction to what the
     * rescale operation is, and what's the FIXEDMANUAL variant of CKKS.
     *
     * Even though FIXEDMANUAL does not implement automatic rescaling
     * as FLEXIBLEAUTO does, this does not mean that it does not abstract
     * away some of the nitty-gritty details of using CKKS.
     *
     * In CKKS, ciphertexts are defined versus a large ciphertext modulus Q.
     * Whenever we rescale a ciphertext, its ciphertext modulus becomes
     * smaller too. All homomorphic operations require that their inputs are
     * defined over the same ciphertext modulus, and therefore, we need to
     * adjust one of them if their ciphertext moduli do not match. The way
     * this is done in the original CKKS paper is through an operation called
     * Modulus Switch. In our implementation, we call this operation
     * level_reduce, and both FIXEDMANUAL and FLEXIBLEAUTO do it automatically.
     * As far as we know, automatic level reduce does not incur any performance
     * penalty and this is why it is performed in both FIXEDMANUAL and
     * FLEXIBLEAUTO.
     *
     * Overall, we believe that automatic modulus switching and rescaling make
     * CKKS much easier to use, at least for non-expert users.
     */
    std::cout << "\n\n\n ===== FixedManualDemo ============= " << std::endl;

    uint32_t batch_size = 8;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(5);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_mult_key_gen(keys.secret_key);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(keys.public_key, ptxt);

    /* Computing f(x) = x^18 + x^9 + 1
     *
     * Compare the following with the corresponding code
     * for FLEXIBLEAUTO. Here we need to track the depth of ciphertexts
     * and call rescale() whenever needed. In this instance it's still
     * not hard to do so, but this can be quite tedious in other
     * complicated computations (e.g., in bootstrapping).
     *
     */
    // x^2
    auto c2_depth2 = cc->eval_mult(c, c);
    auto c2_depth1 = cc->rescale(c2_depth2);
    // x^4
    auto c4_depth2 = cc->eval_mult(c2_depth1, c2_depth1);
    auto c4_depth1 = cc->rescale(c4_depth2);
    // x^8
    auto c8_depth2 = cc->eval_mult(c4_depth1, c4_depth1);
    auto c8_depth1 = cc->rescale(c8_depth2);
    // x^16
    auto c16_depth2 = cc->eval_mult(c8_depth1, c8_depth1);
    auto c16_depth1 = cc->rescale(c16_depth2);
    // x^9
    auto c9_depth2 = cc->eval_mult(c8_depth1, c);
    // x^18
    auto c18_depth2 = cc->eval_mult(c16_depth1, c2_depth1);
    // Final result
    auto c_res_depth2 = cc->eval_add(cc->eval_add(c18_depth2, c9_depth2), 1.0);
    auto c_res_depth1 = cc->rescale(c_res_depth2);

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(keys.secret_key, c_res_depth1, &result);
    result->set_length(batch_size);
    std::cout << "x^18 + x^9 + 1 = " << result << std::endl;
}

void hybrid_key_switching_demo1() {
    /*
     * Please refer to comments in the demo-simple_real_number.cpp
     * for a brief introduction on what key switching is and to
     * find reference for HYBRID key switching.
     *
     * In this demo, we focus on how to choose the number of digits
     * in HYBRID key switching, and how that affects the usage and
     * efficiency of the CKKS scheme.
     *
     */

    std::cout << "\n\n\n ===== hybrid_key_switching_demo1 ============= " << std::endl;
    /*
     * dnum is the number of large digits in HYBRID decomposition
     *
     * If not supplied (or value 0 is supplied), the default value is
     * set as follows:
     * - If multiplicative depth is > 3, then dnum = 3 digits are used.
     * - If multiplicative depth is 3, then dnum = 2 digits are used.
     * - If multiplicative depth is < 3, then dnum is set to be equal to
     * mult_depth_value+1
     */
    uint32_t dnum = 2;
    /* To understand the effects of changing dnum, it is important to
     * understand how the ciphertext modulus size changes during key
     * switching.
     *
     * In our RNS implementation of CKKS, every ciphertext corresponds
     * to a large number (which is represented as small integers in RNS)
     * modulo a ciphertext modulus Q, which is defined as the product of
     * (mult_depth_value+1) prime numbers: Q = q0 * q1 * ... * qL. Each qi is
     * selected to be close to the scaling factor D=2^p, hence the total
     * size of Q is approximately:
     *
     * sizeof(Q) = (mult_depth_value+1)*scale_mod_size.
     *
     * HYBRID key switching takes a number d that's defined modulo Q,
     * and performs 4 steps:
     * 1 - Digit decomposition:
     *     Split d into dnum digits - the size of each digit is roughly
     *     ceil(sizeof(Q)/dnum)
     * 2 - Extend ciphertext modulus from Q to Q*P
     *     Here P is a product of special primes
     * 3 - Multiply extended component with key switching key
     * 4 - Decrease the ciphertext modulus back down to Q
     *
     * It's not necessary to understand how all these stages work, as
     * long as it's clear that the size of the ciphertext modulus is
     * increased from sizeof(Q) to sizeof(Q)+sizeof(P) in stage 2. P
     * is always set to be as small as possible, as long as sizeof(P)
     * is larger than the size of the largest digit, i.e., than
     * ceil(sizeof(Q)/dnum). Therefore, the size of P is inversely
     * related to the number of digits, so the more digits we have, the
     * smaller P has to be.
     *
     * The tradeoff here is that more digits means that the digit
     * decomposition stage becomes more expensive, but the maximum
     * size of the ciphertext modulus Q*P becomes smaller. Since
     * the size of Q*P determines the necessary ring dimension to
     * achieve a certain security level, more digits can in some
     * cases mean that we can use smaller ring dimension and get
     * better performance overall.
     *
     * We show this effect with demos hybrid_key_switching_demo1 and
     * hybrid_key_switching_demo2.
     *
     */
    uint32_t batch_size = 8;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(5);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(batch_size);
    parameters.set_scaling_technique(FLEXIBLEAUTO);
    parameters.set_num_large_digits(dnum);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << std::endl;

    std::cout << "- Using HYBRID key switching with " << dnum << " digits" << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1, -2});

    // Input
    std::vector<double> x = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(keys.public_key, ptxt);

    TimeVar t;
    TIC(t);
    auto c_rot1 = cc->eval_rotate(c, 1);
    auto c_rot2 = cc->eval_rotate(c_rot1, -2);
    double time2digits = TOC(t);
    // Take note and compare the runtime to the runtime
    // of the same computation in the next demo.

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(keys.secret_key, c_rot2, &result);
    result->set_length(batch_size);
    std::cout << "x rotate by -1 = " << result << std::endl;
    std::cout << " - 2 rotations with HYBRID (2 digits) took " << time2digits << "ms" << std::endl;

    /* Interested users may set the following if to 1
     * to observe the prime numbers comprising Q and P,
     * and how these change with the number of digits
     * dnum.
     */
    // #if 0
    // const auto crypto_params_ckks =
    //     std::dynamic_pointer_cast<CkksRnsCryptoParams>(
    //         cc->get_crypto_parameters());

    // auto params_q = cc->get_element_params()->get_params();
    // std::cout << "\nModuli in Q:" << std::endl;
    // for (uint32_t i = 0; i < params_q.size(); i++) {
    //   // q0 is a bit larger because its default size is 60 bits.
    //   // One can change this by supplying the first_mod_size_value argument
    //   // in genCryptoContextCKKS.
    //   std::cout << "q" << i << ": " << params_q[i]->get_modulus() << std::endl;
    // }
    // auto params_qp = crypto_params_ckks->get_params_qp();
    // std::cout << "Moduli in P: " << std::endl;
    // BigInteger P = BigInteger(1);
    // for (uint32_t i = 0; i < params_qp->get_params().size(); i++) {
    //   if (i > params_q.size()) {
    //     P = P * BigInteger(params_qp->get_params()[i]->get_modulus());
    //     std::cout << "p" << i - params_q.size() << ": "
    //               << params_qp->get_params()[i]->get_modulus() << std::endl;
    //   }
    // }
    // auto QBitLength = cc->get_modulus().get_length_for_base(2);
    // auto PBitLength = P.get_length_for_base(2);
    // std::cout << "\nQ = " << cc->get_modulus() << " (bit length: " << QBitLength
    //           << ")" << std::endl;
    // std::cout << "P = " << P << " (bit length: " << PBitLength << ")"
    //           << std::endl;
    // std::cout << "Total bit-length of ciphertext modulus: "
    //           << QBitLength + PBitLength << std::endl;
    // std::cout << "Given this ciphertext modulus, a ring dimension of "
    //           << cc->get_ring_dimension() << " gives us 128-bit security."
    //           << std::endl;
    // #endif
}

void hybrid_key_switching_demo2() {
    /*
     * Please refer to comments in hybrid_key_switching_demo1.
     *
     */

    std::cout << "\n\n\n ===== hybrid_key_switching_demo2 ============= " << std::endl;

    /*
     * Here we use dnum = 3 digits. Even though 3 digits are
     * more than the two digits in the previous demo and the
     * cost of digit decomposition is higher, the increase in
     * digits means that individual digits are smaller, and we
     * can perform key switching by using only one special
     * prime in P (instead of two in the previous demo).
     *
     * This also means that the maximum size of ciphertext
     * modulus in key switching is smaller by 60 bits, and it
     * turns out that this decrease is adequate to warrant a
     * smaller ring dimension to achieve the same security
     * level (128-bits).
     *
     */
    uint32_t dnum = 3;

    uint32_t batch_size = 8;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(5);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(batch_size);
    parameters.set_scaling_technique(FLEXIBLEAUTO);
    parameters.set_num_large_digits(dnum);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Compare the ring dimension in this demo to the one in
    // the previous.
    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << std::endl;

    std::cout << "- Using HYBRID key switching with " << dnum << " digits" << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1, -2});

    // Input
    std::vector<double> x = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(keys.public_key, ptxt);

    TimeVar t;
    TIC(t);
    auto c_rot1 = cc->eval_rotate(c, 1);
    auto c_rot2 = cc->eval_rotate(c_rot1, -2);
    // The runtime here is smaller than in the previous demo.
    double time3digits = TOC(t);

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(keys.secret_key, c_rot2, &result);
    result->set_length(batch_size);
    std::cout << "x rotate by -1 = " << result << std::endl;
    std::cout << " - 2 rotations with HYBRID (3 digits) took " << time3digits << "ms" << std::endl;

    /* Interested users may set the following if to 1
     * to observe the prime numbers comprising Q and P,
     * and how these change with the number of digits
     * dnum.
     */
    // #if 0
    // const auto crypto_params_ckks =
    //     std::dynamic_pointer_cast<CkksRnsCryptoParams>(
    //         cc->get_crypto_parameters());

    // auto params_q = cc->get_element_params()->get_params();
    // std::cout << "\nModuli in Q:" << std::endl;
    // for (uint32_t i = 0; i < params_q.size(); i++) {
    //   // q0 is a bit larger because its default size is 60 bits.
    //   // One can change this by supplying the first_mod_size_value argument
    //   // in genCryptoContextCKKS.
    //   std::cout << "q" << i << ": " << params_q[i]->get_modulus() << std::endl;
    // }
    // auto params_qp = crypto_params_ckks->get_params_qp();
    // std::cout << "Moduli in P: " << std::endl;
    // BigInteger P = BigInteger(1);
    // for (uint32_t i = 0; i < params_qp->get_params().size(); i++) {
    //   if (i > params_q.size()) {
    //     P = P * BigInteger(params_qp->get_params()[i]->get_modulus());
    //     std::cout << "p" << i - params_q.size() << ": "
    //               << params_qp->get_params()[i]->get_modulus() << std::endl;
    //   }
    // }
    // auto QBitLength = cc->get_modulus().get_length_for_base(2);
    // auto PBitLength = P.get_length_for_base(2);
    // std::cout << "\nQ = " << cc->get_modulus() << " (bit length: " << QBitLength
    //           << ")" << std::endl;
    // std::cout << "P = " << P << " (bit length: " << PBitLength << ")"
    //           << std::endl;
    // std::cout << "Given this ciphertext modulus, a ring dimension of "
    //           << cc->get_ring_dimension() << " gives us 128-bit security."
    //           << std::endl;
    // #endif
}

void fast_rotations_demo1() {
    /*
     * In CKKS, whenever someone applies a rotation R() to a ciphertext
     * encrypted with key s, we get a result which is not valid under
     * key s, but under the same rotation R(s) of s. Therefore, after
     * every rotation we need to perform key switching, making them as
     * expensive as multiplications.
     *
     * As mentioned earlier (in comments of hybrid_key_switching_demo1),
     * key switching involves the following steps:
     * 1 - Digit decomposition
     * 2 - Extend ciphertext modulus from Q to Q*P
     * 3 - Multiply extended component with key switching key
     * 4 - Decrease the ciphertext modulus back down to Q
     *
     * A useful observation is that the first two steps are independent
     * of the particular rotation we want to perform. Steps 3-4 on the
     * other hand depend on the specific rotation we have at hand,
     * because each rotation index has a different key switch key.
     *
     * This observation means that, if we want to perform multiple
     * different rotations to the same ciphertext, we can perform
     * the first two steps once, and then only perform steps 3-4 for
     * each rotation. This technique is called hoisting, and we have
     * implemented it for all three key switching techniques (BV, GHS,
     * HYBRID) in Cipher.
     *
     * The benefits expected by this technique differ depending on the
     * key switching algorithms we're using. BV is the technique that
     * gets the greatest benefits, because the digit decomposition is
     * the most expensive part. However, HYBRID also benefits from
     * hoisting, and we show this in this part of the demo.
     *
     */

    std::cout << "\n\n\n ===== fast_rotations_demo1 ============= " << std::endl;

    uint32_t batch_size = 8;
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    uint32_t N = cc->get_ring_dimension();
    std::cout << "CKKS scheme is using ring dimension " << N << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1, 2, 3, 4, 5, 6, 7});

    // Input
    std::vector<double> x = {0, 0, 0, 0, 0, 0, 0, 1};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(keys.public_key, ptxt);

    Ciphertext<RnsPoly> c_rot1, c_rot2, c_rot3, c_rot4, c_rot5, c_rot6, c_rot7;

    // First, we perform 7 regular (non-hoisted) rotations
    // and measure the runtime.
    TimeVar t;
    TIC(t);
    c_rot1 = cc->eval_rotate(c, 1);
    c_rot2 = cc->eval_rotate(c, 2);
    c_rot3 = cc->eval_rotate(c, 3);
    c_rot4 = cc->eval_rotate(c, 4);
    c_rot5 = cc->eval_rotate(c, 5);
    c_rot6 = cc->eval_rotate(c, 6);
    c_rot7 = cc->eval_rotate(c, 7);
    double time_no_hoisting = TOC(t);

    auto c_res_no_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7;

    // M is the cyclotomic order and we need it to call eval_fast_rotation
    uint32_t M = 2 * N;

    // Then, we perform 7 rotations with hoisting.
    TIC(t);
    auto c_precomp = cc->eval_fast_rotation_precompute(c);
    c_rot1 = cc->eval_fast_rotation(c, 1, M, c_precomp);
    c_rot2 = cc->eval_fast_rotation(c, 2, M, c_precomp);
    c_rot3 = cc->eval_fast_rotation(c, 3, M, c_precomp);
    c_rot4 = cc->eval_fast_rotation(c, 4, M, c_precomp);
    c_rot5 = cc->eval_fast_rotation(c, 5, M, c_precomp);
    c_rot6 = cc->eval_fast_rotation(c, 6, M, c_precomp);
    c_rot7 = cc->eval_fast_rotation(c, 7, M, c_precomp);
    double time_hoisting = TOC(t);
    // The time with hoisting should be faster than without hoisting.

    auto c_res_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7;

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(keys.secret_key, c_res_no_hoist, &result);
    result->set_length(batch_size);
    std::cout << "Result without hoisting = " << result << std::endl;
    std::cout << " - 7 rotations on x without hoisting took " << time_no_hoisting << "ms" << std::endl;

    cc->decrypt(keys.secret_key, c_res_hoist, &result);
    result->set_length(batch_size);
    std::cout << "Result with hoisting = " << result << std::endl;
    std::cout << " - 7 rotations on x with hoisting took " << time_hoisting << "ms" << std::endl;
}

void fast_rotations_demo2() {
    /*
     * This demo is identical to the previous one, with the exception
     * that we use BV key switching instead of HYBRID.
     *
     * The benefits expected by hoisting differ depending on the
     * key switching algorithms we're using. BV is the technique that
     * gets the greatest benefits, because the digit decomposition is
     * the most expensive part. However, HYBRID also benefits from
     * hoisting, and we show this in this part of the demo.
     *
     */

    std::cout << "\n\n\n ===== fast_rotations_demo2 ============= " << std::endl;

    // uint32_t dnum = 0;  -already default
    /*
     * This controls how many multiplications are possible without rescaling.
     * The number of multiplications (max_relin_sk_deg) is maxDepth - 1.
     * This is useful for an optimization technique called lazy
     * re-linearization (only applicable in FIXEDMANUAL, as
     * FLEXIBLEAUTO implements automatic rescaling).
     */
    // uint32_t maxDepth (max_relin_sk_deg) = 2; - already default
    /*
     * The digit size is only used in BV key switching and
     * it allows us to perform digit decomposition at a finer granularity.
     * Under normal circumstances, digit decomposition is what we call
     * RNS decomposition, i.e., each digit is roughly the size of the
     * qi's that comprise the ciphertext modulus Q. When using BV, in
     * certain cases like having to perform rotations without any
     * preceding multiplication, we need to have smaller digits to prevent
     * noise from corrupting the result. In this case, using digit_size = 10
     * does the trick. Users are encouraged to set this to 0 (i.e., RNS
     * decomposition) and see how the results are incorrect.
     */
    uint32_t digit_size = 10;
    uint32_t batch_size = 8;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(batch_size);
    parameters.set_scaling_technique(FLEXIBLEAUTO);
    parameters.set_key_switch_technique(BV);
    parameters.set_first_mod_size(60);
    parameters.set_digit_size(digit_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    uint32_t N = cc->get_ring_dimension();
    std::cout << "CKKS scheme is using ring dimension " << N << std::endl << std::endl;

    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    cc->eval_rotate_key_gen(keys.secret_key, {1, 2, 3, 4, 5, 6, 7});

    // Input
    std::vector<double> x = {0, 0, 0, 0, 0, 0, 0, 1};
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->encrypt(keys.public_key, ptxt);

    Ciphertext<RnsPoly> c_rot1, c_rot2, c_rot3, c_rot4, c_rot5, c_rot6, c_rot7;

    // First, we perform 7 regular (non-hoisted) rotations
    // and measure the runtime.
    TimeVar t;
    TIC(t);
    c_rot1 = cc->eval_rotate(c, 1);
    c_rot2 = cc->eval_rotate(c, 2);
    c_rot3 = cc->eval_rotate(c, 3);
    c_rot4 = cc->eval_rotate(c, 4);
    c_rot5 = cc->eval_rotate(c, 5);
    c_rot6 = cc->eval_rotate(c, 6);
    c_rot7 = cc->eval_rotate(c, 7);
    double time_no_hoisting = TOC(t);

    auto c_res_no_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7;

    // M is the cyclotomic order and we need it to call eval_fast_rotation
    uint32_t M = 2 * N;

    // Then, we perform 7 rotations with hoisting.
    TIC(t);
    auto c_precomp = cc->eval_fast_rotation_precompute(c);
    c_rot1 = cc->eval_fast_rotation(c, 1, M, c_precomp);
    c_rot2 = cc->eval_fast_rotation(c, 2, M, c_precomp);
    c_rot3 = cc->eval_fast_rotation(c, 3, M, c_precomp);
    c_rot4 = cc->eval_fast_rotation(c, 4, M, c_precomp);
    c_rot5 = cc->eval_fast_rotation(c, 5, M, c_precomp);
    c_rot6 = cc->eval_fast_rotation(c, 6, M, c_precomp);
    c_rot7 = cc->eval_fast_rotation(c, 7, M, c_precomp);
    double time_hoisting = TOC(t);
    /* The time with hoisting should be faster than without hoisting.
     * Also, the benefits from hoisting should be more pronounced in this
     * case because we're using BV. Of course, we also observe less
     * accurate results than when using HYBRID, because of using
     * digit_size = 10 (Users can decrease digit_size to see the accuracy
     * increase, and performance decrease).
     */

    auto c_res_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7;

    Plaintext result;
    std::cout.precision(8);

    cc->decrypt(keys.secret_key, c_res_no_hoist, &result);
    result->set_length(batch_size);
    std::cout << "Result without hoisting = " << result << std::endl;
    std::cout << " - 7 rotations on x without hoisting took " << time_no_hoisting << "ms" << std::endl;

    cc->decrypt(keys.secret_key, c_res_hoist, &result);
    result->set_length(batch_size);
    std::cout << "Result with hoisting = " << result << std::endl;
    std::cout << " - 7 rotations on x with hoisting took " << time_hoisting << "ms" << std::endl;
}
