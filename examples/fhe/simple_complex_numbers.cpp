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
  Simple examples for CKKS
 */

#include <complex>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;
using namespace std::literals;

void simple_complex_numbers();
void simple_bootstrapping_complex();
void simple_bootstrapping_st_c_first_complex();

int main() {
    simple_complex_numbers();
    simple_bootstrapping_complex();
    simple_bootstrapping_st_c_first_complex();
    return 0;
}

void simple_complex_numbers() {
    std::cout << "\n================= Simple Operations on Complex Numbers =====================\n";

    // Step 1: Setup CryptoContext

    // A. Specify main parameters
    /* A1) Multiplicative depth:
     * The CKKS scheme we setup here will work for any computation
     * that has a multiplicative depth equal to 'mult_depth_value'.
     * This is the maximum possible depth of a given multiplication,
     * but not the total number of multiplications supported by the
     * scheme.
     *
     * For example, computation f(x, y) = x^2 + x*y + y^2 + x + y has
     * a multiplicative depth of 1, but requires a total of 3 multiplications.
     * On the other hand, computation g(x_i) = x1*x2*x3*x4 can be implemented
     * either as a computation of multiplicative depth 3 as
     * g(x_i) = ((x1*x2)*x3)*x4, or as a computation of multiplicative depth 2
     * as g(x_i) = (x1*x2)*(x3*x4).
     *
     * For performance reasons, it's generally preferable to perform operations
     * in the shorted multiplicative depth possible.
     */
    uint32_t mult_depth_value = 1;

    /* A2) Bit-length of scaling factor.
     * CKKS works for real numbers, but these numbers are encoded as integers.
     * For instance, real number m=0.01 is encoded as m'=round(m*D), where D is
     * a scheme parameter called scaling factor. Suppose D=1000, then m' is 10 (an
     * integer). Say the result of a computation based on m' is 130, then at
     * decryption, the scaling factor is removed so the user is presented with
     * the real number result of 0.13.
     *
     * Parameter 'scale_mod_size' determines the bit-length of the scaling
     * factor D, but not the scaling factor itself. The latter is implementation
     * specific, and it may also vary between ciphertexts in certain versions of
     * CKKS (e.g., in FLEXIBLEAUTO).
     *
     * Choosing 'scale_mod_size' depends on the desired accuracy of the
     * computation, as well as the remaining parameters like mult_depth_value or security
     * standard. This is because the remaining parameters determine how much noise
     * will be incurred during the computation (remember CKKS is an approximate
     * scheme that incurs small amounts of noise with every operation). The
     * scaling factor should be large enough to both accommodate this noise and
     * support results that match the desired accuracy.
     */
    uint32_t scale_mod_size = 50;

    /* A3) Number of plaintext slots used in the ciphertext.
     * CKKS packs multiple plaintext values in each ciphertext.
     * The maximum number of slots depends on a security parameter called ring
     * dimension. In this instance, we don't specify the ring dimension directly,
     * but let the library choose it for us, based on the security level we
     * choose, the multiplicative depth we want to support, and the scaling factor
     * size.
     *
     * Please use method get_ring_dimension() to find out the exact ring dimension
     * being used for these parameters. Give ring dimension N, the maximum batch
     * size is N/2, because of the way CKKS works.
     */
    uint32_t batch_size = 8;

    /* A4) Desired security level based on FHE standards.
     * This parameter can take four values. Three of the possible values
     * correspond to 128-bit, 192-bit, and 256-bit security, and the fourth value
     * corresponds to "NotSet", which means that the user is responsible for
     * choosing security parameters. Naturally, "NotSet" should be used only in
     * non-production environments, or by experts who understand the security
     * implications of their choices.
     *
     * If a given security level is selected, the library will consult the current
     * security parameter tables defined by the FHE standards consortium
     * (https://homomorphicencryption.org/introduction/) to automatically
     * select the security parameters. Please see "TABLES of RECOMMENDED
     * PARAMETERS" in  the following reference for more details:
     * http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
     */

    /* A5) Data type to be encoded.
     * For a ring dimension N, CKKS plaintexts can pack vectors of up to N/2 values.
     * Packing N/2 complex numbers achieves better throughput, as it translates to
     * packing N real numbers. However, packing complex numbers does not currently allow
     * noise estimation (since the noise estimation is uses the imaginary slots).
     * By default, the CkksDataType is set to REAL, which enables packing up to N/2
     * real numbers and allows noise estimation.
     */
    CkksDataType ckks_data_type = COMPLEX;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_batch_size(batch_size);
    parameters.set_ckks_data_type(ckks_data_type);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << "\n\n";

    // B. Step 2: Key Generation
    /* B1) Generate encryption keys.
     * These are used for encryption/decryption, as well as in generating
     * different kinds of keys.
     */
    auto keys = cc->key_gen();

    /* B2) Generate the digit size
     * In CKKS, whenever someone multiplies two ciphertexts encrypted with key s,
     * we get a result with some components that are valid under key s, and
     * with an additional component that's valid under key s^2.
     *
     * In most cases, we want to perform relinearization of the multiplicaiton
     * result, i.e., we want to transform the s^2 component of the ciphertext so
     * it becomes valid under original key s. To do so, we need to create what we
     * call a relinearization key with the following line.
     */
    cc->eval_mult_key_gen(keys.secret_key);

    /* B3) Generate the rotation keys
     * CKKS supports rotating the contents of a packed ciphertext, but to do so,
     * we need to create what we call a rotation key. This is done with the
     * following call, which takes as input a vector with indices that correspond
     * to the rotation offset we want to support. Negative indices correspond to
     * right shift and positive to left shift. Look at the output of this demo for
     * an illustration of this.
     *
     * Keep in mind that rotations work over the batch size or entire ring dimension (if the batch size is not specified).
     * This means that, if ring dimension is 8 and batch
     * size is not specified, then an input (1,2,3,4,0,0,0,0) rotated by 2 will become
     * (3,4,0,0,0,0,1,2) and not (3,4,1,2,0,0,0,0).
     * If ring dimension is 8 and batch
     * size is set to 4, then the rotation of (1,2,3,4) by 2 will become (3,4,1,2).
     * Also, as someone can observe
     * in the output of this demo, since CKKS is approximate, zeros are not exact
     * - they're just very small numbers.
     */
    cc->eval_rotate_key_gen(keys.secret_key, {1, -2});

    /* B4) Generate the conjugation key
    Conjugating an encrypted complex number is done via an automorphism with
    index 2N - 1.
    */
    uint32_t index_conj = 2 * cc->get_ring_dimension() - 1;
    cc->eval_automorphism_key_gen(keys.secret_key, {index_conj});

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<std::complex<double>> x1 = {0.25 + 0.25i, 0.5 + 0.5i, 0.75 + 0.75i, 1.0 + 1.i,
                                            2.0 + 2.i,    3.0 + 3.i,  4.0 + 4.i,    5.0 + 5.i};
    std::vector<std::complex<double>> x2 = {5.0 - 5.0i, 4.0 - 4.i,    3.0 - 3.i,  2.0 - 2.i,
                                            1.0 - 1.i,  0.75 - 0.75i, 0.5 - 0.5i, 0.25 - 0.25i};

    std::complex<double> const_complex(1.0 - 2.0i);
    std::complex<double> const_complex2(1.0 + 0.5i);

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2);

    std::cout << "Input x1: " << ptxt1;
    std::cout << "Input x2: " << ptxt2;

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);
    auto c2 = cc->encrypt(keys.public_key, ptxt2);

    // Step 4: Evaluation

    // Homomorphic addition
    auto c_add = cc->eval_add(c1, c2);

    // Homomorphic subtraction
    auto c_sub = cc->eval_sub(c1, c2);

    // Homomorphic scalar multiplication
    auto c_scalar = cc->eval_mult(c1, 4.0);

    // Homomorphic multiplication
    auto c_mul = cc->eval_mult(c1, c2);

    // Homomorphic rotations
    auto c_rot1 = cc->eval_rotate(c1, 1);
    auto c_rot2 = cc->eval_rotate(c1, -2);

    // Homomorphic conjugation
    auto eval_conj_key_map = cc->get_eval_automorphism_key_map(c1->get_key_tag());
    auto c_conj1 = cc->eval_automorphism(c1, index_conj, eval_conj_key_map);

    // Note that setting the data type to REAL and performing operations with
    // complex constants leads to a decryption error.

    // Multiplication by a complex constant
    auto c_mul_c = cc->eval_mult(c1, const_complex);

    // Additions by a complex constant
    auto c_add_c = cc->eval_add(c2, const_complex);
    cc->eval_add_in_place(c_add_c, const_complex2);

    // Subtractions by a complex constant
    auto c_sub_c = cc->eval_sub(c2, const_complex);
    cc->eval_sub_in_place(c_sub_c, const_complex2);

    // Step 5: Decryption and output
    // Note that this does not automatically create a plaintext that encodes complex values.
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << "\nDecrypted complex inputs:\n";

    cc->decrypt(keys.secret_key, c1, &result);
    result->set_length(batch_size);
    std::cout << "x1 = " << result;

    cc->decrypt(keys.secret_key, c2, &result);
    result->set_length(batch_size);
    std::cout << "x2 = " << result;

    std::cout << "\nResults of homomorphic computations:\n";

    // Decrypt the result of addition
    cc->decrypt(keys.secret_key, c_add, &result);
    result->set_length(batch_size);
    std::cout << "x1 + x2 = " << result;

    // Decrypt the result of subtraction
    cc->decrypt(keys.secret_key, c_sub, &result);
    result->set_length(batch_size);
    std::cout << "x1 - x2 = " << result;

    // Decrypt the result of scalar multiplication
    cc->decrypt(keys.secret_key, c_scalar, &result);
    result->set_length(batch_size);
    std::cout << "4 * x1 = " << result;

    // Decrypt the result of multiplication
    cc->decrypt(keys.secret_key, c_mul, &result);
    result->set_length(batch_size);
    std::cout << "x1 * x2 = " << result;

    // Decrypt the result of rotations
    cc->decrypt(keys.secret_key, c_rot1, &result);
    result->set_length(batch_size);
    std::cout << "\nIn rotations, very small outputs (~10^-10 here) correspond to 0's:\n";
    std::cout << "x1 rotated by 1 = " << result;

    cc->decrypt(keys.secret_key, c_rot2, &result);
    result->set_length(batch_size);
    std::cout << "x1 rotated by -2 = " << result;

    // Decrypt the result of conjugation
    cc->decrypt(keys.secret_key, c_conj1, &result);
    result->set_length(batch_size);
    std::cout << "x1 conjugated = " << result;

    // Decrypt the result of multiplication by complex value
    cc->decrypt(keys.secret_key, c_mul_c, &result);
    result->set_length(batch_size);
    std::cout << "x1 * (1 - 2i) = " << result;

    // Decrypt the result of additions by two complex values
    cc->decrypt(keys.secret_key, c_add_c, &result);
    result->set_length(batch_size);
    std::cout << "x2 + (1 - 2i) + (1 + 0.5i) = " << result;

    // Decrypt the result of subtractions by two complex values
    cc->decrypt(keys.secret_key, c_sub_c, &result);
    result->set_length(batch_size);
    std::cout << "x2 - (1 - 2i) - (1 + 0.5i) = " << result;
}

void simple_bootstrapping_complex() {
    std::cout << "\n================= Bootstrapping Complex Numbers =====================\n";

    ContextParams<CkksRnsContext> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
     * SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
     * UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
     * its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
     * SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
     */
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    /*  A2) Desired security level based on FHE standards.
     * In this example, we use the "NotSet" option, so the example can run more quickly with
     * a smaller ring dimension. Note that this should be used only in
     * non-production environments, or by experts who understand the security
     * implications of their choices. In production-like environments, we recommend using
     * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
     * or 256-bit security, respectively. If you choose one of these as your security level,
     * you do not need to set the ring dimension.
     */
    parameters.set_security_level(HEStd_NotSet);
    uint32_t ring_dim = 1 << 6;
    parameters.set_ring_dim(ring_dim);

    /*  A3) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
#if CIPHER_NATIVE_INT == 128
    ScalingTechnique rescale_tech = FIXEDAUTO;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89;
#else
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
#endif

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    /* A4) Data type to be encoded.
     * For a ring dimension N, CKKS plaintexts can pack vectors of up to N/2 values.
     * Packing N/2 complex numbers achieves better throughput, as it translates to
     * packing N real numbers. However, packing complex numbers does not currently allow
     * noise estimation (since the noise estimation is uses the imaginary slots).
     * By default, the CkksDataType is set to REAL, which enables packing up to N/2
     * real numbers and allows noise estimation.
     */
    parameters.set_ckks_data_type(COMPLEX);

    /* A5) Batch size.
     * Bootstrapping fewer or equal than N/4 complex numbers in the StC variant of bootstrapping requires evaluating
     * the modular approximation polynomial on a single ciphertext, while bootstrapping N/2 complex numbers
     * requires evaluating the modular approximation polynomial on two ciphertexts. For comparison,
     * bootstrapping up to N/2 real numbers in the StC variant of bootstrapping requires evaluating the modular
     * approximation polynomial on a single ciphertext.
     */
    uint32_t num_slots = ring_dim / 2;
    // parameters.set_batch_size(num_slots);

    /*  A6) Multiplicative depth.
     * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
     * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
     * needs to consume a few levels to run. We compute the number of bootstrapping levels required
     * using get_bootstrap_depth, and add it to levels_available_after_bootstrap to set our initial multiplicative
     * depth. We recommend using the input parameters below to get started.
     */
    std::vector<uint32_t> level_budget = {2, 2};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping
    // will be levels_available_after_bootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << ring_dim << " and number of slots " << num_slots << "\n\n";

    crypto_context->eval_bootstrap_setup(level_budget, {0, 0}, num_slots);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    std::vector<std::complex<double>> x = {0.25 + 0.25i, 0.5 - 0.5i, 0.75 + 0.75i, 1.0 - 1.i,
                                           2.0 + 2.i,    3.0 - 3.i,  4.0 + 4.i,    5.0 - 5.i};
    if (x.size() < num_slots)
        x = Fill<std::complex<double>>(x, num_slots);
    size_t encoded_length = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1, nullptr, num_slots);

    ptxt->set_length(encoded_length);
    std::cout << "Input: " << ptxt << "\n";

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    std::cout << "Initial number of levels remaining: " << (depth - ciph->get_level()) << "\n";

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    std::cout << "Number of levels remaining after bootstrapping: "
              << (depth - ciphertext_after->get_level() - (ciphertext_after->get_noise_scale_deg() - 1)) << "\n\n";

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(encoded_length);
    std::cout << "Output after bootstrapping: \n\t" << result;
}

void simple_bootstrapping_st_c_first_complex() {
    std::cout
            << "\n================= Bootstrapping Complex Numbers with StC Transformation First =====================\n";

    ContextParams<CkksRnsContext> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
     * SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
     * UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
     * its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
     * SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
     */
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    /*  A2) Desired security level based on FHE standards.
     * In this example, we use the "NotSet" option, so the example can run more quickly with
     * a smaller ring dimension. Note that this should be used only in
     * non-production environments, or by experts who understand the security
     * implications of their choices. In production-like environments, we recommend using
     * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
     * or 256-bit security, respectively. If you choose one of these as your security level,
     * you do not need to set the ring dimension.
     */
    parameters.set_security_level(HEStd_NotSet);
    uint32_t ring_dim = 1 << 6;
    parameters.set_ring_dim(ring_dim);

    /*  A3) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
#if CIPHER_NATIVE_INT == 128
    ScalingTechnique rescale_tech = FIXEDAUTO;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89;
#else
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
#endif

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    /* A4) Data type to be encoded.
     * For a ring dimension N, CKKS plaintexts can pack vectors of up to N/2 values.
     * Packing N/2 complex numbers achieves better throughput, as it translates to
     * packing N real numbers. However, packing complex numbers does not currently allow
     * noise estimation (since the noise estimation is uses the imaginary slots).
     * By default, the CkksDataType is set to REAL, which enables packing up to N/2
     * real numbers and allows noise estimation.
     */
    parameters.set_ckks_data_type(COMPLEX);

    /* A5) Batch size.
     * Bootstrapping fewer or equal than N/4 complex numbers in the StC variant of bootstrapping requires evaluating
     * the modular approximation polynomial on a single ciphertext, while bootstrapping N/2 complex numbers
     * requires evaluating the modular approximation polynomial on two ciphertexts. For comparison,
     * bootstrapping up to N/2 real numbers in the StC variant of bootstrapping requires evaluating the modular
     * approximation polynomial on a single ciphertext.
     */
    uint32_t num_slots = ring_dim / 2;
    // parameters.set_batch_size(num_slots);

    /*  A6) Multiplicative depth.
     * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
     * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
     * needs to consume a few levels to run. We compute the number of bootstrapping levels required
     * using get_bootstrap_depth, and add it to levels_available_after_bootstrap to set our initial multiplicative
     * depth. We recommend using the input parameters below to get started.
     */
    std::vector<uint32_t> level_budget = {2, 2};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping
    // will be levels_available_after_bootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    uint32_t levels_available_after_bootstrap = 10 + level_budget[1];
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth({level_budget[0], 0}, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << ring_dim << " and number of slots " << num_slots
              << " with depth " << depth << "\n\n";

    crypto_context->eval_bootstrap_setup(level_budget, {0, 0}, num_slots, 0, true, true);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    std::vector<std::complex<double>> x = {0.25 + 0.25i, 0.5 - 0.5i, 0.75 + 0.75i, 1.0 - 1.i,
                                           2.0 + 2.i,    3.0 - 3.i,  4.0 + 4.i,    5.0 - 5.i};
    if (x.size() < num_slots)
        x = Fill<std::complex<double>>(x, num_slots);
    size_t encoded_length = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1 - level_budget[1], nullptr, num_slots);

    ptxt->set_length(encoded_length);
    std::cout << "Input: " << ptxt << "\n";

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    std::cout << "Initial number of levels remaining: " << (depth - ciph->get_level()) << "\n";

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    std::cout << "Number of levels remaining after bootstrapping: "
              << (depth - ciphertext_after->get_level() - (ciphertext_after->get_noise_scale_deg() - 1)) << "\n\n";

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(2 * encoded_length);
    std::cout << "Output after bootstrapping: \n\t" << result;
}
