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
  Simple examples for CKKS in the COMPOSITESCALINGAUTO mode
 */

#define PROFILE

#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

int main(int argc, char* argv[]) {
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
    uint32_t mult_depth_value = 2;

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
    uint32_t first_mod_size_value = 90;
    uint32_t scale_mod_size = 73;

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

    /*
     * The word size in bits of the target hardware architecture.
     */
    uint32_t register_word_size = 32;

    int argc_count = 1;
    if (argc > 1) {
        while (argc_count < argc) {
            uint32_t param_value = atoi(argv[argc_count]);
            switch (argc_count) {
                case 1:
                    first_mod_size_value = param_value;
                    std::cout << "Setting First Mod Size: " << first_mod_size_value << std::endl;
                    break;
                case 2:
                    scale_mod_size = param_value;
                    std::cout << "Setting Scaling Mod Size: " << scale_mod_size << std::endl;
                    break;
                case 3:
                    register_word_size = param_value;
                    std::cout << "Setting Register Word Size: " << register_word_size << std::endl;
                    break;
                case 4:
                    mult_depth_value = param_value;
                    std::cout << "Setting Multiplicative Depth: " << mult_depth_value << std::endl;
                    break;
                default:
                    std::cout << "Invalid option" << std::endl;
                    break;
            }
            argc_count += 1;
            std::cout << "argc_count: " << argc_count << std::endl;
        }
        std::cout << "Complete !" << std::endl;
    } else {
        std::cout << "Using default parameters" << std::endl;
        std::cout << "First Mod Size: " << first_mod_size_value << std::endl;
        std::cout << "Scaling Mod Size: " << scale_mod_size << std::endl;
        std::cout << "Register Word Size: " << register_word_size << std::endl;
        std::cout << "Multiplicative Depth: " << mult_depth_value << std::endl;
        std::cout << "Usage: " << argv[0] << " [firstModSize] [scalingModSize] [registerWordSize] [multDepth]"
                  << std::endl;
    }

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
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_batch_size(batch_size);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

    parameters.set_scaling_technique(COMPOSITESCALINGAUTO);
    parameters.set_register_word_size(register_word_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    const auto crypto_params_ckksrns = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    std::cout << "Composite Degree: " << crypto_params_ckksrns->get_composite_degree() << "\nPrime Modulus Size: "
              << static_cast<float>(scale_mod_size) / crypto_params_ckksrns->get_composite_degree()
              << "\nRegister Word Size: " << register_word_size << std::endl;

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension() << std::endl << std::endl;

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

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2);

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;

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

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    cc->decrypt(keys.secret_key, c1, &result);
    result->set_length(batch_size);
    std::cout << "x1 = " << result;
    std::cout << "Estimated precision in bits: " << result->get_log_precision() << std::endl;

    // Decrypt the result of addition
    cc->decrypt(keys.secret_key, c_add, &result);
    result->set_length(batch_size);
    std::cout << "x1 + x2 = " << result;
    std::cout << "Estimated precision in bits: " << result->get_log_precision() << std::endl;

    // Decrypt the result of subtraction
    cc->decrypt(keys.secret_key, c_sub, &result);
    result->set_length(batch_size);
    std::cout << "x1 - x2 = " << result << std::endl;

    // Decrypt the result of scalar multiplication
    cc->decrypt(keys.secret_key, c_scalar, &result);
    result->set_length(batch_size);
    std::cout << "4 * x1 = " << result << std::endl;

    // Decrypt the result of multiplication
    cc->decrypt(keys.secret_key, c_mul, &result);
    result->set_length(batch_size);
    std::cout << "x1 * x2 = " << result << std::endl;

    // Decrypt the result of rotations

    cc->decrypt(keys.secret_key, c_rot1, &result);
    result->set_length(batch_size);
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotate by 1 = " << result << std::endl;

    cc->decrypt(keys.secret_key, c_rot2, &result);
    result->set_length(batch_size);
    std::cout << "x1 rotate by -2 = " << result << std::endl;

    // Testing eval_add ciphertext - double
    auto c_sub_double = cc->eval_sub(c1, 0.5);
    std::cout << "c1 noise degree = " << c1->get_noise_scale_deg() << std::endl;
    std::cout << "c1 scaling factor = " << c1->get_scaling_factor() << std::endl;

    // Testing eval_add ciphertext + negative double
    auto c_add_neg_double = cc->eval_add(c1, -0.5);

    // Decrypt the result of subtraction
    cc->decrypt(keys.secret_key, c_sub_double, &result);
    result->set_length(batch_size);
    std::cout << "x1 - 0.5 = " << result << std::endl;

    // Decrypt the result of subtraction
    cc->decrypt(keys.secret_key, c_add_neg_double, &result);
    result->set_length(batch_size);
    std::cout << "x1 + (-0.5) = " << result << std::endl;

    return 0;
}
