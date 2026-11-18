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
  Simple example for BFVrns (integer arithmetic) with serialization. Refer to the simple-real-numbers-serial file for
  an example of how to use. this in a "client-server" setup
 */

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cipher/cipher.h"

// header files needed for serialization
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/bfv/ser.h"

using namespace cipher;

const std::string DATAFOLDER = "data";

int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    // Sample Program: Step 1: Set CryptoContext
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_multiplicative_depth(2);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // Enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    std::cout << "\nThe cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!serialization::serialize_to_file(DATAFOLDER + "/cryptocontext.txt", crypto_context, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    // Generate a public/private key pair
    key_pair = crypto_context->key_gen();

    std::cout << "The key pair has been generated." << std::endl;

    // Serialize the public key
    if (!serialization::serialize_to_file(DATAFOLDER + "/key-public.txt", key_pair.public_key, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return 1;
    }
    std::cout << "The public key has been serialized." << std::endl;

    // Serialize the secret key
    if (!serialization::serialize_to_file(DATAFOLDER + "/key-private.txt", key_pair.secret_key, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been serialized." << std::endl;

    // Generate the relinearization key
    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    std::cout << "The eval mult keys have been generated." << std::endl;

    // Serialize the relinearization (evaluation) key for homomorphic
    // multiplication
    std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
        if (crypto_context->serialize_eval_mult_key(emkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval mult keys to "
                         "key-eval-mult.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval mult keys have been serialized." << std::endl;

        emkeyfile.close();
    } else {
        std::cerr << "Error serializing eval mult keys" << std::endl;
        return 1;
    }

    // Generate the rotation evaluation keys
    crypto_context->eval_rotate_key_gen(key_pair.secret_key, {1, 2, -1, -2});

    std::cout << "The rotation keys have been generated." << std::endl;

    // Serialize the rotation keyhs
    std::ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out | std::ios::binary);
    if (erkeyfile.is_open()) {
        if (crypto_context->serialize_eval_automorphism_key(erkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval rotation keys to "
                         "key-eval-rot.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval rotation keys have been serialized." << std::endl;

        erkeyfile.close();
    } else {
        std::cerr << "Error serializing eval rotation keys" << std::endl;
        return 1;
    }

    // Sample Program: Step 3: Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);
    // Third plaintext vector is encoded
    std::vector<int64_t> vector_of_ints3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3 = crypto_context->make_packed_plaintext(vector_of_ints3);

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // The encoded vectors are encrypted
    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);
    auto ciphertext3 = crypto_context->encrypt(key_pair.public_key, plaintext3);

    std::cout << "The plaintexts have been encrypted." << std::endl;

    if (!serialization::serialize_to_file(DATAFOLDER + "/" + "ciphertext1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext has been serialized." << std::endl;

    if (!serialization::serialize_to_file(DATAFOLDER + "/" + "ciphertext2.txt", ciphertext2, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 2 to ciphertext2.txt" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext has been serialized." << std::endl;

    if (!serialization::serialize_to_file(DATAFOLDER + "/" + "ciphertext3.txt", ciphertext3, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 3 to ciphertext3.txt" << std::endl;
        return 1;
    }
    std::cout << "The third ciphertext has been serialized." << std::endl;

    // Sample Program: Step 4: Evaluation

    // Cipher maintains an internal map of CryptoContext objects which are
    // indexed by a tag and the tag is applied to both the CryptoContext and some
    // of the keys. When deserializing a context, Cipher checks for the tag and
    // if it finds it in the CryptoContext map, it will return the stored version.
    // Hence, we need to clear the context and clear the keys.
    crypto_context->clear_eval_mult_keys();
    crypto_context->clear_eval_automorphism_keys();
    cipher::ContextFactory<cipher::RnsPoly>::release_all_contexts();

    // Deserialize the crypto context
    CryptoContext<RnsPoly> cc;
    if (!serialization::deserialize_from_file(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<RnsPoly> pk;
    if (serialization::deserialize_from_file(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return 1;
    }
    std::cout << "The public key has been deserialized." << std::endl;

    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->deserialize_eval_mult_key(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;

    std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
    if (!erkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
        return 1;
    }
    if (cc->deserialize_eval_automorphism_key(erkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval rotation keys." << std::endl;

    Ciphertext<RnsPoly> ct1;
    if (serialization::deserialize_from_file(DATAFOLDER + "/ciphertext1.txt", ct1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext has been deserialized." << std::endl;

    Ciphertext<RnsPoly> ct2;
    if (serialization::deserialize_from_file(DATAFOLDER + "/ciphertext2.txt", ct2, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The second ciphertext has been deserialized." << std::endl;

    Ciphertext<RnsPoly> ct3;
    if (serialization::deserialize_from_file(DATAFOLDER + "/ciphertext3.txt", ct3, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The third ciphertext has been deserialized." << std::endl;

    // Homomorphic additions
    auto ciphertext_add12 = cc->eval_add(ct1, ct2);                  // iphertext2);
    auto ciphertext_add_result = cc->eval_add(ciphertext_add12, ct3);  // iphertext3);

    // Homomorphic multiplications
    auto ciphertext_mul12 = cc->eval_mult(ct1, ct2);                   // iphertext2);
    auto ciphertext_mult_result = cc->eval_mult(ciphertext_mul12, ct3);  // iphertext3);

    // Homomorphic rotations
    auto ciphertext_rot1 = cc->eval_rotate(ct1, 1);
    auto ciphertext_rot2 = cc->eval_rotate(ct1, 2);
    auto ciphertext_rot3 = cc->eval_rotate(ct1, -1);
    auto ciphertext_rot4 = cc->eval_rotate(ct1, -2);

    // Sample Program: Step 5: Decryption

    PrivateKey<RnsPoly> sk;
    if (serialization::deserialize_from_file(DATAFOLDER + "/key-private.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    // Decrypt the result of additions
    Plaintext plaintext_add_result;
    cc->decrypt(sk, ciphertext_add_result, &plaintext_add_result);

    // Decrypt the result of multiplications
    Plaintext plaintext_mult_result;
    cc->decrypt(sk, ciphertext_mult_result, &plaintext_mult_result);

    // Decrypt the result of rotations
    Plaintext plaintext_rot1;
    cc->decrypt(sk, ciphertext_rot1, &plaintext_rot1);
    Plaintext plaintext_rot2;
    cc->decrypt(sk, ciphertext_rot2, &plaintext_rot2);
    Plaintext plaintext_rot3;
    cc->decrypt(sk, ciphertext_rot3, &plaintext_rot3);
    Plaintext plaintext_rot4;
    cc->decrypt(sk, ciphertext_rot4, &plaintext_rot4);

    // Shows only the same number of elements as in the original plaintext vector
    // By default it will show all coefficients in the BFV-encoded polynomial
    plaintext_rot1->set_length(vector_of_ints1.size());
    plaintext_rot2->set_length(vector_of_ints1.size());
    plaintext_rot3->set_length(vector_of_ints1.size());
    plaintext_rot4->set_length(vector_of_ints1.size());

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2 + #3: " << plaintext_add_result << std::endl;
    std::cout << "#1 * #2 * #3: " << plaintext_mult_result << std::endl;
    std::cout << "Left rotation of #1 by 1: " << plaintext_rot1 << std::endl;
    std::cout << "Left rotation of #1 by 2: " << plaintext_rot2 << std::endl;
    std::cout << "Right rotation of #1 by 1: " << plaintext_rot3 << std::endl;
    std::cout << "Right rotation of #1 by 2: " << plaintext_rot4 << std::endl;
    return 0;
}
