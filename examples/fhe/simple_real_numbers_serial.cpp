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
  Real number serialization in a simple context. The goal of this is to show a simple setup for real number
  serialization before progressing into the next logical step - serialization and communication across
  2 separate entities
 */

#include <unistd.h>

#include <complex>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include "cipher/cipher.h"

// header files needed for serialization
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/ckks/ser.h"

using namespace cipher;

/////////////////////////////////////////////////////////////////
// NOTE:
// If running locally, you may want to replace the "hardcoded" DATAFOLDER with
// the DATAFOLDER location below which gets the current working directory
/////////////////////////////////////////////////////////////////
// char buff[1024];
// std::string DATAFOLDER = std::string(getcwd(buff, 1024));

// Save-Load locations for keys
const std::string DATAFOLDER = "data";
std::string cc_location = "/cryptocontext.txt";
std::string pub_key_location = "/key_pub.txt";    // Pub key
std::string mult_key_location = "/key_mult.txt";  // relinearization key
std::string rot_key_location = "/key_rot.txt";    // automorphism / rotation key

// Save-load locations for RAW ciphertexts
std::string cipher_one_location = "/ciphertext1.txt";
std::string cipher_two_location = "/ciphertext2.txt";

// Save-load locations for evaluated ciphertexts
std::string cipher_mult_location = "/ciphertextMult.txt";
std::string cipher_add_location = "/ciphertextAdd.txt";
std::string cipher_rot_location = "/ciphertextRot.txt";
std::string cipher_rot_neg_location = "/ciphertextRotNegLocation.txt";
std::string client_vector_location = "/ciphertextVectorFromClient.txt";

/**
 * Demarcate - Visual separator between the sections of code
 * @param msg - string message that you want displayed between blocks of
 * characters
 */
void demarcate(const std::string& msg) {
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
    std::cout << msg << std::endl;
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
}

/**
 * server_setup_and_write
 *  - simulates a server at startup where we generate a cryptocontext and keys.
 *  - then, we generate some data (akin to loading raw data on an enclave)
 * before encrypting the data
 * @param mult_depth_value - multiplication depth
 * @param scale_mod_size - number of bits to use in the scale factor (not the
 * scale factor itself)
 * @param batch_size - batch size to use
 * @return Tuple<crypto_context, key_pair>
 */
std::tuple<CryptoContext<RnsPoly>, KeyPair<RnsPoly>, int> server_setup_and_write(int mult_depth_value, int scale_mod_size,
                                                                                int batch_size) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> server_cc = make_crypto_context(parameters);

    server_cc->enable(PKE);
    server_cc->enable(KEYSWITCH);
    server_cc->enable(LEVELEDSHE);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<RnsPoly> server_kp = server_cc->key_gen();
    std::cout << "Keypair generated" << std::endl;

    server_cc->eval_mult_key_gen(server_kp.secret_key);
    std::cout << "Eval Mult Keys/ Relinearization keys have been generated" << std::endl;

    server_cc->eval_rotate_key_gen(server_kp.secret_key, {1, 2, -1, -2});
    std::cout << "Rotation keys generated" << std::endl;

    std::vector<std::complex<double>> vec1 = {1.0, 2.0, 3.0, 4.0};
    std::vector<std::complex<double>> vec2 = {12.5, 13.5, 14.5, 15.5};
    std::vector<std::complex<double>> vec3 = {10.5, 11.5, 12.5, 13.5};
    std::cout << "\nDisplaying first data vector: ";

    for (auto& v : vec1) {
        std::cout << v << ',';
    }

    std::cout << '\n' << std::endl;

    Plaintext server_p1 = server_cc->make_ckks_packed_plaintext(vec1);
    Plaintext server_p2 = server_cc->make_ckks_packed_plaintext(vec2);
    Plaintext server_p3 = server_cc->make_ckks_packed_plaintext(vec3);

    std::cout << "Plaintext version of first vector: " << server_p1 << std::endl;

    std::cout << "Plaintexts have been generated from complex-double vectors" << std::endl;

    auto server_c1 = server_cc->encrypt(server_kp.public_key, server_p1);
    auto server_c2 = server_cc->encrypt(server_kp.public_key, server_p2);
    auto server_c3 = server_cc->encrypt(server_kp.public_key, server_p3);

    std::cout << "Ciphertexts have been generated from Plaintexts" << std::endl;

    /*
     * Part 2:
     * We serialize the following:
     *  Cryptocontext
     *  Public key
     *  relinearization (eval mult keys)
     *  rotation keys
     *  Some of the ciphertext
     *
     *  We serialize all of them to files
     */

    demarcate("Part 2: Data Serialization (server)");

    if (!serialization::serialize_to_file(DATAFOLDER + cc_location, server_cc, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }

    std::cout << "Cryptocontext serialized" << std::endl;

    if (!serialization::serialize_to_file(DATAFOLDER + pub_key_location, server_kp.public_key, SerType::BINARY)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    std::ofstream mult_key_file(DATAFOLDER + mult_key_location, std::ios::out | std::ios::binary);
    if (mult_key_file.is_open()) {
        if (!server_cc->serialize_eval_mult_key(mult_key_file, SerType::BINARY)) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult/ relinearization keys have been serialized" << std::endl;
        mult_key_file.close();
    } else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotation_key_file(DATAFOLDER + rot_key_location, std::ios::out | std::ios::binary);
    if (rotation_key_file.is_open()) {
        if (!server_cc->serialize_eval_automorphism_key(rotation_key_file, SerType::BINARY)) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    } else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    if (!serialization::serialize_to_file(DATAFOLDER + cipher_one_location, server_c1, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }

    if (!serialization::serialize_to_file(DATAFOLDER + cipher_two_location, server_c2, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 2" << std::endl;
    }

    return std::make_tuple(server_cc, server_kp, vec1.size());
}

/**
 * client_process
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data by doing operations (multiplication, addition,
 * rotation, etc)
 *  - !! We also create an object and encrypt it in this function before sending
 * it off to the server to be decrypted
 */
void client_process() {
    CryptoContext<RnsPoly> client_cc;
    client_cc->clear_eval_mult_keys();
    client_cc->clear_eval_automorphism_keys();
    cipher::ContextFactory<cipher::RnsPoly>::release_all_contexts();
    if (!serialization::deserialize_from_file(DATAFOLDER + cc_location, client_cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized";

    KeyPair<RnsPoly> client_kp;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<RnsPoly> client_public_key;
    if (!serialization::deserialize_from_file(DATAFOLDER + pub_key_location, client_public_key, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << '\n' << std::endl;

    std::ifstream mult_key_i_stream(DATAFOLDER + mult_key_location, std::ios::in | std::ios::binary);
    if (!mult_key_i_stream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + mult_key_location << std::endl;
        std::exit(1);
    }
    if (!client_cc->deserialize_eval_mult_key(mult_key_i_stream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized eval mult keys" << '\n' << std::endl;
    std::ifstream rot_key_i_stream(DATAFOLDER + rot_key_location, std::ios::in | std::ios::binary);
    if (!rot_key_i_stream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + mult_key_location << std::endl;
        std::exit(1);
    }
    if (!client_cc->deserialize_eval_automorphism_key(rot_key_i_stream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    Ciphertext<RnsPoly> client_c1;
    Ciphertext<RnsPoly> client_c2;
    if (!serialization::deserialize_from_file(DATAFOLDER + cipher_one_location, client_c1, SerType::BINARY)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipher_one_location << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized ciphertext1" << '\n' << std::endl;

    if (!serialization::deserialize_from_file(DATAFOLDER + cipher_two_location, client_c2, SerType::BINARY)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipher_two_location << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized ciphertext1" << '\n' << std::endl;
    auto client_ciphertext_mult = client_cc->eval_mult(client_c1, client_c2);
    auto client_ciphertext_add = client_cc->eval_add(client_c1, client_c2);
    auto client_ciphertext_rot = client_cc->eval_rotate(client_c1, 1);
    auto client_ciphertext_rot_neg = client_cc->eval_rotate(client_c1, -1);

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    std::vector<std::complex<double>> client_vector1 = {1.0, 2.0, 3.0, 4.0};
    auto client_plaintext1 = client_cc->make_ckks_packed_plaintext(client_vector1);
    auto client_initiated_encryption = client_cc->encrypt(client_public_key, client_plaintext1);
    serialization::serialize_to_file(DATAFOLDER + cipher_mult_location, client_ciphertext_mult, SerType::BINARY);
    serialization::serialize_to_file(DATAFOLDER + cipher_add_location, client_ciphertext_add, SerType::BINARY);
    serialization::serialize_to_file(DATAFOLDER + cipher_rot_location, client_ciphertext_rot, SerType::BINARY);
    serialization::serialize_to_file(DATAFOLDER + cipher_rot_neg_location, client_ciphertext_rot_neg, SerType::BINARY);
    serialization::serialize_to_file(DATAFOLDER + client_vector_location, client_initiated_encryption, SerType::BINARY);

    std::cout << "Serialized all ciphertexts from client" << '\n' << std::endl;
}

/**
 * server_verification
 *  - deserialize data from the client.
 *  - Verify that the results are as we expect
 * @param cc cryptocontext that was previously generated
 * @param kp keypair that was previously generated
 * @param vector_size vector size of the vectors supplied
 * @return
 *  5-tuple of the plaintexts of various operations
 */

std::tuple<Plaintext, Plaintext, Plaintext, Plaintext, Plaintext> server_verification(CryptoContext<RnsPoly>& cc,
                                                                                     KeyPair<RnsPoly>& kp,
                                                                                     int vector_size) {
    Ciphertext<RnsPoly> server_ciphertext_from_client_mult;
    Ciphertext<RnsPoly> server_ciphertext_from_client_add;
    Ciphertext<RnsPoly> server_ciphertext_from_client_rot;
    Ciphertext<RnsPoly> server_ciphertext_from_client_rog_neg;
    Ciphertext<RnsPoly> server_ciphertext_from_client_vec;

    serialization::deserialize_from_file(DATAFOLDER + cipher_mult_location, server_ciphertext_from_client_mult, SerType::BINARY);
    serialization::deserialize_from_file(DATAFOLDER + cipher_add_location, server_ciphertext_from_client_add, SerType::BINARY);
    serialization::deserialize_from_file(DATAFOLDER + cipher_rot_location, server_ciphertext_from_client_rot, SerType::BINARY);
    serialization::deserialize_from_file(DATAFOLDER + cipher_rot_neg_location, server_ciphertext_from_client_rog_neg, SerType::BINARY);
    serialization::deserialize_from_file(DATAFOLDER + client_vector_location, server_ciphertext_from_client_vec, SerType::BINARY);
    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    demarcate("Part 5: Correctness verification");

    Plaintext server_plaintext_from_client_mult;
    Plaintext server_plaintext_from_client_add;
    Plaintext server_plaintext_from_client_rot;
    Plaintext server_plaintext_from_client_rot_neg;
    Plaintext server_plaintext_from_client_vec;

    cc->decrypt(kp.secret_key, server_ciphertext_from_client_mult, &server_plaintext_from_client_mult);
    cc->decrypt(kp.secret_key, server_ciphertext_from_client_add, &server_plaintext_from_client_add);
    cc->decrypt(kp.secret_key, server_ciphertext_from_client_rot, &server_plaintext_from_client_rot);
    cc->decrypt(kp.secret_key, server_ciphertext_from_client_rog_neg, &server_plaintext_from_client_rot_neg);
    cc->decrypt(kp.secret_key, server_ciphertext_from_client_vec, &server_plaintext_from_client_vec);

    server_plaintext_from_client_mult->set_length(vector_size);
    server_plaintext_from_client_add->set_length(vector_size);
    server_plaintext_from_client_vec->set_length(vector_size);
    server_plaintext_from_client_rot->set_length(vector_size + 1);
    server_plaintext_from_client_rot_neg->set_length(vector_size + 1);

    return std::make_tuple(server_plaintext_from_client_mult, server_plaintext_from_client_add, server_plaintext_from_client_vec,
                           server_plaintext_from_client_rot, server_plaintext_from_client_rot_neg);
}
int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    // Set main params
    const int mult_depth_value = 5;
    const int scale_mod_size = 40;
    const uint32_t batch_size = 32;

    const int crypto_context_idx = 0;
    const int key_pair_idx = 1;
    const int vector_size_idx = 2;

    const int cipher_mult_res_idx = 0;
    const int cipher_add_res_idx = 1;
    const int cipher_vec_res_idx = 2;
    const int cipher_rot_res_idx = 3;
    const int cipher_rot_neg_res_idx = 4;

    demarcate(
            "Part 1: Cryptocontext generation, key generation, data encryption "
            "(server)");

    auto tuple_crypto_context_key_pair = server_setup_and_write(mult_depth_value, scale_mod_size, batch_size);
    auto cc = std::get<crypto_context_idx>(tuple_crypto_context_key_pair);
    auto kp = std::get<key_pair_idx>(tuple_crypto_context_key_pair);
    int vector_size = std::get<vector_size_idx>(tuple_crypto_context_key_pair);

    demarcate("Part 3: Client deserialize all data");
    client_process();

    demarcate("Part 4: Server deserialization of data from client. ");

    auto tuple_res = server_verification(cc, kp, vector_size);
    auto mult_res = std::get<cipher_mult_res_idx>(tuple_res);
    auto add_res = std::get<cipher_add_res_idx>(tuple_res);
    auto vec_res = std::get<cipher_vec_res_idx>(tuple_res);
    auto rot_res = std::get<cipher_rot_res_idx>(tuple_res);
    auto rot_neg_res = std::get<cipher_rot_neg_res_idx>(tuple_res);

    // vec1: {1,2,3,4}
    // vec2: {12.5, 13.5, 14.5, 15.5}

    std::cout << mult_res << std::endl;  // EXPECT: 12.5, 27.0, 43.5, 62
    std::cout << add_res << std::endl;   // EXPECT: 13.5, 15.5, 17.5, 19.5
    std::cout << vec_res << std::endl;   // EXPECT:  {1,2,3,4}

    std::cout << "Displaying 5 elements of a 4-element vector to illustrate rotation" << '\n';
    std::cout << rot_res << std::endl;     // EXPECT: {2, 3, 4, noise, noise}
    std::cout << rot_neg_res << std::endl;  // EXPECT: {noise, 1, 2, 3, 4}
}
