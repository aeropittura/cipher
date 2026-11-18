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
  Scheme switching serialization in a simple context. The goal of this is to show a simple setup for scheme switching
  serialization before progressing into the next logical step - serialization and communication across
  2 separate entities
 */

#include <unistd.h>

#include <cmath>
#include <complex>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/cipher.h"

// header files needed for serialization
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/ckks/ser.h"
#include "fhe/support/scheme_switching_data.h"

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

// Save-load locations for evaluated ciphertext
std::string cipher_argmin_location = "/ciphertextArgmin.txt";

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
 * server_verification
 *  - deserialize data from the client.
 *  - Verify that the results are as we expect
 * @param cc cryptocontext that was previously generated
 * @param kp keypair that was previously generated
 * @param vector_size vector size of the vectors supplied
 * @return
 *  5-tuple of the plaintexts of various operations
 */

Plaintext server_verification(CryptoContext<RnsPoly>& cc, KeyPair<RnsPoly>& kp, int vector_size) {
    Ciphertext<RnsPoly> server_ciphertext_from_client_argmin;

    serialization::deserialize_from_file(DATAFOLDER + cipher_argmin_location, server_ciphertext_from_client_argmin,
                                         SerType::BINARY);
    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    demarcate("Part 5: Correctness verification");

    Plaintext server_plaintext_from_client_argmin;
    cc->decrypt(kp.secret_key, server_ciphertext_from_client_argmin, &server_plaintext_from_client_argmin);

    server_plaintext_from_client_argmin->set_length(vector_size);

    return server_plaintext_from_client_argmin;
}

/**
 * server_setup_and_write
 *  - simulates a server at startup where we generate a cryptocontext and keys.
 *  - then, we generate some data (akin to loading raw data on an enclave)
 * before encrypting the data
 * @param ring_dim - ring dimension
 * @param batch_size - batch size to use
 * @param mult_depth_value - multiplication depth
 * @param log_q_lwe - number of bits of the ciphertext modulus in FHEW
 * @param one_hot - flag to indicate one hot encoding of the result
 * @return Tuple<crypto_context, key_pair>
 */
std::tuple<CryptoContext<RnsPoly>, KeyPair<RnsPoly>, int> server_setup_and_write(uint32_t ring_dim, uint32_t batch_size,
                                                                                 uint32_t mult_depth_value,
                                                                                 uint32_t scale_mod_size,
                                                                                 uint32_t first_mod_size_value,
                                                                                 uint32_t log_q_lwe, bool one_hot) {
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(FLEXIBLEAUTO);

    CryptoContext<RnsPoly> server_cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    server_cc->enable(PKE);
    server_cc->enable(KEYSWITCH);
    server_cc->enable(LEVELEDSHE);
    server_cc->enable(ADVANCEDSHE);
    server_cc->enable(FHE);
    server_cc->enable(SCHEMESWITCH);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<RnsPoly> server_kp = server_cc->key_gen();
    std::cout << "Keypair generated" << std::endl;

    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_lwe);
    params.set_num_slots_ckks(batch_size);
    params.set_num_values(batch_size);
    params.set_compute_argmin(true);
    params.set_one_hot_encoding(one_hot);
    auto private_key_fhew = server_cc->eval_scheme_switching_setup(params);

    server_cc->eval_scheme_switching_key_gen(server_kp, private_key_fhew);

    std::vector<std::complex<double>> vec = {1.0, 2.0, 3.0, 4.0};
    std::cout << "\nDisplaying data vector: ";

    for (auto& v : vec) {
        std::cout << v << ',';
    }

    std::cout << '\n' << std::endl;

    Plaintext server_p = server_cc->make_ckks_packed_plaintext(vec);

    std::cout << "Plaintext version of vector: " << server_p << std::endl;

    std::cout << "Plaintexts have been generated from complex-double vectors" << std::endl;

    auto server_c = server_cc->encrypt(server_kp.public_key, server_p);

    std::cout << "Ciphertext have been generated from Plaintext" << std::endl;

    /*
     * Part 2:
     * We serialize the following:
     *  Cryptocontext
     *  Public key
     *  relinearization (eval mult keys)
     *  rotation keys
     *  binfhe cryptocontext
     *  binfhe bootstrapping keys
     *  Some of the ciphertext
     *
     *  We serialize all of them to files
     */

    demarcate("Scheme Switching Part 2: Data Serialization (server)");

    SchemeSwitchingDataSerializer serializer(server_cc, server_kp.public_key, server_c);
    serializer.to_stream();

    return std::make_tuple(server_cc, server_kp, vec.size());
}

/**
 * client_process
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data
 */

void client_process(uint32_t modulus_lwe) {
    CryptoContextImpl<RnsPoly>::clear_eval_mult_keys();
    CryptoContextImpl<RnsPoly>::clear_eval_sum_keys();
    CryptoContextImpl<RnsPoly>::clear_eval_automorphism_keys();
    ContextFactory<RnsPoly>::release_all_contexts();

    SchemeSwitchingDataDeserializer deserializer;
    deserializer.from_stream();

    CryptoContext<RnsPoly> client_cc{deserializer.get_crypto_context_impl()};
    PublicKey<RnsPoly> client_public_key{deserializer.get_public_key_impl()};
    std::shared_ptr<cipher::BooleanContext> client_bin_cc{client_cc->get_bin_cc_for_scheme_switch()};
    Ciphertext<RnsPoly> client_c{deserializer.get_raw_ciphertext()};

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto beta = client_bin_cc->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);  // Large precision

    client_cc->eval_compare_switch_precompute(p_lwe, scale_sign, false);

    std::cout << "Done with precomputations" << '\n' << std::endl;

    // Compute on the ciphertext
    auto client_ciphertext_argmin = client_cc->eval_min_scheme_switching(
            client_c, client_public_key, client_c->get_slots(), client_c->get_slots(), 0, 1);

    std::cout << "Done with argmin computation" << '\n' << std::endl;

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    serialization::serialize_to_file(DATAFOLDER + cipher_argmin_location, client_ciphertext_argmin[1], SerType::BINARY);

    std::cout << "Serialized ciphertext from client" << '\n' << std::endl;
}

int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    // Set main params
    uint32_t ring_dim = 64;
    uint32_t batch_size = 4;
    uint32_t mult_depth_value = 13 + static_cast<int>(std::log2(batch_size));
    uint32_t log_q_cc_lwe = 25;
    bool one_hot = true;
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;

    const int crypto_context_idx = 0;
    const int key_pair_idx = 1;
    const int vector_size_idx = 2;

    demarcate(
            "Scheme switching Part 1: Cryptocontext generation, key generation, data encryption "
            "(server)");

    auto tuple_crypto_context_key_pair = server_setup_and_write(ring_dim, batch_size, mult_depth_value, scale_mod_size,
                                                                first_mod_size_value, log_q_cc_lwe, one_hot);

    auto cc = std::get<crypto_context_idx>(tuple_crypto_context_key_pair);
    auto kp = std::get<key_pair_idx>(tuple_crypto_context_key_pair);
    auto vector_size = std::get<vector_size_idx>(tuple_crypto_context_key_pair);

    demarcate("Scheme switching Part 3: Client deserialize all data");

    client_process(1 << log_q_cc_lwe);

    demarcate("Scheme switching Part 4: Server deserialization of data from client. ");

    auto argmin_res = server_verification(cc, kp, vector_size);

    // vec1: {1,2,3,4}

    std::cout << argmin_res << std::endl;  // EXPECT: 1.0, 0.0, 0.0, 0.0
}
