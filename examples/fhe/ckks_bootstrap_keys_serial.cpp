//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Example for serializing and deserializing CKKS bootstrap evaluation keys.
 */

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cipher/cipher.h"

// Header files needed for serialization
#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/ckks/ser.h"

using namespace cipher;

const std::string DATAFOLDER = "data";
const std::string cc_location = "/bootstrap-cryptocontext.txt";
const std::string public_key_location = "/bootstrap-public-key.txt";
const std::string secret_key_location = "/bootstrap-secret-key.txt";
const std::string ciphertext_location = "/bootstrap-ciphertext.txt";
const std::string mult_key_location = "/bootstrap-eval-mult-keys.txt";
const std::string bootstrap_key_location = "/bootstrap-eval-keys.txt";

void error_check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << message << std::endl;
        std::exit(1);
    }
}

int main() {
    std::cout << "This program requires the `" << DATAFOLDER << "' directory to exist." << std::endl;

    ContextParams<CkksRnsContext> parameters;
    // SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128). UNIFORM_TERNARY,
    // used here, is the distribution of the homomorphic encryption security guidelines; its probability of failure is
    // 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

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

    std::vector<uint32_t> level_budget = {4, 4};
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> server_cc = make_crypto_context(parameters);
    server_cc->enable(PKE);
    server_cc->enable(KEYSWITCH);
    server_cc->enable(LEVELEDSHE);
    server_cc->enable(ADVANCEDSHE);
    server_cc->enable(FHE);

    uint32_t num_slots = server_cc->get_ring_dimension() / 2;
    server_cc->eval_bootstrap_setup(level_budget, {0, 0}, num_slots);

    auto key_pair = server_cc->key_gen();
    server_cc->eval_mult_key_gen(key_pair.secret_key);
    server_cc->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    auto plaintext = server_cc->make_ckks_packed_plaintext(x, 1, depth - 1);
    plaintext->set_length(x.size());
    auto ciphertext = server_cc->encrypt(key_pair.public_key, plaintext);

    error_check(serialization::serialize_to_file(DATAFOLDER + cc_location, server_cc, SerType::BINARY),
               "Error serializing crypto context");
    error_check(serialization::serialize_to_file(DATAFOLDER + public_key_location, key_pair.public_key, SerType::BINARY),
               "Error serializing public key");
    error_check(serialization::serialize_to_file(DATAFOLDER + secret_key_location, key_pair.secret_key, SerType::BINARY),
               "Error serializing secret key");
    error_check(serialization::serialize_to_file(DATAFOLDER + ciphertext_location, ciphertext, SerType::BINARY),
               "Error serializing ciphertext");

    std::ofstream mult_key_out(DATAFOLDER + mult_key_location, std::ios::out | std::ios::binary);
    error_check(mult_key_out.is_open(), "Error opening eval-mult key output file");
    error_check(server_cc->serialize_eval_mult_key(mult_key_out, SerType::BINARY), "Error serializing eval-mult keys");
    mult_key_out.close();

    std::ofstream bootstrap_key_out(DATAFOLDER + bootstrap_key_location, std::ios::out | std::ios::binary);
    error_check(bootstrap_key_out.is_open(), "Error opening bootstrap eval-key output file");
    error_check(server_cc->serialize_eval_bootstrap_key(bootstrap_key_out, SerType::BINARY, server_cc,
                                                   key_pair.secret_key->get_key_tag(), num_slots),
               "Error serializing bootstrap eval keys");
    bootstrap_key_out.close();

    server_cc->clear_eval_mult_keys();
    server_cc->clear_eval_automorphism_keys();
    ContextFactory<RnsPoly>::release_all_contexts();

    CryptoContext<RnsPoly> client_cc;
    PublicKey<RnsPoly> public_key;
    PrivateKey<RnsPoly> secret_key;
    Ciphertext<RnsPoly> client_ciphertext;

    error_check(serialization::deserialize_from_file(DATAFOLDER + cc_location, client_cc, SerType::BINARY),
               "Error deserializing crypto context");
    error_check(serialization::deserialize_from_file(DATAFOLDER + public_key_location, public_key, SerType::BINARY),
               "Error deserializing public key");
    error_check(serialization::deserialize_from_file(DATAFOLDER + secret_key_location, secret_key, SerType::BINARY),
               "Error deserializing secret key");
    error_check(serialization::deserialize_from_file(DATAFOLDER + ciphertext_location, client_ciphertext, SerType::BINARY),
               "Error deserializing ciphertext");
    client_cc->eval_bootstrap_setup(level_budget, {0, 0}, num_slots);
    const auto bootstrap_key_indices = client_cc->get_scheme()->eval_bootstrap_key_map_indices(client_cc, num_slots);

    std::ifstream mult_key_in(DATAFOLDER + mult_key_location, std::ios::in | std::ios::binary);
    error_check(mult_key_in.is_open(), "Error opening eval-mult key input file");
    error_check(client_cc->deserialize_eval_mult_key(mult_key_in, SerType::BINARY), "Error deserializing eval-mult keys");
    mult_key_in.close();

    std::ifstream bootstrap_key_in(DATAFOLDER + bootstrap_key_location, std::ios::in | std::ios::binary);
    error_check(bootstrap_key_in.is_open(), "Error opening bootstrap eval-key input file");
    error_check(client_cc->deserialize_eval_bootstrap_key(bootstrap_key_in, SerType::BINARY, client_cc, secret_key->get_key_tag(),
                                                     num_slots),
               "Error deserializing bootstrap eval keys");
    bootstrap_key_in.close();

    std::ifstream bootstrap_key_in_by_index(DATAFOLDER + bootstrap_key_location, std::ios::in | std::ios::binary);
    error_check(bootstrap_key_in_by_index.is_open(), "Error opening bootstrap eval-key input file");
    error_check(client_cc->deserialize_eval_bootstrap_key(bootstrap_key_in_by_index, SerType::BINARY, secret_key->get_key_tag(),
                                                     bootstrap_key_indices),
               "Error deserializing bootstrap eval keys by index list");
    bootstrap_key_in_by_index.close();

    auto ciphertext_after = client_cc->eval_bootstrap(client_ciphertext);

    Plaintext result;
    client_cc->decrypt(secret_key, ciphertext_after, &result);
    result->set_length(x.size());

    std::cout << "Input: " << plaintext << std::endl;
    std::cout << "Output after deserialized-key bootstrapping: " << result << std::endl;

    client_cc->clear_static_maps_and_vectors();

    return 0;
}
