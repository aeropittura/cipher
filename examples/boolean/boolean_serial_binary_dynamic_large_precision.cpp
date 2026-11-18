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
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS forA PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// forANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example forFHEW with binary serialization
 */

#include <cmath>
#include <cstdint>
#include <iostream>
#include <string>

#include "cipher/boolean/context_ser.h"

using namespace cipher;

// path where files will be written to
const std::string DATAFOLDER = "data";

int main() {
    // Generating the crypto context

    auto cc1 = BooleanContext();

    uint32_t log_q = 17;
    cc1.generate_boolean_context(TOY, false, log_q, 0, GINX, true);
    uint32_t Q = 1 << log_q;

    int q = 4096;                                                     // q
    int factor = 1 << int(log_q - std::log2(q));                      // Q/q
    int p = cc1.get_max_plaintext_space().convert_to_int() * factor;  // Obtain the maximum plaintext space

    std::cout << "Generating keys." << std::endl;

    // Generating the secret key
    auto sk1 = cc1.key_gen();

    // Generate the bootstrapping keys
    cc1.bt_key_gen(sk1);

    std::cout << "Done generating all keys." << std::endl;

    // Encryption fora ciphertext that will be serialized
    auto ct1 = cc1.encrypt(sk1, 1);

    // CODE forSERIALIZATION

    // Serializing key-independent crypto context

    if (!serialization::serialize_to_file(DATAFOLDER + "/cryptoContext.txt", cc1, SerType::BINARY)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed forbootstrapping)

    if (!serialization::serialize_to_file(DATAFOLDER + "/btKey.txt", cc1.get_bt_key(), SerType::BINARY)) {
        std::cerr << "Error serializing the bootstrapping keys" << std::endl;
        return 1;
    }
    std::cout << "The bootstrapping keys have been serialized." << std::endl;

    auto bt_key_map = cc1.get_bt_key_map();
    for (auto it = bt_key_map->begin(); it != bt_key_map->end(); it++) {
        auto index = it->first;
        auto thekey = it->second;
        if (!serialization::serialize_to_file(DATAFOLDER + "/" + std::to_string(index) + "btKey.txt", thekey,
                                              SerType::BINARY)) {
            std::cerr << "Error serializing the bootstrapping keys" << std::endl;
            return 1;
        }

        std::cout << "The BT map element for baseG = " << index << " has been serialized." << std::endl;
    }

    // Serializing private keys

    if (!serialization::serialize_to_file(DATAFOLDER + "/sk1.txt", sk1, SerType::BINARY)) {
        std::cerr << "Error serializing sk1" << std::endl;
        return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    // Serializing a ciphertext

    if (!serialization::serialize_to_file(DATAFOLDER + "/ct1.txt", ct1, SerType::BINARY)) {
        std::cerr << "Error serializing ct1" << std::endl;
        return 1;
    }
    std::cout << "A ciphertext has been serialized." << std::endl;

    // CODE forDESERIALIZATION

    // Deserializing the cryptocontext

    BooleanContext cc;
    if (serialization::deserialize_from_file(DATAFOLDER + "/cryptoContext.txt", cc, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (forbootstrapping)

    RingGswBtKey bt_key;
    if (serialization::deserialize_from_file(DATAFOLDER + "/btKey.txt", bt_key, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the bootstrapping keys" << std::endl;
        return 1;
    }
    std::cout << "The bootstrapping keys have been deserialized." << std::endl;

    uint32_t base_glist[3] = {1 << 14, 1 << 18, 1 << 27};

    for (size_t i = 0; i < 3; i++) {
        RingGswBtKey map_key;
        if (serialization::deserialize_from_file(DATAFOLDER + "/" + std::to_string(base_glist[i]) + "btKey.txt",
                                                 map_key, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the bootstrapping keys" << std::endl;
            return 1;
        }
        std::cout << "The BT map element for baseG = " << base_glist[i] << " has been deserialized." << std::endl;

        // Loading the keys in the cryptocontext
        cc.bt_key_map_load_single_element(base_glist[i], map_key);
    }

    // Loading the keys in the cryptocontext
    cc.bt_key_load(bt_key);

    // Deserializing the secret key

    LwePrivateKey sk;
    if (serialization::deserialize_from_file(DATAFOLDER + "/sk1.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    // Deserializing a previously serialized ciphertext

    LweCiphertext ct;
    if (serialization::deserialize_from_file(DATAFOLDER + "/ct1.txt", ct, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The ciphertext has been deserialized." << std::endl;

    // OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

    for (int i = 0; i < 8; i++) {
        // We first encrypt with large Q
        auto ct1 = cc.encrypt(sk, p / 2 + i - 3, LARGE_DIM, p, Q);

        // Get the MSB
        ct1 = cc.eval_sign(ct1);

        LwePlaintext result;
        cc.decrypt(sk, ct1, &result, 2);
        std::cout << "Input: " << i << ". Expected sign: " << (i >= 3)
                  << ". "
                     "Evaluated Sign: "
                  << result << std::endl;
    }

    return 0;
}
