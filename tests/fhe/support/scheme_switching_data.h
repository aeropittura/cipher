//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#ifndef CIPHER_TESTS_FHE_SUPPORT_SCHEME_SWITCHING_DATA_H_
#define CIPHER_TESTS_FHE_SUPPORT_SCHEME_SWITCHING_DATA_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/context.h"

namespace cipher {

class DataAndLocation {
    std::string get_data_dir();

  protected:
    CryptoContext<RnsPoly> crypto_context{nullptr};
    PublicKey<RnsPoly> public_key{nullptr};
    std::shared_ptr<cipher::BooleanContext> bin_fhe_crypto_context{nullptr};
    Ciphertext<RnsPoly> fhew_to_ckks_switch_key{nullptr};
    Ciphertext<RnsPoly> raw_ciphertext{nullptr};

    // Save-Load locations
    std::string data_directory = "data";
    const std::string crypto_context_file = "cryptocontext.txt";
    const std::string pub_key_file = "key_pub.txt";
    const std::string mult_key_file = "key_mult.txt";
    const std::string rot_key_file = "key_rot.txt";
    const std::string fhew_to_ckks_switch_key_file = "key_switch_fhew_ckks.txt";
    const std::string ciphertext_file = "ciphertext.txt";  // RAW ciphertext
    const std::string bin_fhe_crypto_context_file = "binfhe_cryptocontext.txt";
    const std::string bin_fhe_boot_key_file = "key_binfhe_boot.txt";
    const std::string base_bt_key_file = "key_bt.txt";
    const std::string key_index_file = "key_indices.txt";

    std::string create_map_file_name(uint32_t index, const std::string& base_file_name) {
        return std::string(data_directory) + "/" + std::to_string(index) + "_" + base_file_name;
    }

    DataAndLocation() = default;
    DataAndLocation(CryptoContext<RnsPoly> crypto_context0, PublicKey<RnsPoly> public_key0,
                    Ciphertext<RnsPoly> raw_ciphertext0)
        : crypto_context(crypto_context0),
          public_key(public_key0),
          bin_fhe_crypto_context(crypto_context0->get_bin_cc_for_scheme_switch()),
          fhew_to_ckks_switch_key(crypto_context0->get_swk_fc()),
          raw_ciphertext(raw_ciphertext0) {}

  public:
    void set_data_directory(const std::string& dir) {
        if (dir.empty()) {
            CIPHER_THROW("dir is an empty string");
        }

        // remove slash if it is the last charactes in "dir"
        if (dir.back() == '/')
            data_directory = dir.substr(0, dir.size() - 1);
        else
            data_directory = dir;
    }
};

class SchemeSwitchingDataSerializer : public DataAndLocation {
  public:
    SchemeSwitchingDataSerializer(CryptoContext<RnsPoly> crypto_context0, PublicKey<RnsPoly> public_key0,
                                  Ciphertext<RnsPoly> raw_ciphertext0)
        : DataAndLocation(crypto_context0, public_key0, raw_ciphertext0) {}

    void to_stream();
};

class SchemeSwitchingDataDeserializer : public DataAndLocation {
  public:
    SchemeSwitchingDataDeserializer() = default;

    CryptoContext<RnsPoly> get_crypto_context_impl() {
        return crypto_context;
    }
    PublicKey<RnsPoly> get_public_key_impl() {
        return public_key;
    }
    Ciphertext<RnsPoly> get_raw_ciphertext() {
        return raw_ciphertext;
    }

    void from_stream();
};

}  // namespace cipher

#endif  // CIPHER_TESTS_FHE_SUPPORT_SCHEME_SWITCHING_DATA_H_
