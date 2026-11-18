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

#include "fhe/support/scheme_switching_data.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "cipher/fhe/ciphertext_ser.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/key/key_ser.h"
#include "cipher/fhe/ckks/ser.h"

// includes for get_program_path()
#if defined(_WIN32) && (defined(__MINGW32__) || defined(__MINGW64__))
    #include <windows.h>
#elif defined(__APPLE__)
    #include <mach-o/dyld.h>
#endif

namespace cipher {

// Helper function to get the absolute path to the running unittests executable
std::filesystem::path get_program_path() {
#if defined(_WIN32) && (defined(__MINGW32__) || defined(__MINGW64__))
    // MinGW: Unicode-safe wide API. Use a big static buffer (32K).
    wchar_t buf[32768];
    const DWORD cap = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    const DWORD len = GetModuleFileNameW(nullptr, buf, cap);
    if (len == 0 || len >= cap)
        CIPHER_THROW("Cannot get the executable path for Windows/MinGW.");

    return std::filesystem::path(buf, buf + len);
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);  // ask required size
    std::string tmp(size, '\0');
    if (_NSGetExecutablePath(tmp.data(), &size) != 0)
        CIPHER_THROW("Can not get the executable path for macOS.");

    return std::filesystem::path(tmp.c_str());
#elif defined(__linux__)
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec)
        CIPHER_THROW("Cannot read /proc/self/exe.");

    return p;
#else
    CIPHER_THROW("This architecture is not supported.");
#endif
}

std::string DataAndLocation::get_data_dir() {
    const std::filesystem::path exe = get_program_path();
    const std::filesystem::path exe_dir = exe.empty() ? std::filesystem::current_path() : exe.parent_path();

    // One level up (e.g., .../build/tests -> .../build)
    const std::filesystem::path base_dir = exe_dir.parent_path();
    const std::filesystem::path data_dir = base_dir / "data";

    std::error_code ec;
    std::filesystem::path abs = std::filesystem::weakly_canonical(data_dir, ec);
    if (ec || abs.empty()) {
        ec.clear();                                    // don't carry the old error forward
        abs = std::filesystem::absolute(data_dir, ec);  // fallback
    }
    if (ec || abs.empty()) {
        CIPHER_THROW(std::string("Cannot resolve data directory: ") + data_dir.string());
    }

    // Uncomment, if you want to ensure that the dir exists
    // std::filesystem::create_directories(abs); // throws on error

    return abs.string();
}

// Macros to be used in this source file only
#define THROW_SERIALIZATION_ERROR   CIPHER_THROW(std::string("Error serializing to ") + out_file)
#define THROW_DESERIALIZATION_ERROR CIPHER_THROW(std::string("Error deserializing from ") + out_file)
#define THROW_CAN_NOT_OPEN_FILE     CIPHER_THROW(std::string("Can not open ") + out_file)
#define SERTYPE                     SerType::BINARY

void SchemeSwitchingDataSerializer::to_stream() {
    // check if all 5 data memebers to be serialized are valid (not NULL)
    if (nullptr == crypto_context)
        CIPHER_THROW("cryptoContext is nullptr");
    else if (nullptr == public_key)
        CIPHER_THROW("publicKey is nullptr");
    else if (nullptr == bin_fhe_crypto_context)
        CIPHER_THROW("binFHECryptoContext is nullptr");
    else if (nullptr == fhew_to_ckks_switch_key)
        CIPHER_THROW("FHEWtoCKKSSwitchKey is nullptr");
    else if (nullptr == raw_ciphertext)
        CIPHER_THROW("RAWCiphertext is nullptr");

    std::string out_file;
    //=============================================================================================================
    out_file = data_directory + "/" + crypto_context_file;
    if (!serialization::serialize_to_file(out_file, crypto_context, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + pub_key_file;
    if (!serialization::serialize_to_file(out_file, public_key, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + mult_key_file;
    std::ofstream mult_key_file(out_file, std::ios::out | std::ios::binary);
    if (mult_key_file.is_open()) {
        if (!crypto_context->serialize_eval_mult_key(mult_key_file, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }
        mult_key_file.close();
    } else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + rot_key_file;
    std::ofstream rotation_key_file(out_file, std::ios::out | std::ios::binary);
    if (rotation_key_file.is_open()) {
        if (!crypto_context->serialize_eval_automorphism_key(rotation_key_file, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }
        rotation_key_file.close();
    } else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + fhew_to_ckks_switch_key_file;
    if (!serialization::serialize_to_file(out_file, fhew_to_ckks_switch_key, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + ciphertext_file;
    if (!serialization::serialize_to_file(out_file, raw_ciphertext, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + bin_fhe_crypto_context_file;
    if (!serialization::serialize_to_file(out_file, bin_fhe_crypto_context, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + bin_fhe_boot_key_file;
    if (!serialization::serialize_to_file(out_file, bin_fhe_crypto_context->get_bt_key(), SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    std::vector<uint32_t> indices;
    auto bt_key_map = bin_fhe_crypto_context->get_bt_key_map();
    for (auto it = bt_key_map->begin(); it != bt_key_map->end(); ++it) {
        uint32_t index = it->first;
        RingGswBtKey thekey = it->second;

        out_file = create_map_file_name(index, base_bt_key_file);
        if (!serialization::serialize_to_file(out_file, thekey, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }

        indices.push_back(index);
    }
    out_file = data_directory + "/" + key_index_file;
    if (!serialization::serialize_to_file(out_file, indices, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
}

void SchemeSwitchingDataDeserializer::from_stream() {
    std::string out_file;
    //=============================================================================================================
    out_file = data_directory + "/" + crypto_context_file;
    if (!serialization::deserialize_from_file(out_file, crypto_context, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + pub_key_file;
    if (!serialization::deserialize_from_file(out_file, public_key, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + mult_key_file;
    std::ifstream mult_key_file(out_file, std::ios::in | std::ios::binary);
    if (mult_key_file.is_open()) {
        if (!crypto_context->deserialize_eval_mult_key(mult_key_file, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }
        mult_key_file.close();
    } else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + rot_key_file;
    std::ifstream rotation_key_file(out_file, std::ios::in | std::ios::binary);
    if (rotation_key_file.is_open()) {
        if (!crypto_context->deserialize_eval_automorphism_key(rotation_key_file, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }
        rotation_key_file.close();
    } else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + fhew_to_ckks_switch_key_file;
    if (!serialization::deserialize_from_file(out_file, fhew_to_ckks_switch_key, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    crypto_context->set_swk_fc(fhew_to_ckks_switch_key);
    //=============================================================================================================
    out_file = data_directory + "/" + ciphertext_file;
    if (!serialization::deserialize_from_file(out_file, raw_ciphertext, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    out_file = data_directory + "/" + bin_fhe_crypto_context_file;
    if (!serialization::deserialize_from_file(out_file, bin_fhe_crypto_context, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    RingGswBtKey BT_key;
    out_file = data_directory + "/" + bin_fhe_boot_key_file;
    if (!serialization::deserialize_from_file(out_file, BT_key, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    bin_fhe_crypto_context->bt_key_load(BT_key);
    //=============================================================================================================
    std::vector<uint32_t> indices;
    out_file = data_directory + "/" + key_index_file;
    if (!serialization::deserialize_from_file(out_file, indices, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    } else if (!indices.size()) {
        std::string err_msg(std::string("Error deserializing from ") + out_file + ". No indices found.");
        CIPHER_THROW(err_msg);
    }
    for (uint32_t index : indices) {
        RingGswBtKey thekey;
        out_file = create_map_file_name(index, base_bt_key_file);
        if (!serialization::deserialize_from_file(out_file, thekey, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }

        // add single keys to the map
        bin_fhe_crypto_context->bt_key_map_load_single_element(index, thekey);
    }
    crypto_context->set_bin_cc_for_scheme_switch(bin_fhe_crypto_context);
    //=============================================================================================================
}

}  // namespace cipher
