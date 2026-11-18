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

#include "fhe/support/csv_data.h"

#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "fhe/support/test_exception.h"
#include "cipher/fhe/config/params.h"
#include "cipher/util/exception.h"

//===========================================================================================================
constexpr char DELIMITER = ',';
constexpr char EXTENSION[] = ".csv";
//===========================================================================================================
std::string create_data_file_name(const std::string& source_file_name) {
    size_t lastindex = source_file_name.find_last_of(".");
    return (source_file_name.substr(0, lastindex) + EXTENSION);
}
std::string create_data_file_name(const char* source_file_name) {
    return create_data_file_name(std::string(source_file_name));
}
//===========================================================================================================
std::vector<std::string> tokenize(const std::string& str, const char delim) {
    std::istringstream ss(std::move(str));
    std::vector<std::string> vec;
    for (std::string val; std::getline(ss, val, delim);) {
        vec.push_back(std::move(val));
    }
    return vec;
}
//===========================================================================================================
/**
 * check_column_names_for_cryptocontext_parameters() gets the first table row with column names and checks
 * if there are columns for all cryptocontext parameters. Throws an exception on error. The function is static in order
 * to limit access to it with this file.
 *
 * @param test_data is the open file with test data
 */
static void check_column_names_for_cryptocontext_parameters(std::ifstream& test_data) {
    std::string line;
    std::getline(test_data, line);
    // get all the columns first
    auto row = tokenize(line, DELIMITER);
    // skip the first 2 fields as they are for the test name
    auto start = row.begin() + 2;
    std::vector<std::string> column_names(start, start + cipher::Params::get_all_params_data_members().size());
    if (column_names != cipher::Params::get_all_params_data_members()) {
        std::string s;
        for (const auto& n : column_names) {
            s += n + ',';
        }
        std::string err_msg(
                std::string(
                        "Check the number and names of the columns for cryptoparameters as they do not match the expected: ") +
                s);
        CIPHER_THROW(err_msg);
    }
}
//===========================================================================================================
std::vector<std::vector<std::string>> read_data_file(const std::string& data_file_name) {
    std::ifstream test_data(data_file_name);
    if (!test_data.is_open()) {
        CIPHER_THROW("Cannot read file " + data_file_name);
    }

    try {
        check_column_names_for_cryptocontext_parameters(test_data);

        std::vector<std::vector<std::string>> file_rows;
        for (std::string line; std::getline(test_data, line);) {
            // skip all commented lines; they start with #
            if (line[0] != '#') {
                auto row = tokenize(line, DELIMITER);
                file_rows.push_back(std::move(row));
            }
        }

        return file_rows;
    } catch (std::exception& e) {
        std::string err_msg(std::string("Exception for data file ") + data_file_name + ": " + e.what());
        CIPHER_THROW(err_msg);
    } catch (...) {
        std::string err_msg(std::string("Unknown exception for data file ") + data_file_name + ": type " +
                            UNIT_TEST_EXCEPTION_TYPE_NAME);
        CIPHER_THROW(err_msg);
    }
}
//===========================================================================================================
