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
#ifndef CIPHER_TESTS_FHE_SUPPORT_BASE_TEST_CASE_H_
#define CIPHER_TESTS_FHE_SUPPORT_BASE_TEST_CASE_H_

#include <memory>
#include <string>
#include <vector>

#include "cipher/config.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/fhe/bgv/context_gen.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/fhe/config/params.h"
#include "cipher/util/exception.h"

struct BaseTestCase {
  private:
    // std::shared_ptr<cipher::Params> params;
    cipher::SCHEME scheme;
    std::vector<std::string> param_overrides;

  public:
    // there are cases when we don't support some features depending on different conditions.
    // skip_test() is to check all those conditions, so we do not get our unit tests failed
    bool skip_test() const {
#if CIPHER_NATIVE_INT == 128
        cipher::SCHEME scheme_id_value = cipher::convert_to_scheme(*param_overrides.begin());
        if (scheme_id_value == cipher::SCHEME::CKKSRNS_SCHEME) {
            cipher::ContextParams<cipher::CkksRnsContext> parameters(param_overrides);
            // CKKS does not support FLEXIBLEAUTO or FLEXIBLEAUTOEXT for CIPHER_NATIVE_INT == 128
            switch (parameters.get_scaling_technique()) {
                case cipher::ScalingTechnique::FLEXIBLEAUTO:
                case cipher::ScalingTechnique::FLEXIBLEAUTOEXT:
                    return true;
                default:
                    break;
            }
        }
#endif
        return false;
    }

    // const std::shared_ptr<cipher::Params> get_crypto_context_params() const {
    //    return params;
    // }

    // void set_crypto_context_params(std::shared_ptr<cipher::Params> params0) {
    //    params = params0;
    // }

    const std::vector<std::string>& get_crypto_context_param_overrides() const {
        return param_overrides;
    }

    /**
     * creates a new cryptocontext parameter object, overrides its data members if necessary and assigns it to params
     *
     * @param vec vector with overrides
     * @return number of all data members of Params or number of vec's elements that can override params
     */
    // size_t populate_crypto_context_params(const std::vector<std::string>::const_iterator& start) {
    //    // get the total number of the parameter override values
    //    size_t num_overrides = cipher::Params::get_all_params_data_members().size();

    //    // get the subset of elements with the parameter override values
    //    std::vector<std::string> override_values(start, start + num_overrides);

    //    cipher::SCHEME scheme = cipher::convert_to_scheme(*start);
    //    switch (scheme) {
    //    case cipher::CKKSRNS_SCHEME:
    //        set_crypto_context_params(std::make_shared<cipher::ContextParams<cipher::CkksRnsContext>>(overrideValues));
    //        break;
    //    case cipher::BFVRNS_SCHEME:
    //        set_crypto_context_params(std::make_shared<cipher::ContextParams<cipher::BfvRnsContext>>(overrideValues));
    //        break;
    //    case cipher::BGVRNS_SCHEME:
    //        set_crypto_context_params(std::make_shared<cipher::ContextParams<cipher::BgvRnsContext>>(overrideValues));
    //        break;
    //    default: {
    //        std::string err_msg(std::string("Unknown scheme_id_value ") + std::to_string(scheme));
    //        CIPHER_THROW(err_msg);
    //    }
    //    }

    //    return num_overrides;
    //}

    size_t set_crypto_context_params_overrides(const std::vector<std::string>::const_iterator& start) {
        // get the total number of the parameter override values
        size_t num_overrides = cipher::Params::get_all_params_data_members().size();

        scheme = cipher::convert_to_scheme(*start);

        // get the subset of elements with the parameter override values
        try {
            param_overrides = std::vector<std::string>(start, start + num_overrides);
        } catch (...) {
            std::string err_msg("Check the number of parameter overrides in the .csv file. It should be [" +
                                std::to_string(num_overrides) + "]");
            CIPHER_THROW(err_msg);
        }
        return num_overrides;
    }
};

#endif  // CIPHER_TESTS_FHE_SUPPORT_BASE_TEST_CASE_H_
