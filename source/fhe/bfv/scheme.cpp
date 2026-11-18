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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cipher/fhe/bfv/scheme.h"

#include <memory>
#include <sstream>
#include <string>

namespace cipher {

void BfvRnsScheme::enable(PkeSchemeFeature feature) {
    switch (feature) {
        case PKE:
            if (pke_ == nullptr)
                pke_ = std::make_shared<BfvRnsPke>();
            break;
        case KEYSWITCH:
            // key_switch_ must be initialized later by calling set_key_switching_technique() with the value of key switching technique from cryptoparams
            break;
        case PRE:
            if (pre_ == nullptr)
                pre_ = std::make_shared<BfvRnsPre>();
            break;
        case LEVELEDSHE:
            if (leveled_she_ == nullptr)
                leveled_she_ = std::make_shared<BfvRnsLeveledShe>();
            break;
        case MULTIPARTY:
            if (multiparty_ == nullptr)
                multiparty_ = std::make_shared<BfvRnsMultiparty>();
            break;
        case ADVANCEDSHE:
            if (advanced_she_ == nullptr)
                advanced_she_ = std::make_shared<BfvRnsAdvancedShe>();
            break;
        case FHE:
            if (fhe_ == nullptr)
                fhe_ = std::make_shared<BfvRnsFhe>();
            break;
        default:
            std::stringstream ss;
            ss << feature;
            CIPHER_THROW(std::string("This feature [") + ss.str() + "] is not supported for BFVRNS scheme");
    }
}

}  // namespace cipher
