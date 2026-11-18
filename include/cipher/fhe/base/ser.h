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
  serialize keys; include this in any app that needs to serialize these objects
 */

#ifndef CIPHER_FHE_BASE_SER_H_
#define CIPHER_FHE_BASE_SER_H_

#include "cipher/ring/backend.h"
#include "cipher/util/serial.h"

extern template class cipher::BaseCryptoParams<cipher::RnsPoly>;
extern template class cipher::RlweCryptoParams<cipher::RnsPoly>;
extern template class cipher::SchemeBase<cipher::RnsPoly>;
extern template class cipher::BaseFhe<cipher::RnsPoly>;

CEREAL_REGISTER_TYPE_WITH_NAME(cipher::Serializable, "lbcrypto::Serializable");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::BaseCryptoParams<cipher::RnsPoly>, "lbcrypto::CryptoParametersBase<lbcrypto::DCRTPoly>");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::RlweCryptoParams<cipher::RnsPoly>, "lbcrypto::CryptoParametersRLWE<lbcrypto::DCRTPoly>");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::SchemeBase<cipher::RnsPoly>, "lbcrypto::SchemeBase<lbcrypto::DCRTPoly>");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::BaseFhe<cipher::RnsPoly>, "lbcrypto::FHEBase<lbcrypto::DCRTPoly>");

CEREAL_REGISTER_POLYMORPHIC_RELATION(cipher::BaseCryptoParams<cipher::RnsPoly>,
                                     cipher::RlweCryptoParams<cipher::RnsPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(cipher::Serializable, cipher::BaseCryptoParams<cipher::RnsPoly>);

#endif  // CIPHER_FHE_BASE_SER_H_
