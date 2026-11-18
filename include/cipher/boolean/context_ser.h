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
  Header file adding serialization support to Boolean circuit FHE
 */

#ifndef CIPHER_BOOLEAN_CONTEXT_SER_H_
#define CIPHER_BOOLEAN_CONTEXT_SER_H_

#include "cipher/boolean/context.h"
#include "cipher/util/serial.h"

// Registers types needed for serialization
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::LweCryptoParams, "lbcrypto::LWECryptoParams");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::LweCiphertextImpl, "lbcrypto::LWECiphertextImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::LwePrivateKeyImpl, "lbcrypto::LWEPrivateKeyImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::LwePublicKeyImpl, "lbcrypto::LWEPublicKeyImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::LweSwitchingKeyImpl, "lbcrypto::LWESwitchingKeyImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::RlweCiphertextImpl, "lbcrypto::RLWECiphertextImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::RingGswCryptoParams, "lbcrypto::RingGSWCryptoParams");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::RingGswEvalKeyImpl, "lbcrypto::RingGSWEvalKeyImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::RingGswAccKeyImpl, "lbcrypto::RingGSWACCKeyImpl");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::BooleanCryptoParams, "lbcrypto::BinFHECryptoParams");
CEREAL_REGISTER_TYPE_WITH_NAME(cipher::BooleanContext, "lbcrypto::BinFHEContext");

#endif  // CIPHER_BOOLEAN_CONTEXT_SER_H_
