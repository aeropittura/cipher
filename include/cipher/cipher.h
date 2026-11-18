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

#ifndef CIPHER_CIPHER_H_
#define CIPHER_CIPHER_H_

#include <initializer_list>
#include <memory>
#include <string>
#include <utility>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/crypto_object.h"
#include "cipher/fhe/encoding/plaintext_factory.h"
#include "cipher/fhe/context_gen.h"
#include "cipher/fhe/key/eval_key.h"
#include "cipher/fhe/key/relin_key.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/fhe/key/private_key.h"
#include "cipher/fhe/key/public_key.h"
#include "cipher/fhe/keyswitch/bv.h"
#include "cipher/fhe/keyswitch/hybrid.h"
#include "cipher/math/matrix.h"
#include "cipher/core.h"
#include "cipher/fhe/bfv/scheme.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/fhe/bgv/advanced_she.h"
#include "cipher/fhe/bgv/crypto_params.h"
#include "cipher/fhe/bgv/fhe.h"
#include "cipher/fhe/bgv/leveled_she.h"
#include "cipher/fhe/bgv/multiparty.h"
#include "cipher/fhe/bgv/param_gen.h"
#include "cipher/fhe/bgv/pke.h"
#include "cipher/fhe/bgv/pre.h"
#include "cipher/fhe/bgv/scheme.h"
#include "cipher/fhe/bgv/context_gen.h"
#include "cipher/fhe/ckks/scheme.h"
#include "cipher/fhe/ckks/context_gen.h"

#endif  // CIPHER_CIPHER_H_
