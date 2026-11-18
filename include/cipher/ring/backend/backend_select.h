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
  Defines aliases for the lattice default backend
 */

#ifndef CIPHER_RING_BACKEND_BACKEND_SELECT_H_
#define CIPHER_RING_BACKEND_BACKEND_SELECT_H_

#define ILPARAMS_IMPLEMENTATION     "cipher/ring/backend/standard/poly_params.h"
#define ILDCRTPARAMS_IMPLEMENTATION "cipher/ring/backend/standard/rns_params.h"
#define POLY_IMPLEMENTATION         "cipher/ring/backend/standard/poly_impl.h"
#define DCRTPOLY_IMPLEMENTATION     "cipher/ring/backend/standard/rns_poly_impl.h"

#define MAKE_ILPARAMS_TYPE(T)     template class PolyParamsImpl<T>;
#define MAKE_ILDCRTPARAMS_TYPE(T) template class RnsParams<T>;
#define MAKE_POLY_TYPE(T)         template class PolyImpl<T>;
#define MAKE_DCRTPOLY_TYPE(T)     template class RnsPolyImpl<T>;

#include "cipher/ring/backend/standard/rns_poly.h"
#include "cipher/ring/backend/standard/rns_params.h"
#include "cipher/ring/backend/standard/poly_params.h"
#include "cipher/ring/backend/standard/poly.h"

namespace cipher {

using NativePolyParams = PolyParamsImpl<NativeInteger>;
using PolyParams = PolyParamsImpl<BigInteger>;
using Poly = PolyImpl<BigVector>;
using NativePoly = PolyImpl<NativeVector>;
using RnsPoly = RnsPolyImpl<BigVector>;

using NativePolyParams32 = PolyParamsImpl<NativeInteger32>;
using NativePoly32 = PolyImpl<NativeVector32>;

#ifdef CIPHER_WITH_BE2
using M2Params = PolyParamsImpl<M2Integer>;
using M2RnsParams = RnsParams<M2Integer>;
using M2Poly = PolyImpl<M2Vector>;
using M2RnsPoly = RnsPolyImpl<M2Vector>;
#else
using M2Params = void;
using M2RnsParams = void;
using M2Poly = void;
using M2RnsPoly = void;
#endif

#ifdef CIPHER_WITH_BE4
using M4Params = PolyParamsImpl<M4Integer>;
using M4RnsParams = RnsParams<M4Integer>;
using M4Poly = PolyImpl<M4Vector>;
using M4RnsPoly = RnsPolyImpl<M4Vector>;
#else
using M4Params = void;
using M4RnsParams = void;
using M4Poly = void;
using M4RnsPoly = void;
#endif

#ifdef CIPHER_WITH_NTL
using M6Params = PolyParamsImpl<M6Integer>;
using M6RnsParams = RnsParams<M6Integer>;
using M6Poly = PolyImpl<M6Vector>;
using M6RnsPoly = RnsPolyImpl<M6Vector>;
#else
using M6Params = void;
using M6RnsParams = void;
using M6Poly = void;
using M6RnsPoly = void;
#endif

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_BACKEND_SELECT_H_
