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
  implementation of the integer lattice
 */

#include "cipher/config.h"
#include "cipher/ring/field2n_impl.h"
#include "cipher/ring/backend.h"
#include "cipher/ring/ring_matrix_impl.h"
#include "cipher/math/binary_uniform_gen_impl.h"
#include "cipher/math/discrete_gaussian_gen_impl.h"
#include "cipher/math/discrete_uniform_gen_impl.h"
#include "cipher/math/matrix_impl.h"
#include "cipher/math/number_theory_impl.h"
#include "cipher/math/ternary_uniform_gen_impl.h"

#include ILPARAMS_IMPLEMENTATION
#include ILDCRTPARAMS_IMPLEMENTATION
#include POLY_IMPLEMENTATION
#include DCRTPOLY_IMPLEMENTATION

//---------------------------------------------------------------------------------------------
namespace cipher {

template class ElementParams<NativeInteger>;

MAKE_ILPARAMS_TYPE(NativeInteger)
MAKE_POLY_TYPE(NativeVector)

#if CIPHER_NATIVE_INT != 32
template class ElementParams<NativeInteger32>;
MAKE_ILPARAMS_TYPE(NativeInteger32)
MAKE_POLY_TYPE(NativeVector32)
#endif

template class Matrix<NativePoly>;
SPLIT64_FOR_TYPE(NativePoly)
SPLIT64ALT_FOR_TYPE(NativePoly)
SPLIT32ALT_FOR_TYPE(NativePoly)
template Matrix<NativeVector> rotate_vec_result(Matrix<NativePoly> const& in_mat);
template Matrix<NativeInteger> Rotate(Matrix<NativePoly> const& in_mat);

template class Matrix<Field2n>;

}  // namespace cipher

CEREAL_CLASS_VERSION(cipher::ElementParams<NativeInteger>, cipher::ElementParams<NativeInteger>::serialized_version());
CEREAL_CLASS_VERSION(cipher::NativePolyParams, cipher::NativePolyParams::serialized_version());
CEREAL_CLASS_VERSION(cipher::NativePoly, cipher::NativePoly::serialized_version());
CEREAL_CLASS_VERSION(cipher::Field2n, cipher::Field2n::serialized_version());

//---------------------------------------------------------------------------------------------
#ifdef CIPHER_WITH_BE2
namespace cipher {

template class ElementParams<M2Integer>;

MAKE_ILPARAMS_TYPE(M2Integer)
MAKE_ILDCRTPARAMS_TYPE(M2Integer)
MAKE_POLY_TYPE(M2Vector)
MAKE_DCRTPOLY_TYPE(M2Vector)

template class Matrix<M2Poly>;
SPLIT64_FOR_TYPE(M2Poly)
SPLIT64ALT_FOR_TYPE(M2Poly)
SPLIT32ALT_FOR_TYPE(M2Poly)
template Matrix<M2Vector> rotate_vec_result(Matrix<M2Poly> const& in_mat);
template Matrix<M2Integer> Rotate(Matrix<M2Poly> const& in_mat);

template class Matrix<M2RnsPoly>;
SPLIT64_FOR_TYPE(M2RnsPoly)
SPLIT64ALT_FOR_TYPE(M2RnsPoly)
SPLIT32ALT_FOR_TYPE(M2RnsPoly)
template Matrix<M2Vector> rotate_vec_result(Matrix<M2RnsPoly> const& in_mat);
template Matrix<M2Integer> Rotate(Matrix<M2RnsPoly> const& in_mat);

}  // namespace cipher

CEREAL_CLASS_VERSION(cipher::ElementParams<M2Integer>, cipher::ElementParams<M2Integer>::serialized_version());
CEREAL_CLASS_VERSION(cipher::M2Params, cipher::M2Params::serialized_version());
CEREAL_CLASS_VERSION(cipher::M2RnsParams, cipher::M2RnsParams::serialized_version());
CEREAL_CLASS_VERSION(cipher::M2Poly, cipher::M2Poly::serialized_version());
CEREAL_CLASS_VERSION(cipher::M2RnsPoly, cipher::M2RnsPoly::serialized_version());
#endif

//---------------------------------------------------------------------------------------------
#ifdef CIPHER_WITH_BE4
namespace cipher {

template class ElementParams<M4Integer>;

MAKE_ILPARAMS_TYPE(M4Integer)
MAKE_ILDCRTPARAMS_TYPE(M4Integer)
MAKE_POLY_TYPE(M4Vector)
MAKE_DCRTPOLY_TYPE(M4Vector)

template class Matrix<M4Poly>;
SPLIT64_FOR_TYPE(M4Poly)
SPLIT64ALT_FOR_TYPE(M4Poly)
SPLIT32ALT_FOR_TYPE(M4Poly)
template Matrix<M4Vector> rotate_vec_result(Matrix<M4Poly> const& in_mat);
template Matrix<M4Integer> Rotate(Matrix<M4Poly> const& in_mat);

template class Matrix<M4RnsPoly>;
SPLIT64_FOR_TYPE(M4RnsPoly)
SPLIT64ALT_FOR_TYPE(M4RnsPoly)
SPLIT32ALT_FOR_TYPE(M4RnsPoly)
template Matrix<M4Vector> rotate_vec_result(Matrix<M4RnsPoly> const& in_mat);
template Matrix<M4Integer> Rotate(Matrix<M4RnsPoly> const& in_mat);

}  // namespace cipher

CEREAL_CLASS_VERSION(cipher::ElementParams<M4Integer>, cipher::ElementParams<M4Integer>::serialized_version());
CEREAL_CLASS_VERSION(cipher::M4Params, cipher::M4Params::serialized_version());
CEREAL_CLASS_VERSION(cipher::M4RnsParams, cipher::M4RnsParams::serialized_version());
CEREAL_CLASS_VERSION(cipher::M4Poly, cipher::M4Poly::serialized_version());
CEREAL_CLASS_VERSION(cipher::M4RnsPoly, cipher::M4RnsPoly::serialized_version());
#endif

//---------------------------------------------------------------------------------------------
#ifdef CIPHER_WITH_NTL
namespace cipher {

template class ElementParams<M6Integer>;

MAKE_ILPARAMS_TYPE(M6Integer)
MAKE_ILDCRTPARAMS_TYPE(M6Integer)
MAKE_POLY_TYPE(M6Vector)
MAKE_DCRTPOLY_TYPE(M6Vector)

template class Matrix<M6Poly>;
SPLIT64_FOR_TYPE(M6Poly)
SPLIT64ALT_FOR_TYPE(M6Poly)
SPLIT32ALT_FOR_TYPE(M6Poly)
template Matrix<M6Vector> rotate_vec_result(Matrix<M6Poly> const& in_mat);
template Matrix<M6Integer> Rotate(Matrix<M6Poly> const& in_mat);

template class Matrix<M6RnsPoly>;
SPLIT64_FOR_TYPE(M6RnsPoly)
SPLIT64ALT_FOR_TYPE(M6RnsPoly)
SPLIT32ALT_FOR_TYPE(M6RnsPoly)
template Matrix<M6Vector> rotate_vec_result(Matrix<M6RnsPoly> const& in_mat);
template Matrix<M6Integer> Rotate(Matrix<M6RnsPoly> const& in_mat);

}  // namespace cipher

CEREAL_CLASS_VERSION(cipher::ElementParams<M6Integer>, cipher::ElementParams<M6Integer>::serialized_version());
CEREAL_CLASS_VERSION(cipher::M6Params, cipher::M6Params::serialized_version());
CEREAL_CLASS_VERSION(cipher::M6RnsParams, cipher::M6RnsParams::serialized_version());
CEREAL_CLASS_VERSION(cipher::M6Poly, cipher::M6Poly::serialized_version());
CEREAL_CLASS_VERSION(cipher::M6RnsPoly, cipher::M6RnsPoly::serialized_version());
#endif
