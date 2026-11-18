//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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
  serialize cryptocontext; include this in any app that needs to serialize them
 */

#ifndef CIPHER_FHE_CONTEXT_SER_H_
#define CIPHER_FHE_CONTEXT_SER_H_

#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/bfv/ser.h"
#include "cipher/fhe/bgv/ser.h"
#include "cipher/fhe/ckks/ser.h"
#include "cipher/util/serial.h"

CEREAL_CLASS_VERSION(cipher::CryptoContextImpl<cipher::RnsPoly>,
                     cipher::CryptoContextImpl<cipher::RnsPoly>::serialized_version());

// the routines below are only instantiated if the user includes the appropriate
// serialize-*.h file

namespace cipher {

namespace internal_cc_traits {

// enable CryptoContextImpl<Element>
template <typename Element>
struct cc_ser_enabled<CryptoContextImpl<Element>> : std::true_type {};

// enable shared_ptr<CryptoContextImpl<Element>>
template <typename Element>
struct cc_ser_enabled<std::shared_ptr<CryptoContextImpl<Element>>> : std::true_type {};

}  // namespace internal_cc_traits

// ================================= JSON serialization/deserialization
namespace serialization {
/**
 * Deserialize for a CryptoContext (that is, a shared pointer to a
 * CryptoContextImpl Cipher doesn't want multiple copies of the same crypto
 * context floating around, and it enforces that here
 *
 * The unnamed third argument selects JSON serialization.
 *
 * @param obj - the target for the deserialization
 * @param stream - where the serialization is coming from
 */
template <typename T>
void from_stream(CryptoContext<T>& obj, std::istream& stream, const SerType::SERJSON&) {
    CryptoContext<T> newob;

    cereal::JSONInputArchive archive(stream);
    archive(newob);

    obj = ContextFactory<T>::get_context(newob->get_crypto_parameters(), newob->get_scheme(),
                                         newob->get_scheme_id_impl());
}

/**
 * Deserialize a CryptoContext from a JSON file (see Deserialize).
 *
 * @param filename - the file to read the serialization from
 * @param obj - the target for the deserialization
 * @param sertype - selects JSON serialization
 * @return true if the file could be opened
 */
template <typename T>
bool deserialize_from_file(const std::string& filename, CryptoContext<T>& obj, const SerType::SERJSON& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        serialization::from_stream(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}
}  // namespace serialization
/// @cond INTERNAL
template void serialization::from_stream(std::shared_ptr<CryptoContextImpl<RnsPoly>>& obj, std::istream& stream,
                                         const SerType::SERJSON&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_mult_key<SerType::SERJSON>(std::ostream& ser,
                                                                                    const SerType::SERJSON&,
                                                                                    const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_mult_key<SerType::SERJSON>(std::ostream& ser,
                                                                                    const SerType::SERJSON&,
                                                                                    const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key<SerType::SERJSON>(std::istream& ser,
                                                                                      const SerType::SERJSON&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_sum_key<SerType::SERJSON>(std::ostream& ser,
                                                                                   const SerType::SERJSON&,
                                                                                   const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_sum_key<SerType::SERJSON>(std::ostream& ser,
                                                                                   const SerType::SERJSON&,
                                                                                   const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_sum_key<SerType::SERJSON>(std::istream& ser,
                                                                                     const SerType::SERJSON&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_automorphism_key<SerType::SERJSON>(std::ostream& ser,
                                                                                            const SerType::SERJSON&,
                                                                                            const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_automorphism_key<SerType::SERJSON>(
        std::ostream& ser, const SerType::SERJSON&, const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_automorphism_key<SerType::SERJSON>(std::istream& ser,
                                                                                              const SerType::SERJSON&);
/// @endcond

// ================================= BINARY serialization/deserialization
namespace serialization {
/**
 * Deserialize for a CryptoContext (that is, a shared pointer to a
 * CryptoContextImpl Cipher doesn't want multiple copies of the same crypto
 * context floating around, and it enforces that here
 *
 * The unnamed third argument selects BINARY serialization.
 *
 * @param obj - the target for the deserialization
 * @param stream - where the serialization is coming from
 */
template <typename T>
void from_stream(CryptoContext<T>& obj, std::istream& stream, const SerType::SERBINARY&) {
    CryptoContext<T> newob;

    cereal::PortableBinaryInputArchive archive(stream);
    archive(newob);

    obj = ContextFactory<T>::get_context(newob->get_crypto_parameters(), newob->get_scheme(),
                                         newob->get_scheme_id_impl());
}

/**
 * Deserialize a CryptoContext from a binary file (see Deserialize).
 *
 * @param filename - the file to read the serialization from
 * @param obj - the target for the deserialization
 * @param sertype - selects BINARY serialization
 * @return true if the file could be opened
 */
template <typename T>
bool deserialize_from_file(const std::string& filename, CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        serialization::from_stream(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

/**
 * Deserialize a CryptoContext from a JSON string (see Deserialize).
 *
 * @param obj - the target for the deserialization
 * @param json - the JSON serialization
 */
template <typename T>
void deserialize_from_string(CryptoContext<T>& obj, const std::string& json) {
    std::stringstream s;
    s << json;
    serialization::from_stream(obj, s, SerType::JSON);
}
}  // namespace serialization

/// @cond INTERNAL
template void serialization::from_stream(std::shared_ptr<CryptoContextImpl<RnsPoly>>& obj, std::istream& stream,
                                         const SerType::SERBINARY&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_mult_key<SerType::SERBINARY>(std::ostream& ser,
                                                                                      const SerType::SERBINARY&,
                                                                                      const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_mult_key<SerType::SERBINARY>(std::ostream& ser,
                                                                                      const SerType::SERBINARY&,
                                                                                      const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_mult_key<SerType::SERBINARY>(std::istream& ser,
                                                                                        const SerType::SERBINARY&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_sum_key<SerType::SERBINARY>(std::ostream& ser,
                                                                                     const SerType::SERBINARY&,
                                                                                     const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_sum_key<SerType::SERBINARY>(std::ostream& ser,
                                                                                     const SerType::SERBINARY&,
                                                                                     const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_sum_key<SerType::SERBINARY>(std::istream& ser,
                                                                                       const SerType::SERBINARY&);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_automorphism_key<SerType::SERBINARY>(
        std::ostream& ser, const SerType::SERBINARY&, const std::string& key_tag);
template bool CryptoContextImpl<RnsPoly>::serialize_eval_automorphism_key<SerType::SERBINARY>(
        std::ostream& ser, const SerType::SERBINARY&, const CryptoContext<RnsPoly> cc);
template bool CryptoContextImpl<RnsPoly>::deserialize_eval_automorphism_key<SerType::SERBINARY>(
        std::istream& ser, const SerType::SERBINARY&);
/// @endcond

}  // namespace cipher

#endif  // CIPHER_FHE_CONTEXT_SER_H_
