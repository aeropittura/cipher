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

#ifndef CIPHER_FHE_BASE_MULTIPARTY_H_
#define CIPHER_FHE_BASE_MULTIPARTY_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/context_fwd.h"
#include "cipher/fhe/base/decrypt_result.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/private_key_fwd.h"
#include "cipher/fhe/key/public_key_fwd.h"
#include "cipher/fhe/ckks/crypto_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {
template <class Element>
class KeyPair;
/**
 * @brief Abstract interface class for LBC Multiparty algorithms based on
 * threshold FHE.  A version of this multiparty scheme built on the BGV scheme
 * is seen here:
 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs
 * D. (2012) Multiparty Computation with Low Communication, Computation and
 * Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds)
 * Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in
 * Computer Science, vol 7237. Springer, Berlin, Heidelberg
 *
 * During offline key generation, this multiparty scheme relies on the clients
 * coordinating their public key generation.  To do this, a single client
 * generates a public-secret key pair. This public key is shared with other
 * keys which use an element in the public key to generate their own public
 * keys. The clients generate a shared key pair using a scheme-specific
 * approach, then generate re-encryption keys.  Re-encryption keys are
 * uploaded to the server. Clients encrypt data with their public keys and
 * send the encrypted data server. The data is re-encrypted.  Computations are
 * then run on the data. The result is sent to each of the clients. One client
 * runs a "Leader" multiparty decryption operation with its own secret key.
 * All other clients run a regular "Main" multiparty decryption with their own
 * secret key. The resulting partially decrypted ciphertext are then fully
 * decrypted with the decryption fusion algorithms.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class BaseMultiparty {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

    constexpr static std::string_view NOT_SUPPORTED_ERROR = "This function is not supported";

  public:
    virtual ~BaseMultiparty() = default;

    /**
     * Threshold FHE: Generates a public key from a vector of secret shares.
     * ONLY FOR DEBUGGING PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
     *
     * @param cc cryptocontext for the keys to be generated.
     * @param private_key_vec secret key shares.
     * @param make_sparse_value set to true if ring reduce by a factor of 2 is to be
     * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
     * @return key pair including the private for the current party and joined
     * public key
     */
    virtual KeyPair<Element> multiparty_key_gen(CryptoContext<Element> cc,
                                              const std::vector<PrivateKey<Element>>& private_key_vec, bool make_sparse_value);

    /**
     * Threshold FHE: Generation of a public key derived
     * from a previous joined public key (for prior secret shares) and the secret
     * key share of the current party.
     *
     * @param cc cryptocontext for the keys to be generated.
     * @param public_key joined public key from prior parties.
     * @param make_sparse_value set to true if ring reduce by a factor of 2 is to be
     * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
     * @param fresh set to true if proxy re-encryption is used in the multi-party
     * protocol or star topology is used
     * @return key pair including the secret share for the current party and
     * joined public key
     */
    virtual KeyPair<Element> multiparty_key_gen(CryptoContext<Element> cc, const PublicKey<Element> public_key,
                                              bool make_sparse_value, bool fresh);

    /**
     * Threshold FHE: Generates a joined evaluation key
     * from the current secret share and a prior joined
     * evaluation key
     *
     * @param old_private_key secret key transformed from.
     * @param new_private_key secret key transformed to.
     * @param eval_key the prior joined evaluation key.
     * @return the new joined evaluation key.
     */
    virtual EvalKey<Element> multi_key_switch_gen(const PrivateKey<Element> old_private_key,
                                               const PrivateKey<Element> new_private_key,
                                               const EvalKey<Element> eval_key) const;

    /**
     * Threshold FHE: Generates joined automorphism keys
     * from the current secret share and prior joined
     * automorphism keys
     *
     * @param private_key secret key share.
     * @param eval_key_map a dictionary with prior joined automorphism keys.
     * @param index_vec a vector of automorphism indices.
     * @return a dictionary with new joined automorphism keys.
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_automorphism_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
            const std::vector<uint32_t>& index_vec) const;

    /**
     * Threshold FHE: Generates evaluation keys for a list of indices for a
     * multi-party setting Currently works only for power-of-two and cyclic-group
     * cyclotomics
     *
     * @param private_key secret share
     * @param eval_key_map evaluation key set from other party (parties)
     * @param index_vec list of indices to be computed
     * @return returns the joined evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_at_index_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
            const std::vector<int32_t>& index_vec) const;

    /**
     * Threshold FHE: Generates joined summation evaluation keys
     * from the current secret share and prior joined
     * summation keys
     *
     * @param private_key secret key share.
     * @param eval_key_map a dictionary with prior joined summation keys.
     * @return new joined summation keys.
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_sum_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map) const;

    // MULTIPARTY PKE

    /**
     * Threshold FHE: "Partial" decryption computed by all parties except for the
     * lead one
     *
     * @param ciphertext ciphertext that is being decrypted.
     * @param private_key secret key share used for decryption.
     * @return the partial decryption.
     */
    virtual Ciphertext<Element> multiparty_decrypt_main(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> private_key) const;

    /**
     * Threshold FHE: Method for decryption operation run by the lead decryption
     * client
     *
     * @param ciphertext ciphertext that is being decrypted.
     * @param private_key secret key share used for decryption.
     * @return the partial decryption.
     */
    virtual Ciphertext<Element> multiparty_decrypt_lead(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> private_key) const;

    /**
     * Threshold FHE: Method for combining the partially decrypted ciphertexts
     * and getting the final decryption in the clear as a NativePoly.
     *
     * @param ciphertext_vec vector of "partial" decryptions.
     * @param plaintext the plaintext output as a NativePoly.
     * @return the decoding result.
     */
    virtual DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                  NativePoly* plaintext) const;

    /**
     * Threshold FHE: Method for combining the partially decrypted ciphertexts
     * and getting the final decryption in the clear as a Poly.
     *
     * @param ciphertext_vec vector of "partial" decryptions.
     * @param plaintext the plaintext output as a Poly.
     * @return the decoding result.
     */
    virtual DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                  Poly* plaintext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Threshold FHE: Adds two prior public keys
     *
     * @param public_key1 first public key.
     * @param public_key2 second public key.
     * @return the new joined key.
     */
    virtual PublicKey<Element> multi_add_pub_keys(PublicKey<Element> public_key1, PublicKey<Element> public_key2) const;

    /**
     * Threshold FHE: Adds two prior evaluation keys
     *
     * @param eval_key1 first evaluation key.
     * @param eval_key2 second evaluation key.
     * @return the new joined key.
     */
    virtual EvalKey<Element> multi_add_eval_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2) const;

    /**
     * Threshold FHE: Adds two partial evaluation keys for multiplication
     *
     * @param eval_key1 first evaluation key.
     * @param eval_key2 second evaluation key.
     * @return the new joined key.
     */
    virtual EvalKey<Element> multi_add_eval_mult_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2) const;

    /**
     * Threshold FHE: Generates a partial evaluation key for homomorphic
     * multiplication based on the current secret share and an existing partial
     * evaluation key
     *
     * @param private_key current secret share.
     * @param eval_key prior evaluation key.
     * @return the new joined key.
     */
    virtual EvalKey<Element> multi_mult_eval_key(PrivateKey<Element> private_key, EvalKey<Element> eval_key) const;
    /**
     *
     * Threshold FHE: Adds two prior evaluation key sets for automorphisms
     *
     * @param eval_key_map1 first automorphism key set.
     * @param eval_key_map2 second automorphism key set.
     * @return the new joined key set for automorphisms.
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_automorphism_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2) const;

    /**
     * Threshold FHE: Adds two prior evaluation key sets for summation
     *
     * @param eval_key_map1 first summation key set.
     * @param eval_key_map2 second summation key set.
     * @return the new joined key set for summation.
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_sum_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2) const;

    /**
     * Prepare a ciphertext for interactive bootstrapping.
     *
     * For the FIXEDMANUAL and FIXEDAUTO modes of CKKS, drops the
     * the number of towers 2 and makes sure the scale is Delta
     * (not a power of Delta). The input should have at least 2
     * towers.
     *
     * For the FLEXIBLEAUTO mode of CKKS, the input ciphertext
     * should have at least 3 towers. One tower will be used to adjust
     * the scale to level 0.
     *
     * @param ciphertext Input Ciphertext
     * @return Resulting Ciphertext
     */
    virtual Ciphertext<Element> int_boot_adjust_scale(ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Does masked decryption as part of interactive bootstrapping.
     *
     * For the case of Server, it expects a ciphertext with both polynomials a and b.
     * For the case of Client, it expects only the polynomial a (for the linear term).
     * Under the hood, the decryption also includes the rounding operation.
     *
     * @param private_key secret key share
     * @param ciphertext input ciphertext
     * @return Resulting masked decryption
     */
    virtual Ciphertext<Element> int_boot_decrypt(const PrivateKey<Element> private_key,
                                               ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Does public key encryption of Client's masked decryption
     * as part of interactive bootstrapping, which increases
     * the ciphertext modulus and enables future computations.
     * This operation is done by the Client.
     *
     * @param public_key joint public key based on Threshold FHE
     * @param ciphertext input ciphertext
     * @return Resulting encryption
     */
    virtual Ciphertext<Element> int_boot_encrypt(const PublicKey<Element> public_key,
                                               ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Adds up both masked decryptions (one encrypted with public key
     * encryption), which is the last step of the interactive bootstrapping
     * procedure.
     *
     * @param ciphertext1 encrypted masked decryption
     * @param ciphertext2 unencrypted masked decryption
     * @return Refreshed ciphertext
     */
    virtual Ciphertext<Element> int_boot_add(ConstCiphertext<Element> ciphertext1,
                                           ConstCiphertext<Element> ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Threshold FHE: Prepare a ciphertext for Multi-Party Interactive Bootstrapping
     *
     * @param ciphertext Input Ciphertext
     * @return Resulting Ciphertext
     */
    virtual Ciphertext<Element> int_mp_boot_adjust_scale(ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping
     *
     * @param params CKKS crypto parameters used to sample the random polynomial
     * @param public_key the scheme public key (you can also provide the lead party's public-key)
     * @return Resulting ring element
     */
    virtual Ciphertext<Element> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                          const PublicKey<Element> public_key) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }
    /**
     * Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping,
     * using an existing ciphertext to derive the crypto context, key tag and element parameters,
     * so that no public key has to be supplied.
     *
     * @param params CKKS crypto parameters
     * @param ciphertext reference ciphertext whose metadata and element parameters are used
     * @return Resulting ring element, wrapped in a single-element ciphertext
     */
    virtual Ciphertext<Element> int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                          ConstCiphertext<Element>& ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Threshold FHE: Does masked decryption as part of Multi-Party Interactive Bootstrapping.
     * Each party calls this function as part of the protocol
     *
     * @param private_key secret key share for party i
     * @param ciphertext input ciphertext
     * @param a input common random polynomial
     * @return Resulting masked decryption
     */
    virtual std::vector<Ciphertext<Element>> int_mp_boot_decrypt(const PrivateKey<Element> private_key,
                                                              ConstCiphertext<Element> ciphertext,
                                                              ConstCiphertext<Element> a) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Threshold FHE: Aggregates a vector of masked decryptions and re-encryption shares,
     * which is the second step of the interactive multiparty bootstrapping procedure.
     *
     * @param shares_pair_vec vector of pair of ciphertexts, each element of this vector contains
     * (h_0i, h_1i) - the masked-decryption and encryption shares of party i
     * @return aggregated pair of shares (h_0, h_1)
     */
    virtual std::vector<Ciphertext<Element>> int_mp_boot_add(
            std::vector<std::vector<Ciphertext<Element>>>& shares_pair_vec) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     *  Threshold FHE: Does public key encryption of lead party's masked decryption
     * as part of interactive multi-party bootstrapping, which increases
     * the ciphertext modulus and enables future computations.
     * This operation is done by the lead party as the final step
     * of interactive multi-party bootstrapping.
     *
     * @param public_key the lead party's public key
     * @param shares_pair aggregated decryption and re-encryption shares
     * @param a common random ring element
     * @param ciphertext input ciphertext
     * @return Resulting encryption
     */
    virtual Ciphertext<Element> int_mp_boot_encrypt(const PublicKey<Element> public_key,
                                                 const std::vector<Ciphertext<Element>>& shares_pair,
                                                 ConstCiphertext<Element> a,
                                                 ConstCiphertext<Element> ciphertext) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string serialized_object_name() const {
        return "MultiPartyBase";
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_MULTIPARTY_H_
