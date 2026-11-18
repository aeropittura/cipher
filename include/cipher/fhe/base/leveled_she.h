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

#ifndef CIPHER_FHE_BASE_LEVELED_SHE_H_
#define CIPHER_FHE_BASE_LEVELED_SHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/encoding/plaintext_fwd.h"
#include "cipher/fhe/key/eval_key_fwd.h"
#include "cipher/fhe/key/private_key_fwd.h"
#include "cipher/fhe/key/public_key_fwd.h"
#include "cipher/ring/backend.h"
#include "cipher/util/caller_info.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {
/**
 * @brief Abstract interface class for LBC SHE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class BaseLeveledShe {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

    // TODO: should we use just one error message instead of two (see below)
    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_ERROR = "Not supported for this scheme";

  public:
    virtual ~BaseLeveledShe() = default;

    /////////////////////////////////////////
    // SHE NEGATION
    /////////////////////////////////////////

    /**
     * Virtual function to define the homomorphic negation of
     * ciphertext.
     *
     * @param ciphertext the input ciphertext.
     * @return new ciphertext.
     */
    virtual Ciphertext<Element> eval_negate(ConstCiphertext<Element>& ciphertext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic negation of
     * ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
     */
    virtual void eval_negate_in_place(Ciphertext<Element>& ciphertext) const;

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for in-place homomorphic addition
     * of ciphertexts.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext1,
                                                 Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void eval_add_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_add_mutable_in_place(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic addition of an integer scalar to a ciphertext.
     * Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of an integer scalar
     * to a ciphertext. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar to add.
     */
    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Adds a real constant to every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place addition of a real constant to every slot of a ciphertext (CKKS): the constant is scaled
     * by the scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant to add.
     */
    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Adds a complex constant to every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the complex constant to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place addition of a complex constant to every slot of a ciphertext (CKKS): the constant is scaled
     * by the scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the complex constant to add.
     */
    virtual void eval_add_in_place(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext1,
                                                 Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void eval_sub_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_sub_mutable_in_place(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic subtraction of an integer scalar from
     * a ciphertext. Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar to subtract.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of an integer scalar
     * from a ciphertext. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar to subtract.
     */
    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Subtracts a real constant from every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and subtracted from its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant to subtract.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place subtraction of a real constant from every slot of a ciphertext (CKKS): the constant is
     * scaled by the scaling factor of the ciphertext and subtracted from its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant to subtract.
     */
    virtual void eval_sub_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION
    //------------------------------------------------------------------------------

    /**
     * Virtual function to define the interface for generating an evaluation key
     * which is used after each multiplication.
     *
     * @param private_key the private key the relinearization key is generated for.
     * @return the relinearization (evaluation) key for s^2.
     */
    virtual EvalKey<Element> eval_mult_key_gen(const PrivateKey<Element> private_key) const;

    /**
     * Virtual function to define the interface for generating a evaluation key
     * which is used after each multiplication for depth more than 2.
     *
     * @param private_key the private key the relinearization keys are generated for.
     * @return the vector of relinearization (evaluation) keys for s^2, s^3, ...
     */
    virtual std::vector<EvalKey<Element>> eval_mult_keys_gen(const PrivateKey<Element> private_key) const;

    //------------------------------------------------------------------------------
    // EVAL MULTIPLICATION CIPHERTEXT & CIPHERTEXT
    //------------------------------------------------------------------------------

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext1,
                                          ConstCiphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext. This is the mutable version - input ciphertexts
     * may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic squaring
     * of ciphertext.
     *
     * @param ciphertext1 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_square(ConstCiphertext<Element>& ciphertext1) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic squaring
     * of ciphertext. This is the mutable version - input ciphertext
     * may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_square_mutable(Ciphertext<Element>& ciphertext1) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // EVAL MULTIPLICATION CIPHERTEXT & PLAINTEXT
    //------------------------------------------------------------------------------

    /**
     * Virtual function to define the interface for multiplication of ciphertext
     * by plaintext.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place multiplication of a ciphertext
     * by a plaintext: every ciphertext element is multiplied by the plaintext polynomial
     * (in EVALUATION format).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for multiplication of ciphertext
     * by plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place multiplication of ciphertext
     * by plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void eval_mult_mutable_in_place(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies the ciphertext by the monomial x^power of the cyclotomic ring, i.e., performs a
     * negacyclic shift of the encrypted coefficients (power is reduced modulo 2N; powers in [N, 2N)
     * flip the sign). The scaling factor and noise are not changed.
     *
     * @param ciphertext the input ciphertext.
     * @param power the exponent of the monomial.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> mult_by_monomial(ConstCiphertext<Element>& ciphertext, uint32_t power) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of the ciphertext by the monomial x^power of the cyclotomic ring
     * (negacyclic shift of the encrypted coefficients); see mult_by_monomial.
     *
     * @param ciphertext the input/output ciphertext.
     * @param power the exponent of the monomial.
     */
    virtual void mult_by_monomial_in_place(Ciphertext<Element>& ciphertext, uint32_t power) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for multiplication of a ciphertext by an integer scalar.
     * Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place multiplication of a ciphertext by an integer
     * scalar. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar.
     */
    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies a ciphertext by a real constant (CKKS): the constant is encoded at the scaling factor
     * of the current level, so the noise scale degree of the result is one higher than that of the input
     * (the automatic scaling techniques first rescale an input of noise scale degree 2).
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of a ciphertext by a real constant (CKKS); see eval_mult.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant.
     */
    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies a ciphertext by a complex constant (CKKS): the constant is encoded at the scaling factor
     * of the current level, so the noise scale degree of the result is one higher than that of the input
     * (the automatic scaling techniques first rescale an input of noise scale degree 2).
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the complex constant.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of a ciphertext by a complex constant (CKKS); see eval_mult.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the complex constant.
     */
    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies every element of the ciphertext by a positive integer without encoding it at the
     * scaling factor: the encrypted values are scaled by the integer exactly and the scaling factor and
     * noise scale degree of the ciphertext are left unchanged (CKKS).
     *
     * @param ciphertext the input ciphertext.
     * @param integer the positive integer to multiply by.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> mult_by_integer(ConstCiphertext<Element>& ciphertext, uint64_t integer) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of every element of the ciphertext by a positive integer without changing
     * the scaling factor or the noise scale degree (CKKS); see mult_by_integer.
     *
     * @param ciphertext the input/output ciphertext.
     * @param integer the positive integer to multiply by.
     */
    virtual void mult_by_integer_in_place(Ciphertext<Element>& ciphertext, uint64_t integer) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext using the evaluation key.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key is the evaluation key to make the new ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                          const EvalKey<Element> eval_key) const;

    /**
     * Virtual function to define the interface for in-place multiplicative homomorphic
     * evaluation of ciphertexts followed by relinearization with the evaluation key
     * (the third element of the product is key switched back to two elements).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key is the evaluation key to make the resulting ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     */
    virtual void eval_mult_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                    const EvalKey<Element> eval_key) const;

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext using the evaluation key. This is the mutable
     * version - input ciphertext may change (automatically rescaled, or towers
     * dropped).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key is the evaluation key to make the new ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                  const EvalKey<Element> eval_key) const;

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext using the evaluation key. This is the mutable
     * version - input ciphertext may change (automatically rescaled, or towers
     * dropped).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key is the evaluation key to make the resulting ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     */
    virtual void eval_mult_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                            const EvalKey<Element> eval_key) const;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     *
     * @param ciphertext the input ciphertext.
     * @param eval_key the relinearization key for s^2.
     * @return the new ciphertext with two elements.
     */
    virtual Ciphertext<Element> eval_square(ConstCiphertext<Element>& ciphertext,
                                            const EvalKey<Element> eval_key) const;

    /**
     * In-place homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param eval_key the relinearization key for s^2.
     */
    virtual void eval_square_in_place(Ciphertext<Element>& ciphertext1, const EvalKey<Element> eval_key) const;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     * This is the mutable version - the input ciphertext may change (automatically rescaled,
     * or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param eval_key the relinearization key for s^2.
     * @return the new ciphertext with two elements.
     */
    virtual Ciphertext<Element> eval_square_mutable(Ciphertext<Element>& ciphertext,
                                                    const EvalKey<Element> eval_key) const;
    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext followed by relinearization using the evaluation keys.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param eval_key_vec are the evaluation keys to make the new ciphertext
     *  decryptable by the same secret key as that of ciphertext1 and
     * ciphertext2.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> eval_mult_and_relinearize(ConstCiphertext<Element>& ciphertext1,
                                                          ConstCiphertext<Element>& ciphertext2,
                                                          const std::vector<EvalKey<Element>>& eval_key_vec) const;

    /**
     * Virtual function to do relinearization
     *
     * @param ciphertext input ciphertext.
     * @param eval_key_vec are the evaluation keys to make the new ciphertext
     *  decryptable by the same secret key as that of the input ciphertext.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> relinearize(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<EvalKey<Element>>& eval_key_vec) const;

    /**
     * Virtual function to do relinearization in-place
     *
     * @param ciphertext input/output ciphertext.
     * @param eval_key_vec are the evaluation keys to make the resulting ciphertext
     *  decryptable by the same secret key as that of the input ciphertext.
     */
    virtual void relinearize_in_place(Ciphertext<Element>& ciphertext,
                                      const std::vector<EvalKey<Element>>& eval_key_vec) const;

    //------------------------------------------------------------------------------
    // SHE AUTOMORPHISM
    //------------------------------------------------------------------------------

    /**
     * Virtual function to generate automophism keys for a given private key;
     * Uses the private key for encryption
     *
     * @param private_key private key.
     * @param index_list list of automorphism indices to be computed
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_automorphism_key_gen(
            const PrivateKey<Element> private_key, const std::vector<uint32_t>& index_list) const;

    /**
     * Virtual function for evaluating automorphism of ciphertext at index i
     *
     * @param ciphertext the input ciphertext.
     * @param i automorphism index
     * @param eval_key_map - reference to the map of evaluation keys generated by eval_automorphism_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_automorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                                  const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                                  CALLER_INFO_ARGS_HDR) const;

    /**
     * Shared core for evaluating an automorphism from precomputed key-switch digits.
     * Both eval_automorphism and eval_fast_rotation delegate here, so every rotation
     * entry point (eval_rotate/eval_at_index, hoisted fast rotations, conjugation)
     * applies the same operation sequence and produces bit-identical ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param auto_index automorphism index.
     * @param digits the digit decomposition of the second ciphertext element,
     * as produced by eval_fast_rotation_precompute.
     * @param eval_key the automorphism key for auto_index.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_automorphism_core(ConstCiphertext<Element>& ciphertext, uint32_t auto_index,
                                                       const std::shared_ptr<std::vector<Element>>& digits,
                                                       const EvalKey<Element>& eval_key) const;

    /**
     * Virtual function for the automorphism and key switching step of
     * hoisted automorphisms.
     *
     * @param ciphertext the input ciphertext to perform the automorphism on
     * @param index the index of the rotation. Positive indices correspond to
     * left rotations and negative indices correspond to right rotations.
     * @param m is the cyclotomic order
     * @param digits the digit decomposition created by
     * eval_fast_rotation_precompute at the precomputation step.
     * @return the rotated ciphertext
     */
    virtual Ciphertext<Element> eval_fast_rotation(ConstCiphertext<Element>& ciphertext, const uint32_t index,
                                                   const uint32_t m,
                                                   const std::shared_ptr<std::vector<Element>> digits) const;

    /**
     * Virtual function for the precomputation step of hoisted
     * automorphisms.
     *
     * @param ciphertext the input ciphertext on which to do the precomputation (digit
     * decomposition)
     * @return the digit decomposition of the ciphertext
     */
    virtual std::shared_ptr<std::vector<Element>> eval_fast_rotation_precompute(
            ConstCiphertext<Element>& ciphertext) const;

    /**
     * Hoisted (fast) rotation in the extended CRT basis Q*P, supported only with HYBRID key switching:
     * applies the key switching for the automorphism of rotation index \p index to the precomputed
     * digit decomposition and then the automorphism itself. The result stays in the extended basis
     * (see key_switch_down), which lets several rotations be accumulated with a single modulus reduction.
     *
     * @param ciphertext the input ciphertext.
     * @param index the rotation index (positive for left, negative for right).
     * @param expanded_ciphertext the digit decomposition of the second ciphertext element in the extended
     * basis, as produced by eval_fast_rotation_precompute.
     * @param add_first if true, the first ciphertext element (scaled up by P) is added to the result so
     * that it is a complete ciphertext; if false, only the key-switched part is returned.
     * @param eval_keys the map of automorphism keys generated by eval_automorphism_key_gen.
     * @return the rotated ciphertext in the extended basis Q*P.
     */
    virtual Ciphertext<Element> eval_fast_rotation_ext(ConstCiphertext<Element>& ciphertext, uint32_t index,
                                                       const std::shared_ptr<std::vector<Element>> expanded_ciphertext,
                                                       bool add_first,
                                                       const std::map<uint32_t, EvalKey<Element>>& eval_keys) const {
        CIPHER_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Generates evaluation keys for a list of indices
     * Currently works only for power-of-two and cyclic-group cyclotomics
     *
     * @param private_key private key the rotation keys are generated for.
     * @param index_list list of indices to be computed
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_at_index_key_gen(
            const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list) const;

    /**
     * Rotates the slots of the ciphertext by index
     *
     * @param ciphertext the input ciphertext.
     * @param index the rotation index (positive for left, negative for right).
     * @param eval_key_map - reference to the map of evaluation keys
     * generated by eval_at_index_key_gen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> eval_at_index(ConstCiphertext<Element>& ciphertext, int32_t index,
                                              const std::map<uint32_t, EvalKey<Element>>& eval_key_map) const;

    /**
     * Maps a rotation index to the automorphism index (Galois element) that realizes it for the
     * cyclotomic order m; the mapping depends on the packing of the scheme (real packing for BGV/BFV,
     * complex packing for CKKS).
     *
     * @param index the rotation index (positive for left, negative for right).
     * @param m the cyclotomic order.
     * @return the automorphism index.
     */
    virtual uint32_t find_automorphism_index(uint32_t index, uint32_t m) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /////////////////////////////////////////
    // SHE LEVELED Mod Reduce
    /////////////////////////////////////////

    /**
     * Method for Modulus Reduction.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction.
     */
    virtual Ciphertext<Element> mod_reduce(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for In-place Modulus Reduction.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     */
    virtual void mod_reduce_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for Composed eval_mult (multiplication, relinearization and modulus reduction)
     *
     * @param ciphertext1 first input ciphertext to perform
     * multiplication on.
     * @param ciphertext2 second input ciphertext to perform
     * multiplication on.
     * @param eval_key is the relinearization key for the quadratic secret key after
     * multiplication.
     * @return the resulting ciphertext that can be
     * decrypted with the secret key of the particular level.
     */
    virtual Ciphertext<Element> composed_eval_mult(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2,
                                                   const EvalKey<Element> eval_key) const;

    /**
     * Method for Level Reduction. Drops the given number of towers of the ciphertext
     * without changing the underlying plaintext.
     *
     * @param ciphertext1 is the original ciphertext to be level reduced.
     * @param eval_key evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     * @return the resulting ciphertext.
     */
    virtual Ciphertext<Element> level_reduce(ConstCiphertext<Element>& ciphertext1, const EvalKey<Element> eval_key,
                                             size_t levels) const;

    /**
     * Method for in-place Level Reduction. Drops the given number of towers of the
     * ciphertext without changing the underlying plaintext.
     *
     * @param ciphertext1 is the ciphertext to be level reduced in-place.
     * @param eval_key evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     */
    virtual void level_reduce_in_place(Ciphertext<Element>& ciphertext1, const EvalKey<Element> eval_key,
                                       size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Compresses a ciphertext to reduce its size for communication: rescales it until its noise scale
     * degree is at most \p noise_scale_deg and then drops towers until \p towers_left towers remain.
     * For the composite scaling techniques, \p towers_left must be a multiple of the composite degree.
     *
     * @param ciphertext the input ciphertext.
     * @param towers_left the number of RNS towers to keep.
     * @param noise_scale_deg the noise scale degree the ciphertext is rescaled to before towers are dropped.
     * @return the compressed ciphertext.
     */
    virtual Ciphertext<Element> compress(ConstCiphertext<Element>& ciphertext, size_t towers_left,
                                         size_t noise_scale_deg) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for rescaling.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction performed.
     */
    virtual Ciphertext<Element> mod_reduce_internal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for rescaling in-place.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @details \p ciphertext will have modulus reduction performed in-place.
     */
    virtual void mod_reduce_internal_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for Level Reduction in the CKKS scheme. It just drops "levels"
     * number of the towers of the ciphertext without changing the underlying
     * plaintext.
     *
     * @param ciphertext is the original ciphertext to be level reduced.
     * @param levels the number of towers to drop.
     * @return resulting ciphertext.
     */
    virtual Ciphertext<Element> level_reduce_internal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for in-place Level Reduction in the CKKS scheme. It just drops
     * "levels" number of the towers of the ciphertext without changing the
     * underlying plaintext.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place
     * @param levels the number of towers to drop.
     */
    virtual void level_reduce_internal_in_place(Ciphertext<Element>& ciphertext, size_t levels) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same number of RNS towers by dropping towers from the one with
     * more towers (level_reduce_internal_in_place); noise scale degrees are not changed.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void adjust_levels_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same level and noise scale degree so that they can be added or
     * subtracted (used by the automatic scaling techniques): the ciphertext at the lower level or
     * degree is rescaled, or multiplied by the appropriate scaling factor, and level reduced as needed.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void adjust_levels_and_depth_in_place(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same level and noise scale degree as adjust_levels_and_depth_in_place and
     * then rescales both to noise scale degree 1 if they are at degree 2; used before a multiplication.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void adjust_levels_and_depth_to_one_in_place(Ciphertext<Element>& ciphertext1,
                                                         Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    // TODO (Andrey) : Move these functions to protected or to rns?
    /**
     * Prepares two operands for addition or subtraction according to the scaling technique: FIXEDMANUAL
     * only matches the number of towers (and scales a single-element operand obtained from a plaintext up
     * to the noise scale degree of the other operand); the automatic techniques call
     * adjust_levels_and_depth_in_place; NORESCALE does nothing.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void adjust_for_add_or_sub_in_place(Ciphertext<Element>& ciphertext1,
                                                Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Prepares two operands for multiplication according to the scaling technique: FIXEDMANUAL only
     * matches the number of towers; the automatic techniques call adjust_levels_and_depth_to_one_in_place;
     * NORESCALE does nothing.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void adjust_for_mult_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        CIPHER_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Wraps a plaintext in a single-element ciphertext that shares the metadata of \p ciphertext
     * (crypto context, key tag) and carries the slots, level, noise scale degree and scaling factors of
     * the plaintext, so that a plaintext operand can go through the ciphertext level/depth adjustment
     * helpers (adjust_for_add_or_sub_in_place, adjust_for_mult_in_place).
     *
     * @param plaintext the plaintext to wrap.
     * @param ciphertext the ciphertext whose metadata is used for the result.
     * @return a ciphertext with one element holding the plaintext polynomial in EVALUATION format.
     */
    virtual Ciphertext<Element> morph_plaintext(ConstPlaintext& plaintext, ConstCiphertext<Element>& ciphertext) const;

  protected:
    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////
    /**
     * Throws if the two ciphertexts do not have the same number of RNS towers. The trailing
     * CALLER_INFO arguments carry the location of the caller for the error message.
     *
     * @param ciphertext1 first ciphertext.
     * @param ciphertext second ciphertext.
     */
    void verify_num_of_towers(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext,
                              CALLER_INFO_ARGS_HDR) const;
    /**
     * Throws if the ciphertext and the plaintext polynomial do not have the same number of RNS towers.
     * The trailing CALLER_INFO arguments carry the location of the caller for the error message.
     *
     * @param ciphertext the ciphertext.
     * @param plaintext the plaintext polynomial.
     */
    void verify_num_of_towers(ConstCiphertext<Element>& ciphertext, const Element& plaintext,
                              CALLER_INFO_ARGS_HDR) const;

    /**
     * Internal function for homomorphic addition of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic addition of input ciphertexts.
     */
    virtual Ciphertext<Element> eval_add_core(ConstCiphertext<Element>& ciphertext1,
                                              ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for in-place homomorphic addition of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input/output ciphertext; on return it contains the
     * result of the homomorphic addition of the input ciphertexts.
     * @param ciphertext2 second input ciphertext.
     */
    void eval_add_core_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for homomorphic subtraction of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic subtraction of input ciphertexts.
     */
    virtual Ciphertext<Element> eval_sub_core(ConstCiphertext<Element>& ciphertext1,
                                              ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for in-place homomorphic subtraction of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input/output ciphertext; on return it contains the
     * result of the homomorphic subtraction of the input ciphertexts.
     * @param ciphertext2 second input ciphertext.
     */
    void eval_sub_core_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for homomorphic multiplication of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic multiplication of input ciphertexts.
     */
    Ciphertext<Element> eval_mult_core(ConstCiphertext<Element>& ciphertext1,
                                       ConstCiphertext<Element>& ciphertext2) const;
    /**
     * Internal function for multiplication of a ciphertext by a plaintext polynomial: every ciphertext
     * element is multiplied by the polynomial. Only the number of towers is checked; the metadata
     * (scaling factor, noise scale degree) of the result is not updated.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the product ciphertext.
     */
    Ciphertext<Element> eval_mult_core(ConstCiphertext<Element>& ciphertext, const Element& plaintext) const;
    /**
     * Internal in-place multiplication of a ciphertext by a plaintext polynomial; see eval_mult_core.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void eval_mult_core_in_place(Ciphertext<Element>& ciphertext, const Element& plaintext) const;

    /**
     * Internal function for addition of a plaintext polynomial to a ciphertext: the polynomial is added
     * to the first ciphertext element. Only the number of towers is checked.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the sum ciphertext.
     */
    virtual Ciphertext<Element> eval_add_core(ConstCiphertext<Element>& ciphertext, const Element& plaintext) const;
    /**
     * Internal in-place addition of a plaintext polynomial to the first ciphertext element; see eval_add_core.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void eval_add_core_in_place(Ciphertext<Element>& ciphertext, const Element& plaintext) const;

    /**
     * Internal function for subtraction of a plaintext polynomial from a ciphertext: the polynomial is
     * subtracted from the first ciphertext element. Only the number of towers is checked.
     *
     * @param ciphertext1 the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the difference ciphertext.
     */
    virtual Ciphertext<Element> eval_sub_core(ConstCiphertext<Element>& ciphertext1, const Element& plaintext) const;
    /**
     * Internal in-place subtraction of a plaintext polynomial from the first ciphertext element;
     * see eval_sub_core.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void eval_sub_core_in_place(Ciphertext<Element>& ciphertext1, const Element& plaintext) const;

    /**
     * Internal function for homomorphic squaring of a ciphertext (tensor product with itself, using the
     * symmetry to halve the number of polynomial multiplications). An input with n elements gives a result
     * with 2n-1 elements, doubled noise scale degree and squared scaling factor. This method does not
     * check the level of the input.
     *
     * @param ciphertext the input ciphertext.
     * @return result of homomorphic squaring of the input ciphertext.
     */
    Ciphertext<Element> eval_square_core(ConstCiphertext<Element>& ciphertext) const;
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_LEVELED_SHE_H_
