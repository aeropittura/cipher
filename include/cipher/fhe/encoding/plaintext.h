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
  Represents and defines plaintext objects in Cipher
 */

#ifndef CIPHER_FHE_ENCODING_PLAINTEXT_H_
#define CIPHER_FHE_ENCODING_PLAINTEXT_H_

#include <algorithm>
#include <complex>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/constants.h"
#include "cipher/fhe/encoding/encoding_params.h"
#include "cipher/fhe/encoding/plaintext_fwd.h"
#include "cipher/fhe/config/scheme_id.h"

namespace cipher {

/**
 * @class PlaintextImpl
 * @brief This class represents plaintext in the Cipher library.
 *
 * PlaintextImpl is primarily intended to be
 * used as a container and in conjunction with specific encodings which inherit
 * from this class which depend on the application the plaintext is used with.
 * It provides virtual methods for encoding and decoding of data.
 */
class PlaintextImpl {
  protected:
    /**
     * @brief Type of the polynomial the plaintext is encoded into.
     */
    enum PtxtPolyType { IsPoly, IsDCRTPoly, IsNativePoly };

    bool is_encoded_{false};         ///< whether the values have been encoded into the polynomial
    PtxtPolyType type_flag;          ///< which of the three polynomial members is in use
    EncodingParams encoding_params;  ///< encoding parameters (plaintext modulus, batch size, ...)

    Poly encoded_vector;               ///< encoded polynomial (multiprecision)
    NativePoly encoded_native_vector;  ///< encoded polynomial (native integers)
    RnsPoly encoded_vector_dcrt;       ///< encoded polynomial (RNS/CRT representation)

    PlaintextEncodings ptxt_encoding{INVALID_ENCODING};  ///< encoding type
    SCHEME scheme_id{SCHEME::INVALID_SCHEME};            ///< scheme the plaintext was created for
    CkksDataType ckks_data_type{REAL};                   ///< CKKS data type (real or complex slots)
    double scaling_factor{1.0};                          ///< CKKS scaling factor
    NativeInteger scaling_factor_int{1};                 ///< BGV scaling factor
    size_t level{0};                                     ///< level (number of dropped RNS limbs) of the plaintext
    size_t noise_scale_deg{1};                           ///< noise scale degree (power of the scaling factor)
    uint32_t slots{0};                                   ///< number of slots (CKKS)

    /**
     * @brief print_value() is called by operator<<
     * @param out stream to print to
     */
    virtual void print_value(std::ostream& out) const = 0;

    /**
     * Method to compare two plaintext to test for equivalence.
     * This method is called by operator==
     *
     * @param other - the other plaintext to compare to.
     * @return whether the two plaintext are equivalent.
     */
    virtual bool compare_to(const PlaintextImpl& other) const = 0;

  public:
    /**
     * Constructs an empty plaintext encoded into a multiprecision polynomial (Poly) in COEFFICIENT format.
     *
     * @param vp element parameters of the polynomial
     * @param ep encoding parameters
     * @param encoding encoding type
     * @param scheme_tag scheme the plaintext is created for
     */
    PlaintextImpl(const std::shared_ptr<Poly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME scheme_tag = SCHEME::INVALID_SCHEME)
        : type_flag(IsPoly),
          encoding_params(std::move(ep)),
          encoded_vector(vp, Format::COEFFICIENT),
          ptxt_encoding(encoding),
          scheme_id(scheme_tag) {}

    /**
     * Constructs an empty plaintext encoded into a native polynomial (NativePoly) in COEFFICIENT format.
     *
     * @param vp element parameters of the polynomial
     * @param ep encoding parameters
     * @param encoding encoding type
     * @param scheme_tag scheme the plaintext is created for
     */
    PlaintextImpl(const std::shared_ptr<NativePoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME scheme_tag = SCHEME::INVALID_SCHEME)
        : type_flag(IsNativePoly),
          encoding_params(std::move(ep)),
          encoded_native_vector(vp, Format::COEFFICIENT),
          ptxt_encoding(encoding),
          scheme_id(scheme_tag) {}

    /**
     * Constructs an empty plaintext encoded into an RNS polynomial (RnsPoly) in COEFFICIENT format; the
     * multiprecision polynomial is initialized as well because the coefficient-packed encoding uses it.
     *
     * @param vp element parameters of the polynomial
     * @param ep encoding parameters
     * @param encoding encoding type
     * @param scheme_tag scheme the plaintext is created for
     */
    // TODO: eliminate use of encoded_vector in coefpackedencoding to remove encoded_vector init here
    PlaintextImpl(const std::shared_ptr<RnsPoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME scheme_tag = SCHEME::INVALID_SCHEME)
        : type_flag(IsDCRTPoly),
          encoding_params(std::move(ep)),
          encoded_vector(vp, Format::COEFFICIENT),
          encoded_vector_dcrt(vp, Format::COEFFICIENT),
          ptxt_encoding(encoding),
          scheme_id(scheme_tag) {}

    PlaintextImpl(const PlaintextImpl& rhs) = default;

    PlaintextImpl(PlaintextImpl&& rhs) noexcept = default;

    virtual ~PlaintextImpl() = default;

    /**
     * get_encoding_type
     * @return Encoding type used by this plaintext
     */
    PlaintextEncodings get_encoding_type() const {
        return ptxt_encoding;
    }

    /**
     * Get the scaling factor of the plaintext for CKKS-based plaintexts.
     * @return the scaling factor
     */
    double get_scaling_factor() const {
        return scaling_factor;
    }

    /**
     * Set the scaling factor of the plaintext for CKKS-based plaintexts.
     * @param sf the scaling factor
     */
    void set_scaling_factor(double sf) {
        scaling_factor = sf;
    }

    /**
     * Get the scaling factor of the plaintext for BGV-based plaintexts.
     * @return the integer scaling factor
     */
    NativeInteger get_scaling_factor_int() const {
        return scaling_factor_int;
    }

    /**
     * Set the scaling factor of the plaintext for BGV-based plaintexts.
     * @param sf the integer scaling factor
     */
    void set_scaling_factor_int(NativeInteger sf) {
        scaling_factor_int = sf;
    }

    /**
     * Get the scheme ID the plaintext was created for.
     * @return the scheme ID
     */
    SCHEME get_scheme_id() const {
        return scheme_id;
    }

    /**
     * is_encoded
     * @return true when encoding is done
     */
    bool is_encoded() const {
        return is_encoded_;
    }

    /**
     * get_encoding_params
     * @return Encoding params used with this plaintext
     */
    EncodingParams get_encoding_params() const {
        return encoding_params;
    }

    /**
     * get_ckks_data_type
     * @return CKKS data type with this plaintext
     */
    CkksDataType get_ckks_data_type() const {
        return ckks_data_type;
    }

    /**
     * set_ckks_data_type
     * @param cdt CKKS data type to be used with this plaintext
     */
    void set_ckks_data_type(CkksDataType cdt) {
        ckks_data_type = cdt;
    }

    /**
     * Encode the plaintext into a polynomial
     * @return true on success
     */
    virtual bool encode() = 0;

    /**
     * @brief Decode the polynomial into the plaintext
     * @return true on success
     */
    virtual bool decode() = 0;

    /**
     * @brief Decode the polynomial into the plaintext for CKKS, i.e., divide by the scaling factor of the
     * ciphertext the plaintext was decrypted from (only implemented by CKKSPackedEncoding).
     * @param depth noise scale degree of the decrypted ciphertext
     * @param scaling_factor scaling factor of the decrypted ciphertext
     * @param scal_tech scaling technique of the scheme (selects the fixed or the level-specific scaling factor)
     * @param execution_mode EXEC_NOISE_ESTIMATION to decode only the noise estimate, EXEC_EVALUATION otherwise
     * @return true on success
     */
    virtual bool decode(size_t depth, double scaling_factor, ScalingTechnique scal_tech, ExecutionMode execution_mode) {
        CIPHER_THROW("Not implemented");
    }

    /**
     * Calculate and return lower bound that can be encoded with the plaintext
     * modulus the number to encode MUST be greater than this value
     * @return floor(-p/2)
     */
    int64_t low_bound() const {
        uint64_t ptm = get_encoding_params()->get_plaintext_modulus();
        return -static_cast<int64_t>((ptm >> 1) + (ptm & 0x1));
    }

    /**
     * Calculate and return upper bound that can be encoded with the plaintext
     * modulus the number to encode MUST be less than or equal to this value
     * @return floor(p/2)
     */
    int64_t high_bound() const {
        return get_encoding_params()->get_plaintext_modulus() >> 1;
    }

    /**
     * set_format - allows format to be changed for PlaintextImpl evaluations
     *
     * @param fmt the format (COEFFICIENT or EVALUATION) to switch the encoded element to
     */
    void set_format(Format fmt) {
        if (type_flag == IsPoly)
            encoded_vector.set_format(fmt);
        else if (type_flag == IsNativePoly)
            encoded_native_vector.set_format(fmt);
        else
            encoded_vector_dcrt.set_format(fmt);
    }

    /**
     * get_element
     * @return the Polynomial that the element was encoded into
     */
    template <typename Element>
    Element& get_element() {
        CIPHER_THROW("Not implemented");
    }

    /**
     * get_element
     * @return the Polynomial that the element was encoded into
     */
    template <typename Element>
    const Element& get_element() const {
        CIPHER_THROW("Not implemented");
    }

    /**
     * get_element_ring_dimension
     * @return ring dimension on the underlying element
     */
    uint32_t get_element_ring_dimension() const {
        return type_flag == IsPoly ? encoded_vector.get_ring_dimension() :
                                     (type_flag == IsNativePoly ? encoded_native_vector.get_ring_dimension() :
                                                                  encoded_vector_dcrt.get_ring_dimension());
    }

    /**
     * get_element_modulus
     * @return modulus on the underlying element
     */
    BigInteger get_element_modulus() const {
        return type_flag == IsPoly ? encoded_vector.get_modulus() :
                                     (type_flag == IsNativePoly ? BigInteger(encoded_native_vector.get_modulus()) :
                                                                  encoded_vector_dcrt.get_modulus());
    }

    /**
     * Get method to return the length of plaintext
     *
     * @return the length of the plaintext in terms of the number of elements.
     */
    virtual size_t get_length() const = 0;

    /**
     * resize the plaintext; only works for plaintexts that support a resizable
     * vector (coefpacked)
     * @param new_size the new number of elements
     */
    virtual void set_length(size_t new_size) {
        CIPHER_THROW("resize not supported");
    }

    /**
     * Method to get the degree of the scaling factor of a plaintext.
     *
     * @return the degree of the scaling factor of the plaintext
     */
    size_t get_noise_scale_deg() const {
        return noise_scale_deg;
    }

    /**
     * Method to set the degree of the scaling factor of a plaintext.
     *
     * @param d the degree of the scaling factor
     */
    void set_noise_scale_deg(size_t d) {
        noise_scale_deg = d;
    }

    /**
     * Method to get the level of a plaintext.
     *
     * @return the level of the plaintext
     */
    size_t get_level() const {
        return level;
    }

    /**
     * Method to set the level of a plaintext.
     *
     * @param l the level
     */
    void set_level(size_t l) {
        level = l;
    }

    /**
     * Method to get the number of slots of a plaintext.
     *
     * @return the number of slots of the plaintext
     */
    uint32_t get_slots() const {
        return slots;
    }

    /**
     * Method to set the number of slots of a plaintext.
     *
     * @param l the number of slots
     */
    void set_slots(uint32_t l) {
        slots = l;
    }

    /**
     * Get log2 of the estimated standard deviation of the approximation error (CKKS only; throws otherwise).
     *
     * @return log2 of the estimated error
     */
    virtual double get_log_error() const {
        CIPHER_THROW("no estimate of noise available for the current scheme");
    }

    /**
     * Get log2 of the estimated precision of the decoded values (CKKS only; throws otherwise).
     *
     * @return log2 of the estimated precision
     */
    virtual double get_log_precision() const {
        CIPHER_THROW("no estimate of precision available for the current scheme");
    }

    /**
     * Get the decoded string (string encoding only; throws otherwise).
     *
     * @return the string
     */
    virtual const std::string& get_string_value() const {
        CIPHER_THROW("not a string");
    }
    /**
     * Get the decoded integer vector (coefficient-packed encoding only; throws otherwise).
     *
     * @return the integer vector
     */
    virtual const std::vector<int64_t>& get_coef_packed_value() const {
        CIPHER_THROW("not a packed coefficient vector");
    }
    /**
     * Get the decoded integer vector (packed encoding only; throws otherwise).
     *
     * @return the integer vector
     */
    virtual const std::vector<int64_t>& get_packed_value() const {
        CIPHER_THROW("not a packed vector");
    }
    /**
     * Get the decoded complex vector (CKKS packed encoding only; throws otherwise).
     *
     * @return the complex vector
     */
    virtual const std::vector<std::complex<double>>& get_ckks_packed_value() const {
        CIPHER_THROW("not a packed vector of complex numbers");
    }
    /**
     * Get the real parts of the decoded complex vector (CKKS packed encoding only; throws otherwise).
     *
     * @return the real vector
     */
    virtual std::vector<double> get_real_packed_value() const {
        CIPHER_THROW("not a packed vector of real numbers");
    }
    /**
     * Set the string to encode (string encoding only; throws otherwise).
     */
    virtual void set_string_value(const std::string&) {
        CIPHER_THROW("does not support a string");
    }
    /**
     * Set the integer vector to encode (packed and coefficient-packed encodings only; throws otherwise).
     */
    virtual void set_int_vector_value(const std::vector<int64_t>&) {
        CIPHER_THROW("does not support an int vector");
    }

    /**
     * operator== for plaintexts.  This method makes sure the plaintexts are of
     * the same type.
     *
     * @param other - the other plaintext to compare to.
     * @return whether the two plaintext are the same.
     */
    bool operator==(const PlaintextImpl& other) const {
        return compare_to(other);
    }

    /**
     * operator!= for plaintexts.
     *
     * @param other - the other plaintext to compare to.
     * @return whether the two plaintext differ.
     */
    bool operator!=(const PlaintextImpl& other) const {
        return !(*this == other);
    }

    /**
     * @brief operator<< for ostream integration - calls print_value()
     * @param out the output stream
     * @param item the plaintext to print
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& out, const PlaintextImpl& item) {
        item.print_value(out);
        return out;
    }
    /**
     * @brief operator<< for a shared pointer to a plaintext - prints the plaintext it points to
     * @param out the output stream
     * @param item the plaintext to print (must not be null)
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& out, const Plaintext& item) {
        if (item)
            return out << *item;  // Call the non-pointer version
        CIPHER_THROW("Cannot de-reference nullptr for printing");
    }

    /**
     * @brief get_formatted_values() is similar to print_value() and requires a precision as an argument
     * @param precision number of decimal digits of precision to print
     * @return string with all values
     */
    virtual std::string get_formatted_values(int64_t precision) const {
        CIPHER_THROW("not implemented");
    }
};

/**
 * Compares the plaintexts two shared pointers point to.
 *
 * @param p1 the first plaintext
 * @param p2 the second plaintext
 * @return whether the two plaintexts are the same
 */
inline bool operator==(const Plaintext& p1, const Plaintext& p2) {
    return *p1 == *p2;
}

/**
 * Compares the plaintexts two shared pointers point to.
 *
 * @param p1 the first plaintext
 * @param p2 the second plaintext
 * @return whether the two plaintexts differ
 */
inline bool operator!=(const Plaintext& p1, const Plaintext& p2) {
    return *p1 != *p2;
}

/**
 * get_element
 * @return the Polynomial that the element was encoded into
 */
template <>
inline const Poly& PlaintextImpl::get_element<Poly>() const {
    return encoded_vector;
}

/**
 * get_element
 * @return the Polynomial that the element was encoded into
 */
template <>
inline Poly& PlaintextImpl::get_element<Poly>() {
    return encoded_vector;
}

/**
 * get_element
 * @return the NativePolynomial that the element was encoded into
 */
template <>
inline const NativePoly& PlaintextImpl::get_element<NativePoly>() const {
    return encoded_native_vector;
}

/**
 * get_element
 * @return the NativePolynomial that the element was encoded into
 */
template <>
inline NativePoly& PlaintextImpl::get_element<NativePoly>() {
    return encoded_native_vector;
}

/**
 * get_element
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline const RnsPoly& PlaintextImpl::get_element<RnsPoly>() const {
    return encoded_vector_dcrt;
}

/**
 * get_element
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline RnsPoly& PlaintextImpl::get_element<RnsPoly>() {
    return encoded_vector_dcrt;
}

}  // namespace cipher

#endif  // CIPHER_FHE_ENCODING_PLAINTEXT_H_
