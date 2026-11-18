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
  Operations for the representation of ciphertext in OpenFHE
 */

#ifndef CIPHER_FHE_CIPHERTEXT_H_
#define CIPHER_FHE_CIPHERTEXT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext_fwd.h"
#include "cipher/fhe/crypto_object.h"
#include "cipher/fhe/key/key.h"
#include "cipher/fhe/metadata.h"

namespace cipher {
/**
 * @brief CiphertextImpl
 *
 * The CiphertextImpl object is used to contain encrypted text in the OpenFHE
 * library
 *
 * @tparam Element a ring element.
 */
template <class Element>
class CiphertextImpl : public CryptoObject<Element> {
  public:
    /**
     * Default constructor
     */
    CiphertextImpl() = default;

    /**
     * Construct a new ciphertext in the given context
     *
     * @param cc the crypto context the ciphertext belongs to
     * @param id key tag of the key used to encrypt the ciphertext
     * @param enc_type encoding type of the plaintext the ciphertext was created from
     */
    explicit CiphertextImpl(const CryptoContext<Element>& cc, const std::string& id = "",
                            PlaintextEncodings enc_type = INVALID_ENCODING)
        : CryptoObject<Element>(cc, id), encoding_type_(enc_type) {}

    /**
     * Construct a new ciphertext from the parameters of a given public key
     *
     * @param k key whose CryptoObject parameters will get cloned
     */
    explicit CiphertextImpl(const std::shared_ptr<Key<Element>>& k)
        : CryptoObject<Element>(k->get_crypto_context(), k->get_key_tag()) {}

    /**
     * Copy constructor
     *
     * @param ct the ciphertext to copy from
     */
    CiphertextImpl(const CiphertextImpl<Element>& ct) = default;

    /**
     * Copy constructor from a shared pointer: copies all elements and metadata of the pointed-to ciphertext.
     *
     * @param ct shared pointer to the ciphertext to copy from
     */
    explicit CiphertextImpl(const Ciphertext<Element>& ct)
        : CryptoObject<Element>(*ct),
          elements_(ct->elements_),
          slots_(ct->slots_),
          level_(ct->level_),
          hopslevel_(ct->hopslevel_),
          noise_scale_deg_(ct->noise_scale_deg_),
          scaling_factor_(ct->scaling_factor_),
          scaling_factor_int_(ct->scaling_factor_int_),
          encoding_type_(ct->encoding_type_),
          metadata_map_(ct->metadata_map_) {}

    /**
     * Move constructor
     *
     * @param ct the ciphertext to move from
     */
    CiphertextImpl(CiphertextImpl<Element>&& ct) noexcept = default;

    /**
     * Move constructor from a shared pointer: moves all elements and metadata out of the pointed-to ciphertext,
     * leaving that ciphertext in an unspecified state.
     *
     * @param ct shared pointer to the ciphertext to move from
     */
    explicit CiphertextImpl(Ciphertext<Element>&& ct) noexcept
        : CryptoObject<Element>(std::move(*ct)),
          elements_(std::move(ct->elements_)),
          slots_(std::move(ct->slots_)),
          level_(std::move(ct->level_)),
          hopslevel_(std::move(ct->hopslevel_)),
          noise_scale_deg_(std::move(ct->noise_scale_deg_)),
          scaling_factor_(std::move(ct->scaling_factor_)),
          scaling_factor_int_(std::move(ct->scaling_factor_int_)),
          encoding_type_(std::move(ct->encoding_type_)),
          metadata_map_(std::move(ct->metadata_map_)) {}

    /**
     * Destructor
     */
    virtual ~CiphertextImpl() = default;

    /**
     * Assignment Operator.
     *
     * @param rhs the CiphertextImpl to assign from
     * @return this CiphertextImpl
     */
    CiphertextImpl<Element>& operator=(const CiphertextImpl<Element>& rhs) = default;

    /**
     * Move Assignment Operator.
     *
     * @param rhs the CiphertextImpl to move from
     * @return this CiphertextImpl
     */
    CiphertextImpl<Element>& operator=(CiphertextImpl<Element>&& rhs) noexcept = default;

    /**
     * get_element - get the ring element for the cases that use only one element
     * in the vector this method will throw an exception if it's ever called in
     * cases with other than 1 element
     * @return the first (and only!) ring element
     */
    const Element& get_element() const {
        if (elements_.size() == 1)
            return elements_[0];
        CIPHER_THROW("Can be called on a Ciphertext with a single element ONLY");
    }

    /**
     * get_element - get the ring element for the cases that use only one element
     * in the vector this method will throw an exception if it's ever called in
     * cases with other than 1 element
     * @return the first (and only!) ring element
     */
    Element& get_element() {
        if (elements_.size() == 1)
            return elements_[0];
        CIPHER_THROW("Can be called on a Ciphertext with a single element ONLY");
    }

    /**
     * get_elements: get all of the ring elements in the CiphertextImpl
     * @return vector of ring elements
     */
    const std::vector<Element>& get_elements() const {
        return elements_;
    }

    /**
     * get_elements: get all of the ring elements in the CiphertextImpl
     * @return vector of ring elements
     */
    std::vector<Element>& get_elements() {
        return elements_;
    }

    /**
     * Returns the number of ring elements (polynomials) in the ciphertext, e.g. 2 for a fresh encryption and 3
     * after a multiplication without relinearization.
     *
     * @return the number of ring elements
     */
    size_t number_ciphertext_elements() const {
        return elements_.size();
    }

    /**
     * set_element - sets the ring element for the cases that use only one element
     * in the vector this method will throw an exception if it's ever called in
     * cases with other than 1 element
     * @param element is a polynomial ring element.
     */
    void set_element(const Element& element) {
        if (elements_.size() == 0)
            elements_.push_back(element);
        else if (elements_.size() == 1)
            elements_[0] = element;
        else
            CIPHER_THROW("Can be called on a Ciphertext with a single element ONLY");
    }

    /**
     * Sets the data element by std::move.
     *
     * @param element is a polynomial ring element.
     */
    void set_element(Element&& element) {
        if (elements_.size() == 0)
            elements_.push_back(std::move(element));
        else if (elements_.size() == 1)
            elements_[0] = std::move(element);
        else
            CIPHER_THROW("Can be called on a Ciphertext with a single element ONLY");
    }

    /**
     * Sets the data elements.
     *
     * @param elements is a vector of polynomial ring elements.
     */
    void set_elements(const std::vector<Element>& elements) {
        elements_ = elements;
    }

    /**
     * Sets the data elements by std::move.
     *
     * @param elements is a vector of polynomial ring elements.
     */
    void set_elements(std::vector<Element>&& elements) noexcept {
        elements_ = std::move(elements);
    }

    /**
     * Get the degree of the scaling factor for the encrypted message.
     * @return the degree of the scaling factor (1 for a fresh ciphertext, 2 after a multiplication)
     */
    size_t get_noise_scale_deg() const {
        return noise_scale_deg_;
    }

    /**
     * Set the degree of the scaling factor for the encrypted message.
     * @param noise_scale_deg the degree of the scaling factor
     */
    void set_noise_scale_deg(size_t noise_scale_deg) {
        noise_scale_deg_ = noise_scale_deg;
    }

    /**
     * Get the number of scalings performed
     * @return the level (number of RNS limbs dropped so far) of the ciphertext
     */
    size_t get_level() const {
        return level_;
    }

    /**
     * Set the number of scalings.
     * This generic version performs no validation. The RnsPoly specialization additionally checks, for CKKS,
     * that the ciphertext still has at least as many RNS limbs as its noise scale degree and throws an exception
     * asking for a larger multiplicative depth otherwise.
     * @param level the number of scalings (level) of the ciphertext
     */
    void set_level(size_t level) {
        level_ = level;
    }

    /**
     * Get the re-encryption level of the ciphertext.
     * @return the number of times the ciphertext has been re-encrypted (proxy re-encryption hops)
     */
    size_t get_hop_level() const {
        return hopslevel_;
    }

    /**
     * Set the re-encryption level of the ciphertext.
     * @param hoplevel the re-encryption (hop) level
     */
    void set_hop_level(size_t hoplevel) {
        hopslevel_ = hoplevel;
    }

    /**
     * Get the scaling factor of the ciphertext.
     * @return the (approximate, double-precision) scaling factor of the encrypted message
     */
    double get_scaling_factor() const {
        return scaling_factor_;
    }

    /**
     * Set the scaling factor of the ciphertext.
     * @param sf the scaling factor
     */
    void set_scaling_factor(double sf) {
        scaling_factor_ = sf;
    }

    /**
     * Get the integer scaling factor of the ciphertext.
     * @return the exact integer scaling factor of the encrypted message (used by BGV)
     */
    NativeInteger get_scaling_factor_int() const {
        return scaling_factor_int_;
    }

    /**
     * Set the integer scaling factor of the ciphertext.
     * @param sf the integer scaling factor
     */
    void set_scaling_factor_int(NativeInteger sf) {
        scaling_factor_int_ = sf;
    }

    /**
     * Get the number of slots of the ciphertext.
     * @return the number of plaintext slots the ciphertext encrypts
     */
    uint32_t get_slots() const {
        return slots_;
    }

    /**
     * Set the number of slots of the ciphertext.
     * @param slots the number of slots
     */
    void set_slots(uint32_t slots) {
        slots_ = slots;
    }

    /**
     * get_encoding_type
     * @return how the Plaintext that this CiphertextImpl was created from was
     * encoded
     */
    PlaintextEncodings get_encoding_type() const {
        return encoding_type_;
    }

    /**
     * set_encoding_type - after Encrypt, remember the CiphertextImpl's encoding
     * type
     * @param et the encoding type of the plaintext the ciphertext was created from
     */
    void set_encoding_type(PlaintextEncodings et) {
        encoding_type_ = et;
    }

    /**
     * Get the Metadata map of the ciphertext.
     * @return shared pointer to the map of metadata objects keyed by name
     */
    MetadataMap get_metadata_map() const {
        return metadata_map_;
    }

    /**
     * Set the Metadata map of the ciphertext.
     * @param mdata the metadata map
     */
    void set_metadata_map(const MetadataMap& mdata) {
        metadata_map_ = mdata;
    }

    /**
     * This method searches the metadata map for metadata of a specific key.
     *
     * @param key the string value which serves as a key in the metadata map
     * @return an iterator pointing at the position in the map where the key
     *         was found (or the map.end() if not found).
     */
    std::map<std::string, std::shared_ptr<Metadata>>::iterator find_metadata_by_key(std::string key) const {
        return metadata_map_->find(key);
    }

    /**
     * This method checks whether an iterator return from find_metadata_by_key
     * corresponds to whether the key was found or not.
     *
     * @param it iterator pointing at the position in the map where the key
     *         was found (or the map.end() if not found).
     * @return a boolean value indicating whether the key was found or not.
     */
    bool metadata_found(std::map<std::string, std::shared_ptr<Metadata>>::iterator it) const {
        return (it != metadata_map_->end());
    }

    /**
     * This method returns the Metadata object stored in the iterator position
     * returned by find_metadata_by_key.
     *
     * @param it iterator pointing at the position in the map where the key
     *         was found (or the map.end() if not found).
     * @return a shared pointer pointing to the Metadata object in the map.
     */
    std::shared_ptr<Metadata>& get_metadata(std::map<std::string, std::shared_ptr<Metadata>>::iterator it) const {
        return it->second;
    }

    /**
     * Get a copy of a Metadata element from the Metadata map of the ciphertext.
     * @param key the string key of the metadata element
     * @return a new shared pointer to a copy of the metadata element; throws an exception if the key is not found
     */
    std::shared_ptr<Metadata> get_metadata_by_key(const std::string& key) const {
        auto it = metadata_map_->find(key);
        if (it == metadata_map_->end())
            CIPHER_THROW("Metadata element with key [" + key + "] is not found in the Metadata map.");
        return it->second->clone();
    }

    /**
     * Set a Metadata element in the Metadata map of the ciphertext.
     * @param key the string key of the metadata element
     * @param value the metadata element to store
     */
    void set_metadata_by_key(const std::string& key, const std::shared_ptr<Metadata>& value) {
        (*metadata_map_)[key] = value;
    }

    /**
     * This method creates a copy of this, skipping the actual encrypted
     * elements. This means it copies parameters, key tags, encoding type,
     * and metadata.
     * @return a new ciphertext with the same context, key tag, level/scaling data and metadata but no elements
     */
    virtual Ciphertext<Element> clone_empty() const {
        auto ct(std::make_shared<CiphertextImpl<Element>>(this->get_crypto_context(), this->get_key_tag(), encoding_type_));
        ct->slots_ = slots_;
        ct->level_ = level_;
        ct->hopslevel_ = hopslevel_;
        ct->noise_scale_deg_ = noise_scale_deg_;
        ct->scaling_factor_ = scaling_factor_;
        ct->scaling_factor_int_ = scaling_factor_int_;
        *(ct->metadata_map_) = *(metadata_map_);
        return ct;
    }

    /**
     * Creates a deep copy of this ciphertext, including the encrypted elements.
     * @return a new ciphertext equal to this one
     */
    virtual Ciphertext<Element> clone() const {
        auto ct = this->clone_empty();
        ct->elements_ = elements_;
        return ct;
    }

    /**
     * Equality: same crypto context (by pointer) and key tag, equal slots, level, hop level, noise scale degree,
     * scaling factors, encoding type, metadata entries and ring elements.
     *
     * @param rhs the ciphertext to compare with
     * @return true if the ciphertexts are equal
     */
    bool operator==(const CiphertextImpl<Element>& rhs) const {
        if (!CryptoObject<Element>::operator==(rhs))
            return false;
        if (slots_ != rhs.slots_)
            return false;
        if (level_ != rhs.level_)
            return false;
        if (hopslevel_ != rhs.hopslevel_)
            return false;
        if (noise_scale_deg_ != rhs.noise_scale_deg_)
            return false;
        if (scaling_factor_ != rhs.scaling_factor_)
            return false;
        if (scaling_factor_int_ != rhs.scaling_factor_int_)
            return false;
        if (encoding_type_ != rhs.encoding_type_)
            return false;
        if (metadata_map_->size() != rhs.metadata_map_->size())
            return false;
        for (auto x = metadata_map_->begin(), y = rhs.metadata_map_->begin(); x != metadata_map_->end(); ++x, ++y)
            if (*(x->second) != *(y->second))
                return false;
        if (elements_ != rhs.elements_)
            return false;
        return true;
    }

    /**
     * Inequality: negation of operator==.
     *
     * @param rhs the ciphertext to compare with
     * @return true if the ciphertexts differ
     */
    bool operator!=(const CiphertextImpl<Element>& rhs) const {
        return !(*this == rhs);
    }

    /**
     * Prints the encoding type, noise scale degree, metadata entries and every ring element of the ciphertext.
     *
     * @param out the output stream
     * @param c the ciphertext to print
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& out, const CiphertextImpl<Element>& c) {
        out << "enc=" << c.encoding_type_ << " noiseScaleDeg=" << c.noise_scale_deg_ << std::endl;
        out << "metadata: [ ";
        for (auto i = c.metadata_map_->begin(); i != c.metadata_map_->end(); ++i)
            out << "(\"" << i->first << "\", " << *(i->second) << ") ";
        out << "]" << std::endl;
        for (size_t i = 0; i < c.elements_.size(); i++) {
            if (i != 0)
                out << std::endl;
            out << "Element " << i << ": " << c.elements_[i];
        }
        return out;
    }

    /**
     * Prints the ciphertext a shared pointer refers to (see the reference overload).
     *
     * @param out the output stream
     * @param c shared pointer to the ciphertext to print
     * @return the output stream
     */
    friend std::ostream& operator<<(std::ostream& out, Ciphertext<Element> c) {
        return out << *c;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<CryptoObject<Element>>(this));
        ar(cereal::make_nvp("v", elements_));
        ar(cereal::make_nvp("sl", slots_));
        ar(cereal::make_nvp("l", level_));
        ar(cereal::make_nvp("t", hopslevel_));
        ar(cereal::make_nvp("d", noise_scale_deg_));
        ar(cereal::make_nvp("s", scaling_factor_));
        ar(cereal::make_nvp("si", scaling_factor_int_));
        ar(cereal::make_nvp("e", encoding_type_));
        ar(cereal::make_nvp("m", metadata_map_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version())
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        ar(cereal::base_class<CryptoObject<Element>>(this));
        ar(cereal::make_nvp("v", elements_));
        ar(cereal::make_nvp("sl", slots_));
        ar(cereal::make_nvp("l", level_));
        ar(cereal::make_nvp("t", hopslevel_));
        ar(cereal::make_nvp("d", noise_scale_deg_));
        ar(cereal::make_nvp("s", scaling_factor_));
        ar(cereal::make_nvp("si", scaling_factor_int_));
        ar(cereal::make_nvp("e", encoding_type_));
        ar(cereal::make_nvp("m", metadata_map_));
    }

    std::string serialized_object_name() const {
        return "Ciphertext";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // vector of ring elements for this Ciphertext
    std::vector<Element> elements_;

    uint32_t slots_{0};

    // holds the number of scalings performed before getting this ciphertext - initially 0
    uint32_t level_{0};

    // Parameter for re-encryption to store the number of times the ciphertext has been re-encrypted.
    uint32_t hopslevel_{0};

    // the degree of the scaling factor for the encrypted message.
    uint32_t noise_scale_deg_{1};

    double scaling_factor_{1.0};

    NativeInteger scaling_factor_int_{1};

    // how was this Ciphertext encoded?
    PlaintextEncodings encoding_type_{INVALID_ENCODING};

    // A map to hold different Metadata objects - used for flexible extensions of Ciphertext
    MetadataMap metadata_map_{std::make_shared<std::map<std::string, std::shared_ptr<Metadata>>>()};
};

/**
 * RnsPoly specialization of set_level(): stores the level and, for CKKS, checks that the ciphertext still has at
 * least as many RNS limbs as its noise scale degree, throwing an exception that asks for a larger multiplicative
 * depth otherwise.
 *
 * @param level the number of scalings (level) of the ciphertext
 */
template <>
void CiphertextImpl<RnsPoly>::set_level(size_t level);

/**
 * operator+ overload for Ciphertexts.  Performs eval_add.
 *
 * @tparam Element a ring element.
 * @param a ciphertext operand
 * @param b ciphertext operand
 *
 * @return The result of addition.
 */
template <class Element>
Ciphertext<Element> operator+(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->get_crypto_context()->eval_add(a, b);
}

/**
 * operator+= overload for Ciphertexts.  Performs eval_add.
 *
 * @tparam Element a ring element.
 * @param a ciphertext to be added to
 * @param b ciphertext to add to a
 *
 * @return a
 */
template <class Element>
Ciphertext<Element>& operator+=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->get_crypto_context()->eval_add(a, b);
}

/**
 * Unary negation operator.
 *
 * @param a ciphertext operand
 * @return the result of the negation.
 */
template <class Element>
Ciphertext<Element> operator-(const Ciphertext<Element>& a) {
    return a->get_crypto_context()->eval_negate(a);
}

/**
 * operator- overload.  Performs eval_sub.
 *
 * @tparam Element a ring element.
 * @param a ciphertext operand
 * @param b ciphertext operand
 *
 * @return The result of subtraction.
 */
template <class Element>
Ciphertext<Element> operator-(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->get_crypto_context()->eval_sub(a, b);
}

/**
 * operator-= overload for Ciphertexts.  Performs eval_sub.
 *
 * @tparam Element a ring element.
 * @param a ciphertext to be subtracted from
 * @param b ciphertext to subtract from a
 *
 * @return a
 */
template <class Element>
Ciphertext<Element>& operator-=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->get_crypto_context()->eval_sub(a, b);
}

/**
 * operator* overload.  Performs eval_mult.
 *
 * @tparam Element a ring element.
 * @param a ciphertext operand
 * @param b ciphertext operand
 *
 * @return The result of multiplication.
 */
template <class Element>
Ciphertext<Element> operator*(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->get_crypto_context()->eval_mult(a, b);
}

/**
 * operator*= overload for Ciphertexts.  Performs eval_mult.
 *
 * @tparam Element a ring element.
 * @param a ciphertext to be multiplied
 * @param b ciphertext to multiply a by
 *
 * @return a
 */
template <class Element>
Ciphertext<Element>& operator*=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->get_crypto_context()->eval_mult(a, b);
}

}  // namespace cipher

#endif  // CIPHER_FHE_CIPHERTEXT_H_
