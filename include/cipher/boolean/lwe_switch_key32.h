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

#ifndef CIPHER_BOOLEAN_LWE_SWITCH_KEY32_H_
#define CIPHER_BOOLEAN_LWE_SWITCH_KEY32_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/boolean/lwe_params.h"
#include "cipher/boolean/lwe_switch_key_fwd.h"
#include "cipher/util/serializable.h"

namespace cipher {

#if CIPHER_NATIVE_INT != 32

class LweSwitchingKey32Impl;
using LweSwitchingKey32 = std::shared_ptr<LweSwitchingKey32Impl>;
using ConstLweSwitchingKey32 = const std::shared_ptr<const LweSwitchingKey32Impl>;

/**
 * @brief 32-bit internal form of the LWE key switching key.
 *
 * Every stored value is a residue mod q_ks, so when q_ks fits a 32-bit word the key stores in half
 * the memory of the 64-bit form -- and it is by far the largest key object. Storage is two flat
 * arrays indexed by (LWE index i, digit position, digit value): rows of n words in key_a_ and one
 * word each in key_b_, replacing the nested vector-of-vectors layout. Rows exist for digit values
 * 1..base_ks-1 only -- the value-0 row would encrypt zero and the key switch skips zero digits --
 * and the top digit position holds only the values a coefficient below q_ks can reach. The key switch itself
 * accumulates rows in uint64 and reduces once per output coefficient, which yields the same
 * residues as the 64-bit path, so results are bit-identical.
 */
class LweSwitchingKey32Impl : public Serializable {
  public:
    LweSwitchingKey32Impl() = default;

    /**
     * Checks whether the parameters qualify for the 32-bit switching key: generation runs on 32-bit kernels, exact up
     * to MAX_MODULUS_SIZE32 bits of q_ks, and the key switch accumulates N*digit_count unreduced rows below q_ks in a
     * 64-bit word
     *
     * @param params LWE scheme parameters
     * @return true if q_ks fits MAX_MODULUS_SIZE32 bits and N*digit_count*q_ks does not overflow a uint64
     */
    static bool fits(const LweCryptoParams& params) {
        const auto& q_ks = params.get_q_ks();
        if (q_ks.get_msb() > MAX_MODULUS_SIZE32)
            return false;
        uint64_t rows{static_cast<uint64_t>(params.get_N()) * params.get_digit_count_ks()};
        return rows <= static_cast<uint64_t>(-1) / q_ks.convert_to_int<uint64_t>();
    }

    /**
     * Allocates a key of the given shape with its storage deliberately left uninitialized: both generation paths write
     * every element, and value-initialization would fault and zero the whole key on the constructing thread before
     * the parallel fill re-touches it. Each LWE index holds base_ks-1 rows (digit values 1..base_ks-1) per digit
     * position except the top position, which holds top_extent-1: the values a coefficient below q_ks can reach there
     *
     * @param N dimension of the source (old) secret key, the number of LWE indices
     * @param base_ks key-switching base
     * @param digit_count number of base-base_ks digits of a value below q_ks
     * @param top_extent number of values the top digit can take (LweCryptoParams::get_digit_extent_ks(digit_count - 1))
     * @param n dimension of the target (new) secret key, the length of each row
     */
    LweSwitchingKey32Impl(uint32_t N, uint32_t base_ks, uint32_t digit_count, uint32_t top_extent, uint32_t n)
        : N_(N),
          m_(base_ks),
          d_(digit_count),
          top_(top_extent),
          n_(n),
          rows_(static_cast<uint64_t>(digit_count - 1) * (base_ks - 1) + (top_extent - 1)),
          size_a_(static_cast<uint64_t>(N) * rows_ * n),
          size_b_(static_cast<uint64_t>(N) * rows_),
          key_a_(new uint32_t[size_a_]),
          key_b_(new uint32_t[size_b_]) {}

    /**
     * Narrows an existing 64-bit key, taking the shape from the parameters and copying only the reachable digit rows.
     * Peak memory holds both forms; the released pages come back only after alloc_trim(). Prefer
     * LweEncryptionScheme::key_switch_gen32, which never materialises the 64-bit key
     *
     * @param params LWE scheme parameters the key was generated with
     * @param K the 64-bit switching key, which must have N entries with base_ks-1 digit-value rows each
     */
    LweSwitchingKey32Impl(const LweCryptoParams& params, const LweSwitchingKeyImpl& K);

    /**
     * Produces an exact 64-bit copy of the key for serialization: every value fits, so 32 -> 64 -> 32 is the identity
     *
     * @param params LWE scheme parameters, supplying the key-switching modulus of the 64-bit vectors
     * @return a shared pointer to the 64-bit switching key
     */
    LweSwitchingKey widen(const LweCryptoParams& params) const;

    /**
     * Accesses the A part of the encryption of val * base_ks^pos * sk_n[i]: a row of n residues mod q_ks
     *
     * @param i LWE index of the source secret-key coefficient, in [0, N)
     * @param val digit value, in [1, get_digit_extent(pos)); the value-0 row is not stored
     * @param pos digit position, in [0, digit_count)
     * @return pointer to the n words of the row
     */
    uint32_t* row_a(uint32_t i, uint32_t val, uint32_t pos) {
        return key_a_.get() + slot(i, val, pos) * n_;
    }

    /**
     * Accesses the A part of the encryption of val * base_ks^pos * sk_n[i]: a row of n residues mod q_ks
     *
     * @param i LWE index of the source secret-key coefficient, in [0, N)
     * @param val digit value, in [1, get_digit_extent(pos)); the value-0 row is not stored
     * @param pos digit position, in [0, digit_count)
     * @return pointer to the n words of the row
     */
    const uint32_t* row_a(uint32_t i, uint32_t val, uint32_t pos) const {
        return key_a_.get() + slot(i, val, pos) * n_;
    }

    /**
     * Accesses the B part of the encryption of val * base_ks^pos * sk_n[i]: one residue mod q_ks
     *
     * @param i LWE index of the source secret-key coefficient, in [0, N)
     * @param val digit value, in [1, get_digit_extent(pos)); the value-0 row is not stored
     * @param pos digit position, in [0, digit_count)
     * @return reference to the stored word
     */
    uint32_t& B(uint32_t i, uint32_t val, uint32_t pos) {
        return key_b_[slot(i, val, pos)];
    }

    /**
     * Reads the B part of the encryption of val * base_ks^pos * sk_n[i]: one residue mod q_ks
     *
     * @param i LWE index of the source secret-key coefficient, in [0, N)
     * @param val digit value, in [1, get_digit_extent(pos)); the value-0 row is not stored
     * @param pos digit position, in [0, digit_count)
     * @return the stored word
     */
    uint32_t B(uint32_t i, uint32_t val, uint32_t pos) const {
        return key_b_[slot(i, val, pos)];
    }

    /**
     * Gets the number of digit values stored for a digit position: base_ks for every position except the top one,
     * which holds top_extent
     *
     * @param pos digit position, in [0, digit_count)
     * @return the digit extent; rows exist for values 1..extent-1
     */
    uint32_t get_digit_extent(uint32_t pos) const {
        return pos + 1 < d_ ? m_ : top_;
    }

    uint32_t get_N() const {
        return N_;
    }

    uint32_t get_base_ks() const {
        return m_;
    }

    uint32_t get_digit_count() const {
        return d_;
    }

    uint32_t get_n() const {
        return n_;
    }

    /**
     * Gets the resident bytes of key material (the A rows and the B words), for memory accounting
     *
     * @return the size of the two flat arrays in bytes
     */
    uint64_t key_bytes() const {
        return (size_a_ + size_b_) * sizeof(uint32_t);
    }

    bool operator==(const LweSwitchingKey32Impl& other) const {
        if (N_ != other.N_ || m_ != other.m_ || d_ != other.d_ || top_ != other.top_ || n_ != other.n_)
            return false;
        return std::equal(key_a_.get(), key_a_.get() + size_a_, other.key_a_.get()) &&
               std::equal(key_b_.get(), key_b_.get() + size_b_, other.key_b_.get());
    }

    bool operator!=(const LweSwitchingKey32Impl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("N", N_));
        ar(::cereal::make_nvp("m", m_));
        ar(::cereal::make_nvp("d", d_));
        ar(::cereal::make_nvp("top", top_));
        ar(::cereal::make_nvp("n", n_));
        archive_bytes(ar, key_a_.get(), size_a_);
        archive_bytes(ar, key_b_.get(), size_b_);
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("N", N_));
        ar(::cereal::make_nvp("m", m_));
        ar(::cereal::make_nvp("d", d_));
        ar(::cereal::make_nvp("top", top_));
        ar(::cereal::make_nvp("n", n_));
        Size();
        key_a_.reset(new uint32_t[size_a_]);
        key_b_.reset(new uint32_t[size_b_]);
        archive_bytes(ar, key_a_.get(), size_a_);
        archive_bytes(ar, key_b_.get(), size_b_);
    }

    std::string serialized_object_name() const override {
        return "LWESwitchingKey32";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // One flat array, in whichever form the archive takes: the binary archives move it as a block,
    // and the JSON archive, which has no binary support, takes it one element at a time. Both sides
    // call this, so the two representations stay paired.
    template <class Archive, typename T>
    static void archive_bytes(Archive& ar, T* p, uint64_t n) {
        if constexpr (::cereal::traits::is_output_serializable<::cereal::BinaryData<T*>, Archive>::value ||
                      ::cereal::traits::is_input_serializable<::cereal::BinaryData<T*>, Archive>::value) {
            ar(::cereal::binary_data(p, n * sizeof(T)));
        } else {
            for (uint64_t i = 0; i < n; ++i)
                ar(p[i]);
        }
    }

    void Size() {
        rows_ = static_cast<uint64_t>(d_ - 1) * (m_ - 1) + (top_ - 1);
        size_a_ = static_cast<uint64_t>(N_) * rows_ * n_;
        size_b_ = static_cast<uint64_t>(N_) * rows_;
    }

    uint64_t slot(uint32_t i, uint32_t val, uint32_t pos) const {
        return static_cast<uint64_t>(i) * rows_ + static_cast<uint64_t>(pos) * (m_ - 1) + (val - 1);
    }

    uint32_t N_{0};
    uint32_t m_{0};
    uint32_t d_{0};
    uint32_t top_{0};
    uint32_t n_{0};
    uint64_t rows_{0};
    uint64_t size_a_{0};
    uint64_t size_b_{0};
    std::unique_ptr<uint32_t[]> key_a_;
    std::unique_ptr<uint32_t[]> key_b_;
};

#endif  // CIPHER_NATIVE_INT != 32

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_SWITCH_KEY32_H_
