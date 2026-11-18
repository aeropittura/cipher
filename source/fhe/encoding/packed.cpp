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
  Represents and defines plaintext encodings in OpenFHE with bit packing capabilities
 */

#include "cipher/fhe/encoding/packed.h"

#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/math/backend.h"
#include "cipher/util/utilities.h"

namespace cipher {

// TODO (dsuponit): we should not have globals!
std::map<ModulusM, NativeInteger> PackedEncoding::init_root_;
std::map<ModulusM, NativeInteger> PackedEncoding::big_modulus_;
std::map<ModulusM, NativeInteger> PackedEncoding::big_root_;

std::map<uint32_t, uint32_t> PackedEncoding::automorphism_generator_;
std::map<uint32_t, std::vector<uint32_t>> PackedEncoding::to_crt_perm_;
std::map<uint32_t, std::vector<uint32_t>> PackedEncoding::from_crt_perm_;

bool PackedEncoding::encode() {
    if (this->is_encoded_)
        return true;
    auto mod_value = this->encoding_params->get_plaintext_modulus();

    if ((this->type_flag == IsNativePoly) || (this->type_flag == IsDCRTPoly)) {
        NativeVector temp_vector = NativeVector(this->get_element_ring_dimension(), mod_value);

        NativeInteger original_sf = scaling_factor_int;
        for (size_t j = 1; j < noise_scale_deg; j++) {
            scaling_factor_int = scaling_factor_int.mod_mul(original_sf, mod_value);
        }

        for (size_t i = 0; i < value.size(); i++) {
            if ((PlaintextModulus)llabs(value[i]) >= mod_value) {
                CIPHER_THROW("Cannot encode integer " + std::to_string(value[i]) + " at position " +
                              std::to_string(i) + " that is > plaintext modulus " + std::to_string(mod_value));
            }

            if (value[i] < 0) {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                temp_vector[i] = NativeInteger(mod_value) - NativeInteger((uint64_t)llabs(value[i]));
            } else {
                temp_vector[i] = NativeInteger(value[i]);
            }
        }

        // no need to do extra multiplications for many scenarios when the scaling factor is 1, e.g., in BFV
        if (scaling_factor_int != 1) {
            temp_vector.mod_mul_eq(scaling_factor_int);
        }

        if (this->type_flag == IsNativePoly) {
            PlaintextModulus q = this->get_element_modulus().convert_to_int();
            if (q < mod_value) {
                CIPHER_THROW(
                        "the plaintext modulus size is larger than the size of "
                        "NativePoly modulus; increase the NativePoly modulus.");
            }

            // Calls the inverse NTT mod plaintext modulus
            this->pack_native_vector(this->encoding_params->get_plaintext_modulus(),
                                   this->encoded_native_vector.get_cyclotomic_order(), &temp_vector);
            temp_vector.set_modulus(q);
            this->encoded_native_vector.set_values(std::move(temp_vector), Format::COEFFICIENT);
        } else {
            PlaintextModulus q = this->encoded_vector_dcrt.get_params()->get_params()[0]->get_modulus().convert_to_int();
            if (q < mod_value) {
                CIPHER_THROW(
                        "the plaintext modulus size is larger than the size of "
                        "CRT moduli; either decrease the plaintext modulus or "
                        "increase the CRT moduli.");
            }

            // Calls the inverse NTT mod plaintext modulus
            this->pack_native_vector(this->encoding_params->get_plaintext_modulus(),
                                   this->encoded_vector_dcrt.get_cyclotomic_order(), &temp_vector);
            // Switches from plaintext modulus to the modulus of the first RNS limb
            temp_vector.set_modulus(q);
            NativePoly first_element = this->get_element<RnsPoly>().get_element_at_index(0);
            first_element.set_values(std::move(temp_vector), Format::COEFFICIENT);

            const std::shared_ptr<RnsParams<BigInteger>> params = this->encoded_vector_dcrt.get_params();
            const std::vector<std::shared_ptr<NativePolyParams>>& native_params = params->get_params();

            // Sets the values for all other RNS limbs
            for (size_t j = 1; j < native_params.size(); j++) {
                NativePoly temp_poly(native_params[j], Format::COEFFICIENT);
                temp_poly.set_values(NativeVector(first_element.get_values(), native_params[j]->get_modulus()),
                                   Format::COEFFICIENT);
                this->encoded_vector_dcrt.set_element_at_index(j, std::move(temp_poly));
            }
            // Setting the first limb at the end make sure first_element is available during the main loop
            this->encoded_vector_dcrt.set_element_at_index(0, std::move(first_element));
            this->encoded_vector_dcrt.set_format(Format::EVALUATION);
        }
    } else {
        BigVector temp(this->get_element_ring_dimension(), BigInteger(this->get_element_modulus()));

        BigInteger q = this->get_element_modulus();

        for (size_t i = 0; i < value.size(); ++i) {
            BigInteger entry;

            if ((PlaintextModulus)llabs(value[i]) >= mod_value)
                CIPHER_THROW("Cannot encode integer " + std::to_string(value[i]) + " at position " +
                              std::to_string(i) + " that is > plaintext modulus " + std::to_string(mod_value));

            if (value[i] < 0) {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                entry = BigInteger(mod_value) - BigInteger((uint64_t)llabs(value[i]));
            } else {
                entry = BigInteger(value[i]);
            }

            temp[i] = entry;
        }
        for (size_t j = value.size(); j < this->get_element_ring_dimension(); ++j)
            temp[j] = BigInteger(0);

        // the input plaintext data is in the evaluation format
        this->get_element<Poly>().set_values(std::move(temp), Format::EVALUATION);

        // ilVector coefficients are packed and resulting ilVector is in COEFFICIENT
        // form.
        this->pack_into(&this->get_element<Poly>(), this->encoding_params->get_plaintext_modulus());
    }

    this->is_encoded_ = true;
    return true;
}

template <typename T>
static void fill_vec(const T& poly, const PlaintextModulus& mod_value, std::vector<int64_t>& vec) {
    vec.clear();
    vec.reserve(poly.get_length());

    int64_t half = int64_t(mod_value) / 2;
    // const typename T::Integer &q = poly.get_modulus();
    // typename T::Integer q_half = q>>1;

    for (size_t i = 0; i < poly.get_length(); i++) {
        int64_t val = poly[i].convert_to_int();
        /*if (poly[i] > q_half)
            val = (-(q-poly[i]).convert_to_int());
    else
            val = poly[i].convert_to_int();*/
        if (val > half)
            val -= mod_value;
        vec.push_back(val);
    }
}

bool PackedEncoding::decode() {
    auto ptm = this->encoding_params->get_plaintext_modulus();

    if ((this->type_flag == IsNativePoly) || (this->type_flag == IsDCRTPoly)) {
        NativeInteger scf_inv = scaling_factor_int.mod_inverse(ptm);
        if (this->type_flag == IsNativePoly) {
            this->unpack(&this->get_element<NativePoly>(), ptm);
            NativePoly first_element = encoded_native_vector;
            first_element = first_element.Times(scf_inv);
            first_element = first_element.mod(ptm);
            fill_vec(first_element, ptm, this->value);
            // clears the values containing information about the noise
            this->get_element<NativePoly>().set_values_to_zero();
        } else {
            NativePoly first_element = this->get_element<RnsPoly>().get_element_at_index(0);
            this->unpack(&first_element, ptm);
            first_element = first_element.Times(scf_inv);
            first_element = first_element.mod(ptm);
            fill_vec(first_element, ptm, this->value);
            // clears the values containing information about the noise
            this->get_element<RnsPoly>().set_values_to_zero();
        }
    } else {
        this->unpack(&this->get_element<Poly>(), ptm);
        fill_vec(this->encoded_vector, ptm, this->value);
        // clears the values containing information about the noise
        this->get_element<Poly>().set_values_to_zero();
    }

    return true;
}

void PackedEncoding::destroy() {
    init_root_.clear();
    big_modulus_.clear();
    big_root_.clear();

    automorphism_generator_.clear();
    to_crt_perm_.clear();
    from_crt_perm_.clear();
}

void PackedEncoding::set_params(uint32_t m, EncodingParams params) {
    NativeInteger modulus_ni(params->get_plaintext_modulus());  // native int modulus
    std::string exception_message;
    bool had_ex = false;

    // initialize the CRT coefficients if not initialized
    try {
        if (is_power_of_two(m)) {
#pragma omp critical
            {
                set_params_2n(m, params);
            }
        } else {
#pragma omp critical
            {
                const ModulusM modulus_m = {modulus_ni, m};
                // Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity
                if (params->get_plaintext_root_of_unity() == 0) {
                    NativeInteger init_root = root_of_unity<NativeInteger>(2 * m, modulus_ni);
                    init_root_[modulus_m] = init_root;
                    params->set_plaintext_root_of_unity(init_root_[modulus_m].convert_to_int());
                } else {
                    init_root_[modulus_m] = params->get_plaintext_root_of_unity();
                }

                // Find a compatible big-modulus and root of unity for CRTArb
                if (params->get_plaintext_big_modulus() == 0) {
                    uint32_t ntt_dim = uint32_t{1} << get_msb(2 * m - 2);
                    if ((modulus_ni.convert_to_int() - 1) % ntt_dim == 0) {
                        big_modulus_[modulus_m] = modulus_ni;
                    } else {
                        uint32_t big_modulus_size = get_msb(2 * m - 2) + 2 * modulus_ni.get_msb() + 1;
                        big_modulus_[modulus_m] = last_prime<NativeInteger>(big_modulus_size, ntt_dim);
                    }
                    big_root_[modulus_m] = root_of_unity<NativeInteger>(ntt_dim, big_modulus_[modulus_m]);
                    params->set_plaintext_big_modulus(big_modulus_[modulus_m]);
                    params->set_plaintext_big_root_of_unity(big_root_[modulus_m]);
                } else {
                    big_modulus_[modulus_m] = params->get_plaintext_big_modulus();
                    big_root_[modulus_m] = params->get_plaintext_big_root_of_unity();
                }

                // Find a generator for the automorphism group
                if (params->get_plaintext_generator() == 0) {
                    NativeInteger M(m);  // Hackish typecast
                    NativeInteger automorphism_generator = find_generator_cyclic<NativeInteger>(M);
                    automorphism_generator_[m] = automorphism_generator.convert_to_int();
                    params->set_plaintext_generator(automorphism_generator_[m]);
                } else {
                    automorphism_generator_[m] = params->get_plaintext_generator();
                }

                // Create the permutations that interchange the automorphism and crt
                // ordering
                uint32_t phim = get_totient(m);
                auto t_list = get_totient_list(m);
                auto t_idx = std::vector<uint32_t>(m, -1);
                for (uint32_t i = 0; i < phim; i++) {
                    t_idx[t_list[i]] = i;
                }

                to_crt_perm_[m] = std::vector<uint32_t>(phim);
                from_crt_perm_[m] = std::vector<uint32_t>(phim);

                uint32_t curr_index = 1;
                for (uint32_t i = 0; i < phim; i++) {
                    to_crt_perm_[m][t_idx[curr_index]] = i;
                    from_crt_perm_[m][i] = t_idx[curr_index];

                    curr_index = curr_index * automorphism_generator_[m] % m;
                }
            }
        }
    } catch (std::exception& e) {
        exception_message = e.what();
        had_ex = true;
    }

    if (had_ex)
        CIPHER_THROW(exception_message);
}

template <typename P>
void PackedEncoding::pack_into(P* ring, const PlaintextModulus& modulus) const {
    CIPHER_DEBUG_FLAG(false);

    uint32_t m = ring->get_cyclotomic_order();  // cyclotomic order
    NativeInteger modulus_ni(modulus);         // native int modulus

    const ModulusM modulus_m = {modulus_ni, m};

    // Do the precomputation if not initialized
    if (this->init_root_[modulus_m].get_msb() == 0) {
        set_params(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    uint32_t phim = ring->get_ring_dimension();

    CIPHER_DEBUG("Pack for order " << m << " phim " << phim << " modulus " << modulus_ni);

    // copy values from ring to the vector
    NativeVector slot_values(phim, modulus_ni);
    for (uint32_t i = 0; i < phim; i++) {
        slot_values[i] = (*ring)[i].convert_to_int();
    }

    CIPHER_DEBUG(*ring);
    CIPHER_DEBUG(slot_values);

    // Transform Eval to Coeff
    if (is_power_of_two(m)) {
        if (to_crt_perm_[m].size() > 0) {
            // Permute to CRT Order
            NativeVector permuted_slots(phim, modulus_ni);

            for (uint32_t i = 0; i < phim; i++) {
                permuted_slots[i] = slot_values[to_crt_perm_[m][i]];
            }
            ChineseRemainderTransformFtt<NativeVector>().inverse_transform_from_bit_reverse(
                    permuted_slots, init_root_[modulus_m], m, &slot_values);
        } else {
            ChineseRemainderTransformFtt<NativeVector>().inverse_transform_from_bit_reverse(
                    slot_values, init_root_[modulus_m], m, &slot_values);
        }
    } else {  // Arbitrary cyclotomic
        // Permute to CRT Order
        NativeVector permuted_slots(phim, modulus_ni);
        for (uint32_t i = 0; i < phim; i++) {
            permuted_slots[i] = slot_values[to_crt_perm_[m][i]];
        }

        CIPHER_DEBUG("permutedSlots " << permuted_slots);
        CIPHER_DEBUG("m_initRoot[modulusM] " << init_root_[modulus_m]);
        CIPHER_DEBUG("m_bigModulus[modulusM] " << big_modulus_[modulus_m]);
        CIPHER_DEBUG("m_bigRoot[modulusM] " << big_root_[modulus_m]);

        slot_values = ChineseRemainderTransformArb<NativeVector>().inverse_transform(
                permuted_slots, init_root_[modulus_m], big_modulus_[modulus_m], big_root_[modulus_m], m);
    }

    CIPHER_DEBUG("slotvalues now " << slot_values);
    // copy values into the slot_values_ring
    typename P::Vector slot_values_ring(phim, ring->get_modulus());
    for (uint32_t i = 0; i < phim; i++) {
        slot_values_ring[i] = typename P::Integer(slot_values[i].convert_to_int());
    }

    ring->set_values(std::move(slot_values_ring), Format::COEFFICIENT);

    CIPHER_DEBUG(*ring);
}

void PackedEncoding::pack_native_vector(const PlaintextModulus& modulus, uint32_t m, NativeVector* values) const {
    NativeVector& slot_values = *values;
    NativeInteger modulus_ni(modulus);  // native int modulus
    uint32_t phim = slot_values.get_length();

    const ModulusM modulus_m = {modulus_ni, m};

    // Do the precomputation if not initialized
    if (this->init_root_[modulus_m].get_msb() == 0) {
        set_params(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    // Transform Eval to Coeff
    if (is_power_of_two(m)) {
        if (to_crt_perm_[m].size() > 0) {
            // Permute to CRT Order
            NativeVector permuted_slots(phim, modulus_ni);

            for (uint32_t i = 0; i < phim; i++) {
                permuted_slots[i] = slot_values[to_crt_perm_[m][i]];
            }
            ChineseRemainderTransformFtt<NativeVector>().inverse_transform_from_bit_reverse(
                    permuted_slots, init_root_[modulus_m], m, &slot_values);
        } else {
            ChineseRemainderTransformFtt<NativeVector>().inverse_transform_from_bit_reverse(
                    slot_values, init_root_[modulus_m], m, &slot_values);
        }
    } else {  // Arbitrary cyclotomic
        // Permute to CRT Order
        NativeVector permuted_slots(phim, modulus_ni);
        for (uint32_t i = 0; i < phim; i++) {
            permuted_slots[i] = slot_values[to_crt_perm_[m][i]];
        }

        slot_values = ChineseRemainderTransformArb<NativeVector>().inverse_transform(
                permuted_slots, init_root_[modulus_m], big_modulus_[modulus_m], big_root_[modulus_m], m);
    }
}

template <typename P>
void PackedEncoding::unpack(P* ring, const PlaintextModulus& modulus) const {
    CIPHER_DEBUG_FLAG(false);

    uint32_t m = ring->get_cyclotomic_order();  // cyclotomic order
    NativeInteger modulus_ni(modulus);         // native int modulus

    const ModulusM modulus_m = {modulus_ni, m};

    // Do the precomputation if not initialized
    if (this->init_root_[modulus_m].get_msb() == 0) {
        set_params(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    uint32_t phim = ring->get_ring_dimension();  // ring dimension

    CIPHER_DEBUG("Unpack for order " << m << " phim " << phim << " modulus " << modulus_ni);

    // copy aggregate plaintext values
    NativeVector packed_vector(phim, modulus_ni);
    for (uint32_t i = 0; i < phim; i++) {
        packed_vector[i] = NativeInteger((*ring)[i].convert_to_int());
    }

    CIPHER_DEBUG(packed_vector);

    // Transform Coeff to Eval
    NativeVector permuted_slots(phim, modulus_ni);
    if (is_power_of_two(m)) {
        ChineseRemainderTransformFtt<NativeVector>().forward_transform_to_bit_reverse(packed_vector, init_root_[modulus_m], m,
                                                                                  &permuted_slots);
    } else {  // Arbitrary cyclotomic
        permuted_slots = ChineseRemainderTransformArb<NativeVector>().forward_transform(
                packed_vector, init_root_[modulus_m], big_modulus_[modulus_m], big_root_[modulus_m], m);
    }

    if (from_crt_perm_[m].size() > 0) {
        // Permute to automorphism Order
        for (uint32_t i = 0; i < phim; i++) {
            packed_vector[i] = permuted_slots[from_crt_perm_[m][i]];
        }
    } else {
        packed_vector = permuted_slots;
    }

    CIPHER_DEBUG(packed_vector);

    // copy values into the slot_values_ring
    typename P::Vector packed_vector_ring(phim, ring->get_modulus());
    for (uint32_t i = 0; i < phim; i++) {
        packed_vector_ring[i] = typename P::Integer(packed_vector[i].convert_to_int());
    }

    ring->set_values(std::move(packed_vector_ring), Format::COEFFICIENT);
}

void PackedEncoding::set_params_2n(uint32_t m, NativeInteger modulus_ni) {
    if (!miller_rabin_primality_test(modulus_ni)) {
        CIPHER_THROW("The modulus value is [" + modulus_ni.to_string() + "]. It must be prime.");
    }

    const ModulusM modulus_m = {modulus_ni, m};

    // Power of two: m/2-point FTT. So we need the mth root of unity
    init_root_[modulus_m] = root_of_unity<NativeInteger>(m, modulus_ni);

    // Create the permutations that interchange the automorphism and crt ordering
    // First we create the cyclic group generated by 5 and then adjoin the
    // co-factor by multiplying by (-1)

    uint32_t phim = (m >> 1);
    uint32_t phim_by_2 = (m >> 2);

    to_crt_perm_[m] = std::vector<uint32_t>(phim);
    from_crt_perm_[m] = std::vector<uint32_t>(phim);

    uint32_t curr_index = 1;
    uint32_t logn = std::round(std::log2(m / 2));
    for (uint32_t i = 0; i < phim_by_2; i++) {
        to_crt_perm_[m][reverse_bits((curr_index - 1) / 2, logn)] = i;
        from_crt_perm_[m][i] = reverse_bits((curr_index - 1) / 2, logn);

        uint32_t cofactor_index = curr_index * (m - 1) % m;

        to_crt_perm_[m][reverse_bits((cofactor_index - 1) / 2, logn)] = i + phim_by_2;
        from_crt_perm_[m][i + phim_by_2] = reverse_bits((cofactor_index - 1) / 2, logn);

        curr_index = curr_index * 5 % m;
    }
}

void PackedEncoding::set_params_2n(uint32_t m, EncodingParams params) {
    NativeInteger modulus_ni(params->get_plaintext_modulus());  // native int modulus

    if (!miller_rabin_primality_test(modulus_ni)) {
        CIPHER_THROW("The modulus value is [" + modulus_ni.to_string() + "]. It must be prime.");
    }

    const ModulusM modulus_m = {modulus_ni, m};

    // Power of two: m/2-point FTT. So we need the mth root of unity
    if (params->get_plaintext_root_of_unity() == 0) {
        init_root_[modulus_m] = root_of_unity<NativeInteger>(m, modulus_ni);
        params->set_plaintext_root_of_unity(init_root_[modulus_m]);
    } else {
        init_root_[modulus_m] = params->get_plaintext_root_of_unity();
    }

    // Create the permutations that interchange the automorphism and crt ordering
    // First we create the cyclic group generated by 5 and then adjoin the
    // co-factor by multiplying by (-1)
    uint32_t phim = (m >> 1);
    uint32_t phim_by_2 = (m >> 2);

    to_crt_perm_[m] = std::vector<uint32_t>(phim);
    from_crt_perm_[m] = std::vector<uint32_t>(phim);

    uint32_t curr_index = 1;
    uint32_t logn = std::round(std::log2(m >> 1));
    for (uint32_t i = 0; i < phim_by_2; i++) {
        to_crt_perm_[m][reverse_bits((curr_index - 1) / 2, logn)] = i;
        from_crt_perm_[m][i] = reverse_bits((curr_index - 1) / 2, logn);

        uint32_t cofactor_index = curr_index * (m - 1) % m;

        to_crt_perm_[m][reverse_bits((cofactor_index - 1) / 2, logn)] = i + phim_by_2;
        from_crt_perm_[m][i + phim_by_2] = reverse_bits((cofactor_index - 1) / 2, logn);

        curr_index = curr_index * 5 % m;
    }
}
}  // namespace cipher
