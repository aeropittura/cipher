//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  Header for the standard values for Lattice Parms, as determined by homomorphicencryption.org
 */

#ifndef CIPHER_RING_STANDARD_PARAMS_H_
#define CIPHER_RING_STANDARD_PARAMS_H_

//  #include "math/math-hal.h"

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "cipher/util/inttypes.h"

namespace cipher {

// this is the representation of the standard lattice parameters defined in the
// Homomorphic Encryption Standard, as defined by
// http://homomorphicencryption.org

// given a distribution type and a security level, you can get the max_q for a
// given ring dimension, and you can get the ring dimension given a max_q

// The code below is very specific to the layout of the DistributionType and
// SecurityLevel enums IF you change them, go look at and change by_ring and
// by_log_q

/**
 * @brief Secret key distribution used to select a table of the Homomorphic Encryption Standard.
 * The enumerators must stay consecutive from 0 because they index the lookup tables in StdLatticeParm.
 */
enum DistributionType {
    HEStd_uniform,
    HEStd_error,
    HEStd_ternary,
};

/**
 * @brief Security level of the Homomorphic Encryption Standard (bits of security, classical or quantum attacks).
 * HEStd_NotSet disables the standard-based parameter checks. The enumerators must stay consecutive from 0 because
 * they index the lookup tables in StdLatticeParm.
 */
enum SecurityLevel {
    HEStd_128_classic,
    HEStd_192_classic,
    HEStd_256_classic,
    HEStd_128_quantum,
    HEStd_192_quantum,
    HEStd_256_quantum,
    HEStd_NotSet,
};

/**
 * @brief Converts the name of a security level (e.g., "HEStd_128_classic") to the enumerator; throws for an
 * unknown name.
 * @param str name of the security level, spelled as the enumerator
 * @return the security level
 */
SecurityLevel convert_to_security_level(const std::string& str);
/**
 * @brief Converts an integer to a security level; throws for values that do not correspond to one of the
 * standard levels (HEStd_NotSet is not accepted).
 * @param num integer value of the enumerator
 * @return the security level
 */
SecurityLevel convert_to_security_level(uint32_t num);
/**
 * @brief Prints the name of a security level.
 * @param s output stream
 * @param sl security level to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, SecurityLevel sl);

/**
 * @brief One row of the Homomorphic Encryption Standard parameter tables: for a secret key distribution,
 * a ring dimension, and a security level, the largest supported bit size of the ciphertext modulus.
 * The rows are stored in a static table and indexed by (distribution, security level), then by ring dimension
 * (find_max_q) or by modulus bit size (find_ring_dim).
 */
class StdLatticeParm {
    DistributionType dist_type;
    uint32_t ring_dim;
    SecurityLevel min_sec_lev;
    uint32_t max_log_q;

    // NOTE!!! the declaration below relies upon there being three possible values
    // for the first index (the distribution type), and six possible values for
    // the second index (the security level)
    // The values in the enums, above, meet this criteria
    // it's also important that the different values are numbered from 0-2
    // again, the enums above do this
    // DO NOT change the values of the enums to be anything other than consecutive
    // numbers starting from 0, or this code will break in strange ways, and you
    // will suffer MAKE SURE that the number of entries in the DistributionType
    // enum is == the first index, and MAKE SURE that the number of entries in the
    // SecurityLevel enum is == the second index
    static std::map<uint32_t, StdLatticeParm*> by_ring[3][6];
    static std::map<uint32_t, StdLatticeParm*> by_log_q[3][6];

    static std::vector<StdLatticeParm> standard_lattice_parm_sets;
    static bool initialized;

  public:
    /**
     * @brief Constructs one table row.
     * @param dist_type secret key distribution
     * @param ring_dim ring dimension
     * @param min_sec_lev security level the row is certified for
     * @param max_log_q largest supported bit size of the ciphertext modulus
     */
    StdLatticeParm(DistributionType dist_type, uint32_t ring_dim, SecurityLevel min_sec_lev, uint32_t max_log_q)
        : dist_type(dist_type), ring_dim(ring_dim), min_sec_lev(min_sec_lev), max_log_q(max_log_q) {}

    /**
     * @brief Builds the lookup maps (by ring dimension and by modulus bit size) from the static table of rows.
     * Called on first use by find_max_q and find_ring_dim.
     */
    static void initialize_lookups() {
        for (size_t i = 0; i < standard_lattice_parm_sets.size(); i++) {
            StdLatticeParm& s = standard_lattice_parm_sets[i];
            by_ring[static_cast<int>(s.dist_type)][static_cast<int>(s.min_sec_lev)][s.ring_dim] = &s;
            by_log_q[static_cast<int>(s.dist_type)][static_cast<int>(s.min_sec_lev)][s.max_log_q] = &s;
        }
        initialized = true;
    }

    /**
     * @brief Looks up the largest supported ciphertext modulus bit size for a ring dimension.
     * @param dist_type secret key distribution
     * @param min_sec_lev required security level
     * @param ring_dim ring dimension
     * @return the maximum log2 of the ciphertext modulus, or 0 if the table has no row for this ring dimension
     */
    static uint32_t find_max_q(DistributionType dist_type, SecurityLevel min_sec_lev, uint32_t ring_dim) {
        int dist_type_idx = static_cast<int>(dist_type);
        int min_sec_lev_idx = static_cast<int>(min_sec_lev);
        if (!initialized)
            initialize_lookups();
        auto it = by_ring[dist_type_idx][min_sec_lev_idx].find(ring_dim);
        if (it == by_ring[dist_type_idx][min_sec_lev_idx].end())
            return 0;
        return it->second->get_max_log_q();
    }

    /**
     * @brief Finds the smallest tabulated ring dimension whose maximum modulus bit size is at least cur_log_q.
     * @param dist_type secret key distribution
     * @param min_sec_lev required security level
     * @param cur_log_q log2 of the ciphertext modulus
     * @return the ring dimension, or twice the largest tabulated ring dimension if cur_log_q exceeds every table row
     */
    static uint32_t find_ring_dim(DistributionType dist_type, SecurityLevel min_sec_lev, uint32_t cur_log_q) {
        if (!initialized)
            initialize_lookups();
        uint32_t prev = 0;

        int dist_type_idx = static_cast<int>(dist_type);
        int min_sec_lev_idx = static_cast<int>(min_sec_lev);
        uint32_t n = 0;
        for (std::pair<const unsigned int, StdLatticeParm*>& it : by_log_q[dist_type_idx][min_sec_lev_idx]) {
            if ((cur_log_q <= it.second->get_max_log_q()) && (cur_log_q > prev))
                return it.second->get_ring_dim_impl();
            prev = it.second->get_max_log_q();
            n = it.second->get_ring_dim_impl();
        }
        return 2 * n;
    }

    DistributionType get_dist_type() const {
        return dist_type;
    }
    uint32_t get_ring_dim_impl() const {
        return ring_dim;
    }
    SecurityLevel get_min_sec_lev() const {
        return min_sec_lev;
    }
    uint32_t get_max_log_q() const {
        return max_log_q;
    }
};

} /* namespace cipher */

#endif  // CIPHER_RING_STANDARD_PARAMS_H_
