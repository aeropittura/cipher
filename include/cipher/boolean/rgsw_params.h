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

#ifndef CIPHER_BOOLEAN_RGSW_PARAMS_H_
#define CIPHER_BOOLEAN_RGSW_PARAMS_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cipher/boolean/constants.h"
#include "cipher/ring/backend.h"
#include "cipher/boolean/lwe_ciphertext.h"
#include "cipher/boolean/lwe_params.h"
#include "cipher/boolean/lwe_switch_key.h"
#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/serializable.h"
#include "cipher/util/utilities.h"

namespace cipher {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class RingGswCryptoParams : public Serializable {
  public:
    RingGswCryptoParams() = default;

    /**
     * Main constructor for RingGswCryptoParams
     *
     * @param N ring dimension for RingGSW/RLWE used in bootstrapping
     * @param Q modulus for RingGSW/RLWE used in bootstrapping
     * @param q ciphertext modulus for additive LWE
     * @param base_g the gadget base used in the bootstrapping
     * @param base_r the base for the refreshing key
     * @param method bootstrapping method (DM or CGGI or LMKCDEY)
     * @param std standard deviation
     * @param key_dist secret key distribution
     * @param sign_eval flag if sign evaluation is needed
     * @param num_auto_keys number of automorphism keys in LMKCDEY bootstrapping
     */
    explicit RingGswCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t base_g, uint32_t base_r,
                                 BINFHE_METHOD method, double std, SecretKeyDist key_dist = UNIFORM_TERNARY,
                                 bool sign_eval = false, uint32_t num_auto_keys = 10)
        : Q_(Q),
          q_(q),
          N_(N),
          base_g_(base_g),
          base_r_(base_r),
          poly_params_{std::make_shared<NativePolyParams>(2 * N, Q)},
          method_(method),
          key_dist_(key_dist),
          num_auto_keys_(num_auto_keys) {
        if (base_g <= 1 || !is_power_of_two(base_g))
            CIPHER_THROW("Gadget base should be a power of two.");
        if ((method == LMKCDEY) && (num_auto_keys == 0))
            CIPHER_THROW("numAutoKeys should be greater than 0.");
        digits_g_ = digits_for_base(Q_, base_g_);
        check_digits_g(base_g_, digits_g_);
        dgg_.set_std(std);
        pre_compute(sign_eval);
    }

    /**
     * Constructor for using multiple gadget bases in bootstrapping
     *
     * @param N ring dimension for RingGSW/RLWE used in bootstrapping
     * @param Q modulus for RingGSW/RLWE used in bootstrapping
     * @param q ciphertext modulus for additive LWE
     * @param base_g the default gadget base, also used for automorphism keys
     * @param base_g_map number of LWE secret-key coefficients assigned to each gadget base
     * @param base_r the base for the refreshing key
     * @param method bootstrapping method (DM or CGGI or LMKCDEY)
     * @param std standard deviation
     * @param key_dist secret key distribution
     * @param sign_eval flag if sign evaluation is needed
     * @param num_auto_keys number of automorphism keys in LMKCDEY bootstrapping
     */
    explicit RingGswCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t base_g,
                                 const std::map<uint32_t, uint32_t>& base_g_map, uint32_t base_r, BINFHE_METHOD method,
                                 double std, SecretKeyDist key_dist = UNIFORM_TERNARY, bool sign_eval = false,
                                 uint32_t num_auto_keys = 10)
        : Q_(Q),
          q_(q),
          N_(N),
          base_g_(base_g),
          base_g_map_(base_g_map),
          base_r_(base_r),
          poly_params_{std::make_shared<NativePolyParams>(2 * N, Q)},
          method_(method),
          key_dist_(key_dist),
          num_auto_keys_(num_auto_keys) {
        if (base_g_map.empty())
            CIPHER_THROW("Gadget base map should not be empty.");
        if (!is_power_of_two(base_g))
            CIPHER_THROW("Gadget base should be a power of two.");
        for (const auto& [base_g, count] : base_g_map) {
            if (count == 0 || base_g <= 1 || !is_power_of_two(base_g))
                CIPHER_THROW("Gadget base should be a power of two and its count should be greater than zero.");
            check_digits_g(base_g, digits_for_base(Q, base_g));
        }
        if ((method == LMKCDEY) && (num_auto_keys == 0))
            CIPHER_THROW("numAutoKeys should be greater than 0.");
        digits_g_ = digits_for_base(Q_, base_g_);
        check_digits_g(base_g_, digits_g_);
        dgg_.set_std(std);
        pre_compute(sign_eval);
    }

    /**
     * @brief Gadget parameters for one LWE secret-key index: the base, its digit count, and its gadget powers
     */
    struct BaseGParams {
        uint32_t base_g{0};                                ///< gadget base, a power of two
        uint32_t digits_g{0};                              ///< number of base-base_g digits needed to represent Q
        uint32_t g_bits{0};                                ///< log2(base_g), the width of one digit in bits
        const std::vector<NativeInteger>* gpow{nullptr};  ///< powers base_g^i mod Q for i < digits_g, owned by the params
        uint32_t team_width{0};                            ///< thread-team size for the external product: the largest
                                                          ///< 2(digits_g - 1) over all gadget bases in use
    };

    /**
     * Performs precomputations based on the supplied parameters: the powers of base_r (AP only), the gadget powers of
     * every gadget base in use, the gate constants, the CGGI monomials X^m - 1, the per-index gadget table when a
     * gadget base map is in use, and the discrete-log and automorphism tables for LMKCDEY
     *
     * @param sign_eval whether to also precompute the gadget powers of the bases 2^14, 2^18 and 2^27 that the
     *        large-precision sign evaluation switches between through change_base_g
     */
    void pre_compute(bool sign_eval = false);

    /**
     * Computes the gadget powers base_g^i mod Q for i < digits_g, once per base, and caches them in the gadget power map
     *
     * @param base_g the gadget base
     * @return the cached vector of gadget powers for base_g
     */
    const std::vector<NativeInteger>& precompute_g_power(uint32_t base_g);

    uint32_t get_N() const {
        return N_;
    }

    NativeInteger get_Q() const {
        return Q_;
    }

    NativeInteger get_q() const {
        return q_;
    }

    uint32_t get_base_g() const {
        return base_g_;
    }

    uint32_t get_digits_g() const {
        return digits_g_;
    }

    /**
     * Gets the gadget parameters of the default gadget base. The result is built by value from the live members, so
     * a base switched by change_base_g() after pre_compute() takes effect; when no gadget base map is in use these
     * parameters apply to every LWE index
     *
     * @return the gadget parameters of the default base
     */
    BaseGParams get_default_base_g_params() const {
        return {base_g_, digits_g_, cipher::get_msb(base_g_) - 1, &gpower_,
                base_g_by_index_.empty() ? ((digits_g_ - 1) << 1) : team_width_};
    }

    /**
     * Gets the gadget parameters assigned to an LWE secret-key coefficient; pre_compute() expands the gadget base map
     * into one entry per index
     *
     * @param index LWE secret-key coefficient index
     * @return the gadget parameters for that index, or the default ones when no gadget base map is in use
     */
    BaseGParams get_base_g_params(uint32_t index) const {
        if (base_g_by_index_.empty())
            return get_default_base_g_params();
        if (index >= base_g_by_index_.size())
            CIPHER_THROW("Gadget base map does not cover the LWE dimension.");
        return base_g_by_index_[index];
    }

    uint32_t get_base_g(uint32_t index) const {
        return get_base_g_params(index).base_g;
    }

    uint32_t get_digits_g(uint32_t index) const {
        return get_base_g_params(index).digits_g;
    }

    // empty when no per-dimension base map is in use; then get_default_base_g_params() applies to
    // every index
    const std::vector<BaseGParams>& get_base_g_by_index() const {
        return base_g_by_index_;
    }

    /**
     * Checks that the per-index gadget table, when present, has exactly one entry per LWE secret-key coefficient. The
     * table is built from a map that never sees the LWE dimension, so only a caller holding both can reconcile them;
     * call this before entering a parallel region
     *
     * @param n the LWE dimension
     */
    void verify_base_g_coverage(uint32_t n) const {
        if (!base_g_by_index_.empty() && base_g_by_index_.size() != n)
            CIPHER_THROW("Gadget base map does not cover the LWE dimension.");
    }

    uint32_t get_base_r() const {
        return base_r_;
    }

    uint32_t get_num_auto_keys() const {
        return num_auto_keys_;
    }

    const std::vector<NativeInteger>& get_digits_r() const {
        return digits_r_;
    }

    /**
     * Gets the number of values the digit at position pos can take when a coefficient below q is written in base
     * base_r: every position spans the whole base except the top one (AP bootstrapping only)
     *
     * @param pos digit position, 0 being the least significant
     * @return the number of values the digit can take
     */
    uint32_t get_digit_extent_r(uint32_t pos) const {
        if (pos + 1 < digits_r_.size())
            return base_r_;
        return static_cast<uint32_t>((q_.convert_to_int<uint64_t>() - 1) / digits_r_.back().convert_to_int<uint64_t>()) +
               1;
    }

    const std::shared_ptr<NativePolyParams> get_poly_params() const {
        return poly_params_;
    }

    const std::vector<NativeInteger>& get_g_power() const {
        return gpower_;
    }

    /**
     * Gets the precomputed gadget powers of a given gadget base
     *
     * @param base_g the gadget base, which must have been precomputed
     * @return the vector of powers base_g^i mod Q
     */
    const std::vector<NativeInteger>& get_g_power(uint32_t base_g) const {
        auto it = gpower_map_.find(base_g);
        if (it == gpower_map_.end())
            CIPHER_THROW("No GPower found for the requested gadget base.");
        return it->second;
    }

    /**
     * Gets the gadget powers of the base assigned to an LWE secret-key coefficient
     *
     * @param index LWE secret-key coefficient index
     * @return the vector of gadget powers for that index, or the default powers when none is assigned
     */
    const std::vector<NativeInteger>& get_g_power_by_index(uint32_t index) const {
        const auto* gpow = get_base_g_params(index).gpow;
        return (gpow == nullptr) ? gpower_ : *gpow;
    }

    /**
     * Gets the precomputed automorphism index map for X -> X^index (LMKCDEY only); maps exist for the generator
     * powers 5^k, k in [1, num_auto_keys], and for 2N - 5
     *
     * @param index the automorphism index
     * @return the coefficient permutation map of length N
     */
    const std::vector<uint32_t>& get_auto_map(uint32_t index) const {
        auto it = auto_map_.find(index);
        if (it == auto_map_.end())
            CIPHER_THROW("No automorphism map precomputed for index " + std::to_string(index));
        return it->second;
    }

    const std::vector<int32_t>& get_log_gen() const {
        return log_gen_;
    }

    const std::map<uint32_t, std::vector<NativeInteger>>& get_g_power_map() const {
        return gpower_map_;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& get_dgg_impl() const {
        return dgg_;
    }

    const std::vector<NativeInteger>& get_gate_const() const {
        return gate_const_;
    }

    /**
     * Gets a precomputed CGGI monomial in EVALUATION format: X^i - 1 for i < N and -X^(i-N) - 1 for N <= i < 2N
     *
     * @param i index in [0, 2N), the exponent modulo 2N with X^N = -1
     * @return the monomial polynomial
     */
    const NativePoly& get_monomial(uint32_t i) const {
        return monomials_[i];
    }

    /**
     * Checks whether the CGGI monomials X^m - 1 are resident
     *
     * @return true if the monomial table is built
     */
    bool has_monomials() const {
        return !monomials_.empty();
    }

    /**
     * Releases the precomputed CGGI monomials X^m - 1 and their storage; used once every resident refreshing key is in
     * the 32-bit internal form, which keeps its own 32-bit monomial table
     */
    void clear_monomials() {
        std::vector<NativePoly>().swap(monomials_);
    }

    /**
     * Builds the CGGI monomials X^m - 1 if the method is GINX and they are not resident, e.g. after clear_monomials()
     */
    void ensure_monomials() {
        if (method_ == BINFHE_METHOD::GINX && monomials_.empty())
            build_monomials();
    }

#if CIPHER_NATIVE_INT != 32
    /**
     * Gets the 32-bit polynomial parameters (cyclotomic order 2N, and Q and its root of unity narrowed to 32 bits) for
     * the 32-bit internal path, building them on first use. Requires Q to fit MAX_MODULUS_SIZE32 bits. The cache is
     * unguarded, so build it before entering a parallel region
     *
     * @return a shared pointer to the 32-bit polynomial parameters
     */
    const std::shared_ptr<NativePolyParams32>& get_poly_params32();

    /**
     * Gets the 2N monomials X^m - 1, m < 2N with X^N = -1, in EVALUATION format at 32 bits for the CGGI accumulator on
     * the 32-bit internal key, built natively on first use; the table equals the narrowed 64-bit one, which need not
     * exist. The cache is unguarded, so build it before entering a parallel region
     *
     * @return a shared pointer to the 32-bit monomial table
     */
    const std::shared_ptr<const std::vector<NativePoly32>>& get_monomials32();

    /**
     * Gets the Shoup precomputation of every coefficient of the 32-bit monomials, for multiplication by a constant
     * mod Q, built on first use together with the monomials themselves
     *
     * @return a shared pointer to the precomputed vectors, one per monomial
     */
    const std::shared_ptr<const std::vector<NativeVector32>>& get_monomials_precon32();
#endif

    BINFHE_METHOD get_method() const {
        return method_;
    }

    SecretKeyDist get_key_dist() const {
        return key_dist_;
    }

    bool operator==(const RingGswCryptoParams& other) const {
        return N_ == other.N_ && Q_ == other.Q_ && q_ == other.q_ && base_r_ == other.base_r_ &&
               base_g_ == other.base_g_ && base_g_map_ == other.base_g_map_ && method_ == other.method_ &&
               key_dist_ == other.key_dist_ && num_auto_keys_ == other.num_auto_keys_ &&
               dgg_.get_std() == other.dgg_.get_std();
    }

    bool operator!=(const RingGswCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("bN", N_));
        ar(::cereal::make_nvp("bQ", Q_));
        ar(::cereal::make_nvp("bq", q_));
        ar(::cereal::make_nvp("bR", base_r_));
        ar(::cereal::make_nvp("bG", base_g_));
        ar(::cereal::make_nvp("bmethod", method_));
        ar(::cereal::make_nvp("bs", dgg_.get_std()));
        ar(::cereal::make_nvp("bdigitsG", digits_g_));
        ar(::cereal::make_nvp("bparams", poly_params_));
        ar(::cereal::make_nvp("numAutoKeys", num_auto_keys_));
        ar(::cereal::make_nvp("baseGMap", base_g_map_));
        ar(::cereal::make_nvp("keyDist", key_dist_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("bN", N_));
        ar(::cereal::make_nvp("bQ", Q_));
        ar(::cereal::make_nvp("bq", q_));
        ar(::cereal::make_nvp("bR", base_r_));
        ar(::cereal::make_nvp("bG", base_g_));
        ar(::cereal::make_nvp("bmethod", method_));
        double sigma = 0;
        ar(::cereal::make_nvp("bs", sigma));
        dgg_.set_std(sigma);
        ar(::cereal::make_nvp("bdigitsG", digits_g_));
        ar(::cereal::make_nvp("bparams", poly_params_));
        ar(::cereal::make_nvp("numAutoKeys", num_auto_keys_));
        ar(::cereal::make_nvp("baseGMap", base_g_map_));
        ar(::cereal::make_nvp("keyDist", key_dist_));
        pre_compute();
    }

    std::string serialized_object_name() const override {
        return "RingGSWCryptoParams";
    }

    static uint32_t serialized_version() {
        return 1;
    }

    /**
     * Switches the default gadget base, updating the digit count and the gadget powers (computed if not cached); a
     * no-op when the base is unchanged. Used by the large-precision sign evaluation
     *
     * @param base_g_value the new gadget base, a power of two that leaves at least two digits mod Q; not supported when a
     *        gadget base map is in use
     */
    void change_base_g(uint32_t base_g_value) {
        if (base_g_ != base_g_value) {
            if (!base_g_by_index_.empty())
                CIPHER_THROW("Change_BaseG is not supported with per-dimension gadget bases");
            check_digits_g(base_g_value, digits_for_base(Q_, base_g_value));
            base_g_ = base_g_value;
            gpower_ = precompute_g_power(base_g_value);
            digits_g_ = digits_for_base(Q_, base_g_);
        }
    }

  private:
    // the approximate gadget decomposition drops the first digit, so a single-digit gadget
    // leaves the external product with no rows at all
    static void check_digits_g(uint32_t base_g, uint32_t digits_g) {
        if (digits_g < 2)
            CIPHER_THROW("Gadget base " + std::to_string(base_g) +
                          " is too large for Q: the approximate gadget decomposition needs at least two digits.");
    }

    static uint32_t digits_for_base(const NativeInteger& Q, uint32_t base_g) {
        return cipher::get_digit_count(Q.convert_to_int(), base_g);
    }

    void build_monomials();

    // modulus for the RingGSW/RingLWE scheme
    NativeInteger Q_;

    // modulus for the RingLWE scheme
    NativeInteger q_;

    // ring dimension for RingGSW/RingLWE scheme
    uint32_t N_;

    // gadget base used in bootstrapping
    uint32_t base_g_;

    // number of LWE secret-key coefficients assigned to each gadget base, in ascending base order
    std::map<uint32_t, uint32_t> base_g_map_;

    // base_g_map_ expanded to one entry per LWE index, filled by pre_compute()
    std::vector<BaseGParams> base_g_by_index_;
    uint32_t team_width_{0};

    // base used for the refreshing key (used only for DM bootstrapping)
    uint32_t base_r_;

    // number of digits in decomposing integers mod Q for given base_g
    uint32_t digits_g_;

    // powers of base_r_ (used only for DM bootstrapping)
    std::vector<NativeInteger> digits_r_;

    // A vector of powers of base_g
    std::vector<NativeInteger> gpower_;

    // A vector of log by generator g (=5) (only for LMKCDEY)
    // Not exactly log, but a mapping similar to logarithm for efficiency
    // log_gen_[5^i (mod M)] = i (i > 0)
    // log_gen_[-5^i (mod M)] = -i ()
    // log_gen_[1] = 0
    // log_gen_[-1 (mod M)] = M (special case for efficiency)
    std::vector<int32_t> log_gen_;

    std::unordered_map<uint32_t, std::vector<uint32_t>> auto_map_;

    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> dgg_;

    // A map of vectors of powers for each gadget base
    std::map<uint32_t, std::vector<NativeInteger>> gpower_map_;

    // Parameters for polynomials in RingGSW/RingLWE
    std::shared_ptr<NativePolyParams> poly_params_;

    // Constants used in evaluating binary gates
    std::vector<NativeInteger> gate_const_;

    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> monomials_;

#if CIPHER_NATIVE_INT != 32
    // transient caches for the 32-bit internal path; never serialized, rebuilt on demand
    std::shared_ptr<NativePolyParams32> poly_params32_;
    std::shared_ptr<const std::vector<NativePoly32>> monomials32_;
    std::shared_ptr<const std::vector<NativeVector32>> monomials_precon32_;
#endif

    // Bootstrapping method (DM or CGGI or LMKCDEY)
    BINFHE_METHOD method_{BINFHE_METHOD::INVALID_METHOD};

    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist key_dist_{SecretKeyDist::UNIFORM_TERNARY};

    // number of automorphism keys (used only for LMKCDEY bootstrapping)
    uint32_t num_auto_keys_;
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_PARAMS_H_
