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
  Creates Represents integer lattice elements
 */

#ifndef CIPHER_RING_BACKEND_STANDARD_POLY_H_
#define CIPHER_RING_BACKEND_STANDARD_POLY_H_

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cipher/ring/backend/standard/rns_params.h"
#include "cipher/ring/backend/standard/poly_params.h"
#include "cipher/ring/backend/poly_interface.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * @class PolyImpl
 * @brief Ideal lattice using a vector representation: a polynomial with coefficients modulo one integer modulus,
 * stored as a single vector of values in COEFFICIENT or EVALUATION format.
 *
 * @tparam VecType the vector type holding the values, e.g. BigVector or NativeVector.
 */
template <typename VecType>
class PolyImpl final : public PolyInterface<PolyImpl<VecType>, VecType, PolyImpl> {
  public:
    using Vector = VecType;
    using Integer = typename VecType::Integer;
    using Params = PolyParamsImpl<Integer>;
    using PolyNative = PolyImpl<NativeVector>;
    using PolyType = PolyImpl<VecType>;
    using PolyLargeType = PolyImpl<VecType>;
    using PolyInterfaceType = PolyInterface<PolyImpl<VecType>, VecType, PolyImpl>;
    using DggType = typename PolyInterfaceType::DggType;
    using DugType = typename PolyInterfaceType::DugType;
    using TugType = typename PolyInterfaceType::TugType;
    using BugType = typename PolyInterfaceType::BugType;

    constexpr PolyImpl() = default;

    /**
     * @brief Constructs an element with the given parameters and format; the values are set to zero if requested and
     * left unallocated otherwise.
     *
     * @param params the element parameters (cyclotomic order, modulus, root of unity).
     * @param format the format of the element (COEFFICIENT or EVALUATION).
     * @param initialize_element_to_zero if true, the values are allocated and set to zero.
     */
    PolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             bool initialize_element_to_zero = false)
        : format_{format}, params_{params} {
        if (initialize_element_to_zero)
            PolyImpl::set_values_to_zero();
    }
    /**
     * @brief Constructs an element from double-CRT parameters: a single-modulus parameter set with the same cyclotomic
     * order, the composite modulus and a root of unity of 1 is created; the values are set to zero if requested and
     * left unallocated otherwise.
     *
     * @param params the double-CRT parameters.
     * @param format the format of the element (COEFFICIENT or EVALUATION).
     * @param initialize_element_to_zero if true, the values are allocated and set to zero.
     */
    PolyImpl(const std::shared_ptr<RnsParams<Integer>>& params, Format format = Format::EVALUATION,
             bool initialize_element_to_zero = false)
        : format_(format), params_(std::make_shared<Params>(params->get_cyclotomic_order(), params->get_modulus(), 1)) {
        if (initialize_element_to_zero)
            this->set_values_to_zero();
    }

    /**
     * @brief Constructs an element with the given parameters and format whose values are all set to modulus - 1 if
     * requested and left unallocated otherwise.
     *
     * @param initialize_element_to_max if true, the values are allocated and set to modulus - 1.
     * @param params the element parameters (cyclotomic order, modulus, root of unity).
     * @param format the format of the element (COEFFICIENT or EVALUATION).
     */
    PolyImpl(bool initialize_element_to_max, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION)
        : format_{format}, params_{params} {
        if (initialize_element_to_max)
            PolyImpl::set_values_to_max();
    }
    /**
     * @brief Constructs an element whose coefficients are sampled from a discrete Gaussian distribution and converted
     * to the requested format.
     *
     * @param dgg the discrete Gaussian generator.
     * @param params the element parameters.
     * @param format the format of the resulting element.
     */
    PolyImpl(const DggType& dgg, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
     * @brief Constructs an element with values sampled uniformly modulo the modulus, recorded as already being in the
     * requested format (no transform is applied).
     *
     * @param dug the discrete uniform generator.
     * @param params the element parameters.
     * @param format the format recorded for the resulting element.
     */
    PolyImpl(DugType& dug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
     * @brief Constructs an element whose coefficients are sampled from the binary uniform distribution and converted
     * to the requested format.
     *
     * @param bug the binary uniform generator.
     * @param params the element parameters.
     * @param format the format of the resulting element.
     */
    PolyImpl(const BugType& bug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
     * @brief Constructs an element whose coefficients are sampled from the ternary uniform distribution and converted
     * to the requested format.
     *
     * @param tug the ternary uniform generator.
     * @param params the element parameters.
     * @param format the format of the resulting element.
     * @param h the Hamming weight (number of nonzero coefficients) for the sparse distribution; 0 samples every
     * coefficient uniformly.
     */
    PolyImpl(const TugType& tug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             uint32_t h = 0);

    /**
     * @brief Copy-converts a native polynomial when this instantiation is itself the native polynomial: the
     * parameters and values are copied and the element is converted to the requested format.
     *
     * @param rhs the native polynomial to copy.
     * @param format the format of the resulting element.
     */
    template <typename T = VecType>
    PolyImpl(const PolyNative& rhs, Format format,
             typename std::enable_if_t<std::is_same_v<T, NativeVector>, bool> = true)
        : format_{rhs.format_},
          params_{rhs.params_},
          values_{rhs.values_ ? std::make_unique<VecType>(*rhs.values_) : nullptr} {
        PolyImpl<VecType>::set_format(format);
    }

    /**
     * @brief Converts a native polynomial to this instantiation: new parameters are built from the cyclotomic order,
     * modulus and root of unity of rhs, every value is converted to Integer and the element is converted to the
     * requested format.
     *
     * @param rhs the native polynomial to convert.
     * @param format the format of the resulting element.
     */
    template <typename T = VecType>
    PolyImpl(const PolyNative& rhs, Format format,
             typename std::enable_if_t<!std::is_same_v<T, NativeVector>, bool> = true)
        : format_{rhs.get_format()} {
        auto c{rhs.get_params()->get_cyclotomic_order()};
        auto m{rhs.get_params()->get_modulus().convert_to_int()};
        auto r{rhs.get_params()->get_root_of_unity().convert_to_int()};
        params_ = std::make_shared<PolyImpl::Params>(c, m, r);

        const auto& v{rhs.get_values()};
        uint32_t vlen{params_->get_ring_dimension()};
        VecType tmp(vlen);
        tmp.set_modulus(params_->get_modulus());
        for (uint32_t i{0}; i < vlen; ++i)
            tmp[i] = Integer(v[i]);
        values_ = std::make_unique<VecType>(tmp);
        PolyImpl<VecType>::set_format(format);
    }

    PolyImpl(const PolyType& p) noexcept
        : format_{p.format_},
          params_{p.params_},
          values_{p.values_ ? std::make_unique<VecType>(*p.values_) : nullptr} {}

    PolyImpl(PolyType&& p) noexcept
        : format_{p.format_}, params_{std::move(p.params_)}, values_{std::move(p.values_)} {}

    PolyType& operator=(const PolyType& rhs) noexcept override;
    PolyType& operator=(PolyType&& rhs) noexcept override {
        format_ = std::move(rhs.format_);
        params_ = std::move(rhs.params_);
        values_ = std::move(rhs.values_);
        return *this;
    }
    /**
     * @brief Assigns signed coefficients reduced modulo the modulus (including the most negative values), used for
     * trapdoor sampling; missing trailing coefficients are zero and the format becomes COEFFICIENT.
     *
     * @param rhs the signed coefficients.
     * @return the resulting element.
     */
    PolyType& operator=(const std::vector<int32_t>& rhs);
    /**
     * @brief Assigns signed coefficients reduced modulo the modulus (including the most negative values), used for
     * trapdoor sampling; missing trailing coefficients are zero and the format becomes COEFFICIENT.
     *
     * @param rhs the signed coefficients.
     * @return the resulting element.
     */
    PolyType& operator=(const std::vector<int64_t>& rhs);
    /**
     * @brief Assigns unsigned coefficients as given (they are assumed to be less than the modulus); missing trailing
     * coefficients are zero and the format is kept.
     *
     * @param rhs the coefficients.
     * @return the resulting element.
     */
    PolyType& operator=(std::initializer_list<uint64_t> rhs) override;
    /**
     * @brief Assigns coefficients given as decimal strings, reduced modulo the modulus; missing trailing coefficients
     * are zero and the format is kept.
     *
     * @param rhs the coefficients as decimal strings.
     * @return the resulting element.
     */
    PolyType& operator=(std::initializer_list<std::string> rhs);
    /**
     * @brief Assigns the constant polynomial: every entry is set to val (allocating the values if needed) and the
     * format becomes EVALUATION.
     *
     * @param val the constant to assign.
     * @return the resulting element.
     */
    PolyType& operator=(uint64_t val);

    PolyNative decryption_crt_interpolate(PlaintextModulus ptm) const override;
    PolyNative to_native_poly() const final {
        uint32_t vlen{params_->get_ring_dimension()};
        auto c{params_->get_cyclotomic_order()};
        NativeInteger m{std::numeric_limits<BasicInteger>::max()};
        auto params{std::make_shared<PolyParamsImpl<NativeInteger>>(c, m, 1)};
        typename PolyImpl<VecType>::PolyNative tmp(params, format_, true);
        for (uint32_t i = 0; i < vlen; ++i)
            tmp[i] = NativeInteger((*values_)[i]);
        return tmp;
    }

    void set_values(const VecType& values, Format format) override;
    void set_values(VecType&& values, Format format) override;

    void set_values_to_zero() override {
        uint32_t r{params_->get_ring_dimension()};
        values_ = std::make_unique<VecType>(r, params_->get_modulus());
    }

    void set_values_to_max() override {
        uint32_t r{params_->get_ring_dimension()};
        auto max{params_->get_modulus() - Integer(1)};
        values_ = std::make_unique<VecType>(r, params_->get_modulus(), max);
    }

    inline Format get_format() const final {
        return format_;
    }

    void override_format(const Format f) final {
        format_ = f;
    }

    inline const std::shared_ptr<Params>& get_params() const {
        return params_;
    }

    inline const VecType& get_values() const final {
        if (values_ == nullptr)
            CIPHER_THROW("No values in PolyImpl");
        return *values_;
    }

    inline bool is_empty() const final {
        return values_ == nullptr;
    }

    inline Integer& at(uint32_t i) final {
        if (values_ == nullptr)
            CIPHER_THROW("No values in PolyImpl");
        return values_->at(i);
    }

    inline const Integer& at(uint32_t i) const final {
        if (values_ == nullptr)
            CIPHER_THROW("No values in PolyImpl");
        return values_->at(i);
    }

    inline Integer& operator[](uint32_t i) final {
        return (*values_)[i];
    }

    inline const Integer& operator[](uint32_t i) const final {
        return (*values_)[i];
    }

    /**
     * @brief Adds rhs entry-wise after checking that the ring dimension, modulus and format match.
     *
     * @param rhs the element to add.
     * @return the result of the addition.
     */
    PolyImpl plus_impl(const PolyImpl& rhs) const override {
        if (params_->get_ring_dimension() != rhs.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (params_->get_modulus() != rhs.params_->get_modulus())
            CIPHER_THROW("Modulus mismatch");
        if (format_ != rhs.format_)
            CIPHER_THROW("Format mismatch");
        auto tmp(*this);
        tmp.values_->mod_add_no_check_eq(*rhs.values_);
        return tmp;
    }
    /**
     * @brief Adds rhs entry-wise without checking the parameters.
     *
     * @param rhs the element to add.
     * @return the result of the addition.
     */
    PolyImpl plus_no_check(const PolyImpl& rhs) const {
        auto tmp(*this);
        tmp.values_->mod_add_no_check_eq(*rhs.values_);
        return tmp;
    }
    /**
     * @brief Adds rhs entry-wise in place without checking the parameters.
     *
     * @param rhs the element to add.
     * @return the resulting element.
     */
    PolyImpl& plus_no_check_eq(const PolyImpl& rhs) {
        values_->mod_add_no_check_eq(*rhs.values_);
        return *this;
    }
    PolyImpl& operator+=(const PolyImpl& element) override;

    /**
     * @brief Element addition reusing the storage of the rvalue operand a, after checking that the ring dimension,
     * modulus and format match.
     *
     * @param a the element to add to, consumed.
     * @param b the element to add.
     * @return a, holding the sum.
     */
    friend PolyImpl operator+(PolyImpl&& a, const PolyImpl& b) {
        if (a.params_->get_ring_dimension() != b.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (a.params_->get_modulus() != b.params_->get_modulus())
            CIPHER_THROW("Modulus mismatch");
        if (a.format_ != b.format_)
            CIPHER_THROW("Format mismatch");
        a.values_->mod_add_no_check_eq(*b.values_);
        return std::move(a);
    }
    /**
     * @brief Element addition reusing the storage of the rvalue operand b.
     *
     * @param a the element to add.
     * @param b the element to add to, consumed.
     * @return b, holding the sum.
     */
    friend PolyImpl operator+(const PolyImpl& a, PolyImpl&& b) {
        return std::move(b) + a;
    }
    /**
     * @brief Element addition of two rvalues, reusing the storage of a.
     *
     * @param a the element to add to, consumed.
     * @param b the element to add.
     * @return a, holding the sum.
     */
    friend PolyImpl operator+(PolyImpl&& a, PolyImpl&& b) {
        return std::move(a) + static_cast<const PolyImpl&>(b);
    }

    PolyImpl plus_impl(const Integer& element) const override;
    PolyImpl& operator+=(const Integer& element) override {
        return *this = this->plus_impl(element);  // don't change this
    }

    PolyImpl minus_impl(const PolyImpl& element) const override;
    PolyImpl& operator-=(const PolyImpl& element) override;

    PolyImpl minus_impl(const Integer& element) const override;
    PolyImpl& operator-=(const Integer& element) override {
        values_->mod_sub_eq(element);
        return *this;
    }

    PolyImpl Times(const PolyImpl& rhs) const override {
        if (params_->get_ring_dimension() != rhs.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (params_->get_modulus() != rhs.params_->get_modulus())
            CIPHER_THROW("Modulus mismatch");
        if (format_ != Format::EVALUATION || rhs.format_ != Format::EVALUATION)
            CIPHER_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        auto tmp(*this);
        tmp.values_->mod_mul_no_check_eq(*rhs.values_);
        return tmp;
    }
    /**
     * @brief Multiplies by rhs entry-wise (EVALUATION format) without checking the parameters.
     *
     * @param rhs the element to multiply by.
     * @return the result of the multiplication.
     */
    PolyImpl times_no_check(const PolyImpl& rhs) const {
        auto tmp(*this);
        tmp.values_->mod_mul_no_check_eq(*rhs.values_);
        return tmp;
    }
    /**
     * @brief Multiplies by rhs entry-wise (EVALUATION format) in place without checking the parameters.
     *
     * @param rhs the element to multiply by.
     * @return the resulting element.
     */
    PolyImpl& times_no_check_eq(const PolyImpl& rhs) {
        values_->mod_mul_no_check_eq(*rhs.values_);
        return *this;
    }

    /**
     * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand a, after
     * checking that the ring dimension, modulus and format match.
     *
     * @param a the element to multiply, consumed.
     * @param b the element to multiply by.
     * @return a, holding the product.
     */
    friend PolyImpl operator*(PolyImpl&& a, const PolyImpl& b) {
        if (a.params_->get_ring_dimension() != b.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (a.params_->get_modulus() != b.params_->get_modulus())
            CIPHER_THROW("Modulus mismatch");
        if (a.format_ != Format::EVALUATION || b.format_ != Format::EVALUATION)
            CIPHER_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        a.values_->mod_mul_no_check_eq(*b.values_);
        return std::move(a);
    }
    /**
     * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand b.
     *
     * @param a the element to multiply by.
     * @param b the element to multiply, consumed.
     * @return b, holding the product.
     */
    friend PolyImpl operator*(const PolyImpl& a, PolyImpl&& b) {
        return std::move(b) * a;
    }
    /**
     * @brief Element multiplication (EVALUATION format only) of two rvalues, reusing the storage of a.
     *
     * @param a the element to multiply, consumed.
     * @param b the element to multiply by.
     * @return a, holding the product.
     */
    friend PolyImpl operator*(PolyImpl&& a, PolyImpl&& b) {
        return std::move(a) * static_cast<const PolyImpl&>(b);
    }
    /**
     * @brief Element subtraction reusing the storage of the rvalue operand a, without checking the parameters.
     *
     * @param a the element to subtract from, consumed.
     * @param b the element to subtract.
     * @return a, holding the difference.
     */
    friend PolyImpl operator-(PolyImpl&& a, const PolyImpl& b) {
        a.values_->mod_sub_eq(*b.values_);
        return std::move(a);
    }
    PolyImpl& operator*=(const PolyImpl& rhs) override {
        if (params_->get_ring_dimension() != rhs.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (params_->get_modulus() != rhs.params_->get_modulus())
            CIPHER_THROW("Modulus mismatch");
        if (format_ != Format::EVALUATION || rhs.format_ != Format::EVALUATION)
            CIPHER_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        if (values_) {
            values_->mod_mul_no_check_eq(*rhs.values_);
            return *this;
        }
        values_ = std::make_unique<VecType>(params_->get_ring_dimension(), params_->get_modulus());
        return *this;
    }

    PolyImpl Times(const Integer& element) const override;
    PolyImpl& operator*=(const Integer& element) override {
        values_->mod_mul_eq(element);
        return *this;
    }

    PolyImpl Times(NativeInteger::SignedNativeInt element) const override;
#if CIPHER_NATIVE_INT != 64
    /**
     * @brief Scalar multiplication by a 64-bit signed integer, forwarded to Times(NativeInteger::SignedNativeInt);
     * provided for builds with 128-bit native integers.
     *
     * @param element the signed integer to multiply by.
     * @return the result of the multiplication.
     */
    inline PolyImpl Times(int64_t element) const {
        return this->Times(static_cast<NativeInteger::SignedNativeInt>(element));
    }
#endif

    PolyImpl multiply_and_round(const Integer& p, const Integer& q) const override;
    PolyImpl divide_and_round(const Integer& q) const override;

    PolyImpl negate() const override;
    inline PolyImpl operator-() const override {
        return PolyImpl(params_, format_, true) -= *this;
    }

    inline bool operator==(const PolyImpl& rhs) const override {
        return ((format_ == rhs.get_format()) && (params_->get_root_of_unity() == rhs.get_root_of_unity()) &&
                (this->get_values() == rhs.get_values()));
    }

    void add_il_element_one() override;
    PolyImpl automorphism_transform(uint32_t k) const override;
    PolyImpl automorphism_transform(uint32_t k, const std::vector<uint32_t>& vec) const override;
    PolyImpl multiplicative_inverse() const override;
    PolyImpl mod_by_two() const override;
    PolyImpl mod(const Integer& modulus) const override;

    void switch_modulus(const Integer& modulus, const Integer& root_of_unity_value, const Integer& modulus_arb,
                        const Integer& root_of_unity_arb) override;
    void lazy_switch_modulus(const Integer& modulus, const Integer& root_of_unity_value, const Integer& modulus_arb,
                             const Integer& root_of_unity_arb) override;

    /**
     * @brief Fused multiply-accumulate: *this += a * b (mod the modulus) entry-wise, without parameter validation;
     * all three operands must hold reduced values.
     *
     * @param a the element to multiply.
     * @param b the element to multiply a by.
     * @return the resulting element.
     */
    PolyImpl& mult_acc_eq_no_check(const PolyImpl& a, const PolyImpl& b) {
        values_->mult_acc_eq_no_check(*a.values_, *b.values_);
        return *this;
    }
    PolyImpl& mult_acc_eq_no_check(const PolyImpl& V, const Integer& I) override {
        values_->mult_acc_eq_no_check(*V.values_, I);
        return *this;
    }

    void switch_format(uint32_t thread_limit = 0) override;
    void make_sparse(uint32_t w_factor) override;
    bool inverse_exists() const override;
    double norm() const override;
    std::vector<PolyImpl> base_decompose(uint32_t base_bits, bool eval_mode_answer) const override;
    std::vector<PolyImpl> powers_of_base(uint32_t base_bits) const override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", values_));
        ar(::cereal::make_nvp("f", format_));
        ar(::cereal::make_nvp("p", params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", values_));
        ar(::cereal::make_nvp("f", format_));
        ar(::cereal::make_nvp("p", params_));
    }

    static const std::string get_element_name() {
        return "PolyImpl";
    }

    std::string serialized_object_name() const override {
        return "Poly";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  protected:
    Format format_{Format::EVALUATION};
    std::shared_ptr<Params> params_{nullptr};
    std::unique_ptr<VecType> values_{nullptr};
    /**
     * @brief Switches the format of an element over an arbitrary (non-power-of-two) cyclotomic ring with the
     * Bluestein-based transform, using the root of unity, big modulus and big root of unity of the parameters;
     * throws if the values are unallocated.
     */
    void arbitrary_switch_format();
};

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_STANDARD_POLY_H_
