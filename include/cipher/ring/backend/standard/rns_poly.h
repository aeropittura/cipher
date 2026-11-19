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

/*
  Represents integer lattice elements with double-CRT
 */

#ifndef CIPHER_RING_BACKEND_STANDARD_RNS_POLY_H_
#define CIPHER_RING_BACKEND_STANDARD_RNS_POLY_H_

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend/rns_poly_interface.h"
#include "cipher/ring/backend/standard/rns_params.h"
#include "cipher/ring/backend/standard/poly.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/parallel.h"

namespace cipher {

/**
 * @brief Default double-CRT polynomial: an element of the cyclotomic ring modulo a composite modulus
 * Q = q_1 * ... * q_l stored as one native polynomial (tower) per CRT modulus q_i, all towers in the same format.
 *
 * @tparam VecType the big-integer vector type of the interpolated single-modulus polynomial, e.g. BigVector.
 */
template <typename VecType>
class RnsPolyImpl final : public RnsPolyInterface<RnsPolyImpl<VecType>, VecType, NativeVector, PolyImpl> {
  public:
    using Vector = VecType;
    using Integer = typename VecType::Integer;
    using Params = RnsParams<Integer>;
    using PolyType = PolyImpl<NativeVector>;
    using PolyLargeType = PolyImpl<VecType>;
    using RnsPolyType = RnsPolyImpl<VecType>;
    using RnsPolyInterfaceType = RnsPolyInterface<RnsPolyImpl<VecType>, VecType, NativeVector, PolyImpl>;
    using Precomputations = typename RnsPolyInterfaceType::CrtBasisExtensionPrecomputations;
    using DggType = typename RnsPolyInterfaceType::DggType;
    using DugType = typename RnsPolyInterfaceType::DugType;
    using TugType = typename RnsPolyInterfaceType::TugType;
    using BugType = typename RnsPolyInterfaceType::BugType;

    using RnsPolyInterfaceType::approx_switch_crt_basis_threads;
    using RnsPolyInterfaceType::THREADS_CRT_BASIS_SWITCH;
    using RnsPolyInterfaceType::THREADS_SCALE_TO_POLY;

    RnsPolyImpl() = default;

    RnsPolyImpl(const RnsPolyType& e) noexcept : params_{e.params_}, format_{e.format_}, vectors_{e.vectors_} {}
    RnsPolyType& operator=(const RnsPolyType& rhs) noexcept override {
        params_ = rhs.params_;
        format_ = rhs.format_;
        vectors_ = rhs.vectors_;
        return *this;
    }

    /**
     * @brief Constructs the double-CRT representation of a big-integer polynomial: every coefficient of e is reduced
     * modulo each tower modulus of params; the format of e is kept.
     *
     * @param e the polynomial with coefficients modulo the composite modulus.
     * @param params the double-CRT parameters defining the towers.
     */
    RnsPolyImpl(const PolyLargeType& e, const std::shared_ptr<Params>& params) noexcept;
    /**
     * @brief Assigns a big-integer polynomial: the towers are rebuilt from this element's parameters and every
     * coefficient of rhs is reduced modulo each tower modulus; this element's format is kept. Reduction preserves
     * the polynomial only for coefficients, so rhs and this element must both be in COEFFICIENT format.
     *
     * @param rhs the polynomial with coefficients modulo the composite modulus.
     * @return the resulting element.
     */
    RnsPolyType& operator=(const PolyLargeType& rhs) noexcept;

    /**
     * @brief Constructs an element whose first tower is the native polynomial e and whose other towers are copies of e
     * switched (centered) to the remaining tower moduli of params; if e is empty, all towers are empty. The switch
     * preserves the polynomial only for coefficients, so e must be in COEFFICIENT format.
     *
     * @param e the native polynomial, with the modulus of the first tower.
     * @param params the double-CRT parameters defining the towers.
     */
    RnsPolyImpl(const PolyType& e, const std::shared_ptr<Params>& params) noexcept;
    /**
     * @brief Assigns a native polynomial: rhs becomes the first tower and copies of it switched (centered) to each
     * remaining tower modulus become the other towers; if rhs is empty, all towers are empty. The element takes the
     * format of rhs, which must be COEFFICIENT because the switch preserves the polynomial only for coefficients.
     *
     * @param rhs the native polynomial, with the modulus of the first tower.
     * @return the resulting element.
     */
    RnsPolyType& operator=(const PolyType& rhs) noexcept;

    RnsPolyImpl(RnsPolyType&& e) noexcept
        : params_{std::move(e.params_)}, format_{e.format_}, vectors_{std::move(e.vectors_)} {}
    RnsPolyType& operator=(RnsPolyType&& rhs) noexcept override {
        params_ = std::move(rhs.params_);
        format_ = std::move(rhs.format_);
        vectors_ = std::move(rhs.vectors_);
        return *this;
    }

    /**
     * @brief Constructs an element from its towers; the parameters (cyclotomic order and the tower moduli) and the
     * format are taken from the towers, which must all have the same cyclotomic order.
     *
     * @param elements the towers, one native polynomial per CRT modulus.
     */
    explicit RnsPolyImpl(const std::vector<PolyType>& elements);

    /**
     * @brief Constructs an element with one tower per modulus of params, in the given format.
     *
     * @param params the double-CRT parameters defining the towers.
     * @param format the format of the element (COEFFICIENT or EVALUATION).
     * @param initialize_element_to_zero if true, the towers are allocated and set to zero; otherwise their values are
     * left unallocated.
     */
    RnsPolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
                bool initialize_element_to_zero = false) noexcept
        : params_{params}, format_{format} {
        vectors_.reserve(params_->get_params().size());
        for (const auto& p : params_->get_params())
            vectors_.emplace_back(p, format_, initialize_element_to_zero);
    }

    /**
     * @brief Constructs an element with coefficients sampled from a discrete Gaussian distribution: one integer vector
     * is sampled and reduced modulo each tower modulus, then the towers are converted to the requested format.
     *
     * @param dgg the discrete Gaussian generator.
     * @param p the double-CRT parameters defining the towers.
     * @param f the format of the resulting element.
     */
    RnsPolyImpl(const DggType& dgg, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    /**
     * @brief Constructs an element with binary uniform coefficients: one polynomial is sampled with the first tower's
     * parameters and switched to the modulus of every other tower, then the towers are converted to the requested
     * format.
     *
     * @param bug the binary uniform generator.
     * @param p the double-CRT parameters defining the towers.
     * @param f the format of the resulting element.
     */
    RnsPolyImpl(const BugType& bug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    /**
     * @brief Constructs an element with ternary uniform coefficients: one integer vector with entries in {-1, 0, 1} is
     * sampled and reduced modulo each tower modulus, then the towers are converted to the requested format.
     *
     * @param tug the ternary uniform generator.
     * @param p the double-CRT parameters defining the towers.
     * @param f the format of the resulting element.
     * @param h the Hamming weight (number of nonzero coefficients) for the sparse distribution; 0 samples every
     * coefficient uniformly.
     */
    RnsPolyImpl(const TugType& tug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION, uint32_t h = 0);
    /**
     * @brief Constructs an element with uniformly random coefficients: each tower is sampled independently and
     * uniformly modulo its own modulus and is recorded as already being in the requested format (no transform).
     *
     * @param dug the discrete uniform generator.
     * @param p the double-CRT parameters defining the towers.
     * @param f the format recorded for the resulting element.
     */
    RnsPolyImpl(DugType& dug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);

    RnsPolyType& operator=(std::initializer_list<uint64_t> rhs) noexcept override;
    /**
     * @brief Assigns the constant val to every entry of every tower; the element and each tower become EVALUATION, as
     * in PolyImpl::operator=(uint64_t).
     *
     * @param val the value to assign.
     * @return the resulting element.
     */
    RnsPolyType& operator=(uint64_t val) noexcept;
    /**
     * @brief Assigns signed coefficients (used for trapdoor sampling): every tower receives the coefficients reduced
     * modulo its own modulus, missing trailing coefficients are zero and the format becomes COEFFICIENT.
     *
     * @param rhs the signed coefficients.
     * @return the resulting element.
     */
    RnsPolyType& operator=(const std::vector<int64_t>& rhs) noexcept;
    /**
     * @brief Assigns signed coefficients (used for trapdoor sampling): every tower receives the coefficients reduced
     * modulo its own modulus, missing trailing coefficients are zero and the format becomes COEFFICIENT.
     *
     * @param rhs the signed coefficients.
     * @return the resulting element.
     */
    RnsPolyType& operator=(const std::vector<int32_t>& rhs) noexcept;
    /**
     * @brief Assigns coefficients given as decimal strings to every tower, as given (without modular reduction);
     * missing trailing coefficients are zero. Towers with unallocated values are allocated first.
     *
     * @param rhs the coefficients as decimal strings.
     * @return the resulting element.
     */
    RnsPolyType& operator=(std::initializer_list<std::string> rhs) noexcept;

    RnsPolyType clone_with_noise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const override;
    /**
     * @brief Makes a copy holding only the towers start_tower to end_tower (inclusive), with parameters restricted to
     * those moduli and the same format.
     *
     * @param start_tower the index of the first tower to copy.
     * @param end_tower the index of the last tower to copy.
     * @return the new element.
     */
    RnsPolyType clone_towers(uint32_t start_tower, uint32_t end_tower) const;

    bool operator==(const RnsPolyType& rhs) const override;

    RnsPolyType& operator+=(const RnsPolyType& rhs) override;
    RnsPolyType& operator+=(const Integer& rhs) override;
    /**
     * @brief Adds a native integer to every tower in place: to the first coefficient of each tower in COEFFICIENT
     * format, or to all entries of each tower in EVALUATION format.
     *
     * @param rhs the native integer to add.
     * @return the resulting element.
     */
    RnsPolyType& operator+=(const NativeInteger& rhs) override;
    RnsPolyType& operator-=(const RnsPolyType& rhs) override;
    RnsPolyType& operator-=(const Integer& rhs) override;
    /**
     * @brief Subtracts a native integer from all entries of every tower in place.
     *
     * @param rhs the native integer to subtract.
     * @return the resulting element.
     */
    RnsPolyType& operator-=(const NativeInteger& rhs) override;
    RnsPolyType& operator*=(const RnsPolyType& rhs) override {
        size_t size{vectors_.size()};
        if (size > rhs.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot multiply");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            vectors_[i] *= rhs.vectors_[i];
        return *this;
    }
    RnsPolyType& operator*=(const Integer& rhs) override;
    /**
     * @brief Multiplies all entries of every tower by a native integer in place.
     *
     * @param rhs the native integer to multiply by.
     * @return the resulting element.
     */
    RnsPolyType& operator*=(const NativeInteger& rhs) override;

    RnsPolyType negate() const override;
    RnsPolyType operator-() const override;

    std::vector<RnsPolyType> base_decompose(uint32_t base_bits, bool eval_mode_answer) const override;
    std::vector<RnsPolyType> powers_of_base(uint32_t base_bits) const override;
    /**
     * @brief Decomposes the element for key switching: element i of the result holds the residue of this element
     * modulo q_i, as an integer in [0, q_i), represented in every tower; when base_bits > 0 each residue is further
     * split into digits of base_bits bits, one element per digit. The result is in EVALUATION format.
     *
     * @param base_bits the number of bits of the digit base for the additional decomposition; 0 for none.
     * @return the vector of decomposed elements.
     */
    std::vector<RnsPolyType> crt_decompose(uint32_t base_bits) const;

    RnsPolyType automorphism_transform(uint32_t i) const override;
    RnsPolyType automorphism_transform(uint32_t i, const std::vector<uint32_t>& vec) const override;

    RnsPolyType plus_impl(const Integer& rhs) const override;
    /**
     * @brief Adds an integer given in CRT form (one value per tower, converted to a native integer) to each tower: to
     * the first coefficient in COEFFICIENT format, or to all entries in EVALUATION format.
     *
     * @param rhs the CRT representation of the integer to add, in tower order.
     * @return the result of the addition.
     */
    RnsPolyType plus_impl(const std::vector<Integer>& rhs) const;
    RnsPolyType plus_impl(const RnsPolyType& rhs) const override {
        if (params_->get_ring_dimension() != rhs.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (format_ != rhs.format_)
            CIPHER_THROW("Format mismatch");
        size_t size{vectors_.size()};
        if (size != rhs.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot add");
        if (vectors_[0].get_modulus() != rhs.vectors_[0].get_modulus())
            CIPHER_THROW("Modulus mismatch");
        RnsPolyType tmp(params_, format_);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.vectors_[i] = vectors_[i].plus_no_check(rhs.vectors_[i]);
        return tmp;
    }

    /**
     * @brief Element addition reusing the storage of the rvalue operand a: after checking the ring dimension, format,
     * number of towers and modulus, the towers of b are added into those of a.
     *
     * @param a the element to add to, consumed.
     * @param b the element to add.
     * @return a, holding the sum.
     */
    friend RnsPolyType operator+(RnsPolyType&& a, const RnsPolyType& b) {
        if (a.params_->get_ring_dimension() != b.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (a.format_ != b.format_)
            CIPHER_THROW("Format mismatch");
        size_t size{a.vectors_.size()};
        if (size != b.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot add");
        if (a.vectors_[0].get_modulus() != b.vectors_[0].get_modulus())
            CIPHER_THROW("Modulus mismatch");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            a.vectors_[i].plus_no_check_eq(b.vectors_[i]);
        return std::move(a);
    }
    /**
     * @brief Element addition reusing the storage of the rvalue operand b.
     *
     * @param a the element to add.
     * @param b the element to add to, consumed.
     * @return b, holding the sum.
     */
    friend RnsPolyType operator+(const RnsPolyType& a, RnsPolyType&& b) {
        return std::move(b) + a;
    }
    /**
     * @brief Element addition of two rvalues, reusing the storage of a.
     *
     * @param a the element to add to, consumed.
     * @param b the element to add.
     * @return a, holding the sum.
     */
    friend RnsPolyType operator+(RnsPolyType&& a, RnsPolyType&& b) {
        return std::move(a) + static_cast<const RnsPolyType&>(b);
    }

    RnsPolyType minus_impl(const RnsPolyType& rhs) const override;

    /**
     * @brief Element subtraction reusing the storage of the rvalue operand a; only the number of towers is checked.
     *
     * @param a the element to subtract from, consumed.
     * @param b the element to subtract.
     * @return a, holding the difference.
     */
    friend RnsPolyType operator-(RnsPolyType&& a, const RnsPolyType& b) {
        size_t size{a.vectors_.size()};
        if (size != b.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot subtract");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            a.vectors_[i] -= b.vectors_[i];
        return std::move(a);
    }
    RnsPolyType minus_impl(const Integer& rhs) const override;
    /**
     * @brief Subtracts an integer given in CRT form (one value per tower, converted to a native integer) from all
     * entries of each tower.
     *
     * @param rhs the CRT representation of the integer to subtract, in tower order.
     * @return the result of the subtraction.
     */
    RnsPolyType minus_impl(const std::vector<Integer>& rhs) const;

    RnsPolyType Times(const RnsPolyType& rhs) const override {
        if (params_->get_ring_dimension() != rhs.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (format_ != Format::EVALUATION || rhs.format_ != Format::EVALUATION)
            CIPHER_THROW("operator* for RnsPolyImpl supported only in Format::EVALUATION");
        size_t size{vectors_.size()};
        if (size != rhs.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot multiply");
        if (vectors_[0].get_modulus() != rhs.vectors_[0].get_modulus())
            CIPHER_THROW("Modulus mismatch");
        RnsPolyType tmp(params_, format_);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.vectors_[i] = vectors_[i].times_no_check(rhs.vectors_[i]);
        return tmp;
    }

    /**
     * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand a: after
     * checking the ring dimension, format, number of towers and modulus, the towers of a are multiplied by those of b.
     *
     * @param a the element to multiply, consumed.
     * @param b the element to multiply by.
     * @return a, holding the product.
     */
    friend RnsPolyType operator*(RnsPolyType&& a, const RnsPolyType& b) {
        if (a.params_->get_ring_dimension() != b.params_->get_ring_dimension())
            CIPHER_THROW("RingDimension mismatch");
        if (a.format_ != Format::EVALUATION || b.format_ != Format::EVALUATION)
            CIPHER_THROW("operator* for RnsPolyImpl supported only in Format::EVALUATION");
        size_t size{a.vectors_.size()};
        if (size != b.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot multiply");
        if (a.vectors_[0].get_modulus() != b.vectors_[0].get_modulus())
            CIPHER_THROW("Modulus mismatch");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            a.vectors_[i].times_no_check_eq(b.vectors_[i]);
        return std::move(a);
    }
    /**
     * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand b.
     *
     * @param a the element to multiply by.
     * @param b the element to multiply, consumed.
     * @return b, holding the product.
     */
    friend RnsPolyType operator*(const RnsPolyType& a, RnsPolyType&& b) {
        return std::move(b) * a;
    }
    /**
     * @brief Element multiplication (EVALUATION format only) of two rvalues, reusing the storage of a.
     *
     * @param a the element to multiply, consumed.
     * @param b the element to multiply by.
     * @return a, holding the product.
     */
    friend RnsPolyType operator*(RnsPolyType&& a, RnsPolyType&& b) {
        return std::move(a) * static_cast<const RnsPolyType&>(b);
    }
    RnsPolyType Times(const Integer& rhs) const override;
    /**
     * @brief Multiplies all entries of each tower by an integer given in CRT form (one value per tower, converted to a
     * native integer).
     *
     * @param rhs the CRT representation of the integer to multiply by, in tower order.
     * @return the result of the multiplication.
     */
    RnsPolyType Times(const std::vector<Integer>& rhs) const;
    RnsPolyType Times(NativeInteger::SignedNativeInt rhs) const override;
#if CIPHER_NATIVE_INT != 64
    /**
     * @brief Scalar multiplication by a 64-bit signed integer, forwarded to Times(NativeInteger::SignedNativeInt);
     * provided for builds with 128-bit native integers.
     *
     * @param rhs the signed integer to multiply by.
     * @return the result of the multiplication.
     */
    RnsPolyType Times(int64_t rhs) const {
        return Times(static_cast<NativeInteger::SignedNativeInt>(rhs));
    }
#endif
    /**
     * @brief Multiplies tower i by rhs[i]; throws if the number of towers differs from the size of rhs.
     *
     * @param rhs the CRT representation of the integer to multiply by, in tower order.
     * @return the result of the multiplication.
     */
    RnsPolyType Times(const std::vector<NativeInteger>& rhs) const;
    /**
     * @brief Multiplies tower i by rhs[i] for the first min(number of towers, rhs.size()) towers without a size check;
     * any remaining towers of the result are left unallocated.
     *
     * @param rhs the CRT representation of the integer to multiply by, in tower order.
     * @return the result of the multiplication.
     */
    RnsPolyType times_no_check(const std::vector<NativeInteger>& rhs) const;

    /**
     * @brief Fused multiply-accumulate: *this += a * b (mod each tower modulus), without
     * parameter validation. All three operands must hold reduced values (see the
     * NativeVectorT overload). Saves the full-element temporary of *this += a * b.
     *
     * @param a the element to multiply.
     * @param b the element to multiply a by.
     * @return the resulting element.
     */
    RnsPolyType& mult_acc_eq_no_check(const RnsPolyType& a, const RnsPolyType& b) {
        size_t size{vectors_.size()};
        if (size > a.vectors_.size() || size > b.vectors_.size())
            CIPHER_THROW("tower size mismatch; cannot multiply-accumulate");
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(size))
        for (size_t i = 0; i < size; ++i)
            vectors_[i].mult_acc_eq_no_check(a.vectors_[i], b.vectors_[i]);
        return *this;
    }

    RnsPolyType multiplicative_inverse() const override;
    bool inverse_exists() const override;
    bool is_empty() const override;

    void set_values_to_zero() override;
    void add_il_element_one() override;
    void drop_last_element() override;
    void drop_last_elements(size_t i) override;
    void drop_last_element_and_scale(const std::vector<NativeInteger>& ql_inv_modq) override;

    void mod_reduce(const NativeInteger& t, const std::vector<NativeInteger>& t_modq_precon,
                    const NativeInteger& negt_inv_modq, const NativeInteger& negt_inv_modq_precon,
                    const std::vector<NativeInteger>& ql_inv_modq,
                    const std::vector<NativeInteger>& ql_inv_modq_precon) override;

    PolyLargeType crt_interpolate() const override;
    PolyType decryption_crt_interpolate(PlaintextModulus ptm) const override;
    PolyType to_native_poly() const override;
    PolyLargeType crt_interpolate_index(uint32_t i) const override;
    Integer get_working_modulus() const override;

    void set_values_mod_switch(const RnsPolyType& element, const NativeInteger& modulus) override;

    /**
     * @brief Builds the parameters of the extended basis {Q, P}: the moduli and roots of unity of this element's
     * current towers followed by those of params_p, with this element's cyclotomic order.
     *
     * @param params_p element parameters for the moduli to append to the current towers.
     * @return element parameters of the extended basis.
     */
    std::shared_ptr<Params> get_extended_crt_basis(const std::shared_ptr<Params>& params_p) const override;

    /**
     * @brief Scales the element by Q/t in place (BFV plaintext encoding); see RnsPolyInterface::times_qovert. Every
     * coefficient m of tower i becomes [[m*(-Q)]_t * t^{-1}]_{q_i}.
     *
     * @param params_q element parameters of the basis Q; not used, the current towers define the basis.
     * @param t_inv_modq precomputed values for [t^{-1}]_{q_i}; throws if fewer than the number of towers.
     * @param t the plaintext modulus.
     * @param neg_q_modt precomputed value for [-Q]_t.
     * @param neg_q_modt_precon NTL-specific precomputation for neg_q_modt.
     */
    void times_qovert(const std::shared_ptr<Params>& params_q, const std::vector<NativeInteger>& t_inv_modq,
                      const NativeInteger& t, const NativeInteger& neg_q_modt,
                      const NativeInteger& neg_q_modt_precon) override;

    /**
     * @brief Approximate CRT basis switching {X}_Q -> {X + alpha*Q}_P for a small alpha; see
     * RnsPolyInterface::approx_switch_crt_basis for the algorithm.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}.
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
     * @param q_hat_inv_modq_precon NTL-specific precomputations for q_hat_inv_modq.
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}.
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j.
     * @return the representation of X + alpha*Q in the basis P.
     */
    RnsPolyType approx_switch_crt_basis(const std::shared_ptr<Params>& params_q,
                                        const std::shared_ptr<Params>& params_p,
                                        const std::vector<NativeInteger>& q_hat_inv_modq,
                                        const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                        const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                        const std::vector<DoubleNativeInt>& modp_barrett_mu) const override;

    /**
     * @brief Approximate modulus raising in place, {X}_Q -> {X + alpha*Q}_{Q,P}: the P towers are computed with
     * approx_switch_crt_basis and appended; see RnsPolyInterface::approx_mod_up.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}.
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param params_qp parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}.
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
     * @param q_hat_inv_modq_precon NTL-specific precomputations for q_hat_inv_modq.
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}.
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j.
     */
    void approx_mod_up(const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
                       const std::shared_ptr<Params>& params_qp, const std::vector<NativeInteger>& q_hat_inv_modq,
                       const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                       const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                       const std::vector<DoubleNativeInt>& modp_barrett_mu) override;

    /**
     * @brief Approximate modulus reduction {X}_{Q,P} -> {approximately X/P}_Q (with the multiplication by t used by
     * BGV); see RnsPolyInterface::approx_mod_down for the algorithm.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}.
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param P_inv_modq precomputed values for [P^{-1}]_{q_i}.
     * @param p_inv_modq_precon NTL-specific precomputations for P_inv_modq.
     * @param p_hat_inv_modp precomputed values for [(P/p_j)^{-1}]_{p_j}.
     * @param p_hat_inv_modp_precon NTL-specific precomputations for p_hat_inv_modp.
     * @param p_hat_modq precomputed values for [P/p_j]_{q_i}.
     * @param modq_barrett_mu 128-bit Barrett reduction precomputed values for q_i.
     * @param t_inv_modp precomputed values for [t^{-1}]_{p_j} (BGV only).
     * @param t_inv_modp_precon NTL-specific precomputations for t_inv_modp.
     * @param t the plaintext modulus (BGV only).
     * @param t_modq_precon NTL-specific precomputations for t modulo q_i.
     * @return the representation of approximately X/P in the basis Q.
     */
    RnsPolyType approx_mod_down(const std::shared_ptr<Params>& params_q, const std::shared_ptr<Params>& params_p,
                                const std::vector<NativeInteger>& P_inv_modq,
                                const std::vector<NativeInteger>& p_inv_modq_precon,
                                const std::vector<NativeInteger>& p_hat_inv_modp,
                                const std::vector<NativeInteger>& p_hat_inv_modp_precon,
                                const std::vector<std::vector<NativeInteger>>& p_hat_modq,
                                const std::vector<DoubleNativeInt>& modq_barrett_mu,
                                const std::vector<NativeInteger>& t_inv_modp,
                                const std::vector<NativeInteger>& t_inv_modp_precon, const NativeInteger& t,
                                const std::vector<NativeInteger>& t_modq_precon) const override;

    /**
     * @brief Exact CRT basis switching {X}_Q -> {X}_P; see RnsPolyInterface::switch_crt_basis for the algorithm.
     *
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
     * @param q_hat_inv_modq_precon NTL-specific precomputations for q_hat_inv_modq.
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}.
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}.
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j.
     * @param q_inv precomputed values for 1/q_i.
     * @return the representation of X in the basis P.
     */
    RnsPolyType switch_crt_basis(const std::shared_ptr<Params>& params_p,
                                 const std::vector<NativeInteger>& q_hat_inv_modq,
                                 const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                 const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                 const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                 const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                 const std::vector<double>& q_inv) const override;

    /**
     * @brief Exact modulus raising in place, {X}_Q -> {X}_{Q,P}: the P towers are computed with switch_crt_basis and
     * appended; see RnsPolyInterface::expand_crt_basis.
     *
     * @param params_qp parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}.
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
     * @param q_hat_inv_modq_precon NTL-specific precomputations for q_hat_inv_modq.
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}.
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}.
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j.
     * @param q_inv precomputed values for 1/q_i.
     * @param result_format the format of the resulting element.
     */
    void expand_crt_basis(const std::shared_ptr<Params>& params_qp, const std::shared_ptr<Params>& params_p,
                          const std::vector<NativeInteger>& q_hat_inv_modq,
                          const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                          const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                          const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                          const std::vector<DoubleNativeInt>& modp_barrett_mu, const std::vector<double>& q_inv,
                          Format result_format) override;

    /**
     * @brief Exact modulus raising in place with the new towers first, {X}_Q -> {X}_{P,Q}; see
     * RnsPolyInterface::expand_crt_basis_reverse_order.
     *
     * @param params_qp parameters for the CRT basis {p_1,...,p_k,q_1,...,q_l}.
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param q_hat_inv_modq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
     * @param q_hat_inv_modq_precon NTL-specific precomputations for q_hat_inv_modq.
     * @param q_hat_modp precomputed values for [Q/q_i]_{p_j}.
     * @param alpha_q_modp precomputed values for [alpha*Q]_{p_j}.
     * @param modp_barrett_mu 128-bit Barrett reduction precomputed values for p_j.
     * @param q_inv precomputed values for 1/q_i.
     * @param result_format the format of the resulting element.
     */
    void expand_crt_basis_reverse_order(const std::shared_ptr<Params>& params_qp,
                                        const std::shared_ptr<Params>& params_p,
                                        const std::vector<NativeInteger>& q_hat_inv_modq,
                                        const std::vector<NativeInteger>& q_hat_inv_modq_precon,
                                        const std::vector<std::vector<NativeInteger>>& q_hat_modp,
                                        const std::vector<std::vector<NativeInteger>>& alpha_q_modp,
                                        const std::vector<DoubleNativeInt>& modp_barrett_mu,
                                        const std::vector<double>& q_inv, Format result_format) override;

    /**
     * @brief Scales the element by P_l/Q and expands it to the basis {Q_l, P_l} in place: approx_switch_crt_basis to
     * P_l with the folded constants, then switch_crt_basis back to Q_l; see RnsPolyInterface::fast_expand_crt_basis_plover_q.
     *
     * @param precomputed the precomputed constants for the bases Q, Q_l and P_l.
     */
    void fast_expand_crt_basis_plover_q(const Precomputations& precomputed) override;

    /**
     * @brief Multiplies the element by Q/Q_l and expands it from the basis Q_l to the full basis Q in place; the towers
     * for the moduli not in Q_l are zero. See RnsPolyInterface::expand_crt_basis_ql_hat.
     *
     * @param params_q element parameters of the full basis Q.
     * @param ql_hat_modq precomputed values for [Q/Q_l]_{q_i} for the towers in Q_l.
     * @param ql_hat_modq_precon NTL-specific precomputations for ql_hat_modq.
     * @param size_q the number of towers in the full basis Q.
     */
    void expand_crt_basis_ql_hat(const std::shared_ptr<Params>& params_q, const std::vector<NativeInteger>& ql_hat_modq,
                                 const std::vector<NativeInteger>& ql_hat_modq_precon, const uint32_t size_q) override;

    PolyType scale_and_round(const NativeInteger& t, const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt,
                             const std::vector<NativeInteger>& t_q_hat_inv_modq_divq_modt_precon,
                             const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt,
                             const std::vector<NativeInteger>& t_q_hat_inv_modq_b_divq_modt_precon,
                             const std::vector<double>& t_q_hat_inv_modq_divq_frac,
                             const std::vector<double>& t_q_hat_inv_modq_b_divq_frac) const override;

    /**
     * @brief Approximate scale and round {X}_{Q,P} -> {approximately t/Q * X}_P; see
     * RnsPolyInterface::approx_scale_and_round for the algorithm.
     *
     * @param params_p parameters for the CRT basis {p_1,...,p_k}.
     * @param t_ps_hat_inv_mods_divs_modp precomputed values for [floor(t*P*[(S/s_k)^{-1}]_{s_k}/s_k)]_{p_j}, S = {Q,P}.
     * @param modp_barret_mu 128-bit Barrett reduction precomputed values for p_j.
     * @return the representation of approximately t/Q * X in the basis P.
     */
    RnsPolyType approx_scale_and_round(const std::shared_ptr<Params>& params_p,
                                       const std::vector<std::vector<NativeInteger>>& t_ps_hat_inv_mods_divs_modp,
                                       const std::vector<DoubleNativeInt>& modp_barret_mu) const override;

    /**
     * @brief Exact scale and round {X}_{I,O} -> {round(t/I * X)}_O, where O is the output basis (P or Q) and I is
     * the other one; see RnsPolyInterface::scale_and_round for the algorithm.
     *
     * @param params_output parameters for the output CRT basis {o_1,...,o_k}.
     * @param t_os_hat_inv_mods_divs_modo precomputed values for [floor(t*O*[(S/s_k)^{-1}]_{s_k}/s_k)]_{o_j}, S = {I,O}.
     * @param t_os_hat_inv_mods_divs_frac precomputed fractional parts of t*O*[(S/s_k)^{-1}]_{s_k}/s_k.
     * @param modo_barret_mu 128-bit Barrett reduction precomputed values for o_j.
     * @return the representation of round(t/I * X) in the basis O.
     */
    RnsPolyType scale_and_round(const std::shared_ptr<Params>& params_output,
                                const std::vector<std::vector<NativeInteger>>& t_os_hat_inv_mods_divs_modo,
                                const std::vector<double>& t_os_hat_inv_mods_divs_frac,
                                const std::vector<DoubleNativeInt>& modo_barret_mu) const override;

    PolyType scale_and_round(const std::vector<NativeInteger>& moduli_q, const NativeInteger& t,
                             const NativeInteger& tgamma, const std::vector<NativeInteger>& tgamma_q_hat_modq,
                             const std::vector<NativeInteger>& tgamma_q_hat_modq_precon,
                             const std::vector<NativeInteger>& neg_invq_modtgamma,
                             const std::vector<NativeInteger>& neg_invq_modtgamma_precon) const override;

    /**
     * @brief Computes round(X/p) in place for an element in the basis {Q, p} (BFV EXTENDED encryption): the last
     * tower, modulo p, is switched (centered) to each q_i and subtracted, the difference is multiplied by
     * [p^{-1}]_{q_i}, the p tower is dropped and the parameters become params_q.
     *
     * @param params_q parameters for the CRT basis {q_1,...,q_l}.
     * @param p_inv_modq precomputed values for [p^{-1}]_{q_i}.
     */
    void scale_and_round_p_over_q(const std::shared_ptr<Params>& params_q,
                                  const std::vector<NativeInteger>& p_inv_modq) override;

    /**
     * @brief Expands the element from the basis Q to {Q, Bsk, mtilde} in place using the Montgomery-style fast base
     * conversion of the BEHZ BFV variant; see RnsPolyInterface::fast_base_convq_to_bsk_montgomery.
     *
     * @param params_q_bsk parameters for the CRT basis {Q, Bsk}.
     * @param moduli_q the moduli {q_1,...,q_l}.
     * @param moduli_bsk the moduli {bsk_1,...,bsk_k} of the auxiliary basis.
     * @param modbsk_barrett_mu 128-bit Barrett reduction precomputed values for bsk_j.
     * @param mtilde_q_hat_inv_modq precomputed values for [mtilde*(Q/q_i)^{-1}]_{q_i}.
     * @param mtilde_q_hat_inv_modq_precon NTL-specific precomputations for mtilde_q_hat_inv_modq.
     * @param q_hat_modbsk precomputed values for [Q/q_i]_{bsk_j}.
     * @param q_hat_modmtilde precomputed values for [Q/q_i]_{mtilde}.
     * @param q_modbsk precomputed values for [Q]_{bsk_j}.
     * @param q_modbsk_precon NTL-specific precomputations for q_modbsk.
     * @param neg_q_inv_modmtilde precomputed value for [-Q^{-1}]_{mtilde}.
     * @param mtilde_inv_modbsk precomputed values for [mtilde^{-1}]_{bsk_j}.
     * @param mtilde_inv_modbsk_precon NTL-specific precomputations for mtilde_inv_modbsk.
     */
    void fast_base_convq_to_bsk_montgomery(
            const std::shared_ptr<Params>& params_q_bsk, const std::vector<NativeInteger>& moduli_q,
            const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
            const std::vector<NativeInteger>& mtilde_q_hat_inv_modq,
            const std::vector<NativeInteger>& mtilde_q_hat_inv_modq_precon,
            const std::vector<std::vector<NativeInteger>>& q_hat_modbsk, const std::vector<uint64_t>& q_hat_modmtilde,
            const std::vector<NativeInteger>& q_modbsk, const std::vector<NativeInteger>& q_modbsk_precon,
            uint64_t neg_q_inv_modmtilde, const std::vector<NativeInteger>& mtilde_inv_modbsk,
            const std::vector<NativeInteger>& mtilde_inv_modbsk_precon) override;

    void fast_rns_floorq(const NativeInteger& t, const std::vector<NativeInteger>& moduli_q,
                         const std::vector<NativeInteger>& moduli_bsk,
                         const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
                         const std::vector<NativeInteger>& t_q_hat_inv_modq,
                         const std::vector<NativeInteger>& t_q_hat_inv_modq_precon,
                         const std::vector<std::vector<NativeInteger>>& q_hat_modbsk,
                         const std::vector<std::vector<NativeInteger>>& q_inv_modbsk,
                         const std::vector<NativeInteger>& t_q_inv_modbsk,
                         const std::vector<NativeInteger>& t_q_inv_modbsk_precon) override;

    /**
     * @brief Converts the element from the basis {Q, Bsk} back to Q in place with the Shenoy-Kumaresan method: the Q
     * towers are recomputed from the Bsk towers, which are then dropped; see RnsPolyInterface::fast_base_conv_sk.
     *
     * @param params_q parameters for the CRT basis Q.
     * @param modq_barrett_mu 128-bit Barrett reduction precomputed values for q_i.
     * @param moduli_bsk the moduli {bsk_1,...,bsk_k} of the auxiliary basis.
     * @param modbsk_barrett_mu 128-bit Barrett reduction precomputed values for bsk_j.
     * @param b_hat_inv_modb precomputed values for [(B/b_j)^{-1}]_{b_j}.
     * @param b_hat_inv_modb_precon NTL-specific precomputations for b_hat_inv_modb.
     * @param b_hat_modmsk precomputed values for [B/b_j]_{msk}.
     * @param b_inv_modmsk precomputed value for [B^{-1}]_{msk}.
     * @param b_inv_modmsk_precon NTL-specific precomputation for b_inv_modmsk.
     * @param b_hat_modq precomputed values for [B/b_j]_{q_i}.
     * @param b_modq precomputed values for [B]_{q_i}.
     * @param b_modq_precon NTL-specific precomputations for b_modq.
     */
    void fast_base_conv_sk(
            const std::shared_ptr<Params>& params_q, const std::vector<DoubleNativeInt>& modq_barrett_mu,
            const std::vector<NativeInteger>& moduli_bsk, const std::vector<DoubleNativeInt>& modbsk_barrett_mu,
            const std::vector<NativeInteger>& b_hat_inv_modb, const std::vector<NativeInteger>& b_hat_inv_modb_precon,
            const std::vector<NativeInteger>& b_hat_modmsk, const NativeInteger& b_inv_modmsk,
            const NativeInteger& b_inv_modmsk_precon, const std::vector<std::vector<NativeInteger>>& b_hat_modq,
            const std::vector<NativeInteger>& b_modq, const std::vector<NativeInteger>& b_modq_precon) override;

    void switch_format(uint32_t thread_limit = 0) override;

    /**
     * @brief Switches the tower at index to a new modulus and root of unity (values converted to native integers and
     * switched with centering). The element moves to its own copy of the parameters, updated with the new tower and
     * composite modulus, so other elements sharing the original parameters are unaffected.
     *
     * @param index the index of the tower; throws if out of range.
     * @param modulus the new modulus of the tower.
     * @param root_of_unity_value the root of unity for the new modulus.
     */
    void switch_modulus_at_index(size_t index, const Integer& modulus, const Integer& root_of_unity_value) override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", vectors_));
        ar(::cereal::make_nvp("f", format_));
        ar(::cereal::make_nvp("p", params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", vectors_));
        ar(::cereal::make_nvp("f", format_));
        ar(::cereal::make_nvp("p", params_));
    }

    static const std::string get_element_name() {
        return "DCRTPolyImpl";
    }

    std::string serialized_object_name() const override {
        return "DCRTPoly";
    }

    static uint32_t serialized_version() {
        return 1;
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

    const std::vector<PolyType>& get_all_elements() const {
        return vectors_;
    }

    std::vector<PolyType>& get_all_elements() {
        return vectors_;
    }

    void set_element_at_index(uint32_t index, const PolyType& element) {
        vectors_[index] = element;
    }

    void set_element_at_index(uint32_t index, PolyType&& element) {
        vectors_[index] = std::move(element);
    }

  protected:
    std::shared_ptr<Params> params_{std::make_shared<RnsPolyImpl::Params>()};
    Format format_{Format::EVALUATION};
    std::vector<PolyType> vectors_;
};

}  // namespace cipher

#endif  // CIPHER_RING_BACKEND_STANDARD_RNS_POLY_H_
