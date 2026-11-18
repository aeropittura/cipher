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

#include "cipher/fhe/rns/leveled_she.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "cipher/fhe/context.h"

namespace cipher {

namespace {
inline ScalingTechnique get_scaling_technique(const CiphertextImpl<RnsPoly>& ct) {
    return static_cast<const RnsCryptoParams&>(*ct.get_crypto_parameters()).get_scaling_technique();
}

// adjust_for_add_or_sub_in_place() is a no-op when the operands share level, noise-scale degree and tower
// count (the plaintext overload additionally requires the plaintext element in EVALUATION format).
inline bool adjust_for_add_or_sub_is_no_op(const CiphertextImpl<RnsPoly>& a, const CiphertextImpl<RnsPoly>& b) {
    return a.get_level() == b.get_level() && a.get_noise_scale_deg() == b.get_noise_scale_deg() &&
           a.get_elements()[0].get_num_of_elements() == b.get_elements()[0].get_num_of_elements();
}
inline bool adjust_for_add_or_sub_is_no_op(const CiphertextImpl<RnsPoly>& ct, const PlaintextImpl& pt) {
    const auto& pe = pt.get_element<RnsPoly>();
    return pt.get_level() == ct.get_level() && pt.get_noise_scale_deg() == ct.get_noise_scale_deg() &&
           pe.get_format() == Format::EVALUATION && pe.get_num_of_elements() == ct.get_elements()[0].get_num_of_elements();
}

// adjust_for_mult_in_place() is a no-op when the operands share level and tower count and either the
// scaling technique is FIXEDMANUAL (no rescale on mult) or both operands are already at depth 1.
inline bool adjust_for_mult_is_no_op(const CiphertextImpl<RnsPoly>& a, const CiphertextImpl<RnsPoly>& b,
                                ScalingTechnique st) {
    return a.get_level() == b.get_level() &&
           a.get_elements()[0].get_num_of_elements() == b.get_elements()[0].get_num_of_elements() &&
           (st == FIXEDMANUAL || (a.get_noise_scale_deg() == 1 && b.get_noise_scale_deg() == 1));
}
inline bool adjust_for_mult_is_no_op(const CiphertextImpl<RnsPoly>& ct, const PlaintextImpl& pt, ScalingTechnique st) {
    const auto& pe = pt.get_element<RnsPoly>();
    return ct.get_level() == pt.get_level() && pe.get_format() == Format::EVALUATION &&
           pe.get_num_of_elements() == ct.get_elements()[0].get_num_of_elements() &&
           (st == FIXEDMANUAL || (ct.get_noise_scale_deg() == 1 && pt.get_noise_scale_deg() == 1));
}
}  // namespace

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::eval_add(ConstCiphertext<RnsPoly>& ciphertext1,
                                            ConstCiphertext<RnsPoly>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_add_in_place(result, ciphertext2);
    return result;
}

void RnsLeveledShe::eval_add_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2) const {
    auto st = get_scaling_technique(*ciphertext1);
    if (st == NORESCALE || adjust_for_add_or_sub_is_no_op(*ciphertext1, *ciphertext2)) {
        eval_add_core_in_place(ciphertext1, ciphertext2);
    } else {
        auto c2 = ciphertext2->clone();
        adjust_for_add_or_sub_in_place(ciphertext1, c2);
        eval_add_core_in_place(ciphertext1, c2);
    }
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_add_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                   Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_for_add_or_sub_in_place(ciphertext1, ciphertext2);
    return eval_add_core(ciphertext1, ciphertext2);
}

void RnsLeveledShe::eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_for_add_or_sub_in_place(ciphertext1, ciphertext2);
    eval_add_core_in_place(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE ADDITION PLAINTEXT
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::eval_add(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_add_in_place(result, plaintext);
    return result;
}

void RnsLeveledShe::eval_add_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = get_scaling_technique(*ciphertext);
    if (st == NORESCALE || adjust_for_add_or_sub_is_no_op(*ciphertext, *plaintext)) {
        eval_add_core_in_place(ciphertext, plaintext->get_element<RnsPoly>());
    } else {
        auto ctmorphed = morph_plaintext(plaintext, ciphertext);
        adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
        eval_add_core_in_place(ciphertext, ctmorphed->get_elements()[0]);
    }
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_add_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
    return eval_add_core(ciphertext, ctmorphed->get_elements()[0]);
}

void RnsLeveledShe::eval_add_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
    eval_add_core_in_place(ciphertext, ctmorphed->get_elements()[0]);
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::eval_sub(ConstCiphertext<RnsPoly>& ciphertext1,
                                            ConstCiphertext<RnsPoly>& ciphertext2) const {
    auto result = ciphertext1->clone();
    eval_sub_in_place(result, ciphertext2);
    return result;
}

void RnsLeveledShe::eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext1, ConstCiphertext<RnsPoly>& ciphertext2) const {
    auto st = get_scaling_technique(*ciphertext1);
    if (st == NORESCALE || adjust_for_add_or_sub_is_no_op(*ciphertext1, *ciphertext2)) {
        eval_sub_core_in_place(ciphertext1, ciphertext2);
    } else {
        auto c2 = ciphertext2->clone();
        adjust_for_add_or_sub_in_place(ciphertext1, c2);
        eval_sub_core_in_place(ciphertext1, c2);
    }
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                   Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_for_add_or_sub_in_place(ciphertext1, ciphertext2);
    return eval_sub_core(ciphertext1, ciphertext2);
}

void RnsLeveledShe::eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const {
    adjust_for_add_or_sub_in_place(ciphertext1, ciphertext2);
    eval_sub_core_in_place(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE SUBTRACTION PLAINTEXT
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::eval_sub(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_sub_in_place(result, plaintext);
    return result;
}

void RnsLeveledShe::eval_sub_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = get_scaling_technique(*ciphertext);
    if (st == NORESCALE || adjust_for_add_or_sub_is_no_op(*ciphertext, *plaintext)) {
        eval_sub_core_in_place(ciphertext, plaintext->get_element<RnsPoly>());
    } else {
        auto ctmorphed = morph_plaintext(plaintext, ciphertext);
        adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
        eval_sub_core_in_place(ciphertext, ctmorphed->get_elements()[0]);
    }
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_sub_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
    return eval_sub_core(ciphertext, ctmorphed->get_elements()[0]);
}

void RnsLeveledShe::eval_sub_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_add_or_sub_in_place(ciphertext, ctmorphed);
    eval_sub_core_in_place(ciphertext, ctmorphed->get_elements()[0]);
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                             ConstCiphertext<RnsPoly>& ciphertext2) const {
    auto st = get_scaling_technique(*ciphertext1);
    if (st == NORESCALE || adjust_for_mult_is_no_op(*ciphertext1, *ciphertext2, st))
        return eval_mult_core(ciphertext1, ciphertext2);

    auto c1 = ciphertext1->clone();
    auto c2 = ciphertext2->clone();
    adjust_for_mult_in_place(c1, c2);
    return eval_mult_core(c1, c2);
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext1,
                                                    Ciphertext<RnsPoly>& ciphertext2) const {
    if (ciphertext1 == ciphertext2)
        return eval_square_mutable(ciphertext1);
    adjust_for_mult_in_place(ciphertext1, ciphertext2);
    return eval_mult_core(ciphertext1, ciphertext2);
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_square(ConstCiphertext<RnsPoly>& ciphertext) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto st = crypto_params->get_scaling_technique();
    if (st == NORESCALE || st == FIXEDMANUAL || ciphertext->get_noise_scale_deg() == 1)
        return eval_square_core(ciphertext);

    size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ? crypto_params->get_composite_degree() :
                                                                                 BASE_NUM_LEVELS_TO_DROP;
    return eval_square_core(mod_reduce_internal(ciphertext, lvls));
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_square_mutable(Ciphertext<RnsPoly>& ciphertext) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto st = crypto_params->get_scaling_technique();
    if (st != NORESCALE && st != FIXEDMANUAL && ciphertext->get_noise_scale_deg() == 2) {
        size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ?
                              crypto_params->get_composite_degree() :
                              BASE_NUM_LEVELS_TO_DROP;
        mod_reduce_internal_in_place(ciphertext, lvls);
    }

    return eval_square_core(ciphertext);
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_mult(ConstCiphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->clone();
    eval_mult_in_place(result, plaintext);
    return result;
}

void RnsLeveledShe::eval_mult_in_place(Ciphertext<RnsPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = get_scaling_technique(*ciphertext);
    if (st == NORESCALE) {
        eval_mult_core_in_place(ciphertext, plaintext->get_element<RnsPoly>());
    } else {
        if (adjust_for_mult_is_no_op(*ciphertext, *plaintext, st)) {
            eval_mult_core_in_place(ciphertext, plaintext->get_element<RnsPoly>());
            ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + plaintext->get_noise_scale_deg());
        } else {
            auto ctmorphed = morph_plaintext(plaintext, ciphertext);
            adjust_for_mult_in_place(ciphertext, ctmorphed);
            eval_mult_core_in_place(ciphertext, ctmorphed->get_elements()[0]);
            ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + ctmorphed->get_noise_scale_deg());
        }
    }
}

Ciphertext<RnsPoly> RnsLeveledShe::eval_mult_mutable(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_mult_in_place(ciphertext, ctmorphed);
    auto result = eval_mult_core(ciphertext, ctmorphed->get_elements()[0]);

    result->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + ctmorphed->get_noise_scale_deg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    result->set_scaling_factor(ciphertext->get_scaling_factor() * ctmorphed->get_scaling_factor());
    // TODO (Andrey) : This part is only used in BGV scheme
    auto st = get_scaling_technique(*ciphertext);
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        result->set_scaling_factor_int(ciphertext->get_scaling_factor_int().mod_mul(
                ctmorphed->get_scaling_factor_int(), ciphertext->get_crypto_parameters()->get_plaintext_modulus()));
    return result;
}

// TODO (Andrey) : currently do same as eval_mult_in_place, as Plaintext element is immutable
void RnsLeveledShe::eval_mult_mutable_in_place(Ciphertext<RnsPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = morph_plaintext(plaintext, ciphertext);
    adjust_for_mult_in_place(ciphertext, ctmorphed);
    eval_mult_core_in_place(ciphertext, ctmorphed->get_elements()[0]);

    ciphertext->set_noise_scale_deg(ciphertext->get_noise_scale_deg() + ctmorphed->get_noise_scale_deg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    ciphertext->set_scaling_factor(ciphertext->get_scaling_factor() * ctmorphed->get_scaling_factor());
    // TODO (Andrey) : This part is only used in BGV scheme
    auto st = get_scaling_technique(*ciphertext);
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        ciphertext->set_scaling_factor_int(ciphertext->get_scaling_factor_int().mod_mul(
                ctmorphed->get_scaling_factor_int(), ciphertext->get_crypto_parameters()->get_plaintext_modulus()));
}

Ciphertext<RnsPoly> RnsLeveledShe::mult_by_monomial(ConstCiphertext<RnsPoly>& ciphertext, uint32_t power) const {
    auto result = ciphertext->clone();
    mult_by_monomial_in_place(result, power);
    return result;
}

void RnsLeveledShe::mult_by_monomial_in_place(Ciphertext<RnsPoly>& ciphertext, uint32_t power) const {
    auto& cv = ciphertext->get_elements();
    auto elem_params = cv[0].get_params();
    auto params_native = elem_params->get_params()[0];
    uint32_t N = elem_params->get_ring_dimension();
    uint32_t M = 2 * N;

    NativePoly monomial(params_native, Format::COEFFICIENT, true);

    uint32_t power_reduced = power % M;
    monomial[power % N] = power_reduced < N ? NativeInteger(1) : params_native->get_modulus() - NativeInteger(1);

    RnsPoly monomial_dcrt(elem_params, Format::COEFFICIENT, true);
    monomial_dcrt = monomial;
    monomial_dcrt.set_format(Format::EVALUATION);

    for (uint32_t i = 0; i < ciphertext->number_ciphertext_elements(); ++i)
        cv[i] *= monomial_dcrt;
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

/////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::mod_reduce(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->clone();
    mod_reduce_in_place(result, levels);
    return result;
}

void RnsLeveledShe::mod_reduce_in_place(Ciphertext<RnsPoly>& ciphertext, size_t levels) const {
    auto st = get_scaling_technique(*ciphertext);
    if (st == FIXEDMANUAL)
        mod_reduce_internal_in_place(ciphertext, levels);
}

/////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////

// TODO (Andrey) : remove eval_key as unused
Ciphertext<RnsPoly> RnsLeveledShe::level_reduce(ConstCiphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key,
                                                size_t levels) const {
    auto result = ciphertext->clone();
    level_reduce_in_place(result, eval_key, levels);
    return result;
}

// TODO (Andrey) : remove eval_key as unused
void RnsLeveledShe::level_reduce_in_place(Ciphertext<RnsPoly>& ciphertext, const EvalKey<RnsPoly> eval_key,
                                       size_t levels) const {
    auto st = get_scaling_technique(*ciphertext);
    if (st == NORESCALE)
        CIPHER_THROW("Not implemented for NORESCALE rescaling technique");
    if (st == FIXEDMANUAL && levels > 0)
        level_reduce_internal_in_place(ciphertext, levels);
}

/////////////////////////////////////////
// SHE LEVELED Compress
/////////////////////////////////////////

/*
 * On COMPOSITESCALING technique, the number of towers to drop passed
 * must be a multiple of composite degree.
 */
Ciphertext<RnsPoly> RnsLeveledShe::compress(ConstCiphertext<RnsPoly>& ciphertext, size_t towers_left,
                                             size_t noise_scale_deg) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    uint32_t levels_to_drop = BASE_NUM_LEVELS_TO_DROP;
    if (crypto_params->get_scaling_technique() == COMPOSITESCALINGAUTO ||
        crypto_params->get_scaling_technique() == COMPOSITESCALINGMANUAL) {
        uint32_t composite_degree = crypto_params->get_composite_degree();
        levels_to_drop = composite_degree;
        if (towers_left % composite_degree != 0)
            CIPHER_THROW("Number of towers to drop must be a multiple of composite degree.");
    }

    auto result = std::make_shared<CiphertextImpl<RnsPoly>>(*ciphertext);
    while (result->get_noise_scale_deg() > noise_scale_deg)
        mod_reduce_internal_in_place(result, levels_to_drop);

    size_t size_ql = result->get_elements()[0].get_num_of_elements();
    if (towers_left < size_ql)
        level_reduce_internal_in_place(result, size_ql - towers_left);

    return result;
}

/////////////////////////////////////////
// SHE CORE OPERATION
/////////////////////////////////////////

Ciphertext<RnsPoly> RnsLeveledShe::mod_reduce_internal(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->clone();
    mod_reduce_internal_in_place(result, levels);
    return result;
}

Ciphertext<RnsPoly> RnsLeveledShe::level_reduce_internal(ConstCiphertext<RnsPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->clone();
    level_reduce_internal_in_place(result, levels);
    return result;
}

void RnsLeveledShe::adjust_levels_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const {
    auto size_ql1 = ciphertext1->get_elements()[0].get_num_of_elements();
    auto size_ql2 = ciphertext2->get_elements()[0].get_num_of_elements();
    if (size_ql1 < size_ql2)
        level_reduce_internal_in_place(ciphertext2, size_ql2 - size_ql1);
    if (size_ql1 > size_ql2)
        level_reduce_internal_in_place(ciphertext1, size_ql1 - size_ql2);
}

void RnsLeveledShe::adjust_for_add_or_sub_in_place(Ciphertext<RnsPoly>& ciphertext1,
                                             Ciphertext<RnsPoly>& ciphertext2) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext1->get_crypto_parameters());

    if (crypto_params->get_scaling_technique() == FIXEDMANUAL) {
        adjust_levels_in_place(ciphertext1, ciphertext2);

        double sc_factor = crypto_params->get_scaling_factor_real();

        // supported only for CKKS
        if (sc_factor == 0.0)
            return;

        RnsPoly ptxt;
        uint32_t ptxt_depth = 0;
        uint32_t ctxt_depth = 0;
        uint32_t size_ql = 0;
        uint32_t ptxt_index = 0;

        // Get moduli chain to create CRT representation of pow_p
        std::vector<RnsPoly::Integer> moduli;

        if (ciphertext1->number_ciphertext_elements() == 1) {
            ptxt = ciphertext1->get_elements()[0];
            ptxt_depth = ciphertext1->get_noise_scale_deg();
            ctxt_depth = ciphertext2->get_noise_scale_deg();
            size_ql = ciphertext2->get_elements()[0].get_num_of_elements();
            moduli.resize(size_ql);
            for (uint32_t i = 0; i < size_ql; i++) {
                moduli[i] = ciphertext2->get_elements()[0].get_element_at_index(i).get_modulus();
            }
            ptxt_index = 1;
        } else if (ciphertext2->number_ciphertext_elements() == 1) {
            ptxt = ciphertext2->get_elements()[0];
            ptxt_depth = ciphertext2->get_noise_scale_deg();
            ctxt_depth = ciphertext1->get_noise_scale_deg();
            size_ql = ciphertext1->get_elements()[0].get_num_of_elements();
            moduli.resize(size_ql);
            for (uint32_t i = 0; i < size_ql; i++) {
                moduli[i] = ciphertext1->get_elements()[0].get_element_at_index(i).get_modulus();
            }
            ptxt_index = 2;
        } else
            return;

        // Bring to same depth if not already same
        if (ptxt_depth < ctxt_depth) {
            // Find out how many levels to scale plaintext up.
            size_t diff_depth = ctxt_depth - ptxt_depth;

            // Each extra degree of the ciphertext is removed by a rescale that divides by the modulus of the
            // dropped tower, so the plaintext is scaled by those moduli rather than by powers of the scaling
            // factor (which would leave a residual sc_factor / q_l on it).
            RnsPoly::Integer int_sf = static_cast<NativeInteger::Integer>(sc_factor + 0.5);
            std::vector<RnsPoly::Integer> crt_pow_sf(size_ql, RnsPoly::Integer(1));
            for (uint32_t j = 1; j <= diff_depth; ++j) {
                std::vector<RnsPoly::Integer> crt_q(size_ql, int_sf);
                if (j < size_ql) {
                    for (uint32_t i = 0; i < size_ql; ++i)
                        crt_q[i] = moduli[size_ql - j].mod(moduli[i]);
                }
                crt_pow_sf = CKKSPackedEncoding::crt_mult(crt_pow_sf, crt_q, moduli);
            }

            if (ptxt_index == 1) {
                ciphertext1->set_elements(std::vector<RnsPoly>{ptxt.Times(crt_pow_sf)});
                ciphertext1->set_noise_scale_deg(ctxt_depth);
            } else {
                ciphertext2->set_elements(std::vector<RnsPoly>{ptxt.Times(crt_pow_sf)});
                ciphertext2->set_noise_scale_deg(ctxt_depth);
            }
        } else if (ptxt_depth > ctxt_depth) {
            CIPHER_THROW("plaintext cannot be encoded at a larger depth than that of the ciphertext.");
        }
    } else if (crypto_params->get_scaling_technique() != NORESCALE) {
        adjust_levels_and_depth_in_place(ciphertext1, ciphertext2);
    }
}

void RnsLeveledShe::adjust_for_mult_in_place(Ciphertext<RnsPoly>& ciphertext1, Ciphertext<RnsPoly>& ciphertext2) const {
    auto st = get_scaling_technique(*ciphertext1);
    if (st == FIXEDMANUAL)
        adjust_levels_in_place(ciphertext1, ciphertext2);
    else if (st != NORESCALE)
        adjust_levels_and_depth_to_one_in_place(ciphertext1, ciphertext2);
}

Ciphertext<RnsPoly> RnsLeveledShe::composed_eval_mult(ConstCiphertext<RnsPoly>& ciphertext1,
                                                     ConstCiphertext<RnsPoly>& ciphertext2,
                                                     const EvalKey<RnsPoly> eval_key) const {
    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext1->get_crypto_parameters());

    auto st = crypto_params->get_scaling_technique();
    size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ? crypto_params->get_composite_degree() :
                                                                                 BASE_NUM_LEVELS_TO_DROP;

    auto ciphertext = eval_mult(ciphertext1, ciphertext2);
    ciphertext->get_crypto_context()->get_scheme()->key_switch_in_place(ciphertext, eval_key);
    mod_reduce_in_place(ciphertext, lvls);
    return ciphertext;
}

}  // namespace cipher
