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

#include "cipher/boolean/base_scheme.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cipher {

// wrapper for key_gen methods
RingGswBtKey BooleanScheme::key_gen(const std::shared_ptr<BooleanCryptoParams>& params, ConstLwePrivateKey& LWE_sk,
                                    KEYGEN_MODE keygen_mode, bool internal32) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (LWE_sk == nullptr)
        CIPHER_THROW("PrivateKey is empty");

    const auto& LWE_params = params->get_lwe_params();

    RingGswBtKey ek;
    LwePrivateKey sk_n;
    if (keygen_mode == SYM_ENCRYPT) {
        sk_n = lwe_scheme->key_gen(LWE_params->get_N(), LWE_params->get_Q());
    } else if (keygen_mode == PUB_ENCRYPT) {
        ConstLweKeyPair kp_n = lwe_scheme->key_gen_pair(LWE_params);
        sk_n = kp_n->secret_key;
        ek.pkey = kp_n->public_key;
    } else {
        CIPHER_THROW("Invalid key_gen mode");
    }

#if CIPHER_NATIVE_INT != 32
    if (internal32 && LweSwitchingKey32Impl::fits(*LWE_params))
        ek.ks_key32 = lwe_scheme->key_switch_gen32(LWE_params, LWE_sk, sk_n);
    if (ek.ks_key32 == nullptr)
#endif
        ek.ks_key = lwe_scheme->key_switch_gen(LWE_params, LWE_sk, sk_n);

    const auto& RGSW_params = params->get_ring_gsw_params();
    const auto& poly_params = RGSW_params->get_poly_params();
    NativePoly sk_n_poly(poly_params);
    sk_n_poly.set_values(std::move(sk_n->get_element()), Format::COEFFICIENT);
    sk_n_poly.set_format(Format::EVALUATION);

#if CIPHER_NATIVE_INT != 32
    // direct 32-bit generation never materialises the 64-bit refreshing key; nullptr means this
    // accumulator does not support it, so fall through
    if (internal32 && RingGswAccKey32Impl::fits(*RGSW_params))
        ek.b_skey32 = acc_scheme->key_gen_acc32(RGSW_params, sk_n_poly, LWE_sk);
    if (ek.b_skey32 == nullptr) {
        // an earlier all-32-bit key generation may have released the 64-bit monomials
        RGSW_params->ensure_monomials();
        ek.b_skey = acc_scheme->key_gen_acc(RGSW_params, sk_n_poly, LWE_sk);
    }
#else
    (void)internal32;
    ek.b_skey = acc_scheme->key_gen_acc(RGSW_params, sk_n_poly, LWE_sk);
#endif

    return ek;
}

LweCiphertext BooleanScheme::switch_c_ttoqn(const std::shared_ptr<LweCryptoParams>& params, const RingGswBtKey& EK,
                                            ConstLweCiphertext& ct) const {
#if CIPHER_NATIVE_INT != 32
    if (EK.ks_key32 != nullptr)
        return lwe_scheme->switch_c_ttoqn(params, EK.ks_key32, ct);
#endif
    return lwe_scheme->switch_c_ttoqn(params, EK.ks_key, ct);
}

LweCiphertext BooleanScheme::key_switch(const std::shared_ptr<LweCryptoParams>& params, const RingGswBtKey& EK,
                                        ConstLweCiphertext& ct) const {
#if CIPHER_NATIVE_INT != 32
    if (EK.ks_key32 != nullptr)
        return lwe_scheme->key_switch(params, EK.ks_key32, ct);
#endif
    return lwe_scheme->key_switch(params, EK.ks_key, ct);
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LweCiphertext BooleanScheme::eval_bin_gate(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate,
                                           const RingGswBtKey& EK, ConstLweCiphertext& ct1, ConstLweCiphertext& ct2,
                                           bool extended) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct1 == nullptr)
        CIPHER_THROW("Ciphertext1 is empty");
    if (ct2 == nullptr)
        CIPHER_THROW("Ciphertext2 is empty");
    if (ct1 == ct2)
        CIPHER_THROW("Input ciphertexts should be independant");

    const auto& LWE_params = params->get_lwe_params();
    NativeInteger Q{LWE_params->get_Q()};

    // input cts expected with SMALL_DIM
    auto cct1 =
            (Q == ct1->get_modulus()) ? switch_c_ttoqn(LWE_params, EK, ct1) : std::make_shared<LweCiphertextImpl>(*ct1);
    const auto cct2 = (Q == ct2->get_modulus()) ? switch_c_ttoqn(LWE_params, EK, ct2) : ct2;

    // the additive homomorphic operation for XOR/NXOR is different from the other gates we compute
    // 2*(ct1 + ct2) mod 4 for XOR, 0 -> 0, 2 -> 1
    // XOR_FAST and XNOR_FAST are included for backwards compatibility; they map to XOR and XNOR
    if ((gate == XOR) || (gate == XNOR) || (gate == XOR_FAST) || (gate == XNOR_FAST)) {
        lwe_scheme->eval_add_eq(cct1, cct2);
        lwe_scheme->eval_add_eq(cct1, cct1);
    } else {
        // for all other gates, we simply compute (ct1 + ct2) mod 4
        // for AND: 0,1 -> 0 and 2,3 -> 1
        // for OR: 1,2 -> 1 and 3,0 -> 0
        lwe_scheme->eval_add_eq(cct1, cct2);
    }

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    auto acc{bootstrap_gate_core(params, gate, EK, cct1)};
    auto& acc_vec{acc->get_elements()};
    acc_vec[0] = acc_vec[0].transposed();
    acc_vec[0].set_format(Format::COEFFICIENT);
    acc_vec[1].set_format(Format::COEFFICIENT);

    // hardcoded for p = 4
    // we add Q/8 to "b" to map back to Q/4 (i.e., mod 2) arithmetic.
    NativeInteger b{(Q >> 3) + 1};
    b.mod_add_fast_eq(acc_vec[1][0], Q);

    auto ct_ext = std::make_shared<LweCiphertextImpl>(std::move(acc_vec[0].get_values()), b);

    if (extended)
        return ct_ext;
    return switch_c_ttoqn(LWE_params, EK, ct_ext);
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LweCiphertext BooleanScheme::eval_bin_gate(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate,
                                           const RingGswBtKey& EK, const std::vector<LweCiphertext>& ctvector,
                                           bool extended) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");

    uint32_t expected_size = 0;
    switch (gate) {
        case AND3:
        case OR3:
        case MAJORITY:
        case CMUX:
            expected_size = 3;
            break;
        case AND4:
        case OR4:
            expected_size = 4;
            break;
        default:
            CIPHER_THROW("This gate is not supported for vector of ciphertexts");
    }
    if (ctvector.size() != expected_size)
        CIPHER_THROW("Invalid number of input ciphertexts");

    for (const auto& ct : ctvector) {
        if (ct == nullptr)
            CIPHER_THROW("Input ciphertext is empty");
    }

    // check if the ciphertexts are all independent
    for (uint32_t i = 0; i < expected_size; ++i) {
        for (uint32_t j = i + 1; j < expected_size; ++j) {
            if (ctvector[i] == ctvector[j]) {
                CIPHER_THROW("Input ciphertexts should be independent");
            }
        }
    }

    if ((gate == AND3) || (gate == OR3) || (gate == AND4) || (gate == OR4) || (gate == MAJORITY)) {
        const auto& LWE_params = params->get_lwe_params();
        NativeInteger Q{LWE_params->get_Q()};

        // input cts expected with SMALL_DIM
        auto ct = (Q == ctvector[0]->get_modulus()) ? switch_c_ttoqn(LWE_params, EK, ctvector[0]) :
                                                      std::make_shared<LweCiphertextImpl>(*ctvector[0]);
        for (uint32_t i = 1; i < expected_size; ++i) {
            lwe_scheme->eval_add_eq(
                    ct, (Q == ctvector[i]->get_modulus()) ? switch_c_ttoqn(LWE_params, EK, ctvector[i]) : ctvector[i]);
        }

        const NativeInteger p{(gate == AND3 || gate == OR3) ? 6 : (gate == AND4 || gate == OR4) ? 8 : 4};
        ct->set_pt_modulus(p);

        auto acc{bootstrap_gate_core(params, gate, EK, ct)};
        auto& acc_vec{acc->get_elements()};
        acc_vec[0] = acc_vec[0].transposed();
        acc_vec[0].set_format(Format::COEFFICIENT);
        acc_vec[1].set_format(Format::COEFFICIENT);

        NativeInteger b = Q / (p * 2) + 1;
        b.mod_add_fast_eq(acc_vec[1][0], Q);

        auto ct_ext = std::make_shared<LweCiphertextImpl>(std::move(acc_vec[0].get_values()), b);

        if (!extended)
            ct_ext = switch_c_ttoqn(LWE_params, EK, ct_ext);

        ct_ext->set_pt_modulus(p);
        return ct_ext;
    } else if (gate == CMUX) {
        auto&& ct_nand1 = eval_bin_gate(params, NAND, EK, ctvector[0], eval_not(params, ctvector[2]));
        auto&& ct_nand2 = eval_bin_gate(params, NAND, EK, ctvector[1], ctvector[2]);
        return eval_bin_gate(params, NAND, EK, ct_nand1, ct_nand2);
    } else {
        CIPHER_THROW("This gate is not implemented for vector of ciphertexts at this time");
    }
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LweCiphertext BooleanScheme::bootstrap(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                       ConstLweCiphertext& ct, bool extended) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    const auto& LWE_params = params->get_lwe_params();
    NativeInteger Q{LWE_params->get_Q()};
    // input ct expected with SMALL_DIM
    auto cct = (Q == ct->get_modulus()) ? switch_c_ttoqn(LWE_params, EK, ct) : std::make_shared<LweCiphertextImpl>(*ct);
    lwe_scheme->eval_add_const_eq(cct, (cct->get_modulus() >> 2));

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    auto acc{bootstrap_gate_core(params, AND, EK, cct)};
    auto& acc_vec{acc->get_elements()};
    acc_vec[0] = acc_vec[0].transposed();
    acc_vec[0].set_format(Format::COEFFICIENT);
    acc_vec[1].set_format(Format::COEFFICIENT);

    NativeInteger b{Q / (ct->get_pt_modulus() * 2) + 1};
    b.mod_add_fast_eq(acc_vec[1][0], Q);

    auto ct_ext = std::make_shared<LweCiphertextImpl>(std::move(acc_vec[0].get_values()), b);

    if (!extended)
        ct_ext = switch_c_ttoqn(LWE_params, EK, ct_ext);

    ct_ext->set_pt_modulus(ct->get_pt_modulus());
    return ct_ext;
}

// Evaluation of the NOT operation; no key material is needed
LweCiphertext BooleanScheme::eval_not(const std::shared_ptr<BooleanCryptoParams>& params,
                                      ConstLweCiphertext& ct) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    NativeVector a(ct->get_A());
    NativeInteger q{ct->get_modulus()};
    uint32_t n{ct->get_length()};
    for (uint32_t i = 0; i < n; ++i) {
        if (a[i] != 0)
            a[i] = q - a[i];
    }
    return std::make_shared<LweCiphertextImpl>(std::move(a), (q >> 2).mod_sub_fast(ct->get_B(), q));
}

// Evaluate Arbitrary Function homomorphically
// Modulus of ct is q | 2N
LweCiphertext BooleanScheme::eval_func(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                       ConstLweCiphertext& ct, const std::vector<NativeInteger>& LUT,
                                       NativeInteger beta) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    auto ct1 = std::make_shared<LweCiphertextImpl>(*ct);
    NativeInteger q{ct->get_modulus()};
    uint32_t function_property{this->check_input_function(LUT, q)};

    if (function_property == 0) {  // negacyclic function only needs one bootstrap
        auto f_lut = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return LUT[x.convert_to_int()];
        };
        lwe_scheme->eval_add_const_eq(ct1, beta);
        return bootstrap_func(params, EK, ct1, f_lut, q);
    }

    if (function_property == 2) {  // arbitary funciton
        const auto& LWE_params = params->get_lwe_params();
        uint32_t N{LWE_params->get_N()};
        if (q.convert_to_int() > N)
            CIPHER_THROW("Ciphertext modulus q must be <= ring dimension for arbitrary function evaluation");

        // TODO: figure out a way to not do this :(

        // repeat the LUT to make it periodic
        std::vector<NativeInteger> LUT2;
        LUT2.reserve(LUT.size() + LUT.size());
        LUT2.insert(LUT2.end(), LUT.begin(), LUT.end());
        LUT2.insert(LUT2.end(), LUT.begin(), LUT.end());

        NativeInteger dq{q << 1};
        // raise the modulus of ct1 : q -> 2q
        ct1->get_A().set_modulus(dq);
        auto ct2 = std::make_shared<LweCiphertextImpl>(*ct1);
        lwe_scheme->eval_add_const_eq(ct2, beta);

        // this is 1/4q_small or -1/4q_small mod q
        auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return Q - (q >> 2);
            else
                return (q >> 2);
        };
        auto ct3 = bootstrap_func(params, EK, ct2, f0, dq);
        lwe_scheme->eval_sub_eq2(ct1, ct3);
        lwe_scheme->eval_add_const_eq(ct3, beta);
        lwe_scheme->eval_sub_const_eq(ct3, q >> 1);

        // Now the input is within the range [0, q/2).
        // Note that for non-periodic function, the input q is boosted up to 2q
        auto f_lut2 = [LUT2](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return LUT2[x.convert_to_int()];
            else
                return Q - LUT2[x.convert_to_int() - q.convert_to_int() / 2];
        };
        auto ct4 = bootstrap_func(params, EK, ct3, f_lut2, dq);
        ct4->set_modulus(q);
        return ct4;
    }

    // Else it's periodic function so we evaluate directly
    lwe_scheme->eval_add_const_eq(ct1, beta);
    // this is 1/4q_small or -1/4q_small mod q
    auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = bootstrap_func(params, EK, ct1, f0, q);
    lwe_scheme->eval_sub_eq2(ct, ct2);
    lwe_scheme->eval_add_const_eq(ct2, beta);
    lwe_scheme->eval_sub_const_eq(ct2, q >> 2);

    // Now the input is within the range [0, q/2).
    // Note that for non-periodic function, the input q is boosted up to 2q
    auto f_lut1 = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return LUT[x.convert_to_int()];
        else
            return Q - LUT[x.convert_to_int() - q.convert_to_int() / 2];
    };
    return bootstrap_func(params, EK, ct2, f_lut1, q);
}

// Evaluate Homomorphic Flooring
LweCiphertext BooleanScheme::eval_floor(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                        ConstLweCiphertext& ct, NativeInteger beta, uint32_t roundbits) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    const auto& LWE_params = params->get_lwe_params();
    NativeInteger q{roundbits == 0 ? LWE_params->get_q() : beta * (1 << (roundbits + 1))};
    NativeInteger mod_value{ct->get_modulus()};

    auto ct1 = std::make_shared<LweCiphertextImpl>(*ct);
    lwe_scheme->eval_add_const_eq(ct1, beta);

    auto ct1_modq = std::make_shared<LweCiphertextImpl>(*ct1);
    ct1_modq->set_modulus(q);
    // this is 1/4q_small or -1/4q_small mod q
    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = bootstrap_func(params, EK, ct1_modq, f1, mod_value);
    lwe_scheme->eval_sub_eq(ct1, ct2);

    auto ct2_modq = std::make_shared<LweCiphertextImpl>(*ct1);
    ct2_modq->set_modulus(q);

    // now the input is only within the range [0, q/2)
    auto f2 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 2))
            return Q - (q >> 1) - x;
        else if (((q >> 2) <= x) && (x < 3 * (q >> 2)))
            return x;
        else
            return Q + (q >> 1) - x;
    };
    auto ct3 = bootstrap_func(params, EK, ct2_modq, f2, mod_value);
    lwe_scheme->eval_sub_eq(ct1, ct3);

    return ct1;
}

// Evaluate large-precision sign
LweCiphertext BooleanScheme::eval_sign(const std::shared_ptr<BooleanCryptoParams>& params,
                                       const std::map<uint32_t, RingGswBtKey>& e_ks, ConstLweCiphertext& ct,
                                       NativeInteger beta, bool scheme_switch) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    auto mod_value{ct->get_modulus()};
    const auto& LWE_params = params->get_lwe_params();
    auto q{LWE_params->get_q()};
    if (mod_value <= q)
        CIPHER_THROW("This function only for large precision. For small precision, use bootstrapping directly");

    const auto& RGSW_params = params->get_ring_gsw_params();
    const auto cur_base = RGSW_params->get_base_g();
    auto search = e_ks.find(cur_base);
    if (search == e_ks.end())
        CIPHER_THROW("No key [" + std::to_string(cur_base) + "] found in the map");
    RingGswBtKey cur_ek(search->second);

    auto cttmp = std::make_shared<LweCiphertextImpl>(*ct);
    while (mod_value > q) {
        cttmp = eval_floor(params, cur_ek, cttmp, beta);
        // round Q to 2betaQ/q
        mod_value = (mod_value << 1) * beta / q;
        cttmp = lwe_scheme->mod_switch(mod_value, cttmp);

        // if dynamic
        if (e_ks.size() == 3) {
            uint32_t bin_log = get_msb(mod_value.convert_to_int()) - 1;
            uint32_t base{0};
            if (bin_log <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (bin_log <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSW_params->change_base_g(base);

                auto search = e_ks.find(base);
                if (search == e_ks.end())
                    CIPHER_THROW("No key [" + std::to_string(base) + "] found in the map");
                cur_ek = search->second;
            }
        }
    }
    lwe_scheme->eval_add_const_eq(cttmp, beta);

    if (!scheme_switch) {
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
        };
        cttmp = bootstrap_func(params, cur_ek, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
        lwe_scheme->eval_sub_const_eq(cttmp, q >> 2);
    } else {  // return the negated f3 and do not subtract q/4 for a more natural encoding in scheme switching
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q - Q / 4) : (Q / 4);
        };
        cttmp = bootstrap_func(params, cur_ek, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    }
    RGSW_params->change_base_g(cur_base);
    return cttmp;
}

// Evaluate Ciphertext Decomposition
std::vector<LweCiphertext> BooleanScheme::eval_decomp(const std::shared_ptr<BooleanCryptoParams>& params,
                                                      const std::map<uint32_t, RingGswBtKey>& e_ks,
                                                      ConstLweCiphertext& ct, NativeInteger beta) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");

    auto mod_value = ct->get_modulus();
    auto& LWE_params = params->get_lwe_params();
    auto& RGSW_params = params->get_ring_gsw_params();

    NativeInteger q = LWE_params->get_q();
    if (mod_value <= q)
        CIPHER_THROW("Function only for large precision. For small precision, use bootstrapping directly");

    const auto cur_base = RGSW_params->get_base_g();
    auto search = e_ks.find(cur_base);
    if (search == e_ks.end())
        CIPHER_THROW("No key [" + std::to_string(cur_base) + "] found in the map");
    RingGswBtKey cur_ek(search->second);

    auto cttmp = std::make_shared<LweCiphertextImpl>(*ct);
    std::vector<LweCiphertext> ret;
    while (mod_value > q) {
        auto ctq = std::make_shared<LweCiphertextImpl>(*cttmp);
        ctq->set_modulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        cttmp = eval_floor(params, cur_ek, cttmp, beta);
        // round Q to 2betaQ/q
        mod_value = (mod_value << 1) * beta / q;
        cttmp = lwe_scheme->mod_switch(mod_value, cttmp);

        if (e_ks.size() == 3) {  // if dynamic
            uint32_t bin_log = get_msb(mod_value.convert_to_int()) - 1;
            uint32_t base = 0;
            if (bin_log <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (bin_log <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSW_params->change_base_g(base);

                auto search = e_ks.find(base);
                if (search == e_ks.end())
                    CIPHER_THROW("No key [" + std::to_string(base) + "] found in the map");
                cur_ek = search->second;
            }
        }
    }
    RGSW_params->change_base_g(cur_base);
    ret.push_back(std::move(cttmp));
    return ret;
}

// private:

RlweCiphertext BooleanScheme::bootstrap_gate_core(const std::shared_ptr<BooleanCryptoParams>& params, BINGATE gate,
                                                  const RingGswBtKey& EK, ConstLweCiphertext& ct) const {
    if (params == nullptr)
        CIPHER_THROW("BooleanCryptoParams is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    if (!EK.has_refresh_key())
        CIPHER_THROW(
                "Bootstrapping keys have not been generated. Please call bt_key_gen before calling bootstrapping.");

    // Specifies the range [lb, ub) that will be used for mapping
    NativeInteger q = ct->get_modulus();
    const uint64_t q_int{q.convert_to_int<uint64_t>()};
    if (q_int == 0 || (2 * static_cast<uint64_t>(params->get_lwe_params()->get_N())) % q_int != 0)
        CIPHER_THROW("Ciphertext modulus must divide 2N");
    auto q_half = q.convert_to_int<uint32_t>() >> 1;
    auto& RGSW_params = params->get_ring_gsw_params();
    NativeInteger q1 = RGSW_params->get_gate_const()[static_cast<size_t>(gate)];
    NativeInteger q2 = q1.mod_add_fast(NativeInteger(q_half), q);

    bool swap = q1 >= q2;
    auto lb = swap ? q2 : q1;
    auto ub = swap ? q1 : q2;

    // depending on whether the value is the range, it will be set
    // to either Q/8 or -Q/8 to match binary arithmetic
    auto& LWE_params = params->get_lwe_params();
    NativeInteger Q = LWE_params->get_Q();

    // TODO: fix this?
    // the OUTPUT encoding, not the input's. The 2-input caller and Bootstrap both pass a
    // ciphertext whose copy or mod_switch has reset this to 4 -- that reset is what re-spaces the
    // result to q/4 -- while the multi-input caller sets the gate's 6 or 8 just above.
    NativeInteger q2p = Q / (ct->get_pt_modulus() * 2) + 1;
    NativeInteger q2p_neg = Q - q2p;

    auto lv = swap ? q2p : q2p_neg;
    auto uv = swap ? q2p_neg : q2p;

    const uint32_t N = LWE_params->get_N();
    NativeVector m(N, Q);
    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)

    const uint32_t factor = (N / q_half);

    NativeInteger b = ct->get_B();

    for (uint32_t i = 0; i < N; i += factor) {
        m[i] = ((b >= lb) && (b < ub)) ? lv : uv;
        b.mod_sub_fast_eq(1, q);
    }

    std::vector<NativePoly> res(2);
    auto& poly_params = RGSW_params->get_poly_params();
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(poly_params, Format::EVALUATION, true);
    res[1] = NativePoly(poly_params, Format::COEFFICIENT, false);
    res[1].set_values(std::move(m), Format::COEFFICIENT);
    res[1].set_format(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RlweCiphertextImpl>(std::move(res));
#if CIPHER_NATIVE_INT != 32
    if (EK.b_skey32 != nullptr)
        acc_scheme->eval_acc32(RGSW_params, EK.b_skey32, acc, ct->get_A());
    else
#endif
        acc_scheme->eval_acc(RGSW_params, EK.b_skey, acc, ct->get_A());
    return acc;
}

// Functions below are for large-precision sign evaluation,
// flooring, homomorphic digit decomposition, and arbitrary
// funciton evaluation, from https://eprint.iacr.org/2021/1337
template <typename Func>
RlweCiphertext BooleanScheme::bootstrap_func_core(const std::shared_ptr<BooleanCryptoParams>& params,
                                                  const RingGswBtKey& EK, ConstLweCiphertext& ct, const Func f,
                                                  NativeInteger fmod) const {
    if (!EK.has_refresh_key())
        CIPHER_THROW("Bootstrapping keys not generated. Please call bt_key_gen before bootstrapping.");

    auto& LWE_params = params->get_lwe_params();
    auto& RGSW_params = params->get_ring_gsw_params();
    auto poly_params = RGSW_params->get_poly_params();

    NativeInteger Q = LWE_params->get_Q();
    uint32_t N = LWE_params->get_N();
    NativeVector m(N, Q);
    // For specific function evaluation instead of general bootstrapping
    NativeInteger ct_mod = ct->get_modulus();
    uint32_t factor = (2 * N / ct_mod.convert_to_int());
    NativeInteger b = ct->get_B();
    for (size_t j = 0; j < (ct_mod >> 1); ++j) {
        NativeInteger temp = b.mod_sub_fast(j, ct_mod);
        m[j * factor] = Q.convert_to_int() / fmod.convert_to_int() * f(temp, ct_mod, fmod);
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(poly_params, Format::EVALUATION, true);
    res[1] = NativePoly(poly_params, Format::COEFFICIENT, false);
    res[1].set_values(std::move(m), Format::COEFFICIENT);
    res[1].set_format(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RlweCiphertextImpl>(std::move(res));
#if CIPHER_NATIVE_INT != 32
    if (EK.b_skey32 != nullptr)
        acc_scheme->eval_acc32(RGSW_params, EK.b_skey32, acc, ct->get_A());
    else
#endif
        acc_scheme->eval_acc(RGSW_params, EK.b_skey, acc, ct->get_A());
    return acc;
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
template <typename Func>
LweCiphertext BooleanScheme::bootstrap_func(const std::shared_ptr<BooleanCryptoParams>& params, const RingGswBtKey& EK,
                                            ConstLweCiphertext& ct, const Func f, NativeInteger fmod) const {
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    auto acc{bootstrap_func_core(params, EK, ct, f, fmod)};
    auto& acc_vec{acc->get_elements()};
    acc_vec[0] = acc_vec[0].transposed();
    acc_vec[0].set_format(Format::COEFFICIENT);
    acc_vec[1].set_format(Format::COEFFICIENT);

    auto ct_ext = std::make_shared<LweCiphertextImpl>(std::move(acc_vec[0].get_values()), acc_vec[1][0]);

    auto& LWE_params = params->get_lwe_params();
    // Modulus switching to a middle step Q'
    auto ct_ms = lwe_scheme->mod_switch(LWE_params->get_q_ks(), ct_ext);
    // Key switching
    auto ct_ks = key_switch(LWE_params, EK, ct_ms);
    // Modulus switching
    return lwe_scheme->mod_switch(fmod, ct_ks);
}

};  // namespace cipher
