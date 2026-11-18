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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#include "cipher/fhe/ckks/multiparty.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/ckks/crypto_params.h"

namespace cipher {

// {Q} = {q_1,...,q_l}, original RNS basis
// {P} = {p_1,...,p_k}, extended RNS basis
struct RnsExtensionTables {
    std::shared_ptr<RnsParams<BigInteger>> params_qp;      // the whole RNS basis
    std::shared_ptr<RnsParams<BigInteger>> params_p;       // only the new RNS basis
    std::vector<NativeInteger> q_hat_inv_modq;             // done
    std::vector<NativeInteger> q_hat_inv_modq_precon;      // done
    std::vector<std::vector<NativeInteger>> q_hat_modp;    // done
    std::vector<std::vector<NativeInteger>> alpha_q_modp;  // done
    std::vector<DoubleNativeInt> modp_barrett_mu;          // done
    std::vector<double> q_inv;                             // done
    Format result_format;
};

DecryptResult CkksRnsMultiparty::multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                                           Poly* plaintext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());
    const std::vector<RnsPoly>& cv0 = ciphertext_vec[0]->get_elements();

    RnsPoly b = cv0[0];
    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        const std::vector<RnsPoly>& cvi = ciphertext_vec[i]->get_elements();
        b += cvi[0];
    }
    b.set_format(Format::COEFFICIENT);

    *plaintext = b.crt_interpolate();

    //  size_t size_ql = b.get_params()->get_params().size();
    //  if (size_ql > 1) {
    //    *plaintext = b.crt_interpolate();
    //  } else if (size_ql == 1) {
    //    *plaintext = Poly(b.get_element_at_index(0), Format::COEFFICIENT);
    //  } else {
    //    CIPHER_THROW(
    //        "Decryption failure: No towers left; consider increasing the depth.");
    //  }

    return DecryptResult(plaintext->get_length());
}

DecryptResult CkksRnsMultiparty::multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                                           NativePoly* plaintext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());

    const std::vector<RnsPoly>& cv0 = ciphertext_vec[0]->get_elements();

    RnsPoly b = cv0[0];
    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        const std::vector<RnsPoly>& cvi = ciphertext_vec[i]->get_elements();
        b += cvi[0];
    }
    b.set_format(Format::COEFFICIENT);

    //  const size_t size_ql = b.get_params()->get_params().size();
    //  if (size_ql == 1)
    //    *plaintext = b.get_element_at_index(0);
    //  else
    //    CIPHER_THROW(
    //        "Decryption failure: No towers left; consider increasing the depth.");

    *plaintext = b.get_element_at_index(0);

    return DecryptResult(plaintext->get_length());
}

Ciphertext<RnsPoly> CkksRnsMultiparty::int_mp_boot_adjust_scale(ConstCiphertext<RnsPoly> ciphertext) const {
    if (ciphertext->number_ciphertext_elements() == 0)
        CIPHER_THROW("No polynomials in the input ciphertext.");

    auto cc = ciphertext->get_crypto_context();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());

    auto st = crypto_params->get_scaling_technique();
    if (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL)
        CIPHER_THROW("Current composite scaling implementation does not yet support interactive bootstrapping");

    auto compression_level = crypto_params->get_mp_int_boot_ciphertext_compression_level();

    // Compress ctxt and reduce it to numPrimesToKeep towers
    // 1 is for the message itself (assuming 1 tower (60-bit) for msg)
    size_t scaling_factor_bits = cc->get_encoding_params()->get_plaintext_modulus();
    size_t first_modulus_size =
            ciphertext->get_elements()[0].get_all_elements()[0].get_params()->get_modulus().get_msb();
    size_t num_towers_to_keep = (scaling_factor_bits / first_modulus_size + 1) + compression_level;

    if (ciphertext->get_elements()[0].get_num_of_elements() < num_towers_to_keep)
        CIPHER_THROW("Not enough towers in the input polynomial.");

    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT) {
        auto ciphertext_adjusted = cc->compress(ciphertext, num_towers_to_keep + 1);

        uint32_t lvl = st == FLEXIBLEAUTO ? 0 : 1;
        double target_sf = crypto_params->get_scaling_factor_real(lvl);
        double source_sf = ciphertext_adjusted->get_scaling_factor();
        uint32_t num_towers = ciphertext_adjusted->get_elements()[0].get_num_of_elements();
        double mod_to_drop =
                crypto_params->get_element_params()->get_params()[num_towers - 1]->get_modulus().convert_to_double();
        double adjustment_factor = (target_sf / source_sf) * (mod_to_drop / source_sf);

        ciphertext_adjusted = cc->eval_mult(ciphertext_adjusted, adjustment_factor);
        cc->get_scheme()->mod_reduce_internal_in_place(ciphertext_adjusted, 1);
        ciphertext_adjusted->set_scaling_factor(target_sf);
        return ciphertext_adjusted;
    }

    return cc->compress(ciphertext, num_towers_to_keep);
}

Ciphertext<RnsPoly> CkksRnsMultiparty::int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                                      const PublicKey<RnsPoly> public_key) const {
    typename RnsPoly::DugType dug;
    RnsPoly crp(dug, params->get_element_params());
    crp.set_format(Format::EVALUATION);

    Ciphertext<RnsPoly> out_ctxt(std::make_shared<CiphertextImpl<RnsPoly>>(public_key));

    std::vector<RnsPoly> crp_elems;
    crp_elems.push_back(std::move(crp));
    out_ctxt->set_elements(std::move(crp_elems));
    out_ctxt->set_encoding_type(CKKS_PACKED_ENCODING);

    return out_ctxt;
}

Ciphertext<RnsPoly> CkksRnsMultiparty::int_mp_boot_random_element_gen(std::shared_ptr<CkksRnsCryptoParams> params,
                                                                      ConstCiphertext<RnsPoly>& ciphertext) const {
    const auto& ctxt_elems = ciphertext->get_elements();

    typename RnsPoly::DugType dug;
    RnsPoly crp(dug, ctxt_elems[0].get_params());
    crp.set_format(Format::EVALUATION);

    Ciphertext<RnsPoly> out_ctxt(std::make_shared<CiphertextImpl<RnsPoly>>(*ciphertext));

    std::vector<RnsPoly> crp_elems;
    crp_elems.push_back(std::move(crp));
    out_ctxt->set_elements(std::move(crp_elems));
    return out_ctxt;
}

// Subroutines for Interactive Multi-Party Bootstrapping
// Calculating RNS parameters
void precompute_rns_extension_tables(CryptoContext<RnsPoly>& cc, uint32_t from, uint32_t to,
                                     RnsExtensionTables& rns_ext_tables) {
    std::vector<NativeInteger> moduli_q;
    moduli_q.reserve(from);
    std::vector<NativeInteger> roots_q;
    roots_q.reserve(from);
    std::vector<NativeInteger> moduli_p;
    moduli_p.reserve(to - from);
    std::vector<NativeInteger> roots_p;
    roots_p.reserve(to - from);

    for (size_t i = 0; i < from; i++) {
        moduli_q.push_back(cc->get_crypto_parameters()->get_element_params()->get_params()[i]->get_modulus());
        roots_q.push_back(cc->get_crypto_parameters()->get_element_params()->get_params()[i]->get_root_of_unity());
    }

    for (size_t i = from; i < to; i++) {
        moduli_p.push_back(cc->get_crypto_parameters()->get_element_params()->get_params()[i]->get_modulus());
        roots_p.push_back(cc->get_crypto_parameters()->get_element_params()->get_params()[i]->get_root_of_unity());
    }

    size_t size_q = moduli_q.size();
    size_t size_p = moduli_p.size();
    BigInteger modulus_q(1);
    for (auto& it : moduli_q)
        modulus_q *= it;

    std::vector<NativeInteger> moduli_qp(size_q + size_p);
    std::vector<NativeInteger> roots_qp(size_q + size_p);

    // populate moduli for CRT basis Q
    for (size_t i = 0; i < size_q; i++) {
        moduli_qp[i] = moduli_q[i];
        roots_qp[i] = roots_q[i];
    }

    // populate moduli for CRT basis P
    for (size_t j = 0; j < size_p; j++) {
        moduli_qp[size_q + j] = moduli_p[j];
        roots_qp[size_q + j] = roots_p[j];
    }

    uint32_t ring_dim = cc->get_crypto_parameters()->get_element_params()->get_ring_dimension();
    rns_ext_tables.params_p = std::make_shared<RnsParams<BigInteger>>(2 * ring_dim, moduli_p, roots_p);
    rns_ext_tables.params_qp = std::make_shared<RnsParams<BigInteger>>(2 * ring_dim, moduli_qp, roots_qp);

    rns_ext_tables.q_hat_inv_modq.resize(size_q);
    rns_ext_tables.q_hat_inv_modq_precon.resize(size_q);
    for (uint32_t i = 0; i < size_q; i++) {
        BigInteger qi(moduli_q[i].convert_to_int());
        BigInteger q_hati = modulus_q / qi;
        rns_ext_tables.q_hat_inv_modq[i] = q_hati.mod_inverse(qi).mod(qi).convert_to_int();
        rns_ext_tables.q_hat_inv_modq_precon[i] =
                rns_ext_tables.q_hat_inv_modq[i].prep_mod_mul_const(qi.convert_to_int());
    }

    // compute the [Q/q_i]_{p_j}
    // used for homomorphic multiplication
    rns_ext_tables.q_hat_modp.resize(size_p, std::vector<NativeInteger>(size_q));
    for (uint32_t j = 0; j < size_p; j++) {
        BigInteger pj(moduli_p[j].convert_to_int());
        for (uint32_t i = 0; i < size_q; i++) {
            BigInteger qi(moduli_q[i].convert_to_int());
            BigInteger q_hati = modulus_q / qi;
            rns_ext_tables.q_hat_modp[j][i] = q_hati.mod(pj).convert_to_int();
        }
    }

    // compute the [\alpha*Q]p_j for 0 <= alpha <= size_q
    // used for homomorphic multiplication
    rns_ext_tables.alpha_q_modp.resize(size_q + 1, std::vector<NativeInteger>(size_p));
    for (uint32_t j = 0; j < size_p; j++) {
        BigInteger pj(moduli_p[j].convert_to_int());
        NativeInteger q_modpj = modulus_q.mod(pj).convert_to_int();
        for (uint32_t i = 0; i < size_q + 1; i++) {
            rns_ext_tables.alpha_q_modp[i][j] = q_modpj.mod_mul(NativeInteger(i), moduli_p[j]);
        }
    }

    const auto barrett_base128_bit(BigInteger(1).l_shift_eq(128));
    rns_ext_tables.modp_barrett_mu.resize(size_p);
    for (uint32_t j = 0; j < moduli_p.size(); j++) {
        rns_ext_tables.modp_barrett_mu[j] =
                (barrett_base128_bit / BigInteger(moduli_p[j])).convert_to_int<DoubleNativeInt>();
    }

    rns_ext_tables.q_inv.resize(size_q);
    for (size_t i = 0; i < size_q; i++) {
        rns_ext_tables.q_inv[i] = 1. / static_cast<double>(moduli_q[i].convert_to_int());
    }
}

// Utility function to compute noisy multiplication ( sk * poly + noise )
// noise will not be added if is_zero_noise is set to true (as in computing h_0,i)
RnsPoly compute_noisy_mult(CryptoContext<RnsPoly>& cc, const RnsPoly& sk, const RnsPoly& poly, bool is_zero_noise) {
    if (sk.get_num_of_elements() != poly.get_num_of_elements())
        CIPHER_THROW("Number of towers in input polys does not match!");
    RnsPoly res = sk * poly;
    if (false == is_zero_noise) {
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(cc->get_crypto_parameters());
        const RnsPoly::DggType& dgg = crypto_params->get_discrete_gaussian_generator();
        res += RnsPoly(dgg, poly.get_params(), Format::EVALUATION);
    }
    return res;
}

// Generate random mask
RnsPoly generate_mi(const RnsPoly& c1, uint32_t mask_bound_num_towers) {
    // only the parameters of the first mask_bound_num_towers towers are needed here, not their contents
    auto params = std::make_shared<RnsPoly::Params>(c1.get_params()->get_cyclotomic_order(),
                                                    c1.get_params()->get_param_partition(0, mask_bound_num_towers - 1));

    typename RnsPoly::DugType dug;
    return RnsPoly(dug, params, Format::EVALUATION);
}

// Compute h_{0,i}
RnsPoly generate_masked_decryption_share(CryptoContext<RnsPoly>& cc, const PrivateKey<RnsPoly> private_key,
                                         const RnsPoly& c1, RnsPoly& mi, uint32_t compression_level) {
    // reduce sk's num_towers to c1's num_towers
    RnsPoly sk = private_key->get_private_element().clone_towers(0, c1.get_all_elements().size() - 1);

    RnsPoly masked_decryption_share = compute_noisy_mult(cc, sk, c1, true);

    RnsPoly mi_copy = mi;

    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RnsExtensionTables mi_for_decryption_share_rns_ext_tables;  // extending Mi from R_t to R_q
    precompute_rns_extension_tables(cc, compression_level, c1.get_all_elements().size(),
                                    mi_for_decryption_share_rns_ext_tables);

    mi_copy.expand_crt_basis(
            mi_for_decryption_share_rns_ext_tables.params_qp, mi_for_decryption_share_rns_ext_tables.params_p,
            mi_for_decryption_share_rns_ext_tables.q_hat_inv_modq,
            mi_for_decryption_share_rns_ext_tables.q_hat_inv_modq_precon,
            mi_for_decryption_share_rns_ext_tables.q_hat_modp, mi_for_decryption_share_rns_ext_tables.alpha_q_modp,
            mi_for_decryption_share_rns_ext_tables.modp_barrett_mu, mi_for_decryption_share_rns_ext_tables.q_inv,
            EVALUATION);

    masked_decryption_share = masked_decryption_share - mi_copy;

    return masked_decryption_share;
}

// Compute h_{1,i}
RnsPoly generate_re_encryption_share(CryptoContext<RnsPoly>& cc, const PrivateKey<RnsPoly> private_key,
                                     ConstCiphertext<RnsPoly> a, RnsPoly& mi, uint32_t compression_level) {
    RnsPoly sk = private_key->get_private_element();
    auto negsk = sk.negate();
    RnsPoly re_encryption_share = compute_noisy_mult(cc, negsk, a->get_elements()[0], false);

    RnsPoly mi_copy = mi;
    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RnsExtensionTables mi_for_re_encryption_share_rns_ext_tables;  // extending Mi from R_t to R_Q
    precompute_rns_extension_tables(cc, compression_level, a->get_elements()[0].get_all_elements().size(),
                                    mi_for_re_encryption_share_rns_ext_tables);

    mi_copy.expand_crt_basis(mi_for_re_encryption_share_rns_ext_tables.params_qp,
                             mi_for_re_encryption_share_rns_ext_tables.params_p,
                             mi_for_re_encryption_share_rns_ext_tables.q_hat_inv_modq,
                             mi_for_re_encryption_share_rns_ext_tables.q_hat_inv_modq_precon,
                             mi_for_re_encryption_share_rns_ext_tables.q_hat_modp,
                             mi_for_re_encryption_share_rns_ext_tables.alpha_q_modp,
                             mi_for_re_encryption_share_rns_ext_tables.modp_barrett_mu,
                             mi_for_re_encryption_share_rns_ext_tables.q_inv, EVALUATION);
    re_encryption_share = re_encryption_share + mi_copy;

    return re_encryption_share;
}

std::vector<Ciphertext<RnsPoly>> CkksRnsMultiparty::int_mp_boot_decrypt(const PrivateKey<RnsPoly> private_key,
                                                                        ConstCiphertext<RnsPoly> ciphertext,
                                                                        ConstCiphertext<RnsPoly> a) const {
    // Generate maskedDecryptionShares: secretShare M_i and publicShare: s_i*c_1+e_{0,i} to compute h_{0,i}
    // Generate secretShare M_i \in R_{q*2^{\lambda}} where lambda is the security level
    // Calculate publicShare s_i*c_1 + e_{0,i} in R_{q*2^{\lambda}}
    // Calculate h_{0,i} = publicShare - secretShare

    auto cc = ciphertext->get_crypto_context();
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());

    auto compression_level = crypto_params->get_mp_int_boot_ciphertext_compression_level();

    auto& c1 = ciphertext->get_elements()[0];         // input ctxt must only include one element which is c1
    RnsPoly mi = generate_mi(c1, compression_level);  // Mi is in NTT domain

    // Encryption to Share protocol to compute: h_{0,i}
    RnsPoly mdsp = generate_masked_decryption_share(cc, private_key, c1, mi, compression_level);
    Ciphertext<RnsPoly> masked_decryption_share(std::make_shared<CiphertextImpl<RnsPoly>>(private_key));
    std::vector<RnsPoly> mds_elems;
    mds_elems.push_back(std::move(mdsp));
    masked_decryption_share->set_elements(std::move(mds_elems));

    // Generate reEncryptionShares: secretShare M_i (no need to recompute, use M_i from above)
    // and publicShare: -s_i*a + e_{1,i} in R_{Q}
    // Get screteShare M_i
    // Calculate publicShare: -s_i*a + e_{1,i}
    // // Calculate h_{1,i} = publicShare + secretShare

    // Shares to Encryption protocol to compute h_{1,i}
    RnsPoly rsp = generate_re_encryption_share(cc, private_key, a, mi, compression_level);
    Ciphertext<RnsPoly> re_encryption_share(std::make_shared<CiphertextImpl<RnsPoly>>(private_key));
    std::vector<RnsPoly> rs_elems;
    rs_elems.push_back(std::move(rsp));
    re_encryption_share->set_elements(std::move(rs_elems));

    std::vector<Ciphertext<RnsPoly>> result = {masked_decryption_share, re_encryption_share};

    return result;
}

std::vector<Ciphertext<RnsPoly>> CkksRnsMultiparty::int_mp_boot_add(
        std::vector<std::vector<Ciphertext<RnsPoly>>>& shares_pair_vec) const {
    if (shares_pair_vec.size() == 0) {
        CIPHER_THROW("No polynomials in input share(s).");
    }

    std::vector<Ciphertext<RnsPoly>> result = shares_pair_vec[0];
    for (size_t i = 1; i < shares_pair_vec.size(); i++) {
        // h_0 = h_0,0 + h_0,i
        result[0]->get_elements()[0] = result[0]->get_elements()[0] + shares_pair_vec[i][0]->get_elements()[0];
        // h_1 = h_1,0 + h_1,i
        result[1]->get_elements()[0] = result[1]->get_elements()[0] + shares_pair_vec[i][1]->get_elements()[0];
    }

    return result;
}

Ciphertext<RnsPoly> CkksRnsMultiparty::int_mp_boot_encrypt(const PublicKey<RnsPoly> public_key,
                                                           const std::vector<Ciphertext<RnsPoly>>& shares_pair,
                                                           ConstCiphertext<RnsPoly> a,
                                                           ConstCiphertext<RnsPoly> ciphertext) const {
    if (ciphertext->number_ciphertext_elements() == 0) {
        CIPHER_THROW("No polynomials in the input ciphertext.");
    }

    auto cc = ciphertext->get_crypto_context();

    RnsPoly c0_prime = ciphertext->get_elements()[0] + shares_pair[0]->get_elements()[0];
    // Init RNS parameters - we generate these params online as of now - should be cheap
    // Extending Mi parameters:
    RnsExtensionTables c0_for_re_encrypt_rns_ext_tables;  // extending c0 from R_q to R_Q
    precompute_rns_extension_tables(cc, c0_prime.get_all_elements().size(),
                                    a->get_elements()[0].get_all_elements().size(), c0_for_re_encrypt_rns_ext_tables);

    c0_prime.expand_crt_basis(
            c0_for_re_encrypt_rns_ext_tables.params_qp, c0_for_re_encrypt_rns_ext_tables.params_p,
            c0_for_re_encrypt_rns_ext_tables.q_hat_inv_modq, c0_for_re_encrypt_rns_ext_tables.q_hat_inv_modq_precon,
            c0_for_re_encrypt_rns_ext_tables.q_hat_modp, c0_for_re_encrypt_rns_ext_tables.alpha_q_modp,
            c0_for_re_encrypt_rns_ext_tables.modp_barrett_mu, c0_for_re_encrypt_rns_ext_tables.q_inv, EVALUATION);

    c0_prime = c0_prime + shares_pair[1]->get_elements()[0];

    Ciphertext<RnsPoly> out_ctxt(std::make_shared<CiphertextImpl<RnsPoly>>(public_key));

    std::vector<RnsPoly> out_elems;
    out_elems.reserve(2);
    out_elems.push_back(std::move(c0_prime));
    out_elems.push_back(std::move(a->get_elements()[0]));
    out_ctxt->set_elements(std::move(out_elems));

    // Ciphertext depth, level, and scaling factor should be
    // equal to that of the plaintext. However, Encrypt does
    // not take Plaintext as input (only RnsPoly), so we
    // don't have access to these here and we copy them
    // from the input ciphertext.

    out_ctxt->set_encoding_type(ciphertext->get_encoding_type());
    out_ctxt->set_scaling_factor(ciphertext->get_scaling_factor());
    out_ctxt->set_noise_scale_deg(ciphertext->get_noise_scale_deg());
    out_ctxt->set_level(0);
    out_ctxt->set_metadata_map(ciphertext->get_metadata_map());
    out_ctxt->set_slots(ciphertext->get_slots());

    return out_ctxt;
}

Ciphertext<RnsPoly> CkksRnsMultiparty::int_boot_adjust_scale(ConstCiphertext<RnsPoly> ciphertext) const {
    if (ciphertext->get_elements().empty())
        CIPHER_THROW("No polynomials in the input ciphertext");

    const std::shared_ptr<CkksRnsCryptoParams> crypto_params =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(ciphertext->get_crypto_parameters());

    auto st = crypto_params->get_scaling_technique();
    if (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL)
        CIPHER_THROW("Current composite scaling implementation does not yet support interactive bootstrapping");

    auto cc = ciphertext->get_crypto_context();

    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT) {
        if (ciphertext->get_elements()[0].get_num_of_elements() < 3)
            CIPHER_THROW("Not enough towers in the input polynomial");

        auto ciphertext_adjusted = cc->compress(ciphertext, 3);

        uint32_t lvl = st == FLEXIBLEAUTO ? 0 : 1;
        double target_sf = crypto_params->get_scaling_factor_real(lvl);
        double source_sf = ciphertext_adjusted->get_scaling_factor();
        uint32_t num_towers = ciphertext_adjusted->get_elements()[0].get_num_of_elements();
        double mod_to_drop =
                crypto_params->get_element_params()->get_params()[num_towers - 1]->get_modulus().convert_to_double();
        double adjustment_factor = (target_sf / source_sf) * (mod_to_drop / source_sf);

        // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
        // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for CIPHER_NATIVE_INT = 64.

        ciphertext_adjusted = cc->eval_mult(ciphertext_adjusted, adjustment_factor);

        ciphertext_adjusted = cc->get_scheme()->mod_reduce_internal(ciphertext_adjusted, BASE_NUM_LEVELS_TO_DROP);
        ciphertext_adjusted->set_scaling_factor(target_sf);

        return ciphertext_adjusted;
    }

    if (ciphertext->get_elements()[0].get_num_of_elements() < 2)
        CIPHER_THROW("Not enough towers in the input polynomial");
    return cc->compress(ciphertext, 2);
}

}  // namespace cipher
