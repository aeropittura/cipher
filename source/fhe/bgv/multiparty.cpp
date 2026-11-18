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
Description:

This code implements RNS variants of the Cheon-Kim-Kim-Song scheme.

The CKKS scheme is introduced in the following paper:
- Jung Hee Cheon, Andrey Kim, Miran Kim, and Yongsoo Song. Homomorphic
encryption for arithmetic of approximate numbers. Cryptology ePrint Archive,
Report 2016/421, 2016. https://eprint.iacr.org/2016/421.

 Our implementation builds from the designs here:
 - Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Kurt Rohloff, and Vinod
Vaikuntanathan. Optimized homomorphic encryption solution for secure genomewide
association studies. Cryptology ePrint Archive, Report 2019/223, 2019.
https://eprint.iacr.org/2019/223.
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate
homomorphic encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#define PROFILE

#include "cipher/fhe/bgv/multiparty.h"

#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/bgv/crypto_params.h"

namespace cipher {

DecryptResult BgvRnsMultiparty::multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                                          NativePoly* plaintext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());

    const std::vector<RnsPoly>& cv0 = ciphertext_vec[0]->get_elements();
    RnsPoly b = cv0[0];
    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        const std::vector<RnsPoly>& cvi = ciphertext_vec[i]->get_elements();
        b += cvi[0];
    }
    b.set_format(Format::COEFFICIENT);

    size_t size_ql = b.get_num_of_elements();

    NativeInteger scaling_factor_int = ciphertext_vec[0]->get_scaling_factor_int();
    if (size_ql > 0) {
        for (size_t i = size_ql - 1; i > 0; --i) {
            b.mod_reduce(crypto_params->get_plaintext_modulus(), crypto_params->get_t_modq_precon(),
                         crypto_params->get_negt_inv_modq(i), crypto_params->get_negt_inv_modq_precon(i),
                         crypto_params->get_ql_inv_modq(i), crypto_params->get_ql_inv_modq_precon(i));
        }
        if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
            crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
            for (size_t i = 0; i < size_ql - 1; ++i) {
                NativeInteger mod_reduce_factor = crypto_params->get_mod_reduce_factor_int(size_ql - 1 - i);
                NativeInteger mod_reduce_factor_inv =
                        mod_reduce_factor.mod_inverse(crypto_params->get_plaintext_modulus());
                scaling_factor_int =
                        scaling_factor_int.mod_mul(mod_reduce_factor_inv, crypto_params->get_plaintext_modulus());
            }
        }
    }

    *plaintext = b.get_element_at_index(0).decryption_crt_interpolate(crypto_params->get_plaintext_modulus());

    return DecryptResult(plaintext->get_length(), scaling_factor_int);
}

DecryptResult BgvRnsMultiparty::multiparty_decrypt_fusion(const std::vector<Ciphertext<RnsPoly>>& ciphertext_vec,
                                                          Poly* plaintext) const {
    const auto crypto_params =
            std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext_vec[0]->get_crypto_parameters());

    const std::vector<RnsPoly>& cv0 = ciphertext_vec[0]->get_elements();

    RnsPoly b = cv0[0];
    for (size_t i = 1; i < ciphertext_vec.size(); i++) {
        const std::vector<RnsPoly>& cvi = ciphertext_vec[i]->get_elements();
        b += cvi[0];
    }
    b.set_format(Format::COEFFICIENT);

    *plaintext = b.crt_interpolate().mod(crypto_params->get_plaintext_modulus());

    return DecryptResult(plaintext->get_length());
}

}  // namespace cipher
