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
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cipher/fhe/bgv/pke.h"

#include <cstdint>
#include <vector>

#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/bgv/crypto_params.h"

namespace cipher {

DecryptResult BgvRnsPke::decrypt(ConstCiphertext<RnsPoly> ciphertext, const PrivateKey<RnsPoly> private_key,
                                 NativePoly* plaintext) const {
    const auto crypto_params = std::dynamic_pointer_cast<BgvRnsCryptoParams>(ciphertext->get_crypto_parameters());
    const std::vector<RnsPoly>& cv = ciphertext->get_elements();
    size_t size_ql = cv[0].get_params()->get_params().size();

    RnsPoly b;
    NativeInteger scaling_factor_int = ciphertext->get_scaling_factor_int();
    if (cv[0].get_format() == Format::EVALUATION) {
        b = RnsPke::decrypt_core(cv, private_key);
        b.set_format(Format::COEFFICIENT);
        if (size_ql > 0) {
            for (size_t i = size_ql - 1; i > 0; --i) {
                b.mod_reduce(crypto_params->get_plaintext_modulus(), crypto_params->get_t_modq_precon(),
                             crypto_params->get_negt_inv_modq(i), crypto_params->get_negt_inv_modq_precon(i),
                             crypto_params->get_ql_inv_modq(i), crypto_params->get_ql_inv_modq_precon(i));
            }
            // TODO: Use pre-computed scaling factor at level L.
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
    } else {
        std::vector<RnsPoly> ct(cv);
        if (size_ql > 0) {
            for (size_t j = size_ql - 1; j > 0; j--) {
                for (uint32_t i = 0; i < ct.size(); i++) {
                    ct[i].mod_reduce(crypto_params->get_plaintext_modulus(), crypto_params->get_t_modq_precon(),
                                     crypto_params->get_negt_inv_modq(j), crypto_params->get_negt_inv_modq_precon(j),
                                     crypto_params->get_ql_inv_modq(j), crypto_params->get_ql_inv_modq_precon(j));
                }
            }
            if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO ||
                crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
                for (size_t i = 0; i < size_ql - 1; i++) {
                    NativeInteger mod_reduce_factor = crypto_params->get_mod_reduce_factor_int(size_ql - 1 - i);
                    NativeInteger mod_reduce_factor_inv =
                            mod_reduce_factor.mod_inverse(crypto_params->get_plaintext_modulus());
                    scaling_factor_int =
                            scaling_factor_int.mod_mul(mod_reduce_factor_inv, crypto_params->get_plaintext_modulus());
                }
            }
        }

        b = RnsPke::decrypt_core(ct, private_key);
        b.set_format(Format::COEFFICIENT);
    }

    *plaintext = b.get_element_at_index(0).decryption_crt_interpolate(crypto_params->get_plaintext_modulus());

    return DecryptResult(plaintext->get_length(), scaling_factor_int);
}

}  // namespace cipher
