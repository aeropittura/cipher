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

#include <cstdint>
#include <ostream>
#include <string>

#include "cipher/fhe/constants.h"
#include "cipher/util/exception.h"

namespace cipher {

std::ostream& operator<<(std::ostream& s, PkeSchemeFeature f) {
    switch (f) {
        case PKE:
            s << "PKE";
            break;
        case KEYSWITCH:
            s << "KEYSWITCH";
            break;
        case PRE:
            s << "PRE";
            break;
        case LEVELEDSHE:
            s << "LEVELEDSHE";
            break;
        case ADVANCEDSHE:
            s << "ADVANCEDSHE";
            break;
        case MULTIPARTY:
            s << "MULTIPARTY";
            break;
        case FHE:
            s << "FHE";
            break;
        case SCHEMESWITCH:
            s << "SCHEMESWITCH";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ScalingTechnique convert_to_scaling_technique(const std::string& str) {
    if (str == "FIXEDMANUAL")
        return FIXEDMANUAL;
    else if (str == "FIXEDAUTO")
        return FIXEDAUTO;
    else if (str == "FLEXIBLEAUTO")
        return FLEXIBLEAUTO;
    else if (str == "FLEXIBLEAUTOEXT")
        return FLEXIBLEAUTOEXT;
    else if (str == "COMPOSITESCALINGAUTO")
        return COMPOSITESCALINGAUTO;
    else if (str == "COMPOSITESCALINGMANUAL")
        return COMPOSITESCALINGMANUAL;
    else if (str == "NORESCALE")
        return NORESCALE;

    std::string err_msg(std::string("Unknown ScalingTechnique ") + str);
    CIPHER_THROW(err_msg);
}
ScalingTechnique convert_to_scaling_technique(uint32_t num) {
    auto sc_tech = static_cast<ScalingTechnique>(num);
    switch (sc_tech) {
        case FIXEDMANUAL:
        case FIXEDAUTO:
        case FLEXIBLEAUTO:
        case FLEXIBLEAUTOEXT:
        case COMPOSITESCALINGAUTO:
        case COMPOSITESCALINGMANUAL:
        case NORESCALE:
            // case INVALID_RS_TECHNIQUE:
            return sc_tech;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for ScalingTechnique ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, ScalingTechnique t) {
    switch (t) {
        case FIXEDMANUAL:
            s << "FIXEDMANUAL";
            break;
        case FIXEDAUTO:
            s << "FIXEDAUTO";
            break;
        case FLEXIBLEAUTO:
            s << "FLEXIBLEAUTO";
            break;
        case FLEXIBLEAUTOEXT:
            s << "FLEXIBLEAUTOEXT";
            break;
        case COMPOSITESCALINGAUTO:
            s << "COMPOSITESCALINGAUTO";
            break;
        case COMPOSITESCALINGMANUAL:
            s << "COMPOSITESCALINGMANUAL";
            break;
        case NORESCALE:
            s << "NORESCALE";
            break;
        case INVALID_RS_TECHNIQUE:
            s << "INVALID_RS_TECHNIQUE";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ProxyReEncryptionMode convert_to_proxy_re_encryption_mode(const std::string& str) {
    if (str == "NOT_SET")
        return NOT_SET;
    else if (str == "INDCPA")
        return INDCPA;
    else if (str == "FIXED_NOISE_HRA")
        return FIXED_NOISE_HRA;
    else if (str == "NOISE_FLOODING_HRA")
        return NOISE_FLOODING_HRA;

    std::string err_msg(std::string("Unknown ProxyReEncryptionMode ") + str);
    CIPHER_THROW(err_msg);
}
ProxyReEncryptionMode convert_to_proxy_re_encryption_mode(uint32_t num) {
    auto encr_mode = static_cast<ProxyReEncryptionMode>(num);
    switch (encr_mode) {
        // case NOT_SET:
        case INDCPA:
        case FIXED_NOISE_HRA:
        case NOISE_FLOODING_HRA:
            return encr_mode;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for ProxyReEncryptionMode ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p) {
    switch (p) {
        case NOT_SET:
            s << "NOT_SET";
            break;
        case INDCPA:
            s << "INDCPA";
            break;
        case FIXED_NOISE_HRA:
            s << "FIXED_NOISE_HRA";
            break;
        case NOISE_FLOODING_HRA:
            s << "NOISE_FLOODING_HRA";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

MultipartyMode convert_to_multiparty_mode(const std::string& str) {
    if (str == "INVALID_MULTIPARTY_MODE")
        return INVALID_MULTIPARTY_MODE;
    else if (str == "FIXED_NOISE_MULTIPARTY")
        return FIXED_NOISE_MULTIPARTY;
    else if (str == "NOISE_FLOODING_MULTIPARTY")
        return NOISE_FLOODING_MULTIPARTY;

    std::string err_msg(std::string("Unknown MultipartyMode ") + str);
    CIPHER_THROW(err_msg);
}
MultipartyMode convert_to_multiparty_mode(uint32_t num) {
    auto mpty_mode = static_cast<MultipartyMode>(num);
    switch (mpty_mode) {
        // case INVALID_MULTIPARTY_MODE:
        case FIXED_NOISE_MULTIPARTY:
        case NOISE_FLOODING_MULTIPARTY:
            return mpty_mode;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for MultipartyMode ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, MultipartyMode t) {
    switch (t) {
        case INVALID_MULTIPARTY_MODE:
            s << "INVALID_MULTIPARTY_MODE";
            break;
        case FIXED_NOISE_MULTIPARTY:
            s << "FIXED_NOISE_MULTIPARTY";
            break;
        case NOISE_FLOODING_MULTIPARTY:
            s << "NOISE_FLOODING_MULTIPARTY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

ExecutionMode convert_to_execution_mode(const std::string& str) {
    if (str == "EXEC_EVALUATION")
        return EXEC_EVALUATION;
    else if (str == "EXEC_NOISE_ESTIMATION")
        return EXEC_NOISE_ESTIMATION;

    std::string err_msg(std::string("Unknown ExecutionMode ") + str);
    CIPHER_THROW(err_msg);
}
ExecutionMode convert_to_execution_mode(uint32_t num) {
    auto exec_mode = static_cast<ExecutionMode>(num);
    switch (exec_mode) {
        case EXEC_EVALUATION:
        case EXEC_NOISE_ESTIMATION:
            return exec_mode;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for ExecutionMode ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, ExecutionMode t) {
    switch (t) {
        case EXEC_EVALUATION:
            s << "EXEC_EVALUATION";
            break;
        case EXEC_NOISE_ESTIMATION:
            s << "EXEC_NOISE_ESTIMATION";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

DecryptionNoiseMode convert_to_decryption_noise_mode(const std::string& str) {
    if (str == "FIXED_NOISE_DECRYPT")
        return FIXED_NOISE_DECRYPT;
    else if (str == "NOISE_FLOODING_DECRYPT")
        return NOISE_FLOODING_DECRYPT;

    std::string err_msg(std::string("Unknown DecryptionNoiseMode ") + str);
    CIPHER_THROW(err_msg);
}
DecryptionNoiseMode convert_to_decryption_noise_mode(uint32_t num) {
    auto noise_mode = static_cast<DecryptionNoiseMode>(num);
    switch (noise_mode) {
        case FIXED_NOISE_DECRYPT:
        case NOISE_FLOODING_DECRYPT:
            return noise_mode;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for DecryptionNoiseMode ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, DecryptionNoiseMode t) {
    switch (t) {
        case FIXED_NOISE_DECRYPT:
            s << "FIXED_NOISE_DECRYPT";
            break;
        case NOISE_FLOODING_DECRYPT:
            s << "NOISE_FLOODING_DECRYPT";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

KeySwitchTechnique convert_to_key_switch_technique(const std::string& str) {
    if (str == "BV")
        return BV;
    else if (str == "HYBRID")
        return HYBRID;

    std::string err_msg(std::string("Unknown KeySwitchTechnique ") + str);
    CIPHER_THROW(err_msg);
}
KeySwitchTechnique convert_to_key_switch_technique(uint32_t num) {
    auto ks_tech = static_cast<KeySwitchTechnique>(num);
    switch (ks_tech) {
        // case INVALID_KS_TECH:
        case BV:
        case HYBRID:
            return ks_tech;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for KeySwitchTechnique ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t) {
    switch (t) {
        case BV:
            s << "BV";
            break;
        case HYBRID:
            s << "HYBRID";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

EncryptionTechnique convert_to_encryption_technique(const std::string& str) {
    if (str == "STANDARD")
        return STANDARD;
    else if (str == "EXTENDED")
        return EXTENDED;

    std::string err_msg(std::string("Unknown EncryptionTechnique ") + str);
    CIPHER_THROW(err_msg);
}
EncryptionTechnique convert_to_encryption_technique(uint32_t num) {
    auto encr_tech = static_cast<EncryptionTechnique>(num);
    switch (encr_tech) {
        case STANDARD:
        case EXTENDED:
            return encr_tech;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for EncryptionTechnique ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t) {
    switch (t) {
        case STANDARD:
            s << "STANDARD";
            break;
        case EXTENDED:
            s << "EXTENDED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

MultiplicationTechnique convert_to_multiplication_technique(const std::string& str) {
    if (str == "BEHZ")
        return BEHZ;
    else if (str == "HPS")
        return HPS;
    else if (str == "HPSPOVERQ")
        return HPSPOVERQ;
    else if (str == "HPSPOVERQLEVELED")
        return HPSPOVERQLEVELED;

    std::string err_msg(std::string("Unknown MultiplicationTechnique ") + str);
    CIPHER_THROW(err_msg);
}
MultiplicationTechnique convert_to_multiplication_technique(uint32_t num) {
    auto mult_tech = static_cast<MultiplicationTechnique>(num);
    switch (mult_tech) {
        case BEHZ:
        case HPS:
        case HPSPOVERQ:
        case HPSPOVERQLEVELED:
            return mult_tech;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for MultiplicationTechnique ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t) {
    switch (t) {
        case BEHZ:
            s << "BEHZ";
            break;
        case HPS:
            s << "HPS";
            break;
        case HPSPOVERQ:
            s << "HPSPOVERQ";
            break;
        case HPSPOVERQLEVELED:
            s << "HPSPOVERQLEVELED";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, PlaintextEncodings p) {
    switch (p) {
        case COEF_PACKED_ENCODING:
            s << "COEF_PACKED_ENCODING";
            break;
        case PACKED_ENCODING:
            s << "PACKED_ENCODING";
            break;
        case STRING_ENCODING:
            s << "STRING_ENCODING";
            break;
        case CKKS_PACKED_ENCODING:
            s << "CKKS_PACKED_ENCODING";
            break;
        case INVALID_ENCODING:
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

CompressionLevel convert_to_compression_level(const std::string& str) {
    if (str == "COMPACT")
        return COMPACT;
    else if (str == "SLACK")
        return SLACK;

    std::string err_msg(std::string("Unknown CompressionLevel ") + str);
    CIPHER_THROW(err_msg);
}
CompressionLevel convert_to_compression_level(uint32_t num) {
    auto compression_level = static_cast<CompressionLevel>(num);
    switch (compression_level) {
        case COMPACT:
        case SLACK:
            return compression_level;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for CompressionLevel ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, CompressionLevel p) {
    switch (p) {
        case COMPACT:
            s << "COMPACT";
            break;
        case SLACK:
            s << "SLACK";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

CkksDataType convert_to_ckks_data_type(const std::string& str) {
    if (str == "REAL")
        return REAL;
    else if (str == "COMPLEX")
        return COMPLEX;

    std::string err_msg(std::string("Unknown CKKSDataType ") + str);
    CIPHER_THROW(err_msg);
}
CkksDataType convert_to_ckks_data_type(uint32_t num) {
    auto data_type = static_cast<CkksDataType>(num);
    switch (data_type) {
        case REAL:
            return data_type;
        case COMPLEX:
            return data_type;
        default:
            break;
    }

    std::string err_msg(std::string("Unknown value for CKKSDataType ") + std::to_string(num));
    CIPHER_THROW(err_msg);
}
std::ostream& operator<<(std::ostream& s, CkksDataType t) {
    switch (t) {
        case REAL:
            s << "REAL";
            break;
        case COMPLEX:
            s << "COMPLEX";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

}  // namespace cipher
