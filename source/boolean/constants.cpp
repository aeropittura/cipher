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

#include "cipher/boolean/constants.h"
#include "cipher/util/exception.h"

namespace cipher {

namespace {

constexpr const char* const k_param_set_names[] = {
#define BINFHE_PARAMSET_NAME(name, methods) #name,
        BINFHE_PARAMSET_LIST(BINFHE_PARAMSET_NAME)
#undef BINFHE_PARAMSET_NAME
};

constexpr uint32_t k_param_set_methods[] = {
#define BINFHE_PARAMSET_METHODS(name, methods) methods,
        BINFHE_PARAMSET_LIST(BINFHE_PARAMSET_METHODS)
#undef BINFHE_PARAMSET_METHODS
};

constexpr size_t k_param_set_count = sizeof(k_param_set_names) / sizeof(k_param_set_names[0]);
static_assert(k_param_set_count == sizeof(k_param_set_methods) / sizeof(k_param_set_methods[0]));

}  // namespace

std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f) {
    auto i = static_cast<size_t>(f);
    return s << (i < k_param_set_count ? k_param_set_names[i] : "UNKNOWN");
}

BINFHE_PARAMSET convert_to_binfhe_paramset(const std::string& str) {
    for (size_t i = 0; i < k_param_set_count; ++i)
        if (str == k_param_set_names[i])
            return static_cast<BINFHE_PARAMSET>(i);
    CIPHER_THROW(std::string("Unknown BINFHE_PARAMSET ") + str);
}

std::ostream& operator<<(std::ostream& s, BINFHE_OUTPUT f) {
    switch (f) {
        case FRESH:
            s << "FRESH";
            break;
        case BOOTSTRAPPED:
            s << "BOOTSTRAPPED";
            break;
        case LARGE_DIM:
            s << "LARGE_DIM";
            break;
        case SMALL_DIM:
            s << "SMALL_DIM";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINFHE_METHOD f) {
    switch (f) {
        case AP:
            s << "DM";
            break;
        case GINX:
            s << "CGGI";
            break;
        case LMKCDEY:
            s << "LMKCDEY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, BINGATE f) {
    switch (f) {
        case OR:
            s << "OR";
            break;
        case AND:
            s << "AND";
            break;
        case NOR:
            s << "NOR";
            break;
        case NAND:
            s << "NAND";
            break;
        case XOR:
        case XOR_FAST:
            s << "XOR";
            break;
        case XNOR:
        case XNOR_FAST:
            s << "XNOR";
            break;
        case AND3:
            s << "AND3";
            break;
        case OR3:
            s << "OR3";
            break;
        case AND4:
            s << "AND4";
            break;
        case OR4:
            s << "OR4";
            break;
        case MAJORITY:
            s << "MAJORITY";
            break;
        case CMUX:
            s << "CMUX";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

void is_method_compatible(BINFHE_METHOD m, BINFHE_PARAMSET p) {
    if (m != AP && m != GINX && m != LMKCDEY)
        CIPHER_THROW("Invalid BINFHE_METHOD");
    auto i = static_cast<size_t>(p);
    if (i >= k_param_set_count || !(k_param_set_methods[i] & (1u << m)))
        CIPHER_THROW("Specified BINFHE_METHOD and BINFHE_PARAMSET are incompatible");
}

};  // namespace cipher
