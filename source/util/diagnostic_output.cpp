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

// Built-in diagnostic sink; see diagnostic_output.h for the interface contract.

#include "cipher/util/diagnostic_output.h"

#include "cipher/config.h"

#ifdef CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK

    #include <iostream>

namespace cipher {

namespace {
std::ostream* g_err_stream = &std::cerr;
std::ostream* g_out_stream = &std::cout;
}  // namespace

namespace internal_diagnostics {

std::ostream& cipher_err_stream() {
    return *g_err_stream;
}
std::ostream& cipher_out_stream() {
    return *g_out_stream;
}

}  // namespace internal_diagnostics

std::ostream& set_cipher_err_stream(std::ostream& os) {
    std::ostream& previous = *g_err_stream;
    g_err_stream = &os;
    return previous;
}
std::ostream& set_cipher_out_stream(std::ostream& os) {
    std::ostream& previous = *g_out_stream;
    g_out_stream = &os;
    return previous;
}

}  // namespace cipher

#endif  // CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK
