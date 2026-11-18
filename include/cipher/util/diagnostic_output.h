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
  Pluggable diagnostic output for OpenFHE. CIPHER_DIAGNOSTIC_ERR / CIPHER_DIAGNOSTIC_OUT
  yield std::ostream& and support normal stream operators and manipulators.
  By default they write to std::cerr / std::cout; the setters below redirect
  them at runtime.

  To omit the built-in sink, build with -DWITH_DEFAULT_LOG_SINK=OFF and
  provide definitions of both internal_diagnostics accessors and any setters
  used by the application. This allows sinks without std::cerr / std::cout.
*/

#ifndef CIPHER_UTIL_DIAGNOSTIC_OUTPUT_H_
#define CIPHER_UTIL_DIAGNOSTIC_OUTPUT_H_

#include <ostream>

namespace cipher {

// Redirect the channels at runtime and return the stream that was previously
// installed, so a caller can restore it afterwards. The referenced stream must
// outlive any subsequent OpenFHE diagnostic. Intended to be called once during
// initialization; concurrent use with library diagnostics is the
// caller's responsibility.
/**
 * @brief Redirects the diagnostic error channel (CIPHER_DIAGNOSTIC_ERR, std::cerr by default) to another
 * stream. The stream must outlive any later OpenFHE diagnostic; call once during initialization.
 * @param os stream to install
 * @return the stream that was previously installed, so the caller can restore it
 */
std::ostream& set_cipher_err_stream(std::ostream& os);
/**
 * @brief Redirects the diagnostic output channel (CIPHER_DIAGNOSTIC_OUT, std::cout by default) to another
 * stream. The stream must outlive any later OpenFHE diagnostic; call once during initialization.
 * @param os stream to install
 * @return the stream that was previously installed, so the caller can restore it
 */
std::ostream& set_cipher_out_stream(std::ostream& os);

namespace internal_diagnostics {

// Implementation hooks; use the logging macros to emit diagnostics.
/**
 * @brief Implementation hook behind CIPHER_DIAGNOSTIC_ERR; use the macro rather than calling this directly.
 * @return the currently installed diagnostic error stream
 */
std::ostream& cipher_err_stream();
/**
 * @brief Implementation hook behind CIPHER_DIAGNOSTIC_OUT; use the macro rather than calling this directly.
 * @return the currently installed diagnostic output stream
 */
std::ostream& cipher_out_stream();

}  // namespace internal_diagnostics

}  // namespace cipher

#define CIPHER_DIAGNOSTIC_ERR (::cipher::internal_diagnostics::cipher_err_stream())
#define CIPHER_DIAGNOSTIC_OUT (::cipher::internal_diagnostics::cipher_out_stream())

#endif  // CIPHER_UTIL_DIAGNOSTIC_OUTPUT_H_
