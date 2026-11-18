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

#include <ostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "cipher/util/diagnostic_output.h"

using namespace cipher;

namespace {

// Installs a capture buffer on both channels and restores the previous streams
// when it goes out of scope, so a failing expectation cannot leave the channels
// pointing at a destroyed stream.
class ScopedDiagnosticCapture {
  public:
    ScopedDiagnosticCapture() : previous_err_(set_cipher_err_stream(err_)), previous_out_(set_cipher_out_stream(out_)) {}

    ~ScopedDiagnosticCapture() {
        set_cipher_err_stream(previous_err_);
        set_cipher_out_stream(previous_out_);
    }

    std::string err() const {
        return err_.str();
    }
    std::string Out() const {
        return out_.str();
    }

  private:
    std::ostringstream err_;
    std::ostringstream out_;
    std::ostream& previous_err_;
    std::ostream& previous_out_;
};

}  // namespace

TEST(UTDiagnosticOutput, redirect_captures_each_channel_separately) {
    ScopedDiagnosticCapture capture;

    CIPHER_DIAGNOSTIC_ERR << "to err" << std::endl;
    CIPHER_DIAGNOSTIC_OUT << "to out" << std::endl;

    EXPECT_EQ(capture.err(), "to err\n");
    EXPECT_EQ(capture.Out(), "to out\n");
}

TEST(UTDiagnosticOutput, manipulators_and_chaining_work) {
    ScopedDiagnosticCapture capture;

    CIPHER_DIAGNOSTIC_ERR << std::hex << 255 << " " << std::dec << 255 << std::endl;

    EXPECT_EQ(capture.err(), "ff 255\n");
    EXPECT_TRUE(capture.Out().empty());
}

TEST(UTDiagnosticOutput, setter_returns_the_previously_installed_stream) {
    std::ostringstream first;
    std::ostringstream second;

    std::ostream& original = set_cipher_err_stream(first);
    std::ostream& returned = set_cipher_err_stream(second);
    EXPECT_EQ(&returned, &first);

    CIPHER_DIAGNOSTIC_ERR << "second" << std::endl;
    EXPECT_TRUE(first.str().empty());
    EXPECT_EQ(second.str(), "second\n");

    // restoring gives back the stream the channel started on
    EXPECT_EQ(&set_cipher_err_stream(original), &second);
    EXPECT_EQ(&set_cipher_err_stream(original), &original);
}
