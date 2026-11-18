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
  framework for exceptions in OpenFHE
 */

#ifndef CIPHER_UTIL_EXCEPTION_H_
#define CIPHER_UTIL_EXCEPTION_H_

#include <cstddef>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "cipher/util/call_stack.h"

namespace cipher {

/**
 * @brief Captures an exception thrown inside an OpenMP parallel region or thread so it can be rethrown in the
 * calling thread after the region ends.
 *
 * Exceptions thrown inside a critical region or an OpenMP thread must be caught in the thread where they were
 * thrown. Declare an instance before the region, call capture_exception() from a catch(...) block inside it (or
 * wrap the body in run()), and call rethrow() after the region; see the usage example below the class.
 */
class ThreadException {
    std::exception_ptr ptr_;
    std::mutex lock_;

  public:
    ThreadException() : ptr_(nullptr) {}
    ~ThreadException() {}
    /**
     * @brief Rethrows the captured exception, if any, in the calling thread; does nothing when none was captured.
     */
    void rethrow() {
        if (this->ptr_)
            std::rethrow_exception(this->ptr_);
    }
    /**
     * @brief Stores the exception currently being handled (call from inside a catch block); thread-safe, the last
     * captured exception wins.
     */
    void capture_exception() {
        std::unique_lock<std::mutex> guard(this->lock_);
        this->ptr_ = std::current_exception();
    }

    /**
     * @brief Invokes f(params...) and captures any exception it throws instead of letting it escape the thread.
     * @param f callable to run
     * @param params arguments forwarded to f
     */
    template <typename Function, typename... Parameters>
    void run(Function f, Parameters... params) {
        try {
            f(params...);
        } catch (...) {
            capture_exception();
        }
    }
};

// how  to use ThreadException
// To use this, declare an instance of the object before the critical
// region/thread, catch exceptions in thread with capture_exception, then after
// the region call object.rethrow()
// #pragma omp parallel for
// for (unsigned i = 0; i < rv.size(); i++) try {
//     rv.polys[i] = (polys[i].*f)();
//   } catch (...) {
//     e.capture_exception();
//   }
// e.rethrow();
//
// // use of Run looks like:
// ThreadException e;
// #pragma omp parallel for
// for (int i = 0; i < n; i++) {
//   e.run([=] {
//     // code that might throw
//     // ...
//   });
// }
// e.rethrow();

/**
 * @brief Exception type thrown by OpenFHE, normally through the CIPHER_THROW macro. Records the error
 * description together with the throw site (file, function, line) and the call stack at construction; what()
 * returns "file:l.line:function(): description".
 */
class CipherException : public std::exception {
    // clang-format off
    std::string error_description_;
    std::string file_name_;
    std::string func_name_;
    size_t line_number_{0};

    std::string error_message_;
    std::vector<std::string> call_stack_;

    static std::string build_error_message(const std::string& file,
                                         const std::string& func,
                                         std::size_t line,
                                         const std::string& desc) {
        return file + ":l." + std::to_string(line) + ":" + func + "(): " + desc;
    }

public:
    /**
     * @brief Constructs the exception and captures the call stack.
     * @param error_description description of the error
     * @param file_name source file of the throw site (__FILE__)
     * @param func_name function of the throw site (__func__)
     * @param line_number line of the throw site (__LINE__)
     */
    explicit CipherException(const std::string_view error_description,
                              const std::string file_name,
                              const std::string func_name,
                              size_t line_number)
        : error_description_(error_description),
          file_name_(file_name),
          func_name_(func_name),
          line_number_(line_number),
          error_message_(build_error_message(file_name_, func_name_, line_number_, error_description_)),
          call_stack_(get_call_stack()) {}
    // clang-format on

    ~CipherException() override = default;
    CipherException(const CipherException&) = default;
    CipherException& operator=(const CipherException&) = default;

    /**
     * @brief Returns the formatted error message "file:l.line:function(): description".
     * @return the error message
     */
    const char* what() const noexcept override {
        return error_message_.c_str();
    }

    /**
     * @brief Returns the call stack captured when the exception was constructed, one frame per entry (empty when
     * call-stack capture is not available in this build).
     * @return the call stack frames
     */
    std::vector<std::string> get_call_stack_as_vector() const {
        return call_stack_;
    }

    // get_call_stack_as_string() was added to be used by JSON logger. the implementtion will follow
    /**
     * @brief Placeholder for a single-string rendering of the call stack intended for a JSON logger.
     * @return an empty string; the implementation is not yet provided
     */
    std::string get_call_stack_as_string() const {
        return std::string();

        // if (call_stack_.empty())
        //     return {};

        // std::string ret = call_stack_.front();
        // for (std::size_t i = 1; i < call_stack_.size(); ++i) {
        //     ret += '\n';
        //     ret += call_stack_[i];
        // }
        // return ret;
    }
};

/**
 * @brief Throws an CipherException with the given description, tagged with the current file, function, and line.
 * @param desc error description (anything convertible to std::string_view)
 */
#define CIPHER_THROW(desc) throw cipher::CipherException((desc), __FILE__, __func__, __LINE__)

}  // namespace cipher

#endif  // CIPHER_UTIL_EXCEPTION_H_
