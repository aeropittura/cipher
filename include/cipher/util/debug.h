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
  This file contains macros and associated helper functions for quick cerr oriented debugging
  that can be quickly enabled and disabled. It also contains functions for timing code
 */

#ifndef CIPHER_UTIL_DEBUG_H_
#define CIPHER_UTIL_DEBUG_H_

/* defining NDEBUG in the compile line turns everything off.
   unless PROFILE is defined in the file before all includes,'
   in which case TIC/TOC will still work and PROFILELOG() can be
   used for logging results to the diagnostic output channel, and
   CIPHER_DEBUG() will remain silent. dbg_flag does not get used by PROFILELOG()
 */

#include <time.h>

#include <chrono>  // for timing
#include <utility>

#include "cipher/util/diagnostic_output.h"
#include "cipher/util/inttypes.h"

#if !defined(NDEBUG)

    // note that for the following dbg_flag needs to be defined in some scope using
    // CIPHER_DEBUG_FLAG
    #define CIPHER_DEBUG_FLAG(x) bool dbg_flag = x;

    // debugging macro prints value of x on cerr
    #define CIPHER_DEBUG(x)                              \
        do {                                              \
            if (dbg_flag) {                               \
                CIPHER_DIAGNOSTIC_ERR << x << std::endl; \
            }                                             \
        } while (0)

    // debugging macro prints typography of x and value of x on cerr
    #define CIPHER_DEBUGEXP(x)                                        \
        do {                                                           \
            if (dbg_flag) {                                            \
                CIPHER_DIAGNOSTIC_ERR << #x << ":" << x << std::endl; \
            }                                                          \
        } while (0)

    // debugging macro prints value of x and location in codex on cerr
    #define CIPHER_DEBUGWHERE(x)                                                                             \
        do {                                                                                                  \
            if (dbg_flag) {                                                                                   \
                CIPHER_DIAGNOSTIC_ERR << __FILE__ << ":" << __LINE__ << ": " << #x << ":" << x << std::endl; \
            }                                                                                                 \
        } while (0)

    // debugging macro prints location in codex on cerr
    #define CIPHER_DEBUGHERE()                                                             \
        do {                                                                                \
            if (dbg_flag) {                                                                 \
                CIPHER_DIAGNOSTIC_ERR << __FILE__ << ":" << __LINE__ << ": " << std::endl; \
            }                                                                               \
        } while (0)

    #if defined(PROFILE)  // Profiler works

        #define PROFILELOG(x)                                 \
            do {                                              \
                if (true) {                                   \
                    CIPHER_DIAGNOSTIC_OUT << x << std::endl; \
                }                                             \
            } while (0)

        // debugging macro prints typography of x and value of x on cerr
        #define PROFILELOGEXP(x)                                           \
            do {                                                           \
                if (true) {                                                \
                    CIPHER_DIAGNOSTIC_OUT << #x << ":" << x << std::endl; \
                }                                                          \
            } while (0)

        // debugging macro prints value of x and location in codex on cerr
        #define PROFILELOGWHERE(x)                                                                         \
            do {                                                                                           \
                if (true) {                                                                                \
                    CIPHER_DIAGNOSTIC_OUT << #x << ":" << x << " at " << __FILE__ << " line " << __LINE__ \
                                           << std::endl;                                                   \
                }                                                                                          \
            } while (0)

    #else  // #if!defined(PROFILE) // profiling a noop
        #define PROFILELOG(x)
        #define PROFILELOGEXP(x)
        #define PROFILELOGWHERE(x)

    #endif  // PROFILE

    #define TIC(t)    t = ::cipher::time_now()
    #define TOC_NS(t) ::cipher::duration_ns(::cipher::time_now() - t)
    #define TOC_US(t) ::cipher::duration_us(::cipher::time_now() - t)
    #define TOC_MS(t) ::cipher::duration_ms(::cipher::time_now() - t)
    #define TOC(t)    TOC_MS(t)

#else  // NDEBUG

    // #define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__,
    // __LINE__, ##__VA_ARGS__)

    #if !defined(PROFILE)

        // these are turned off functions

        #define CIPHER_DEBUG_FLAG(x)
        #define CIPHER_DEBUG(x)
        #define CIPHER_DEBUGEXP(x)
        #define CIPHER_DEBUGWHERE(x)
        #define CIPHER_DEBUGHERE()

        #define PROFILELOG(x)
        #define PROFILELOGEXP(x)
        #define PROFILELOGWHERE(x)

        #define TIC(t)    t = ::cipher::time_now()
        #define TOC(t)    std::chrono::steady_clock::duration::zero().count()
        #define TOC_NS(t) std::chrono::steady_clock::duration::zero().count()
        #define TOC_US(t) std::chrono::steady_clock::duration::zero().count()
        #define TOC_MS(t) std::chrono::steady_clock::duration::zero().count()

    #else  // PROFILE
        // if PROFILE is turned on, then TIC TOC still work and

        #define CIPHER_DEBUG_FLAG(x)
        #define CIPHER_DEBUG(x)
        #define CIPHER_DEBUGEXP(x)
        #define CIPHER_DEBUGWHERE(x)
        #define CIPHER_DEBUGHERE()

        #define PROFILELOG(x)                                 \
            do {                                              \
                if (true) {                                   \
                    CIPHER_DIAGNOSTIC_ERR << x << std::endl; \
                }                                             \
            } while (0)

        // debugging macro prints typography of x and value of x on cerr
        #define PROFILELOGEXP(x)                                           \
            do {                                                           \
                if (true) {                                                \
                    CIPHER_DIAGNOSTIC_OUT << #x << ":" << x << std::endl; \
                }                                                          \
            } while (0)

        // debugging macro prints value of x and location in codex on cerr
        #define PROFILELOGWHERE(x)                                                                         \
            do {                                                                                           \
                if (true) {                                                                                \
                    CIPHER_DIAGNOSTIC_OUT << #x << ":" << x << " at " << __FILE__ << " line " << __LINE__ \
                                           << std::endl;                                                   \
                }                                                                                          \
            } while (0)

        #define TIC(t)    t = ::cipher::time_now()
        #define TOC_NS(t) ::cipher::duration_ns(::cipher::time_now() - t)
        #define TOC_US(t) ::cipher::duration_us(::cipher::time_now() - t)
        #define TOC_MS(t) ::cipher::duration_ms(::cipher::time_now() - t)
        #define TOC(t)    TOC_MS(t)

    #endif  // PROFILE

#endif  // NDEBUG

/** time point type used by the TIC/TOC timing macros */
typedef std::chrono::high_resolution_clock::time_point TimeVar;

namespace cipher {

/**
 * @brief Returns the current time point of the high-resolution clock; used by TIC().
 * @return the current time point
 */
inline TimeVar time_now() {
    return std::chrono::high_resolution_clock::now();
}

/**
 * @brief Converts a clock duration to a count of nanoseconds; used by TOC_NS().
 * @param d duration to convert
 * @return the duration in whole nanoseconds
 */
template <typename Duration>
inline auto duration_ns(const Duration& d) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
}

/**
 * @brief Converts a clock duration to a count of microseconds; used by TOC_US().
 * @param d duration to convert
 * @return the duration in whole microseconds
 */
template <typename Duration>
inline auto duration_us(const Duration& d) {
    return std::chrono::duration_cast<std::chrono::microseconds>(d).count();
}

/**
 * @brief Converts a clock duration to a count of milliseconds; used by TOC_MS() and TOC().
 * @param d duration to convert
 * @return the duration in whole milliseconds
 */
template <typename Duration>
inline auto duration_ms(const Duration& d) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
}

}  // namespace cipher

/**
 * @brief Returns the wall-clock time elapsed since local midnight.
 * @return milliseconds since local midnight, with sub-millisecond fraction
 */
double current_date_time();

/**
 * @brief Calls func(args...) and measures how long the call takes.
 * @param func callable to time
 * @param args arguments forwarded to func
 * @return the elapsed time in whole milliseconds
 */
template <typename F, typename... Args>
double func_time(F func, Args&&... args) {
    TimeVar t1 = cipher::time_now();
    func(std::forward<Args>(args)...);
    return cipher::duration_ms(cipher::time_now() - t1);
}

#endif  // CIPHER_UTIL_DEBUG_H_
