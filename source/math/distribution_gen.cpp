//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code provides basic structure for distribution generators. This should be inherited by
  all other distribution generators
 */

#include "cipher/math/distribution_gen.h"

#include <memory>
#include <string>

#include "cipher/util/diagnostic_output.h"
#include "cipher/util/exception.h"
#include "cipher/util/prng/blake2_engine.h"

#if (defined(__linux__) || defined(__unix__)) && !defined(__APPLE__) && defined(__GNUC__) && !defined(__clang__)
    #include <dlfcn.h>
#endif

namespace cipher {

#if defined(CIPHER_WITH_OPENMP)
std::shared_ptr<PRNG> PseudoRandomNumberGenerator::prng_ = nullptr;
#else
thread_local std::shared_ptr<PRNG> prng_ = nullptr;
#endif
PseudoRandomNumberGenerator::GenPrngEngineFuncPtr PseudoRandomNumberGenerator::gen_prng_engine = nullptr;

void PseudoRandomNumberGenerator::init_prng_engine(const std::string& lib_path) {
    if (gen_prng_engine)  // if gen_prng_engine has already been initialized
        return;

    if (lib_path.empty()) {
        // use the default Cipher PRNG that comes with the library
        gen_prng_engine = default_prng::createEngineInstance;
        if (!gen_prng_engine)
            CIPHER_THROW("Cannot find symbol: default_prng::createEngineInstance");
    } else {
#if (defined(__linux__) || defined(__unix__)) && !defined(__APPLE__) && defined(__GNUC__) && !defined(__clang__)
        // enable this code for g++ on Linux only
        // do not close library_handle, your application will crash if you do
        void* library_handle = dlopen(lib_path.c_str(), RTLD_LAZY);
        if (!library_handle) {
            std::string err_msg{std::string("Cannot open ") + lib_path + ": "};
            const char* dlsym_error = dlerror();
            err_msg += dlsym_error;
            CIPHER_THROW(err_msg);
        }
        gen_prng_engine = (GenPrngEngineFuncPtr)dlsym(library_handle, "createEngineInstance");
        if (!gen_prng_engine) {
            std::string err_msg{std::string("Cannot load symbol createEngineInstance() from ") + lib_path};
            const char* dlsym_error = dlerror();
            err_msg += ": ";
            err_msg += dlsym_error;
            dlclose(library_handle);
            CIPHER_THROW(err_msg);
        }
        CIPHER_DIAGNOSTIC_ERR << __FUNCTION__ << ": using external PRNG" << std::endl;
#else
        CIPHER_THROW("Cipher may use an external PRNG library linked with g++ on Linux only");
#endif
    }
}

PRNG& PseudoRandomNumberGenerator::get_prng() {
    // initialization of PRNGs
    if (prng_ == nullptr) {
#pragma omp critical
        {
            // we would like to believe that the block of code below is a good defense line
            if (!gen_prng_engine)
                init_prng_engine();
            if (!gen_prng_engine)
                CIPHER_THROW("Failure to initialize the PRNG engine");

            prng_ = std::shared_ptr<PRNG>(gen_prng_engine());
            if (!prng_)
                CIPHER_THROW("Cannot create a PRNG engine");
        }  // pragma omp critical
    }
    return *prng_;
}

}  // namespace cipher
