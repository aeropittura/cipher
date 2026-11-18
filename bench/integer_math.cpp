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
  This code benchmarks integer operations.
*/
#define _USE_MATH_DEFINES
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "benchmark/benchmark.h"
#include "cipher/ring/backend.h"

using namespace cipher;

static uint64_t smallva(10403), smallvb(103), smallvm(101101);
static std::string smalla("10403"), smallb("103"), smallm("101101");
static std::string largea("18446744073709551616"), largeb("18446744073709551617"), largem("1844674407370955471617");

template <typename I>
static void make_big_int_small_val_ctor() {
    I a(smallva), b(smallvb), m(smallvm);
}

template <typename I>
void bm_big_int_small_val_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_big_int_small_val_ctor<I>();
}

template <typename I>
static void make_big_int_small_string_ctor() {
    I a(smalla), b(smallb), m(smallm);
}

template <typename I>
void bm_big_int_small_string_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_big_int_small_string_ctor<I>();
}

template <typename I>
static void make_big_int_large_string_ctor() {
    I a(largea), b(largeb), m(largem);
}

template <typename I>
void bm_big_int_large_string_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_big_int_large_string_ctor<I>();
}

template <typename I>
static void add_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c = a + b;
}

template <typename I>
static void bm_big_int_add(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        add_big_int(a, b);
}

template <typename I>
static void addeq_big_int(I a, const I& b) {
    a += b;
}

// technically add_eq + copy ctor
// much more representative than previous add_eq + string ctor
template <typename I>
static void bm_big_int_add_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        addeq_big_int(a, b);
}

template <typename I>
static void sub_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c = a - b;
}

template <typename I>
static void bm_big_int_sub(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        sub_big_int(a, b);
}

template <typename I>
static void subeq_big_int(I a, const I& b) {
    a -= b;
}

template <typename I>
static void bm_big_int_sub_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        subeq_big_int(a, b);
}

template <typename I>
static void mult_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a * b;
}

template <typename I>
static void bm_big_int_mult(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        mult_big_int(a, b);
}

template <typename I>
static void multeq_big_int(I a, const I& b) {
    a *= b;
}

template <typename I>
static void bm_big_int_mult_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        multeq_big_int(a, b);
}

template <typename I>
static void div_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a / b;
}

template <typename I>
static void bm_big_int_divided_by(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        div_big_int(a, b);
}

template <typename I>
static void diveq_big_int(I a, const I& b) {
    a /= b;
}

template <typename I>
static void bm_big_int_divided_by_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        diveq_big_int(a, b);
}

template <typename I>
static void exp_big_int(const I& a, uint32_t b) {
    __attribute__((unused)) I c1 = a.Exp(b);
}

template <typename I>
static void bm_big_int_exp(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        exp_big_int(a, 47);
}

template <typename I>
static void expeq_big_int(I a, uint32_t b) {
    a.exp_eq(b);
}

template <typename I>
static void bm_big_int_exp_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        expeq_big_int(a, 47);
}

template <typename I>
static void multround_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.multiply_and_round(b, m);
}

template <typename I>
static void bm_big_int_multiply_and_round(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        multround_big_int(a, b, m);
}

template <typename I>
static void multroundeq_big_int(I a, const I& b, const I& m) {
    a.multiply_and_round_eq(b, m);
}

template <typename I>
static void bm_big_int_multiply_and_round_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        multroundeq_big_int(a, b, m);
}

template <typename I>
static void lshift_big_int(const I& a, uint16_t b) {
    __attribute__((unused)) I c1 = a.l_shift(b);
}

template <typename I>
static void bm_big_int_l_shift(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        lshift_big_int(a, 11);
}

template <typename I>
static void lshifteq_big_int(I a, uint16_t b) {
    a.l_shift_eq(b);
}

template <typename I>
static void bm_big_int_l_shift_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        lshifteq_big_int(a, 11);
}

template <typename I>
static void rshift_big_int(const I& a, uint16_t b) {
    __attribute__((unused)) I c1 = a.r_shift(b);
}

template <typename I>
static void bm_big_int_r_shift(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        rshift_big_int(a, 11);
}

template <typename I>
static void rshifteq_big_int(I a, uint16_t b) {
    a.r_shift_eq(b);
}

template <typename I>
static void bm_big_int_r_shift_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        rshifteq_big_int(a, 11);
}

template <typename I>
static void mod_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a.mod(b);
}

template <typename I>
static void bm_big_int_mod(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        mod_big_int(a, b);
}

template <typename I>
static void modeq_big_int(I a, const I& b) {
    a.mod_eq(b);
}

template <typename I>
static void bm_big_int_mod_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modeq_big_int(a, b);
}

template <typename I>
static void modadd_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.mod_add(b, m);
}

template <typename I>
static void bm_big_int_mod_add(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modadd_big_int(a, b, m);
}

template <typename I>
static void modaddeq_big_int(I a, const I& b, const I& m) {
    a.mod_add_eq(b, m);
}

template <typename I>
static void bm_big_int_mod_add_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddeq_big_int(a, b, m);
}

template <typename I>
static void modsub_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.mod_sub(b, m);
}

template <typename I>
static void bm_big_int_mod_sub(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modsub_big_int(a, b, m);
}

template <typename I>
static void modsubeq_big_int(I a, const I& b, const I& m) {
    a.mod_sub_eq(b, m);
}

template <typename I>
static void bm_big_int_mod_sub_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modsubeq_big_int(a, b, m);
}

template <typename I>
static void modaddfast_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.mod_add_fast(b, m);
}

template <typename I>
static void bm_big_int_mod_add_fast(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddfast_big_int(a, b, m);
}

template <typename I>
static void modaddfasteq_big_int(I a, const I& b, const I& m) {
    a.mod_add_fast_eq(b, m);
}

template <typename I>
static void bm_big_int_mod_add_fast_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddfasteq_big_int(a, b, m);
}

template <typename I>
static void modmult_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.mod_mul(b, m);
}

template <typename I>
static void bm_big_int_mod_mult(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modmult_big_int(a, b, m);
}

template <typename I>
static void modmulteq_big_int(I a, const I& b, const I& m) {
    a.mod_mul_eq(b, m);
}

template <typename I>
static void bm_big_int_mod_mult_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modmulteq_big_int(a, b, m);
}

template <typename I>
static void modexp_big_int(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.mod_exp(b, m);
}

template <typename I>
static void bm_big_int_mod_exp(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modexp_big_int(a, b, m);
}

template <typename I>
static void modexpeq_big_int(I a, const I& b, const I& m) {
    a.mod_exp_eq(b, m);
}

template <typename I>
static void bm_big_int_mod_exp_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modexpeq_big_int(a, b, m);
}

template <typename I>
static void modinv_big_int(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a.mod_inverse(b);
}

template <typename I>
static void bm_big_int_mod_inverse(benchmark::State& state) {
    I a(state.range(0) == 0 ? smallm : largem);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modinv_big_int(a, b);
}

template <typename I>
static void modinveq_big_int(I a, const I& b) {
    a.mod_inverse_eq(b);
}

template <typename I>
static void bm_big_int_mod_inverse_eq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smallm : largem);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modinveq_big_int(a, b);
}

#define DO_BENCHMARK_TEMPLATE(X, Y) BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond);

// clang-format off
DO_BENCHMARK_TEMPLATE(bm_big_int_small_val_ctor, NativeInteger)
DO_BENCHMARK_TEMPLATE(bm_big_int_small_string_ctor, NativeInteger)
BENCHMARK_TEMPLATE(bm_big_int_add, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);

#ifdef CIPHER_WITH_BE2
DO_BENCHMARK_TEMPLATE(bm_big_int_small_val_ctor, M2Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_small_string_ctor, M2Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_large_string_ctor, M2Integer)
BENCHMARK_TEMPLATE(bm_big_int_add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
#ifdef CIPHER_WITH_BE4
DO_BENCHMARK_TEMPLATE(bm_big_int_small_val_ctor, M4Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_small_string_ctor, M4Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_large_string_ctor, M4Integer)
BENCHMARK_TEMPLATE(bm_big_int_add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
#ifdef CIPHER_WITH_NTL
DO_BENCHMARK_TEMPLATE(bm_big_int_small_val_ctor, M6Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_small_string_ctor, M6Integer)
DO_BENCHMARK_TEMPLATE(bm_big_int_large_string_ctor, M6Integer)
BENCHMARK_TEMPLATE(bm_big_int_add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_add_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_sub_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mult_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_divided_by_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_exp_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_multiply_and_round_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_l_shift_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_r_shift_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_add_fast_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_sub_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_mult_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_exp_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(bm_big_int_mod_inverse_eq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
// clang-format on

// execute the benchmarks
BENCHMARK_MAIN();
