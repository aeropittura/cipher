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
  Implementation file for Boolean Circuit FHE context class
 */

#include "cipher/boolean/context.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

static constexpr double STD_DEV = 3.19;

namespace cipher {

// RingGswCryptoParams never sees the LWE dimension, so the map and n meet only here
static void verify_gadget_base_map_coverage(const std::map<uint32_t, uint32_t>& base_g_map, uint32_t n) {
    uint32_t count{0};
    for (const auto& item : base_g_map)
        count += item.second;
    if (count != n)
        CIPHER_THROW("Gadget base map should cover the LWE dimension.");
}

void BooleanContext::generate_boolean_context(uint32_t n, uint32_t N, NativeInteger q, NativeInteger Q, double std,
                                          uint32_t base_ks, uint32_t base_g, uint32_t base_r, SecretKeyDist key_dist,
                                          BINFHE_METHOD method, uint32_t num_auto_keys) {
    auto lweparams = std::make_shared<LweCryptoParams>(n, N, q, Q, Q, std, base_ks, key_dist);
    auto rgswparams =
            std::make_shared<RingGswCryptoParams>(N, Q, q, base_g, base_r, method, std, key_dist, true, num_auto_keys);
    params_ = std::make_shared<BooleanCryptoParams>(lweparams, rgswparams);
    binfhescheme_ = std::make_shared<BooleanScheme>(method);
}

void BooleanContext::generate_boolean_context(BINFHE_PARAMSET s, bool arb_func, uint32_t log_q, uint32_t N,
                                          BINFHE_METHOD method, bool time_optimization) {
    if (method != GINX)
        CIPHER_THROW("CGGI is the only supported method");
    if (s != STD128 && s != TOY)
        CIPHER_THROW("STD128 and TOY are the only supported sets");
    if (log_q > 29)
        CIPHER_THROW("logQ > 29 is not supported");
    if (log_q < 11)
        CIPHER_THROW("logQ < 11 is not supported");

    is_method_compatible(method, s);

    auto log_qprime = 54;
    uint32_t base_g = 0;
    if (log_q > 25) {
        base_g = 1 << 14;
    } else if (log_q > 16) {
        base_g = 1 << 18;
    } else if (log_q > 11) {
        base_g = 1 << 27;
    } else {  // if (log_q == 11)
        base_g = 1 << 5;
        log_qprime = 27;
    }

    // choose minimum ringD satisfying sl and Q
    // if specified some larger N, security is also satisfied
    auto min_ring_dim = StdLatticeParm::find_ring_dim(HEStd_ternary, HEStd_128_classic, log_qprime);
    uint32_t ring_dim = N > min_ring_dim ? N : min_ring_dim;

    // find prime Q for NTT
    NativeInteger Q = last_prime<NativeInteger>(log_qprime, 2 * ring_dim);

    // q = 2*ring_dim by default for maximum plaintext space, if needed for arbitrary function evaluation, q = ring_dim
    uint32_t q = arb_func ? ring_dim : 2 * ring_dim;

    uint64_t q_ks = uint64_t(1) << 35;

    uint32_t n = (s == TOY) ? 32 : 1305;
    auto lweparams = std::make_shared<LweCryptoParams>(n, ring_dim, q, Q, q_ks, STD_DEV, 32);
    auto rgswparams = std::make_shared<RingGswCryptoParams>(ring_dim, Q, q, base_g, 23, method, STD_DEV, UNIFORM_TERNARY,
                                                            ((log_q != 11) && time_optimization));

    params_ = std::make_shared<BooleanCryptoParams>(lweparams, rgswparams);
    binfhescheme_ = std::make_shared<BooleanScheme>(method);
    time_optimization_ = time_optimization;
}

void BooleanContext::generate_boolean_context(BINFHE_PARAMSET s, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for mod_ks if you want to use the intermediate prime for modulus for key switching

    is_method_compatible(method, s);

    // clang-format off
    static const std::unordered_map<BINFHE_PARAMSET, BooleanContextParams> params_map{
    //  { BINFHE_PARAMSET         { bits, cycOrder, latParam, modq,   mod_ks, Bks,        Bg, Brk, autoKeys,         key_dist, std_dev_value, gadget_base_map } },
        { TOY,                    {   27,     1024,       64,  512,   PRIME,  25,       512,  23,        9, UNIFORM_TERNARY,   3.19, {{512, 64}} } },
        { TOY_MULTI_BASE,         {   27,     1024,       64,  512,   PRIME,  25,       512,  23,        9, UNIFORM_TERNARY,   3.19, {{128, 32}, {512, 32}} } },
        { MEDIUM,                 {   28,     2048,      422, 1024,   16384, 128,      1024,  32,       10, UNIFORM_TERNARY,   3.19, {{1024, 422}} } },
        { STD128,                 {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 303}, {512, 251}} } },
        { STD128_3,               {   27,     2048,      592, 2048,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 575}, {512, 17}} } },
        { STD128_4,               {   27,     2048,      630, 2048,  131072, 512,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 134}, {32, 496}} } },
        { STD128Q,                {   25,     2048,      598, 2048,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 377}, {128, 221}} } },
        { STD128Q_3,              {   25,     2048,      639, 2048,   65536, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 287}, {32, 352}} } },
        { STD128Q_4,              {   28,     4096,      680, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 273}, {128, 407}} } },
        { STD192,                 {   28,     4096,      820, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 658}, {1024, 162}} } },
        { STD192_3,               {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 857}, {1024, 17}} } },
        { STD192_4,               {   28,     4096,      928, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 718}, {128, 210}} } },
        { STD192Q,                {   28,     4096,      889, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 732}, {1024, 157}} } },
        { STD192Q_3,              {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 935}, {1024, 12}} } },
        { STD192Q_4,              {   28,     4096,     1004, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 855}, {128, 149}} } },
        { STD256,                 {   28,     4096,     1077, 4096,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 931}, {1024, 146}} } },
        { STD256_3,               {   28,     4096,     1214, 4096,  131072,  64,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1190}, {1024, 24}} } },
        { STD256_4,               {   28,     4096,     1283, 4096,  262144, 128,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 1137}, {128, 146}} } },
        { STD256Q,                {   26,     4096,     1169, 4096,   32768, 256,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 173}, {64, 996}} } },
        { STD256Q_3,              {   26,     4096,     1317, 4096,  131072,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 41}, {32, 1276}} } },
        { STD256Q_4,              {   26,     4096,     1391, 4096,  262144,  64,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 289}, {16, 1102}} } },
        { LPF_STD128,             {   27,     2048,      554, 2048,   32768, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 523}, {512, 31}} } },
        { LPF_STD128_3,           {   27,     2048,      630, 2048,  131072, 512,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 165}, {64, 465}} } },
        { LPF_STD128_4,           {   28,     4096,      668, 4096,  262144,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 621}, {128, 47}} } },
        { LPF_STD128Q,            {   25,     2048,      598, 2048,   32768, 256,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 106}, {32, 492}} } },
        { LPF_STD128Q_3,          {   25,     2048,      680, 2048,  131072, 512,         4,  64,       10, UNIFORM_TERNARY,   3.19, {{4, 43}, {8, 637}} } },
        { LPF_STD128Q_4,          {   28,     4096,      720, 4096,  262144,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 715}, {128, 5}} } },
        { LPF_STD192,             {   28,     4096,      874, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 782}, {1024, 92}} } },
        { LPF_STD192_3,           {   28,     4096,      928, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 493}, {128, 435}} } },
        { LPF_STD192_4,           {   28,     4096,      982, 4096,  262144,  64,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 893}, {64, 89}} } },
        { LPF_STD192Q,            {   28,     4096,      947, 4096,   65536, 256,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 859}, {1024, 88}} } },
        { LPF_STD192Q_3,          {   28,     4096,     1004, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 629}, {128, 375}} } },
        { LPF_STD192Q_4,          {   28,     4096,     1062, 4096,  262144,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 359}, {32, 703}} } },
        { LPF_STD256,             {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       10, UNIFORM_TERNARY,   3.19, {{128, 1091}, {1024, 55}} } },
        { LPF_STD256_3,           {   28,     4096,     1214, 4096,  131072,  64,        64,  64,       10, UNIFORM_TERNARY,   3.19, {{64, 1006}, {128, 208}} } },
        { LPF_STD256_4,           {   28,     4096,     1352, 4096,  524288, 128,         8,  64,       10, UNIFORM_TERNARY,   3.19, {{8, 110}, {16, 1242}} } },
        { LPF_STD256Q,            {   26,     4096,     1243, 4096,   65536,  64,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 997}, {64, 246}} } },
        { LPF_STD256Q_3,          {   26,     4096,     1391, 4096,  262144,  64,        16,  64,       10, UNIFORM_TERNARY,   3.19, {{16, 1294}, {32, 97}} } },
        { LPF_STD256Q_4,          {   28,     8192,     1465, 8192,  524288,  32,        32,  64,       10, UNIFORM_TERNARY,   3.19, {{32, 1201}, {64, 264}} } },
        { STD128_LMKCDEY,         {   27,     2048,      554, 2048,   32768, 256,       512,  64,       40, UNIFORM_TERNARY,   3.19, {{512, 552}, {16384, 2}} } },
        { STD128_3_LMKCDEY,       {   27,     2048,      592, 2048,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 440}, {512, 152}} } },
        { STD128_4_LMKCDEY,       {   27,     2048,      668, 2048,  262144, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 586}, {128, 82}} } },
        { STD128Q_LMKCDEY,        {   25,     2048,      598, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 565}, {512, 33}} } },
        { STD128Q_3_LMKCDEY,      {   25,     2048,      639, 2048,   65536, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 532}, {128, 107}} } },
        { STD128Q_4_LMKCDEY,      {   28,     4096,      680, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 642}, {1024, 38}} } },
        { STD192_LMKCDEY,         {   28,     4096,      716, 4096,   32768, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 633}, {1024, 83}} } },
        { STD192_3_LMKCDEY,       {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 731}, {1024, 143}} } },
        { STD192_4_LMKCDEY,       {   28,     4096,      928, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 914}, {1024, 14}} } },
        { STD192Q_LMKCDEY,        {   28,     4096,      778, 4096,   32768, 256,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 745}, {1024, 33}} } },
        { STD192Q_3_LMKCDEY,      {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 811}, {1024, 136}} } },
        { STD192Q_4_LMKCDEY,      {   28,     4096,     1004, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 997}, {1024, 7}} } },
        { STD256_LMKCDEY,         {   28,     4096,     1009, 4096,   65536,  64,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 779}, {1024, 230}} } },
        { STD256_3_LMKCDEY,       {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1095}, {1024, 51}} } },
        { STD256_4_LMKCDEY,       {   28,     4096,     1283, 4096,  262144,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1263}, {1024, 20}} } },
        { STD256Q_LMKCDEY,        {   28,     4096,     1120, 4096,   65536,  64,       128,  64,       40,        GAUSSIAN,   3.19, {{128, 980}, {1024, 140}} } },
        { STD256Q_3_LMKCDEY,      {   26,     4096,     1317, 4096,  131072,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 1288}, {128, 29}} } },
        { STD256Q_4_LMKCDEY,      {   26,     4096,     1317, 4096,  131072,  64,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 1014}, {32, 303}} } },
        { LPF_STD128_LMKCDEY,     {   27,     2048,      554, 2048,   32768, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 364}, {512, 190}} } },
        { LPF_STD128_3_LMKCDEY,   {   27,     2048,      630, 2048,  131072, 512,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 120}, {128, 510}} } },
        { LPF_STD128_4_LMKCDEY,   {   28,     4096,      706, 4096,  524288, 128,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 701}, {1024, 5}} } },
        { LPF_STD128Q_LMKCDEY,    {   25,     2048,      598, 2048,   32768, 256,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 448}, {128, 150}} } },
        { LPF_STD128Q_3_LMKCDEY,  {   25,     2048,      680, 2048,  131072, 512,        16,  64,       40, UNIFORM_TERNARY,   3.19, {{16, 658}, {32, 22}} } },
        { LPF_STD128Q_4_LMKCDEY,  {   28,     4096,      760, 4096,  524288, 128,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 760}} } },
        { LPF_STD192_LMKCDEY,     {   28,     4096,      874, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 492}, {1024, 382}} } },
        { LPF_STD192_3_LMKCDEY,   {   28,     4096,      928, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 889}, {1024, 39}} } },
        { LPF_STD192_4_LMKCDEY,   {   28,     4096,      982, 4096,  262144,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 899}, {128, 83}} } },
        { LPF_STD192Q_LMKCDEY,    {   28,     4096,      947, 4096,   65536, 256,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 572}, {1024, 375}} } },
        { LPF_STD192Q_3_LMKCDEY,  {   28,     4096,     1004, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 972}, {1024, 32}} } },
        { LPF_STD192Q_4_LMKCDEY,  {   28,     4096,     1120, 4096,  524288, 128,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 990}, {128, 130}} } },
        { LPF_STD256_LMKCDEY,     {   28,     4096,     1146, 4096,   65536,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 854}, {1024, 292}} } },
        { LPF_STD256_3_LMKCDEY,   {   28,     4096,     1214, 4096,  131072,  64,       128,  64,       40, UNIFORM_TERNARY,   3.19, {{128, 1202}, {1024, 12}} } },
        { LPF_STD256_4_LMKCDEY,   {   28,     4096,     1352, 4096,  524288, 128,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 1276}, {64, 76}} } },
        { LPF_STD256Q_LMKCDEY,    {   26,     4096,     1243, 4096,   65536,  64,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 900}, {128, 343}} } },
        { LPF_STD256Q_3_LMKCDEY,  {   26,     4096,     1391, 4096,  262144,  64,        32,  64,       40, UNIFORM_TERNARY,   3.19, {{32, 1279}, {64, 112}} } },
        { LPF_STD256Q_4_LMKCDEY,  {   28,     8192,     1465, 8192,  524288,  32,        64,  64,       40, UNIFORM_TERNARY,   3.19, {{64, 1243}, {128, 222}} } },
        { STD128_AP,              {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 10}, {512, 544}} } },
        { STD128_3_AP,            {   27,     2048,      592, 2048,   65536, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 512}, {512, 80}} } },
        { STD128_4_AP,            {   27,     2048,      668, 2048,  262144,  64,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 304}, {64, 364}} } },
        { STD128Q_AP,             {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 72}, {128, 526}} } },
        { STD128Q_3_AP,           {   25,     2048,      639, 2048,   65536, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 605}, {128, 34}} } },
        { STD128Q_4_AP,           {   28,     4096,      680, 4096,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 680}} } },
        { STD192_AP,              {   28,     4096,      874, 1024,   65536, 256,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 653}, {1024, 221}} } },
        { STD192_3_AP,            {   28,     4096,      928, 2048,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 904}, {1024, 24}} } },
        { STD192_4_AP,            {   28,     4096,      928, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 488}, {128, 440}} } },
        { STD192Q_AP,             {   28,     4096,      947, 1024,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 808}, {1024, 139}} } },
        { STD192Q_3_AP,           {   28,     4096,     1004, 2048,  131072,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 991}, {1024, 13}} } },
        { STD192Q_4_AP,           {   28,     4096,     1062, 4096,  262144,  32,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 282}, {128, 780}} } },
        { STD256_AP,              {   28,     4096,     1146, 1024,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1117}, {1024, 29}} } },
        { STD256_3_AP,            {   28,     4096,     1214, 4096,  131072,  32,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1160}, {1024, 54}} } },
        { STD256_4_AP,            {   28,     4096,     1214, 4096,  131072,  64,        64,   8,       10, UNIFORM_TERNARY,   3.19, {{64, 1192}, {128, 22}} } },
        { STD256Q_AP,             {   28,     4096,     1120, 4096,   65536,  64,       128,  32,       10,        GAUSSIAN,   3.19, {{128, 1085}, {1024, 35}} } },
        { STD256Q_3_AP,           {   26,     4096,     1317, 4096,  131072,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 1265}, {64, 52}} } },
        { STD256Q_4_AP,           {   26,     4096,     1391, 4096,  262144,  32,         8,   8,       10, UNIFORM_TERNARY,   3.19, {{8, 200}, {16, 1191}} } },
        { LPF_STD128_AP,          {   27,     2048,      554, 2048,   32768, 256,       128, 128,       10, UNIFORM_TERNARY,   3.19, {{128, 449}, {512, 105}} } },
        { LPF_STD128_3_AP,        {   27,     2048,      630, 2048,  131072, 512,        64, 128,       10, UNIFORM_TERNARY,   3.19, {{64, 424}, {128, 206}} } },
        { LPF_STD128_4_AP,        {   28,     4096,      668, 4096,  262144,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 501}, {128, 167}} } },
        { LPF_STD128Q_AP,         {   25,     2048,      598, 2048,   32768, 256,        32, 128,       10, UNIFORM_TERNARY,   3.19, {{32, 534}, {128, 64}} } },
        { LPF_STD128Q_3_AP,       {   25,     2048,      680, 2048,  131072, 512,         8,  32,       10, UNIFORM_TERNARY,   3.19, {{8, 487}, {16, 193}} } },
        { LPF_STD128Q_4_AP,       {   28,     4096,      720, 4096,  262144,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 605}, {128, 115}} } },
        { LPF_STD192_AP,          {   28,     4096,      874, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 801}, {1024, 73}} } },
        { LPF_STD192_3_AP,        {   28,     4096,      928, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 164}, {128, 764}} } },
        { LPF_STD192_4_AP,        {   28,     4096,      982, 4096,  262144,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 834}, {64, 148}} } },
        { LPF_STD192Q_AP,         {   28,     4096,      947, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 884}, {1024, 63}} } },
        { LPF_STD192Q_3_AP,       {   28,     4096,     1004, 4096,  131072,  64,        64,  32,       10, UNIFORM_TERNARY,   3.19, {{64, 315}, {128, 689}} } },
        { LPF_STD192Q_4_AP,       {   28,     4096,     1062, 4096,  262144,  64,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 222}, {32, 840}} } },
        { LPF_STD256_AP,          {   28,     4096,     1146, 2048,   65536,  64,       128,  32,       10, UNIFORM_TERNARY,   3.19, {{128, 1112}, {1024, 34}} } },
        { LPF_STD256_3_AP,        {   28,     4096,     1214, 4096,  131072,  64,        64,   8,       10, UNIFORM_TERNARY,   3.19, {{64, 942}, {128, 272}} } },
        { LPF_STD256_4_AP,        {   28,     4096,     1352, 4096,  524288,  32,         8,   8,       10, UNIFORM_TERNARY,   3.19, {{8, 288}, {16, 1064}} } },
        { LPF_STD256Q_AP,         {   26,     4096,     1243, 4096,   65536,  64,        32,   8,       10, UNIFORM_TERNARY,   3.19, {{32, 908}, {64, 335}} } },
        { LPF_STD256Q_3_AP,       {   26,     4096,     1391, 4096,  262144,  32,        16,   8,       10, UNIFORM_TERNARY,   3.19, {{16, 1248}, {32, 143}} } },
        { LPF_STD256Q_4_AP,       {   51,     8192,     1391, 8192,  262144,  32,  67108864,   8,       10, UNIFORM_TERNARY,   3.19, {{67108864, 1391}} } },
        { SIGNED_MOD_TEST,        {   28,     2048,      512, 1024,   PRIME,  25,       128,  23,       10, UNIFORM_TERNARY,   3.19, {{128, 512}} } },
    };
    // clang-format on

    auto search = params_map.find(s);
    if (params_map.end() == search)
        CIPHER_THROW("unknown parameter set");

    auto& params = search->second;

    auto Q = last_prime<NativeInteger>(params.number_bits, params.cycl_order);
    auto ring_dim = params.cycl_order >> 1;
    auto lweparams = std::make_shared<LweCryptoParams>(params.lattice_param, ring_dim, params.mod_value, Q,
                                                       (params.mod_ks == PRIME ? Q : params.mod_ks), params.std_dev_value,
                                                       params.base_ks, params.key_dist);
    verify_gadget_base_map_coverage(params.gadget_base_map, params.lattice_param);

    auto rgswparams = std::make_shared<RingGswCryptoParams>(ring_dim, Q, params.mod_value, params.gadget_base,
                                                            params.gadget_base_map, params.base_rk, method, params.std_dev_value,
                                                            params.key_dist, false, params.num_auto_keys);
    params_ = std::make_shared<BooleanCryptoParams>(lweparams, rgswparams);

    binfhescheme_ = std::make_shared<BooleanScheme>(method);
}

void BooleanContext::generate_boolean_context(const BooleanContextParams& params, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for mod_ks if you want to use the intermediate prime for modulus for key switching

    auto Q = last_prime<NativeInteger>(params.number_bits, params.cycl_order);
    auto ring_dim = params.cycl_order >> 1;
    auto lweparams = std::make_shared<LweCryptoParams>(params.lattice_param, ring_dim, params.mod_value, Q,
                                                       (params.mod_ks == PRIME ? Q : params.mod_ks), params.std_dev_value,
                                                       params.base_ks, params.key_dist);
    std::shared_ptr<RingGswCryptoParams> rgswparams;
    if (params.gadget_base_map.empty()) {
        rgswparams =
                std::make_shared<RingGswCryptoParams>(ring_dim, Q, params.mod_value, params.gadget_base, params.base_rk, method,
                                                      params.std_dev_value, params.key_dist, false, params.num_auto_keys);
    } else {
        verify_gadget_base_map_coverage(params.gadget_base_map, params.lattice_param);

        rgswparams = std::make_shared<RingGswCryptoParams>(ring_dim, Q, params.mod_value, params.gadget_base,
                                                           params.gadget_base_map, params.base_rk, method, params.std_dev_value,
                                                           params.key_dist, false, params.num_auto_keys);
    }
    params_ = std::make_shared<BooleanCryptoParams>(lweparams, rgswparams);
    binfhescheme_ = std::make_shared<BooleanScheme>(method);
}

LwePrivateKey BooleanContext::key_gen() const {
    auto&& LWE_params = params_->get_lwe_params();
    if (LWE_params->get_key_dist() == GAUSSIAN)
        return lwe_scheme_->key_gen_gaussian(LWE_params->get_n(), LWE_params->get_q_ks());
    return lwe_scheme_->key_gen(LWE_params->get_n(), LWE_params->get_q_ks());
}

LwePrivateKey BooleanContext::key_gen_n() const {
    auto&& LWE_params = params_->get_lwe_params();
    if (LWE_params->get_key_dist() == GAUSSIAN)
        return lwe_scheme_->key_gen_gaussian(LWE_params->get_N(), LWE_params->get_Q());
    return lwe_scheme_->key_gen(LWE_params->get_N(), LWE_params->get_Q());
}

LweKeyPair BooleanContext::key_gen_pair() const {
    return lwe_scheme_->key_gen_pair(params_->get_lwe_params());
}

LwePublicKey BooleanContext::pub_key_gen(ConstLwePrivateKey& sk) const {
    if (sk == nullptr)
        CIPHER_THROW("PrivateKey is empty");
    return lwe_scheme_->pub_key_gen(params_->get_lwe_params(), sk);
}

LweCiphertext BooleanContext::encrypt(ConstLwePrivateKey& sk, LwePlaintext m, BINFHE_OUTPUT output,
                                     LwePlaintextModulus p, NativeInteger mod_value) const {
    if (sk == nullptr)
        CIPHER_THROW("PrivateKey is empty");
    auto&& LWE_params = params_->get_lwe_params();
    auto ct = lwe_scheme_->encrypt(LWE_params, sk, m, p, (mod_value == 0 ? LWE_params->get_q() : mod_value));

    // BINFHE_OUTPUT is kept as it is for backward compatibility but
    // this logic is obsolete now and commented out
    // if ((output != FRESH) && (p == 4)) {
    //    ct = binfhescheme_->bootstrap(params_, bt_key_, ct);
    //}
    return ct;
}

LweCiphertext BooleanContext::encrypt(ConstLwePublicKey& pk, LwePlaintext m, BINFHE_OUTPUT output, LwePlaintextModulus p,
                                     NativeInteger mod_value) const {
    if (pk == nullptr)
        CIPHER_THROW("PublicKey is empty");
    auto&& LWE_params = params_->get_lwe_params();
    auto ct = lwe_scheme_->encrypt_n(LWE_params, pk, m, p, (mod_value == 0 ? LWE_params->get_Q() : mod_value));

    // Switch from ct of modulus Q and dimension N to smaller q and n
    // This is done by default while calling Encrypt but the output could
    // be set to LARGE_DIM to skip this switching
    if (output == SMALL_DIM) {
#if CIPHER_NATIVE_INT != 32
        if (bt_key_.ks_key32 != nullptr)
            ct = lwe_scheme_->switch_c_ttoqn(LWE_params, bt_key_.ks_key32, ct);
        else
#endif
            ct = switch_c_ttoqn(bt_key_.ks_key, ct);
        ct->set_pt_modulus(p);
    }
    return ct;
}

LweCiphertext BooleanContext::switch_c_ttoqn(ConstLweSwitchingKey& ksk, ConstLweCiphertext& ct) const {
    if (ksk == nullptr)
        CIPHER_THROW("SwitchingKey is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    auto&& LWE_params = params_->get_lwe_params();
    if (ct->get_length() != LWE_params->get_N() || ct->get_modulus() != LWE_params->get_Q())
        CIPHER_THROW("ciphertext must have large dimension N and modulus Q");
    return lwe_scheme_->switch_c_ttoqn(LWE_params, ksk, ct);
}

void BooleanContext::decrypt(ConstLwePrivateKey& sk, ConstLweCiphertext& ct, LwePlaintext* result,
                            LwePlaintextModulus p) const {
    if (sk == nullptr)
        CIPHER_THROW("PrivateKey is empty");
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    lwe_scheme_->decrypt(params_->get_lwe_params(), sk, ct, result, p);
}

LweSwitchingKey BooleanContext::key_switch_gen(ConstLwePrivateKey& sk, ConstLwePrivateKey& sk_n) const {
    if (sk == nullptr)
        CIPHER_THROW("New PrivateKey is empty");
    if (sk_n == nullptr)
        CIPHER_THROW("Old PrivateKey is empty");

    return lwe_scheme_->key_switch_gen(params_->get_lwe_params(), sk, sk_n);
}

void BooleanContext::bt_key_gen(ConstLwePrivateKey& sk, KEYGEN_MODE keygen_mode, bool internal32) {
    if (sk == nullptr)
        CIPHER_THROW("PrivateKey is empty");
    auto&& RGSW_params = params_->get_ring_gsw_params();
    auto temp = RGSW_params->get_base_g();

    // the map is keyed by gadget base alone, but what it caches is only valid for the secret
    // key it was generated from; take a cached entry only when this call just regenerated it
    if (time_optimization_) {
        for (auto&& [k, v] : RGSW_params->get_g_power_map()) {
            RGSW_params->change_base_g(k);
            bt_key_map_[k] = binfhescheme_->key_gen(params_, sk, keygen_mode, internal32);
        }
        RGSW_params->change_base_g(temp);
        bt_key_ = bt_key_map_[temp];
    } else {
        bt_key_ = binfhescheme_->key_gen(params_, sk, keygen_mode, internal32);
        bt_key_map_[temp] = bt_key_;
    }

#if CIPHER_NATIVE_INT != 32
    release_monomials_if_all32();
#endif
}

LweCiphertext BooleanContext::eval_bin_gate(const BINGATE gate, ConstLweCiphertext& ct1, ConstLweCiphertext& ct2,
                                         bool extended) const {
    if (ct1 == nullptr)
        CIPHER_THROW("Ciphertext1 is empty");
    if (ct2 == nullptr)
        CIPHER_THROW("Ciphertext2 is empty");
    return binfhescheme_->eval_bin_gate(params_, gate, bt_key_, ct1, ct2, extended);
}

LweCiphertext BooleanContext::eval_bin_gate(const BINGATE gate, const std::vector<LweCiphertext>& ctvector,
                                         bool extended) const {
    return binfhescheme_->eval_bin_gate(params_, gate, bt_key_, ctvector, extended);
}

LweCiphertext BooleanContext::bootstrap(ConstLweCiphertext& ct, bool extended) const {
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->bootstrap(params_, bt_key_, ct, extended);
}

LweCiphertext BooleanContext::eval_not(ConstLweCiphertext& ct) const {
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->eval_not(params_, ct);
}

LweCiphertext BooleanContext::eval_constant(bool value) const {
    return lwe_scheme_->noiseless_embedding(params_->get_lwe_params(), value);
}

LweCiphertext BooleanContext::eval_func(ConstLweCiphertext& ct, const std::vector<NativeInteger>& LUT) const {
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->eval_func(params_, bt_key_, ct, LUT, get_beta());
}

LweCiphertext BooleanContext::eval_floor(ConstLweCiphertext& ct, uint32_t roundbits) const {
    //    auto q = params_->get_lwe_params()->get_q().convert_to_int();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->get_max_plaintext_space();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->eval_floor(params_, bt_key_, ct, get_beta(), roundbits);
}

LweCiphertext BooleanContext::eval_sign(ConstLweCiphertext& ct, bool scheme_switch) {
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->eval_sign(std::make_shared<BooleanCryptoParams>(*params_), bt_key_map_, ct, get_beta(),
                                    scheme_switch);
}

std::vector<LweCiphertext> BooleanContext::eval_decomp(ConstLweCiphertext& ct) {
    if (ct == nullptr)
        CIPHER_THROW("Ciphertext is empty");
    return binfhescheme_->eval_decomp(params_, bt_key_map_, ct, get_beta());
}

std::vector<NativeInteger> BooleanContext::generate_lut_via_function(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (!is_power_of_two(p.convert_to_int<BasicInteger>()))
        CIPHER_THROW("plaintext p not power of two");

    NativeInteger q{get_params()->get_lwe_params()->get_q()};
    NativeInteger x{0};

    std::vector<NativeInteger> vec(q.convert_to_int(), q / p);
    for (size_t i = 0; i < vec.size(); ++i, x += p) {
        vec[i] *= f(x / q, p);  // x/q = (i*p)/q = i/(q/p)
        if (vec[i] >= q)        // (f(x/q, p) >= p) --> (f(x/q, p)*(q/p) >= q)
            CIPHER_THROW("input function should output in Z_{p_output}");
    }
    return vec;
}

}  // namespace cipher
