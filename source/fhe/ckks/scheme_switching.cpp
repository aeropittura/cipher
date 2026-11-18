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
        CKKS to FHEW scheme switching implementation.
 */

#include "cipher/fhe/ckks/scheme_switching.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "cipher/math/dft.h"
#include "cipher/fhe/ckks/fhe.h"
#include "cipher/fhe/ckks/context_gen.h"
#include "cipher/util/parallel.h"

// K = 16
// eval_chebyshev_coefficients([](double x) -> double {return std::pow(2.*M_PI, -1./8.) * std::cos(2.*M_PI/8. * (x - 0.25));}, -16, 16, 117)
static constexpr std::initializer_list<double> g_coefficients_fhew16{
        0.2455457340168511,     -0.04791906488334782,   0.2838870204084082,     -0.02994453873551349,
        0.3557652261903648,     0.01510656188507299,    0.2953294667450001,     0.07120360233373937,
        -0.1034734733966807,    0.04499759051255525,    -0.4275071243192574,    -0.09034212972909554,
        0.367628762693249,      0.04931806603933471,    -0.14535986272412,      -0.01510693848306369,
        0.03595193549924024,    0.003103658218868759,   -0.006264460660707066,  -0.0004660943047712052,
        0.0008212879885240095,  5.391053389217882e-05,  -8.455154976914221e-05, -4.977380178602518e-06,
        7.04666204400644e-06,   3.765980757166835e-07,  -4.864851013612591e-07, -2.383026746930811e-08,
        2.832970640938316e-08,  1.28177429687131e-09,   -1.412145521045378e-09, -5.939145408994641e-11,
        6.099273252183116e-11,  2.397381728164642e-12,  -2.307402856353623e-12, -8.500921247536622e-14,
        7.704571444110577e-14,  2.704051671841271e-15,  -2.154585361348821e-15, -7.263493008564584e-16,
        -1.260761739828568e-16, 1.637108527837095e-16,  1.185492382226862e-16,  6.379078056744543e-16,
        -1.411300455031979e-16, 3.123678340470779e-16,  5.946279250534737e-16,  2.954322285866942e-16,
        -8.279629336187608e-17, 5.024229619913844e-16,  -3.293034395074617e-16, -1.189255850106947e-15,
        1.674743206637948e-16,  -1.524204491434537e-16, -7.90328254817908e-17,  3.95164127408954e-16,
        -1.317213758029847e-17, 8.016186584581639e-16,  -3.650563843682718e-16, 3.763467880085276e-16,
        -2.709696873661399e-16, -1.524204491434537e-16, -4.83605622590958e-16,  7.376397044967142e-16,
        1.234417464667971e-15,  -2.672062194860546e-16, -4.892508244110859e-17, -7.122362963061386e-16,
        3.763467880085276e-17,  -2.944913616166729e-16, -2.897870267665663e-16, 9.794425157921932e-16,
        -3.198947698072485e-17, 6.614294799249873e-16,  -5.7769231959309e-16,   6.586068790149234e-16,
        -4.629065492504889e-16, -5.127724986616189e-16, -3.236582376873337e-16, -1.64745806450733e-15,
        -9.408669700213192e-16, -4.986594941112991e-16, -1.209954923447416e-15, -1.373665776231126e-16,
        -2.314532746252445e-16, 3.217765037472911e-16,  3.481207789078881e-16,  8.223177317986329e-16,
        -9.766199148821293e-16, 6.19090466274028e-16,   1.209014056477395e-15,  -3.30244306477483e-16,
        5.974505259635377e-16,  5.993322599035803e-16,  1.829986256691466e-16,  -2.690879534260973e-16,
        8.618341445395283e-16,  -1.002023323072705e-16, 6.374373721894436e-16,  6.270878355192092e-16,
        1.199605386777182e-15,  -8.712428142397415e-16, -2.507410475106815e-16, -1.086230916889613e-15,
        1.072588345824304e-15,  -4.534978795502758e-16, 2.119067633230516e-15,  -1.842923177529259e-15,
        -1.814697168428619e-15, 4.243310034796149e-16,  4.224492695395723e-16,  1.531966643937213e-15,
        -2.850826919164597e-16, -8.958229638315484e-16, -5.02893395476395e-16,  1.096110020074837e-16,
        -6.975352498995555e-16, -8.743006318923108e-16};

// K = 128
// eval_chebyshev_coefficients([](double x) -> double {return std::pow(2.*M_PI, -1./8.) * std::cos(2.*M_PI/8. * (x - 0.25));}, -128, 128, 159)
static constexpr std::initializer_list<double> g_coefficients_fhew128_9{
        0.08761193238226354,    -0.01738402917379392,   0.08935060894767313,    -0.01667686631436392,
        0.09435445639097996,    -0.01518333497826596,   0.1019473189108075,     -0.01276275748916528,
        0.110882655474149,      -0.009252446966171999,  0.1192111685574758,     -0.004534979909938953,
        0.1242004317120066,     0.001362904847617233,   0.1224283765086551,     0.008145596233693092,
        0.1102080588183085,     0.01512350467093644,    0.08449405378412403,    0.02114203679334985,
        0.04431786059830115,    0.02464956129638114,    -0.007454366487154669,  0.02400059020366966,
        -0.06266441339261235,   0.0180491215413637,     -0.1077943201829795,    0.00695836538813938,
        -0.1265848641500751,    -0.007067567033131986,  -0.1060856934163377,    -0.01966175019277508,
        -0.04512467324356773,   -0.02537595733026167,   0.03862916785371963,    -0.0201785566296389,
        0.1092652333753526,     -0.004612578019766411,  0.1263344585514989,     0.01438496124842956,
        0.07022427857484209,    0.02550072245548077,    -0.03434514153678107,   0.01979242584243335,
        -0.1194659697149694,    -0.001008794768691528,  -0.1149256786653964,    -0.02192904329965044,
        -0.01184295110147364,   -0.02417858011117596,   0.1066507410103885,     -0.003076473516323838,
        0.122343225763269,      0.02209885820126707,    0.005200840409852563,   0.02321022960558625,
        -0.1224755172356864,    -0.003930982569218595,  -0.1000653894904632,    -0.02689795846413602,
        0.05865754664309684,    -0.01297065380451242,   0.1377909895596227,     0.02083617539534925,
        0.006502421233003679,   0.02248299870285675,    -0.139660074659475,     -0.01399307934458518,
        -0.04589168496663835,   -0.0263421662574377,    0.1358978738303921,     0.01130242907664306,
        0.05563799538901031,    0.02715486116995984,    -0.1426236952996719,    -0.01461041285557406,
        -0.03302834981489188,   -0.02454368648125577,   0.1559877850928394,     0.02360418859443232,
        -0.03051465817859748,   0.01394389273916019,    -0.1434779685133351,    -0.0326137520114734,
        0.1272587840850199,     0.00968806150092634,    0.04489729856072615,    0.02496761251245225,
        -0.1723551233719199,    -0.03505277577503257,   0.1396636892583818,     0.01468861799711852,
        0.00597622458952793,    0.01686435635501478,    -0.1508869780062401,    -0.0392626068463298,
        0.2221665014327329,     0.04513725581939847,    -0.2157338005707834,    -0.03852627732394119,
        0.1657363840292956,     0.02705951812948022,    -0.1076077703571204,    -0.01637507278621027,
        0.06108202920758021,    0.00876339054415577,    -0.03094805600072437,   -0.004218297546715713,
        0.01419483272929196,    0.001848310901625205,   -0.005954927442783235,  -0.000743844834357433,
        0.002303049930851211,   0.000276890872388833,   -0.0008263094529170254, -9.587788269377866e-05,
        0.000276459761481133,   3.10280277328683e-05,   -8.662530848949058e-05, -9.421991495095434e-06,
        2.551403977799462e-05,  2.693817139509806e-06,  -7.08627853168575e-06,  -7.273160333789605e-07,
        1.861116908629967e-06,  1.859288982562724e-07,  -4.633601616493963e-07, -4.510790623761216e-08,
        1.096004151863654e-07,  1.040757606442787e-08,  -2.467843591423806e-08, -2.288015736340782e-09,
        5.299290810294302e-09,  4.800959747999802e-10,  -1.086991796689273e-09, -9.63033831430537e-11,
        2.133040952766737e-10,  1.849336626863696e-11,  -4.010173216641153e-11, -3.404204559101731e-12,
        7.232799297263385e-12,  6.027665442316686e-13,  -1.252868789531569e-12, -1.035300267428826e-13,
        2.072453780944445e-13,  1.81572061755555e-14,   -3.012503176280137e-14, -4.417490972407089e-16,
        3.698522891563647e-15,  -4.204154533937635e-16, -2.740777660720187e-15, -1.348919106364917e-15,
        -1.620799477984723e-15, 4.003965342611375e-16,  -5.245330582249314e-16, 1.754761547401069e-15,
        -5.0481471966847e-16,   -4.722624632690369e-16, 1.628901569091919e-16,  -1.219903204684612e-15};

// eval_chebyshev_coefficients([](double x) -> double {return std::pow(2.*M_PI, -1./8.) * std::cos(2.*M_PI/8. * (x - 0.25));}, -128, 128, 118)
static constexpr std::initializer_list<double> g_coefficients_fhew128_8{
        0.08761193238226343,   -0.01738402917379268,  0.08935060894767202,    -0.0166768663143651,
        0.09435445639098095,   -0.01518333497826714,  0.1019473189108076,     -0.01276275748916462,
        0.1108826554741475,    -0.009252446966171845, 0.1192111685574773,     -0.004534979909938402,
        0.1242004317120066,    0.001362904847616587,  0.1224283765086535,     0.008145596233693802,
        0.1102080588183083,    0.0151235046709367,    0.08449405378412395,    0.02114203679334948,
        0.04431786059830203,   0.02464956129638117,   -0.007454366487155707,  0.02400059020367158,
        -0.06266441339261287,  0.01804912154136392,   -0.107794320182978,     0.006958365388138488,
        -0.1265848641500738,   -0.007067567033133184, -0.1060856934163389,    -0.01966175019277399,
        -0.0451246732435682,   -0.02537595733026211,  0.0386291678537217,     -0.02017855662963969,
        0.1092652333753532,    -0.004612578019767425, 0.1263344585514991,     0.01438496124843117,
        0.07022427857484087,   0.02550072245548053,   -0.03434514153678073,   0.01979242584243296,
        -0.1194659697149702,   -0.00100879476868968,  -0.1149256786653952,    -0.02192904329965062,
        -0.01184295110147335,  -0.02417858011117619,  0.1066507410103884,     -0.003076473516322021,
        0.1223432257632692,    0.02209885820126752,   0.005200840409853516,   0.02321022960558683,
        -0.1224755172356849,   -0.003930982569218244, -0.1000653894904628,    -0.02689795846413568,
        0.05865754664309823,   -0.01297065380451253,  0.1377909895596233,     0.02083617539534807,
        0.006502421233004046,  0.02248299870285591,   -0.1396600746594754,    -0.01399307934458444,
        -0.04589168496663817,  -0.02634216625743798,  0.1358978738303917,     0.0113024290766429,
        0.05563799538901171,   0.02715486116995986,   -0.1426236952996744,    -0.01461041285557423,
        -0.03302834981489241,  -0.02454368648125667,  0.155987785092838,      0.02360418859443058,
        -0.03051465817859778,  0.01394389273915945,   -0.1434779685133346,    -0.03261375201147241,
        0.1272587840850196,    0.009688061500927738,  0.04489729856072736,    0.02496761251245433,
        -0.1723551233719191,   -0.03505277577503064,  0.1396636892583768,     0.01468861799712161,
        0.005976224589562133,  0.01686435635499993,   -0.1508869780064481,    -0.03926260684622985,
        0.2221665014339838,    0.04513725581879824,   -0.2157338005780147,    -0.03852627732053739,
        0.1657363840693943,    0.02705951811098469,   -0.1076077705704247,    -0.0163750726899083,
        0.06108203029457551,   0.008763390064061401,  -0.03094806130001855,   -0.00421829525869962,
        0.01419485740772663,   0.001848300494047458,  -0.005955037043195616,  -0.000743799726455706,
        0.002303513291010024,  0.0002767049434914361, -0.0008281705698254814, -9.515056665793518e-05,
        0.0002835460400168608, 2.833421059257267e-05, -0.0001121393482639905};

namespace cipher {

//------------------------------------------------------------------------------
// Key and modulus switch and extraction methods
//------------------------------------------------------------------------------

static NativeInteger roundq_q_alter(NativeInteger v, NativeInteger q, NativeInteger Q) {
    return NativeInteger(static_cast<BasicInteger>(
                                 std::floor(0.5 + v.convert_to_double() * q.convert_to_double() / Q.convert_to_double())))
            .mod(q);
}

// TODO: used anywhere?
EvalKey<RnsPoly> switching_key_gen_rlwe(const PrivateKey<RnsPoly>& ckks_sk, ConstLwePrivateKey& LWE_sk) {
    // This function is without the intermediate mod_switch
    // Extract CKKS params: method which populates the first n elements of a new RLWE key with the n elements of the target LWE key
    auto skelements = ckks_sk->get_private_element();
    auto lwesk_elements = LWE_sk->get_element();

    for (size_t i = 0; i < skelements.get_num_of_elements(); i++) {
        auto skelements_plain = skelements.get_element_at_index(i);
        skelements_plain.set_format(Format::COEFFICIENT);
        for (size_t j = 0; j < skelements_plain.get_length(); j++) {
            if (j >= lwesk_elements.get_length()) {
                skelements_plain[j] = 0;
            } else {
                if (lwesk_elements[j] == 0) {
                    skelements_plain[j] = 0;
                } else if (lwesk_elements[j].convert_to_int() == 1) {
                    skelements_plain[j] = 1;
                } else
                    skelements_plain[j] = skelements_plain.get_modulus() - 1;
            }
        }
        skelements_plain.set_format(Format::EVALUATION);
        skelements.set_element_at_index(i, std::move(skelements_plain));
    }
    skelements.override_format(Format::EVALUATION);

    auto cc_ckks = ckks_sk->get_crypto_context();
    auto rlwelw_esk = cc_ckks->key_gen().secret_key;
    rlwelw_esk->set_private_element(std::move(skelements));

    return cc_ckks->key_switch_gen(ckks_sk, rlwelw_esk);
}

void mod_switch(ConstCiphertext<RnsPoly> ctxt, Ciphertext<RnsPoly>& ctxt_ks, NativeInteger modulus_ckks_to) {
    if (ctxt->get_elements()[0].get_ring_dimension() != ctxt_ks->get_elements()[0].get_ring_dimension())
        CIPHER_THROW("ModSwitch is implemented only for the same ring dimension.");
    if (ctxt->get_elements()[0].get_num_of_elements() != 1 || ctxt_ks->get_elements()[0].get_num_of_elements() != 1)
        CIPHER_THROW("ModSwitch is implemented only for ciphertext with one tower.");

    std::vector<RnsPoly> result_elements;
    result_elements.reserve(ctxt->get_elements().size());
    const auto& params_ql_p = ctxt_ks->get_elements()[0].get_params();
    for (const auto& elem : ctxt->get_elements()) {
        auto& ref = result_elements.emplace_back(params_ql_p, Format::COEFFICIENT, true);
        ref.set_values_mod_switch(elem, modulus_ckks_to);
        ref.set_format(Format::EVALUATION);
    }
    ctxt_ks->set_elements(std::move(result_elements));
}

// TODO: used anywhere?
EvalKey<RnsPoly> switching_key_gen(const PrivateKey<RnsPoly>& ckks_s_kto, const PrivateKey<RnsPoly>& ckks_s_kfrom) {
    auto sk_elements = ckks_s_kto->get_private_element();
    sk_elements.set_format(Format::COEFFICIENT);
    auto sk_elements_from = ckks_s_kfrom->get_private_element();
    sk_elements_from.set_format(Format::COEFFICIENT);

    for (size_t i = 0; i < sk_elements.get_num_of_elements(); i++) {
        auto sk_elements_plain = sk_elements.get_element_at_index(i);
        auto sk_elements_from_plain = sk_elements_from.get_element_at_index(i);
        for (size_t j = 0; j < sk_elements_plain.get_length(); j++) {
            if (sk_elements_from_plain[j] == 0) {
                sk_elements_plain[j] = 0;
            } else if (sk_elements_from_plain[j] == 1) {
                sk_elements_plain[j] = 1;
            } else
                sk_elements_plain[j] = sk_elements_plain.get_modulus() - 1;
        }
        sk_elements.set_element_at_index(i, std::move(sk_elements_plain));
    }

    sk_elements.set_format(Format::EVALUATION);

    auto cc_ckks_to = ckks_s_kto->get_crypto_context();
    auto old_tranformed_sk = cc_ckks_to->key_gen().secret_key;
    old_tranformed_sk->set_private_element(std::move(sk_elements));

    return cc_ckks_to->key_switch_gen(old_tranformed_sk, ckks_s_kto);
}

EvalKey<RnsPoly> switching_key_gen_rlwe_cc(const PrivateKey<RnsPoly>& ckks_s_kto, const PrivateKey<RnsPoly>& ckks_s_kfrom,
                                        ConstLwePrivateKey& LWE_sk) {
    auto sk_elements = ckks_s_kto->get_private_element();
    sk_elements.set_format(Format::COEFFICIENT);
    auto sk_elements_from = ckks_s_kfrom->get_private_element();
    sk_elements_from.set_format(Format::COEFFICIENT);
    auto sk_elements2 = ckks_s_kto->get_private_element();
    sk_elements2.set_format(Format::COEFFICIENT);
    auto lwesk_elements = LWE_sk->get_element();

    for (uint32_t i = 0; i < sk_elements.get_num_of_elements(); ++i) {
        auto sk_elements_plain = sk_elements.get_element_at_index(i);
        auto sk_elements_from_plain = sk_elements_from.get_element_at_index(i);
        auto sk_elements_plain_lwe = sk_elements2.get_element_at_index(i);
        for (uint32_t j = 0; j < sk_elements_plain.get_length(); ++j) {
            if (sk_elements_from_plain[j] == 0)
                sk_elements_plain[j] = 0;
            else if (sk_elements_from_plain[j] == 1)
                sk_elements_plain[j] = 1;
            else
                sk_elements_plain[j] = sk_elements_plain.get_modulus() - 1;

            if (j >= lwesk_elements.get_length()) {
                sk_elements_plain_lwe[j] = 0;
            } else {
                if (lwesk_elements[j] == 0)
                    sk_elements_plain_lwe[j] = 0;
                else if (lwesk_elements[j].convert_to_int() == 1)
                    sk_elements_plain_lwe[j] = 1;
                else
                    sk_elements_plain_lwe[j] = sk_elements_plain.get_modulus() - 1;
            }
        }
        sk_elements.set_element_at_index(i, std::move(sk_elements_plain));
        sk_elements2.set_element_at_index(i, std::move(sk_elements_plain_lwe));
    }
    sk_elements.set_format(Format::EVALUATION);
    sk_elements2.set_format(Format::EVALUATION);

    auto cc_ckks_to = ckks_s_kto->get_crypto_context();
    auto old_tranformed_sk = cc_ckks_to->key_gen().secret_key;
    old_tranformed_sk->set_private_element(std::move(sk_elements));
    auto rlwelw_esk = cc_ckks_to->key_gen().secret_key;
    rlwelw_esk->set_private_element(std::move(sk_elements2));

    return cc_ckks_to->key_switch_gen(old_tranformed_sk, rlwelw_esk);
}

std::vector<std::vector<NativeInteger>> extract_lwe_packed(const Ciphertext<RnsPoly>& ct) {
    auto original_a_value{(ct->get_elements()[1]).get_element_at_index(0)};
    original_a_value.set_format(Format::COEFFICIENT);
    auto* ptr_a = &original_a_value.get_values()[0];
    auto original_b_value{(ct->get_elements()[0]).get_element_at_index(0)};
    original_b_value.set_format(Format::COEFFICIENT);
    auto* ptr_b = &original_b_value.get_values()[0];
    size_t N = original_b_value.get_length();
    return {std::vector<NativeInteger>(ptr_b, ptr_b + N), std::vector<NativeInteger>(ptr_a, ptr_a + N)};
}

std::shared_ptr<LweCiphertextImpl> extract_lwe_ciphertext(const std::vector<std::vector<NativeInteger>>& a_an_db,
                                                        NativeInteger modulus, uint32_t n, uint32_t index = 0) {
    NativeVector a(n, modulus);
    for (uint32_t i = 0; i < n && i <= index; ++i)
        a[i] = modulus - a_an_db[1][index - i];
    if (n > index) {
        uint32_t N = a_an_db[0].size();
        for (uint32_t i = index + 1; i < n; ++i)
            a[i] = a_an_db[1][N + index - i];
    }
    return std::make_shared<LweCiphertextImpl>(std::move(a), a_an_db[0][index]);
}

//------------------------------------------------------------------------------
// Linear transformation methods.
//------------------------------------------------------------------------------

std::vector<ReadOnlyPlaintext> CkksRnsSchemeSwitching::eval_lt_precompute_switch(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        const std::vector<std::vector<std::complex<double>>>& B, uint32_t dim1, uint32_t L, double scale = 1.0) const {
    const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    auto element_params = *(crypto_params_ckks->get_element_params());

    uint32_t towers_to_drop = 0;
    if (L != 0) {
        towers_to_drop = element_params.get_params().size() - L - 1;
        for (uint32_t i = 0; i < towers_to_drop; ++i)
            element_params.pop_last_param();
    }

    const auto& params_q = element_params.get_params();
    const auto& params_p = crypto_params_ckks->get_params_p()->get_params();

    size_t size_qp = params_q.size() + params_p.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(size_qp);
    std::vector<NativeInteger> roots;
    roots.reserve(size_qp);
    for (const auto& elem : params_q) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }
    for (const auto& elem : params_p) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }

    auto element_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(cc.get_cyclotomic_order(), moduli, roots);

    int32_t slots = A.size();
    int32_t step = (dim1 == 0) ? get_ratio_bsgslt(slots) : dim1;

    std::vector<std::vector<std::complex<double>>> new_a(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
        new_a[i].reserve(A[i].size() + B[i].size());
        new_a[i].insert(new_a[i].end(), A[i].begin(), A[i].end());
        new_a[i].insert(new_a[i].end(), B[i].begin(), B[i].end());
    }

    uint32_t M4 = cc.get_cyclotomic_order() / 4;
    std::vector<ReadOnlyPlaintext> result(slots);
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(slots))
#endif
    for (int32_t ji = 0; ji < slots; ++ji) {
        auto vec = extract_shifted_diagonal(new_a, ji);
        for (auto& v : vec)
            v *= scale;
        result[ji] = CkksRnsFhe::make_aux_plaintext(cc, element_params_ptr, Rotate(Fill(vec, M4), -step * (ji / step)), 1,
                                                  towers_to_drop, M4);
    }
    return result;
}

std::vector<ReadOnlyPlaintext> CkksRnsSchemeSwitching::eval_lt_precompute_switch(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1,
        uint32_t L, double scale = 1.0) const {
    if (A[0].size() != A.size())
        CIPHER_THROW("The matrix passed to EvalLTPrecomputeSwitch is not square");

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());

    auto element_params = *(crypto_params->get_element_params());

    uint32_t towers_to_drop = 0;
    if (L != 0) {
        towers_to_drop = element_params.get_params().size() - L - 1;
        for (uint32_t i = 0; i < towers_to_drop; i++)
            element_params.pop_last_param();
    }

    const auto& params_q = element_params.get_params();
    const auto& params_p = crypto_params->get_params_p()->get_params();

    size_t size_qp = params_q.size() + params_p.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(size_qp);
    std::vector<NativeInteger> roots;
    roots.reserve(size_qp);
    for (const auto& elem : params_q) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }
    for (const auto& elem : params_p) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }

    auto element_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(cc.get_cyclotomic_order(), moduli, roots);

    int32_t slots = A.size();
    int32_t step = (dim1 == 0) ? get_ratio_bsgslt(slots) : dim1;

    uint32_t M4 = cc.get_cyclotomic_order() / 4;
    std::vector<ReadOnlyPlaintext> result(slots);
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(slots))
#endif
    for (int32_t ji = 0; ji < slots; ++ji) {
        auto vec = extract_shifted_diagonal(A, ji);
        for (auto& v : vec)
            v *= scale;
        result[ji] = CkksRnsFhe::make_aux_plaintext(cc, element_params_ptr, Rotate(Fill(vec, M4), -step * (ji / step)), 1,
                                                  towers_to_drop, M4);
    }
    return result;
}

std::vector<std::vector<std::complex<double>>> eval_lt_rect_precompute_switch(
        const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if (!is_power_of_two(A.size()) || !is_power_of_two(A[0].size()))
        CIPHER_THROW("The matrix passed to EvalLTPrecompute is not padded up to powers of two");

    const uint32_t n = std::min(A.size(), A[0].size());
    std::vector<std::vector<std::complex<double>>> diags(n);

    if (A.size() >= A[0].size()) {
        uint32_t b_step = (dim1 == 0) ? get_ratio_bsgslt(n) : dim1;
        uint32_t g_step = std::ceil(static_cast<double>(n) / b_step);

        auto num_slices = A.size() / A[0].size();
        std::vector<std::vector<std::vector<std::complex<double>>>> a_slices(num_slices);
        for (size_t i = 0; i < num_slices; i++) {
            a_slices[i] = std::vector<std::vector<std::complex<double>>>(A.begin() + i * A[0].size(),
                                                                         A.begin() + (i + 1) * A[0].size());
        }
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(g_step))
        for (uint32_t j = 0; j < g_step; j++) {
            for (uint32_t i = 0; i < b_step; i++) {
                if (b_step * j + i < n) {
                    std::vector<std::complex<double>> diag;
                    diag.reserve(A.size() * num_slices);
                    for (uint32_t k = 0; k < num_slices; k++) {
                        auto tmp = extract_shifted_diagonal(a_slices[k], b_step * j + i);
                        diag.insert(diag.end(), std::make_move_iterator(tmp.begin()),
                                    std::make_move_iterator(tmp.end()));
                    }
                    std::transform(diag.begin(), diag.end(), diag.begin(),
                                   [&](const std::complex<double>& elem) { return elem * scale; });
                    diags[b_step * j + i] = std::move(diag);
                }
            }
        }
    } else {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
        for (uint32_t ji = 0; ji < n; ++ji) {
            auto diag = extract_shifted_diagonal(A, ji);
            for (auto& d : diag)
                d *= scale;
            diags[ji] = std::move(diag);
        }
    }
    return diags;
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_lt_with_precompute_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                               ConstCiphertext<RnsPoly> ctxt,
                                                               const std::vector<ReadOnlyPlaintext>& A, uint32_t dim1,
                                                               bool ext) const {
    // Computing the baby-step b_step and the giant-step g_step
    uint32_t slots = A.size();
    uint32_t b_step = dim1;
    int32_t g_step = std::ceil(static_cast<double>(slots) / b_step);

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.eval_fast_rotation_precompute(ctxt);

    // Hoisted automorphisms
    std::vector<Ciphertext<RnsPoly>> fast_rotation(b_step - 1);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(b_step - 1))
    for (uint32_t j = 1; j < b_step; ++j)
        fast_rotation[j - 1] = cc.eval_fast_rotation_ext(ctxt, j, digits, true);

    auto ctxt_ext = cc.key_switch_ext(ctxt, true);

    // Horner backward accumulation with a single giant stride t = b_step
    uint32_t auto_index = 0;
    std::vector<uint32_t> map;
    EvalKey<RnsPoly> giant_key;
    if (g_step > 1)
        giant_key = CkksRnsFhe::get_giant_step_rotation(ctxt, b_step, auto_index, map);

    const int32_t gtop = b_step * (g_step - 1);
    Ciphertext<RnsPoly> result = CkksRnsFhe::eval_mult_ext(ctxt_ext, A[gtop]);
    for (uint32_t i = 1; i < b_step; ++i)
        if (gtop + i < slots)
            CkksRnsFhe::eval_add_ext_in_place(result, CkksRnsFhe::eval_mult_ext(fast_rotation[i - 1], A[gtop + i]));

    for (int32_t j = g_step - 2; j >= 0; --j) {
        result = CkksRnsFhe::eval_horner_giant_rotate(result, auto_index, map, giant_key);
        const int32_t G = b_step * j;
        auto inner = CkksRnsFhe::eval_mult_ext(ctxt_ext, A[G]);
        for (uint32_t i = 1; i < b_step; ++i)
            CkksRnsFhe::eval_add_ext_in_place(inner, CkksRnsFhe::eval_mult_ext(fast_rotation[i - 1], A[G + i]));
        CkksRnsFhe::eval_add_ext_in_place(result, inner);
    }

    return ext ? result : cc.key_switch_down(result);
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_lt_rect_with_precompute_switch(
        const CryptoContextImpl<RnsPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        ConstCiphertext<RnsPoly> ct, bool wide, uint32_t dim1, uint32_t L) const {
    uint32_t n = std::min(A.size(), A[0].size());

    // Computing the baby-step b_step and the giant-step g_step
    uint32_t b_step = (dim1 == 0) ? get_ratio_bsgslt(n) : dim1;
    int32_t g_step = std::ceil(static_cast<double>(n) / b_step);

    uint32_t M = cc.get_cyclotomic_order();
    uint32_t N = cc.get_ring_dimension();

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.eval_fast_rotation_precompute(ct);

    std::vector<Ciphertext<RnsPoly>> fast_rotation(b_step - 1);

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(ct->get_crypto_parameters());

    RnsParams<RnsPoly::Integer> element_params = *(crypto_params_ckks->get_element_params());
    uint32_t towers_to_drop = 0;

    // For FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    if (L != 0) {
        towers_to_drop = element_params.get_params().size() - L - 1;
        for (uint32_t i = 0; i < towers_to_drop; i++)
            element_params.pop_last_param();
    }
    if (crypto_params_ckks->get_scaling_technique() == FLEXIBLEAUTOEXT) {
        towers_to_drop += 1;
        element_params.pop_last_param();
    }

    const auto& params_q = element_params.get_params();
    const auto& params_p = crypto_params_ckks->get_params_p()->get_params();

    size_t size_qp = params_q.size() + params_p.size();
    std::vector<NativeInteger> moduli;
    moduli.reserve(size_qp);
    std::vector<NativeInteger> roots;
    roots.reserve(size_qp);
    for (const auto& elem : params_q) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }
    for (const auto& elem : params_p) {
        moduli.emplace_back(elem->get_modulus());
        roots.emplace_back(elem->get_root_of_unity());
    }

    auto element_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(M, moduli, roots);
    auto element_params_ptr2 = std::dynamic_pointer_cast<typename RnsPoly::Params>(element_params_ptr);

// Hoisted automorphisms
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(b_step - 1))
    for (uint32_t j = 1; j < b_step; ++j)
        fast_rotation[j - 1] = cc.eval_fast_rotation_ext(ct, j, digits, true);

    // ct raised to the extended (P*Q) basis -- the unrotated (i=0) baby term.
    auto ct_ext = cc.key_switch_ext(ct, true);

    // Horner backward accumulation with a single giant stride t = b_step
    uint32_t auto_index = 0;
    std::vector<uint32_t> map;
    EvalKey<RnsPoly> giant_key;
    if (g_step > 1)
        giant_key = CkksRnsFhe::get_giant_step_rotation(ct, b_step, auto_index, map);

    const int32_t gtop = b_step * (g_step - 1);
    const int32_t off_top = (g_step == 1) ? 0 : -gtop;
    auto temp_top =
            cc.make_ckks_packed_plaintext(Rotate(Fill(A[gtop], N / 2), off_top), 1, towers_to_drop, element_params_ptr2, N / 2);
    Ciphertext<RnsPoly> result = CkksRnsFhe::eval_mult_ext(ct_ext, temp_top);
    for (uint32_t i = 1; i < b_step; ++i) {
        if (gtop + i < n) {
            auto tempi = cc.make_ckks_packed_plaintext(Rotate(Fill(A[gtop + i], N / 2), off_top), 1, towers_to_drop,
                                                    element_params_ptr2, N / 2);
            CkksRnsFhe::eval_add_ext_in_place(result, CkksRnsFhe::eval_mult_ext(fast_rotation[i - 1], tempi));
        }
    }

    for (int32_t j = g_step - 2; j >= 0; --j) {
        result = CkksRnsFhe::eval_horner_giant_rotate(result, auto_index, map, giant_key);
        const int32_t G = b_step * j;
        const int32_t offset = (j == 0) ? 0 : -G;
        auto temp = cc.make_ckks_packed_plaintext(Rotate(Fill(A[G], N / 2), offset), 1, towers_to_drop, element_params_ptr2,
                                               N / 2);
        auto inner = CkksRnsFhe::eval_mult_ext(ct_ext, temp);
        for (uint32_t i = 1; i < b_step; ++i) {
            auto tempi = cc.make_ckks_packed_plaintext(Rotate(Fill(A[G + i], N / 2), offset), 1, towers_to_drop,
                                                    element_params_ptr2, N / 2);
            CkksRnsFhe::eval_add_ext_in_place(inner, CkksRnsFhe::eval_mult_ext(fast_rotation[i - 1], tempi));
        }
        CkksRnsFhe::eval_add_ext_in_place(result, inner);
    }

    // A represents the diagonals, which lose the information whether the initial matrix is tall or wide
    if (wide) {
        uint32_t logl = cipher::get_msb(A[0].size() / A.size()) - 1;  // These are powers of two, so log(l) is integer
        for (uint32_t j = 1; j <= logl; ++j) {
            uint32_t auto_index = 0;
            std::vector<uint32_t> map;
            auto eval_key = CkksRnsFhe::get_giant_step_rotation(result, static_cast<int32_t>(A.size() * (1 << (j - 1))),
                                                            auto_index, map);
            CkksRnsFhe::eval_add_ext_in_place(result, CkksRnsFhe::eval_horner_giant_rotate(result, auto_index, map, eval_key));
        }
    }

    return cc.key_switch_down(result);
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_slots_to_coeffs_switch(const CryptoContextImpl<RnsPoly>& cc,
                                                            ConstCiphertext<RnsPoly> ctxt) const {
    if (u0_pre_.size() == 0)
        CIPHER_THROW("Precomputations not generated. Call EvalCKKSToFHEWPrecompute to proceed.");

    uint32_t m = 4 * num_slots_ckks_;
    uint32_t M = cc.get_cyclotomic_order();
    bool is_sparse = (M != m);

    auto ctxt_to_decode = ctxt->clone();

    uint32_t num_towers_to_keep = 2;
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    if (crypto_params->get_scaling_technique() == ScalingTechnique::FLEXIBLEAUTO ||
        crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) {
        ctxt_to_decode = cc.compress(ctxt_to_decode, num_towers_to_keep + 1);

        double target_sf = crypto_params->get_scaling_factor_real(crypto_params->get_element_params()->get_params().size() -
                                                             num_towers_to_keep);
        double source_sf = ctxt_to_decode->get_scaling_factor();
        uint32_t num_towers = ctxt_to_decode->get_elements()[0].get_num_of_elements();
        double mod_to_drop = crypto_params->get_element_params()->get_params()[num_towers - 1]->get_modulus().convert_to_double();
        double adjustment_factor = (target_sf / source_sf) * (mod_to_drop / source_sf);

        ctxt_to_decode = cc.eval_mult(ctxt_to_decode, adjustment_factor);
        cc.get_scheme()->mod_reduce_internal_in_place(ctxt_to_decode, 1);
        ctxt_to_decode->set_scaling_factor(target_sf);
    } else {
        ctxt_to_decode = cc.compress(ctxt_to_decode, num_towers_to_keep);
    }

    Ciphertext<RnsPoly> ctxt_decoded;
    if (!is_sparse) {  // fully packed
        // ctxt_to_decode = cc.eval_add(ctxt_to_decode, cc.get_scheme()->mult_by_monomial(ctxt_to_decode, M / 4));
        ctxt_decoded = eval_lt_with_precompute_switch(cc, ctxt_to_decode, u0_pre_, dim1_cf_);
    } else {  // sparsely packed
        auto ctxt_ext = eval_lt_with_precompute_switch(cc, ctxt_to_decode, u0_pre_, dim1_cf_, true);
        uint32_t auto_index = 0;
        std::vector<uint32_t> map;
        auto eval_key = CkksRnsFhe::get_giant_step_rotation(ctxt_ext, num_slots_ckks_, auto_index, map);
        CkksRnsFhe::eval_add_ext_in_place(ctxt_ext, CkksRnsFhe::eval_horner_giant_rotate(ctxt_ext, auto_index, map, eval_key));
        ctxt_decoded = cc.key_switch_down(ctxt_ext);
    }
    return ctxt_decoded;
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_partial_hom_decryption(const CryptoContextImpl<RnsPoly>& cc,
                                                             const std::vector<std::vector<std::complex<double>>>& A,
                                                             ConstCiphertext<RnsPoly> ct, uint32_t dim1, double scale,
                                                             uint32_t L) const {
    // Currently, by design, the # rows (# LWE ciphertexts to switch) is a power of two.
    // Ensure that # cols (LWE lattice parameter n) is padded up to a power of two
    auto acopy = A;
    size_t cols_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(A[0].size())));
    if (cols_po2 > A[0].size()) {
        for (size_t i = 0; i < A.size(); ++i)
            acopy[i].resize(cols_po2);
    }

    auto apre = eval_lt_rect_precompute_switch(acopy, dim1, scale);
    // The result is repeated every Acopy.size() slots
    return eval_lt_rect_with_precompute_switch(cc, apre, ct, (acopy.size() < A[0].size()), dim1, L);
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
LwePrivateKey CkksRnsSchemeSwitching::eval_ckks_to_fhew_setup(const SchSwchParams& params) {
    if (params.get_security_level_fhew() != TOY && params.get_security_level_fhew() != STD128)
        CIPHER_THROW("Only STD128 or TOY are currently supported.");

    uint32_t ring_dim = params.get_ring_dimension();
    num_slots_ckks_ = (params.get_num_slots_ckks() == 0) ? ring_dim / 2 : params.get_num_slots_ckks();

    modulus_ckks_initial_ = params.get_initial_ckks_modulus();
    // Modulus to switch to in order to have secure RLWE samples with ring dimension n.
    // We can select any Qswitch less than 27 bits corresponding to 128 bits of security for lattice parameter n=1024 < 1305
    // according to https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // or any Qswitch for TOY security.

    // Ensure that Qswitch is larger than Q_FHEW and smaller than Q_CKKS.
    if (params.get_ctxt_mod_size_fhew_intermed_swch() <= params.get_ctxt_mod_size_fhew_large_prec() ||
        params.get_ctxt_mod_size_fhew_intermed_swch() > modulus_ckks_initial_.get_msb() - 1) {
        CIPHER_THROW("Qswitch should be larger than QFHEW and smaller than QCKKS.");
    }

    // Intermediate cryptocontext
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(0);
    parameters.set_first_mod_size(params.get_ctxt_mod_size_fhew_intermed_swch());
    // scaling mod size is not used in this case
    parameters.set_scaling_mod_size(params.get_ctxt_mod_size_fhew_intermed_swch());
    // This doesn't need this to be the same scaling technique as the outer cryptocontext, since we only do a key switch
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_security_level(params.get_security_level_ckks());
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(params.get_batch_size());
    parameters.set_ckks_data_type(REAL);

    cc_ks_ = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc_ks_->enable(PKE);
    cc_ks_->enable(KEYSWITCH);

    // Get the ciphertext modulus
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc_ks_->get_crypto_parameters());
    modulus_ckks_from_ = crypto_params->get_element_params()->get_params()[0]->get_modulus();

    cc_lwe_ = std::make_shared<BooleanContext>();
    cc_lwe_->BooleanContext::generate_boolean_context(
            params.get_security_level_fhew(), params.get_arbitrary_function_evaluation(),
            params.get_ctxt_mod_size_fhew_large_prec(), 0, GINX, params.get_use_dynamic_mode_fhew());

    // For arbitrary functions, the LWE ciphertext needs to be at most the ring dimension in FHEW bootstrapping
    modulus_lwe_ = (!params.get_arbitrary_function_evaluation()) ?
                            1 << params.get_ctxt_mod_size_fhew_large_prec() :
                            cc_lwe_->get_params()->get_lwe_params()->get_q().convert_to_int();

    // The baby-step and number of levels for the linear transformation associated to the homomorphic decoding
    dim1_cf_ = (params.get_b_step_l_tr_ckks_to_fhew() == 0) ? get_ratio_bsgslt(params.get_num_slots_ckks()) :
                                                       params.get_b_step_l_tr_ckks_to_fhew();
    lcf_ = params.get_level_l_tr_ckks_to_fhew();

    // Return LWE private key
    return cc_lwe_->key_gen();
}

std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> CkksRnsSchemeSwitching::eval_ckks_to_fhew_key_gen(
        const KeyPair<RnsPoly>& key_pair, ConstLwePrivateKey& lwesk) {
    auto& private_key = key_pair.secret_key;

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(private_key->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO || crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto cc_ckks = private_key->get_crypto_context();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = cc_ks_->key_gen();

    ctxt_ks_ = cc_ks_->encrypt(keys2.public_key, cc_ks_->make_ckks_packed_plaintext(std::vector<double>{0.0}));

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    ckks_to_fhew_swk_ = switching_key_gen_rlwe_cc(keys2.secret_key, private_key, lwesk);

    // Compute automorphism keys
    uint32_t M = cc_ckks->get_cyclotomic_order();
    uint32_t slots = num_slots_ckks_;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> index_rotation_s2_c = find_lt_rotation_indices_switch(dim1_cf_, M, slots);
    index_rotation_s2_c.emplace_back(static_cast<int32_t>(slots));

    // Remove possible duplicates and zero
    sort(index_rotation_s2_c.begin(), index_rotation_s2_c.end());
    index_rotation_s2_c.erase(unique(index_rotation_s2_c.begin(), index_rotation_s2_c.end()), index_rotation_s2_c.end());
    index_rotation_s2_c.erase(std::remove(index_rotation_s2_c.begin(), index_rotation_s2_c.end(), 0), index_rotation_s2_c.end());

    auto algo = cc_ckks->get_scheme();

    // Compute multiplication key
    algo->eval_mult_key_gen(private_key);

    auto eval_keys = algo->eval_at_index_key_gen(private_key, index_rotation_s2_c);

    // Compute conjugation key
    (*eval_keys)[M - 1] = CkksRnsFhe::conjugate_key_gen(private_key);

    return eval_keys;
}

void CkksRnsSchemeSwitching::eval_ckks_to_fhew_precompute(const CryptoContextImpl<RnsPoly>& cc, double scale) {
    uint32_t M = cc.get_cyclotomic_order();
    uint32_t slots = num_slots_ckks_;
    uint32_t m = 4 * num_slots_ckks_;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool is_sparse = (M != m);

    // Computes indices for all primitive roots of unity
    std::vector<uint32_t> rot_group(slots);
    uint32_t five_pows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rot_group[i] = five_pows;
        five_pows *= 5;
        five_pows &= mmask;
    }
    // Computes all powers of a primitive root of unity exp(2*M_PI/m)
    std::vector<std::complex<double>> ksi_pows(m + 1);
    double ak = 2 * M_PI / m;
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksi_pows[j].real(std::cos(angle));
        ksi_pows[j].imag(std::sin(angle));
    }
    ksi_pows[m] = ksi_pows[0];

    // Matrices for decoding
    std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
    std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));

    for (uint32_t i = 0; i < slots; ++i) {
        for (uint32_t j = 0; j < slots; ++j) {
            U0[i][j] = ksi_pows[(j * rot_group[i]) & mmask];
            U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
        }
    }

    // Obtain the right scaling for encoded messages in FHEW coming from encoded messages in CKKS
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc.get_crypto_parameters());
    double sc_factor = crypto_params->get_scaling_factor_real(crypto_params->get_element_params()->get_params().size() - 1);
    scale *= modulus_ckks_initial_.convert_to_double() / sc_factor;

    if (!is_sparse) {  // fully packed
        u0_pre_ = eval_lt_precompute_switch(cc, U0, dim1_cf_, lcf_, scale);
    } else {  // sparsely packed
        u0_pre_ = eval_lt_precompute_switch(cc, U0, U1, dim1_cf_, lcf_, scale);
    }
}

std::vector<std::shared_ptr<LweCiphertextImpl>> CkksRnsSchemeSwitching::eval_ckks_to_fhew(ConstCiphertext<RnsPoly> ciphertext,
                                                                              uint32_t num_ctxts) {
    if (num_ctxts == 0 || num_ctxts > num_slots_ckks_)
        num_ctxts = num_slots_ckks_;

    // Step 1. Homomorphic decoding
    auto cc_ckks = ciphertext->get_crypto_context();
    auto ctxt_decoded = eval_slots_to_coeffs_switch(*cc_ckks, ciphertext);
    cc_ckks->get_scheme()->mod_reduce_internal_in_place(ctxt_decoded, 1);

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc_ckks->get_crypto_parameters());

    // Step 2. Modulus switch to Q', such that CKKS is secure for (Q',n)
    auto ctxt_ks = ctxt_ks_->clone();
    mod_switch(ctxt_decoded, ctxt_ks, modulus_ckks_from_);

    // Step 3: Key switch from the CKKS key with the new modulus Q' to the RLWE version of the FHEW key with the new modulus Q'
    auto cc_ks = ctxt_ks->get_crypto_context();  // Use this instead of cc_ks_ to work with serialization
    auto ct_switched = cc_ks->key_switch(ctxt_ks, ckks_to_fhew_swk_);

    // Step 4. Extract LWE ciphertexts with the modulus Q'
    uint32_t n = cc_lwe_->get_params()->get_lwe_params()->get_n();  // lattice parameter for additive LWE
    std::vector<std::shared_ptr<LweCiphertextImpl>> LWE_ciphertexts(num_ctxts);
    auto aand_b = extract_lwe_packed(ct_switched);

    uint32_t gap = cc_ks->get_ring_dimension() / (2 * num_slots_ckks_);
    for (uint32_t i = 0, idx = 0; i < num_ctxts; ++i, idx += gap)
        LWE_ciphertexts[i] = extract_lwe_ciphertext(aand_b, modulus_ckks_from_, n, idx);

    // Step 5. Modulus switch to q in FHEW

    // Compute the necessary factor to obtaine the message Q'/p_lwe
    if (modulus_lwe_ != modulus_ckks_from_) {
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_ctxts))
        for (uint32_t i = 0; i < num_ctxts; ++i) {
            auto& original_a = LWE_ciphertexts[i]->get_A();
            auto original_b = LWE_ciphertexts[i]->get_B();
            // multiply by Q_LWE/Q' and round to Q_LWE
            NativeVector a_round(n, modulus_lwe_);
            for (uint32_t j = 0; j < n; ++j)
                a_round[j] = roundq_q_alter(original_a[j], modulus_lwe_, modulus_ckks_from_);
            NativeInteger b_round = roundq_q_alter(original_b, modulus_lwe_, modulus_ckks_from_);
            LWE_ciphertexts[i] = std::make_shared<LweCiphertextImpl>(std::move(a_round), std::move(b_round));
        }
    }

    return LWE_ciphertexts;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
void CkksRnsSchemeSwitching::eval_fhew_to_ckks_setup(const CryptoContextImpl<RnsPoly>& cc_ckks,
                                        const std::shared_ptr<BooleanContext>& cc_lwe, uint32_t num_slots_ckks,
                                        uint32_t log_q) {
    if (cc_lwe->get_params()->get_lwe_params()->get_n() * 2 > cc_ckks.get_ring_dimension())
        CIPHER_THROW("The lattice parameter in LWE cannot be larger than half the RLWE ring dimension.");
    cc_lwe_ = cc_lwe;

    if (num_slots_ckks == 0) {
        if (cc_ckks.get_encoding_params()->get_batch_size() != 0)
            num_slots_ckks_ = cc_ckks.get_encoding_params()->get_batch_size();
        else
            num_slots_ckks_ = cc_ckks.get_ring_dimension() / 2;
    } else {
        num_slots_ckks_ = num_slots_ckks;
    }

    modulus_lwe_ = (log_q != 0) ? uint64_t{1} << log_q : cc_lwe_->get_params()->get_lwe_params()->get_q().convert_to_int();
}

std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> CkksRnsSchemeSwitching::eval_fhew_to_ckks_key_gen(
        const KeyPair<RnsPoly>& key_pair, ConstLwePrivateKey& lwesk, uint32_t num_slots, uint32_t num_ctxts,
        uint32_t dim1, uint32_t L) {
    auto& private_key = key_pair.secret_key;
    auto& public_key = key_pair.public_key;

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(private_key->get_crypto_parameters());
    auto cc_ckks = private_key->get_crypto_context();

    uint32_t n = lwesk->get_element().get_length();
    uint32_t ring_dim = cc_ckks->get_ring_dimension();

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key. Pad up to the closest power of two
    uint32_t n_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(n)));
    auto& sk_lwe_elements = lwesk->get_element();
    const auto neg = lwesk->get_modulus().convert_to_double() - 1.0;
    std::vector<std::complex<double>> sk_lwe_double(n_po2);
    for (uint32_t i = 0; i < n; ++i) {
        auto tmp = sk_lwe_elements[i].convert_to_double();
        sk_lwe_double[i] = std::complex<double>(tmp == neg ? -1.0 : tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext sk_lwe_plainswk;
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        sk_lwe_plainswk = cc_ckks->make_ckks_packed_plaintext(Fill(sk_lwe_double, ring_dim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ring_dim / 2);
    else
        sk_lwe_plainswk = cc_ckks->make_ckks_packed_plaintext(Fill(sk_lwe_double, ring_dim / 2), 1, 0, nullptr, ring_dim / 2);

    fhew_to_ckks_swk_ = cc_ckks->encrypt(public_key, sk_lwe_plainswk);

    // Compute automorphism keys for CKKS for baby-step giant-step
    if (num_ctxts == 0)
        num_ctxts = num_slots_ckks_;  // If no value is specified, default to the column size of the linear transformation
    uint32_t M = cc_ckks->get_cyclotomic_order();
    if (dim1 == 0)
        dim1 = get_ratio_bsgslt(num_ctxts);
    dim1_fc_ = dim1;
    lfc_ = L;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> index_rotation_hom_dec = find_lt_rotation_indices_switch(dim1, M, num_ctxts);

    // If the linear transform is wide instead of tall, we need extra rotations
    if (num_ctxts < n_po2) {
        uint32_t logl = cipher::get_msb(n_po2 / num_ctxts) - 1;  // These are powers of two, so log(l) is integer
        index_rotation_hom_dec.reserve(index_rotation_hom_dec.size() + logl);
        for (uint32_t j = 1; j <= logl; ++j)
            index_rotation_hom_dec.emplace_back(num_ctxts * (1 << (j - 1)));
    }

    uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;
    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    // (the radix-configured eval_partial_sum_in_place fold)
    if (ring_dim > 2 * slots) {  // if the encoding is full, this does not execute
        constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
        const uint32_t size = ring_dim / (2 * slots);
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                index_rotation_hom_dec.emplace_back(static_cast<int32_t>(idx));
    }

    // Remove possible duplicates and zero
    sort(index_rotation_hom_dec.begin(), index_rotation_hom_dec.end());
    index_rotation_hom_dec.erase(unique(index_rotation_hom_dec.begin(), index_rotation_hom_dec.end()),
                              index_rotation_hom_dec.end());
    index_rotation_hom_dec.erase(std::remove(index_rotation_hom_dec.begin(), index_rotation_hom_dec.end(), 0),
                              index_rotation_hom_dec.end());

    auto algo = cc_ckks->get_scheme();
    auto eval_keys = algo->eval_at_index_key_gen(private_key, index_rotation_hom_dec);

    // Compute multiplication key
    cc_ckks->eval_mult_key_gen(private_key);

    return eval_keys;
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_fhew_to_ckks(std::vector<std::shared_ptr<LweCiphertextImpl>>& lwe_ciphertexts,
                                                   uint32_t num_ctxts, uint32_t num_slots, uint32_t p, double pmin,
                                                   double pmax, uint32_t dim1) const {
    if (lwe_ciphertexts.empty())
        CIPHER_THROW("Empty input FHEW ciphertext vector");

    // This is the number of CKKS slots to use in encoding
    const uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;

    uint32_t num_lwe_ctxts = lwe_ciphertexts.size();
    uint32_t num_values = (num_ctxts == 0) ? num_lwe_ctxts : std::min(num_ctxts, num_lwe_ctxts);
    num_values = std::min(num_values, slots);  // This is the number of LWE ciphertexts to pack into the CKKS ciphertext

    uint32_t n = lwe_ciphertexts[0]->get_A().get_length();

    auto cc_ckks = fhew_to_ckks_swk_->get_crypto_context();
    const auto crypto_params_ckks = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc_ckks->get_crypto_parameters());

    uint32_t m = 4 * slots;
    uint32_t M = cc_ckks->get_cyclotomic_order();
    uint32_t N = cc_ckks->get_ring_dimension();
    bool is_sparse = (M != m);

    double K = 0.0;
    std::vector<double> coefficients_fhew;  // eval_fhew_to_ckks assumes lattice parameter n is at most 2048.
    if (n == 32) {
        K = 16.0;
        coefficients_fhew.assign(g_coefficients_fhew16);
    } else {
        K = 128.0;  // Failure probability of 2^{-49}
        if (p <= 4) {
            // If the output messages are bits, we could use a lower degree polynomial
            coefficients_fhew.assign(g_coefficients_fhew128_8);
        } else {
            coefficients_fhew.assign(g_coefficients_fhew128_9);
        }
    }

    // Step 1. Form matrix A and vector b from the LWE ciphertexts, but only extract the first necessary number of them
    std::vector<std::vector<std::complex<double>>> A(num_values);

    // To have the same encoding as A*s, create b with the appropriate number of elements
    const uint32_t b_size = std::min(((num_values % n) != 0) ? (num_values + n - (num_values % n)) : num_values, N / 2);
    std::vector<std::complex<double>> b(b_size);

    // Combine the scale with the division by K to consume fewer levels, but careful since the value might be too small
    const double prescale = (1.0 / lwe_ciphertexts[0]->get_modulus().convert_to_double()) / K;

#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(num_values))
    for (uint32_t i = 0; i < num_values; ++i) {
        auto& a = lwe_ciphertexts[i]->get_A();
        A[i].resize(a.get_length());
        for (uint32_t j = 0; j < a.get_length(); ++j)
            A[i][j] = std::complex<double>(a[j].convert_to_double(), 0);
        b[i] = std::complex<double>(prescale * lwe_ciphertexts[i]->get_B().convert_to_double(), 0);
    }

    // Step 2. Perform the homomorphic linear transformation of A*skLWE
    if (dim1 == 0)
        dim1 = dim1_fc_;
    auto adot_s = eval_partial_hom_decryption(*cc_ckks, A, fhew_to_ckks_swk_, dim1, prescale, 0);

    // Step 3. Get the ciphertext of B - A*s
    Plaintext b_plain = cc_ckks->make_ckks_packed_plaintext(b, adot_s->get_noise_scale_deg(), adot_s->get_level(), nullptr, N / 2);
    auto bminus_adot_s = cc_ckks->eval_add(cc_ckks->eval_negate(adot_s), b_plain);
    if (crypto_params_ckks->get_scaling_technique() == FIXEDMANUAL)
        cc_ckks->mod_reduce_in_place(bminus_adot_s);
    else if (bminus_adot_s->get_noise_scale_deg() == 2)
        cc_ckks->get_scheme()->mod_reduce_internal_in_place(bminus_adot_s, BASE_NUM_LEVELS_TO_DROP);

    // Step 4. Do the modulus reduction: homomorphically evaluate modular function. We do it by using sine approximation.
    // auto BminusAdotS2 = bminus_adot_s;  // Instead of zeroing out slots which are not of interest as done above

    double a_cheby = -1.0;
    double b_cheby = 1.0;  // The division by K was performed before

    // double a_cheby = -K; double b_cheby = K; // Alternatively, do this separately to not lose precision when scaling with everything at once
    auto bminus_adot_s3 = cc_ckks->eval_chebyshev_series(bminus_adot_s, coefficients_fhew, a_cheby, b_cheby);
    if (crypto_params_ckks->get_scaling_technique() != FIXEDMANUAL)
        cc_ckks->get_scheme()->mod_reduce_internal_in_place(bminus_adot_s3, BASE_NUM_LEVELS_TO_DROP);

    const int32_t BT_ITER = 3;
    for (int32_t j = 1; j <= BT_ITER; ++j) {
        bminus_adot_s3 = cc_ckks->eval_mult(bminus_adot_s3, bminus_adot_s3);
        cc_ckks->eval_add_in_place(bminus_adot_s3, bminus_adot_s3);
        double scalar = 1.0 / std::pow((2.0 * M_PI), std::pow(2.0, j - BT_ITER));
        cc_ckks->eval_sub_in_place(bminus_adot_s3, scalar);
        if (crypto_params_ckks->get_scaling_technique() == FIXEDMANUAL)
            cc_ckks->mod_reduce_in_place(bminus_adot_s3);
        else
            cc_ckks->get_scheme()->mod_reduce_internal_in_place(bminus_adot_s3, BASE_NUM_LEVELS_TO_DROP);
    }

    /* For p <= 4 and when we only encrypt bits, we don't need sin(2pi*x)/2pi to approximate x,
     * we can directly use sin(0) for 0 and sin(pi/2) for 1.
     * Here pmax is actually the plaintext modulus, not the maximum value of the messages that we
     * consider. For plaintext modulus > 4, even if we only care about encrypting bits, 2pi is not
     * the correct post-scaling factor.
     * Moreover, we have to account for the different encoding the end ciphertext should have.
     */
    double post_scale = (p >= 1 && p <= 4) ? (2.0 * M_PI) : static_cast<double>(p);
    double post_bias = 0.0;
    if (pmin != 0) {
        post_scale *= (pmax - pmin) / 4.0;
        post_bias = (pmax - pmin) / 4.0;
    }

    // num_values are set; the rest of values up to N/2 are made zero when creating the plaintext
    std::vector<std::complex<double>> post_scale_vec(num_values, std::complex<double>(post_scale, 0));
    std::vector<std::complex<double>> post_bias_vec(num_values, std::complex<double>(post_bias, 0));

    RnsParams<RnsPoly::Integer> element_params = *(crypto_params_ckks->get_element_params());

    uint32_t towers_to_drop = bminus_adot_s3->get_level() + bminus_adot_s3->get_noise_scale_deg() - 1;
    for (uint32_t i = 0; i < towers_to_drop; i++)
        element_params.pop_last_param();

    // Use full packing here to clear up the junk in the slots after num_values
    auto post_scale_plain = cc_ckks->make_ckks_packed_plaintext(post_scale_vec, 1, towers_to_drop, nullptr, N / 2);
    auto bminus_adot_sres = cc_ckks->eval_mult(bminus_adot_s3, post_scale_plain);

    // Add the plaintext for bias at the correct level and depth
    auto post_bias_plain = cc_ckks->make_ckks_packed_plaintext(post_bias_vec, bminus_adot_sres->get_noise_scale_deg(),
                                                         bminus_adot_sres->get_level(), nullptr, N / 2);

    cc_ckks->eval_add_in_place(bminus_adot_sres, post_bias_plain);

    // Go back to the sparse encoding if needed
    if (is_sparse) {
        CkksRnsFhe::eval_partial_sum_in_place(bminus_adot_sres, slots, N / (2 * slots), CIPHER_PARTIAL_SUM_RADIX);
        bminus_adot_sres->set_slots(slots);
    }

    if (crypto_params_ckks->get_scaling_technique() == FIXEDMANUAL) {
        cc_ckks->mod_reduce_in_place(bminus_adot_sres);
    }

    return bminus_adot_sres;
}

LwePrivateKey CkksRnsSchemeSwitching::eval_scheme_switching_setup(const SchSwchParams& params) {
    // FHEW to CKKS
    // Save the parameters to be used in eval_scheme_switching_key_gen
    argmin_ = params.get_compute_argmin();
    one_hot_ = params.get_one_hot_encoding();
    alt_ = params.get_use_alt_argmin();

    // Set parameters for linear transform for FHEW to CKKS
    if (!argmin_ || (argmin_ && alt_)) {
        num_ctxts_ = (params.get_num_values() == 0) ? num_slots_ckks_ : params.get_num_values();
    } else {  // argmin not in the alternative mode
        num_ctxts_ = (params.get_num_values() == 0) ? num_slots_ckks_ / 2 : params.get_num_values() / 2;
    }

    // There are multiple dim1's required in argmin, but they are specified individually in eval_scheme_switching_key_gen
    dim1_fc_ = (params.get_b_step_l_tr_fhew_to_ckks() == 0) ? get_ratio_bsgslt(num_ctxts_) : params.get_b_step_l_tr_fhew_to_ckks();
    lfc_ = params.get_level_l_tr_fhew_to_ckks();

    // CKKS to FHEW
    return eval_ckks_to_fhew_setup(params);
}

std::shared_ptr<std::map<uint32_t, EvalKey<RnsPoly>>> CkksRnsSchemeSwitching::eval_scheme_switching_key_gen(
        const KeyPair<RnsPoly>& key_pair, ConstLwePrivateKey& lwesk) {
    auto& private_key = key_pair.secret_key;
    auto& public_key = key_pair.public_key;

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(private_key->get_crypto_parameters());

    if (crypto_params->get_key_switch_technique() != HYBRID)
        CIPHER_THROW("CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if CIPHER_NATIVE_INT == 128
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTO || crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        CIPHER_THROW("128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto cc_ckks = private_key->get_crypto_context();

    uint32_t M = cc_ckks->get_cyclotomic_order();
    uint32_t slots = num_slots_ckks_;
    uint32_t n = lwesk->get_element().get_length();
    uint32_t ring_dim = cc_ckks->get_ring_dimension();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = cc_ks_->key_gen();

    Plaintext ptxt_zero_ks = cc_ks_->make_ckks_packed_plaintext(std::vector<double>{0.0}, 1, 0, nullptr, slots);
    ctxt_ks_ = cc_ks_->encrypt(keys2.public_key, ptxt_zero_ks);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    ckks_to_fhew_swk_ = switching_key_gen_rlwe_cc(keys2.secret_key, private_key, lwesk);

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key. Pad up to the closest power of two
    uint32_t n_po2 = 1 << static_cast<uint32_t>(std::ceil(std::log2(n)));
    auto sk_lwe_elements = lwesk->get_element();
    const auto neg = lwesk->get_modulus().convert_to_double() - 1.0;
    std::vector<std::complex<double>> sk_lwe_double(n_po2);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = sk_lwe_elements[i].convert_to_double();
        sk_lwe_double[i] = std::complex<double>(tmp == neg ? -1.0 : tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext sk_lwe_plainswk;
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        sk_lwe_plainswk = cc_ckks->make_ckks_packed_plaintext(Fill(sk_lwe_double, ring_dim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ring_dim / 2);
    else
        sk_lwe_plainswk = cc_ckks->make_ckks_packed_plaintext(Fill(sk_lwe_double, ring_dim / 2), 1, 0, nullptr, ring_dim / 2);

    fhew_to_ckks_swk_ = cc_ckks->encrypt(public_key, sk_lwe_plainswk);

    // Compute automorphism keys

    /* CKKS to FHEW */
    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> index_rotation_s2_c = find_lt_rotation_indices_switch(dim1_cf_, M, slots);
    index_rotation_s2_c.emplace_back(static_cast<int32_t>(slots));

    // Compute indices for rotations for sparse packing
    if (ring_dim > 2 * slots) {  // if the encoding is full, this does not execute
        index_rotation_s2_c.reserve(index_rotation_s2_c.size() + get_msb(ring_dim) - 2 + get_msb(slots));
        for (uint32_t i = 1; i < ring_dim / 2; i <<= 1) {
            index_rotation_s2_c.emplace_back(static_cast<int32_t>(i));
            if (i <= slots)
                index_rotation_s2_c.emplace_back(-static_cast<int32_t>(i));
        }
    }

    /* FHEW to CKKS */
    std::vector<int32_t> index_rotation_hom_dec;
    std::vector<int32_t> index_rotation_argmin;

    if (!argmin_ || (argmin_ && alt_)) {
        // Compute indices for rotations for homomorphic decryption
        index_rotation_hom_dec = find_lt_rotation_indices_switch(dim1_fc_, M, num_ctxts_);

        // If the linear transform is wide instead of tall, we need extra rotations
        if (num_ctxts_ < n_po2) {
            uint32_t logl = cipher::get_msb(n_po2 / num_ctxts_) - 1;  // These are powers of two, so log(l) is integer
            index_rotation_hom_dec.reserve(index_rotation_hom_dec.size() + logl);
            for (size_t j = 1; j <= logl; ++j) {
                index_rotation_hom_dec.emplace_back(num_ctxts_ * (1 << (j - 1)));
            }
        }
        if (argmin_) {
            // Rotations for postprocessing after a level of the binary tree
            index_rotation_argmin.reserve(get_msb(num_ctxts_) - 2);
            for (uint32_t i = 1; i < num_ctxts_; i <<= 1) {
                index_rotation_argmin.emplace_back(static_cast<int32_t>(num_ctxts_ / (2 * i)));
            }
        }
    } else {  // argmin not in the alternative mode
        // Compute indices for rotations for all homomorphic decryptions for the levels of the tree
        index_rotation_hom_dec = find_lt_rotation_indices_switch_argmin(M, num_ctxts_, n_po2);

        // Rotations for postprocessing after a level of the binary tree
        index_rotation_argmin.reserve(get_msb(num_ctxts_) - 1 + 2 * (get_msb(num_ctxts_) - 1));
        for (uint32_t i = 1; i < 2 * num_ctxts_; i <<= 1) {
            index_rotation_argmin.emplace_back(static_cast<int32_t>(num_ctxts_ / (2 * i)));
            index_rotation_argmin.emplace_back(-static_cast<int32_t>(num_ctxts_ / (2 * i)));
            if (i > 1) {
                for (uint32_t j = 2 * num_ctxts_ / i; j < 2 * num_ctxts_; j <<= 1)
                    index_rotation_argmin.emplace_back(-static_cast<int32_t>(j));
            }
        }
    }

    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    // (the radix-configured eval_partial_sum_in_place fold)
    if (ring_dim > 2 * slots) {  // if the encoding is full, this does not execute
        constexpr uint32_t radix = CIPHER_PARTIAL_SUM_RADIX;
        const uint32_t size = ring_dim / (2 * slots);
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                index_rotation_hom_dec.emplace_back(static_cast<int32_t>(idx));
    }

    // Combine the indices lists
    index_rotation_s2_c.reserve(index_rotation_s2_c.size() + index_rotation_hom_dec.size() + index_rotation_argmin.size());
    index_rotation_s2_c.insert(index_rotation_s2_c.end(), index_rotation_hom_dec.begin(), index_rotation_hom_dec.end());
    index_rotation_s2_c.insert(index_rotation_s2_c.end(), index_rotation_argmin.begin(), index_rotation_argmin.end());

    // Remove possible duplicates and zero
    sort(index_rotation_s2_c.begin(), index_rotation_s2_c.end());
    index_rotation_s2_c.erase(unique(index_rotation_s2_c.begin(), index_rotation_s2_c.end()), index_rotation_s2_c.end());
    index_rotation_s2_c.erase(std::remove(index_rotation_s2_c.begin(), index_rotation_s2_c.end(), 0), index_rotation_s2_c.end());

    auto algo = cc_ckks->get_scheme();
    auto eval_keys = algo->eval_at_index_key_gen(private_key, index_rotation_s2_c);

    // Compute conjugation key
    auto conj_key = CkksRnsFhe::conjugate_key_gen(private_key);
    (*eval_keys)[M - 1] = conj_key;

    // Compute multiplication key
    cc_ckks->eval_mult_key_gen(private_key);

    // Compute automorphism keys if we don't want one hot encoding for argmin
    if (argmin_ && (one_hot_ == false)) {
        cc_ckks->eval_sum_key_gen(private_key);
    }

    /* FHEW computations */
    // Generate the bootstrapping keys (refresh and switching keys)
    cc_lwe_->bt_key_gen(lwesk);

    return eval_keys;
}

void CkksRnsSchemeSwitching::eval_compare_switch_precompute(const CryptoContextImpl<RnsPoly>& cc_ckks, uint32_t p_lwe,
                                                double scale_sign, bool unit) {
    double scale_cf = 1.0;
    if ((p_lwe != 0) && (!unit)) {  // The messages are already scaled between 0 and 1, no need to divide by p_lwe
        scale_cf = 1.0 / p_lwe;
    }
    // Else perform no scaling; the implicit FHEW plaintext modulus will be modulus_ckks_initial_ / sc_factor
    scale_cf *= scale_sign;

    eval_ckks_to_fhew_precompute(cc_ckks, scale_cf);
}

Ciphertext<RnsPoly> CkksRnsSchemeSwitching::eval_compare_scheme_switching(ConstCiphertext<RnsPoly> ciphertext1,
                                                               ConstCiphertext<RnsPoly> ciphertext2, uint32_t num_ctxts,
                                                               uint32_t num_slots, uint32_t p_lwe, double scale_sign,
                                                               bool unit) {
    auto cc_ckks = ciphertext1->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc_ckks->get_crypto_parameters());

    auto c_diff = cc_ckks->eval_sub(ciphertext1, ciphertext2);

    if (unit) {
        if (p_lwe == 0)
            CIPHER_THROW("To scale to the unit circle, pLWE must be non-zero.");
        c_diff = cc_ckks->eval_mult(c_diff, 1.0 / static_cast<double>(p_lwe));
        c_diff = cc_ckks->rescale(c_diff);
    }

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (p_lwe != 0) {
        double scale_cf = 1.0;
        if ((p_lwe != 0) && (!unit)) {
            scale_cf = 1.0 / p_lwe;
        }
        scale_cf *= scale_sign;

        eval_ckks_to_fhew_precompute(*cc_ckks, scale_cf);
    }

    auto lwe_ciphertexts = eval_ckks_to_fhew(c_diff, num_ctxts);
    const uint32_t n = lwe_ciphertexts.size();
    std::vector<LweCiphertext> c_signs(n);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
    for (uint32_t i = 0; i < n; ++i)
        c_signs[i] = cc_lwe_->eval_sign(lwe_ciphertexts[i], true);

    return eval_fhew_to_ckks(c_signs, num_ctxts, num_slots, 4, -1.0, 1.0, 0);
}

std::vector<Ciphertext<RnsPoly>> CkksRnsSchemeSwitching::eval_min_scheme_switching(ConstCiphertext<RnsPoly> ciphertext,
                                                                        PublicKey<RnsPoly> public_key,
                                                                        uint32_t num_values, uint32_t num_slots,
                                                                        uint32_t p_lwe, double scale_sign) {
    auto cc = ciphertext->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (p_lwe != 0)
        eval_ckks_to_fhew_precompute(*cc, scale_sign / p_lwe);

    uint32_t towers_to_drop = 12;  // How many levels are consumed in the eval_fhew_to_ckks

    uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;

    Plaintext p_ind;
    if (one_hot_) {
        std::vector<std::complex<double>> ind(num_values, 1.0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    } else {
        std::vector<std::complex<double>> ind(num_values);
        std::iota(ind.begin(), ind.end(), 0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    }
    auto c_ind = cc->encrypt(public_key, p_ind);
    auto new_ciphertext = ciphertext->clone();

    for (uint32_t M = 1; M < num_values; M <<= 1) {
        const auto n = num_values / (2 * M);

        // Compute CKKS ciphertext encoding difference of the first num_values
        auto c_diff = cc->eval_sub(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        // Transform the ciphertext from CKKS to FHEW
        auto c_temp = eval_ckks_to_fhew(c_diff, n);

        // Evaluate the sign
        // We always assume for the moment that num_values is a power of 2
        std::vector<LweCiphertext> lwe_sign(n);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
        for (uint32_t j = 0; j < n; ++j)
            lwe_sign[j] = cc_lwe_->eval_sign(c_temp[j], true);

        // Scheme switching from FHEW to CKKS
        auto dim1 = get_ratio_bsgslt(n);
        auto c_select = eval_fhew_to_ckks(lwe_sign, n, num_slots, 4, -1.0, 1.0, dim1);

        std::vector<std::complex<double>> ones_value(n, 1.0);
        Plaintext ptxt_ones = cc->make_ckks_packed_plaintext(ones_value, 1, 0, nullptr, slots);
        cc->eval_add_in_place(c_select, cc->eval_at_index(cc->eval_sub(ptxt_ones, c_select), -static_cast<int32_t>(n)));

        if (M > 1) {
            for (uint32_t j = num_values / M; j < num_values; j <<= 1)
                cc->eval_add_in_place(c_select, cc->eval_at_index(c_select, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        new_ciphertext = cc->eval_mult(new_ciphertext, c_select);
        cc->eval_add_in_place(new_ciphertext, cc->eval_at_index(new_ciphertext, n));
        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(new_ciphertext);

        c_ind = cc->eval_mult(c_ind, c_select);
        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(c_ind);
    }

    // After computing the minimum and argument
    if (!one_hot_)
        c_ind = cc->eval_sum(c_ind, num_values);

    return std::vector<Ciphertext<RnsPoly>>{new_ciphertext, c_ind};
}

std::vector<Ciphertext<RnsPoly>> CkksRnsSchemeSwitching::eval_min_scheme_switching_alt(ConstCiphertext<RnsPoly> ciphertext,
                                                                           PublicKey<RnsPoly> public_key,
                                                                           uint32_t num_values, uint32_t num_slots,
                                                                           uint32_t p_lwe, double scale_sign) {
    auto cc = ciphertext->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (p_lwe != 0)
        eval_ckks_to_fhew_precompute(*cc, scale_sign / p_lwe);

    uint32_t towers_to_drop = 12;  // How many levels are consumed in the eval_fhew_to_ckks, for binary FHEW output.

    uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;

    Plaintext p_ind;
    if (one_hot_) {
        std::vector<std::complex<double>> ind(num_values, 1.0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    } else {
        std::vector<std::complex<double>> ind(num_values);
        std::iota(ind.begin(), ind.end(), 0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    }
    auto c_ind = cc->encrypt(public_key, p_ind);
    auto new_ciphertext = ciphertext->clone();

    for (uint32_t M = 1; M < num_values; M <<= 1) {
        const auto n = num_values / (2 * M);

        // Compute CKKS ciphertext encoding difference of the first num_values
        auto c_diff = cc->eval_sub(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        // Transform the ciphertext from CKKS to FHEW
        auto c_temp = eval_ckks_to_fhew(c_diff, n);

        // Evaluate the sign
        // We always assume for the moment that num_values is a power of 2
        std::vector<LweCiphertext> lwe_sign(num_values);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
        for (uint32_t j = 0; j < n; ++j) {
            LweCiphertext temp_sign = cc_lwe_->eval_sign(c_temp[j], true);
            LweCiphertext neg_temp_sign = std::make_shared<LweCiphertextImpl>(*temp_sign);
            cc_lwe_->get_lwe_scheme()->eval_add_const_eq(neg_temp_sign, neg_temp_sign->get_modulus() >> 1);  // "negated" temp_sign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                lwe_sign[i * n + j] = temp_sign;
                lwe_sign[(i + 1) * n + j] = neg_temp_sign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto dim1 = get_ratio_bsgslt(num_values);
        auto c_expand_select = eval_fhew_to_ckks(lwe_sign, num_values, num_slots, 4, -1.0, 1.0, dim1);

        // Update the ciphertext of values and the indicator
        new_ciphertext = cc->eval_mult(new_ciphertext, c_expand_select);
        cc->eval_add_in_place(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(new_ciphertext);

        c_ind = cc->eval_mult(c_ind, c_expand_select);
        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(c_ind);
    }

    // After computing the minimum and argument
    if (!one_hot_)
        c_ind = cc->eval_sum(c_ind, num_values);

    return std::vector<Ciphertext<RnsPoly>>{new_ciphertext, c_ind};
}

// TODO: used anywhere?
std::vector<Ciphertext<RnsPoly>> CkksRnsSchemeSwitching::eval_max_scheme_switching(ConstCiphertext<RnsPoly> ciphertext,
                                                                        PublicKey<RnsPoly> public_key,
                                                                        uint32_t num_values, uint32_t num_slots,
                                                                        uint32_t p_lwe, double scale_sign) {
    auto cc = ciphertext->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (p_lwe != 0)
        eval_ckks_to_fhew_precompute(*cc, scale_sign / p_lwe);

    uint32_t towers_to_drop = 12;  // How many levels are consumed in the eval_fhew_to_ckks, for binary FHEW output.

    uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;

    Plaintext p_ind;
    if (one_hot_) {
        std::vector<std::complex<double>> ind(num_values, 1.0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    } else {
        std::vector<std::complex<double>> ind(num_values);
        std::iota(ind.begin(), ind.end(), 0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    }
    auto c_ind = cc->encrypt(public_key, p_ind);
    auto new_ciphertext = ciphertext->clone();

    for (uint32_t M = 1; M < num_values; M <<= 1) {
        const auto n = num_values / (2 * M);

        // Compute CKKS ciphertext encoding difference of the first num_values
        auto c_diff = cc->eval_sub(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        // Transform the ciphertext from CKKS to FHEW
        auto c_temp = eval_ckks_to_fhew(c_diff, n);

        // Evaluate the sign
        // We always assume for the moment that num_values is a power of 2
        std::vector<LweCiphertext> lwe_sign(n);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
        for (uint32_t j = 0; j < n; ++j)
            lwe_sign[j] = cc_lwe_->eval_sign(c_temp[j], true);

        // Scheme switching from FHEW to CKKS
        auto dim1 = get_ratio_bsgslt(n);
        auto c_select = eval_fhew_to_ckks(lwe_sign, n, num_slots, 4, -1.0, 1.0, dim1);

        std::vector<std::complex<double>> ones_value(n, 1.0);
        Plaintext ptxt_ones = cc->make_ckks_packed_plaintext(ones_value, 1, 0, nullptr, slots);
        c_select = cc->eval_add(cc->eval_sub(ptxt_ones, c_select), cc->eval_at_index(c_select, -static_cast<int32_t>(n)));

        if (M > 1) {
            for (uint32_t j = num_values / M; j < num_values; j <<= 1)
                cc->eval_add_in_place(c_select, cc->eval_at_index(c_select, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        new_ciphertext = cc->eval_mult(new_ciphertext, c_select);
        cc->eval_add_in_place(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(new_ciphertext);

        c_ind = cc->eval_mult(c_ind, c_select);
        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(c_ind);
    }

    // After computing the minimum and argument
    if (!one_hot_)
        c_ind = cc->eval_sum(c_ind, num_values);

    return std::vector<Ciphertext<RnsPoly>>{new_ciphertext, c_ind};
}

// TODO: used anywhere?
std::vector<Ciphertext<RnsPoly>> CkksRnsSchemeSwitching::eval_max_scheme_switching_alt(ConstCiphertext<RnsPoly> ciphertext,
                                                                           PublicKey<RnsPoly> public_key,
                                                                           uint32_t num_values, uint32_t num_slots,
                                                                           uint32_t p_lwe, double scale_sign) {
    auto cc = ciphertext->get_crypto_context();

    const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(ciphertext->get_crypto_parameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (p_lwe != 0)
        eval_ckks_to_fhew_precompute(*cc, scale_sign / p_lwe);

    uint32_t towers_to_drop = 12;  // How many levels are consumed in the eval_fhew_to_ckks, for binary FHEW output

    uint32_t slots = (num_slots == 0) ? num_slots_ckks_ : num_slots;

    Plaintext p_ind;
    if (one_hot_) {
        std::vector<std::complex<double>> ind(num_values, 1.0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    } else {
        std::vector<std::complex<double>> ind(num_values);
        std::iota(ind.begin(), ind.end(), 0);
        p_ind = cc->make_ckks_packed_plaintext(ind, 1, towers_to_drop, nullptr, slots);
    }
    auto c_ind = cc->encrypt(public_key, p_ind);
    auto new_ciphertext = ciphertext->clone();

    for (uint32_t M = 1; M < num_values; M <<= 1) {
        const auto n = num_values / (2 * M);

        // Compute CKKS ciphertext encoding difference of the first num_values
        auto c_diff = cc->eval_sub(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        // Transform the ciphertext from CKKS to FHEW
        auto c_temp = eval_ckks_to_fhew(c_diff, n);

        // Evaluate the sign
        // We always assume for the moment that num_values is a power of 2
        std::vector<LweCiphertext> lwe_sign(num_values);
#pragma omp parallel for num_threads(cipher_parallel_controls.get_thread_limit(n))
        for (uint32_t j = 0; j < n; ++j) {
            LweCiphertext temp_sign = cc_lwe_->eval_sign(c_temp[j], true);
            LweCiphertext neg_temp_sign = std::make_shared<LweCiphertextImpl>(*temp_sign);
            cc_lwe_->get_lwe_scheme()->eval_add_const_eq(neg_temp_sign, neg_temp_sign->get_modulus() >> 1);  // "negated" temp_sign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                lwe_sign[i * n + j] = neg_temp_sign;
                lwe_sign[(i + 1) * n + j] = temp_sign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto dim1 = get_ratio_bsgslt(num_values);
        auto c_expand_select = eval_fhew_to_ckks(lwe_sign, num_values, num_slots, 4, -1.0, 1.0, dim1);

        // Update the ciphertext of values and the indicator
        new_ciphertext = cc->eval_mult(new_ciphertext, c_expand_select);
        cc->eval_add_in_place(new_ciphertext, cc->eval_at_index(new_ciphertext, n));

        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(new_ciphertext);

        c_ind = cc->eval_mult(c_ind, c_expand_select);
        if (crypto_params->get_scaling_technique() == FIXEDMANUAL)
            cc->mod_reduce_in_place(c_ind);
    }

    // After computing the minimum and argument
    if (!one_hot_)
        c_ind = cc->eval_sum(c_ind, num_values);

    return std::vector<Ciphertext<RnsPoly>>{new_ciphertext, c_ind};
}

}  // namespace cipher
