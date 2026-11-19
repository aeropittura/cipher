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
  This class provides a class for big integers
 */

#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE2

    #include "cipher/math/backend.h"
    #include "cipher/util/exception.h"
    #include "cipher/util/serializable.h"

namespace fixed_int {

// MOST REQUIRED STATIC CONSTANTS INITIALIZATION

// constant static member variable initialization of uint_bit_length_ which is
// equal to number of bits in the unit data type permitted values: 8,16,32
template <typename uint_type, uint32_t BITLENGTH>
const uint8_t BigIntegerFixedT<uint_type, BITLENGTH>::uint_bit_length_ = UIntBitWidth<uint_type>::value;

template <typename uint_type, uint32_t BITLENGTH>
const uint32_t BigIntegerFixedT<uint_type, BITLENGTH>::num_digit_in_printval_ = BITLENGTH / fixed_int::LOG2_10;

// constant static member variable initialization of log_uint_bit_length_ which is
// equal to log of number of bits in the unit data type permitted values: 3,4,5
template <typename uint_type, uint32_t BITLENGTH>
const uint8_t BigIntegerFixedT<uint_type, BITLENGTH>::log_uint_bit_length_ = LogDtype<uint_type>::value;

// constant static member variable initialization of n_size_ which is size of
// the array of unit data type
template <typename uint_type, uint32_t BITLENGTH>
const uint32_t BigIntegerFixedT<uint_type, BITLENGTH>::n_size_ =
        BITLENGTH % uint_bit_length_ == 0 ? BITLENGTH / uint_bit_length_ : BITLENGTH / uint_bit_length_ + 1;

// constant static member variable initialization of uint_max_ which is maximum
// value of unit data type
template <typename uint_type, uint32_t BITLENGTH>
const uint_type BigIntegerFixedT<uint_type, BITLENGTH>::uint_max_ = std::numeric_limits<uint_type>::max();

// CONSTRUCTORS

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT() {
    memset(this->value_, 0, sizeof(this->value_));
    this->msb_ = 0;  // MSB set to zero since value set to 0
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const BigIntegerFixedT& val) {
    msb_ = val.msb_;
    for (size_t i = 0; i < n_size_; ++i) {  // copy array values
        value_[i] = val.value_[i];
    }
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(BigIntegerFixedT&& val) {
    msb_ = std::move(val.msb_);
    for (size_t i = 0; i < n_size_; ++i) {
        value_[i] = std::move(val.value_[i]);
    }
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const std::string& strval) {
    assign_val(strval);  // setting the array values from the string
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(uint64_t val) {
    uint32_t msb = cipher::get_msb64(val);
    this->msb_ = msb;

    uint_type ceil_int = ceil_int_by_u_int(msb);
    int i = n_size_ - 1;

    for (; i >= static_cast<int>(n_size_ - ceil_int); i--) {  // setting the values of the array
        this->value_[i] = (uint_type)val;
        val >>= uint_bit_length_;
    }
    for (; i >= 0; i--) {
        this->value_[i] = 0;
    }
}

    #if defined(CIPHER_HAVE_INT128)
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(U128BITS val) {
    msb_ = cipher::get_msb(val);

    uint_type ceil_int = ceil_int_by_u_int(msb_);
    int i = n_size_ - 1;
    for (; i >= static_cast<int>(n_size_ - ceil_int); i--) {
        this->value_[i] = (uint_type)val;
        val >>= uint_bit_length_;
    }
    for (; i >= 0; i--) {
        this->value_[i] = 0;
    }
}
    #endif

/*
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const NativeInteger &val)
    : BigIntegerFixedT(val.convert_to_int()) {}
*/

// ASSIGNMENT OPERATORS

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::operator=(const BigIntegerFixedT& val) {
    if (this != &val) {
        this->msb_ = val.msb_;
        for (size_t i = 0; i < n_size_; ++i) {
            value_[i] = val.value_[i];
        }
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::operator=(BigIntegerFixedT&& val) {
    if (this != &val) {
        this->msb_ = std::move(val.msb_);
        for (size_t i = 0; i < n_size_; i++) {
            this->value_[i] = std::move(val.value_[i]);
        }
    }
    return *this;
}

// ACCESSORS

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::set_value(const std::string& str) {
    assign_val(str);
}

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::set_value(const BigIntegerFixedT& a) {
    *this = a;
}

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::set_int_at_index(uint32_t idx, uint_type value) {
    if (idx >= n_size_) {
        CIPHER_THROW("Index invalid");
    }
    this->value_[idx] = value;
}

// ARITHMETIC OPERATIONS

/* Addition operation:
 *  Algorithm used is usual school book sum and carry-over, expect for that
 * radix is 2^m_bitLength.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::add(const BigIntegerFixedT& b) const {
    // two operands A and B for addition, A is the greater one, B is the smaller
    // one
    const BigIntegerFixedT* A = nullptr;
    const BigIntegerFixedT* B = nullptr;

    // Assignment of pointers, A assigned the higher value and B assigned the
    // lower value
    if (*this > b) {
        A = this;
        B = &b;
    } else {
        A = &b;
        B = this;
    }

    if (B->msb_ == 0) {
        return BigIntegerFixedT(*A);
    }

    BigIntegerFixedT result;
    Duint_type ofl = 0;                                 // overflow variable
    uint_type ceil_int_a = ceil_int_by_u_int(A->msb_);  // position from A to start addition
    uint_type ceil_int_b = ceil_int_by_u_int(B->msb_);  // position from B to start addition
    size_t i;                                           // counter
    // DTS: TODO: verify that the sign/unsigned compare is valid here. it seems to
    // have the same form as the bugs fixed above, but i did not observe any
    // crashes in this function (perhaps it was never exercised) a safer
    // alternative would be something like what follows (the loops i fixed above
    // could use the same structure; note all variables become unsigned and all
    // loop indices start from zero): for (uint32_t j = 0; j < n_size_ - ceil_int_b
    // /*&& j < n_size_*/; ++j) {
    //    uint32_t i = n_size_ - 1 -j ;
    //    ...
    // }
    for (i = n_size_ - 1; i >= n_size_ - ceil_int_b; i--) {
        ofl = (Duint_type)A->value_[i] + (Duint_type)B->value_[i] + ofl;  // sum of the two int and the carry over
        result.value_[i] = (uint_type)ofl;
        ofl >>= uint_bit_length_;  // current overflow
    }

    if (ofl) {
        for (; i >= n_size_ - ceil_int_a; i--) {
            ofl = (Duint_type)A->value_[i] + ofl;  // sum of the two int and the carry over
            result.value_[i] = (uint_type)ofl;
            ofl >>= uint_bit_length_;  // current overflow
        }

        if (ofl) {  // in the end if overflow is set it indicates MSB is one greater
                    // than the one we started with
            result.value_[n_size_ - ceil_int_a - 1] = 1;
            result.msb_ = A->msb_ + 1;
        } else {
            result.msb_ = (n_size_ - i - 2) * uint_bit_length_;
            result.msb_ += get_msb_uint_type(result.value_[++i]);
        }
    } else {
        for (; i >= n_size_ - ceil_int_a; i--) {
            result.value_[i] = A->value_[i];
        }
        result.msb_ = (n_size_ - i - 2) * uint_bit_length_;
        result.msb_ += get_msb_uint_type(result.value_[++i]);
    }
    return result;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::add_eq(const BigIntegerFixedT& b) {
    // check for trivial conditions
    if (b.msb_ == 0) {
        return *this;
    }
    if (this->msb_ == 0) {
        return *this = b;
    }

    Duint_type ofl = 0;  // overflow variable
    uint_type first_loop_ceil, second_loop_ceil;
    size_t i;  // counter

    const BigIntegerFixedT* larger = nullptr;
    if (*this > b) {
        larger = this;
        first_loop_ceil = ceil_int_by_u_int(b.msb_);
        second_loop_ceil = ceil_int_by_u_int(this->msb_);
    } else {
        larger = &b;
        first_loop_ceil = ceil_int_by_u_int(this->msb_);
        second_loop_ceil = ceil_int_by_u_int(b.msb_);
    }

    for (i = n_size_ - 1; i >= n_size_ - first_loop_ceil; i--) {
        ofl = (Duint_type)this->value_[i] + (Duint_type)b.value_[i] + ofl;  // sum of the two int and the carry over
        this->value_[i] = (uint_type)ofl;
        ofl >>= uint_bit_length_;  // current overflow
    }

    if (ofl) {
        for (; i >= n_size_ - second_loop_ceil; i--) {
            ofl = (Duint_type)larger->value_[i] + ofl;  // sum of the two int and the carry over
            this->value_[i] = (uint_type)ofl;
            ofl >>= uint_bit_length_;  // current overflow
        }

        if (ofl) {  // in the end if overflow is set it indicates MSB is one greater
                    // than the one we started with
            this->value_[n_size_ - second_loop_ceil - 1] = 1;
            this->msb_ = larger->msb_ + 1;
        } else {
            this->msb_ = (n_size_ - i - 2) * uint_bit_length_;
            this->msb_ += get_msb_uint_type(this->value_[++i]);
        }
    } else {
        for (; i >= n_size_ - second_loop_ceil; i--) {
            this->value_[i] = larger->value_[i];
        }
        this->msb_ = (n_size_ - i - 2) * uint_bit_length_;
        this->msb_ += get_msb_uint_type(this->value_[++i]);
    }
    return *this;
}

/* Subtraction operation:
 *  Algorithm used is usual school book borrow and subtract, except for that
 * radix is 2^m_bitLength.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::sub(const BigIntegerFixedT& b) const {
    // return 0 if b is higher than *this as there is no support for negative
    // number
    if (!(*this > b)) {
        //    CIPHER_THROW(
        //        "there is no support if the minuend is smaller
        // than the subtrahend");
        return 0;
    }

    // DTS: note: these variables are confusing. if you look close you will find
    // (a) they are only inside the inner if block (cntr=0 is superfluous); (b)
    // current simply equals i (neither changes after the current=i assignment);
    // and (c) the while loop needs to check cntr >= 0 (when value_[] == 0...)
    int cntr = 0, current = 0;
    // DTS: (see add(), above) this function uses [signed] int for end_val_a and
    // end_val_b, unlike all the similar loops in the previous functions
    BigIntegerFixedT result(*this);
    // array position in A to end subtraction
    volatile int end_val_a = n_size_ - ceil_int_by_u_int(this->msb_);
    // array position in B to end subtraction
    int end_val_b = n_size_ - ceil_int_by_u_int(b.msb_);
    int i;
    for (i = n_size_ - 1; i >= end_val_b; i--) {
        // carryover condtion
        if (result.value_[i] < b.value_[i]) {
            current = i;
            cntr = current - 1;
            // assigning carryover value
            // DTS: added check against cntr being < 0 (I think)
            while (cntr >= 0 && result.value_[cntr] == 0) {
                result.value_[cntr] = uint_max_;
                cntr--;
            }
            // DTS: probably need to check cntr >= 0 here, too
            result.value_[cntr]--;
            result.value_[i] = result.value_[i] + uint_max_ + 1 - b.value_[i];
        } else {
            // usual subtraction condition
            result.value_[i] = result.value_[i] - b.value_[i];
        }
        cntr = 0;
    }
    while (result.value_[end_val_a] == 0) {
        end_val_a++;
    }
    // reset the MSB after subtraction
    result.msb_ = (n_size_ - end_val_a - 1) * uint_bit_length_ + get_msb_uint_type(result.value_[end_val_a]);
    // return the result
    return result;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::sub_eq(const BigIntegerFixedT& b) {
    // return 0 if b is higher than *this as there is no support for negative
    // number
    if (!(*this > b)) {
        //    CIPHER_THROW(
        //        "there is no support if the minuend is smaller
        // than the subtrahend");
        *this = BigIntegerFixedT(0);
        return *this;
    }
    // DTS: note: these variables are confusing. if you look close you will find
    // (a) they are only inside the inner if block (cntr=0 is superfluous); (b)
    // current simply equals i (neither changes after the current=i assignment);
    // and (c) the while loop needs to check cntr >= 0 (when value_[] == 0...)
    int cntr = 0, current = 0;
    // array position in A to end subtraction
    volatile int end_val_a = n_size_ - ceil_int_by_u_int(this->msb_);
    // array position in B to end subtraction
    int end_val_b = n_size_ - ceil_int_by_u_int(b.msb_);
    int i;
    for (i = n_size_ - 1; i >= end_val_b; i--) {
        // carryover condtion
        if (this->value_[i] < b.value_[i]) {
            current = i;
            cntr = current - 1;
            // assigning carryover value
            // DTS: added check against cntr being < 0 (I think)
            while (cntr >= 0 && this->value_[cntr] == 0) {
                this->value_[cntr] = uint_max_;
                cntr--;
            }
            // DTS: probably need to check cntr >= 0 here, too
            this->value_[cntr]--;
            this->value_[i] = this->value_[i] + uint_max_ + 1 - b.value_[i];
        } else {
            // usual subtraction condition
            this->value_[i] = this->value_[i] - b.value_[i];
        }
        cntr = 0;
    }
    while (this->value_[end_val_a] == 0) {
        end_val_a++;
    }
    // reset the MSB after subtraction
    this->msb_ = (n_size_ - end_val_a - 1) * uint_bit_length_ + get_msb_uint_type(this->value_[end_val_a]);
    return *this;
}

/* Multiplication operation:
 *  Algorithm used is usual school book shift and add after multiplication,
 * except for that radix is 2^m_bitLength.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mul(const BigIntegerFixedT& b) const {
    // check for trivial conditions
    if (b.msb_ == 0 || this->msb_ == 0) {
        return 0;
    }
    BigIntegerFixedT ans;
    if (b.msb_ == 1) {
        ans = *this;
        return ans;
    }
    if (this->msb_ == 1) {
        ans = b;
        return ans;
    }

    uint_type ceil_int = ceil_int_by_u_int(b.msb_);  // position of B in the array where the
                                                     // multiplication should start
    // Multiplication is done by getting a uint_type from b and multiplying it
    // with *this after multiplication the result is shifted and added to the
    // final answer
    BigIntegerFixedT temp;
    for (size_t i = n_size_ - 1; i >= n_size_ - ceil_int; i--) {
        this->mul_by_uint_to_int(b.value_[i], &temp);
        ans += temp <<= (n_size_ - 1 - i) * uint_bit_length_;
    }
    return ans;
}

// TODO reconsider operation
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mul_eq(const BigIntegerFixedT& b) {
    return *this = this->mul(b);
}

/* Division operation:
 *  Algorithm used is usual school book long division , except for that radix is
 * 2^m_bitLength. Optimization done: Uses bit shift operation for logarithmic
 * convergence.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::divided_by(
        const BigIntegerFixedT& b) const {
    // check for trivial conditions
    if (b == 0) {
        CIPHER_THROW("Division by zero");
    }
    if (b > *this) {
        return 0;
    }
    if (b == *this) {
        return 1;
    }

    BigIntegerFixedT ans;

    BigIntegerFixedT normalised_dividend(this->sub(this->mod(b)));  // normalised_dividend = result*quotient
    uint_type nchar_in_divisor = ceil_int_by_u_int(b.msb_);         // Number of array elements in Divisor
    uint_type nchar_in_normalised_dividend =
            ceil_int_by_u_int(normalised_dividend.msb_);  // Number of array elements in Normalised_dividend
    BigIntegerFixedT running_dividend;                    // variable to store the running dividend
    BigIntegerFixedT running_remainder;                   // variable to store the running remainder
    BigIntegerFixedT expected_prod;
    BigIntegerFixedT estimate_finder;

    // Initialize the running dividend
    for (uint32_t i = 0; i < nchar_in_divisor; i++) {
        running_dividend.value_[n_size_ - nchar_in_divisor + i] =
                normalised_dividend.value_[n_size_ - nchar_in_normalised_dividend + i];
    }
    running_dividend.msb_ = get_msb_uint_type(running_dividend.value_[n_size_ - nchar_in_divisor]) +
                            (nchar_in_divisor - 1) * uint_bit_length_;

    uint_type estimate = 0;
    uint_type mask_bit = 0;
    uint_type shifts = 0;
    uint32_t ans_ctr = n_size_ - nchar_in_normalised_dividend + nchar_in_divisor - 1;
    // Long Division Computation to determine quotient
    for (uint32_t i = nchar_in_normalised_dividend - nchar_in_divisor;;) {
        running_remainder = running_dividend.mod(b);           // Get the remainder from the Modulus operation
        expected_prod = running_dividend - running_remainder;  // Compute the expected product from the
                                                               // running dividend and remainder
        estimate_finder = expected_prod;
        estimate = 0;
        // compute the quotient
        if (expected_prod > b) {
            while (estimate_finder.msb_ > 0) {
                shifts = estimate_finder.msb_ - b.msb_;
                if (shifts == uint_bit_length_) {
                    mask_bit = (uint_type)1 << (uint_bit_length_ - 1);
                } else {
                    mask_bit = (uint_type)1 << (shifts);
                }

                if ((b.mul_by_uint(mask_bit)) > estimate_finder) {
                    mask_bit >>= 1;
                    estimate_finder -= b << (shifts - 1);
                } else if (shifts == uint_bit_length_) {
                    estimate_finder -= b << (shifts - 1);
                } else {
                    estimate_finder -= b << shifts;
                }
                estimate |= mask_bit;
            }
        } else if (expected_prod.msb_ == 0) {
            estimate = 0;
        } else {
            estimate = 1;
        }

        ans.value_[ans_ctr] = estimate;  // assigning the quotient in the result array
        ans_ctr++;
        if (i == 0) {
            break;
        }
        // Get the next uint element from the divisor and proceed with long division
        if (running_dividend.msb_ == 0) {
            running_dividend.msb_ = get_msb_uint_type(normalised_dividend.value_[n_size_ - i]);
        } else {
            running_dividend = running_remainder << uint_bit_length_;
        }
        running_dividend.value_[n_size_ - 1] = normalised_dividend.value_[n_size_ - i];
        if (running_dividend.msb_ == 0) {
            running_dividend.msb_ = get_msb_uint_type(normalised_dividend.value_[n_size_ - i]);
        }
        i--;
    }
    ans_ctr = n_size_ - nchar_in_normalised_dividend + nchar_in_divisor - 1;
    // Loop to the MSB position
    while (ans.value_[ans_ctr] == 0) {
        ans_ctr++;
    }
    ans.msb_ = get_msb_uint_type(ans.value_[ans_ctr]) +
               (n_size_ - 1 - ans_ctr) * uint_bit_length_;  // Computation of MSB value
    return ans;
}

// TODO reconsider operation
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::divided_by_eq(
        const BigIntegerFixedT& b) {
    return *this = this->divided_by(b);
}

// Recursive Exponentiation function
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::raise_to(uint32_t p) const {
    if (p == 0) {
        return 1;
    }
    BigIntegerFixedT x(*this);
    if (p == 1) {
        return x;
    }
    BigIntegerFixedT tmp = x.raise_to(p / 2);
    if (p % 2 == 0) {
        return tmp * tmp;
    } else {
        return tmp * tmp * x;
    }
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::exp_eq(uint32_t p) {
    if (p == 0) {
        return *this = 1;
    }
    if (p == 1) {
        return *this;
    }
    BigIntegerFixedT tmp = this->raise_to(p / 2);
    if (p % 2 == 0) {
        *this = tmp * tmp;
        return *this;
    } else {
        *this *= (tmp * tmp);
        return *this;
    }
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::multiply_and_round(
        const BigIntegerFixedT& p, const BigIntegerFixedT& q) const {
    BigIntegerFixedT ans(*this);
    ans.mul_eq(p);
    ans.divide_and_round_eq(q);
    return ans;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::multiply_and_round_eq(
        const BigIntegerFixedT& p, const BigIntegerFixedT& q) {
    this->mul_eq(p);
    this->divide_and_round_eq(q);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::divide_and_round(
        const BigIntegerFixedT& q) const {
    // check for garbage initialization and 0 condition
    if (q == 0) {
        CIPHER_THROW("Division by zero");
    }
    BigIntegerFixedT half_q(q >> 1);
    if (*this < q) {
        if (*this <= half_q) {
            return 0;
        } else {
            return 1;
        }
    }
    BigIntegerFixedT ans;
    BigIntegerFixedT normalised_dividend(*this);             // normalised_dividend = result*quotient
    uint_type nchar_in_divisor = ceil_int_by_u_int(q.msb_);  // Number of array elements in Divisor
    uint_type nchar_in_normalised_dividend =
            ceil_int_by_u_int(normalised_dividend.msb_);  // Number of array elements in Normalised_dividend
    BigIntegerFixedT running_dividend;                    // variable to store the running dividend
    BigIntegerFixedT running_remainder;                   // variable to store the running remainder
    BigIntegerFixedT expected_prod;
    BigIntegerFixedT estimate_finder;

    // Initialize the running dividend
    for (uint32_t i = 0; i < nchar_in_divisor; i++) {
        running_dividend.value_[n_size_ - nchar_in_divisor + i] =
                normalised_dividend.value_[n_size_ - nchar_in_normalised_dividend + i];
    }
    running_dividend.msb_ = get_msb_uint_type(running_dividend.value_[n_size_ - nchar_in_divisor]) +
                            (nchar_in_divisor - 1) * uint_bit_length_;

    uint_type estimate = 0;
    uint_type mask_bit = 0;
    uint_type shifts = 0;
    uint32_t ans_ctr = n_size_ - nchar_in_normalised_dividend + nchar_in_divisor - 1;
    // Long Division Computation to determine quotient
    for (uint32_t i = nchar_in_normalised_dividend - nchar_in_divisor;;) {
        running_remainder = running_dividend.mod(q);           // Get the remainder from the Modulus operation
        expected_prod = running_dividend - running_remainder;  // Compute the expected product from the
                                                               // running dividend and remainder
        estimate_finder = expected_prod;
        estimate = 0;
        // compute the quotient
        if (expected_prod > q) {
            while (estimate_finder.msb_ > 0) {
                shifts = estimate_finder.msb_ - q.msb_;
                if (shifts == uint_bit_length_) {
                    mask_bit = 1 << (uint_bit_length_ - 1);
                } else {
                    mask_bit = 1 << (shifts);
                }

                if ((q.mul_by_uint(mask_bit)) > estimate_finder) {
                    mask_bit >>= 1;
                    estimate_finder -= q << (shifts - 1);
                } else if (shifts == uint_bit_length_) {
                    estimate_finder -= q << (shifts - 1);
                } else {
                    estimate_finder -= q << shifts;
                }
                estimate |= mask_bit;
            }
        } else if (expected_prod.msb_ == 0) {
            estimate = 0;
        } else {
            estimate = 1;
        }
        // assgning the quotient in the result array
        ans.value_[ans_ctr] = estimate;
        ans_ctr++;
        if (i == 0) {
            break;
        }
        // Get the next uint element from the divisor and proceed with long division
        if (running_dividend.msb_ == 0) {
            running_dividend.msb_ = get_msb_uint_type(normalised_dividend.value_[n_size_ - i]);
        } else {
            running_dividend = running_remainder << uint_bit_length_;
        }

        running_dividend.value_[n_size_ - 1] = normalised_dividend.value_[n_size_ - i];
        if (running_dividend.msb_ == 0) {
            running_dividend.msb_ = get_msb_uint_type(normalised_dividend.value_[n_size_ - i]);
        }
        i--;
    }
    ans_ctr = n_size_ - nchar_in_normalised_dividend + nchar_in_divisor - 1;
    // Loop to the MSB position
    while (ans.value_[ans_ctr] == 0) {
        ans_ctr++;
    }
    ans.msb_ = get_msb_uint_type(ans.value_[ans_ctr]) +
               (n_size_ - 1 - ans_ctr) * uint_bit_length_;  // Computation of MSB value
    // Rounding operation from running remainder
    if (!(running_remainder <= half_q)) {
        ans += 1;
    }
    return ans;
}

// TODO reconsider the method
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::divide_and_round_eq(
        const BigIntegerFixedT& q) {
    return *this = this->divide_and_round(q);
}

// MODULAR ARITHMETIC OPERATIONS

// Algorithm used: Repeated subtraction by a multiple of modulus, which will be
// referred to as "Classical Modulo Reduction Algorithm" Complexity:
// O(log(*this)-log(modulus))
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod(
        const BigIntegerFixedT& modulus) const {
    // return the same value if value is less than modulus
    if (*this < modulus) {
        return BigIntegerFixedT(*this);
    }
    // masking operation if modulus is 2
    if (modulus.msb_ == 2 && modulus.value_[n_size_ - 1] == 2) {
        if (this->value_[n_size_ - 1] % 2 == 0) {
            return 0;
        } else {
            return 1;
        }
    }
    Duint_type initial_shift = 0;
    // No of initial left shift that can be performed which will make it
    // comparable to the current value.
    if (this->msb_ > modulus.msb_) {
        initial_shift = this->msb_ - modulus.msb_ - 1;
    }
    BigIntegerFixedT j = modulus << initial_shift;
    BigIntegerFixedT result(*this);
    BigIntegerFixedT temp;
    // TODO true -> result < modulus
    while (true) {
        // exit criteria
        if (result < modulus) {
            break;
        }
        if (result.msb_ > j.msb_) {
            temp = j << 1;
            if (result.msb_ == j.msb_ + 1) {
                if (result > temp) {
                    j = temp;
                }
            }
        }
        result -= j;  // subtracting the running remainder by a multiple of modulus
        initial_shift = j.msb_ - result.msb_ + 1;
        if (result.msb_ - 1 >= modulus.msb_) {
            j >>= initial_shift;
        } else {
            j = modulus;
        }
    }
    return result;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_eq(
        const BigIntegerFixedT& modulus) {
    // return the same value if value is less than modulus
    if (*this < modulus) {
        return *this;
    }
    // masking operation if modulus is 2
    if (modulus.msb_ == 2 && modulus.value_[n_size_ - 1] == 2) {
        if (this->value_[n_size_ - 1] % 2 == 0) {
            return *this = 0;
        } else {
            return *this = 1;
        }
    }
    Duint_type initial_shift = 0;
    // No of initial left shift that can be performed which will make it
    // comparable to the current value.
    if (this->msb_ > modulus.msb_) {
        initial_shift = this->msb_ - modulus.msb_ - 1;
    }
    BigIntegerFixedT j = modulus << initial_shift;
    BigIntegerFixedT temp;
    // TODO true -> *this < modulus
    while (true) {
        // exit criteria
        if (*this < modulus) {
            break;
        }
        if (this->msb_ > j.msb_) {
            temp = j << 1;
            if (this->msb_ == j.msb_ + 1) {
                if (*this > temp) {
                    j = temp;
                }
            }
        }
        *this -= j;  // subtracting the running remainder by a multiple of modulus
        initial_shift = j.msb_ - this->msb_ + 1;
        if (this->msb_ - 1 >= modulus.msb_) {
            j >>= initial_shift;
        } else {
            j = modulus;
        }
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::compute_mu() const {
    BigIntegerFixedT temp(1);
    temp <<= (2 * msb_ + 3);
    return temp.divided_by(*this);
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).
 The value of \mu is computed by BigVector::ModMult.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod(const BigIntegerFixedT& modulus,
                                                                                   const BigIntegerFixedT& mu) const {
    if (*this < modulus) {
        return BigIntegerFixedT(*this);
    }

    BigIntegerFixedT z(*this);
    BigIntegerFixedT q(*this);

    unsigned int n = modulus.msb_;
    unsigned int alpha = n + 3;
    int beta = -2;

    q >>= n + beta;
    q = q * mu;
    q >>= alpha - beta;
    z -= q * modulus;

    if (!(z < modulus)) {
        z -= modulus;
    }
    return z;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_eq(const BigIntegerFixedT& modulus,
                                                                                       const BigIntegerFixedT& mu) {
    if (*this < modulus) {
        return *this;
    }

    BigIntegerFixedT q(*this);

    unsigned int n = modulus.msb_;
    unsigned int alpha = n + 3;
    int beta = -2;

    q >>= n + beta;
    q = q * mu;
    q >>= alpha - beta;
    (*this) -= q * modulus;

    if (!(*this < modulus)) {
        *this -= modulus;
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_add(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.mod_eq(modulus);
    }
    if (bb >= modulus) {
        bb.mod_eq(modulus);
    }
    a.add_eq(bb);
    a.mod_eq(modulus);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_add_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->mod_eq(modulus);
    }
    if (bb >= modulus) {
        bb.mod_eq(modulus);
    }
    this->add_eq(bb);
    this->mod_eq(modulus);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_add_fast(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    a.add_eq(b);
    a.mod_eq(modulus);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_add_fast_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    this->add_eq(b);
    this->mod_eq(modulus);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_add(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    a.add_eq(b);
    a.mod_eq(modulus, mu);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_add_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    this->add_eq(b);
    this->mod_eq(modulus, mu);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT b_op(b);
    if (a >= modulus) {
        a.mod_eq(modulus);
    }
    if (b >= modulus) {
        b_op.mod_eq(modulus);
    }
    if (a >= b_op) {
        a.sub_eq(b_op);
        a.mod_eq(modulus);
    } else {
        a.add_eq(modulus);
        a.sub_eq(b_op);
    }
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT b_op(b);
    if (*this >= modulus) {
        this->mod_eq(modulus);
    }
    if (b >= modulus) {
        b_op.mod_eq(modulus);
    }
    if (*this >= b_op) {
        this->sub_eq(b_op);
        this->mod_eq(modulus);
    } else {
        this->add_eq(modulus);
        this->sub_eq(b_op);
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub_fast(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    if (a >= b) {
        a.sub_eq(b);
        a.mod_eq(modulus);
    } else {
        a.add_eq(modulus);
        a.sub_eq(b);
    }
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub_fast_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    if (*this >= b) {
        this->sub_eq(b);
        this->mod_eq(modulus);
    } else {
        this->add_eq(modulus);
        this->sub_eq(b);
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT b_op(b);
    // reduce this to a value lower than modulus
    if (a >= modulus) {
        a.mod_eq(modulus, mu);
    }
    // reduce b to a value lower than modulus
    if (b >= modulus) {
        b_op.mod_eq(modulus, mu);
    }
    if (a >= b_op) {
        a.sub_eq(b_op);
        a.mod_eq(modulus, mu);
    } else {
        a.add_eq(modulus);
        a.sub_eq(b_op);
    }
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_sub_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    BigIntegerFixedT b_op(b);
    // reduce this to a value lower than modulus
    if (*this >= modulus) {
        this->mod_eq(modulus, mu);
    }
    // reduce b to a value lower than modulus
    if (b >= modulus) {
        b_op.mod_eq(modulus, mu);
    }
    if (*this >= b_op) {
        this->sub_eq(b_op);
        this->mod_eq(modulus, mu);
    } else {
        this->add_eq(modulus);
        this->sub_eq(b_op);
    }
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.mod_eq(modulus);
    }
    if (b >= modulus) {
        bb.mod_eq(modulus);
    }
    a.mul_eq(bb);
    return a.mod_eq(modulus);
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->mod_eq(modulus);
    }
    if (b >= modulus) {
        bb.mod_eq(modulus);
    }
    this->mul_eq(bb);
    this->mod_eq(modulus);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.mod_eq(modulus, mu);
    }
    if (b >= modulus) {
        bb.mod_eq(modulus, mu);
    }
    a.mul_eq(bb);
    a.mod_eq(modulus, mu);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->mod_eq(modulus, mu);
    }
    if (b >= modulus) {
        bb.mod_eq(modulus, mu);
    }
    this->mul_eq(bb);
    this->mod_eq(modulus, mu);
    return *this;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_fast(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    a.mul_eq(b);
    a.mod_eq(modulus);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_fast_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    this->mul_eq(b);
    this->mod_eq(modulus);
    return *this;
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

 Multiplication and modulo reduction are NOT INTERLEAVED.

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_fast(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    a.mul_eq(b);
    a.mod_eq(modulus, mu);
    return a;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_mul_fast_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    this->mul_eq(b);
    this->mod_eq(modulus, mu);
    return *this;
}

// Modular Multiplication using Square and Multiply Algorithm
// reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_exp(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT mid = this->mod(modulus);  // mid is intermidiate value that calculates mid^2%q
    BigIntegerFixedT product(1);                // product calculates the running product of mod
                                                // values
    BigIntegerFixedT raise_to(b);               // Exp is used for spliting b to bit values/ bit
                                                // extraction

    BigIntegerFixedT temp(1);
    temp <<= 2 * modulus.get_msb() + 3;
    BigIntegerFixedT mu = temp.divided_by(modulus);  // Precompute the Barrett mu parameter

    while (true) {
        // product is multiplied only if bitvalue is 1
        if (exp_bits.value_[n_size_ - 1] % 2 == 1) {
            product = product * mid;
        }
        // running product is calculated
        if (product > modulus) {
            product.mod_eq(modulus, mu);
        }
        exp_bits = exp_bits >> 1;  // divide by 2 and check even to odd to find bit value
        if (exp_bits == 0) {
            break;
        }
        mid = mid * mid;
        mid.mod_eq(modulus, mu);  // mid calculates mid^2%q
    }
    return product;
}

// TODO method should be reconsidered
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_exp_eq(
        const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    return *this = this->mod_exp(b, modulus);
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mod_inverse(
        const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT second;
    if (*this > modulus) {
        second = mod(modulus);
    } else {
        second = *this;
    }

    if (second == 0) {
        CIPHER_THROW("Zero does not have a mod_inverse");
    }
    if (second == 1) {
        return 1;
    }

    // NORTH ALGORITHM
    BigIntegerFixedT first(modulus);
    BigIntegerFixedT mod_back = first.mod(second);
    std::vector<BigIntegerFixedT> quotient{first.divided_by(second)};

    // the max number of iterations should be < 2^k where k ==  min(bitsize
    // (inputs))
    // TODO: consider breaking out of the loop if this limit exceeded. the only
    // issue is that the loop counter could would need to be an ubint.
    while (mod_back != 1) {
        if (mod_back == 0) {
            CIPHER_THROW(this->to_string() + " does not have a mod_inverse using " + modulus.to_string());
        }
        first = second;
        second = mod_back;
        // second != 0, since we throw if mod_back == 0
        quotient.push_back(first.divided_by(second));
        mod_back = first.mod(second);
    }

    // SOUTH ALGORITHM
    first = 0;
    second = 1;
    for (int i = quotient.size() - 1; i >= 0; i--) {
        mod_back = quotient[i] * second + first;
        first = second;
        second = mod_back;
    }
    if (quotient.size() % 2 == 1) {
        return modulus - mod_back;
    }
    return mod_back;
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::mod_inverse_eq(
        const BigIntegerFixedT& modulus) {
    *this = mod_inverse(modulus);
    return *this;
}

/*
 *  Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of uint data type.
 *  Shifting is done by the shifting the uint type numbers.
 *2. Shifts between 1 to bit length of uint data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::l_shift(uint16_t shift) const {
    if (this->msb_ == 0) {
        return 0;
    }
    if ((this->msb_ + shift) > BITLENGTH) {
        CIPHER_THROW("shift overflow");
    }
    BigIntegerFixedT ans(*this);

    uint32_t shift_by_uint = shift >> log_uint_bit_length_;
    uint16_t rem_shift = (shift & (uint_bit_length_ - 1));

    if (rem_shift != 0) {
        uint_type end_val = n_size_ - ceil_int_by_u_int(msb_);
        uint_type o_flow = 0;
        Duint_type temp = 0;
        int i;
        // DTS- BUG FIX!!!!! (signed < unsigned(0) is always true)
        for (i = n_size_ - 1; i >= static_cast<int>(end_val); i--) {
            temp = ans.value_[i];
            temp <<= rem_shift;
            ans.value_[i] = (uint_type)temp + o_flow;
            o_flow = temp >> uint_bit_length_;
        }
        if (i > -1) {
            ans.value_[i] = o_flow;
        }
        ans.msb_ += rem_shift;
    }
    if (shift_by_uint != 0) {
        uint32_t i = n_size_ - ceil_int_by_u_int(ans.msb_);
        for (; i < n_size_; i++) {
            ans.value_[i - shift_by_uint] = ans.value_[i];
        }
        for (uint32_t j = 0; j < shift_by_uint; j++) {
            ans.value_[n_size_ - 1 - j] = 0;
        }
    }
    ans.msb_ += shift_by_uint * uint_bit_length_;
    return ans;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::l_shift_eq(uint16_t shift) {
    if (this->msb_ == 0) {
        return *this;
    }
    if (this->msb_ + shift > BITLENGTH) {
        CIPHER_THROW("shift overflow");
    }
    uint32_t shift_by_uint = shift >> log_uint_bit_length_;  // calculate the no.of
                                                             // shifts
    uint_type rem_shift = (shift & (uint_bit_length_ - 1));
    if (rem_shift != 0) {
        uint_type end_val = n_size_ - ceil_int_by_u_int(this->msb_);
        uint_type o_flow = 0;
        Duint_type temp = 0;
        int i;
        // DTS- BUG FIX!!!!! (end_val may be computed <0)
        for (i = n_size_ - 1; i >= static_cast<int>(end_val); i--) {
            temp = this->value_[i];
            temp <<= rem_shift;
            this->value_[i] = (uint_type)temp + o_flow;
            o_flow = temp >> uint_bit_length_;
        }
        if (i > -1) {
            this->value_[i] = o_flow;
        }
        this->msb_ += rem_shift;
    }
    if (shift_by_uint != 0) {
        uint32_t i = n_size_ - ceil_int_by_u_int(this->msb_);
        for (; i < n_size_; i++) {
            this->value_[i - shift_by_uint] = this->value_[i];
        }
        for (uint32_t ii = 0; ii < shift_by_uint; ii++) {
            this->value_[n_size_ - 1 - ii] = 0;
        }
    }
    this->msb_ += shift_by_uint * uint_bit_length_;
    return *this;
}

/*Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of uint data type.
 *  Shifting is done by the shifting the uint type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of uint data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::r_shift(uint16_t shift) const {
    // trivial cases
    if (this->msb_ == 0 || this->msb_ <= shift) {
        return BigIntegerFixedT(0);
    }
    BigIntegerFixedT ans(*this);
    uint32_t shift_by_uint = shift >> log_uint_bit_length_;  // no of array shifts
    uint_type rem_shift = (shift & (uint_bit_length_ - 1));  // no of bit shifts
    if (shift_by_uint != 0) {
        // termination index counter
        uint32_t end_val = n_size_ - ceil_int_by_u_int(ans.msb_);
        uint32_t j = end_val;
        // array shifting operation
        for (int i = n_size_ - 1 - shift_by_uint; i >= static_cast<int>(end_val); i--) {
            ans.value_[i + shift_by_uint] = ans.value_[i];
        }
        ans.msb_ -= shift_by_uint << log_uint_bit_length_;  // msb adjusted to show the shifts
        // nullptring the removed uints from the array
        while (shift_by_uint > 0) {
            ans.value_[j] = 0;
            shift_by_uint--;
            j++;
        }
    }
    // bit shifts
    if (rem_shift != 0) {
        uint_type over_flow = 0;
        uint_type old_val;
        uint_type mask_val = ((uint_type)1 << (rem_shift)) - 1;
        uint_type comp_shift_val = uint_bit_length_ - rem_shift;
        uint32_t start_val = n_size_ - ceil_int_by_u_int(ans.msb_);
        // perform shifting by bits by calculating the overflow
        // oveflow is added after the shifting operation
        for (; start_val < n_size_; start_val++) {
            old_val = ans.value_[start_val];
            ans.value_[start_val] = (ans.value_[start_val] >> rem_shift) + over_flow;
            over_flow = (old_val & mask_val);
            over_flow <<= comp_shift_val;
        }
        ans.msb_ -= rem_shift;
    }
    return ans;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::r_shift_eq(uint16_t shift) {
    if (this->msb_ == 0) {
        return *this;
    } else if (this->msb_ <= shift) {
        *this = 0;
        return *this;
    }
    int shift_by_uint = shift >> log_uint_bit_length_;     // no of array shifts
    uint8_t rem_shift = (shift & (uint_bit_length_ - 1));  // no of bit shifts
    // perform shifting in arrays
    if (shift_by_uint != 0) {
        int end_val = n_size_ - ceil_int_by_u_int(this->msb_);
        int j = end_val;
        for (int i = n_size_ - 1 - shift_by_uint; i >= end_val; i--) {
            this->value_[i + shift_by_uint] = this->value_[i];
        }
        this->msb_ -= shift_by_uint << log_uint_bit_length_;  // adjust shift to reflect left shifting
        while (shift_by_uint > 0) {
            this->value_[j] = 0;
            shift_by_uint--;
            j++;
        }
    }
    // perform shift by bits if any
    if (rem_shift != 0) {
        uint_type over_flow = 0;
        uint_type old_val;
        uint_type mask_val = ((uint_type)1 << (rem_shift)) - 1;
        uint_type comp_shift_val = uint_bit_length_ - rem_shift;
        uint32_t start_val = n_size_ - ceil_int_by_u_int(this->msb_);
        // shift and add the overflow from the previous position
        for (; start_val < n_size_; start_val++) {
            old_val = this->value_[start_val];
            this->value_[start_val] = (this->value_[start_val] >> rem_shift) + over_flow;
            over_flow = (old_val & mask_val);
            over_flow <<= comp_shift_val;
        }
        this->msb_ -= rem_shift;
    }
    return *this;
}

// COMPARE

// Compares the current object with the BigIntegerFixedT a.
// Uses MSB comparision to output requisite value.
template <typename uint_type, uint32_t BITLENGTH>
int BigIntegerFixedT<uint_type, BITLENGTH>::compare_with(const BigIntegerFixedT& a) const {
    if (this->msb_ < a.msb_) {
        return -1;
    }
    if (this->msb_ > a.msb_) {
        return 1;
    }
    if (this->msb_ == a.msb_) {
        uint8_t ceil_int = ceil_int_by_u_int(this->msb_);
        for (uint32_t i = n_size_ - ceil_int; i < n_size_; i++) {
            auto test_char = int64_t(this->value_[i]) - int64_t(a.value_[i]);
            if (test_char < 0)
                return -1;
            if (test_char > 0)
                return 1;
        }
    }
    return 0;
}

// CONVERTERS

template <typename uint_type, uint32_t BITLENGTH>
inline double BigIntegerFixedT<uint_type, BITLENGTH>::convert_to_double() const {
    double result = 0.0;
    uint32_t ceil_int = n_size_ - ceil_int_by_u_int(msb_);
    double factor = std::pow(2.0, uint_bit_length_);
    double power = 1.0;
    // copy the values by shift and add
    for (uint32_t i = 0; (n_size_ - i - 1) >= ceil_int; i++) {
        result += static_cast<double>(this->value_[n_size_ - i - 1]) * power;
        power *= factor;
    }
    return result;
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::from_binary_string(
        const std::string& bit_string) {
    BigIntegerFixedT value;
    uint32_t len = bit_string.length();
    uint32_t cntr = ceil_int_by_u_int(len);
    std::string val;
    Duint_type partial_value = 0;
    for (uint32_t i = 0; i < cntr; i++) {
        if (len >= ((i + 1) * uint_bit_length_)) {  // modified -- the fix by ES
            val = bit_string.substr((len - (i + 1) * uint_bit_length_), uint_bit_length_);
        } else {
            val = bit_string.substr(0, len % uint_bit_length_);
        }
        for (uint32_t j = 0; j < val.length(); j++) {
            partial_value += std::stoi(val.substr(j, 1));
            partial_value <<= 1;
        }
        partial_value >>= 1;
        value.value_[n_size_ - 1 - i] = (uint_type)partial_value;
        partial_value = 0;
    }
    uint32_t i = n_size_ - cntr;
    while (get_msb_uint_type(value.value_[i]) == 0 && i < n_size_ - 1) {
        i++;
    }
    value.msb_ = get_msb_uint_type(value.value_[i]);
    value.msb_ += (uint_bit_length_ * (n_size_ - i - 1));
    return value;
}

/*
 This method can be used to convert int to BigIntegerFixedT
 */
template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::int_to_big_integer(uint32_t m) {
    return BigIntegerFixedT(m);
}

// OTHER OPERATIONS

template <typename uint_type, uint32_t BITLENGTH>
bool BigIntegerFixedT<uint_type, BITLENGTH>::check_if_power_of_two(const BigIntegerFixedT& num_to_check_) {
    uint32_t msb_ = num_to_check_.msb_;
    for (int i = msb_ - 1; i > 0; i--) {
        if (static_cast<int>(num_to_check_.get_bit_at_index(i)) == 1) {
            return false;
        }
    }
    return true;
}

template <typename uint_type, uint32_t BITLENGTH>
uint32_t BigIntegerFixedT<uint_type, BITLENGTH>::get_digit_at_index_for_base(uint32_t index, uint32_t base) const {
    uint32_t digit_len_value = cipher::get_msb(base - 1);
    uint32_t digit = 0;
    uint32_t new_index = 1 + (index - 1) * digit_len_value;
    for (uint32_t i = 1; i < base; i = i * 2) {
        digit += get_bit_at_index(new_index) * i;
        new_index++;
    }
    return digit;
}

template <typename uint_type, uint32_t BITLENGTH>
uint8_t BigIntegerFixedT<uint_type, BITLENGTH>::get_bit_at_index(uint32_t index) const {
    if (index <= 0) {
        return 0;
    } else if (index > msb_) {
        return 0;
    }
    uint_type result;
    // idx is the index of the character array
    int idx = n_size_ - ceil_int_by_u_int(index);
    uint_type temp = this->value_[idx];
    // bmask is the bit number in the 8 bit array
    uint_type bmask_counter = index % uint_bit_length_ == 0 ? uint_bit_length_ : index % uint_bit_length_;
    uint_type bmask = 1;
    for (size_t i = 1; i < bmask_counter; i++) {
        bmask <<= 1;  // generate the bitmask number
    }
    result = temp & bmask;         // finds the bit in  bit format
    result >>= bmask_counter - 1;  // shifting operation gives bit either 1 or 0
    return (uint8_t)result;
}

// STRINGS & STREAMS

template <typename uint_type, uint32_t BITLENGTH>
const std::string BigIntegerFixedT<uint_type, BITLENGTH>::to_string() const {
    std::string bbi_string;  // this string object will store this BigIntegerFixedT's value
    uint32_t counter;

    // print_value_value array stores the decimal value in the array
    // NOLINTNEXTLINE
    uint8_t* print_value_value = new uint8_t[num_digit_in_printval_];
    for (size_t i = 0; i < num_digit_in_printval_; i++) {  // reset to zero
        *(print_value_value + i) = 0;
    }
    // starts the conversion from base r to decimal value
    for (size_t i = this->msb_; i > 0; i--) {
        // print_value_value = print_value_value*2
        BigIntegerFixedT<uint_type, BITLENGTH>::double_bit_val(print_value_value);

        // adds the bit value to the print_value_value
        BigIntegerFixedT<uint_type, BITLENGTH>::add_bit_val(print_value_value, this->get_bit_at_index(i));
    }
    // find the first occurrence of non-zero value in print_value_value
    for (counter = 0; counter < num_digit_in_printval_ - 1; counter++) {
        if (static_cast<int>(print_value_value[counter]) != 0) {
            break;
        }
    }
    // append this BigIntegerFixedT's digits to this method's returned string object
    for (; counter < num_digit_in_printval_; counter++) {
        bbi_string += std::to_string(print_value_value[counter]);
    }
    delete[] print_value_value;
    return bbi_string;
}

// Initializes the array of uint_array from the string equivalent of BigIntegerFixedT
// Algorithm used is repeated division by 2
// Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::assign_val(const std::string& v) {
    int arr_size = v.length();
    uint8_t* dec_value = new uint8_t[arr_size];  // memory allocated for decimal array
    for (int i = 0; i < arr_size; i++) {         // store the string to decimal array
        dec_value[i] = (uint8_t)atoi(v.substr(i, 1).c_str());
    }
    int zptr = 0;
    // index of highest non-zero number in decimal number
    // define  bit register array
    uint8_t* bit_arr = new uint8_t[uint_bit_length_]();

    int bit_val_ptr = n_size_ - 1;
    // bit_val_ptr is a pointer to the Value char array, initially pointed to the
    // last char we increment the pointer to the next char when we get the
    // complete value of the char array

    int cnt = uint_bit_length_ - 1;
    // cnt8 is a pointer to the bit position in bit_arr, when bit_arr is complete it
    // is ready to be transfered to Value
    while (zptr != arr_size) {
        bit_arr[cnt] = dec_value[arr_size - 1] % 2;
        // start divide by 2 in the dec_value array
        for (int i = zptr; i < arr_size - 1; i++) {
            dec_value[i + 1] = (dec_value[i] % 2) * 10 + dec_value[i + 1];
            dec_value[i] >>= 1;
        }
        dec_value[arr_size - 1] >>= 1;
        // division ends here
        cnt--;
        if (cnt == -1) {  // cnt = -1 indicates bit_arr is ready for transfer
            if (bit_val_ptr < 0) {
                CIPHER_THROW("string " + v + " cannot fit into BigIntegerFixedT");
            }

            cnt = uint_bit_length_ - 1;
            value_[bit_val_ptr--] =
                    uint_in_binary_to_decimal(bit_arr);  // uint_in_binary_to_decimal converts bit_arr to decimal and
                                                         // resets the content of bit_arr.
        }

        if (dec_value[zptr] == 0) {
            zptr++;  // division makes Most significant digit zero, hence we increment
                     // zptr to next value
        }
        if (zptr == arr_size && dec_value[arr_size - 1] == 0) {
            if (bit_val_ptr < 0) {
                CIPHER_THROW("string " + v + " cannot fit into BigIntegerFixedT");
            }
            value_[bit_val_ptr] = uint_in_binary_to_decimal(bit_arr);  // Value assignment
        }
    }
    set_msb(bit_val_ptr);
    delete[] bit_arr;
    delete[] dec_value;  // deallocate memory
}

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::set_msb() {
    msb_ = 0;
    for (uint32_t i = 0; i < n_size_; i++) {  // loops to find first nonzero number in char array
        if ((Duint_type)value_[i] != 0) {
            msb_ = (n_size_ - i - 1) * uint_bit_length_;
            msb_ += get_msb_uint_type(value_[i]);
            break;
        }
    }
}

// guessIdx is the index of largest uint_type number in array.
template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::set_msb(uint32_t guess_idx_char) {
    msb_ = (n_size_ - guess_idx_char - 1) * uint_bit_length_;
    msb_ += get_msb_uint_type(value_[guess_idx_char]);
}

// DTS:
// this seems to be the traditional "round up to the next power of two"
// function, except that ceil_int_by_u_int(0) == 1
//
// ((number+(1<<uint_bit_length_)-1)>>uint_bit_length_);
// where uint_bit_length_ = 8*sizeof(uint_type)
//
// optimized ceiling function after division by number of bits in the interal
// data type.
template <typename uint_type, uint32_t BITLENGTH>
uint_type BigIntegerFixedT<uint_type, BITLENGTH>::ceil_int_by_u_int(const uint_type number_value) {
    // mask to perform bitwise AND
    // static uint_type mask = uint_bit_length_-1;
    uint_type mask = uint_bit_length_ - 1;
    if ((number_value & mask) != 0) {
        return (number_value >> log_uint_bit_length_) + 1;
    } else if (!number_value) {
        return 1;
    } else {
        return number_value >> log_uint_bit_length_;
    }
}

template <typename uint_type, uint32_t BITLENGTH>
uint32_t BigIntegerFixedT<uint_type, BITLENGTH>::get_msb_uint_type(uint_type x) {
    return cipher::get_msb64(x);
}

template <typename uint_type, uint32_t BITLENGTH>
uint32_t BigIntegerFixedT<uint_type, BITLENGTH>::get_msbd_uint_type(Duint_type x) {
    return cipher::get_msb64(x);
}

template <typename uint_type, uint32_t BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::mul_by_uint(const uint_type b) const {
    BigIntegerFixedT ans;
    mul_by_uint_to_int(b, &ans);
    return ans;
}

/* Mul operation:
 *  Algorithm used is usual school book multiplication.
 *  This function is used in the Multiplication of two BigIntegerFixedT objects
 */
template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::mul_by_uint_to_int(const uint_type b, BigIntegerFixedT* ans) const {
    // check for trivial conditions
    if (b == 0 || this->msb_ == 0) {
        *ans = 0;
        return;
    }

    // position in the array to start multiplication
    uint32_t end_val = n_size_ - ceil_int_by_u_int(msb_);
    // variable to capture the overflow
    Duint_type temp = 0;
    // overflow value
    uint_type ofl = 0;
    size_t i = n_size_ - 1;

    for (; i >= end_val; i--) {
        temp = ((Duint_type)value_[i] * (Duint_type)b) + ofl;
        ans->value_[i] = (uint_type)temp;
        ofl = temp >> uint_bit_length_;
    }
    // check if there is any final overflow
    if (ofl) {
        ans->value_[i] = ofl;
    }
    ans->msb_ = (n_size_ - 1 - end_val) * uint_bit_length_;
    // set the MSB after the final computation
    ans->msb_ += get_msbd_uint_type(temp);
    return;
}

// Algoritm used is shift and add
template <typename uint_type, uint32_t BITLENGTH>
uint_type BigIntegerFixedT<uint_type, BITLENGTH>::uint_in_binary_to_decimal(uint8_t* a) {
    uint_type val_value = 0;
    uint_type one = 1;
    for (int i = uint_bit_length_ - 1; i >= 0; i--) {
        val_value += one * *(a + i);
        one <<= 1;
        *(a + i) = 0;
    }
    return val_value;
}

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::double_bit_val(uint8_t* a) {
    uint8_t ofl = 0;
    for (int i = num_digit_in_printval_ - 1; i > -1; i--) {
        *(a + i) <<= 1;
        if (*(a + i) > 9) {
            *(a + i) = *(a + i) - 10 + ofl;
            ofl = 1;
        } else {
            *(a + i) = *(a + i) + ofl;
            ofl = 0;
        }
    }
}

template <typename uint_type, uint32_t BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::add_bit_val(uint8_t* a, uint8_t b) {
    uint8_t ofl = 0;
    *(a + num_digit_in_printval_ - 1) += b;
    for (int i = num_digit_in_printval_ - 1; i > -1; i--) {
        *(a + i) += ofl;
        if (*(a + i) > 9) {
            *(a + i) = 0;
            ofl = 1;
        }
    }
}

template class BigIntegerFixedT<integral_dtype, BigIntegerBitLength>;

}  // namespace fixed_int

#endif
