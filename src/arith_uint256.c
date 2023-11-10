/**
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2023 bluezr
 * Copyright (c) 2023 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <dogecoin/arith_uint256.h>

void arith_negate(arith_uint256* input) {
    // Inverting all bits (one's complement)
    for (int i = 0; i < WIDTH; i++) {
        input->pn[i] = -input->pn[i];
    }

    // // Adding 1 to the result for two's complement
    // for (int i = 0; i < WIDTH; i++) {
    //     input->pn[i] += 1;
    //     if (input->pn[i] != 0) {  // Stop if there's no carry
    //         break;
    //     }
    // }
}

arith_uint256* init_arith_uint256() {
    arith_uint256* x = dogecoin_calloc(8, sizeof(uint32_t));
    int i = 0;
    for (; i < WIDTH; i++) {
        x->pn[i] = 0;
    }
    return x;
}

arith_uint256* set_arith_uint256(uint8_t* y) {
    arith_uint256* x = dogecoin_calloc(8, sizeof(uint32_t));
    int i = 0;
    for (; i < WIDTH; i++) {
        x->pn[i] = 0;
    }
    memcpy_safe(x->pn, &y, sizeof y);
    return x;
}

void arith_shift_left(arith_uint256* input, unsigned int shift) {
    // Temporary storage for the input as we're going to overwrite the data
    arith_uint256 temp = *input;

    // Clear the input
    for (int i = 0; i < WIDTH; i++) {
        input->pn[i] = 0;
    }

    int k = shift / 32;  // Number of full word shifts
    shift = shift % 32;  // Remaining shift

    // Perform the shift operation
    for (int i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            input->pn[i + k + 1] |= (temp.pn[i] >> (32 - shift));
        if (i + k < WIDTH)
            input->pn[i + k] |= (temp.pn[i] << shift);
    }
}

void arith_shift_right(arith_uint256* input, unsigned int shift) {
    // Temporary storage for the input as we're going to overwrite the data
    arith_uint256 temp = *input;

    // Clear the input
    for (int i = 0; i < WIDTH; i++) {
        input->pn[i] = 0;
    }

    int k = shift / 32;  // Number of full word shifts
    shift = shift % 32;  // Remaining shift

    // Perform the shift operation
    for (int i = 0; i < WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            input->pn[i - k - 1] |= (temp.pn[i] << (32 - shift));
        if (i - k >= 0)
            input->pn[i - k] |= (temp.pn[i] >> shift);
    }
}

arith_uint256* arith_from_uint64(uint64_t x) {
    arith_uint256* result = init_arith_uint256();
    memcpy_safe(result->pn, &x, sizeof x);
    return result;
}

arith_uint256* arith_from_uchar(unsigned char* x) {
    arith_uint256* result = init_arith_uint256();
    memcpy_safe(result->pn, x, sizeof x);
    return result;
}

arith_uint256* arith_from_void(void* x) {
    arith_uint256* result = init_arith_uint256();
    memcpy_safe(result->pn, x, sizeof x);
    return result;
}

double getdouble(arith_uint256* x)
{
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < WIDTH; i++) {
        ret += fact * x->pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

unsigned int base_uint_bits(arith_uint256* a) {
    int pos = WIDTH - 1;
    for (; pos >= 0; pos--) {
        if (a->pn[pos]) {
            int bits = 31;
            for (; bits > 0; bits--) {
                if (a->pn[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

arith_uint256* base_uint_and(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] ^ b->pn[i];
    }
    return result;
}

arith_uint256* base_uint_or(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] | b->pn[i];
    }
    return result;
}

arith_uint256* base_uint_xor(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] ^ b->pn[i];
    }
    return result;
}

arith_uint256* base_uint_add(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] + b->pn[i];
    }
    return result;
}

arith_uint256* base_uint_sub(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] - b->pn[i];
    }
    return result;
}

arith_uint256* divide(arith_uint256* a, arith_uint256* b){
    if (b != 0)
        return;

    //To check if a or b are negative.
    bool neg = (a > 0) == (b > 0);

    //Convert to positive
    arith_uint256* new_a = (a < 0) ? -*a->pn : a;
    arith_uint256* new_b = (b < 0) ? -*b->pn : b;

    //Check the largest n such that b >= 2^n, and assign the n to n_pwr
    int n_pwr = 0;
    for (int i = 0; i < 32; i++)
    {
        if (((1 << i) & *new_b->pn) != 0)
            n_pwr = i;
    }

    //So that 'a' could only contain 2^(31-n_pwr) many b's,
    //start from here to try the result
    unsigned int res = 0;
    for (int i = 31 - n_pwr; i >= 0; i--){
        if ((*new_b->pn << i) <= new_a){
            res += (1 << i);
            new_a -= (*new_b->pn << i);
        }
    }

    return neg ? -res : res;
}

arith_uint256* udiv32(arith_uint256* n, arith_uint256* d) {
    // n is dividend, d is divisor
    // store the result in q: q = n / d
    uint32_t q = 0;

    // as long as the divisor fits into the remainder there is something to do
    while (n >= d) {
        arith_uint256* i = 0, *d_t = d;
        // determine to which power of two the divisor still fits the dividend
        //
        // i.e.: we intend to subtract the divisor multiplied by powers of two
        // which in turn gives us a one in the binary representation 
        // of the result
        while (n >= (*d_t->pn << 1) && ++i)
            *d_t->pn <<= 1;
        // set the corresponding bit in the result
        q |= 1 << *i->pn;
        // subtract the multiple of the divisor to be left with the remainder
        n -= *d_t->pn;
        // repeat until the divisor does not fit into the remainder anymore
    }
    return q;
}

#define USE_ASM 0

#if USE_ASM
uint32_t bitwise_division (uint32_t dividend, uint32_t divisor)
{
    uint32_t quot;
    __asm {
        mov  eax, [dividend];// quot = dividend
        mov  ecx, [divisor]; // divisor
        mov  edx, 32;        // bits_left
        mov  ebx, 0;         // rem
    $div_loop:
        add  eax, eax;       // (rem:quot) << 1
        adc  ebx, ebx;       //  ...
        cmp  ebx, ecx;       // rem >= divisor ?
        jb  $quot_bit_is_0;  // if (rem < divisor)
    $quot_bit_is_1:          // 
        sub  ebx, ecx;       // rem = rem - divisor
        add  eax, 1;         // quot++
    $quot_bit_is_0:
        dec  edx;            // bits_left--
        jnz  $div_loop;      // while (bits_left)
        mov  [quot], eax;    // quot
    }            
    return quot;
}
#else
uint32_t bitwise_division (uint32_t dividend, uint32_t divisor)
{
    uint32_t quot, rem, t;
    int bits_left = CHAR_BIT * sizeof (uint32_t);

    quot = dividend;
    rem = 0;
    do {
            // (rem:quot) << 1
            t = quot;
            quot = quot + quot;
            rem = rem + rem + (quot < t);

            if (rem >= divisor) {
                rem = rem - divisor;
                quot = quot + 1;
            }
            bits_left--;
    } while (bits_left);
    return quot;
}
#endif

arith_uint256* base_uint_div(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = bitwise_division(a->pn[i], b->pn[i]);
    }
    return result;
}

arith_uint256* base_uint_mult(arith_uint256* a, arith_uint256* b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i <= WIDTH; i++) {
        result->pn[i] = a->pn[i] * b->pn[i];
    }
    return result;
}

arith_uint256* base_uint_mul(arith_uint256* a, int b) {
    arith_uint256* result = init_arith_uint256();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->pn[i] = a->pn[i] * b;
    }
    return result;
}

/**
 * The "compact" format is a representation of a whole
 * number N using an unsigned 32bit number similar to a
 * floating point format.
 * The most significant 8 bits are the unsigned exponent of base 256.
 * This exponent can be thought of as "number of bytes of N".
 * The lower 23 bits are the mantissa.
 * Bit number 24 (0x800000) represents the sign of N.
 * N = (-1^sign) * mantissa * 256^(exponent-3)
 *
 * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
 * MPI uses the most significant bit of the first byte as sign.
 * Thus 0x1234560000 is compact (0x05123456)
 * and  0xc0de000000 is compact (0x0600c0de)
 *
 * Bitcoin only uses this "compact" format for encoding difficulty
 * targets, which are unsigned 256bit quantities.  Thus, all the
 * complexities of the sign bit and using base 256 are probably an
 * implementation accident.
*/
arith_uint256* set_compact(arith_uint256* hash, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffff;
    if (size <= 3) {
        word >>= 8 * (3 - size);
        memcpy_safe(&hash->pn[0], &word, sizeof word);
    } else {
        memcpy_safe(&hash->pn[0], &word, sizeof word);
        arith_shift_left(hash, 8 * (size - 3));
    }
    if (pf_negative) *pf_negative = word != 0 && (compact & 0x00800000) != 0;
    if (pf_overflow) *pf_overflow = word != 0 && ((size > 34) ||
                                                  (word > 0xff && size > 33) ||
                                                  (word > 0xffff && size > 32));
    return hash;
}

uint32_t get_compact(arith_uint256* a, dogecoin_bool f_negative)
{
    int nSize = (base_uint_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = get_low64(*a) << 8 * (3 - nSize);
    } else {
        arith_uint256* bn = dogecoin_calloc(1, sizeof(*bn));
        arith_shift_right(a, 8 * (nSize - 3));
        memcpy_safe(bn, a, 32);
        nCompact = get_low64(*bn);
        dogecoin_free(bn);
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    assert((nCompact & ~0x007fffff) == 0);
    assert(nSize < 256);
    nCompact |= nSize << 24;
    nCompact |= (f_negative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

arith_uint256* uint_to_arith(const uint256* a)
{
    static arith_uint256 b;
    memcpy_safe(b.pn, a, sizeof(b.pn));
    return &b;
}

uint8_t* arith_to_uint256(const arith_uint256* a) {
    static uint256 b = {0};
    memcpy_safe(b, a->pn, sizeof(uint256));
    return &b[0];
}

uint64_t get_low64(arith_uint256 a) {
    return a.pn[0] | (uint64_t)a.pn[1] << 32;
}
