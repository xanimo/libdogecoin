/**
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

#include <ctype.h>
#include <inttypes.h>

#include <dogecoin/arith_uint256.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/common.h>


/* base_uint functions */

void base_uint_shift_left(base_uint* b, unsigned int shift) {
    base_uint* a = init_base_uint();
    copy_base_uint(a, b);
    int i = 0;
    for (; i < b->WIDTH; i++)
        b->pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < b->WIDTH; i++) {
        if (i + k + 1 < b->WIDTH && shift != 0)
            b->pn[i + k + 1] |= (a->pn[i] >> (32 - shift));
        if (i + k < b->WIDTH)
            b->pn[i + k] |= (a->pn[i] << shift);
    }
}

void base_uint_shift_right(base_uint* b, unsigned int shift) {
    base_uint* a = init_base_uint();
    copy_base_uint(a, b);
    int i = 0;
    for (; i < b->WIDTH; i++)
        b->pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < b->WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            b->pn[i - k - 1] |= (a->pn[i] << (32 - shift));
        if (i - k >= 0)
            b->pn[i - k] |= (a->pn[i] >> shift);
    }
}

void base_uint_times_equal_uint32(base_uint* b, uint32_t b32) {
    uint64_t carry = 0;
    int i = 0;
    for (; i < b->WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * b->pn[i];
        b->pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
}

base_uint* base_uint_times_equal(base_uint* b) {
    base_uint* a = b;
    _base_uint(b);
    int j = 0;
    for (; j < a->WIDTH; j++) {
        uint64_t carry = 0;
        int i = 0;
        for (; i + j < a->WIDTH; i++) {
            uint64_t n = carry + a->pn[i + j] + (uint64_t)a->pn[j] * b->pn[i];
            a->pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return a;
}

base_uint* base_uint_divide_equal(base_uint* a) {
    base_uint* div = a;     // make a copy, so we can shift.
    base_uint* num = a; // make a copy, so we can subtract.
    _base_uint(a);                   // the quotient.
    unsigned int num_bits = base_uint_bits(num);
    unsigned int div_bits = base_uint_bits(div);
    if (div_bits == 0)
        return set_uint_err("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return a;
    unsigned int shift = num_bits - div_bits;
    base_uint_shift_left(div, shift); // shift so that div and num align.
    while (shift >= 0) {
        if (num >= div) {
            num = num - div;
            a->pn[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        base_uint_shift_right(div, 1); // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return a;
}

int compare_base_uint_to(base_uint* a, base_uint* b) {
    int i = WIDTH - 1;
    for (; i >= 0; i--) {
        if (a->pn[i] < b->pn[i])
            return -1;
        if (a->pn[i] > b->pn[i])
            return 1;
    }
    return 0;
}

dogecoin_bool base_uint_equal_to(base_uint* a, uint64_t b) {
    int i = WIDTH - 1;
    for (; i >= 2; i--) {
        if (a->pn[i])
            return false;
    }
    if (a->pn[1] != (b >> 32))
        return false;
    if (a->pn[0] != (b & 0xfffffffful))
        return false;
    return true;
}

double base_uint_get_double(base_uint* a) {
    double ret = 0.0;
    double fact = 1.0;
    int i = 0;
    for (; i < WIDTH; i++) {
        ret += fact * a->pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

char* base_uint_get_hex(base_uint* a) {
    char* psz = dogecoin_char_vla(sizeof(a->pn) * 2 + 1);
    unsigned int i = 0;
    for (; i < sizeof(a->pn); i++)
        sprintf(psz + i * 2, "%02x", a->pn[sizeof(a->pn) - i - 1]);
    printf("psz: %s\n", psz);
    return psz;
}

void base_uint_set_hex(base_uint* a, const char* psz) {
    memset_safe((volatile void*)&a->pn[0], 0, sizeof(a->pn), 0);

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (utils_hex_digit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)a->pn;
    unsigned char* pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = utils_hex_digit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)utils_hex_digit(*psz--) << 4);
            p1++;
        }
    }
}

char* base_uint_to_string(base_uint* a) {
    return base_uint_get_hex((base_uint*)a);
}

unsigned int base_uint_bits(base_uint* a) {
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

/* arith_uint256 functions */

char* arith_uint256_to_string(arith_uint256* arr_u256) {
    return utils_uint8_to_hex((const uint8_t*)arith_to_uint256(arr_u256), 32);
}

arith_uint256* init_arith_uint256() {
    arith_uint256* x = dogecoin_calloc(1, sizeof(*x));
    x->to_string = arith_uint256_to_string;
    int i = 0;
    x->WIDTH = WIDTH;
    for (; i < x->WIDTH; i++)
        x->pn[i] = 0;
    return x;
}

uint64_t get_low64(arith_uint256* a) {
    assert(a->WIDTH >= 2);
    return a->pn[0] | (uint64_t)a->pn[1] << 32;
}

uint32_t get_compact(arith_uint256* a, dogecoin_bool f_negative)
{
    int nSize = (base_uint_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = get_low64(a) << 8 * (3 - nSize);
    } else {
        arith_uint256* bn = init_arith_uint256();
        bn = *a->pn >> 8 * (nSize - 3);
        nCompact = get_low64(bn);
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

arith_uint256 set_compact(arith_uint256 hash, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffff;
    if (size <= 3) {
        word >>= 8 * (3 - size);
        memcpy_safe(&hash, &word, sizeof word);
    } else {
        word <<= 8 * (size - 3);
        memcpy_safe(&hash, &word, sizeof word);
    }
    if (pf_negative) *pf_negative = word != 0 && (compact & 0x00800000) != 0;
    if (pf_overflow) *pf_overflow = word != 0 && ((size > 34) ||
                                                  (word > 0xff && size > 33) ||
                                                  (word > 0xffff && size > 32));
    return hash;
}

arith_uint256* uint_to_arith(const uint256* a)
{
    arith_uint256* b = init_arith_uint256();
    int x = 0;
    for(; x < 8; ++x) {
        uint32_t y = read_le32((const unsigned char*)a + x * 4);
        memcpy_safe(b->pn[x * 4], y, sizeof(uint32_t));
    }
    return b;
}

uint256* arith_to_uint256(const arith_uint256* a) {
    uint256* b = dogecoin_uint256_vla(1);
    int x = 0;
    for(; x < 8; ++x)
        write_le32((unsigned char*)b + x * 4, a->pn[x]);
    return b;
}
