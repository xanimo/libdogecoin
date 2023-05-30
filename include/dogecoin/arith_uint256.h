/*

 The MIT License (MIT)

 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#ifndef __LIBDOGECOIN_ARITH_UINT256_H__
#define __LIBDOGECOIN_ARITH_UINT256_H__

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/mem.h>

LIBDOGECOIN_BEGIN_DECL

typedef struct uint_err {
    const char* str;
} uint_err;

typedef struct base_uint_ {
    uint_err err;
    int WIDTH; // BITS / 8
    uint8_t pn[32]; // pn[WIDTH]
    uint16_t u16[16];
    uint32_t u32[8];
    uint64_t u64[4];
    char* (*to_string)(void*);
} base_uint;

static base_uint* set_uint_err(char* str) {
    uint_err err;
    err.str = str;
    base_uint* b;
    b->err = err;
    return b;
}

static void _base_uint(base_uint* b) {
    int i = 0;
    b->WIDTH = WIDTH;
    for (; i < b->WIDTH; i++)
        b->pn[i] = 0;
}

static void copy_base_uint(base_uint* a, base_uint* b) {
    int i = 0;
    for (; i < b->WIDTH; i++)
        a->pn[i] = b->pn[i];
}

static void _base_uint64(base_uint* a, uint64_t* b) {
    a->pn[0] = (unsigned int)*b;
    a->pn[1] = (unsigned int)(*b >> 32);
    int i = 2;
    for (; i < a->WIDTH; i++)
        a->pn[i] = 0;
}

static unsigned long _base_uint_size(base_uint* b) {
    return sizeof b->pn;
}

void base_uint_shift_left(base_uint* b, unsigned int shift);
void base_uint_shift_right(base_uint* b, unsigned int shift);
void base_uint_times_equal_uint32(base_uint* b, uint32_t b32);
base_uint* base_uint_times_equal(base_uint* a);
base_uint* base_uint_divide_equal(base_uint* a);
int compare_base_uint_to(base_uint* a, base_uint* b);
dogecoin_bool base_uint_equal_to(base_uint* a, uint64_t b);
double base_uint_get_double(base_uint* a);
char* base_uint_get_hex(base_uint* a);
void base_uint_set_hex(base_uint* a, const char* psz);
char* base_uint_to_string(base_uint* a);
unsigned int base_uint_bits(base_uint* a);

static base_uint* init_base_uint() {
    base_uint* x = dogecoin_calloc(1, sizeof(*x));
    x->to_string = base_uint_to_string;
    return x;
}

typedef base_uint arith_uint256;

arith_uint256* init_arith_uint256();
uint64_t get_low64(arith_uint256* a);
arith_uint256 set_compact(arith_uint256 hash, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow);
uint32_t get_compact(arith_uint256* a, dogecoin_bool f_negative);

uint256* arith_to_uint256(const arith_uint256* a);
arith_uint256* uint_to_arith(const uint256* a);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_ARITH_UINT256_H__
