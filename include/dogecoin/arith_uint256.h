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
#include <tgmath.h>
#include <inttypes.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/uthash.h>
#include <dogecoin/utils.h>

LIBDOGECOIN_BEGIN_DECL

/* hash_uint functions */
typedef struct checks_uint {
    dogecoin_bool negative;
    dogecoin_bool overflow;
} checks_uint;

typedef union swap {
    uint8_t u8[32];
    uint32_t u32[8];
} swap;

typedef struct hash_uint {
    int index;
    uint256* data;
    swap x;
    checks_uint checks;
    UT_hash_handle hh;
} hash_uint;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static hash_uint *hash_uints = NULL;
#pragma GCC diagnostic pop

// instantiates a new hash_uint
LIBDOGECOIN_API hash_uint* new_hash_uint();
LIBDOGECOIN_API int start_hash_uint();

LIBDOGECOIN_API void add_hash_uint(hash_uint *hash_uint);
LIBDOGECOIN_API hash_uint* zero_hash_uint(int index);
LIBDOGECOIN_API void set_hash_uint(int index, uint8_t* x, char* typename);
LIBDOGECOIN_API hash_uint* find_hash_uint(int index);
char* get_hash_uint_by_index(int index);

LIBDOGECOIN_API void remove_hash_uint(hash_uint *hash_uint);

LIBDOGECOIN_API void remove_all_hash_uints();

DISABLE_WARNING_PUSH
DISABLE_WARNING(-Wunused-function)
typedef struct uint_err {
    const char* str;
} uint_err;

typedef struct base_uint {
    uint_err err;
    int WIDTH; // BITS / 8
    swap x;
    uint8_t pn[32];
    char* (*to_string)(const struct base_uint* a);
    char* (*get_hex)(const struct base_uint* a);
    void (*set_hex)(const struct base_uint* a, const char* psz);
    double (*get_double)(const struct base_uint* a);
    uint64_t (*get_low64)(const struct base_uint* a);
    unsigned long (*size)(const struct base_uint* b);
    struct base_uint* (*this)(struct base_uint* this, ...);
} base_uint;

#define printf_dec_format(x) _Generic((x), \
    char: "%c", \
    signed char: "%hhd", \
    unsigned char: "%hhu", \
    signed short: "%hd", \
    unsigned short: "%hu", \
    signed int: "%d", \
    unsigned int: "%u", \
    long int: "%ld", \
    unsigned long int: "%lu", \
    long long int: "%lld", \
    unsigned long long int: "%llu", \
    float: "%f", \
    double: "%f", \
    long double: "%Lf", \
    char *: "%s", \
    void *: "%p")
 
#define print(x) printf(printf_dec_format(x), x)
#define printnl(x) printf(printf_dec_format(x), x), printf("\n");
void shift_left(int index, uint256 b, unsigned int shift);
typedef union __base_uint {
    char hex[65];
    uint8_t byte[32];
    char* (*tostring);
} __base_uint;

static char* u(char* a, ...) {
    size_t len = 0;
    char *retbuf;
    va_list argp;
    char *p;

    if(a == NULL)
        return NULL;

    len = strlen(a);

    va_start(argp, a);

    while((p = va_arg(argp, char *)) != NULL)
        len += strlen(p);

    va_end(argp);

    retbuf = malloc(len + 1);	/* +1 for trailing \0 */

    if(retbuf == NULL)
        return NULL;		/* error */

    (void)strcpy(retbuf, a);

    va_start(argp, a);

    while((p = va_arg(argp, char *)) != NULL)
        (void)strcat(retbuf, p);

    va_end(argp);
    return retbuf;
}

static base_uint* set_uint_err(char* str) {
    uint_err err;
    err.str = str;
    base_uint* b;
    b->err = err;
    return b;
}

#define typename(x) _Generic((x),        /* Get the name of a type */             \
                                                                                  \
        _Bool: "_Bool",                  unsigned char: "unsigned char",          \
         char: "char",                     signed char: "signed char",            \
    short int: "short int",         unsigned short int: "unsigned short int",     \
          int: "int",                     unsigned int: "unsigned int",           \
     long int: "long int",           unsigned long int: "unsigned long int",      \
long long int: "long long int", unsigned long long int: "unsigned long long int", \
        float: "float",                         double: "double",                 \
  long double: "long double",                   char *: "char *",                 \
       void *: "pointer to void",                int *: "pointer to int",         \
       uint8_t *: "uint8_t *",                 default: "other")

#define fmt "%20s is '%s'\n"

static const base_uint* _base_uint(base_uint* b, ...) {
    va_list parameters;
    va_start (parameters, b);

    int i = 0;
    b->WIDTH = WIDTH;
    for (; i < b->WIDTH; i++)
        b->x.u32[i] = va_arg(parameters, uint8_t*) ? va_arg(parameters, uint8_t*) : 0;
    va_end(parameters);
    return b;
}

static void copy_base_uint(base_uint* a, base_uint* b) {
    int i = 0;
    for (; i < b->WIDTH; i++)
        a->x.u8[i] = b->x.u8[i];
}

static unsigned long _base_uint_size(base_uint* b) {
    return sizeof b->x.u8;
}

void base_uint_shift_left_equal(base_uint* b, unsigned int shift);
void base_uint_shift_right_equal(base_uint* b, unsigned int shift);
void base_uint_times_equal_uint32(base_uint* b, uint32_t b32);
base_uint* base_uint_times_equal(base_uint* a);
base_uint* base_uint_divide_equal(base_uint* a);
int base_uint_compare(base_uint* a, base_uint* b);
dogecoin_bool base_uint_equal_to(base_uint* a, uint64_t b);
double base_uint_get_double(base_uint* a);
char* base_uint_get_hex(base_uint* a);
char* get_hash_uint_hex(hash_uint* a);
void base_uint_set_hex(base_uint* a, const char* psz);
char* base_uint_to_string(const struct base_uint* a);
unsigned int base_uint_bits(swap* a);

static dogecoin_bool base_uint_null(const base_uint* b) {
    int i = 0;
    for (; i < WIDTH; i++) {
        if (b->x.u8[i] != 0) return false;
    }
    return true;
}

base_uint* base_uint_shift_right(const base_uint* b, int shift);
base_uint* base_uint_shift_left(const base_uint* b, int shift);
uint64_t get_low64(swap* a);
swap* set_compact(swap* hash_uint, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow);
uint32_t get_compact_hash_uint(int index);
uint32_t get_compact(swap* a, dogecoin_bool f_negative);

uint256* arith_to_uint256(const base_uint* a);
base_uint* uint_to_arith(const uint256* a);

static base_uint* init_base_uint() {
    base_uint* x = dogecoin_calloc(1, sizeof(*x));
    x->to_string = base_uint_to_string;
    x->get_hex = base_uint_get_hex;
    x->set_hex = base_uint_set_hex;
    x->get_double = base_uint_get_double;
    x->get_low64 = get_low64;
    x->size = _base_uint_size;
    x->this = (struct base_uint *(*)(struct base_uint *, ...))x;
    int i = 0;
    x->WIDTH = WIDTH;
    for (; i < WIDTH; i++)
        x->x.u32[i] = 0;
    return x;
}

static base_uint* _base_uint64(uint64_t b) {
    base_uint* a = init_base_uint();
    a->x.u32[0] = (unsigned int)b;
    a->x.u32[1] = (unsigned int)(b >> 32);
    int i = 2;
    for (; i < 8; i++) {
        a->x.u32[i] = 0;
    }
    printf("%s %s\n", __func__, utils_uint8_to_hex(a->x.u32, 32));
    return a;
}

static base_uint* _base_uint64_str(char* b) {
    base_uint* a = init_base_uint();
    uint64_t c = strtoul(b, NULL, 0);
    a->x.u32[0] = (unsigned int)c;
    a->x.u32[1] = (unsigned int)(c >> 32);
    int i = 2;
    for (; i < 8; i++)
        a->x.u32[i] = 0;
    printf("%s %s %lu %s\n", __func__, utils_uint8_to_hex(a->x.u32, 32), c, b);
    return a;
}

static base_uint* base_uint_and(base_uint* a, base_uint* b) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < 8; i++) {
        result->x.u32[i] = a->x.u32[i] & b->x.u32[i];
    }
    return result;
}

static base_uint* base_uint_or(base_uint* a, base_uint* b) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] = a->x.u8[i] | b->x.u8[i];
    }
    return result;
}

base_uint* base_uint_xor(base_uint* a, base_uint* b);

static base_uint* base_uint_left_shift(base_uint* a, base_uint* b) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] = a->x.u8[i] << b->x.u8[i];
    }
    return result;
}

static base_uint* base_uint_right_shift(base_uint* a, base_uint* b) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] = a->x.u8[i] >> b->x.u8[i];
    }
    return result;
}

static base_uint* base_uint_negative(base_uint* a) {
    base_uint* result = init_base_uint();
    int i = 0;
    
    for (; i < 8; i++) {
        result->x.u32[i] = ~a->x.u32[i];
    }
    result++;
    return result;
}

static base_uint* base_uint_xor_equal(base_uint* a) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] ^= a->x.u8[i];
    }
    return result;
}

static base_uint* base_uint_and_equal(base_uint* a) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] &= a->x.u8[i];
    }
    return result;
}

static base_uint* base_uint_or_equal(base_uint* a) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] |= a->x.u8[i];
    }
    return result;
}

static base_uint* base_uint_xor_equal64(uint64_t a) {
    base_uint* result = init_base_uint();
    result->x.u8[0] ^= (unsigned int)a;
    result->x.u8[1] ^= (unsigned int)(a >> 32);
    return result;
}

static base_uint* base_uint_or_equal64(uint64_t a) {
    base_uint* result = init_base_uint();
    result->x.u8[0] |= (unsigned int)a;
    result->x.u8[1] |= (unsigned int)(a >> 32);
    return result;
}

static base_uint* base_uint_plus_equal(base_uint* b) {
    base_uint* result = init_base_uint();
    uint64_t carry = 0;
    int i = 0;
    for (; i < WIDTH; i++) {
        uint64_t n = carry + result->x.u8[i] + b->x.u8[i];
        result->x.u8[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return result;
}

static base_uint* base_uint_minus_equal(base_uint* b) {
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++) {
        result->x.u8[i] += -b->x.u8[i];
    }
    return result;
}
DISABLE_WARNING_POP

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_ARITH_UINT256_H__
