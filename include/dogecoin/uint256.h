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

#ifndef __LIBDOGECOIN_UINT256_H__
#define __LIBDOGECOIN_UINT256_H__

#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>

#include <dogecoin/common.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

LIBDOGECOIN_BEGIN_DECL

DISABLE_WARNING_PUSH
DISABLE_WARNING(-Wunused-function)
typedef struct base_blob {
    uint8_t data[32];
    void (*set_data)(struct base_blob* blob, uint8_t data[32]);
    dogecoin_bool (*is_null)(uint8_t data[32]);
    void (*set_null)(uint8_t data[32]);
    unsigned char* (*begin)(struct base_blob blob);
    unsigned char* (*end)(struct base_blob blob);
    unsigned int (*size)(struct base_blob blob);
    uint64_t (*blob_uint64)(struct base_blob blob, int pos);
    int (*compare)(const struct base_blob* blob, const struct base_blob* other);
    dogecoin_bool (*eq)(const struct base_blob* a, const struct base_blob* b);
    dogecoin_bool (*neq)(const struct base_blob* a, const struct base_blob* b);
    dogecoin_bool (*lt)(const struct base_blob* a, const struct base_blob* b);
    char* (*get_hex)(const struct base_blob blob);
    void (*set_hex)(struct base_blob blob, const char* psz);
    char* (*to_str)(struct base_blob blob);
    void (*serialize)(cstring* s, const void* p, size_t len);
    int (*unserialize)(void* po, struct const_buffer* buf, size_t len);
} base_blob;

static void set_data(struct base_blob* blob, uint8_t data[32]) {
    unsigned int i = 0;
    for (; i < 32; i++) {
        memcpy_safe(&blob->data[i], &data[i], sizeof(uint8_t));
    }
}

static dogecoin_bool is_null(uint8_t data[32]) {
    unsigned int i = 0;
    for (; i < 32; i++) if (data[i] != 0) return false;
    return true;
}

static void set_null(uint8_t data[32]) {
    memset_safe(data, 0, sizeof(*data), 0);
}

static unsigned char* begin(struct base_blob blob) {
    return (unsigned char*)blob.data[0];
}

static unsigned char* end(struct base_blob blob) {
    return (unsigned char*)blob.data[32];
}

static unsigned int size(struct base_blob blob) {
    return sizeof(blob.data);
}

static uint64_t blob_uint64(struct base_blob blob, int pos) {
    const uint8_t* ptr = blob.data + pos * 8;
    return ((uint64_t)ptr[0]) | \
            ((uint64_t)ptr[1]) << 8 | \
            ((uint64_t)ptr[2]) << 16 | \
            ((uint64_t)ptr[3]) << 24 | \
            ((uint64_t)ptr[4]) << 32 | \
            ((uint64_t)ptr[5]) << 40 | \
            ((uint64_t)ptr[6]) << 48 | \
            ((uint64_t)ptr[7]) << 56;
}

static int compare(const struct base_blob* blob, const struct base_blob* other) {
    return memcmp(blob->data, other->data, sizeof(blob->data));
}

static dogecoin_bool eq(const struct base_blob* a, const struct base_blob* b) { 
    return compare(a, b) == 0; 
}

static dogecoin_bool neq(const struct base_blob* a, const struct base_blob* b) { 
    return compare(a, b) != 0; 
}

static dogecoin_bool lt(const struct base_blob* a, const struct base_blob* b) { 
    return compare(a, b) < 0; 
}

static char* get_hex(struct base_blob blob) {
    char* psz = dogecoin_char_vla(sizeof(blob.data) * 2 + 1);
    unsigned int i = 0;
    for (; i < sizeof(blob.data); i++)
        sprintf(psz + i * 2, "%02x", blob.data[sizeof(blob.data) - i - 1]);
    return psz;
}

static void set_hex(const struct base_blob blob, const char* psz) {
    memset_safe((volatile void*)&blob.data[0], 0, sizeof(blob.data), 0);

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
    unsigned char* p1 = (unsigned char*)blob.data;
    unsigned char* pend = p1 + 32;
    while (psz >= pbegin && p1 < pend) {
        *p1 = utils_hex_digit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)utils_hex_digit(*psz--) << 4);
            p1++;
        }
    }
};

static char* to_str(const struct base_blob blob) {
    return get_hex(blob);
}

static void set_compact_blob(struct base_blob* blob, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffff;
    if (size <= 3) {
        word >>= 8 * (3 - size);
        memcpy_safe(blob->data, &word, sizeof word);
    } else {
        word <<= 8 * (size - 3);
        memcpy_safe(blob->data, &word, sizeof word);
    }
    if (pf_negative) *pf_negative = word != 0 && (compact & 0x00800000) != 0;
    if (pf_overflow) *pf_overflow = word != 0 && ((size > 34) ||
                                                  (word > 0xff && size > 33) ||
                                                  (word > 0xffff && size > 32));
}

static struct base_blob* init_blob() {
    struct base_blob* blob = (struct base_blob*)dogecoin_calloc(1, sizeof(*blob));
    blob->set_data = set_data;
    blob->is_null = is_null;
    blob->set_null = set_null;
    blob->begin = begin;
    blob->end = end;
    blob->size = size;
    blob->blob_uint64 = blob_uint64;
    blob->compare = compare;
    blob->eq = eq;
    blob->neq = neq;
    blob->lt = lt;
    blob->get_hex = get_hex;
    blob->set_hex = set_hex;
    blob->to_str = to_str;
    blob->serialize = ser_bytes;
    blob->unserialize = deser_bytes;
    blob->set_null(blob->data);
    return blob;
}

uint16_t* uint256_to_uint16(uint256 in) {
    return (uint16_t*)&in;
}

uint32_t* uint256_to_uint32(uint256 in) {
    return (uint32_t*)&in;
}

uint64_t* uint256_to_uint64(uint256 in) {
    return (uint64_t*)&in;
}

vector* uchar_arr_to_vec(const unsigned char* array) {
    vector* vout = vector_new(32, dogecoin_free);
    unsigned int i = 0;
    for (; i < strlen((char*)array); i++) {
        vector_add(vout, array[i]);
    }
    return vout;
}

unsigned char* vec_to_uchar_arr(const vector* vector) {
    unsigned char* arr_out = dogecoin_uchar_vla(vector->len);
    unsigned int i = 0;
    for (; i < vector->len; i++) {
        arr_out[i] = vector_idx(vector, i);
    }
    return arr_out;
}

uint256* uint256_u(const vector* blob) {
    return (uint256*)vec_to_uchar_arr(blob);
}

vector* uint256_v(const uint256* blob) {
    vector* x = vector_new(sizeof(uint256), dogecoin_free);
    unsigned int i = 0;
    for (; i < x->len; i++) {
        x->data[i] = (void*)blob[i];
    }
    return x;
}

uint64_t get_cheap_hash(const base_blob* blob) {
    return read_le64(blob->data);
}
DISABLE_WARNING_POP

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_UINT256_H__
