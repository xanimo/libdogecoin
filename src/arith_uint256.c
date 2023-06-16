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



/**
 * @brief This function instantiates a new working hash_uint,
 * but does not add it to the hash_uint table.
 * 
 * @return A pointer to the new working hash_uint. 
 */
hash_uint* new_hash_uint() {
    hash_uint* h = (struct hash_uint*)dogecoin_calloc(1, sizeof *h);
    h->data = (uint256*)dogecoin_calloc(1, sizeof(*h->data));
    *h->x.u8 = *h->data;
    h->index = HASH_COUNT(hash_uints) + 1;
    return h;
}

/**
 * @brief This function takes a pointer to an existing working
 * hash_uint object and adds it to the hash_uint table.
 * 
 * @param map The pointer to the working hash_uint.
 * 
 * @return Nothing.
 */
void add_hash_uint(hash_uint *x) {
    hash_uint* hash_uint_local;
    HASH_FIND_INT(hash_uints, &x->index, hash_uint_local);
    if (hash_uint_local == NULL) {
        HASH_ADD_INT(hash_uints, index, x);
    } else {
        HASH_REPLACE_INT(hash_uints, index, x, hash_uint_local);
    }
    dogecoin_free(hash_uint_local);
}

/**
 * @brief This function creates a new map, places it in
 * the hash_uint table, and returns the index of the new map,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new map.
 */
int start_hash_uint() {
    hash_uint* hash_uint = new_hash_uint();
    add_hash_uint(hash_uint);
    return hash_uint->index;
}

/**
 * @brief This function takes an index and returns the working
 * hash_uint associated with that index in the hash_uint table.
 * 
 * @param index The index of the target working hash_uint.
 * 
 * @return The pointer to the working hash_uint associated with
 * the provided index.
 */
hash_uint* find_hash_uint(int index) {
    hash_uint *hash_uint;
    HASH_FIND_INT(hash_uints, &index, hash_uint);
    return hash_uint;
}

hash_uint* zero_hash_uint(int index) {
    hash_uint* hash_uint = find_hash_uint(index);
    dogecoin_mem_zero(hash_uint->data, sizeof(uint256));
    return hash_uint;
}

void set_hash_uint(int index, uint8_t* x, char* typename) {
    printnl(typename);
    hash_uint* hash_uint_local = zero_hash_uint(index);
    dogecoin_bool set = true;
    size_t i = sizeof(x);
    if (typename=="unsigned char") {
        printf("%s\n", typename);
        goto sethash_uint;
    } else if (typename=="unsigned long int") {
        printf("%s\n", typename);
        set = false;
        goto sethash_uint;
    } else if (typename=="int") {
        printf("%s\n", typename);
        set = false;
        goto sethash_uint;
    } else if (typename=="unsigned int") {
        printf("%s\n", typename);
        set = false;
        goto sethash_uint;
    }

sethash_uint:
    printf("i: %d\n", i);
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->x.u8, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->x.u32, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->data, 32));
    set_compact(&hash_uint_local->x, x, &hash_uint_local->checks.negative, &hash_uint_local->checks.overflow);
    memcpy_safe(hash_uint_local->data, hash_uint_local->x.u8, 32);
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->x.u8, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->x.u32, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->data, 32));
    if (i < 32) {
        if (((uint32_t)x >> 24) < 32) swap_bytes(hash_uint_local->data, 32);
        else swap_bytes(hash_uint_local->data, 4);
    } else {
        x = utils_uint8_to_hex((uint8_t*)x, 32);
        utils_reverse_hex(x, 64);
        swap_bytes(hash_uint_local->x.u8, 32);
    }
    printf("u32: %s\n", utils_uint8_to_hex(hash_uint_local->x.u8, 32));
    if (set) utils_uint256_sethex(x, hash_uint_local->data);
}

void set_hash_uint_compact(int index, uint8_t* x, char* typename) {

    printnl(typename);
    hash_uint* hash_uint_local = zero_hash_uint(index);
    dogecoin_bool set = true;
    if (typename=="unsigned char") {
        printf("%s\n", typename);
        x = utils_uint8_to_hex((uint8_t*)x, 32);
        utils_reverse_hex(x, 64);
    } else if (typename=="unsigned long int") {
        printf("%s\n", typename);
        size_t i = sizeof(x);
        if (i < 32) {
            memcpy_safe(hash_uint_local->data, (uint8_t*)&x, i);
        }
        set = false;
    } else if (typename=="int") {
        printf("%s\n", typename);
        size_t i = sizeof(x);
        if (i < 32) {
            base_uint* b = init_base_uint();
            dogecoin_bool overflow, negative;
            set_compact(b, x, negative, overflow);
            memcpy_safe(hash_uint_local->data, b->x.u8, 32);
            printf("b: %s\n", to_string(b->x.u8));
            printf("b: %s\n", to_string(b->x.u32));
            swap_bytes(hash_uint_local->data, 32);
            dogecoin_free(b);
        }
        set = false;
    }
    if (set) utils_uint256_sethex(x, hash_uint_local->data);
}

void showbits( unsigned int x )
{
    int i=0;
    for (i = (sizeof(int) * 8) - 1; i >= 0; i--)
    {
       putchar(x & (1u << i) ? '1' : '0');
    }
    printf("\n");
}

void print_hash_uint(int index) {
    hash_uint* hash_uint_local = find_hash_uint(index);
    showbits(hash_uint_local->data);
    printf("%s\n", utils_uint8_to_hex(hash_uint_local->data, 32));
}

char* get_hash_uint_by_index(int index) {
    hash_uint* hash_uint_local = find_hash_uint(index);
    return utils_uint8_to_hex(hash_uint_local->data, 32);
}

/**
 * @brief This function removes the specified working hash_uint
 * from the hash_uint table and frees the hash_uintes in memory.
 * 
 * @param map The pointer to the hash_uint to remove.
 * 
 * @return Nothing.
 */
void remove_hash_uint(hash_uint *hash_uint) {
    HASH_DEL(hash_uints, hash_uint); /* delete it (hash_uintes advances to next) */
    if (hash_uint->data) dogecoin_free(hash_uint->data);
    dogecoin_free(hash_uint);
}

/**
 * @brief This function removes all working hash_uintes from
 * the hash_uint table.
 * 
 * @return Nothing. 
 */
void remove_all_hash_uintes() {
    struct hash_uint *hash_uint;
    struct hash_uint *tmp;

    HASH_ITER(hh, hash_uints, hash_uint, tmp) {
        remove_hash_uint(hash_uint);
    }
}

/**
 * @brief This function instantiates a new working hash_uintmap,
 * but does not add it to the hash_uint table.
 * 
 * @return A pointer to the new working hash_uintmap. 
 */
hash_uintmap* new_hash_uintmap() {
    hash_uintmap* map = (struct hash_uintmap*)dogecoin_calloc(1, sizeof *map);
    map->count = 1;
    map->hash_uints = hash_uints;
    map->index = HASH_COUNT(hash_uintmaps) + 1;
    return map;
}

/**
 * @brief This function creates a new map, places it in
 * the hash_uint table, and returns the index of the new map,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new map.
 */
int start_hash_uintmap() {
    hash_uintmap* map = new_hash_uintmap();
    add_hash_uintmap(map);
    return map->index;
}

/**
 * @brief This function takes a pointer to an existing working
 * hash_uintmap object and adds it to the hash_uint table.
 * 
 * @param map The pointer to the working hash_uintmap.
 * 
 * @return Nothing.
 */
void add_hash_uintmap(hash_uintmap *map) {
    hash_uintmap *hash_uint_local;
    HASH_FIND_INT(hash_uintmaps, &map->index, hash_uint_local);
    if (hash_uint_local == NULL) {
        HASH_ADD_INT(hash_uintmaps, index, map);
    } else {
        HASH_REPLACE_INT(hash_uintmaps, index, map, hash_uint_local);
    }
    dogecoin_free(hash_uint_local);
}

/**
 * @brief This function takes an index and returns the working
 * hash_uintmap associated with that index in the hash_uint table.
 * 
 * @param index The index of the target working hash_uintmap.
 * 
 * @return The pointer to the working hash_uintmap associated with
 * the provided index.
 */
hash_uintmap* find_hash_uintmap(int index) {
    hash_uintmap *map;
    HASH_FIND_INT(hash_uintmaps, &index, map);
    return map;
}

/**
 * @brief This function removes the specified working hash_uintmap
 * from the hash_uint table and frees the hash_uintmaps in memory.
 * 
 * @param map The pointer to the hash_uintmap to remove.
 * 
 * @return Nothing.
 */
void remove_hash_uintmap(hash_uintmap *map) {
    HASH_DEL(hash_uintmaps, map); /* delete it (hash_uintmaps advances to next) */
    dogecoin_free(map);
}

/**
 * @brief This function removes all working hash_uintmaps from
 * the hash_uint table.
 * 
 * @return Nothing. 
 */
void remove_all_hash_uintmaps() {
    struct hash_uintmap *map;
    struct hash_uintmap *tmp;

    HASH_ITER(hh, hash_uintmaps, map, tmp) {
        remove_hash_uintmap(map);
    }
}

/* base_uint functions */

void shift_left(int index, uint256 b, unsigned int shift) {
    hash_uint* hash_uint = find_hash_uint(index);
    int i = 0;
    uint256 pn;
    memcpy_safe(&pn, &b, 32);
    for (; i < 32; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < 32; i++) {
        if (i + k + 1 < 32 && shift != 0)
            pn[i + k + 1] |= ((uint8_t)hash_uint->data[i] >> (32 - shift));
        if (i + k < 32)
            pn[i + k] |= ((uint8_t)hash_uint->data[i] << shift);
    }
}

void base_uint_shift_left_equal(base_uint* b, unsigned int shift) {
    base_uint* a = init_base_uint();
    int i = 0;
    for (; i < WIDTH; i++)
        b->x.u32[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            a->x.u32[i + k + 1] |= (b->x.u32[i] >> (32 - shift));
        if (i + k < WIDTH)
            a->x.u32[i + k] |= (b->x.u32[i] << shift);
    }
    b = a;
}

void base_uint_shift_right_equal(base_uint* b, unsigned int shift) {
    base_uint* a = init_base_uint();
    int i = 0;
    for (; i < 8; i++)
        b->x.u32[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < 8; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            a->x.u32[i - k - 1] |= (b->x.u32[i] << (32 - shift));
        if (i - k >= 0)
            a->x.u32[i - k] |= (b->x.u32[i] >> shift);
    }
    b = a;
}

void base_uint_times_equal_uint32(base_uint* b, uint32_t b32) {
    uint64_t carry = 0;
    int i = 0;
    for (; i < WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * b->x.u32[i];
        b->x.u32[i] = n & 0xffffffff;
        carry = n >> 32;
    }
}

base_uint* base_uint_times_equal(base_uint* b) {
    base_uint* a = b;
    _base_uint(b, NULL);
    int j = 0;
    for (; j < WIDTH; j++) {
        uint64_t carry = 0;
        int i = 0;
        for (; i + j < WIDTH; i++) {
            uint64_t n = carry + a->x.u32[i + j] + (uint64_t)a->x.u32[j] * b->x.u32[i];
            a->x.u32[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return a;
}

base_uint* base_uint_divide_equal(base_uint* a) {
    base_uint* div = a;     // make a copy, so we can shift.
    base_uint* num = a; // make a copy, so we can subtract.
    _base_uint(a, NULL);                   // the quotient.
    unsigned int num_bits = base_uint_bits(num);
    unsigned int div_bits = base_uint_bits(div);
    if (div_bits == 0)
        return set_uint_err("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return a;
    unsigned int shift = num_bits - div_bits;
    base_uint_shift_left_equal(div, shift); // shift so that div and num align.
    while (shift >= 0) {
        if (num >= div) {
            num = num - div;
            a->x.u32[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        base_uint_shift_right_equal(div, 1); // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return a;
}

int base_uint_compare(base_uint* a, base_uint* b) {
    int i = WIDTH - 1;
    for (; i >= 0; i--) {
        if (a->x.u8[i] < b->x.u8[i])
            return -1;
        if (a->x.u8[i] > b->x.u8[i])
            return 1;
    }
    return 0;
}

dogecoin_bool base_uint_equal_to(base_uint* a, uint64_t b) {
    int i = WIDTH - 1;
    for (; i >= 2; i--) {
        if (a->x.u8[i])
            return false;
    }
    if (a->x.u8[1] != (b >> 32))
        return false;
    if (a->x.u8[0] != (b & 0xfffffffful))
        return false;
    return true;
}

double base_uint_get_double(base_uint* a) {
    double ret = 0.0;
    double fact = 1.0;
    int i = 0;
    for (; i < WIDTH; i++) {
        ret += fact * a->x.u32[i];
        fact *= 4294967296.0;
    }
    return ret;
}

char* base_uint_get_hex(base_uint* a) {
    char* psz = dogecoin_char_vla(sizeof(a->x.u32) * 2 + 1);
    unsigned int i = 0;
    for (; i < sizeof(a->x.u32); i++)
        sprintf(psz + i * 2, "%02x", a->x.u32[sizeof(a->x.u32) - i - 1]);
    return psz;
}

char* get_hash_uint_hex(hash_uint* a) {
    char* psz = dogecoin_char_vla(sizeof(a->data) * 2 + 1);
    unsigned int i = 0;
    for (; i < sizeof(a->data); i++)
        sprintf(psz + i * 2, "%02x", a->data[sizeof(a->data) - i - 1]);
    return psz;
}

void base_uint_set_hex(base_uint* a, const char* psz) {
    memset_safe((volatile void*)&a->x.u32[0], 0, sizeof(a->x.u32), 0);

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
    unsigned char* p1 = (unsigned char*)a->x.u32;
    unsigned char* pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = utils_hex_digit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)utils_hex_digit(*psz--) << 4);
            p1++;
        }
    }
    printf("psz: %s\n", a->to_string(a));
}

char* base_uint_to_string(const struct base_uint* a) {
    return base_uint_get_hex(a);
    // return utils_uint8_to_hex((const uint8_t*)arith_to_uint256(a), 32);
}

unsigned int base_uint_bits(swap* a) {
    int pos = WIDTH - 1;
    for (; pos >= 0; pos--) {
        if (a->u32[pos]) {
            int bits = 31;
            for (; bits > 0; bits--) {
                if (a->u32[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

unsigned int hash_uint_bits(hash_uint* a) {
    int pos = WIDTH - 1;
    for (; pos >= 0; pos--) {
        if (&a->x.u32[pos]) {
            int bits = 31;
            for (; bits > 0; bits--) {
                if ((uint32_t)&a->x.u32[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

/* base_uint functions */

char* base_uint_to_string_from_vector(base_uint* arr_u256) {
    return utils_uint8_to_hex((const uint8_t*)arith_to_uint256(arr_u256), 32);
}

base_uint* base_uint_shift_right(const base_uint* b, int shift) { 
    base_uint_shift_right_equal(b, shift);
    return b;
}

base_uint* base_uint_shift_left(const base_uint* b, int shift) { 
    base_uint_shift_left_equal(b, shift);
    return b;
}

base_uint* base_uint_xor(base_uint* a, base_uint* b) { 
    base_uint* result = init_base_uint();
    int i = 0;
    for (; i < 8; i++) {
        result->x.u32[i] = a->x.u32[i] ^ b->x.u32[i];
    }
    return result;
}

uint64_t get_low64(swap* a) {
    return a->u32[0] | (uint64_t)a->u32[1] << 32;
}

uint64_t get_hash_uint_low64(hash_uint* a) {
    return a->x.u32[0] | (uint64_t)a->x.u32[1] << 32;
}

uint32_t get_compact(swap* a, dogecoin_bool f_negative)
{
    int nSize = (base_uint_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = get_low64(a) << 8 * (3 - nSize);
    } else {
        swap* bn = dogecoin_calloc(1, sizeof(*bn));
        bn->u32[0] = a->u32[0] >> 8 * (nSize - 3);
        nCompact = get_low64(bn);
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

uint32_t get_compact_hash_uint(int index)
{
    hash_uint* a = find_hash_uint(a);
    print_hash_uint(index);
    int nSize = (hash_uint_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = get_hash_uint_low64(a) << 8 * (3 - nSize);
    } else {
        swap* bn = dogecoin_calloc(1, sizeof(*bn));
        bn->u32[0] = (uint32_t)&a->x.u32[0] >> 8 * (nSize - 3);
        nCompact = get_low64(bn);
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
    nCompact |= (&a->checks.negative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

swap* set_compact(swap* hash_uint, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffff;
    printf("word: %lu\n", word);
    printf("size: %d\n", size);
    printf("size: %d\n", pf_negative);
    printf("size: %d\n", &pf_negative);
    printf("size: %d\n", *pf_negative);
    if (size <= 3) {
        word >>= 8 * (3 - size);
        hash_uint->u32[0] = word;
    } else {
        hash_uint->u32[0] = word;
        hash_uint->u32[0] <<= 8 * (size - 3);
    }
    if (pf_negative) {
        *pf_negative = word != 0 && (compact & 0x00800000) != 0;
    }
    if (pf_overflow) {
        *pf_overflow = word != 0 && ((size > 34) ||
                                    (word > 0xff && size > 33) ||
                                    (word > 0xffff && size > 32));
    }
    printf("size: %d\n", *pf_negative);
    return hash_uint;
}

base_uint* uint_to_arith(const uint256* a) {
    base_uint* b = init_base_uint();
    memcpy_safe(b->x.u8, a, 32);
    return b;
}

uint256* arith_to_uint256(const base_uint* a) {
    uint256* b = dogecoin_uint256_vla(1);
    memcpy_safe(b, a->x.u8, 32);
    return b;
}
