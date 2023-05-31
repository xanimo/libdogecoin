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
 * @brief This function instantiates a new working hash,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working hash. 
 */
hash* new_hash() {
    hash* h = (struct hash*)dogecoin_calloc(1, sizeof *h);
    h->data = (uint256*)dogecoin_calloc(1, sizeof(*h->data));
    *h->x.u8 = *h->data;
    h->index = HASH_COUNT(hashes) + 1;
    return h;
}

/**
 * @brief This function takes a pointer to an existing working
 * hash object and adds it to the hash table.
 * 
 * @param map The pointer to the working hash.
 * 
 * @return Nothing.
 */
void add_hash(hash *x) {
    hash* hash_local;
    HASH_FIND_INT(hashes, &x->index, hash_local);
    if (hash_local == NULL) {
        HASH_ADD_INT(hashes, index, x);
    } else {
        HASH_REPLACE_INT(hashes, index, x, hash_local);
    }
    dogecoin_free(hash_local);
}

/**
 * @brief This function creates a new map, places it in
 * the hash table, and returns the index of the new map,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new map.
 */
int start_hash() {
    hash* hash = new_hash();
    add_hash(hash);
    return hash->index;
}

/**
 * @brief This function takes an index and returns the working
 * hash associated with that index in the hash table.
 * 
 * @param index The index of the target working hash.
 * 
 * @return The pointer to the working hash associated with
 * the provided index.
 */
hash* find_hash(int index) {
    hash *hash;
    HASH_FIND_INT(hashes, &index, hash);
    return hash;
}

hash* zero_hash(int index) {
    hash* hash = find_hash(index);
    dogecoin_mem_zero(hash->data, sizeof(uint256));
    return hash;
}

void set_hash(int index, uint8_t* x, char* typename) {
    printnl(typename);
    hash* hash_local = zero_hash(index);
    dogecoin_bool set = true;
    size_t i = sizeof(x);
    if (typename=="unsigned char") {
        printf("%s\n", typename);
        goto sethash;
    } else if (typename=="unsigned long int") {
        printf("%s\n", typename);
        set = false;
        goto sethash;
    } else if (typename=="int") {
        printf("%s\n", typename);
        set = false;
        goto sethash;
    } else if (typename=="unsigned int") {
        printf("%s\n", typename);
        set = false;
        goto sethash;
    }

sethash:
    printf("i: %d\n", i);
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->x.u8, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->x.u32, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->data, 32));
    set_compact(&hash_local->x, x, &hash_local->checks.negative, &hash_local->checks.overflow);
    memcpy_safe(hash_local->data, hash_local->x.u8, 32);
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->x.u8, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->x.u32, 32));
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->data, 32));
    if (i < 32) {
        if (((uint32_t)x >> 24) < 32) swap_bytes(hash_local->data, 32);
        else swap_bytes(hash_local->data, 4);
    } else {
        x = utils_uint8_to_hex((uint8_t*)x, 32);
        utils_reverse_hex(x, 64);
        swap_bytes(hash_local->x.u8, 32);
    }
    printf("u32: %s\n", utils_uint8_to_hex(hash_local->x.u8, 32));
    if (set) utils_uint256_sethex(x, hash_local->data);
}

void set_hash_compact(int index, uint8_t* x, char* typename) {

    printnl(typename);
    hash* hash_local = zero_hash(index);
    dogecoin_bool set = true;
    if (typename=="unsigned char") {
        printf("%s\n", typename);
        x = utils_uint8_to_hex((uint8_t*)x, 32);
        utils_reverse_hex(x, 64);
    } else if (typename=="unsigned long int") {
        printf("%s\n", typename);
        size_t i = sizeof(x);
        if (i < 32) {
            memcpy_safe(hash_local->data, (uint8_t*)&x, i);
        }
        set = false;
    } else if (typename=="int") {
        printf("%s\n", typename);
        size_t i = sizeof(x);
        if (i < 32) {
            base_uint* b = init_base_uint();
            dogecoin_bool overflow, negative;
            set_compact(b, x, negative, overflow);
            memcpy_safe(hash_local->data, b->x.u8, 32);
            printf("b: %s\n", to_string(b->x.u8));
            printf("b: %s\n", to_string(b->x.u32));
            swap_bytes(hash_local->data, 32);
            dogecoin_free(b);
        }
        set = false;
    }
    if (set) utils_uint256_sethex(x, hash_local->data);
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

void print_hash(int index) {
    hash* hash_local = find_hash(index);
    showbits(hash_local->data);
    printf("%s\n", utils_uint8_to_hex(hash_local->data, 32));
}

char* get_hash_by_index(int index) {
    hash* hash_local = find_hash(index);
    return utils_uint8_to_hex(hash_local->data, 32);
}

/**
 * @brief This function removes the specified working hash
 * from the hash table and frees the hashes in memory.
 * 
 * @param map The pointer to the hash to remove.
 * 
 * @return Nothing.
 */
void remove_hash(hash *hash) {
    HASH_DEL(hashes, hash); /* delete it (hashes advances to next) */
    if (hash->data) dogecoin_free(hash->data);
    dogecoin_free(hash);
}

/**
 * @brief This function removes all working hashes from
 * the hash table.
 * 
 * @return Nothing. 
 */
void remove_all_hashes() {
    struct hash *hash;
    struct hash *tmp;

    HASH_ITER(hh, hashes, hash, tmp) {
        remove_hash(hash);
    }
}

/**
 * @brief This function instantiates a new working hashmap,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working hashmap. 
 */
hashmap* new_hashmap() {
    hashmap* map = (struct hashmap*)dogecoin_calloc(1, sizeof *map);
    map->count = 1;
    map->hashes = hashes;
    map->index = HASH_COUNT(hashmaps) + 1;
    return map;
}

/**
 * @brief This function creates a new map, places it in
 * the hash table, and returns the index of the new map,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new map.
 */
int start_hashmap() {
    hashmap* map = new_hashmap();
    add_hashmap(map);
    return map->index;
}

/**
 * @brief This function takes a pointer to an existing working
 * hashmap object and adds it to the hash table.
 * 
 * @param map The pointer to the working hashmap.
 * 
 * @return Nothing.
 */
void add_hashmap(hashmap *map) {
    hashmap *hash_local;
    HASH_FIND_INT(hashmaps, &map->index, hash_local);
    if (hash_local == NULL) {
        HASH_ADD_INT(hashmaps, index, map);
    } else {
        HASH_REPLACE_INT(hashmaps, index, map, hash_local);
    }
    dogecoin_free(hash_local);
}

/**
 * @brief This function takes an index and returns the working
 * hashmap associated with that index in the hash table.
 * 
 * @param index The index of the target working hashmap.
 * 
 * @return The pointer to the working hashmap associated with
 * the provided index.
 */
hashmap* find_hashmap(int index) {
    hashmap *map;
    HASH_FIND_INT(hashmaps, &index, map);
    return map;
}

/**
 * @brief This function removes the specified working hashmap
 * from the hash table and frees the hashmaps in memory.
 * 
 * @param map The pointer to the hashmap to remove.
 * 
 * @return Nothing.
 */
void remove_hashmap(hashmap *map) {
    HASH_DEL(hashmaps, map); /* delete it (hashmaps advances to next) */
    dogecoin_free(map);
}

/**
 * @brief This function removes all working hashmaps from
 * the hash table.
 * 
 * @return Nothing. 
 */
void remove_all_hashmaps() {
    struct hashmap *map;
    struct hashmap *tmp;

    HASH_ITER(hh, hashmaps, map, tmp) {
        remove_hashmap(map);
    }
}

/* base_uint functions */

void shift_left(int index, uint256 b, unsigned int shift) {
    hash* hash = find_hash(index);
    int i = 0;
    uint256 pn;
    memcpy_safe(&pn, &b, 32);
    for (; i < 32; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (i = 0; i < 32; i++) {
        if (i + k + 1 < 32 && shift != 0)
            pn[i + k + 1] |= ((uint8_t)hash->data[i] >> (32 - shift));
        if (i + k < 32)
            pn[i + k] |= ((uint8_t)hash->data[i] << shift);
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

char* get_hash_hex(hash* a) {
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

unsigned int hash_bits(hash* a) {
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

uint64_t get_hash_low64(hash* a) {
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

uint32_t get_compact_hash(int index)
{
    hash* a = find_hash(a);
    print_hash(index);
    int nSize = (hash_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = get_hash_low64(a) << 8 * (3 - nSize);
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

swap* set_compact(swap* hash, uint32_t compact, dogecoin_bool *pf_negative, dogecoin_bool *pf_overflow) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffff;
    printf("word: %lu\n", word);
    printf("size: %d\n", size);
    printf("size: %d\n", pf_negative);
    printf("size: %d\n", &pf_negative);
    printf("size: %d\n", *pf_negative);
    if (size <= 3) {
        word >>= 8 * (3 - size);
        hash->u32[0] = word;
    } else {
        hash->u32[0] = word;
        hash->u32[0] <<= 8 * (size - 3);
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
    return hash;
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
