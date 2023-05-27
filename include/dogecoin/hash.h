/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_HASH_H__
#define __LIBDOGECOIN_HASH_H__

#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

LIBDOGECOIN_API static inline dogecoin_bool dogecoin_hash_is_empty(uint256 hash)
{
    return hash[0] == 0 && !memcmp(hash, hash + 1, 19);
}

LIBDOGECOIN_API static inline void dogecoin_hash_clear(uint256 hash)
{
    dogecoin_mem_zero(hash, DOGECOIN_HASH_LENGTH);
}

LIBDOGECOIN_API static inline dogecoin_bool dogecoin_hash_equal(uint256 hash_a, uint256 hash_b)
{
    return (memcmp(hash_a, hash_b, DOGECOIN_HASH_LENGTH) == 0);
}

LIBDOGECOIN_API static inline void dogecoin_hash_set(uint256 hash_dest, const uint256 hash_src)
{
    memcpy_safe(hash_dest, hash_src, DOGECOIN_HASH_LENGTH);
}

LIBDOGECOIN_API static inline void dogecoin_hash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout);
    sha256_raw(hashout, SHA256_DIGEST_LENGTH, hashout); // dogecoin double sha256 hash
}

LIBDOGECOIN_API static inline dogecoin_bool dogecoin_dblhash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout);
    sha256_raw(hashout, SHA256_DIGEST_LENGTH, hashout); // dogecoin double sha256 hash
    return true;
}

LIBDOGECOIN_API static inline void dogecoin_hash_sngl_sha256(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout); // single sha256 hash
}

LIBDOGECOIN_API static inline void dogecoin_get_auxpow_hash(const uint32_t version, uint256 hashout)
{
    scrypt_1024_1_1_256(BEGIN(version), BEGIN(hashout));
}

typedef uint256 chain_code;

typedef struct _chash256 {
    sha256_context* sha;
    void (*finalize)(sha256_context* ctx, unsigned char hash[SHA256_DIGEST_LENGTH]);
    void (*write)(sha256_context* ctx, const uint8_t* data, size_t len);
    void (*reset)();
} chash256;

static inline chash256* dogecoin_chash256_init() {
    chash256* chash = dogecoin_calloc(1, sizeof(*chash));
    sha256_context* ctx = NULL;
    sha256_init(ctx);
    chash->sha = ctx;
    chash->write = sha256_write;
    chash->finalize = sha256_finalize;
    chash->reset = sha256_reset;
    return chash;
}

static inline uint256* Hash(const uint256 p1begin, const uint256 p1end,
                    const uint256 p2begin, const uint256 p2end) {
    static const unsigned char pblank[1];
    uint256* result = dogecoin_uint256_vla(1);
    chash256* chash = dogecoin_chash256_init();
    chash->write(chash->sha, p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
    chash->write(chash->sha, p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
    chash->finalize(chash->sha, (unsigned char*)result);
    chash->reset(chash->sha);
    return result;
}

/** SipHash 2-4 */
typedef struct siphasher {
    uint64_t v[4];
    uint64_t tmp;
    int count;
    void (*write)(struct siphasher* sh, uint64_t data);
    void (*hash)(struct siphasher* sh, const unsigned char* data, size_t size);
    uint64_t (*finalize)(struct siphasher* sh);
} siphasher;

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do { \
    v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; \
    v0 = ROTL64(v0, 32); \
    v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; \
    v2 = ROTL64(v2, 32); \
} while (0)

static void siphasher_set(struct siphasher* sh, uint64_t k0, uint64_t k1)
{
    sh->v[0] = 0x736f6d6570736575ULL ^ k0;
    sh->v[1] = 0x646f72616e646f6dULL ^ k1;
    sh->v[2] = 0x6c7967656e657261ULL ^ k0;
    sh->v[3] = 0x7465646279746573ULL ^ k1;
    sh->count = 0;
    sh->tmp = 0;
}

static void siphasher_write(struct siphasher* sh, uint64_t data)
{
    uint64_t v0 = sh->v[0], v1 = sh->v[1], v2 = sh->v[2], v3 = sh->v[3];

    assert(sh->count % 8 == 0);

    v3 ^= data;
    SIPROUND;
    SIPROUND;
    v0 ^= data;

    sh->v[0] = v0;
    sh->v[1] = v1;
    sh->v[2] = v2;
    sh->v[3] = v3;

    sh->count += 8;
}

static void siphasher_hash(struct siphasher* sh, const unsigned char* data, size_t size) {
    uint64_t v0 = sh->v[0], v1 = sh->v[1], v2 = sh->v[2], v3 = sh->v[3];
    uint64_t t = sh->tmp;
    int c = sh->count;

    while (size--) {
        t |= ((uint64_t)(*(data++))) << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND;
            SIPROUND;
            v0 ^= t;
            t = 0;
        }
    }

    sh->v[0] = v0;
    sh->v[1] = v1;
    sh->v[2] = v2;
    sh->v[3] = v3;
    sh->count = c;
    sh->tmp = t;
}

static uint64_t siphasher_finalize(struct siphasher* sh) {
    uint64_t v0 = sh->v[0], v1 = sh->v[1], v2 = sh->v[2], v3 = sh->v[3];

    uint64_t t = sh->tmp | (((uint64_t)sh->count) << 56);

    v3 ^= t;
    SIPROUND;
    SIPROUND;
    v0 ^= t;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

DISABLE_WARNING_PUSH
DISABLE_WARNING(-Wunused-function)
typedef union u256 {
    uint256 data;
    uint64_t (*get_uint64)(union u256* u256, int pos);
} u256;

static uint64_t get_uint64(union u256* u256, int pos) {
    const uint8_t* ptr = u256->data + pos * 8;
    return ((uint64_t)ptr[0]) | \
            ((uint64_t)ptr[1]) << 8 | \
            ((uint64_t)ptr[2]) << 16 | \
            ((uint64_t)ptr[3]) << 24 | \
            ((uint64_t)ptr[4]) << 32 | \
            ((uint64_t)ptr[5]) << 40 | \
            ((uint64_t)ptr[6]) << 48 | \
            ((uint64_t)ptr[7]) << 56;
}

static uint64_t siphash_u256(uint64_t k0, uint64_t k1, u256* val) {
    val->get_uint64 = get_uint64;
    /* Specialized implementation for efficiency */
    uint64_t d = val->get_uint64(val, 0);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ d;

    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val->get_uint64(val, 1);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val->get_uint64(val, 2);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val->get_uint64(val, 3);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    v3 ^= ((uint64_t)4) << 59;
    SIPROUND;
    SIPROUND;
    v0 ^= ((uint64_t)4) << 59;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
DISABLE_WARNING_POP

static inline siphasher* init_siphasher() {
    siphasher* sh = dogecoin_calloc(1, sizeof(*sh));
    uint64_t zero = 0;
    siphasher_set(sh, zero, zero);
    sh->write = siphasher_write;
    sh->hash = siphasher_hash;
    sh->finalize = siphasher_finalize;
    return sh;
}

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_HASH_H__
