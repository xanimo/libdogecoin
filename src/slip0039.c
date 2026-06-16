/**
 * Copyright (c) 2026 edtubbs
 * Copyright (c) 2026 The Dogecoin Foundation
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

#include <dogecoin/slip0039.h>

#include <dogecoin/mem.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>

#include "slip0039_wordlist.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SLIP0039_RADIX_BITS              10
#define SLIP0039_ID_BITS                 15
#define SLIP0039_EXT_BITS                 1
#define SLIP0039_ITER_EXP_BITS            4
#define SLIP0039_METADATA_BITS           40   /* 4 mnemonic words */
#define SLIP0039_CHECKSUM_WORDS           3   /* 30-bit RS1024 checksum */
#define SLIP0039_DIGEST_INDEX           254
#define SLIP0039_SECRET_INDEX           255
#define SLIP0039_DIGEST_LENGTH_BYTES      4
#define SLIP0039_BASE_ITERATION_COUNT 10000
#define SLIP0039_ROUND_COUNT              4
#define SLIP0039_DEFAULT_ITER_EXP         1
#define SLIP0039_CUSTOMIZATION_STRING    "shamir"

/* "shamir" mapped to wordlist 10-bit indices for the RS1024 customization. */
static const uint16_t SLIP0039_RS1024_CUSTOMIZATION[6] = {
    's', 'h', 'a', 'm', 'i', 'r'
};

/* "shamir_extendable" for extendable mnemonics (ext=1). */
static const uint16_t SLIP0039_RS1024_CUSTOMIZATION_EXT[17] = {
    's','h','a','m','i','r','_','e','x','t','e','n','d','a','b','l','e'
};

static const uint32_t SLIP0039_RS1024_GEN[10] = {
    0x00E0E040UL, 0x01C1C080UL, 0x03838100UL, 0x07070200UL, 0x0E0E0009UL,
    0x1C0C2412UL, 0x38086C24UL, 0x3090FC48UL, 0x21B1F890UL, 0x03F3F120UL
};

/**
 * @brief Multiplies two elements in GF(256) using the AES polynomial.
 *
 * @param a Left operand.
 * @param b Right operand.
 *
 * @return Product in GF(256).
 */
static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return r;
}

/**
 * @brief Raises a GF(256) element to an integer power.
 *
 * @param a Base element.
 * @param exp Exponent.
 *
 * @return a^exp in GF(256).
 */
static uint8_t gf256_pow(uint8_t a, uint8_t exp)
{
    uint8_t r = 1;
    while (exp) {
        if (exp & 1) r = gf256_mul(r, a);
        a = gf256_mul(a, a);
        exp >>= 1;
    }
    return r;
}

/**
 * @brief Computes multiplicative inverse in GF(256) for non-zero input.
 *
 * @param a Byte value in GF(256).
 *
 * @return a^-1 in GF(256) when a != 0.
 */
static uint8_t gf256_inv(uint8_t a)
{
    return gf256_pow(a, 254);
}

/**
 * @brief Evaluates Lagrange interpolation in GF(256) for byte vectors.
 *
 * @param target_x X-coordinate to evaluate.
 * @param xs Distinct x-coordinates (n entries).
 * @param n Number of interpolation points.
 * @param ys Concatenated y-vectors (n * ylen bytes).
 * @param ylen Length of each y-vector in bytes.
 * @param out Output buffer for interpolated y-vector (ylen bytes).
 *
 * @return 0 on success, -1 on duplicate x-coordinate input.
 */
static int gf256_lagrange(uint8_t target_x,
                          const uint8_t* xs, size_t n,
                          const uint8_t* ys, size_t ylen,
                          uint8_t* out)
{
    memset(out, 0, ylen);
    /* If target_x matches a known x, copy that y directly. */
    for (size_t i = 0; i < n; ++i) {
        if (xs[i] == target_x) {
            memcpy(out, ys + i * ylen, ylen);
            return 0;
        }
    }
    for (size_t i = 0; i < n; ++i) {
        uint8_t num = 1;
        uint8_t den = 1;
        for (size_t j = 0; j < n; ++j) {
            if (j == i) continue;
            num = gf256_mul(num, (uint8_t)(target_x ^ xs[j]));
            den = gf256_mul(den, (uint8_t)(xs[i] ^ xs[j]));
        }
        if (den == 0) {
            /* Duplicate x in input. */
            return -1;
        }
        uint8_t lag = gf256_mul(num, gf256_inv(den));
        for (size_t k = 0; k < ylen; ++k) {
            out[k] ^= gf256_mul(ys[i * ylen + k], lag);
        }
    }
    return 0;
}

/**
 * @brief Computes the RS1024 polymod for a sequence of 10-bit words.
 *
 * @param values Input words.
 * @param n Number of input words.
 *
 * @return RS1024 polymod state.
 */
static uint32_t rs1024_polymod(const uint16_t* values, size_t n)
{
    uint32_t chk = 1;
    for (size_t i = 0; i < n; ++i) {
        uint32_t b = chk >> 20;
        chk = ((chk & 0xFFFFFUL) << 10) ^ (uint32_t)values[i];
        for (int j = 0; j < 10; ++j) {
            if ((b >> j) & 1) chk ^= SLIP0039_RS1024_GEN[j];
        }
    }
    return chk;
}

/**
 * @brief Creates and writes the 3-word RS1024 checksum.
 *
 * @param words Mnemonic words with checksum slots at the end.
 * @param total_words Total number of words including checksum.
 * @param extendable Non-zero for extendable checksum customization.
 *
 * @return Nothing.
 */
static void rs1024_create_checksum(uint16_t* words, size_t total_words, int extendable)
{
    /* total_words includes the 3 checksum slots (already zeroed by caller). */
    enum { RS1024_MAX_DATA = 64 };
    const uint16_t* cust    = extendable ? SLIP0039_RS1024_CUSTOMIZATION_EXT
                                         : SLIP0039_RS1024_CUSTOMIZATION;
    size_t          cust_len = extendable ? 17 : 6;
    uint16_t buf[17 + RS1024_MAX_DATA];
    if (total_words > RS1024_MAX_DATA) {
        return; /* unreachable for supported sizes (<= 33) */
    }
    memcpy(buf, cust, cust_len * sizeof(uint16_t));
    memcpy(buf + cust_len, words, total_words * sizeof(uint16_t));
    uint32_t poly = rs1024_polymod(buf, cust_len + total_words) ^ 1UL;
    for (size_t i = 0; i < SLIP0039_CHECKSUM_WORDS; ++i) {
        words[total_words - SLIP0039_CHECKSUM_WORDS + i] =
            (uint16_t)((poly >> (10 * (SLIP0039_CHECKSUM_WORDS - 1 - i))) & 0x3FFU);
    }
}

/**
 * @brief Verifies the RS1024 checksum of a mnemonic word sequence.
 *
 * @param words Mnemonic words including checksum.
 * @param total_words Total number of words including checksum.
 * @param extendable Non-zero for extendable checksum customization.
 *
 * @return 0 if checksum is valid, -1 otherwise.
 */
static int rs1024_verify_checksum(const uint16_t* words, size_t total_words, int extendable)
{
    enum { RS1024_MAX_DATA = 64 };
    const uint16_t* cust    = extendable ? SLIP0039_RS1024_CUSTOMIZATION_EXT
                                         : SLIP0039_RS1024_CUSTOMIZATION;
    size_t          cust_len = extendable ? 17 : 6;
    uint16_t buf[17 + RS1024_MAX_DATA];
    if (total_words > RS1024_MAX_DATA) return -1;
    memcpy(buf, cust, cust_len * sizeof(uint16_t));
    memcpy(buf + cust_len, words, total_words * sizeof(uint16_t));
    return (rs1024_polymod(buf, cust_len + total_words) == 1UL) ? 0 : -1;
}

typedef struct {
    uint16_t* words;
    size_t    capacity;
    size_t    count;       /* number of complete 10-bit words emitted */
    uint32_t  buf;         /* pending bit accumulator */
    int       bits;        /* number of pending bits (0..9) */
} bitpack_writer;

/**
 * @brief Initializes a 10-bit word writer.
 *
 * @param w Writer state to initialize.
 * @param words Destination word buffer.
 * @param capacity Maximum number of words that can be written.
 *
 * @return Nothing.
 */
static void bw_init(bitpack_writer* w, uint16_t* words, size_t capacity)
{
    w->words = words;
    w->capacity = capacity;
    w->count = 0;
    w->buf = 0;
    w->bits = 0;
}

/**
 * @brief Appends bits to the writer as 10-bit words.
 *
 * @param w Writer state.
 * @param value Source bits in the low nbits positions.
 * @param nbits Number of bits to append.
 *
 * @return 0 on success, -1 if capacity is exceeded.
 */
static int bw_put(bitpack_writer* w, uint32_t value, int nbits)
{
    while (nbits > 0) {
        int take = (nbits >= (10 - w->bits)) ? (10 - w->bits) : nbits;
        w->buf = (w->buf << take) | ((value >> (nbits - take)) & ((1U << take) - 1U));
        w->bits += take;
        nbits   -= take;
        if (w->bits == 10) {
            if (w->count >= w->capacity) return -1;
            w->words[w->count++] = (uint16_t)(w->buf & 0x3FFU);
            w->buf  = 0;
            w->bits = 0;
        }
    }
    return 0;
}

typedef struct {
    const uint16_t* words;
    size_t          total;
    size_t          idx;        /* index of the next 10-bit word to consume */
    uint32_t        buf;        /* bits available in buf, MSB-first */
    int             bits;       /* number of bits available in buf */
} bitpack_reader;

/**
 * @brief Initializes a 10-bit word reader.
 *
 * @param r Reader state to initialize.
 * @param words Source word buffer.
 * @param total Number of source words.
 *
 * @return Nothing.
 */
static void br_init(bitpack_reader* r, const uint16_t* words, size_t total)
{
    r->words = words;
    r->total = total;
    r->idx   = 0;
    r->buf   = 0;
    r->bits  = 0;
}

/**
 * @brief Reads a bit field from a 10-bit word stream.
 *
 * @param r Reader state.
 * @param nbits Number of bits to read.
 * @param out Output value.
 *
 * @return 0 on success, -1 on underflow.
 */
static int br_get(bitpack_reader* r, int nbits, uint32_t* out)
{
    while (r->bits < nbits) {
        if (r->idx >= r->total) return -1;
        r->buf = (r->buf << 10) | (uint32_t)(r->words[r->idx++] & 0x3FFU);
        r->bits += 10;
    }
    r->bits -= nbits;
    *out = (r->buf >> r->bits) & ((nbits == 32) ? 0xFFFFFFFFU : ((1U << nbits) - 1U));
    r->buf &= (r->bits == 0) ? 0U : ((1U << r->bits) - 1U);
    return 0;
}

/**
 * @brief Resolves a mnemonic word to its SLIP-0039 wordlist index.
 *
 * @param word Word bytes (not necessarily null-terminated).
 * @param word_len Length of the word in bytes.
 *
 * @return Word index on success, -1 if not found.
 */
static int slip0039_word_to_index(const char* word, size_t word_len)
{
    /* Wordlist is sorted alphabetically; binary search by full string. */
    int lo = 0, hi = SLIP0039_WORDLIST_SIZE - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        const char* m = slip0039_wordlist[mid];
        size_t mlen = strlen(m);
        size_t cmp_len = (mlen < word_len) ? mlen : word_len;
        int cmp = strncmp(m, word, cmp_len);
        if (cmp == 0) {
            if (mlen == word_len) return mid;
            cmp = (mlen < word_len) ? -1 : 1;
        }
        if (cmp < 0) lo = mid + 1;
        else         hi = mid - 1;
    }
    return -1;
}

/**
 * @brief Computes one Feistel round function output for EMS encryption.
 *
 * @param round_index Round number.
 * @param passphrase Optional passphrase bytes.
 * @param passlen Passphrase length in bytes.
 * @param identifier SLIP-0039 identifier.
 * @param iter_exp Iteration exponent.
 * @param extendable Non-zero for extendable mode.
 * @param r_half Right half input bytes.
 * @param half_len Half-size in bytes.
 * @param out Output round bytes.
 *
 * @return 0 on success, -1 on invalid input sizing.
 */
static int slip0039_round_function(uint8_t round_index,
                                   const uint8_t* passphrase, size_t passlen,
                                   uint16_t identifier,
                                   uint8_t iter_exp,
                                   int extendable,
                                   const uint8_t* r_half, size_t half_len,
                                   uint8_t* out)
{
    /* Password = round_index byte || passphrase. */
    uint8_t pass_buf[1 + 256];
    if (passlen > sizeof(pass_buf) - 1) return -1;
    pass_buf[0] = round_index;
    if (passphrase && passlen) memcpy(pass_buf + 1, passphrase, passlen);

    /* Salt computation depends on extendable flag:
     *   extendable=0: salt = "shamir" || id_BE(2) || R
     *   extendable=1: salt = R  (empty prefix) */
    uint8_t salt_buf[16 + 64];
    size_t  salt_len;
    if (extendable) {
        if (half_len > sizeof(salt_buf)) return -1;
        memcpy(salt_buf, r_half, half_len);
        salt_len = half_len;
    } else {
        const size_t cust_len = 6; /* strlen("shamir") */
        if (cust_len + 2 + half_len > sizeof(salt_buf)) return -1;
        memcpy(salt_buf, SLIP0039_CUSTOMIZATION_STRING, cust_len);
        salt_buf[cust_len + 0] = (uint8_t)((identifier >> 8) & 0xFF);
        salt_buf[cust_len + 1] = (uint8_t)(identifier & 0xFF);
        memcpy(salt_buf + cust_len + 2, r_half, half_len);
        salt_len = cust_len + 2 + half_len;
    }

    uint32_t iters = ((uint32_t)SLIP0039_BASE_ITERATION_COUNT << iter_exp) / SLIP0039_ROUND_COUNT;
    pbkdf2_hmac_sha256(pass_buf, (int)(1 + passlen),
                       salt_buf, (int)salt_len,
                       iters, out, (int)half_len);
    dogecoin_mem_zero(pass_buf, sizeof(pass_buf));
    dogecoin_mem_zero(salt_buf, sizeof(salt_buf));
    return 0;
}

/**
 * @brief Encrypts a master secret into an encrypted master secret (EMS).
 *
 * @param ms Master secret bytes.
 * @param ms_len Master secret length in bytes.
 * @param passphrase Optional passphrase bytes.
 * @param passlen Passphrase length in bytes.
 * @param identifier SLIP-0039 identifier.
 * @param iter_exp Iteration exponent.
 * @param extendable Non-zero for extendable mode.
 * @param ems_out Output encrypted master secret.
 *
 * @return 0 on success, -1 on invalid input.
 */
static int slip0039_encrypt(const uint8_t* ms, size_t ms_len,
                            const uint8_t* passphrase, size_t passlen,
                            uint16_t identifier, uint8_t iter_exp,
                            int extendable, uint8_t* ems_out)
{
    if (ms_len < 2 || (ms_len & 1)) return -1;
    size_t half = ms_len / 2;
    uint8_t L[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t R[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t F[SLIP0039_MAX_SECRET_BYTES / 2];
    if (half > sizeof(L)) return -1;
    memcpy(L, ms, half);
    memcpy(R, ms + half, half);
    for (uint8_t i = 0; i < SLIP0039_ROUND_COUNT; ++i) {
        if (slip0039_round_function(i, passphrase, passlen, identifier, iter_exp, extendable, R, half, F) != 0) {
            dogecoin_mem_zero(L, sizeof(L));
            dogecoin_mem_zero(R, sizeof(R));
            dogecoin_mem_zero(F, sizeof(F));
            return -1;
        }
        for (size_t k = 0; k < half; ++k) F[k] ^= L[k];
        memcpy(L, R, half);
        memcpy(R, F, half);
    }
    /* EMS = R || L per spec. */
    memcpy(ems_out, R, half);
    memcpy(ems_out + half, L, half);
    dogecoin_mem_zero(L, sizeof(L));
    dogecoin_mem_zero(R, sizeof(R));
    dogecoin_mem_zero(F, sizeof(F));
    return 0;
}

/**
 * @brief Decrypts an encrypted master secret (EMS) into the master secret.
 *
 * @param ems Encrypted master secret bytes.
 * @param ems_len EMS length in bytes.
 * @param passphrase Optional passphrase bytes.
 * @param passlen Passphrase length in bytes.
 * @param identifier SLIP-0039 identifier.
 * @param iter_exp Iteration exponent.
 * @param extendable Non-zero for extendable mode.
 * @param ms_out Output master secret bytes.
 *
 * @return 0 on success, -1 on invalid input.
 */
static int slip0039_decrypt(const uint8_t* ems, size_t ems_len,
                            const uint8_t* passphrase, size_t passlen,
                            uint16_t identifier, uint8_t iter_exp,
                            int extendable, uint8_t* ms_out)
{
    if (ems_len < 2 || (ems_len & 1)) return -1;
    size_t half = ems_len / 2;
    uint8_t L[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t R[SLIP0039_MAX_SECRET_BYTES / 2];
    uint8_t F[SLIP0039_MAX_SECRET_BYTES / 2];
    if (half > sizeof(L)) return -1;
    memcpy(L, ems, half);
    memcpy(R, ems + half, half);
    for (int i = SLIP0039_ROUND_COUNT - 1; i >= 0; --i) {
        if (slip0039_round_function((uint8_t)i, passphrase, passlen, identifier, iter_exp, extendable, R, half, F) != 0) {
            dogecoin_mem_zero(L, sizeof(L));
            dogecoin_mem_zero(R, sizeof(R));
            dogecoin_mem_zero(F, sizeof(F));
            return -1;
        }
        for (size_t k = 0; k < half; ++k) F[k] ^= L[k];
        memcpy(L, R, half);
        memcpy(R, F, half);
    }
    memcpy(ms_out, R, half);
    memcpy(ms_out + half, L, half);
    dogecoin_mem_zero(L, sizeof(L));
    dogecoin_mem_zero(R, sizeof(R));
    dogecoin_mem_zero(F, sizeof(F));
    return 0;
}

/**
 * @brief Encodes a single share into a SLIP-0039 mnemonic phrase.
 *
 * @param identifier 15-bit identifier.
 * @param iter_exp Iteration exponent (0..15).
 * @param group_idx Group index (0..15).
 * @param group_thr Group threshold (1..16).
 * @param group_count Group count (1..16).
 * @param member_idx Member index (0..15).
 * @param member_thr Member threshold (1..16).
 * @param share_value Raw share bytes.
 * @param ems_len Share value length in bytes (16..32, even).
 * @param out Output mnemonic buffer.
 * @param out_size Output buffer size.
 *
 * @return 0 on success, -1 on invalid input or encoding failure.
 */
static int slip0039_encode_mnemonic(uint16_t identifier,
                                    uint8_t  iter_exp,
                                    uint8_t  group_idx,
                                    uint8_t  group_thr,
                                    uint8_t  group_count,
                                    uint8_t  member_idx,
                                    uint8_t  member_thr,
                                    const uint8_t* share_value,
                                    size_t   ems_len,
                                    char*    out, size_t out_size)
{
    if (group_thr < 1 || group_count < 1 || member_thr < 1) return -1;
    if (group_thr > 16 || group_count > 16 || member_thr > 16) return -1;
    if (group_idx > 15 || member_idx > 15) return -1;
    if (iter_exp > 15) return -1;
    if (identifier > ((1U << SLIP0039_ID_BITS) - 1)) return -1;
    if (ems_len < SLIP0039_MIN_SECRET_BYTES || ems_len > SLIP0039_MAX_SECRET_BYTES || (ems_len & 1)) return -1;

    /* Number of words for the share value section (including pad bits). */
    size_t share_bits = ems_len * 8;
    size_t pad_bits = (10 - (share_bits % 10)) % 10;
    size_t share_words = (share_bits + pad_bits) / 10;
    size_t total_words = (SLIP0039_METADATA_BITS / 10) + share_words + SLIP0039_CHECKSUM_WORDS;

    uint16_t words[40];
    if (total_words > sizeof(words) / sizeof(words[0])) return -1;
    memset(words, 0, sizeof(words));

    bitpack_writer w;
    bw_init(&w, words, total_words - SLIP0039_CHECKSUM_WORDS);

    if (bw_put(&w, identifier, SLIP0039_ID_BITS)            != 0) return -1;
    if (bw_put(&w, 0, SLIP0039_EXT_BITS)                    != 0) return -1; /* non-extendable */
    if (bw_put(&w, iter_exp, SLIP0039_ITER_EXP_BITS)        != 0) return -1;
    if (bw_put(&w, group_idx, 4)                            != 0) return -1;
    if (bw_put(&w, (uint32_t)(group_thr - 1), 4)            != 0) return -1;
    if (bw_put(&w, (uint32_t)(group_count - 1), 4)          != 0) return -1;
    if (bw_put(&w, member_idx, 4)                           != 0) return -1;
    if (bw_put(&w, (uint32_t)(member_thr - 1), 4)           != 0) return -1;

    /* Pad bits (zeros) to align share value on 10-bit boundary. */
    if (pad_bits) {
        if (bw_put(&w, 0, (int)pad_bits)                    != 0) return -1;
    }

    /* Share value, byte-by-byte MSB first. */
    for (size_t i = 0; i < ems_len; ++i) {
        if (bw_put(&w, share_value[i], 8)                   != 0) return -1;
    }

    /* RS1024 checksum (computed over data + zero placeholders). */
    rs1024_create_checksum(words, total_words, 0 /* non-extendable */);

    /* Render to space-separated mnemonic string. */
    size_t pos = 0;
    for (size_t i = 0; i < total_words; ++i) {
        if (words[i] >= SLIP0039_WORDLIST_SIZE) return -1;
        const char* mn = slip0039_wordlist[words[i]];
        size_t mn_len = strlen(mn);
        size_t need = mn_len + (i + 1 < total_words ? 1 : 1); /* word + space or word + null */
        if (pos + need >= out_size) return -1;
        memcpy(out + pos, mn, mn_len);
        pos += mn_len;
        if (i + 1 < total_words) out[pos++] = ' ';
    }
    out[pos] = '\0';
    return 0;
}

/**
 * @brief Decodes a SLIP-0039 mnemonic phrase into metadata and share bytes.
 *
 * @param mnemonic Input mnemonic phrase.
 * @param identifier_out Decoded identifier.
 * @param extendable_out Decoded extendable bit.
 * @param iter_exp_out Decoded iteration exponent.
 * @param group_idx_out Decoded group index.
 * @param group_thr_out Decoded group threshold.
 * @param group_count_out Decoded group count.
 * @param member_idx_out Decoded member index.
 * @param member_thr_out Decoded member threshold.
 * @param share_value Output buffer for decoded share bytes.
 * @param value_len In/out share length buffer.
 *
 * @return 0 on success, -1 on invalid input or checksum/decode failure.
 */
static int slip0039_decode_mnemonic(const char* mnemonic,
                                    uint16_t* identifier_out,
                                    uint8_t*  extendable_out,
                                    uint8_t*  iter_exp_out,
                                    uint8_t*  group_idx_out,
                                    uint8_t*  group_thr_out,
                                    uint8_t*  group_count_out,
                                    uint8_t*  member_idx_out,
                                    uint8_t*  member_thr_out,
                                    uint8_t*  share_value, size_t* value_len)
{
    if (!mnemonic || !share_value || !value_len) return -1;

    /* Tokenize words into 10-bit indices. */
    uint16_t words[40];
    size_t   total_words = 0;
    const char* p = mnemonic;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') ++p;
        if (!*p) break;
        const char* start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
        size_t wlen = (size_t)(p - start);
        if (wlen == 0 || wlen > 8) return -1;
        if (total_words >= sizeof(words) / sizeof(words[0])) return -1;
        int idx = slip0039_word_to_index(start, wlen);
        if (idx < 0) return -1;
        words[total_words++] = (uint16_t)idx;
    }

    if (total_words < (SLIP0039_METADATA_BITS / 10) + SLIP0039_CHECKSUM_WORDS + 1) return -1;
    if (total_words > sizeof(words) / sizeof(words[0])) return -1;

    /* Extract ext bit from header words (first 20 bits across words[0..1]) before
     * checksum verification, since the customization string depends on it.
     * Layout: [id:15][ext:1][iter_exp:4] packed into 2 x 10-bit words. */
    {
        uint32_t id_exp = ((uint32_t)words[0] << 10) | (uint32_t)words[1];
        uint8_t ext_bit = (uint8_t)((id_exp >> SLIP0039_ITER_EXP_BITS) & 1);
        if (rs1024_verify_checksum(words, total_words, ext_bit) != 0) return -1;
    }

    size_t share_words = total_words - (SLIP0039_METADATA_BITS / 10) - SLIP0039_CHECKSUM_WORDS;
    size_t share_bits  = share_words * 10;
    /* Determine padding so share_bits - pad is a whole-byte share value. */
    /* For 16-byte share: share_words=13 -> share_bits=130 -> pad=2 -> 128 = 16 bytes. */
    /* For 32-byte share: share_words=26 -> share_bits=260 -> pad=4 -> 256 = 32 bytes. */
    if (share_bits < 8) return -1;
    size_t pad_bits = share_bits % 8;
    if (pad_bits >= 10) return -1; /* per spec: pad must be < radix */
    size_t value_bits = share_bits - pad_bits;
    if ((value_bits & 7) != 0) return -1;
    size_t ems_len = value_bits / 8;
    if (ems_len < SLIP0039_MIN_SECRET_BYTES || ems_len > SLIP0039_MAX_SECRET_BYTES) return -1;
    if ((ems_len & 1) != 0) return -1;
    if (*value_len < ems_len) return -1;

    bitpack_reader r;
    br_init(&r, words, total_words - SLIP0039_CHECKSUM_WORDS);

    uint32_t v = 0;
    if (br_get(&r, SLIP0039_ID_BITS, &v) != 0)        return -1;
    *identifier_out = (uint16_t)v;
    if (br_get(&r, SLIP0039_EXT_BITS, &v) != 0)       return -1;
    *extendable_out = (uint8_t)v;
    if (br_get(&r, SLIP0039_ITER_EXP_BITS, &v) != 0)  return -1;
    *iter_exp_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_idx_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_thr_out = (uint8_t)(v + 1);
    if (br_get(&r, 4, &v) != 0) return -1;
    *group_count_out = (uint8_t)(v + 1);
    /* group_threshold must not exceed group_count */
    if (*group_thr_out > *group_count_out) return -1;
    if (br_get(&r, 4, &v) != 0) return -1;
    *member_idx_out = (uint8_t)v;
    if (br_get(&r, 4, &v) != 0) return -1;
    *member_thr_out = (uint8_t)(v + 1);

    /* Verify pad bits are zero. */
    if (pad_bits) {
        if (br_get(&r, (int)pad_bits, &v) != 0) return -1;
        if (v != 0) return -1;
    }
    /* Read share bytes. */
    for (size_t i = 0; i < ems_len; ++i) {
        if (br_get(&r, 8, &v) != 0) return -1;
        share_value[i] = (uint8_t)v;
    }
    *value_len = ems_len;
    return 0;
}

/**
 * @brief Builds the digest share value from a secret and random pad.
 *
 * @param secret Encrypted master secret bytes.
 * @param ems_len Encrypted master secret length in bytes.
 * @param random_pad Random pad bytes (ems_len - digest length).
 * @param out Output digest-share buffer (ems_len bytes).
 */
static void slip0039_make_digest_share(const uint8_t* secret, size_t ems_len,
                                       const uint8_t* random_pad,
                                       uint8_t* out)
{
    uint8_t mac[32];
    hmac_sha256(random_pad, ems_len - SLIP0039_DIGEST_LENGTH_BYTES,
                secret, ems_len, mac);
    memcpy(out, mac, SLIP0039_DIGEST_LENGTH_BYTES);
    memcpy(out + SLIP0039_DIGEST_LENGTH_BYTES, random_pad,
           ems_len - SLIP0039_DIGEST_LENGTH_BYTES);
    dogecoin_mem_zero(mac, sizeof(mac));
}

/**
 * @brief Verifies that a digest share matches the provided EMS bytes.
 *
 * @param secret Reconstructed encrypted master secret bytes.
 * @param ems_len EMS length in bytes.
 * @param digest_share Digest share bytes.
 *
 * @return 0 if digest matches, -1 otherwise.
 */
static int slip0039_verify_digest_share(const uint8_t* secret, size_t ems_len,
                                        const uint8_t* digest_share)
{
    uint8_t mac[32];
    hmac_sha256(digest_share + SLIP0039_DIGEST_LENGTH_BYTES,
                ems_len - SLIP0039_DIGEST_LENGTH_BYTES,
                secret, ems_len, mac);
    int ok = (memcmp(mac, digest_share, SLIP0039_DIGEST_LENGTH_BYTES) == 0) ? 0 : -1;
    dogecoin_mem_zero(mac, sizeof(mac));
    return ok;
}

/**
 * @brief Splits EMS bytes into member shares at a given threshold.
 *
 * @param ems Encrypted master secret bytes.
 * @param ems_len EMS length in bytes.
 * @param threshold Member threshold.
 * @param share_count Number of shares to produce.
 * @param shares_y_out Output share values buffer.
 *
 * @return 0 on success, -1 on invalid input or interpolation failure.
 */
static int slip0039_split(const uint8_t* ems, size_t ems_len,
                          uint8_t threshold, uint8_t share_count,
                          uint8_t* shares_y_out)
{
    if (threshold < 1 || share_count < threshold || share_count > SLIP0039_MAX_SHARES) return -1;

    if (threshold == 1) {
        for (uint8_t i = 0; i < share_count; ++i) {
            memcpy(shares_y_out + i * ems_len, ems, ems_len);
        }
        return 0;
    }

    /* Build T known points: indices 0..T-3 random, plus digest at 254 and secret at 255. */
    uint8_t known_x[SLIP0039_MAX_SHARES + 2];
    uint8_t known_y[(SLIP0039_MAX_SHARES + 2) * SLIP0039_MAX_SECRET_BYTES];
    size_t  known_n = 0;

    /* Random shares with x = 0..T-3, becoming the first T-2 user shares. */
    for (uint8_t i = 0; i + 2 < threshold; ++i) {
        if (!dogecoin_random_bytes(known_y + known_n * ems_len, (uint32_t)ems_len, 0)) {
            return -1;
        }
        known_x[known_n] = i;
        memcpy(shares_y_out + i * ems_len, known_y + known_n * ems_len, ems_len);
        ++known_n;
    }

    /* Digest share at x = 254. */
    uint8_t random_pad[SLIP0039_MAX_SECRET_BYTES];
    if (!dogecoin_random_bytes(random_pad, (uint32_t)(ems_len - SLIP0039_DIGEST_LENGTH_BYTES), 0)) {
        return -1;
    }
    uint8_t digest_share[SLIP0039_MAX_SECRET_BYTES];
    slip0039_make_digest_share(ems, ems_len, random_pad, digest_share);
    known_x[known_n] = SLIP0039_DIGEST_INDEX;
    memcpy(known_y + known_n * ems_len, digest_share, ems_len);
    ++known_n;

    /* Secret share at x = 255. */
    known_x[known_n] = SLIP0039_SECRET_INDEX;
    memcpy(known_y + known_n * ems_len, ems, ems_len);
    ++known_n;

    /* Interpolate remaining user shares for x = T-2 .. share_count-1. */
    for (uint8_t i = (uint8_t)(threshold - 2); i < share_count; ++i) {
        uint8_t y[SLIP0039_MAX_SECRET_BYTES];
        if (gf256_lagrange(i, known_x, known_n, known_y, ems_len, y) != 0) {
            dogecoin_mem_zero(known_y, sizeof(known_y));
            dogecoin_mem_zero(random_pad, sizeof(random_pad));
            dogecoin_mem_zero(digest_share, sizeof(digest_share));
            return -1;
        }
        memcpy(shares_y_out + i * ems_len, y, ems_len);
        dogecoin_mem_zero(y, sizeof(y));
    }

    dogecoin_mem_zero(known_y, sizeof(known_y));
    dogecoin_mem_zero(random_pad, sizeof(random_pad));
    dogecoin_mem_zero(digest_share, sizeof(digest_share));
    return 0;
}

/**
 * @brief Combines threshold shares into EMS and verifies digest share.
 *
 * @param xs Share x-indices.
 * @param ys Concatenated share values.
 * @param n Number of input shares.
 * @param ems_len EMS length in bytes.
 * @param threshold Threshold required for reconstruction.
 * @param ems_out Output reconstructed EMS bytes.
 *
 * @return 0 on success, -1 on invalid input or verification failure.
 */
static int slip0039_combine(const uint8_t* xs, const uint8_t* ys,
                            size_t n, size_t ems_len, uint8_t threshold,
                            uint8_t* ems_out)
{
    if (n != threshold) return -1;
    if (threshold == 1) {
        memcpy(ems_out, ys, ems_len);
        return 0;
    }

    /* Recover secret at x=255. */
    if (gf256_lagrange(SLIP0039_SECRET_INDEX, xs, n, ys, ems_len, ems_out) != 0) return -1;

    /* Recover digest share at x=254 and verify. */
    uint8_t digest_share[SLIP0039_MAX_SECRET_BYTES];
    if (gf256_lagrange(SLIP0039_DIGEST_INDEX, xs, n, ys, ems_len, digest_share) != 0) {
        dogecoin_mem_zero(digest_share, sizeof(digest_share));
        return -1;
    }
    int ok = slip0039_verify_digest_share(ems_out, ems_len, digest_share);
    dogecoin_mem_zero(digest_share, sizeof(digest_share));
    if (ok != 0) return -1;
    return 0;
}

/**
 * @brief Generates SLIP-0039 mnemonic shares for a master secret.
 *
 * @param secret Master secret bytes.
 * @param secret_len Master secret length in bytes.
 * @param threshold Share threshold required for recovery.
 * @param share_count Number of shares to generate.
 * @param shares Output share strings.
 *
 * @return 0 on success, -1 on invalid input or generation failure.
 */
int dogecoin_slip0039_generate_shares(const uint8_t* secret, size_t secret_len,
                                      uint8_t threshold, uint8_t share_count,
                                      char shares[][SLIP0039_MAX_SHARE_STR_SIZE])
{
    if (!secret || !shares) return -1;
    if (secret_len < SLIP0039_MIN_SECRET_BYTES ||
        secret_len > SLIP0039_MAX_SECRET_BYTES ||
        (secret_len & 1)) {
        return -1;
    }
    if (threshold < 1 || share_count < threshold || share_count > SLIP0039_MAX_SHARES) {
        return -1;
    }

    /* Pick a random 15-bit identifier. */
    uint8_t id_bytes[2];
    if (!dogecoin_random_bytes(id_bytes, sizeof(id_bytes), 0)) return -1;
    uint16_t identifier = (uint16_t)((((uint16_t)id_bytes[0] << 8) | id_bytes[1]) & 0x7FFFU);
    uint8_t  iter_exp = SLIP0039_DEFAULT_ITER_EXP;

    /* Encrypt master secret to EMS. */
    uint8_t ems[SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_encrypt(secret, secret_len, NULL, 0, identifier, iter_exp, 0 /* non-extendable */, ems) != 0) {
        return -1;
    }

    /* Shamir split EMS into share values. */
    uint8_t share_y[SLIP0039_MAX_SHARES * SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_split(ems, secret_len, threshold, share_count, share_y) != 0) {
        dogecoin_mem_zero(ems, sizeof(ems));
        dogecoin_mem_zero(share_y, sizeof(share_y));
        return -1;
    }

    /* Encode each share as a mnemonic. */
    for (uint8_t i = 0; i < share_count; ++i) {
        if (slip0039_encode_mnemonic(identifier, iter_exp,
                                     0 /* GI */, 1 /* Gt */, 1 /* g */,
                                     i /* I */, threshold /* t */,
                                     share_y + (size_t)i * secret_len, secret_len,
                                     shares[i], SLIP0039_MAX_SHARE_STR_SIZE) != 0) {
            dogecoin_mem_zero(ems, sizeof(ems));
            dogecoin_mem_zero(share_y, sizeof(share_y));
            return -1;
        }
    }

    dogecoin_mem_zero(ems, sizeof(ems));
    dogecoin_mem_zero(share_y, sizeof(share_y));
    return 0;
}

/**
 * @brief Recovers a master secret from SLIP-0039 mnemonic shares.
 *
 * @param shares Input share strings.
 * @param share_count Number of provided shares.
 * @param passphrase Optional passphrase bytes.
 * @param passphrase_len Passphrase length in bytes.
 * @param secret_out Output recovered secret bytes.
 * @param secret_len_out In/out length of secret_out.
 *
 * @return 0 on success, -1 on invalid input or recovery failure.
 */
int dogecoin_slip0039_recover_secret(const char* shares[], size_t share_count,
                                     const uint8_t* passphrase, size_t passphrase_len,
                                     uint8_t* secret_out, size_t* secret_len_out)
{
    if (!shares || !share_count || !secret_out || !secret_len_out) return -1;
    /* At most gc(16) * mc(16) = 256 shares total. */
    if (share_count > (size_t)SLIP0039_MAX_SHARES * SLIP0039_MAX_SHARES) return -1;

    /* Common parameters (must match across all shares). */
    uint16_t common_id   = 0;
    uint8_t  common_ext  = 0;
    uint8_t  common_iter = 0;
    uint8_t  common_gt   = 0;  /* group threshold */
    uint8_t  common_gc   = 0;  /* group count */
    size_t   common_len  = 0;
    int      have_common = 0;
    int      rc          = -1;

    /* Per-group state, indexed by group_idx (0..15). */
    typedef struct {
        uint8_t  member_thr;
        uint8_t  member_count;
        uint8_t  xs[SLIP0039_MAX_SHARES];
        uint8_t  ys[SLIP0039_MAX_SHARES * SLIP0039_MAX_SECRET_BYTES];
        uint8_t  used_mi[SLIP0039_MAX_SHARES]; /* duplicate detection */
        int      present;
    } group_slot_t;
    group_slot_t groups[SLIP0039_MAX_SHARES];
    memset(groups, 0, sizeof(groups));

    /* Group-level Shamir coordinates, populated after member combine. */
    uint8_t group_xs[SLIP0039_MAX_SHARES];
    uint8_t group_ys[SLIP0039_MAX_SHARES * SLIP0039_MAX_SECRET_BYTES];
    memset(group_xs, 0, sizeof(group_xs));
    memset(group_ys, 0, sizeof(group_ys));

    /* --- Step 1: Parse and group all shares. --- */
    for (size_t i = 0; i < share_count; ++i) {
        if (!shares[i]) goto cleanup;

        uint16_t id;
        uint8_t  ext, iter, gi, gt, gc, mi, mt;
        uint8_t  value[SLIP0039_MAX_SECRET_BYTES];
        size_t   vlen = sizeof(value);

        if (slip0039_decode_mnemonic(shares[i], &id, &ext, &iter, &gi, &gt, &gc,
                                     &mi, &mt, value, &vlen) != 0) {
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }

        /* Establish or verify common parameters. */
        if (!have_common) {
            common_id   = id;
            common_ext  = ext;
            common_iter = iter;
            common_gt   = gt;
            common_gc   = gc;
            common_len  = vlen;
            have_common = 1;
        } else if (id != common_id || ext != common_ext || iter != common_iter ||
                   gt != common_gt || gc != common_gc || vlen != common_len) {
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }

        if (gi >= SLIP0039_MAX_SHARES) {
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }

        group_slot_t* g = &groups[gi];
        if (!g->present) {
            g->present      = 1;
            g->member_thr   = mt;
            g->member_count = 0;
        } else if (g->member_thr != mt) {
            /* Conflicting member thresholds within the same group. */
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }

        if (mi >= SLIP0039_MAX_SHARES || g->used_mi[mi]) {
            /* Duplicate or out-of-range member index. */
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }

        uint8_t slot = g->member_count;
        if (slot >= SLIP0039_MAX_SHARES) {
            dogecoin_mem_zero(value, sizeof(value));
            goto cleanup;
        }
        g->xs[slot] = mi;
        memcpy(g->ys + (size_t)slot * common_len, value, common_len);
        g->used_mi[mi] = 1;
        g->member_count++;

        dogecoin_mem_zero(value, sizeof(value));
    }

    if (!have_common) goto cleanup;

    /* --- Step 2: For each complete group, combine member shares. --- */
    uint8_t n_complete = 0;
    for (uint8_t gi = 0; gi < common_gc && n_complete < common_gt; ++gi) {
        group_slot_t* g = &groups[gi];
        if (!g->present || g->member_count < g->member_thr) continue;

        uint8_t group_share[SLIP0039_MAX_SECRET_BYTES];
        if (slip0039_combine(g->xs, g->ys, g->member_thr, common_len,
                             g->member_thr, group_share) != 0) {
            dogecoin_mem_zero(group_share, sizeof(group_share));
            goto cleanup;
        }

        group_xs[n_complete] = gi;
        memcpy(group_ys + (size_t)n_complete * common_len, group_share, common_len);
        ++n_complete;

        dogecoin_mem_zero(group_share, sizeof(group_share));
    }

    if (n_complete < common_gt) goto cleanup;

    /* --- Step 3: Group-level combine to recover master EMS. --- */
    uint8_t master_ems[SLIP0039_MAX_SECRET_BYTES];
    if (slip0039_combine(group_xs, group_ys, common_gt, common_len,
                         common_gt, master_ems) != 0) {
        dogecoin_mem_zero(master_ems, sizeof(master_ems));
        goto cleanup;
    }

    /* --- Step 4: Decrypt master EMS to recover the master secret. --- */
    if (*secret_len_out < common_len) {
        dogecoin_mem_zero(master_ems, sizeof(master_ems));
        goto cleanup;
    }

    if (slip0039_decrypt(master_ems, common_len, passphrase, passphrase_len,
                         common_id, common_iter, common_ext, secret_out) != 0) {
        dogecoin_mem_zero(master_ems, sizeof(master_ems));
        goto cleanup;
    }
    *secret_len_out = common_len;
    rc = 0;

    dogecoin_mem_zero(master_ems, sizeof(master_ems));

cleanup:
    dogecoin_mem_zero(groups, sizeof(groups));
    dogecoin_mem_zero(group_ys, sizeof(group_ys));
    return rc;
}
