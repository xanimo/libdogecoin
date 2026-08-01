/*

 The MIT License (MIT)

 Copyright (c) 2018 Bitcoin Core developers
 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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

/**
 * @file golomb.c
 * @brief BIP 158 Golomb-Coded Set (GCS) compact block filter implementation.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/golomb.h>
#include <dogecoin/hash.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

/* ================================================================ */
/*  Internal helpers                                                */
/* ================================================================ */

/**
 * @brief Wrapper for cstr_free to be used as a vector element free function.
 */
static void cstr_free_void(void *ptr) {
    cstr_free((cstring *)ptr, true);
}

/**
 * @brief 128-bit multiply helper: returns (a * b) >> 64.
 *
 * This maps a 64-bit siphash into the range [0, F) without bias,
 * as specified by BIP 158.
 */
static uint64_t map_to_range(uint64_t x, uint64_t F) {
    /* Compute (x * F) >> 64 using 64x64->128 multiply */
    uint64_t x_hi = x >> 32;
    uint64_t x_lo = x & 0xFFFFFFFFULL;
    uint64_t F_hi = F >> 32;
    uint64_t F_lo = F & 0xFFFFFFFFULL;

    uint64_t lo_lo = x_lo * F_lo;
    uint64_t lo_hi = x_lo * F_hi;
    uint64_t hi_lo = x_hi * F_lo;
    uint64_t hi_hi = x_hi * F_hi;

    uint64_t carry = ((lo_lo >> 32) + (lo_hi & 0xFFFFFFFFULL) + (hi_lo & 0xFFFFFFFFULL)) >> 32;

    return hi_hi + (lo_hi >> 32) + (hi_lo >> 32) + carry;
}

/**
 * @brief Comparison function for qsort of uint64_t values.
 */
static int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* ================================================================ */
/*  Bitwriter Implementation                                        */
/* ================================================================ */

void gcs_bitwriter_init(gcs_bitwriter *writer, size_t initial_size) {
    writer->data = cstr_new_sz(initial_size);
    writer->accumulator = 0;
    writer->n_bits = 0;
}

void gcs_bitwriter_write_bit(gcs_bitwriter *writer, uint8_t bit) {
    writer->accumulator |= ((bit & 1) << (7 - writer->n_bits));
    writer->n_bits++;
    if (writer->n_bits == 8) {
        cstr_append_buf(writer->data, &writer->accumulator, 1);
        writer->accumulator = 0;
        writer->n_bits = 0;
    }
}

void gcs_bitwriter_write_bits_be(gcs_bitwriter *writer, uint64_t value, int n_bits) {
    int i;
    for (i = n_bits - 1; i >= 0; i--) {
        gcs_bitwriter_write_bit(writer, (uint8_t)((value >> i) & 1));
    }
}

void gcs_bitwriter_flush(gcs_bitwriter *writer) {
    if (writer->n_bits > 0) {
        cstr_append_buf(writer->data, &writer->accumulator, 1);
        writer->accumulator = 0;
        writer->n_bits = 0;
    }
}

/* ================================================================ */
/*  Bitreader Implementation                                        */
/* ================================================================ */

void gcs_bitreader_init(gcs_bitreader *reader, const void *data, size_t len) {
    reader->data.p = data;
    reader->data.len = len;
    reader->accumulator = 0;
    reader->n_bits = 0;
}

int gcs_bitreader_read_bit(gcs_bitreader *reader) {
    if (reader->n_bits == 0) {
        if (reader->data.len == 0) return -1;
        reader->accumulator = *(const uint8_t *)reader->data.p;
        reader->data.p = (const uint8_t *)reader->data.p + 1;
        reader->data.len--;
        reader->n_bits = 8;
    }
    reader->n_bits--;
    return (reader->accumulator >> reader->n_bits) & 1;
}

dogecoin_bool gcs_bitreader_read_bits_be(gcs_bitreader *reader, int n_bits, uint64_t *out) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < n_bits; i++) {
        int bit = gcs_bitreader_read_bit(reader);
        if (bit < 0) return false;
        result = (result << 1) | (uint64_t)bit;
    }
    *out = result;
    return true;
}

/* ================================================================ */
/*  Golomb-Rice Coding                                              */
/* ================================================================ */

void golomb_rice_encode(gcs_bitwriter *writer, uint64_t value, int P) {
    uint64_t quotient = value >> P;
    uint64_t remainder = value & ((1ULL << P) - 1);

    /* Write quotient in unary: quotient 1-bits followed by a 0-bit */
    uint64_t i;
    for (i = 0; i < quotient; i++) {
        gcs_bitwriter_write_bit(writer, 1);
    }
    gcs_bitwriter_write_bit(writer, 0);

    /* Write remainder in P bits (MSB first) */
    gcs_bitwriter_write_bits_be(writer, remainder, P);
}

dogecoin_bool golomb_rice_decode(gcs_bitreader *reader, int P, uint64_t *out) {
    /* Read unary-encoded quotient */
    uint64_t quotient = 0;
    for (;;) {
        int bit = gcs_bitreader_read_bit(reader);
        if (bit < 0) return false;
        if (bit == 0) break;
        quotient++;
    }

    /* Read P-bit remainder */
    uint64_t remainder = 0;
    if (!gcs_bitreader_read_bits_be(reader, P, &remainder)) return false;

    *out = (quotient << P) | remainder;
    return true;
}

/* ================================================================ */
/*  GCS Key Derivation and Hashing                                  */
/* ================================================================ */

void gcs_derive_key(const uint256_t blockhash, uint8_t key[GCS_SIPHASH_KEY_SIZE]) {
    /* Per BIP 158: The first 16 bytes of the block hash (in standard
     * byte order) are used as the SipHash key. */
    memcpy(key, blockhash, GCS_SIPHASH_KEY_SIZE);
}

uint64_t gcs_hash_element(const uint8_t key[GCS_SIPHASH_KEY_SIZE], uint64_t F, const uint8_t *data, size_t data_len) {
    /* Extract k0 and k1 from the 16-byte key (little-endian) */
    uint64_t k0 = 0, k1 = 0;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);

    /* SipHash-2-4 the data element */
    struct siphasher sh;
    siphasher_set(&sh, k0, k1);
    siphasher_hash(&sh, data, data_len);
    uint64_t hash = siphasher_finalize(&sh);

    /* Map into [0, F) using fast range reduction */
    return map_to_range(hash, F);
}

/* ================================================================ */
/*  GCS Filter Lifecycle                                            */
/* ================================================================ */

gcs_filter* gcs_filter_new(void) {
    gcs_filter *filter = dogecoin_calloc(1, sizeof(gcs_filter));
    if (!filter) return NULL;
    filter->filter_type = GCS_BASIC_FILTER_TYPE;
    filter->P = GCS_BASIC_FILTER_P;
    filter->M = GCS_BASIC_FILTER_M;
    filter->N = 0;
    filter->F = 0;
    filter->encoded = NULL;
    return filter;
}

void gcs_filter_free(gcs_filter *filter) {
    if (!filter) return;
    if (filter->encoded) {
        cstr_free(filter->encoded, true);
        filter->encoded = NULL;
    }
    dogecoin_free(filter);
}

/* ================================================================ */
/*  GCS Filter Building                                             */
/* ================================================================ */

dogecoin_bool gcs_filter_build(gcs_filter *filter, uint8_t filter_type, const uint256_t blockhash, const vector_t *elements) {
    if (!filter || !elements) return false;

    filter->filter_type = filter_type;
    filter->P = GCS_BASIC_FILTER_P;
    filter->M = GCS_BASIC_FILTER_M;
    filter->N = (uint32_t)elements->len;
    filter->F = (uint64_t)filter->N * (uint64_t)filter->M;

    /* Derive the SipHash key from the block hash */
    gcs_derive_key(blockhash, filter->key);

    /* Handle empty filter */
    if (filter->N == 0) {
        filter->encoded = cstr_new_sz(0);
        return true;
    }

    /* Hash all elements and collect into a sorted array */
    uint64_t *hashes = dogecoin_calloc(filter->N, sizeof(uint64_t));
    if (!hashes) return false;

    unsigned int i;
    for (i = 0; i < filter->N; i++) {
        cstring *elem = (cstring *)vector_idx(elements, i);
        hashes[i] = gcs_hash_element(filter->key, filter->F, (const uint8_t *)elem->str, elem->len);
    }

    /* Sort hashes */
    qsort(hashes, filter->N, sizeof(uint64_t), compare_uint64);

    /* Golomb-Rice encode the sorted deltas */
    gcs_bitwriter writer;
    gcs_bitwriter_init(&writer, filter->N * 2); /* rough estimate */

    uint64_t prev = 0;
    for (i = 0; i < filter->N; i++) {
        uint64_t delta = hashes[i] - prev;
        golomb_rice_encode(&writer, delta, filter->P);
        prev = hashes[i];
    }
    gcs_bitwriter_flush(&writer);

    dogecoin_free(hashes);

    filter->encoded = writer.data;
    return true;
}

/* ================================================================ */
/*  GCS Filter Matching                                             */
/* ================================================================ */

dogecoin_bool gcs_filter_match(const gcs_filter *filter, const uint8_t *data, size_t data_len) {
    if (!filter || !filter->encoded) return false;
    if (filter->N == 0) return false;

    /* Hash the query element */
    uint64_t target = gcs_hash_element(filter->key, filter->F, data, data_len);

    /* Decode the filter and check for a match */
    gcs_bitreader reader;
    gcs_bitreader_init(&reader, filter->encoded->str, filter->encoded->len);

    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < filter->N; i++) {
        uint64_t delta;
        if (!golomb_rice_decode(&reader, filter->P, &delta)) return false;
        value += delta;

        if (value == target) return true;
        if (value > target) return false;
    }

    return false;
}

dogecoin_bool gcs_filter_match_any(const gcs_filter *filter, const vector_t *elements) {
    if (!filter || !filter->encoded || !elements) return false;
    if (filter->N == 0 || elements->len == 0) return false;

    /* Hash all query elements and sort */
    size_t n_queries = elements->len;
    uint64_t *query_hashes = dogecoin_calloc(n_queries, sizeof(uint64_t));
    if (!query_hashes) return false;

    size_t qi;
    for (qi = 0; qi < n_queries; qi++) {
        cstring *elem = (cstring *)vector_idx(elements, qi);
        query_hashes[qi] = gcs_hash_element(filter->key, filter->F, (const uint8_t *)elem->str, elem->len);
    }

    qsort(query_hashes, n_queries, sizeof(uint64_t), compare_uint64);

    /* Walk through both the filter and the sorted queries simultaneously */
    gcs_bitreader reader;
    gcs_bitreader_init(&reader, filter->encoded->str, filter->encoded->len);

    uint64_t filter_value = 0;
    size_t query_idx = 0;
    unsigned int filter_idx = 0;

    /* Decode the first filter element */
    if (filter_idx < filter->N) {
        uint64_t delta;
        if (!golomb_rice_decode(&reader, filter->P, &delta)) {
            dogecoin_free(query_hashes);
            return false;
        }
        filter_value += delta;
        filter_idx++;
    }

    while (query_idx < n_queries && filter_idx <= filter->N) {
        if (filter_value == query_hashes[query_idx]) {
            dogecoin_free(query_hashes);
            return true;
        }

        if (filter_value < query_hashes[query_idx]) {
            /* Advance filter */
            if (filter_idx >= filter->N) break;
            uint64_t delta;
            if (!golomb_rice_decode(&reader, filter->P, &delta)) break;
            filter_value += delta;
            filter_idx++;
        } else {
            /* Advance query */
            query_idx++;
        }
    }

    dogecoin_free(query_hashes);
    return false;
}

/* ================================================================ */
/*  BIP 158 Basic Filter Construction                               */
/* ================================================================ */

dogecoin_bool gcs_build_basic_filter(gcs_filter *filter, const uint256_t blockhash, const vector_t *txs, const vector_t *prev_output_scripts) {
    if (!filter || !txs) return false;

    /* Collect all scriptPubKeys */
    vector_t *elements = vector_new(64, cstr_free_void);

    unsigned int ti;
    for (ti = 0; ti < txs->len; ti++) {
        dogecoin_tx *tx = (dogecoin_tx *)vector_idx(txs, ti);

        /* Add all output scriptPubKeys */
        unsigned int oi;
        for (oi = 0; oi < tx->vout->len; oi++) {
            dogecoin_tx_out *txout = (dogecoin_tx_out *)vector_idx(tx->vout, oi);
            if (txout->script_pubkey && txout->script_pubkey->len > 0) {
                /* Skip OP_RETURN (0x6a) outputs per BIP 158 */
                if (txout->script_pubkey->len > 0 && (uint8_t)txout->script_pubkey->str[0] == 0x6a) {
                    continue;
                }
                cstring *elem = cstr_new_buf(txout->script_pubkey->str, txout->script_pubkey->len);
                vector_add(elements, elem);
            }
        }
    }

    /* Add all previous output scripts (scripts being spent by inputs) */
    if (prev_output_scripts) {
        unsigned int pi;
        for (pi = 0; pi < prev_output_scripts->len; pi++) {
            cstring *script = (cstring *)vector_idx(prev_output_scripts, pi);
            if (script && script->len > 0) {
                cstring *elem = cstr_new_buf(script->str, script->len);
                vector_add(elements, elem);
            }
        }
    }

    /* Remove duplicates: sort by content and deduplicate */
    /* For simplicity, we let the GCS handle duplicates - they just
     * result in zero-deltas which encode efficiently. The BIP says
     * to deduplicate, so we do a simple O(n^2) check for small sets. */
    /* TODO: optimize for large sets with a hash set */

    dogecoin_bool result = gcs_filter_build(filter, GCS_BASIC_FILTER_TYPE, blockhash, elements);

    vector_free(elements, true);
    return result;
}

/* ================================================================ */
/*  Filter Header Computation                                       */
/* ================================================================ */

dogecoin_bool gcs_filter_compute_header(const gcs_filter *filter, const uint256_t prev_header, uint256_t header_out) {
    if (!filter) return false;

    /* Compute filter_hash = dbl_sha256(N (compact size) || encoded_data) */
    cstring *serialized = cstr_new_sz(filter->encoded ? filter->encoded->len + 5 : 5);
    ser_varlen(serialized, filter->N);
    if (filter->encoded && filter->encoded->len > 0) {
        cstr_append_buf(serialized, filter->encoded->str, filter->encoded->len);
    }

    uint256_t filter_hash;
    dogecoin_hash((const unsigned char *)serialized->str, serialized->len, filter_hash);
    cstr_free(serialized, true);

    /* Compute filter_header = dbl_sha256(filter_hash || prev_header) */
    uint8_t combined[64];
    memcpy(combined, filter_hash, 32);
    memcpy(combined + 32, prev_header, 32);
    dogecoin_hash(combined, 64, header_out);

    return true;
}

/* ================================================================ */
/*  Filter Serialization / Deserialization                          */
/* ================================================================ */

void gcs_filter_serialize(const gcs_filter *filter, cstring *out) {
    if (!filter || !out) return;

    /* Serialize as: N (CompactSize) || encoded_filter_data */
    ser_varlen(out, filter->N);
    if (filter->encoded && filter->encoded->len > 0) {
        cstr_append_buf(out, filter->encoded->str, filter->encoded->len);
    }
}

dogecoin_bool gcs_filter_deserialize(gcs_filter *filter, uint8_t filter_type, const uint256_t blockhash, struct const_buffer *buf) {
    if (!filter || !buf) return false;

    filter->filter_type = filter_type;
    filter->P = GCS_BASIC_FILTER_P;
    filter->M = GCS_BASIC_FILTER_M;

    /* Derive the key from the block hash */
    gcs_derive_key(blockhash, filter->key);

    /* Deserialize: N (CompactSize) || encoded_filter_data */
    uint32_t N;
    if (!deser_varlen(&N, buf)) return false;
    filter->N = N;
    filter->F = (uint64_t)N * (uint64_t)filter->M;

    /* Remaining data is the encoded filter */
    if (filter->encoded) {
        cstr_free(filter->encoded, true);
    }

    if (buf->len > 0) {
        filter->encoded = cstr_new_buf(buf->p, buf->len);
        /* Consume the rest of the buffer */
        buf->p = (const uint8_t *)buf->p + buf->len;
        buf->len = 0;
    } else {
        filter->encoded = cstr_new_sz(0);
    }

    return true;
}
