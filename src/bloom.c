/*

 The MIT License (MIT)

 Copyright (c) 2012-2015 The Bitcoin Core developers
 Copyright (c) 2024 bluezr
 Copyright (c) 2024 The Dogecoin Foundation

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
 * @file bloom.c
 * @brief BIP37 Bloom filter implementation.
 *
 * Implements:
 * - MurmurHash3 x86 32-bit
 * - Bloom filter creation with optimal BIP37 parameters
 * - Insert / contains / tx-matching
 * - Serialization (BIP37 wire format)
 * - P2P message construction (filterload, filteradd, filterclear)
 */

#include <math.h>
#include <string.h>

#include <dogecoin/bloom.h>
#include <dogecoin/hash.h>
#include <dogecoin/mem.h>
#include <dogecoin/protocol.h>
#include <dogecoin/script.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

/* Natural-log constants for optimal filter sizing */
static const double LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
static const double LN2        = 0.6931471805599453094172321214581765680755001343602552;

/* ================================================================ */
/*  MurmurHash3 x86 32-bit                                         */
/* ================================================================ */

/**
 * @brief MurmurHash3 x86 32-bit implementation.
 *
 * This is the hash function specified by BIP37 for computing bloom
 * filter bit positions.
 */
LIBDOGECOIN_API uint32_t murmurhash3(uint32_t seed, const uint8_t* data, size_t len)
{
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    /* body — process 4-byte blocks */
    const size_t nblocks = len / 4;
    size_t i;
    for (i = 0; i < nblocks; i++) {
        uint32_t k1;
        memcpy(&k1, data + i * 4, 4);
        k1 = le32toh(k1);

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }

    /* tail — remaining bytes */
    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= (uint32_t)tail[2] << 16; /* FALLTHROUGH */
        case 2: k1 ^= (uint32_t)tail[1] << 8;  /* FALLTHROUGH */
        case 1: k1 ^= (uint32_t)tail[0];
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    /* finalization mix */
    h1 ^= (uint32_t)len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

/* ================================================================ */
/*  Internal: compute bloom hash index for a given hash number      */
/* ================================================================ */

/**
 * @brief Compute the bit index for a given hash function number.
 *
 * Per BIP37: hash_i = MurmurHash3(i * 0xFBA4C795 + nTweak, data) % (filter_size * 8)
 */
static uint32_t dogecoin_bloom_hash(const dogecoin_bloom_filter* filter, uint32_t hash_num, const uint8_t* data, size_t len)
{
    uint32_t seed = (uint32_t)(hash_num * BLOOM_UPDATE_SEED + filter->n_tweak);
    return murmurhash3(seed, data, len) % (filter->vdata_size * 8);
}

/* ================================================================ */
/*  Bloom filter create / free                                      */
/* ================================================================ */

LIBDOGECOIN_API dogecoin_bloom_filter* dogecoin_bloom_filter_new(
    uint32_t n_elements,
    double fp_rate,
    uint32_t n_tweak,
    uint8_t n_flags)
{
    if (n_elements == 0) {
        n_elements = 1;
    }

    dogecoin_bloom_filter* filter = dogecoin_calloc(1, sizeof(dogecoin_bloom_filter));
    if (!filter) return NULL;

    /* Compute optimal filter size in bytes (BIP37 formula) */
    uint32_t filter_size = (uint32_t)(-1.0 / LN2SQUARED * (double)n_elements * log(fp_rate) / 8.0);
    if (filter_size > MAX_BLOOM_FILTER_SIZE) {
        filter_size = MAX_BLOOM_FILTER_SIZE;
    }
    if (filter_size == 0) {
        filter_size = 1;
    }

    filter->vdata_size = filter_size;
    filter->vdata = dogecoin_calloc(1, filter_size);
    if (!filter->vdata) {
        dogecoin_free(filter);
        return NULL;
    }

    /* Compute optimal number of hash functions */
    filter->n_hash_funcs = (uint32_t)((double)filter_size * 8.0 / (double)n_elements * LN2);
    if (filter->n_hash_funcs > MAX_BLOOM_FILTER_HASH_FUNCS) {
        filter->n_hash_funcs = MAX_BLOOM_FILTER_HASH_FUNCS;
    }
    if (filter->n_hash_funcs == 0) {
        filter->n_hash_funcs = 1;
    }

    filter->n_tweak = n_tweak;
    filter->n_flags = n_flags;
    filter->is_full = false;
    filter->is_empty = true;

    return filter;
}

LIBDOGECOIN_API void dogecoin_bloom_filter_free(dogecoin_bloom_filter* filter)
{
    if (!filter) return;
    if (filter->vdata) {
        dogecoin_free(filter->vdata);
        filter->vdata = NULL;
    }
    dogecoin_free(filter);
}

/* ================================================================ */
/*  Insert / Contains                                               */
/* ================================================================ */

LIBDOGECOIN_API void dogecoin_bloom_filter_insert(dogecoin_bloom_filter* filter, const uint8_t* data, size_t len)
{
    if (!filter || filter->is_full || !data || len == 0) return;

    uint32_t i;
    for (i = 0; i < filter->n_hash_funcs; i++) {
        uint32_t idx = dogecoin_bloom_hash(filter, i, data, len);
        /* set bit idx in the filter */
        filter->vdata[idx >> 3] |= (1 << (7 & idx));
    }
    filter->is_empty = false;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_bloom_filter_contains(const dogecoin_bloom_filter* filter, const uint8_t* data, size_t len)
{
    if (!filter || !data || len == 0) return false;
    if (filter->is_full) return true;
    if (filter->is_empty) return false;

    uint32_t i;
    for (i = 0; i < filter->n_hash_funcs; i++) {
        uint32_t idx = dogecoin_bloom_hash(filter, i, data, len);
        if (!(filter->vdata[idx >> 3] & (1 << (7 & idx)))) {
            return false;
        }
    }
    return true;
}

/* ================================================================ */
/*  BIP37 transaction matching                                      */
/* ================================================================ */

LIBDOGECOIN_API dogecoin_bool dogecoin_bloom_filter_matches_tx(dogecoin_bloom_filter* filter, const dogecoin_tx* tx)
{
    if (!filter || !tx) return false;

    /* Step 1: test the transaction hash itself */
    uint256_t txhash;
    dogecoin_tx_hash(tx, txhash);
    if (dogecoin_bloom_filter_contains(filter, txhash, sizeof(txhash))) {
        return true;
    }

    dogecoin_bool found = false;
    unsigned int oi;

    /* Step 2: for each output, parse the scriptPubKey and test data pushes */
    for (oi = 0; oi < tx->vout->len; oi++) {
        dogecoin_tx_out* txout = vector_idx(tx->vout, oi);
        if (!txout || !txout->script_pubkey) continue;

        vector_t* ops = vector_new(8, dogecoin_script_op_free_cb);
        if (!dogecoin_script_get_ops(txout->script_pubkey, ops)) {
            vector_free(ops, true);
            continue;
        }

        unsigned int j;
        for (j = 0; j < ops->len; j++) {
            dogecoin_script_op* op = vector_idx(ops, j);
            if (!op || !op->data || op->datalen == 0) continue;

            if (dogecoin_bloom_filter_contains(filter, op->data, op->datalen)) {
                found = true;
                vector_free(ops, true);
                goto done_outputs;
            }
        }
        vector_free(ops, true);
    }

done_outputs:

    if (found) return true;

    /* Step 3: for each input, test the prevout and script_sig data pushes */
    unsigned int ii;
    for (ii = 0; ii < tx->vin->len; ii++) {
        dogecoin_tx_in* txin = vector_idx(tx->vin, ii);
        if (!txin) continue;

        /* Test the previous outpoint (hash + index) */
        uint8_t outpoint[36];
        memcpy(outpoint, txin->prevout.hash, 32);
        uint32_t le_n = htole32(txin->prevout.n);
        memcpy(outpoint + 32, &le_n, 4);
        if (dogecoin_bloom_filter_contains(filter, outpoint, 36)) {
            return true;
        }

        /* Test data pushes in script_sig */
        if (txin->script_sig && txin->script_sig->len > 0) {
            vector_t* ops = vector_new(8, dogecoin_script_op_free_cb);
            if (dogecoin_script_get_ops(txin->script_sig, ops)) {
                unsigned int j;
                for (j = 0; j < ops->len; j++) {
                    dogecoin_script_op* op = vector_idx(ops, j);
                    if (!op || !op->data || op->datalen == 0) continue;

                    if (dogecoin_bloom_filter_contains(filter, op->data, op->datalen)) {
                        vector_free(ops, true);
                        return true;
                    }
                }
            }
            vector_free(ops, true);
        }
    }

    return false;
}

/* ================================================================ */
/*  Serialization / Deserialization (BIP37 wire format)             */
/* ================================================================ */

LIBDOGECOIN_API void dogecoin_bloom_filter_serialize(const dogecoin_bloom_filter* filter, cstring* buf)
{
    if (!filter || !buf) return;

    ser_varlen(buf, filter->vdata_size);
    ser_bytes(buf, filter->vdata, filter->vdata_size);
    ser_u32(buf, filter->n_hash_funcs);
    ser_u32(buf, filter->n_tweak);
    ser_bytes(buf, &filter->n_flags, 1);
}

LIBDOGECOIN_API dogecoin_bloom_filter* dogecoin_bloom_filter_deserialize(struct const_buffer* buf)
{
    if (!buf) return NULL;

    dogecoin_bloom_filter* filter = dogecoin_calloc(1, sizeof(dogecoin_bloom_filter));
    if (!filter) return NULL;

    uint32_t vdata_size;
    if (!deser_varlen(&vdata_size, buf)) goto fail;
    if (vdata_size > MAX_BLOOM_FILTER_SIZE) goto fail;

    filter->vdata_size = vdata_size;
    filter->vdata = dogecoin_calloc(1, vdata_size > 0 ? vdata_size : 1);
    if (!filter->vdata) goto fail;

    if (vdata_size > 0) {
        if (!deser_bytes(filter->vdata, buf, vdata_size)) goto fail;
    }

    if (!deser_u32(&filter->n_hash_funcs, buf)) goto fail;
    if (filter->n_hash_funcs > MAX_BLOOM_FILTER_HASH_FUNCS) goto fail;

    if (!deser_u32(&filter->n_tweak, buf)) goto fail;

    uint8_t flags;
    if (!deser_bytes(&flags, buf, 1)) goto fail;
    filter->n_flags = flags;

    /* Determine full/empty state */
    filter->is_full = true;
    filter->is_empty = true;
    uint32_t i;
    for (i = 0; i < filter->vdata_size; i++) {
        if (filter->vdata[i] != 0xFF) filter->is_full = false;
        if (filter->vdata[i] != 0x00) filter->is_empty = false;
    }

    return filter;

fail:
    dogecoin_bloom_filter_free(filter);
    return NULL;
}

/* ================================================================ */
/*  P2P Message Construction                                        */
/* ================================================================ */

#ifdef WITH_NET

LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filterload(const dogecoin_bloom_filter* filter, const unsigned char netmagic[4])
{
    if (!filter || !netmagic) return NULL;

    cstring* payload = cstr_new_sz(filter->vdata_size + 16);
    dogecoin_bloom_filter_serialize(filter, payload);

    cstring* msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_FILTERLOAD, payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filteradd(const uint8_t* data, size_t len, const unsigned char netmagic[4])
{
    if (!data || len == 0 || !netmagic) return NULL;

    /* BIP37: max element size is 520 bytes */
    if (len > 520) return NULL;

    cstring* payload = cstr_new_sz(len + 8);
    ser_varlen(payload, (uint32_t)len);
    ser_bytes(payload, data, len);

    cstring* msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_FILTERADD, payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filterclear(const unsigned char netmagic[4])
{
    if (!netmagic) return NULL;

    /* filterclear has an empty payload */
    cstring* msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_FILTERCLEAR, NULL, 0);
    return msg;
}

#endif /* WITH_NET */
