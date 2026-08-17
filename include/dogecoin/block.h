/*

 The MIT License (MIT)

 Copyright (c) 2016 Thomas Kerin
 Copyright (c) 2016 libbtc developers
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 edtubbs
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

#ifndef __LIBDOGECOIN_BLOCK_H__
#define __LIBDOGECOIN_BLOCK_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/arith_uint256.h>

LIBDOGECOIN_BEGIN_DECL

#include <dogecoin/buffer.h>
#include <dogecoin/cstr.h>
#include <dogecoin/hash.h>
#include <dogecoin/map.h>
#include <dogecoin/tx.h>

typedef struct _auxpow {
    dogecoin_bool is;
    dogecoin_bool (*check)(void* ctx, uint256_t* hash, uint32_t chainid, dogecoin_chainparams* params);
    void *ctx;
} auxpow;

/* The AuxPoW proof carried by a merge-mined header, owned by the header it
   belongs to.
 *
 * This deliberately has no back-pointer to its owning header, unlike
 * dogecoin_auxpow_block. That struct owns both its header and its parent_header
 * and frees them, so a header could not hold one without the two owning each
 * other. The payload owns only parent_header, which is a plain 80-byte header
 * with no payload of its own, so ownership terminates.
 *
 * The auxpow.check / auxpow.ctx hook on dogecoin_block_header is unaffected:
 * it is a validation hook whose context the caller supplies at call time, not a
 * reference to this data. */
typedef struct dogecoin_auxpow_payload_ {
    dogecoin_tx* parent_coinbase;
    uint256_t parent_hash;
    uint8_t parent_merkle_count;
    uint256_t* parent_coinbase_merkle;
    uint32_t parent_merkle_index;
    uint8_t aux_merkle_count;
    uint256_t* aux_merkle_branch;
    uint32_t aux_merkle_index;
    struct dogecoin_block_header_* parent_header;
} dogecoin_auxpow_payload;

typedef struct dogecoin_block_header_ {
    int32_t version;
    uint256_t prev_block;
    uint256_t merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    auxpow auxpow[1];
    /** AuxPoW proof for a merge-mined header, NULL otherwise. Retained so the
        header can reproduce the bytes it was parsed from: the deserializer used
        to parse this into a local dogecoin_auxpow_block and free it, and
        dogecoin_block_header_copy carried only the auxpow hook fields, so the
        proof was discarded and anything needing it had to re-parse. */
    dogecoin_auxpow_payload* auxpow_payload;
} dogecoin_block_header;

/** Free an AuxPoW payload and everything it owns. */
LIBDOGECOIN_API void dogecoin_auxpow_payload_free(dogecoin_auxpow_payload* payload);

/** Deep-copy an AuxPoW payload. Returns NULL if src is NULL. */
LIBDOGECOIN_API dogecoin_auxpow_payload* dogecoin_auxpow_payload_copy(const dogecoin_auxpow_payload* src);

typedef struct dogecoin_auxpow_block_ {
    dogecoin_block_header* header;
    dogecoin_tx* parent_coinbase;
    uint256_t parent_hash;
    uint8_t parent_merkle_count;
    uint256_t* parent_coinbase_merkle;
    uint32_t parent_merkle_index;
    uint8_t aux_merkle_count;
    uint256_t* aux_merkle_branch;
    uint32_t aux_merkle_index;
    dogecoin_block_header* parent_header;
} dogecoin_auxpow_block;

LIBDOGECOIN_API dogecoin_block_header* dogecoin_block_header_new();
/**
 * @brief Release what a header owns, without freeing the header.
 *
 * dogecoin_block_header_free ends in dogecoin_free(header), so it cannot be used
 * on a header that is embedded by value in another struct -- and two of them are:
 * dogecoin_blockindex holds one, and dogecoin_compact_block holds one. Since a
 * parsed header now owns an auxpow_payload (a transaction plus two heap arrays),
 * those owners have to release it explicitly or leak it on every merge-mined
 * block. This is the entry point for that.
 *
 * Idempotent: the payload pointer is nulled, so a second call is a no-op.
 */
LIBDOGECOIN_API void dogecoin_block_header_destroy(dogecoin_block_header* header);

LIBDOGECOIN_API void dogecoin_block_header_free(dogecoin_block_header* header);
LIBDOGECOIN_API dogecoin_auxpow_block* dogecoin_auxpow_block_new();
LIBDOGECOIN_API void dogecoin_auxpow_block_free(dogecoin_auxpow_block* block);
/** Parse a block header off the wire without validating it.
 *
 * Reads the 80 base fields and, when version bit 0x100 is set, the AuxPoW
 * proof, which is retained on the header. Runs no proof-of-work check.
 *
 * check_auxpow is scrypt work over the parent chain. Doing it during parsing
 * means every caller pays for it whether or not it wants the answer yet, and
 * before any peer-level gating has happened. Callers that want the fields and
 * will decide about validation later use this; callers that want the existing
 * parse-and-validate behaviour keep using dogecoin_block_header_deserialize.
 */
LIBDOGECOIN_API int dogecoin_block_header_parse(dogecoin_block_header* header, struct const_buffer* buf, const dogecoin_chainparams *params);

/** Validate a parsed header's AuxPoW and fill @p chainwork.
 *
 * Returns true immediately for a header with no AuxPoW: its proof of work is
 * over the 80 base bytes and is the caller's to verify. Requires the header to
 * still own its proof, so it must have come from dogecoin_block_header_parse
 * or dogecoin_block_header_deserialize.
 */
LIBDOGECOIN_API int dogecoin_block_header_validate(dogecoin_block_header* header, const dogecoin_chainparams *params, arith_uint256* chainwork);

/** Parse and validate. Unchanged in behaviour and signature: this is
 *  dogecoin_block_header_parse followed by dogecoin_block_header_validate.
 *
 *  Deliberately kept as the name that validates. Making this the pure parse and
 *  adding a checked variant would silently stop verifying proof of work for any
 *  caller of the existing name, with no compile error to catch it.
 */
LIBDOGECOIN_API int dogecoin_block_header_deserialize(dogecoin_block_header* header, struct const_buffer* buf, const dogecoin_chainparams *params, arith_uint256* chainwork);
LIBDOGECOIN_API int deserialize_dogecoin_auxpow_block(dogecoin_auxpow_block* block, struct const_buffer* buffer, const dogecoin_chainparams *params, arith_uint256* chainwork);
/** Serialize the 80 base header fields. This is the pure header: it never
 *  emits AuxPoW, because its output is what the block hash, the scrypt proof of
 *  work and the fixed-width headers.db record are computed over. */
LIBDOGECOIN_API void dogecoin_block_header_serialize(cstring* s, const dogecoin_block_header* header);

/** Serialize an AuxPoW proof in wire order. */
LIBDOGECOIN_API void dogecoin_auxpow_payload_serialize(cstring* s, const dogecoin_auxpow_payload* payload);

/** Compute a merkle root over pre-hashed leaves.
 *
 *  @param mutated_out set true when the tree contains a duplicated subtree.
 *         A block whose merkle tree is mutated must be rejected: two different
 *         transaction lists can otherwise produce the same root (CVE-2012-2459).
 *         Callers that ignore this flag are accepting mutated blocks.
 */
LIBDOGECOIN_API void dogecoin_compute_merkle_root(const uint256_t* leaves, size_t leaf_count, uint256_t root_out, dogecoin_bool* mutated_out);

/** Compute the merkle root of a transaction vector. Hashes each transaction and
 *  reduces. Returns false on allocation failure or a NULL entry. */
LIBDOGECOIN_API dogecoin_bool dogecoin_block_merkle_root(dogecoin_tx** txs, size_t txs_count, uint256_t root_out, dogecoin_bool* mutated_out);

/** Serialize a whole block: the header in wire form, then the transaction
 *  vector.
 *
 *  This is what a `block` message contains, and what code expecting a block off
 *  the network parses. A compact block that has been reconstructed has a header
 *  and a set of transactions but no wire bytes; this is how it becomes something
 *  the rest of the client can consume.
 *
 *  Stops rather than emitting a short block if @p txs contains a NULL, since a
 *  vector with a hole in it is a reconstruction that did not finish.
 */
LIBDOGECOIN_API void dogecoin_block_serialize(cstring* s, const dogecoin_block_header* header, dogecoin_tx** txs, uint32_t txs_count);

/** Serialize a header as it appears on the wire: the 80 base bytes, followed by
 *  the AuxPoW proof when the header carries one.
 *
 *  This is Core's CBlockHeader to dogecoin_block_header_serialize's
 *  CPureBlockHeader. Messages that carry a whole header -- headers, block,
 *  cmpctblock -- want this one; anything hashing the header wants the pure form.
 */
LIBDOGECOIN_API void dogecoin_block_header_serialize_full(cstring* s, const dogecoin_block_header* header);
LIBDOGECOIN_API void dogecoin_block_header_copy(dogecoin_block_header* dest, const dogecoin_block_header* src);
LIBDOGECOIN_API dogecoin_bool dogecoin_block_header_hash(dogecoin_block_header* header, uint256_t hash);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BLOCK_H__
