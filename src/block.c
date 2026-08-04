/*

 The MIT License (MIT)

 Copyright (c) 2016 Thomas Kerin
 Copyright (c) 2016 Jonas Schnelli
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

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <dogecoin/auxpow.h>
#include <dogecoin/mem.h>
#include <dogecoin/portable_endian.h>
#include <dogecoin/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

dogecoin_bool check(void *ctx, uint256_t* hash, uint32_t chainid, dogecoin_chainparams* params) {
    dogecoin_auxpow_block* block = (dogecoin_auxpow_block*)ctx;

    if (block->parent_merkle_index != 0) {
        printf("Auxpow is not a generate\n");
        return false;
    }

    uint32_t parent_chainid = get_chainid(block->parent_header->version);
    if (params->strict_id && parent_chainid == chainid) {
        printf("Aux POW parent has our chain ID\n");
        return false;
    }

    vector_t* chain_merkle_branch = vector_new(block->aux_merkle_count, NULL);
    for (size_t p = 0; p < block->aux_merkle_count; p++) {
        vector_add(chain_merkle_branch, block->aux_merkle_branch[p]);
    }

    if (chain_merkle_branch->len > 30) {
        printf("Aux POW chain merkle branch too long\n");
        vector_free(chain_merkle_branch, true);
        return false;
    }

    // First call to check_merkle_branch for the auxiliary blockchain's merkle branch
    uint256_t* chain_merkle_root = check_merkle_branch(hash, chain_merkle_branch, block->aux_merkle_index);
    vector_free(chain_merkle_branch, true);

    // Check that there is at least one input in the parent coinbase transaction
    if (block->parent_coinbase->vin->len == 0) {
        printf("Aux POW coinbase has no inputs\n");
        dogecoin_free(chain_merkle_root);
        return false;
    }

    // Convert the root hash to a human-readable format (hex)
    unsigned char vch_roothash[64]; // Make sure it's large enough to hold the hash
    memcpy(vch_roothash, hash_to_string((uint8_t*)chain_merkle_root), 64); // Copy the data
    dogecoin_free(chain_merkle_root); // Free the computed merkle root

    // Compute the Merkle root for the parent block
    vector_t* parent_merkle_branch = vector_new(block->parent_merkle_count, NULL);
    for (size_t p = 0; p < block->parent_merkle_count; p++) {
        vector_add(parent_merkle_branch, block->parent_coinbase_merkle[p]);
    }

    // Compute the hash of the parent block's coinbase transaction
    uint256_t parent_coinbase_hash;
    dogecoin_tx_hash(block->parent_coinbase, parent_coinbase_hash);

    uint256_t* parent_merkle_root = check_merkle_branch(&parent_coinbase_hash, parent_merkle_branch, block->parent_merkle_index);
    vector_free(parent_merkle_branch, true);

    // Check that the computed Merkle root matches the parent block's Merkle root
    if (memcmp(parent_merkle_root, block->parent_header->merkle_root, sizeof(uint256_t)) != 0) {
        printf("Aux POW merkle root incorrect\n");
        dogecoin_free(parent_merkle_root);
        return false;
    }
    dogecoin_free(parent_merkle_root);

    dogecoin_tx_in *tx_in = vector_idx(block->parent_coinbase->vin, 0);
    size_t idx = 0, count = 0;
    for (; idx < tx_in->script_sig->len; idx++) {

        bool needle_found = true;
        size_t header_idx = 0;
        for (; header_idx < 4; header_idx++) {
            const char haystack_char = tx_in->script_sig->str[idx + header_idx];
            const char needle_character = pch_merged_mining_header[header_idx];

            if (haystack_char == needle_character) {
                continue;
            } else {
                needle_found = false;
                break;
            }
        }

        if (needle_found) {
            count++;
            if (strncmp((const char*)vch_roothash, utils_uint8_to_hex((uint8_t*)&tx_in->script_sig->str[idx + header_idx], 32), 32) != 0) {
                printf("vch_roothash is not after merge mining header!\n");
                return false;
            }

            uint32_t nSize;
            memcpy(&nSize, &tx_in->script_sig->str[idx + 4 + 32], 4);
            nSize = le32toh(nSize);
            const unsigned int merkleHeight = block->aux_merkle_count;
            if (nSize != (1u << merkleHeight)) {
                printf("Aux POW merkle branch size does not match parent coinbase\n");
                return false;
            }

            uint32_t nNonce;
            memcpy(&nNonce, &tx_in->script_sig->str[idx + 4 + 32 + 4], 4);
            nNonce = le32toh(nNonce);
            uint32_t expected_index = get_expected_index(nNonce, chainid, merkleHeight);
            if (block->aux_merkle_index != expected_index) {
                printf("Aux POW wrong index\n");
                return false;
            }
        }
    }

    if (count > (uint32_t)1) {
        printf("Multiple merged mining headers in coinbase\n");
        return false;
    }

    return true;
}

/**
 * @brief This function allocates a new dogecoin block header->
 *
 * @return A pointer to the new dogecoin block header object.
 */
dogecoin_block_header* dogecoin_block_header_new() {
    dogecoin_block_header* header;
    header = dogecoin_calloc(1, sizeof(*header));
    header->version = 0;
    dogecoin_mem_zero(&header->prev_block, DOGECOIN_HASH_LENGTH);
    dogecoin_mem_zero(&header->merkle_root, DOGECOIN_HASH_LENGTH);
    header->bits = 0;
    header->timestamp = 0;
    header->nonce = 0;
    header->auxpow->check = check;
    header->auxpow->ctx = header;
    header->auxpow->is = false;
    header->auxpow_payload = NULL;
    return header;
    }

/**
 * It allocates a new dogecoin_auxpow_block and returns it
 *
 * @return A pointer to a new dogecoin_auxpow_block object.
 */
dogecoin_auxpow_block* dogecoin_auxpow_block_new() {
    dogecoin_auxpow_block* block = dogecoin_calloc(1, sizeof(*block));
    block->header = dogecoin_block_header_new();
    block->parent_coinbase = dogecoin_tx_new();
    dogecoin_mem_zero(&block->parent_hash, DOGECOIN_HASH_LENGTH);
    block->parent_merkle_count = 0;
    block->parent_coinbase_merkle = NULL;
    block->parent_merkle_index = 0;
    block->aux_merkle_count = 0;
    block->aux_merkle_branch = NULL;
    block->aux_merkle_index = 0;
    block->parent_header = dogecoin_block_header_new();
    block->header->auxpow->ctx = block;
    return block;
    }

/**
 * @brief This function sets the memory for the specified block
 * header to zero and then frees the memory.
 *
 * @param header The pointer to the block header to be freed.
 *
 * @return Nothing.
 */
void dogecoin_auxpow_payload_free(dogecoin_auxpow_payload* payload) {
    if (!payload) return;
    dogecoin_tx_free(payload->parent_coinbase);
    dogecoin_free(payload->parent_coinbase_merkle);
    dogecoin_free(payload->aux_merkle_branch);
    /* parent_header is a plain 80-byte header: its own auxpow_payload is NULL,
       so this does not recurse. */
    dogecoin_block_header_free(payload->parent_header);
    dogecoin_free(payload);
    }

dogecoin_auxpow_payload* dogecoin_auxpow_payload_copy(const dogecoin_auxpow_payload* src) {
    if (!src) return NULL;
    dogecoin_auxpow_payload* dst = dogecoin_calloc(1, sizeof(*dst));
    if (!dst) return NULL;

    memcpy_safe(dst->parent_hash, src->parent_hash, sizeof(uint256_t));
    dst->parent_merkle_count = src->parent_merkle_count;
    dst->parent_merkle_index = src->parent_merkle_index;
    dst->aux_merkle_count    = src->aux_merkle_count;
    dst->aux_merkle_index    = src->aux_merkle_index;

    if (src->parent_coinbase) {
        dst->parent_coinbase = dogecoin_tx_new();
        if (!dst->parent_coinbase) goto fail;
        dogecoin_tx_copy(dst->parent_coinbase, src->parent_coinbase);
    }
    if (src->parent_merkle_count && src->parent_coinbase_merkle) {
        size_t n = (size_t)src->parent_merkle_count * sizeof(uint256_t);
        dst->parent_coinbase_merkle = dogecoin_malloc(n);
        if (!dst->parent_coinbase_merkle) goto fail;
        memcpy_safe(dst->parent_coinbase_merkle, src->parent_coinbase_merkle, n);
    }
    if (src->aux_merkle_count && src->aux_merkle_branch) {
        size_t n = (size_t)src->aux_merkle_count * sizeof(uint256_t);
        dst->aux_merkle_branch = dogecoin_malloc(n);
        if (!dst->aux_merkle_branch) goto fail;
        memcpy_safe(dst->aux_merkle_branch, src->aux_merkle_branch, n);
    }
    if (src->parent_header) {
        dst->parent_header = dogecoin_block_header_new();
        if (!dst->parent_header) goto fail;
        dogecoin_block_header_copy(dst->parent_header, src->parent_header);
    }
    return dst;

fail:
    dogecoin_auxpow_payload_free(dst);
    return NULL;
    }

void dogecoin_block_header_destroy(dogecoin_block_header* header) {
    if (!header) return;
    dogecoin_auxpow_payload_free(header->auxpow_payload);
    header->auxpow_payload = NULL;
    header->version = 0;
    dogecoin_mem_zero(&header->prev_block, DOGECOIN_HASH_LENGTH);
    dogecoin_mem_zero(&header->merkle_root, DOGECOIN_HASH_LENGTH);
    header->bits = 0;
    header->timestamp = 0;
    header->nonce = 0;
    }

void dogecoin_block_header_free(dogecoin_block_header* header) {
    if (!header) return;
    dogecoin_block_header_destroy(header);
    dogecoin_free(header);
    }

void dogecoin_auxpow_block_free(dogecoin_auxpow_block* block) {
    if (!block) return;
    dogecoin_block_header_free(block->header);
    dogecoin_tx_free(block->parent_coinbase);
    dogecoin_free(block->parent_coinbase_merkle);
    dogecoin_free(block->aux_merkle_branch);
    block->parent_merkle_count = 0;
    block->aux_merkle_count = 0;
    block->aux_merkle_index = 0;
    block->parent_merkle_index = 0;
    remove_all_hashes();
    dogecoin_block_header_free(block->parent_header);
    dogecoin_free(block);
    }

void print_transaction(dogecoin_tx* x) {
    // serialize tx & print raw hex:
    cstring* tx = cstr_new_sz(1024);
    dogecoin_tx_serialize(tx, x);
    char tx_hex[2048];
    utils_bin_to_hex((unsigned char *)tx->str, tx->len, tx_hex);
    printf("block->parent_coinbase (hex):                   %s\n", tx_hex); // uncomment to see raw hexadecimal transactions

    // begin deconstruction into objects:
    printf("block->parent_coinbase->version:                %d\n", x->version);

    // parse inputs:
    unsigned int i = 0;
    for (; i < x->vin->len; i++) {
        printf("block->parent_coinbase->tx_in->i:               %d\n", i);
        dogecoin_tx_in* tx_in = vector_idx(x->vin, i);
        printf("block->parent_coinbase->vin->prevout.n:         %d\n", tx_in->prevout.n);
        char* hex_utxo_txid = utils_uint8_to_hex(tx_in->prevout.hash, sizeof tx_in->prevout.hash);
        printf("block->parent_coinbase->tx_in->prevout.hash:    %s\n", hex_utxo_txid);
        char* script_sig = utils_uint8_to_hex((const uint8_t*)tx_in->script_sig->str, tx_in->script_sig->len);
        printf("block->parent_coinbase->tx_in->script_sig:      %s\n", script_sig);

        printf("block->parent_coinbase->tx_in->sequence:        %x\n", tx_in->sequence);
    }

    // parse outputs:
    i = 0;
    for (; i < x->vout->len; i++) {
        printf("block->parent_coinbase->tx_out->i:              %d\n", i);
        dogecoin_tx_out* tx_out = vector_idx(x->vout, i);
        printf("block->parent_coinbase->tx_out->script_pubkey:  %s\n", utils_uint8_to_hex((const uint8_t*)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
        printf("block->parent_coinbase->tx_out->value:          %" PRId64 "\n", tx_out->value);
    }
    printf("block->parent_coinbase->locktime:               %d\n", x->locktime);
    cstr_free(tx, true);
}

void print_block_header(dogecoin_block_header* header) {
    printf("block->header->version:                         %i\n", header->version);
    printf("block->header->prev_block:                      %s\n", hash_to_string(header->prev_block));
    printf("block->header->merkle_root:                     %s\n", hash_to_string(header->merkle_root));
    printf("block->header->timestamp:                       %u\n", header->timestamp);
    printf("block->header->bits:                            %x\n", header->bits);
    printf("block->header->nonce:                           %x\n", header->nonce);
}

void print_parent_header(dogecoin_auxpow_block* block) {
    printf("block->parent_hash:                             %s\n", hash_to_string(block->parent_hash));
    printf("block->parent_merkle_count:                     %d\n", block->parent_merkle_count);
    size_t j = 0;
    for (; j < block->parent_merkle_count; j++) {
        printf("block->parent_coinbase_merkle[%zu]:               "
                "%s\n", j, hash_to_string((uint8_t*)block->parent_coinbase_merkle[j]));
    }
    printf("block->parent_merkle_index:                     %d\n", block->parent_merkle_index);
    printf("block->aux_merkle_count:                        %d\n", block->aux_merkle_count);
    j = 0;
    for (; j < block->aux_merkle_count; j++) {
        printf("block->aux_merkle_branch[%zu]:                    "
                "%s\n", j, hash_to_string((uint8_t*)block->aux_merkle_branch[j]));
    }
    printf("block->aux_merkle_index:                        %d\n", block->aux_merkle_index);
    printf("block->parent_header->version:                  %i\n", block->parent_header->version);
    printf("block->parent_header->prev_block:               %s\n", hash_to_string(block->parent_header->prev_block));
    printf("block->parent_header->merkle_root:              %s\n", hash_to_string(block->parent_header->merkle_root));
    printf("block->parent_header->timestamp:                %u\n", block->parent_header->timestamp);
    printf("block->parent_header->bits:                     %x\n", block->parent_header->bits);
    printf("block->parent_header->nonce:                    %u\n\n", block->parent_header->nonce);
}

void print_block(dogecoin_auxpow_block* block) {
    print_block_header(block->header);
    print_transaction(block->parent_coinbase);
    print_parent_header(block);
}

/**
 * @brief This function takes a raw buffer and deserializes
 * it into a dogecoin block header object += auxpow data.
 *
 * @param header The header object to be constructed.
 * @param buf The buffer to deserialize from.
 * @param params The chain parameters.
 * @param chainwork The computed chainwork.
 *
 * @return 1 if deserialization was successful, 0 otherwise.
 */
static int parse_dogecoin_auxpow_fields(dogecoin_auxpow_block* block, struct const_buffer* buffer, const dogecoin_chainparams *params);

int dogecoin_block_header_parse(dogecoin_block_header* header, struct const_buffer* buf, const dogecoin_chainparams *params) {
    dogecoin_auxpow_block* block = dogecoin_auxpow_block_new();
    int ret = false;
    if (!deser_s32(&block->header->version, buf))
        goto cleanup;
    if (!deser_u256(block->header->prev_block, buf))
        goto cleanup;
    if (!deser_u256(block->header->merkle_root, buf))
        goto cleanup;
    if (!deser_u32(&block->header->timestamp, buf))
        goto cleanup;
    if (!deser_u32(&block->header->bits, buf))
        goto cleanup;
    if (!deser_u32(&block->header->nonce, buf))
        goto cleanup;
    dogecoin_block_header_copy(header, block->header);
    if ((block->header->version & 0x100) != 0 && buf->len) {
        if (!parse_dogecoin_auxpow_fields(block, buf, params)) {
            printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
            goto cleanup;
        }
        dogecoin_block_header_copy(header, block->header);
        /* Move the proof onto the header instead of letting cleanup free it.
           Ownership transfers: the fields are nulled on the block so
           dogecoin_auxpow_block_free does not release what the header now owns. */
        dogecoin_auxpow_payload* payload = dogecoin_calloc(1, sizeof(*payload));
        if (!payload) goto cleanup;
        payload->parent_coinbase        = block->parent_coinbase;
        memcpy_safe(payload->parent_hash, block->parent_hash, sizeof(uint256_t));
        payload->parent_merkle_count    = block->parent_merkle_count;
        payload->parent_coinbase_merkle = block->parent_coinbase_merkle;
        payload->parent_merkle_index    = block->parent_merkle_index;
        payload->aux_merkle_count       = block->aux_merkle_count;
        payload->aux_merkle_branch      = block->aux_merkle_branch;
        payload->aux_merkle_index       = block->aux_merkle_index;
        payload->parent_header          = block->parent_header;
        block->parent_coinbase          = NULL;
        block->parent_coinbase_merkle   = NULL;
        block->aux_merkle_branch        = NULL;
        block->parent_header            = NULL;
        /* No free of a prior payload here: dogecoin_block_header_copy above has
           already overwritten the pointer, and header may have arrived as an
           uninitialised stack struct. Callers own dest's prior contents, the
           same contract every other field in this function follows. */
        header->auxpow_payload = payload;
    }
    ret = true;
cleanup:
    dogecoin_auxpow_block_free(block);
    return ret;
    }

int dogecoin_block_header_validate(dogecoin_block_header* header, const dogecoin_chainparams *params, arith_uint256* chainwork) {
    if (!header) return false;
    /* Nothing to check for a header with no AuxPoW: its proof of work is over
       the 80 base bytes, which is the caller's to verify -- headersdb_file.c
       does exactly that for the non-AuxPoW case, and fills chainwork itself. */
    if (!header->auxpow_payload) return true;

    /* check_auxpow wants a dogecoin_auxpow_block. Build one that borrows from
       the header and its payload rather than copying: it is never freed, so the
       borrowed pointers are not released twice. dogecoin_auxpow_block_free
       would take the header and parent_header with it, which is exactly the
       ownership tangle the payload type exists to avoid. */
    dogecoin_auxpow_payload* p = header->auxpow_payload;
    dogecoin_auxpow_block view;
    dogecoin_mem_zero(&view, sizeof(view));
    view.header                 = header;
    view.parent_coinbase        = p->parent_coinbase;
    memcpy_safe(view.parent_hash, p->parent_hash, sizeof(uint256_t));
    view.parent_merkle_count    = p->parent_merkle_count;
    view.parent_coinbase_merkle = p->parent_coinbase_merkle;
    view.parent_merkle_index    = p->parent_merkle_index;
    view.aux_merkle_count       = p->aux_merkle_count;
    view.aux_merkle_branch      = p->aux_merkle_branch;
    view.aux_merkle_index       = p->aux_merkle_index;
    view.parent_header          = p->parent_header;

    if (!check_auxpow(&view, (dogecoin_chainparams*)params, chainwork)) {
        printf("check_auxpow failed!\n");
        return false;
    }
    return true;
    }

int dogecoin_block_header_deserialize(dogecoin_block_header* header, struct const_buffer* buf, const dogecoin_chainparams *params, arith_uint256* chainwork) {
    if (!dogecoin_block_header_parse(header, buf, params)) return false;
    return dogecoin_block_header_validate(header, params, chainwork);
    }

/* Parse the AuxPoW fields off the wire. No validation: check_auxpow is scrypt
   work on the parent chain, and doing it here means every caller pays for it
   during parsing whether or not it wants the answer yet. */
static int parse_dogecoin_auxpow_fields(dogecoin_auxpow_block* block, struct const_buffer* buffer, const dogecoin_chainparams *params) {
    (void)params;
    if (buffer->len > DOGECOIN_MAX_P2P_MSG_SIZE) {
        return printf("\ntransaction is invalid or to large.\n\n");
        }

    size_t consumedlength = 0;
    if (!dogecoin_tx_deserialize(buffer->p, buffer->len, block->parent_coinbase, &consumedlength)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
        }

    if (consumedlength == 0) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }

    if (!deser_skip(buffer, consumedlength)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }

    block->header->auxpow->is = (block->header->version & 0x100) == 256;

    if (!deser_u256(block->parent_hash, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    /* Read the count into a properly-typed local. Previously this wrote a full
       uint32_t through (uint32_t*)&parent_merkle_count, a uint8_t field: a
       4-byte store through a 1-byte-typed pointer (undefined behavior, and it
       clobbered adjacent struct bytes). It also silently truncated the wire
       value to 8 bits. Bound the count so the field can hold it and so a
       malicious block can't request an enormous allocation; merkle branch
       depth is log2(tx count), so anything beyond a byte is already invalid. */
    uint32_t parent_merkle_count = 0;
    if (!deser_varlen(&parent_merkle_count, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (parent_merkle_count > 0xff) {
        printf("%s:%d:%s: parent_merkle_count %u out of range\n", __FILE__, __LINE__, __func__, parent_merkle_count);
        return false;
    }
    block->parent_merkle_count = (uint8_t)parent_merkle_count;
    uint32_t i = 0;
    if (block->parent_merkle_count > 0) {
        block->parent_coinbase_merkle = dogecoin_calloc(block->parent_merkle_count, sizeof(uint256_t));
        if (!block->parent_coinbase_merkle) {
            printf("%s:%d:%s: allocation failed\n", __FILE__, __LINE__, __func__);
            return false;
        }
    }
    for (; i < block->parent_merkle_count; i++) {
        if (!deser_u256(block->parent_coinbase_merkle[i], buffer)) {
            printf("%d:%s:%u\n", __LINE__, __func__, i);
            return false;
        }
        }

    if (!deser_u32(&block->parent_merkle_index, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    uint32_t aux_merkle_count = 0;
    if (!deser_varlen(&aux_merkle_count, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (aux_merkle_count > 0xff) {
        printf("%s:%d:%s: aux_merkle_count %u out of range\n", __FILE__, __LINE__, __func__, aux_merkle_count);
        return false;
    }
    block->aux_merkle_count = (uint8_t)aux_merkle_count;
    if (block->aux_merkle_count > 0) {
        block->aux_merkle_branch = dogecoin_calloc(block->aux_merkle_count, sizeof(uint256_t));
        if (!block->aux_merkle_branch) {
            printf("%s:%d:%s: allocation failed\n", __FILE__, __LINE__, __func__);
            return false;
        }
    }
    for (i = 0; i < block->aux_merkle_count; i++) {
        if (!deser_u256(block->aux_merkle_branch[i], buffer)) {
            printf("%d:%s:%u\n", __LINE__, __func__, i);
            return false;
        }
        }

    if (!deser_u32(&block->aux_merkle_index, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_s32(&block->parent_header->version, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_u256(block->parent_header->prev_block, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_u256(block->parent_header->merkle_root, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_u32(&block->parent_header->timestamp, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_u32(&block->parent_header->bits, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (!deser_u32(&block->parent_header->nonce, buffer)) {
        printf("%s:%d:%s:%s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }

    return true;
    }

/* Unchanged behaviour and signature: parse, then validate. Callers that want
   only the fields use parse_dogecoin_auxpow_fields via
   dogecoin_block_header_parse. */
int deserialize_dogecoin_auxpow_block(dogecoin_auxpow_block* block, struct const_buffer* buffer, const dogecoin_chainparams *params, arith_uint256* chainwork) {
    if (!parse_dogecoin_auxpow_fields(block, buffer, params)) return false;
    if (!check_auxpow(block, (dogecoin_chainparams*)params, chainwork)) {
        printf("check_auxpow failed!\n");
        return false;
    }
    return true;
    }

/**
 * @brief This function serializes a dogecoin block header into
 * a cstring object.
 *
 * @param s The cstring to write the serialized header->
 * @param header The block header to be serialized.
 *
 * @return Nothing.
 */
void dogecoin_block_header_serialize(cstring* s, const dogecoin_block_header* header) {
    ser_s32(s, header->version);
    ser_u256(s, header->prev_block);
    ser_u256(s, header->merkle_root);
    ser_u32(s, header->timestamp);
    ser_u32(s, header->bits);
    ser_u32(s, header->nonce);
    }

/**
 * @brief This function copies the contents of one header object
 * into another.
 *
 * @param dest The pointer to the header object copy.
 * @param src The pointer to the source block header object.
 *
 * @return Nothing.
 */
void dogecoin_block_header_copy(dogecoin_block_header* dest, const dogecoin_block_header* src) {
    dest->version = src->version;
    memcpy_safe(&dest->prev_block, &src->prev_block, sizeof(src->prev_block));
    memcpy_safe(&dest->merkle_root, &src->merkle_root, sizeof(src->merkle_root));
    dest->timestamp = src->timestamp;
    dest->bits = src->bits;
    dest->nonce = src->nonce;
    dest->auxpow->check = src->auxpow->check;
    dest->auxpow->ctx = src->auxpow->ctx;
    dest->auxpow->is = src->auxpow->is;
    /* Deep-copy the proof. Carrying only the hook fields is what discarded it
       before, so a copied merge-mined header could not be re-serialized or
       re-validated without going back to the wire bytes.

       Assign, do not free what dest held. Every other field here is a plain
       overwrite: this function treats dest as raw memory, and callers pass
       uninitialised stack headers to it -- net_tests.c does, via
       dogecoin_block_header_deserialize. Freeing dest->auxpow_payload would
       dereference whatever the stack happened to contain. A dest that already
       owns a payload is the caller's to release, as with every other member. */
    dest->auxpow_payload = dogecoin_auxpow_payload_copy(src->auxpow_payload);
    }

/**
 * @brief This function takes a block header and generates its
 * SHA256 hash.
 *
 * @param header The pointer to the block header to hash.
 * @param hash The SHA256 hash of the block header->
 *
 * @return True.
 */
dogecoin_bool dogecoin_block_header_hash(dogecoin_block_header* header, uint256_t hash) {
    cstring* s = cstr_new_sz(80);
    dogecoin_block_header_serialize(s, header);
    sha256_raw((const uint8_t*)s->str, s->len, hash);
    sha256_raw(hash, SHA256_DIGEST_LENGTH, hash);
    cstr_free(s, true);
    dogecoin_bool ret = true;
    return ret;
    }
