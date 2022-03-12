/*

 The MIT License (MIT)

 Copyright (c) 2016 Thomas Kerin
 Copyright (c) 2016 Jonas Schnelli
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/block.h>
#include <dogecoin/net/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/crypto/sha2.h>
#include <dogecoin/utils.h>

/**
 * It allocates a new dogecoin_block_header and returns it
 * 
 * @return A pointer to a new dogecoin_block_header object.
 */
dogecoin_block_header* dogecoin_block_header_new() {
    dogecoin_block_header* header;
    header = dogecoin_calloc(1, sizeof(*header));
    return header;
}

/**
 * It takes a pointer to a dogecoin_block_header and sets all the fields to zero
 * 
 * @param header the pointer to the block header to be freed.
 * 
 * @return Nothing
 */
void dogecoin_block_header_free(dogecoin_block_header* header) {
    if (!header) return;
    header->version = 1;
    memset(&header->prev_block, 0, DOGECOIN_HASH_LENGTH);
    memset(&header->merkle_root, 0, DOGECOIN_HASH_LENGTH);
    header->bits = 0;
    header->timestamp = 0;
    header->nonce = 0;
    dogecoin_free(header);
}

void printBits(size_t const size, void const* ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    uint64_t bytestr;
    int i, j;
    
    for (i = size-1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

int dogecoin_get_block_header_version(struct const_buffer* buffer) {
    int32_t version;
    if (!deser_s32(&version, buffer))
        return false;
    // printf("version: %d\n", version);
    return true;
}

int dogecoin_get_block_header_prev_block(struct const_buffer* buffer) {
    uint256 prev_block;
    if (!deser_u256(prev_block, buffer))
        return false;
    // printf("prev_block: %s\n", prev_block);
    return true;
}

int dogecoin_get_block_header_merkle_root(struct const_buffer* buffer) {
    uint256 merkle_root;
    if (!deser_u256(merkle_root, buffer))
        return false;
    // printf("merkle_root: %s\n", merkle_root);
    return true;
}

int dogecoin_get_block_header_timestamp(struct const_buffer* buffer) {
    uint32_t timestamp;
    if (!deser_u32(&timestamp, buffer))
        return false;
    // printf("timestamp: %u\n", timestamp);
    return true;
}

int dogecoin_get_block_header_bits(struct const_buffer* buffer) {
    int32_t version;
    if (!deser_s32(&version, buffer))
        return false;
    printf("version: %d\n", version);
    return true;
}

int dogecoin_get_block_header_nonce(struct const_buffer* buffer) {
    int32_t version;
    if (!deser_s32(&version, buffer))
        return false;
    printf("version: %d\n", version);
    return true;
}

int dogecoin_get_block_header_coinbase_txn(struct const_buffer* buffer) {
    int32_t coinbase_txn;
    if (!deser_s32(&coinbase_txn, buffer))
        return false;
    printf("dogecoin_tx_is_coinbaseversion: %d\n", coinbase_txn);
    return true;
}

int dogecoin_get_block_header_block_hash(struct const_buffer* buffer) {
    int32_t block_hash;
    if (!deser_s32(&block_hash, buffer))
        return false;
    printf("block_hash: %d\n", block_hash);
    return true;
}

int dogecoin_get_block_header_coinbase_branch(struct const_buffer* buffer) {
    int32_t coinbase_branch;
    if (!deser_s32(&coinbase_branch, buffer))
        return false;
    printf("coinbase_branch: %d\n", coinbase_branch);
    return true;
}

int dogecoin_get_block_header_blockchain_branch(struct const_buffer* buffer) {
    int32_t blockchain_branch;
    if (!deser_s32(&blockchain_branch, buffer))
        return false;
    printf("blockchain_branch: %d\n", blockchain_branch);
    return true;
}

int dogecoin_get_block_header_parent_block(struct const_buffer* buffer) {
    int32_t parent_block;
    if (!deser_s32(&parent_block, buffer))
        return false;
    printf("parent_block: %d\n", parent_block);
    return true;
}

int dogecoin_get_block_header_txn_count(struct const_buffer* buffer) {
    int32_t txn_count;
    if (!deser_s32(&txn_count, buffer))
        return false;
    printf("txn_count: %d\n", txn_count);
    return true;
}

int dogecoin_get_block_header_txns(struct const_buffer* buffer) {
    int32_t txns;
    if (!deser_s32(&txns, buffer))
        return false;
    printf("txns: %d\n", txns);
    return true;
}

/**
 * It deserializes a block header from a buffer
 * 
 * @param header the header object to be filled in
 * @param buf The buffer to deserialize from.
 * 
 * @return Nothing.
 */
int dogecoin_block_header_deserialize(dogecoin_block_header* header, struct const_buffer* buf) {
    if (header->nonce == 0 && &header->version >= 0x00620102) {
        // printBits(buf->len, buf->p);
        // printf("auxpow_block_header }:P\n");
    }
    if (!deser_s32(&header->version, buf))
        return false;
    if (!deser_u256(header->prev_block, buf))
        return false;
    if (!deser_u256(header->merkle_root, buf))
        return false;
    if (!deser_u32(&header->timestamp, buf))
        return false;
    if (!deser_u32(&header->bits, buf))
        return false;
    if (!deser_u32(&header->nonce, buf))
        return false;
    return true;
}

int deser_merkle_branch(merkle_branch* mb, struct const_buffer* buffer) {
    if (!deser_u256(mb->hashes[sizeof(mb)], buffer)) {
        return false;
    }
}

int deserialize_auxpow_block_header(auxpow_block_header* hdr, struct const_buffer* buffer) {
    if (buffer == NULL || buffer->len == 0 || buffer->len > DOGECOIN_MAX_P2P_MSG_SIZE) {
        return printf("Transaction in invalid or to large.\n");
    }
    uint8_t* data_bin = dogecoin_malloc(buffer->len / 2 + 1);
    int outlen = 0;
    utils_hex_to_bin(buffer->p, data_bin, buffer->len, &outlen);

    dogecoin_tx* tx = dogecoin_tx_new();
    if (!dogecoin_tx_deserialize(data_bin, outlen, &hdr->parent_coinbase, NULL, false)) {
        printf("Transaction is invalid\n");
    }
    dogecoin_free(data_bin);
    dogecoin_tx_free(tx);

    if (!deser_u256(hdr->parent_hash, buffer)) {
        return false;
    }
    if (!deser_u256(hdr->parent_hash, buffer)) {
        return false;
    }
    if (!deser_u256(hdr->blockchain_branch, buffer)) {
        return false;
    }
    if (!dogecoin_block_header_deserialize(&hdr->parent_header, buffer)) {
        return false;
    }
}

/**
 * It serializes a dogecoin block header
 * 
 * @param s The string to write to.
 * @param header the block header to serialize
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
 * Copy the contents of a dogecoin_block_header struct to another.
 * 
 * @param dest The destination block header.
 * @param src The source block header.
 */
void dogecoin_block_header_copy(dogecoin_block_header* dest, const dogecoin_block_header* src) {
    dest->version = src->version;
    memcpy(&dest->prev_block, &src->prev_block, sizeof(src->prev_block));
    memcpy(&dest->merkle_root, &src->merkle_root, sizeof(src->merkle_root));
    dest->timestamp = src->timestamp;
    dest->bits = src->bits;
    dest->nonce = src->nonce;
}

/**
 * The function takes a block header and returns a hash of the block header
 * 
 * @param header The block header to hash.
 * @param hash The hash of the block header.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_block_header_hash(dogecoin_block_header* header, uint256 hash) {
    cstring* s = cstr_new_sz(80);
    dogecoin_block_header_serialize(s, header);
    sha256_raw((const uint8_t*)s->str, s->len, hash);
    sha256_raw(hash, SHA256_DIGEST_LENGTH, hash);
    cstr_free(s, true);
    dogecoin_bool ret = true;
    return ret;
}
