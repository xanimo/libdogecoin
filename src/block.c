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
#include <string.h>
#include <inttypes.h>

#include <dogecoin/auxpow.h>
#include <dogecoin/block.h>
#include <dogecoin/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

dogecoin_bool check(void *ctx, uint256* hash, uint32_t chainid, dogecoin_chainparams* params) {
    dogecoin_auxpow_block* block = (dogecoin_auxpow_block*)ctx;
    print_block(block);
    if ((block->parent_merkle_index || block->aux_merkle_index) != 0) {
        printf("Auxpow is not a generate\n");
        return false;
    }

    uint32_t parent_chainid = get_chainid(block->parent_header->version);
    if (params->strict_id && parent_chainid == chainid) {
        printf("Aux POW parent has our chain ID");
        return false;
    }


    // if (vChainMerkleBranch.size() > 30)
    //     return error("Aux POW chain merkle branch too long");

    // // Check that the chain merkle root is in the coinbase
    // const uint256 nRootHash = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    // std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    // std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    // // Check that we are in the parent block merkle tree
    // if (CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot)
    //     return error("Aux POW merkle root incorrect");

    // const dogecoin_script script = tx->vin[0].scriptSig;

    // // Check that the same work is not submitted twice to our chain.
    // //

    // CScript::const_iterator pcHead =
    //     std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));

    // CScript::const_iterator pc =
    //     std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    // if (pc == script.end())
    //     return error("Aux POW missing chain merkle root in parent coinbase");

    // if (pcHead != script.end())
    // {
    //     // Enforce only one chain merkle root by checking that a single instance of the merged
    //     // mining header exists just before.
    //     if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader)))
    //         return error("Multiple merged mining headers in coinbase");
    //     if (pcHead + sizeof(pchMergedMiningHeader) != pc)
    //         return error("Merged mining header is not just before chain merkle root");
    // }
    // else
    // {
    //     // For backward compatibility.
    //     // Enforce only one chain merkle root by checking that it starts early in the coinbase.
    //     // 8-12 bytes are enough to encode extraNonce and nBits.
    //     if (pc - script.begin() > 20)
    //         return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
    // }


    // // Ensure we are at a deterministic point in the merkle leaves by hashing
    // // a nonce and our chain ID and comparing to the index.
    // pc += vchRootHash.size();
    // if (script.end() - pc < 8)
    //     return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

    // uint32_t nSize;
    // memcpy(&nSize, &pc[0], 4);
    // nSize = le32toh(nSize);
    // const unsigned merkleHeight = vChainMerkleBranch.size();
    // if (nSize != (1u << merkleHeight))
    //     return error("Aux POW merkle branch size does not match parent coinbase");

    // uint32_t nNonce;
    // memcpy(&nNonce, &pc[4], 4);
    // nNonce = le32toh (nNonce);
    // if (nChainIndex != getExpectedIndex (nNonce, nChainId, merkleHeight))
    //     return error("Aux POW wrong index");

    // printf("inside check!\n");

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
    block->parent_header = dogecoin_block_header_new();
    block->header->auxpow->check = check;
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
void dogecoin_block_header_free(dogecoin_block_header* header) {
    if (!header) return;
    header->version = 1;
    dogecoin_mem_zero(&header->prev_block, DOGECOIN_HASH_LENGTH);
    dogecoin_mem_zero(&header->merkle_root, DOGECOIN_HASH_LENGTH);
    header->bits = 0;
    header->timestamp = 0;
    header->nonce = 0;
    dogecoin_free(header);
    }

void dogecoin_auxpow_block_free(dogecoin_auxpow_block* block) {
    if (!block) return;
    dogecoin_block_header_free(block->header);
    dogecoin_tx_free(block->parent_coinbase);
    block->parent_merkle_count = 0;
    block->aux_merkle_count = 0;
    remove_all_hashes();
    dogecoin_block_header_free(block->parent_header);
    dogecoin_free(block);
    }

void print_transaction(dogecoin_tx* x) {
    // serialize tx & print raw hex:
    cstring* tx = cstr_new_sz(1024);
    dogecoin_tx_serialize(tx, x);
    char tx_hex[tx->len*2];
    utils_bin_to_hex((unsigned char *)tx->str, tx->len, tx_hex);
    printf("block->parent_coinbase (hex):                   %s\n", tx_hex); // uncomment to see raw hexadecimal transactions

    // begin deconstruction into objects:
    printf("block->parent_coinbase->version:                %d\n", x->version);

    // parse inputs:
    unsigned int i = 0;
    for (; i < x->vin->len; i++) {
        printf("block->parent_coinbase->tx_in->i:               %d\n", i);
        dogecoin_tx_in* tx_in = vector_idx(x->vin, i);
        uint32_t vout_index = tx_in->prevout.n;
        printf("block->parent_coinbase->vin->prevout.n:         %d\n", tx_in->prevout.n);
        char* hex_utxo_txid = utils_uint8_to_hex(tx_in->prevout.hash, sizeof tx_in->prevout.hash);
        printf("block->parent_coinbase->tx_in->prevout.hash:    %s\n", hex_utxo_txid);
        printf("block->parent_coinbase->tx_in->script_sig:      %s\n", utils_uint8_to_hex((const uint8_t*)tx_in->script_sig->str, tx_in->script_sig->len));
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
    printf("block->header->prev_block:                      %s\n", to_string(header->prev_block));
    printf("block->header->merkle_root:                     %s\n", to_string(header->merkle_root));
    printf("block->header->timestamp:                       %u\n", header->timestamp);
    printf("block->header->bits:                            %x\n", header->bits);
    printf("block->header->nonce:                           %x\n", header->nonce);
}

void print_parent_header(dogecoin_auxpow_block* block) {
    printf("block->parent_hash:                             %s\n", to_string(block->parent_hash));
    printf("block->parent_merkle_count:                     %d\n", block->parent_merkle_count);
    size_t j = 0;
    for (; j < block->parent_merkle_count; j++) {
        printf("block->parent_coinbase_merkle[%zu]:               "
                "%s\n", j, to_string((uint8_t*)block->parent_coinbase_merkle[j]));
    }
    printf("block->parent_merkle_index:                     %d\n", block->parent_merkle_index);
    printf("block->aux_merkle_count:                        %d\n", block->aux_merkle_count);
    printf("block->aux_merkle_branch:                       "
            "%s\n", to_string((uint8_t*)block->aux_merkle_branch));
    printf("block->aux_merkle_index:                        %d\n", block->aux_merkle_index);
    printf("block->parent_header.version:                   %i\n", block->parent_header->version);
    printf("block->parent_header.prev_block:                %s\n", to_string(block->parent_header->prev_block));
    printf("block->parent_header.merkle_root:               %s\n", to_string(block->parent_header->merkle_root));
    printf("block->parent_header.timestamp:                 %u\n", block->parent_header->timestamp);
    printf("block->parent_header.bits:                      %x\n", block->parent_header->bits);
    printf("block->parent_header.nonce:                     %u\n\n", block->parent_header->nonce);
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
 *
 * @return 1 if deserialization was successful, 0 otherwise.
 */
int dogecoin_block_header_deserialize(dogecoin_block_header* header, struct const_buffer* buf) {
    dogecoin_auxpow_block* block = dogecoin_auxpow_block_new();
    if (!deser_u32(&block->header->version, buf))
        return false;
    if (!deser_u256(block->header->prev_block, buf))
        return false;
    if (!deser_u256(block->header->merkle_root, buf))
        return false;
    if (!deser_u32(&block->header->timestamp, buf))
        return false;
    if (!deser_u32(&block->header->bits, buf))
        return false;
    if (!deser_u32(&block->header->nonce, buf))
        return false;
    dogecoin_block_header_copy(header, block->header);
    if ((block->header->version & BLOCK_VERSION_AUXPOW_BIT) != 0) {
        deserialize_dogecoin_auxpow_block(block, buf);
        }
    dogecoin_auxpow_block_free(block);
    return true;
    }

int deserialize_dogecoin_auxpow_block(dogecoin_auxpow_block* block, struct const_buffer* buffer) {
    if (buffer->len > DOGECOIN_MAX_P2P_MSG_SIZE) {
        return printf("\ntransaction is invalid or to large.\n\n");
        }

    size_t consumedlength = 0;
    if (!dogecoin_tx_deserialize(buffer->p, buffer->len, block->parent_coinbase, &consumedlength)) {
        return false;
        }

    if (consumedlength == 0) return false;

    if (!deser_skip(buffer, consumedlength)) return false;

    block->header->auxpow->is = (block->header->version & BLOCK_VERSION_AUXPOW_BIT) == 256;

    if (!deser_u256(block->parent_hash, buffer)) return false;

    if (!deser_varlen((uint32_t*)&block->parent_merkle_count, buffer)) return false;

    uint8_t i = 0;
    for (; i < block->parent_merkle_count; i++) {
        hash* parent_cb_merkle_branch = new_hash();
        if (!deser_u256((uint8_t*)parent_cb_merkle_branch->data.u8, buffer)) {
            return false;
        }
        dogecoin_free(parent_cb_merkle_branch);
        }

    if (!deser_u32(&block->parent_merkle_index, buffer)) return false;

    if (!deser_varlen((uint32_t*)&block->aux_merkle_count, buffer)) return false;

    for (i = 0; i < block->aux_merkle_count; i++) {
        hash* aux_merkle_branch = new_hash();
        if (!deser_u256((uint8_t*)aux_merkle_branch->data.u8, buffer)) {
            return false;
        }
        dogecoin_free(aux_merkle_branch);
        }

    if (!deser_u32(&block->aux_merkle_index, buffer)) return false;

    if (!deser_u32(&block->parent_header->version, buffer)) return false;
    if (!deser_u256(block->parent_header->prev_block, buffer)) return false;
    if (!deser_u256(block->parent_header->merkle_root, buffer)) return false;
    if (!deser_u32(&block->parent_header->timestamp, buffer)) return false;
    if (!deser_u32(&block->parent_header->bits, buffer)) return false;
    if (!deser_u32(&block->parent_header->nonce, buffer)) return false;

    // print_block(block);
    if (!check_auxpow(*block, (dogecoin_chainparams*)&dogecoin_chainparams_main)) {
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
    ser_u32(s, header->version);
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
dogecoin_bool dogecoin_block_header_hash(dogecoin_block_header* header, uint256 hash) {
    cstring* s = cstr_new_sz(80);
    dogecoin_block_header_serialize(s, header);
    sha256_raw((const uint8_t*)s->str, s->len, hash);
    sha256_raw(hash, SHA256_DIGEST_LENGTH, hash);
    cstr_free(s, true);
    dogecoin_bool ret = true;
    return ret;
    }
