/*

 The MIT License (MIT)

 Copyright (c) 2023 bluezr
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

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#else
#include <unistd.h>
#endif

#include <dogecoin/base58.h>
#include <dogecoin/bip44.h>
#include <dogecoin/block.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/common.h>
#include <dogecoin/constants.h>
#include <dogecoin/koinu.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

uint8_t TXINDEX_DB_REC_TYPE_TX = 1;

static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
static const unsigned char file_rec_magic[4] = {0xC8, 0xF2, 0x69, 0x1E}; /* record magic */
static const uint32_t current_version = 1;

int dogecoin_blockindex_compare(const void *l, const void *r)
{
    const dogecoin_blockindex *lm = l;
    const dogecoin_blockindex *lr = r;

    uint8_t *hashA = (uint8_t *)lm->hash;
    uint8_t *hashB = (uint8_t *)lr->hash;

    /* byte per byte compare */
    unsigned int i;
    for (i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }
    return 0;
}

/*
 ==========================================================
 BLOCKINDEX FUNCTIONS
 ==========================================================
*/
dogecoin_blockindex* dogecoin_blockindex_new()
{
    dogecoin_blockindex* blockindex;
    blockindex = dogecoin_calloc(1, sizeof(*blockindex));
    blockindex->height = 0;
    dogecoin_hash_clear(blockindex->hash);
    memcpy_safe(&blockindex->header, dogecoin_block_header_new(), sizeof(blockindex->header));
    blockindex->amount_of_txs = 0;
    return blockindex;
}

void dogecoin_blockindex_free(dogecoin_blockindex* blockindex)
{
    blockindex->height = 0;
    dogecoin_hash_clear(blockindex->hash);
    dogecoin_block_header_free(&blockindex->header);
    if (blockindex->amount_of_txs > 0) {
        size_t i = 0;
        for (; i < blockindex->amount_of_txs; i++) {
            dogecoin_tx_free(blockindex->txns[i]);
        }
        blockindex->amount_of_txs = 0;
    }
    dogecoin_free(blockindex);
}

void dogecoin_blockindex_serialize(cstring* s, const dogecoin_blockindex* blockindex)
{
    ser_u32(s, blockindex->height);
    ser_u256(s, blockindex->hash);
    dogecoin_block_header_serialize(s, &blockindex->header);
    ser_u32(s, blockindex->amount_of_txs);
    if (blockindex->amount_of_txs > 0) {
        size_t i = 0;
        for (; i < blockindex->amount_of_txs; i++) {
            dogecoin_tx_serialize(s, blockindex->txns[i]);
        }
    }
}

dogecoin_bool dogecoin_blockindex_deserialize(dogecoin_blockindex* blockindex, struct const_buffer* buf)
{
    printf("buf: %s\n", utils_uint8_to_hex(buf->p, buf->len));
    deser_u32(&blockindex->height, buf);
    deser_u256(blockindex->hash, buf);
    if (!dogecoin_block_header_deserialize(&blockindex->header, buf)) return false;
    if (!deser_u32((uint32_t*)&blockindex->amount_of_txs, buf)) return false;
    printf("amount of txs: %lu\n", blockindex->amount_of_txs);
    if (blockindex->amount_of_txs > 0) {
        size_t i = 0, consumed_length = 0;
        for (; i < blockindex->amount_of_txs; i++) {
            if (!dogecoin_tx_deserialize(buf->p, buf->len, blockindex->txns[i], &consumed_length)) {
                printf("error deserializing tx!\n");
            }
            deser_skip(buf, consumed_length);
        }
    }
    return true;
}

/*
 ==========================================================
 TXINDEX FUNCTIONS
 ==========================================================
*/
dogecoin_txindex* dogecoin_txindex_new(const dogecoin_chainparams *params)
{
    dogecoin_txindex* txindex = dogecoin_calloc(1, sizeof(*txindex));
    txindex->chain = params;
    return txindex;
}

void dogecoin_txindex_free(dogecoin_txindex* txindex)
{
    if (!txindex)
        return;

    if (txindex->dbfile) {
        fclose(txindex->dbfile);
    }

    dogecoin_free(txindex);
}

void dogecoin_txindex_add_blockindex_intern_move(dogecoin_txindex *txindex, const dogecoin_blockindex *blockindex) {
    dogecoin_blockindex* index = dogecoin_btree_tfind(blockindex, &txindex->txns_rbtree, dogecoin_blockindex_compare);
    if (index) {
        // remove existing blockindex
        index = *(dogecoin_blockindex **)index;
        unsigned int i;
        for (i = 0; i < txindex->vec_txns->len; i++) {
            dogecoin_blockindex *blockindex_vec = vector_idx(txindex->vec_txns, i);
            if (blockindex_vec == index) {
                vector_remove_idx(txindex->vec_txns, i);
            }
        }
        // we do not really delete transactions
        dogecoin_btree_tdelete(index, &txindex->txns_rbtree, dogecoin_blockindex_compare);
        dogecoin_blockindex_free(index);
    }
    dogecoin_btree_tfind(blockindex, &txindex->txns_rbtree, dogecoin_blockindex_compare);
    vector_add(txindex->vec_txns, (dogecoin_blockindex *)blockindex);
}

dogecoin_bool dogecoin_txindex_create(dogecoin_txindex* txindex, const char* file_path, int *error)
{
    if (!txindex)
        return false;

    struct stat buffer;
    if (stat(file_path, &buffer) != 0) {
        *error = 1;
        return false;
    }

    txindex->dbfile = fopen(file_path, "a+b");

    // write file-header-magic
    if (fwrite(file_hdr_magic, 4, 1, txindex->dbfile) != 1) return false;

    // write version
    uint32_t v = htole32(current_version);
    if (fwrite(&v, sizeof(v), 1, txindex->dbfile) != 1) return false;

    // write genesis
    if (fwrite(txindex->chain->genesisblockhash, sizeof(uint256), 1, txindex->dbfile ) != 1) return false;

    dogecoin_file_commit(txindex->dbfile);
    return true;
}

dogecoin_bool dogecoin_txindex_load(dogecoin_txindex* txindex, const char* file_path, int *error, dogecoin_bool *created)
{
    (void)(error);
    if (!txindex) { return false; }

    struct stat buffer;
    *created = true;
    if (stat(file_path, &buffer) == 0) *created = false;

    txindex->dbfile = fopen(file_path, *created ? "a+b" : "r+b");

    if (*created) {
        if (!dogecoin_txindex_create(txindex, file_path, error)) {
            return false;
        }
    }
    else {
        // check file-header-magic, version and genesis
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)+sizeof(uint256)];
        if ((uint32_t)buffer.st_size < (uint32_t)(sizeof(buf)) || fread(buf, sizeof(buf), 1, txindex->dbfile) != 1 || memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic)))
        {
            fprintf(stderr, "txindex file: error reading database file\n");
            return false;
        }
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "txindex file: unsupported file version\n");
            return false;
        }
        if (memcmp(buf+sizeof(file_hdr_magic)+sizeof(current_version), txindex->chain->genesisblockhash, sizeof(uint256)) != 0) {
            fprintf(stderr, "txindex file: different network\n");
            return false;
        }
        // read
        while (!feof(txindex->dbfile))
        {
            uint8_t buf[sizeof(file_rec_magic)];
            if (fread(buf, sizeof(buf), 1, txindex->dbfile) != 1 ) {
                // no more record, break
                break;
            }
            if (memcmp(buf, file_rec_magic, sizeof(file_rec_magic))) {
                fprintf(stderr, "txindex file: error reading record file (invalid magic). txindex file is corrupt\n");
                return false;
            }
            uint32_t reclen = 0;
            if (!deser_varlen_from_file(&reclen, txindex->dbfile)) return false;

            uint8_t rectype;
            if (fread(&rectype, 1, 1, txindex->dbfile) != 1) return false;

            if (rectype == TXINDEX_DB_REC_TYPE_TX) {
                unsigned char* buf = dogecoin_uchar_vla(reclen);
                struct const_buffer cbuf = {buf, reclen};
                if (fread(buf, reclen, 1, txindex->dbfile) != 1) {
                    return false;
                }

                dogecoin_blockindex *blockindex = dogecoin_blockindex_new();
                dogecoin_blockindex_deserialize(blockindex, &cbuf);
                dogecoin_txindex_add_blockindex_intern_move(txindex, blockindex); // hands memory management over to the binary tree
            } else {
                fseek(txindex->dbfile, reclen, SEEK_CUR);
            }
        }
    }

    return true;
}

dogecoin_bool dogecoin_txindex_flush(dogecoin_txindex* txindex)
{
    dogecoin_file_commit(txindex->dbfile);
    return true;
}

dogecoin_bool dogecoin_txindex_write_record(dogecoin_txindex *txindex, const cstring* record, uint8_t record_type) {
    // write record magic
    if (fwrite(file_rec_magic, 4, 1, txindex->dbfile) != 1) return false;

    //write record len
    cstring *cstr_len = cstr_new_sz(4);
    ser_varlen(cstr_len, record->len);
    if (fwrite(cstr_len->str, cstr_len->len, 1, txindex->dbfile) != 1) {
        cstr_free(cstr_len, true);
        return false;
    }
    cstr_free(cstr_len, true);

    // write record type & record payload
    if (fwrite(&record_type, 1, 1, txindex->dbfile) != 1 ||
        fwrite(record->str, record->len, 1, txindex->dbfile) != 1) {
        return false;
    }
    return true;
}

dogecoin_bool dogecoin_txindex_add_blockindex(dogecoin_txindex* txindex, dogecoin_blockindex* blockindex) {

    if (!txindex || !blockindex)
        return false;

    printf("size: %lu\n", sizeof *blockindex);
    cstring* record = cstr_new_sz(sizeof *blockindex + 1);
    dogecoin_blockindex_serialize(record, blockindex);

    if (!dogecoin_txindex_write_record(txindex, record, TXINDEX_DB_REC_TYPE_TX)) {
        printf("Writing txindex record failed\n");
        fprintf(stderr, "Writing txindex record failed\n");
    }
    cstr_free(record, true);
    dogecoin_txindex_flush(txindex);

    return true;
}

dogecoin_bool dogecoin_txindex_add_blockindex_move(dogecoin_txindex* txindex, dogecoin_blockindex* blockindex)
{
    dogecoin_txindex_add_blockindex(txindex, blockindex);
    dogecoin_txindex_add_blockindex_intern_move(txindex, blockindex); //hands memory management over to the binary tree
    return true;
}

void dogecoin_add_transaction(void *ctx, dogecoin_blockindex *pindex) {
    dogecoin_txindex *txindexdb = (dogecoin_txindex*)ctx;
    // dogecoin_txindex_add_blockindex_move(txindexdb, pindex);
    cstring* record = cstr_new_sz(sizeof *pindex + 1);
    dogecoin_blockindex_serialize(record, pindex);

    if (!dogecoin_txindex_write_record(txindexdb, record, TXINDEX_DB_REC_TYPE_TX)) {
        printf("Writing txindex record failed\n");
        fprintf(stderr, "Writing txindex record failed\n");
    }
    cstr_free(record, true);
    dogecoin_txindex_flush(txindexdb);
    // dogecoin_txindex_add_blockindex_intern_move(txindexdb, pindex); //hands memory management over to the binary tree
    unsigned int j = 0;
    for (; j < pindex->amount_of_txs; j++) {
        unsigned int i = 0;
        for (i = 0; i < pindex->txns[j]->vin->len; i++) {
            dogecoin_tx_in *tx_in = vector_idx(pindex->txns[j]->vin, i); 
            printf("tx_in prevout hash: %s\n", utils_uint8_to_hex(tx_in->prevout.hash, 32));
        }
        dogecoin_tx_free(pindex->txns[j]);
    }
}
