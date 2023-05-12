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
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

uint8_t TXINDEX_DB_REC_TYPE_TX = 1;

static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
static const unsigned char file_rec_magic[4] = {0xC8, 0xF2, 0x69, 0x1E}; /* record magic */
static const uint32_t current_version = 1;

int dogecoin_txid_compare(const void *l, const void *r)
{
    const dogecoin_txid *lm = l;
    const dogecoin_txid *lr = r;

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
 TXINDEX FUNCTIONS
 ==========================================================
*/
dogecoin_txid* dogecoin_txid_new()
{
    dogecoin_txid* txid;
    txid = dogecoin_calloc(1, sizeof(*txid));
    txid->height = 0;
    dogecoin_hash_clear(txid->hash);
    txid->tx = dogecoin_tx_new();
    return txid;
}

void dogecoin_txid_free(dogecoin_txid* txid)
{
    txid->height = 0;
    dogecoin_hash_clear(txid->hash);
    dogecoin_tx_free(txid->tx);
    dogecoin_free(txid);
}

void dogecoin_txid_serialize(cstring* s, const dogecoin_txid* txid)
{
    ser_u32(s, txid->height);
    ser_u256(s, txid->hash);
    dogecoin_tx_serialize(s, txid->tx);
}

dogecoin_bool dogecoin_txid_deserialize(dogecoin_txid* txid, struct const_buffer* buf)
{
    deser_u32(&txid->height, buf);
    deser_u256(txid->hash, buf);
    size_t consumed_length = 0;
    if (!dogecoin_tx_deserialize(buf->p, buf->len, txid->tx, &consumed_length)) {
        printf("tx deserialization error!\n");
        return false;
    }
    return deser_skip(buf, consumed_length);
}

/*
 ==========================================================
 TXINDEXDB FUNCTIONS
 ==========================================================
*/
dogecoin_txdb* dogecoin_txdb_new(const dogecoin_chainparams *params)
{
    dogecoin_txdb* db = dogecoin_calloc(1, sizeof(*db));
    db->chain = params;
    db->vec_txns = vector_new(10, dogecoin_free);
    db->txns_rbtree = 0;
    return db;
}

void dogecoin_txdb_free(dogecoin_txdb* db)
{
    if (!db)
        return;

    if (db->file) {
        fclose(db->file);
    }

    dogecoin_btree_tdestroy(db->txns_rbtree, dogecoin_free);

    if (db->vec_txns) {
        vector_free(db->vec_txns, true);
        db->vec_txns = NULL;
    }

    dogecoin_free(db);
}

void dogecoin_txdb_add_txid_intern_move(dogecoin_txdb *db, const dogecoin_txid *txid) {
    dogecoin_txid* index = dogecoin_btree_tfind(txid, &db->txns_rbtree, dogecoin_txid_compare);
    if (index) {
        // remove existing txid
        index = *(dogecoin_txid **)index;
        unsigned int i;
        for (i = 0; i < db->vec_txns->len; i++) {
            dogecoin_txid *txid_vec = vector_idx(db->vec_txns, i);
            if (txid_vec == index) {
                vector_remove_idx(db->vec_txns, i);
            }
        }
        // we do not really delete transactions
        dogecoin_btree_tdelete(index, &db->txns_rbtree, dogecoin_txid_compare);
        dogecoin_txid_free(index);
    }
    dogecoin_btree_tfind(txid, &db->txns_rbtree, dogecoin_txid_compare);
    vector_add(db->vec_txns, (dogecoin_txid *)txid);
}

dogecoin_bool dogecoin_txdb_create(dogecoin_txdb* db, const char* file_path, int *error)
{
    if (!db)
        return false;

    struct stat buffer;
    if (stat(file_path, &buffer) != 0) {
        *error = 1;
        return false;
    }

    db->file = fopen(file_path, "a+b");

    // write file-header-magic
    if (fwrite(file_hdr_magic, 4, 1, db->file) != 1) return false;

    // write version
    uint32_t v = htole32(current_version);
    if (fwrite(&v, sizeof(v), 1, db->file) != 1) return false;

    // write genesis
    if (fwrite(db->chain->genesisblockhash, sizeof(uint256), 1, db->file ) != 1) return false;

    dogecoin_file_commit(db->file);
    return true;
}

dogecoin_bool dogecoin_txdb_load(dogecoin_txdb* db, const char* file_path, int *error, dogecoin_bool *created)
{
    (void)(error);
    if (!db) { return false; }

    struct stat buffer;
    *created = true;
    if (stat(file_path, &buffer) == 0) *created = false;

    db->file = fopen(file_path, *created ? "a+b" : "r+b");

    if (*created) {
        if (!dogecoin_txdb_create(db, file_path, error)) {
            return false;
        }
    }
    else {
        // check file-header-magic, version and genesis
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)+sizeof(uint256)];
        if ((uint32_t)buffer.st_size < (uint32_t)(sizeof(buf)) || fread(buf, sizeof(buf), 1, db->file) != 1 || memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic)))
        {
            fprintf(stderr, "txid file: error reading database file\n");
            return false;
        }
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "txid file: unsupported file version\n");
            return false;
        }
        if (memcmp(buf+sizeof(file_hdr_magic)+sizeof(current_version), db->chain->genesisblockhash, sizeof(uint256)) != 0) {
            fprintf(stderr, "txid file: different network\n");
            return false;
        }
        // read
        while (!feof(db->file))
        {
            uint8_t buf[sizeof(file_rec_magic)];
            if (fread(buf, sizeof(buf), 1, db->file) != 1 ) {
                // no more record, break
                break;
            }
            if (memcmp(buf, file_rec_magic, sizeof(file_rec_magic))) {
                fprintf(stderr, "txid file: error reading record file (invalid magic). txid file is corrupt\n");
                return false;
            }
            uint32_t reclen = 0;
            if (!deser_varlen_from_file(&reclen, db->file)) return false;

            uint8_t rectype;
            if (fread(&rectype, 1, 1, db->file) != 1) return false;

            if (rectype == TXINDEX_DB_REC_TYPE_TX) {
                unsigned char* buf = dogecoin_uchar_vla(reclen);
                struct const_buffer cbuf = {buf, reclen};
                if (fread(buf, reclen, 1, db->file) != 1) {
                    return false;
                }

                dogecoin_txid *txid = dogecoin_txid_new();
                dogecoin_txid_deserialize(txid, &cbuf);
                dogecoin_txdb_add_txid_intern_move(db, txid); // hands memory management over to the binary tree
            } else {
                fseek(db->file, reclen, SEEK_CUR);
            }
        }
    }

    return true;
}

dogecoin_bool dogecoin_txdb_flush(dogecoin_txdb* db)
{
    dogecoin_file_commit(db->file);
    return true;
}

dogecoin_bool dogecoin_txdb_write_record(dogecoin_txdb *db, const cstring* record, uint8_t record_type) {
    // write record magic
    if (fwrite(file_rec_magic, 4, 1, db->file) != 1) return false;

    //write record len
    cstring *cstr_len = cstr_new_sz(4);
    ser_varlen(cstr_len, record->len);
    if (fwrite(cstr_len->str, cstr_len->len, 1, db->file) != 1) {
        cstr_free(cstr_len, true);
        return false;
    }
    cstr_free(cstr_len, true);

    // write record type & record payload
    if (fwrite(&record_type, 1, 1, db->file) != 1 ||
        fwrite(record->str, record->len, 1, db->file) != 1) {
        return false;
    }
    return true;
}

dogecoin_bool dogecoin_txdb_add_txid(dogecoin_txdb* db, dogecoin_txid* txid) {

    if (!db || !txid)
        return false;

    cstring* record = cstr_new_sz(1024);
    dogecoin_txid_serialize(record, txid);

    if (!dogecoin_txdb_write_record(db, record, TXINDEX_DB_REC_TYPE_TX)) {
        fprintf(stderr, "Writing txid record failed\n");
    }
    cstr_free(record, true);
    dogecoin_file_commit(db->file);
    return true;
}

dogecoin_bool dogecoin_txdb_add_txid_move(dogecoin_txdb* db, dogecoin_txid* txid)
{
    dogecoin_txdb_add_txid(db, txid);
    dogecoin_txdb_add_txid_intern_move(db, txid); //hands memory management over to the binary tree
    return true;
}

void dogecoin_add_transaction(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_txid *txid) {
    dogecoin_txdb *db = (dogecoin_txdb*)ctx;
    dogecoin_tx_copy(txid->tx, tx);
    dogecoin_txdb_add_txid_move(db, txid);
}
