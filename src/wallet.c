/*

 The MIT License (MIT)

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

#include <assert.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _MSC_VER
#  include <unistd.h>
#endif

#define COINBASE_MATURITY 100

#include <dogecoin/crypto/base58.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/crypto/common.h>
#include <dogecoin/serialize.h>
#include <dogecoin/wallet.h>
#include <dogecoin/utils.h>

/* Creating a new logdb object. */
#include <logdb/logdb.h>
#include <logdb/logdb_rec.h>
#include <logdb/red_black_tree.h>

uint8_t WALLET_DB_REC_TYPE_MASTERKEY = 0;
uint8_t WALLET_DB_REC_TYPE_PUBKEYCACHE = 1;
uint8_t WALLET_DB_REC_TYPE_TX = 2;

static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
static const uint32_t current_version = 1;

static const char hdkey_key[] = "hdkey";
static const char hdmasterkey_key[] = "mstkey";
static const char tx_key[] = "tx";

/* static interface */
static logdb_memmapper dogecoin_wallet_db_mapper = {
    dogecoin_wallet_logdb_append_cb,
    NULL,
    NULL,
    NULL,
    NULL
};

/* ====================== */
/* compare btree callback */
/* ====================== */
/**
 * "Compare two HDNode structs by comparing their public key hashes."
 * 
 * The function is used to sort the HDNode structs in the wallet
 * 
 * @param l pointer to the first item in the array
 * @param r The number of bits to use for the private key.
 * 
 * @return Nothing.
 */
int dogecoin_wallet_hdnode_compare(const void *l, const void *r)
{
    const dogecoin_wallet_hdnode *lm = l;
    const dogecoin_wallet_hdnode *lr = r;

    uint8_t *pubkeyA = (uint8_t *)lm->pubkeyhash;
    uint8_t *pubkeyB = (uint8_t *)lr->pubkeyhash;

    /* byte per byte compare */
    /* TODO: switch to memcmp */
    for (unsigned int i = 0; i < sizeof(uint160); i++) {
        uint8_t iA = pubkeyA[i];
        uint8_t iB = pubkeyB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}

/**
 * The function compares the hashes of two transactions
 * 
 * @param l the left item to compare
 * @param r The pointer to the right-hand side of the comparison.
 * 
 * @return Nothing.
 */
int dogecoin_wtx_compare(const void *l, const void *r)
{
    const dogecoin_wtx *lm = l;
    const dogecoin_wtx *lr = r;

    uint8_t *hashA = (uint8_t *)lm->tx_hash_cache;
    uint8_t *hashB = (uint8_t *)lr->tx_hash_cache;

    /* byte per byte compare */
    for (unsigned int i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}

/* ==================== */
/* txes rbtree callback */
/* ==================== */
/**
 * This function is called by the rbtree when it needs to free a key
 * 
 * @param a The key to be freed.
 */
void dogecoin_rbtree_wtxes_free_key(void* a) {
    /* keys are cstrings that needs to be released by the rbtree */
    cstring *key = (cstring *)a;
    cstr_free(key, true);
}

/**
 * It takes a pointer to a dogecoin_wtx and frees it
 * 
 * @param a the value to be freed
 */
void dogecoin_rbtree_wtxes_free_value(void *a){
    /* free the wallet transaction */
    dogecoin_wtx *wtx = (dogecoin_wtx *)a;
    dogecoin_wallet_wtx_free(wtx);
}

/**
 * Given two pointers to cstrings, compare the cstrings
 * 
 * @param a a pointer to a cstring
 * @param b The tree to search
 * 
 * @return Nothing.
 */
int dogecoin_rbtree_wtxes_compare(const void* a,const void* b) {
    return cstr_compare((cstring *)a, (cstring *)b);
}


/* ====================== */
/* hdkeys rbtree callback */
/* ====================== */
/**
 * This function is called by the rbtree when it needs to free a key
 * 
 * @param a The key to be freed.
 */
void dogecoin_rbtree_hdkey_free_key(void* a) {
    /* keys are cstrings that needs to be released by the rbtree */
    cstring *key = (cstring *)a;
    cstr_free(key, true);
}

/**
 * It takes a pointer to a dogecoin_hdnode and frees it
 * 
 * @param a The key to be freed.
 */
void dogecoin_rbtree_hdkey_free_value(void *a){
    /* free the hdnode */
    dogecoin_hdnode *node = (dogecoin_hdnode *)a;
    dogecoin_hdnode_free(node);
}

/**
 * Given two keys, return a negative number if the first key is smaller, a positive number if the first
 * key is larger, and 0 if the keys are equal
 * 
 * @param a The first parameter is a pointer to the first key to compare.
 * @param b The first parameter is a pointer to the root of the tree.
 * 
 * @return Nothing.
 */
int dogecoin_rbtree_hdkey_compare(const void* a,const void* b) {
    return cstr_compare((cstring *)a, (cstring *)b);
}

/*
 ==========================================================
 WALLET TRANSACTION (WTX) FUNCTIONS
 ==========================================================
*/

/**
 * It allocates memory for a new dogecoin_wtx object and initializes it.
 * 
 * @return A pointer to a new dogecoin_wtx object.
 */
dogecoin_wtx* dogecoin_wallet_wtx_new()
{
    dogecoin_wtx* wtx;
    wtx = dogecoin_calloc(1, sizeof(*wtx)); // calloc(1, sizeof(*wtx));
    wtx->height = 0;
    wtx->tx = dogecoin_tx_new();

    return wtx;
}

/**
 * Create a new dogecoin_wtx object and copy the transaction data from the given dogecoin_wtx object
 * into it
 * 
 * @param wtx the transaction to copy
 * 
 * @return A copy of the transaction.
 */
dogecoin_wtx* dogecoin_wallet_wtx_copy(dogecoin_wtx* wtx)
{
    dogecoin_wtx* wtx_copy;
    wtx_copy = dogecoin_wallet_wtx_new();
    dogecoin_tx_copy(wtx_copy->tx, wtx->tx);

    return wtx_copy;
}

/**
 * It takes a pointer to a dogecoin_wtx struct, and frees the memory allocated to the dogecoin_wtx
 * struct
 * 
 * @param wtx The transaction to free.
 */
void dogecoin_wallet_wtx_free(dogecoin_wtx* wtx)
{
    dogecoin_tx_free(wtx->tx);
    dogecoin_free(wtx); // free(wtx);
}

/**
 * This function serializes a dogecoin_wtx object into a cstring
 * 
 * @param s The string to write the serialized data to.
 * @param wtx the transaction object
 */
void dogecoin_wallet_wtx_serialize(cstring* s, const dogecoin_wtx* wtx)
{
    ser_u32(s, wtx->height);
    ser_u256(s, wtx->tx_hash_cache);
    /* TODO: convert mock tx data to remove witnesses and set allow_witness below to false! */
    /* dogecoin does not support segwit but is segwit aware */
    dogecoin_tx_serialize(s, wtx->tx, true); // dogecoin_tx_serialize(s, wtx->tx);
}

/**
 * The function deserializes a transaction from a buffer into a dogecoin_wtx struct
 * 
 * @param wtx the dogecoin_wtx struct to be filled in
 * @param buf The buffer containing the serialized transaction.
 * 
 * @return The return value is a boolean value indicating success or failure.
 */
dogecoin_bool dogecoin_wallet_wtx_deserialize(dogecoin_wtx* wtx, struct const_buffer* buf)
{
    deser_u32(&wtx->height, buf);
    deser_u256(wtx->tx_hash_cache, buf);
    /* TODO: convert mock tx data to remove witnesses and set allow_witness below to false! */
    /* dogecoin does not support segwit but is segwit aware */
    return dogecoin_tx_deserialize(buf->p, buf->len, wtx->tx, NULL, true); // return dogecoin_tx_deserialize(buf->p, buf->len, wtx->tx);
}

/*
 ==========================================================
 WALLET HDNODE (WALLET_HDNODE) FUNCTIONS
 ==========================================================
*/

/**
 * It creates a new dogecoin_wallet_hdnode object and returns a pointer to it
 * 
 * @return A pointer to a new dogecoin_wallet_hdnode object.
 */
dogecoin_wallet_hdnode* dogecoin_wallet_hdnode_new()
{
    dogecoin_wallet_hdnode* whdnode;
    whdnode = dogecoin_calloc(1, sizeof(*whdnode));
    whdnode->hdnode = dogecoin_hdnode_new();
    whdnode->pubkeyhash;
    return whdnode;
}

/**
 * It takes a pointer to a dogecoin_wallet_hdnode, and frees the memory associated with it
 * 
 * @param whdnode The pointer to the dogecoin_wallet_hdnode struct.
 */
void dogecoin_wallet_hdnode_free(dogecoin_wallet_hdnode* whdnode)
{
    dogecoin_hdnode_free(whdnode->hdnode);
    dogecoin_free(whdnode);
}

/**
 * It takes a dogecoin_wallet_hdnode, and serializes it into a string
 * 
 * @param s The serialization buffer
 * @param params The chainparams struct.
 * @param whdnode The dogecoin_wallet_hdnode object to serialize
 */
void dogecoin_wallet_hdnode_serialize(cstring* s, const dogecoin_chainparams *params, const dogecoin_wallet_hdnode* whdnode)
{
    ser_bytes(s, whdnode->pubkeyhash, sizeof(uint160));
    char strbuf[196];
    dogecoin_hdnode_serialize_private(whdnode->hdnode, params, strbuf, sizeof(strbuf));
    ser_str(s, strbuf, sizeof(strbuf));
}

/**
 * It takes a buffer and a pointer to a dogecoin_wallet_hdnode struct. It deserializes the buffer into
 * the struct
 * 
 * @param whdnode the dogecoin_wallet_hdnode object to be filled in
 * @param params The chainparams struct.
 * @param buf The buffer to deserialize from.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_wallet_hdnode_deserialize(dogecoin_wallet_hdnode* whdnode, const dogecoin_chainparams *params, struct const_buffer* buf) {
    deser_bytes(&whdnode->pubkeyhash, buf, sizeof(uint160));
    char strbuf[196];
    if (!deser_str(strbuf, buf, sizeof(strbuf))) return false;
    if (!dogecoin_hdnode_deserialize(strbuf, params, whdnode->hdnode)) return false;
    return true;
}

/*
 ==========================================================
 WALLET OUTPUT (prev wtx + n) FUNCTIONS
 ==========================================================
 */

/**
 * Create a new dogecoin_output object and return it
 * 
 * @return A pointer to a dogecoin_output struct.
 */
dogecoin_output* dogecoin_wallet_output_new()
{
    dogecoin_output* output;
    output = dogecoin_calloc(1, sizeof(*output)); // calloc(1, sizeof(*output));
    output->i = 0;
    output->wtx = dogecoin_wallet_wtx_new();

    return output;
}

/**
 * It takes a pointer to a dogecoin_output struct, and frees the memory allocated to it
 * 
 * @param output The output to free.
 */
void dogecoin_wallet_output_free(dogecoin_output* output)
{
    dogecoin_wallet_wtx_free(output->wtx);
    dogecoin_free(output); // free(output);
}

/*
 ==========================================================
 WALLET CORE FUNCTIONS
 ==========================================================
 */
/**
 * The function creates a new dogecoin wallet
 * 
 * @param params The chainparams structure that contains the chain parameters.
 * 
 * @return A dogecoin_wallet object.
 */
dogecoin_wallet* dogecoin_wallet_new(const dogecoin_chainparams *params)
{
    dogecoin_wallet* wallet;
    wallet = dogecoin_calloc(1, sizeof(*wallet)); // calloc(1, sizeof(*wallet));
    // wallet->db = logdb_new();
    // logdb_set_memmapper(wallet->db, &dogecoin_wallet_db_mapper, wallet);
    wallet->masterkey = NULL;
    wallet->chain = params; // &dogecoin_chain_main;
    wallet->spends = vector_new(10, free);

    wallet->wtxes_rbtree = 0; // RBTreeCreate(dogecoin_rbtree_wtxes_compare,dogecoin_rbtree_wtxes_free_key,dogecoin_rbtree_wtxes_free_value,NULL,NULL);
    wallet->hdkeys_rbtree = 0; // RBTreeCreate(dogecoin_rbtree_hdkey_compare,dogecoin_rbtree_hdkey_free_key,dogecoin_rbtree_hdkey_free_value,NULL,NULL);
    return wallet;
}

/**
 * It frees the memory allocated to the wallet
 * 
 * @param wallet the wallet to free
 * 
 * @return Nothing
 */
void dogecoin_wallet_free(dogecoin_wallet* wallet)
{
    if (!wallet) {
        return;
    }

    // if (wallet->db)
    // {
    //     logdb_free(wallet->db);
    //     wallet->db = NULL;
    // }

    if (wallet->dbfile) {
        fclose(wallet->dbfile);
        wallet->dbfile = NULL;
    }

    if (wallet->spends) {
        vector_free(wallet->spends, true);
        wallet->spends = NULL;
    }

    if (wallet->masterkey) {
        dogecoin_free(wallet->masterkey); // free(wallet->masterkey);
        wallet->masterkey = NULL;
    }

    dogecoin_btree_tdestroy(wallet->wtxes_rbtree, dogecoin_free); // RBTreeDestroy(wallet->wtxes_rbtree);
    dogecoin_btree_tdestroy(wallet->hdkeys_rbtree, dogecoin_free); // RBTreeDestroy(wallet->hdkeys_rbtree);

    dogecoin_free(wallet); // free(wallet);
}

/**
 * This function is called by the logdb when it is loading the database. 
 * used to load the masterkey and the hdkeys.
 * 
 * @param ctx The wallet object.
 * @param load_phase If true, this is the first time the wallet is being loaded.
 * @param rec The record that was just read.
 */
void dogecoin_wallet_logdb_append_cb(void* ctx, logdb_bool load_phase, logdb_record* rec)
{
   dogecoin_wallet* wallet = (dogecoin_wallet*)ctx;
   if (load_phase) {
       /* Checking if the record is a wallet master key record and if it is a write record. */
       if (wallet->masterkey == NULL && rec->mode == RECORD_TYPE_WRITE && rec->key->len > strlen(hdmasterkey_key) && memcmp(rec->key->str, hdmasterkey_key, strlen(hdmasterkey_key)) == 0) {
           /* Creating a new HDNode object. */
           wallet->masterkey = dogecoin_hdnode_new();
           /* Deserializing the HDNode into the wallet. */
           dogecoin_hdnode_deserialize(rec->value->str, wallet->chain, wallet->masterkey);
       }
       /* Checking if the key is the same as the one we are looking for. */
       if (rec->key->len == strlen(hdkey_key) + sizeof(uint160) && memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0) {
           dogecoin_hdnode* hdnode = dogecoin_hdnode_new();
           dogecoin_hdnode_deserialize(rec->value->str, wallet->chain, hdnode);

           /* rip out the hash from the record key (avoid re-SHA256) */
           cstring* keyhash160 = cstr_new_buf(rec->key->str + strlen(hdkey_key), sizeof(uint160));

           /* add hdnode to the rbtree */
           RBTreeInsert(wallet->hdkeys_rbtree, keyhash160, hdnode);

           if (hdnode->child_num + 1 > wallet->next_childindex)
               wallet->next_childindex = hdnode->child_num + 1;
       }

       /* Checking if the key of the record is the same as the key of the transaction. */
       if (rec->key->len == strlen(tx_key) + SHA256_DIGEST_LENGTH && memcmp(rec->key->str, tx_key, strlen(tx_key)) == 0) {
           dogecoin_wtx* wtx = dogecoin_wallet_wtx_new();
           struct const_buffer buf = {rec->value->str, rec->value->len};

           /* deserialize transaction */
           dogecoin_wallet_wtx_deserialize(wtx, &buf);

           /* rip out the hash from the record key (avoid re-SHA256) */
           cstring* wtxhash = cstr_new_buf(rec->key->str + strlen(tx_key), SHA256_DIGEST_LENGTH);

           /* add wtx to the rbtree */
           RBTreeInsert(wallet->wtxes_rbtree, wtxhash, wtx);

           /* add to spends */
           dogecoin_wallet_add_to_spent(wallet, wtx);
       }
   }
}

// void dogecoin_wallet_logdb_append_cb(void* ctx, logdb_bool load_phase, logdb_record *rec)
// {
//     dogecoin_wallet* wallet = (dogecoin_wallet*)ctx;
//     if (load_phase)
//     {
//         if (wallet->masterkey == NULL && rec->mode == RECORD_TYPE_WRITE && rec->key->len > strlen(hdmasterkey_key) && memcmp(rec->key->str, hdmasterkey_key, strlen(hdmasterkey_key)) == 0)
//         {
//             wallet->masterkey = dogecoin_hdnode_new();
//             dogecoin_hdnode_deserialize(rec->value->str, wallet->chain, wallet->masterkey);
//         }
//         if (rec->key->len == strlen(hdkey_key)+20 && memcmp(rec->key->str, hdkey_key, strlen(hdkey_key)) == 0)
//         {
//             dogecoin_hdnode *hdnode = dogecoin_hdnode_new();
//             dogecoin_hdnode_deserialize(rec->value->str, wallet->chain, hdnode);

//             /* rip out the hash from the record key (avoid re-SHA256) */
//             cstring *keyhash160 = cstr_new_buf(rec->key->str+strlen(hdkey_key),20);

//             /* add hdnode to the rbtree */
//             RBTreeInsert(wallet->hdkeys_rbtree,keyhash160,hdnode);

//             if (hdnode->child_num+1 > wallet->next_childindex)
//                 wallet->next_childindex = hdnode->child_num+1;
//         }

//         if (rec->key->len == strlen(tx_key)+SHA256_DIGEST_LENGTH && memcmp(rec->key->str, tx_key, strlen(tx_key)) == 0)
//         {
//             dogecoin_wtx *wtx = dogecoin_wallet_wtx_new();
//             struct const_buffer buf = {rec->value->str, rec->value->len};

//             /* deserialize transaction */
//             dogecoin_wallet_wtx_deserialize(wtx, &buf);

//             /* rip out the hash from the record key (avoid re-SHA256) */
//             cstring *wtxhash = cstr_new_buf(rec->key->str+strlen(tx_key),SHA256_DIGEST_LENGTH);

//             /* add wtx to the rbtree */
//             RBTreeInsert(wallet->wtxes_rbtree,wtxhash,wtx);

//             /* add to spends */
//             dogecoin_wallet_add_to_spent(wallet, wtx);
//         }
//     }
// }

// dogecoin_bool dogecoin_wallet_load(dogecoin_wallet *wallet, const char *file_path, enum logdb_error *error)
// {
//     if (!wallet)
//         return false;

//     if (!wallet->db)
//         return false;

//     if (wallet->db->file)
//     {
//         *error = LOGDB_ERROR_FILE_ALREADY_OPEN;
//         return false;
//     }

//     struct stat buffer;
//     dogecoin_bool create = true;
//     if (stat(file_path, &buffer) == 0)
//         create = false;

//     enum logdb_error db_error = 0;
//     if (!logdb_load(wallet->db, file_path, create, &db_error))
//     {
//         *error = db_error;
//         return false;

/**
 * Loads the wallet from the file
 * 
 * @param wallet the wallet to load
 * @param file_path The path to the wallet file.
 * @param error pointer to an int, which will be set to 0 if the function succeeds, or non-zero if it
 * fails.
 * @param created a pointer to a boolean that will be set to true if the file was created, false if it
 * already existed.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_wallet_load(dogecoin_wallet* wallet, const char* file_path, int *error, dogecoin_bool *created)
{
    (void)(error);
    if (!wallet)
        return false;

    struct stat buffer;
    *created = true;
    if (stat(file_path, &buffer) == 0)
        *created = false;

    wallet->dbfile = fopen(file_path, *created ? "a+b" : "r+b");

    if (*created) {
        // write file-header-magic
        if (fwrite(file_hdr_magic, 4, 1, wallet->dbfile) != 1) return false;

        // write version
        uint32_t v = htole32(current_version);
        if (fwrite(&v, sizeof(v), 1, wallet->dbfile) != 1) return false;

        // write genesis
        if (fwrite(wallet->chain->genesisblockhash, sizeof(uint256), 1, wallet->dbfile ) != 1) return false;

        dogecoin_file_commit(wallet->dbfile);
    } else {
        // check file-header-magic, version and genesis
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)+sizeof(uint256)];
        printf("buffer: %d\n", (uint32_t)buffer.st_size);
        if ((uint32_t)buffer.st_size < (uint32_t)(sizeof(buf)) || fread(buf, sizeof(buf), 1, wallet->dbfile ) != 1 || memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic)))
        {
            fprintf(stderr, "Wallet file: error reading database file\n");
            return false;
        }
        
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "Wallet file: unsupported file version\n");
            return false;
        }

        if (memcmp(buf+sizeof(file_hdr_magic)+sizeof(current_version), wallet->chain->genesisblockhash, sizeof(uint256)) != 0) {
            fprintf(stderr, "Wallet file: different network\n");
            return false;
        }
        // read

        while (!feof(wallet->dbfile))
        {
            uint8_t rectype;
            if (fread(&rectype, 1, 1, wallet->dbfile) != 1) {
                // no more record, break
                break;
            }

            if (rectype == WALLET_DB_REC_TYPE_MASTERKEY) {
                uint32_t len;
                char strbuf[196];
                memset(strbuf, 0, 196);
                if (!deser_varlen_from_file(&len, wallet->dbfile)) return false;
                if (len > sizeof(strbuf)) { return false; }
                if (fread(strbuf, len, 1, wallet->dbfile) != 1) return false;
                wallet->masterkey = dogecoin_hdnode_new();
                dogecoin_hdnode_deserialize(strbuf, wallet->chain, wallet->masterkey);
            }

            if (rectype == WALLET_DB_REC_TYPE_PUBKEYCACHE) {
                uint32_t len;

                dogecoin_wallet_hdnode *whdnode = dogecoin_wallet_hdnode_new();
                if (fread(whdnode->pubkeyhash, sizeof(uint160), 1, wallet->dbfile) != 1) {
                    dogecoin_wallet_hdnode_free(whdnode);
                    return false;
                }

                // read the varint for the stringlength
                char strbuf[1024];
                if (!deser_varlen_from_file(&len, wallet->dbfile)) {
                    dogecoin_wallet_hdnode_free(whdnode);
                    return false;
                }
                if (len > sizeof(strbuf)) { return false; }
                if (fread(strbuf, len, 1, wallet->dbfile) != 1) {
                    dogecoin_wallet_hdnode_free(whdnode);
                    return false;
                }
                // deserialize the hdnode
                if (!dogecoin_hdnode_deserialize(strbuf, wallet->chain, whdnode->hdnode)) {
                    dogecoin_wallet_hdnode_free(whdnode);
                    return false;
                }

                // add the node to the binary tree
                tsearch(whdnode, &wallet->hdkeys_rbtree, dogecoin_wallet_hdnode_compare);

            }
        }
    }

    return true;
}

/**
 * Flush the database to disk
 * 
 * @param wallet the wallet to flush
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_wallet_flush(dogecoin_wallet* wallet)
{
    dogecoin_file_commit(wallet->dbfile);
    return true; // return logdb_flush(wallet->db);
}

/**
 * The function takes a dogecoin_hdnode and stores it in the wallet database
 * 
 * @param wallet the wallet to set the master key for
 * @param masterkey The master key to use.
 * 
 * @return Nothing.
 */
void dogecoin_wallet_set_master_key_copy(dogecoin_wallet* wallet, dogecoin_hdnode* masterkey)
{
    if (!masterkey) {
        return;
    }

    if (wallet->masterkey != NULL) {
        //changing the master key should not be done,...
        //anyways, we are going to accept that at this point
        //consuming application needs to take care about that
        dogecoin_hdnode_free(wallet->masterkey);
        wallet->masterkey = NULL;
    }
    wallet->masterkey = dogecoin_hdnode_copy(masterkey);
    // //serialize and store node
    // char str[128];
    // dogecoin_hdnode_serialize_private(wallet->masterkey, wallet->chain, str, sizeof(str));

    // uint8_t key[strlen(hdmasterkey_key)+SHA256_DIGEST_LENGTH];
    // memcpy(key, hdmasterkey_key, strlen(hdmasterkey_key));
    // dogecoin_hash(wallet->masterkey->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH, key+strlen(hdmasterkey_key));

    // struct buffer buf_key = {key, sizeof(key)};
    // struct buffer buf_val = {str, strlen(str)};
    // logdb_append(wallet->db, &buf_key, &buf_val);
    cstring* record = cstr_new_sz(256);
    ser_bytes(record, &WALLET_DB_REC_TYPE_MASTERKEY, 1);
    char strbuf[196];
    dogecoin_hdnode_serialize_private(wallet->masterkey, wallet->chain, strbuf, sizeof(strbuf));
    ser_str(record, strbuf, sizeof(strbuf));

    if (fwrite(record->str, record->len, 1, wallet->dbfile) != 1) {
        fprintf(stderr, "Writing master private key record failed\n");
    }
    cstr_free(record, true);

    dogecoin_file_commit(wallet->dbfile);
}

/**
 * The function takes a wallet and a child index, and returns a dogecoin_wallet_hdnode object. The
 * function then creates a new dogecoin_wallet_hdnode object, copies the masterkey into it, and then
 * calls dogecoin_hdnode_private_ckd() to generate the child key. The function then generates the
 * public key hash from the child key, and then adds the new dogecoin_wallet_hdnode object to the
 * binary tree. The function then serializes the new dogecoin_wallet_hdnode object and writes it to the
 * database file. The function then returns the new dogecoin_wallet_hdnode object
 * 
 * @param wallet the wallet object
 * 
 * @return A dogecoin_wallet_hdnode object.
 */
dogecoin_wallet_hdnode* dogecoin_wallet_next_key(dogecoin_wallet* wallet)
{
    if (!wallet || !wallet->masterkey)
        return NULL;

    //for now, only m/k is possible
    dogecoin_wallet_hdnode *whdnode = dogecoin_wallet_hdnode_new();
    dogecoin_hdnode_free(whdnode->hdnode);
    whdnode->hdnode = dogecoin_hdnode_copy(wallet->masterkey);
    dogecoin_hdnode_private_ckd(whdnode->hdnode, wallet->next_childindex);
    dogecoin_hdnode_get_hash160(whdnode->hdnode, whdnode->pubkeyhash);

    //add it to the binary tree
    // tree manages memory
    tsearch(whdnode, &wallet->hdkeys_rbtree, dogecoin_wallet_hdnode_compare);

    //serialize and store node
    cstring* record = cstr_new_sz(256);
    ser_bytes(record, &WALLET_DB_REC_TYPE_PUBKEYCACHE, 1);
    dogecoin_wallet_hdnode_serialize(record, wallet->chain, whdnode);

    if (fwrite(record->str, record->len, 1, wallet->dbfile) != 1) {
        fprintf(stderr, "Writing childkey failed\n");
    }
    cstr_free(record, true);

    dogecoin_file_commit(wallet->dbfile);

    //increase the in-memory counter (cache)
    wallet->next_childindex++;

    return whdnode;
}

/**
 * Given a dogecoin_wallet, return a vector of addresses
 * 
 * @param wallet the wallet to get addresses from
 * @param addr_out The vector to store the addresses in.
 * 
 * @return A vector of strings.
 */
void dogecoin_wallet_get_addresses(dogecoin_wallet* wallet, vector* addr_out)
{
    (void)(wallet);
    (void)(addr_out);
    // rb_red_blk_node* hdkey_rbtree_node;

    // if (!wallet) return;

    // while((hdkey_rbtree_node = rbtree_enumerate_next(wallet->hdkeys_rbtree)))
    // {
    //     cstring *key = hdkey_rbtree_node->key;
    //     uint8_t hash160[21];
    //     hash160[0] = wallet->chain->b58prefix_pubkey_address;
    //     memcpy(hash160+1, key->str, 20);

    //     size_t addrsize = 98;
    //     char *addr = calloc(1, addrsize);
    //     dogecoin_base58_encode_check(hash160, 21, addr, addrsize);
    //     vector_add(addr_out, addr);
    // }
}

/**
 * Given a wallet and a public key hash, find the corresponding HD node
 * 
 * @param wallet the wallet to search
 * @param search_addr the address to search for
 * 
 * @return A pointer to the dogecoin_hdnode.
 */
dogecoin_wallet_hdnode* dogecoin_wallet_find_hdnode_byaddr(dogecoin_wallet* wallet, const char* search_addr) // dogecoin_hdnode * 
{
    if (!wallet || !search_addr)
        return NULL;

    // uint8_t hashdata[strlen(search_addr)];
    // memset(hashdata, 0, 20);
    // dogecoin_base58_decode_check(search_addr, hashdata, strlen(search_addr));
    uint8_t *hashdata = (uint8_t *)dogecoin_malloc(strlen(search_addr));
    memset(hashdata, 0, sizeof(uint160));
    int outlen = dogecoin_base58_decode_check(search_addr, hashdata, strlen(search_addr));
    if (outlen == 0) {
        dogecoin_free(hashdata);
        return NULL;
    }

    dogecoin_wallet_hdnode* whdnode_search;
    whdnode_search = dogecoin_calloc(1, sizeof(*whdnode_search));
    memcpy(whdnode_search->pubkeyhash, hashdata+1, sizeof(uint160));

    dogecoin_wallet_hdnode *needle = tfind(whdnode_search, &wallet->hdkeys_rbtree, dogecoin_wallet_hdnode_compare); /* read */
    if (needle) {
        needle = *(dogecoin_wallet_hdnode **)needle;
    }
    dogecoin_free(whdnode_search);
    // cstring keyhash160;
    // keyhash160.str = (char *)hashdata+1;
    // keyhash160.len = 20;
    // rb_red_blk_node* node = RBExactQuery(wallet->hdkeys_rbtree, &keyhash160);
    // if (node && node->info)
    //     return (dogecoin_hdnode *)node->info;
    // else
    //     return NULL;
    dogecoin_free(hashdata);
    return needle;
}

/**
 * Adds a transaction to the wallet
 * 
 * @param wallet the wallet to add the wtx to
 * @param wtx the wtx to add
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_wallet_add_wtx_move(dogecoin_wallet* wallet, dogecoin_wtx* wtx) // dogecoin_wallet_add_wtx
{
    if (!wallet || !wtx)
        return false;

    cstring* record = cstr_new_sz(1024); // cstring* txser = cstr_new_sz(1024);
    ser_bytes(record, &WALLET_DB_REC_TYPE_TX, 1); // dogecoin_wallet_wtx_serialize(txser, wtx);
    dogecoin_wallet_wtx_serialize(record, wtx);

    // uint8_t key[strlen(tx_key)+SHA256_DIGEST_LENGTH];
    // memcpy(key, tx_key, strlen(tx_key));
    // dogecoin_hash((const uint8_t*)txser->str, txser->len, key+strlen(tx_key));

    // struct buffer buf_key = {key, sizeof(key)};
    // struct buffer buf_val = {txser->str, txser->len};
    // logdb_append(wallet->db, &buf_key, &buf_val);
    if (fwrite(record->str, record->len, 1, wallet->dbfile) ) {
        fprintf(stderr, "Writing master private key record failed\n");
    }
    cstr_free(record, true); // cstr_free(txser, true);

    //add to spends
    dogecoin_wallet_add_to_spent(wallet, wtx);

    //add it to the binary tree
    dogecoin_wtx* checkwtx = tsearch(wtx, &wallet->wtxes_rbtree, dogecoin_wtx_compare);
    if (checkwtx) {
        // remove existing wtx
        checkwtx = *(dogecoin_wtx **)checkwtx;
        tdelete(checkwtx, &wallet->wtxes_rbtree, dogecoin_wtx_compare);
        dogecoin_wallet_wtx_free(checkwtx);

        // insert again
        dogecoin_wtx* checkwtx = tsearch(wtx, &wallet->wtxes_rbtree, dogecoin_wtx_compare);
    }

    return true;
}

/**
 * "Check if the wallet has the private key for the given public key hash."
 * 
 * The function is pretty simple. It first checks if the wallet has been initialized. If not, it
 * returns false
 * 
 * @param wallet the wallet to search
 * @param hash160 The hash160 of the public key.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_wallet_have_key(dogecoin_wallet* wallet, uint160 hash160) // uint8_t *hash160
{
    if (!wallet)
        return false;

    dogecoin_wallet_hdnode* whdnode_search;
    whdnode_search = dogecoin_calloc(1, sizeof(*whdnode_search));
    memcpy(whdnode_search->pubkeyhash, hash160, sizeof(uint160));

    dogecoin_wallet_hdnode *needle = tfind(whdnode_search, &wallet->hdkeys_rbtree, dogecoin_wallet_hdnode_compare); /* read */
    if (needle) {
        needle = *(dogecoin_wallet_hdnode **)needle;
    }
    dogecoin_free(whdnode_search);

    return (needle != NULL);
    // cstring keyhash160;
    // keyhash160.str = (char *)hash160;
    // keyhash160.len = 20;
    // rb_red_blk_node* node = RBExactQuery(wallet->hdkeys_rbtree, &keyhash160);
    // if (node && node->info)
    //     return true;

    // return false;
}

/**
 * "Get the balance of the wallet."
 * 
 * The function is pretty simple. It iterates over the rbtree of wtxes, and adds up the credit of each
 * wtx
 * 
 * @param wallet the wallet to get the balance for
 * 
 * @return The balance of the wallet.
 */
int64_t dogecoin_wallet_get_balance(dogecoin_wallet* wallet)
{
    rb_red_blk_node* hdkey_rbtree_node;
    int64_t credit = 0;

    if (!wallet)
        return false;

    // enumerate over the rbtree, calculate balance
    while((hdkey_rbtree_node = rbtree_enumerate_next(wallet->wtxes_rbtree)))
    {
        dogecoin_wtx *wtx = hdkey_rbtree_node->info;
        credit += dogecoin_wallet_wtx_get_credit(wallet, wtx);
    }

    return credit;
}

/**
 * Given a transaction, return the amount of money that the transaction is sending to the wallet
 * 
 * @param wallet The wallet to check.
 * @param wtx The transaction object.
 * 
 * @return The amount of coins that are being spent by this transaction.
 */
int64_t dogecoin_wallet_wtx_get_credit(dogecoin_wallet* wallet, dogecoin_wtx* wtx)
{
    int64_t credit = 0;

    if (dogecoin_tx_is_coinbase(wtx->tx) &&
        (wallet->bestblockheight < COINBASE_MATURITY || wtx->height > wallet->bestblockheight - COINBASE_MATURITY))
        return credit;

    uint256 hash;
    dogecoin_tx_hash(wtx->tx, hash);
    unsigned int i = 0;
    if (wtx->tx->vout) {
        for (i = 0; i < wtx->tx->vout->len; i++) {
            dogecoin_tx_out* tx_out;
            tx_out = vector_idx(wtx->tx->vout, i);

            if (!dogecoin_wallet_is_spent(wallet, hash, i))
            {
                if (dogecoin_wallet_txout_is_mine(wallet, tx_out))
                    credit += tx_out->value;
            }
        }
    }
    return credit;
}

/**
 * If the script_pubkey is a standard pay-to-pubkey-hash script, and the wallet has the private key for
 * the corresponding pubkey, then the txout is yours
 * 
 * @param wallet the wallet to check
 * @param tx_out The transaction output to check.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_wallet_txout_is_mine(dogecoin_wallet* wallet, dogecoin_tx_out* tx_out)
{
    if (!wallet || !tx_out) return false;

    dogecoin_bool ismine = false;

    vector* vec = vector_new(16, free);
    enum dogecoin_tx_out_type type2 = dogecoin_script_classify(tx_out->script_pubkey, vec);

    //TODO: Multisig, etc.
    if (type2 == DOGECOIN_TX_PUBKEYHASH)
    {
        //TODO: find a better format for vector elements (not a pure pointer)
        uint8_t* hash160 = vector_idx(vec, 0);
        if (dogecoin_wallet_have_key(wallet, hash160))
            ismine = true;
    }

    vector_free(vec, true);

    return ismine;
}

/**
 * If the transaction has any outputs, check if any of them are ours
 * 
 * @param wallet The wallet to check.
 * @param tx The transaction to check.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_wallet_is_mine(dogecoin_wallet* wallet, const dogecoin_tx *tx)
{
    if (!wallet || !tx) return false;
    if (tx->vout) {
        for (unsigned int i = 0; i < tx->vout->len; i++) {
            dogecoin_tx_out* tx_out = vector_idx(tx->vout, i);
            if (tx_out && dogecoin_wallet_txout_is_mine(wallet, tx_out)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * If the transaction input is in the wallet, return the debit value
 * 
 * @param wallet the wallet to search
 * @param txin The transaction input to get the debit from.
 * 
 * @return The debit value of the transaction input.
 */
int64_t dogecoin_wallet_get_debit_txi(dogecoin_wallet *wallet, const dogecoin_tx_in *txin) {
    if (!wallet || !txin) return 0;

    dogecoin_wtx wtx;
    memcpy(wtx.tx_hash_cache, txin->prevout.hash, sizeof(wtx.tx_hash_cache));

    dogecoin_wtx* checkwtx = tfind(&wtx, &wallet->wtxes_rbtree, dogecoin_wtx_compare);
    if (checkwtx) {
        // remove existing wtx
        checkwtx = *(dogecoin_wtx **)checkwtx;
        //todo get debig
    }

    return 0;
}

/**
 * Given a transaction, return the total amount of coins spent in the transaction
 * 
 * @param wallet the wallet to get the debit from
 * @param tx The transaction to get the debit from.
 * 
 * @return The sum of the debit values of all the inputs of the transaction.
 */
int64_t dogecoin_wallet_get_debit_tx(dogecoin_wallet *wallet, const dogecoin_tx *tx) {
    int64_t debit = 0;
    if (tx->vin) {
        for (unsigned int i = 0; i < tx->vin->len; i++) {
            dogecoin_tx_in* tx_in= vector_idx(tx->vin, i);
            if (tx_in) {
                debit += dogecoin_wallet_get_debit_txi(wallet, tx_in);
            }
        }
    }
    return debit;
}

/**
 * "Is this transaction a debit transaction for this wallet?"
 * 
 * The function returns a boolean value. If the transaction is a debit transaction for this wallet, the
 * function returns true. Otherwise, it returns false
 * 
 * @param wallet The wallet to check.
 * @param tx The transaction to check.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_wallet_is_from_me(dogecoin_wallet *wallet, const dogecoin_tx *tx)
{
    return (dogecoin_wallet_get_debit_tx(wallet, tx) > 0);
}

/**
 * This function adds the outpoint of the transaction to the wallet's spent list
 * 
 * @param wallet the wallet to add the transaction to
 * @param wtx The transaction to add to the spent list.
 * 
 * @return Nothing.
 */
void dogecoin_wallet_add_to_spent(dogecoin_wallet* wallet, dogecoin_wtx* wtx) {
    if (!wallet || !wtx)
        return;

    if (dogecoin_tx_is_coinbase(wtx->tx))
        return;
    unsigned int i = 0;
    if (wtx->tx->vin) {
        for (i = 0; i < wtx->tx->vin->len; i++) {
            dogecoin_tx_in* tx_in = vector_idx(wtx->tx->vin, i);

            //add to spends
            dogecoin_tx_outpoint* outpoint = dogecoin_calloc(1, sizeof(dogecoin_tx_outpoint)); // calloc(1, sizeof(dogecoin_tx_outpoint));
            memcpy(outpoint, &tx_in->prevout, sizeof(dogecoin_tx_outpoint));
            vector_add(wallet->spends, outpoint);
        }
    }
}

/**
 * "Check if the wallet has spent the given output."
 * 
 * The function takes a wallet and a hash of the output to check, and a number of the output to check
 * 
 * @param wallet the wallet to check
 * @param hash The hash of the transaction that we are checking.
 * @param n The number of the block that contains the transaction you want to know about.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_wallet_is_spent(dogecoin_wallet* wallet, uint256 hash, uint32_t n)
{
    if (!wallet)
        return false;

    for (size_t i = wallet->spends->len; i > 0; i--)
    {
        dogecoin_tx_outpoint *outpoint = vector_idx(wallet->spends, i-1);
        if (memcmp(outpoint->hash, hash, SHA256_DIGEST_LENGTH) == 0 && n == outpoint->n)
            return true;
    }
    return false;
}

/**
 * Get all unspent outputs from the wallet
 * 
 * @param wallet the wallet to get the unspent outputs from
 * @param unspents vector of dogecoin_output
 * 
 * @return An array of dogecoin_output structs.
 */
dogecoin_bool dogecoin_wallet_get_unspent(dogecoin_wallet* wallet, vector* unspents)
{
    (void)(wallet);
    (void)(unspents);
    rb_red_blk_node* hdkey_rbtree_node;

    if (!wallet)
        return false;

    while ((hdkey_rbtree_node = rbtree_enumerate_next(wallet->wtxes_rbtree))) {
        dogecoin_wtx* wtx = hdkey_rbtree_node->info;
        cstring* key = hdkey_rbtree_node->key;
        uint8_t* hash = (uint8_t*)key->str;

        unsigned int i = 0;
        if (wtx->tx->vout) {
            for (i = 0; i < wtx->tx->vout->len; i++) {
                dogecoin_tx_out* tx_out;
                tx_out = vector_idx(wtx->tx->vout, i);

                if (!dogecoin_wallet_is_spent(wallet, hash, i))
                {
                    if (dogecoin_wallet_txout_is_mine(wallet, tx_out))
                    {
                        dogecoin_output *output = dogecoin_wallet_output_new();
                        dogecoin_wallet_wtx_free(output->wtx);
                        output->wtx = dogecoin_wallet_wtx_copy(wtx);
                        output->i = i;
                        vector_add(unspents, output);
                    }
                }
            }
        }
    }

    return true;
}

/**
 * If the transaction is relevant to the wallet, print a message
 * 
 * @param ctx The wallet context.
 * @param tx The transaction to check.
 * @param pos The transaction's position in the block.
 * @param pindex The block index of the block containing the transaction.
 */
void dogecoin_wallet_check_transaction(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_blockindex *pindex) {
    (void)(pos);
    (void)(pindex);
    dogecoin_wallet *wallet = (dogecoin_wallet *)ctx;
    if (dogecoin_wallet_is_mine(wallet, tx) || dogecoin_wallet_is_from_me(wallet, tx)) {
        printf("\nFound relevant transaction!\n");
    }
}
