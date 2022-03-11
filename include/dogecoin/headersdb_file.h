/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli
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

#ifndef __LIBDOGECOIN_HEADERSDB_FILE_H__
#define __LIBDOGECOIN_HEADERSDB_FILE_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/buffer.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/headersdb.h>

LIBDOGECOIN_BEGIN_DECL

/* filebased headers database (including binary tree option for fast access)
*/
/**
 * This is a struct that contains a file pointer, a boolean that tells us if we're reading or writing
 * to the file, a tree root, a boolean that tells us if we're using a binary tree, and a few other
 * variables.
 */
typedef struct dogecoin_headers_db_
{
    FILE *headers_tree_file;
    dogecoin_bool read_write_file;

    void *tree_root;
    dogecoin_bool use_binary_tree;

    unsigned int max_hdr_in_mem;
    dogecoin_blockindex genesis;
    dogecoin_blockindex *chaintip;
    dogecoin_blockindex *chainbottom;
} dogecoin_headers_db;

/* This is a function that creates a new headers database. It takes a chainparams struct and a boolean
that tells us if we're using an in-memory only database or not. */
dogecoin_headers_db *dogecoin_headers_db_new(const dogecoin_chainparams* chainparams, dogecoin_bool inmem_only);
/* This is a function that frees the memory allocated for the headers database. */
void dogecoin_headers_db_free(dogecoin_headers_db *db);

/* This function is loading the headers database from a file. */
dogecoin_bool dogecoin_headers_db_load(dogecoin_headers_db* db, const char *filename);
/* This function is called when we are trying to connect a header to the headers database. */
dogecoin_blockindex * dogecoin_headers_db_connect_hdr(dogecoin_headers_db* db, struct const_buffer *buf, dogecoin_bool load_process, dogecoin_bool *connected);

/* This function is filling the blocklocators vector with the blocklocators of the headers database. */
void dogecoin_headers_db_fill_block_locator(dogecoin_headers_db* db, vector *blocklocators);

/* This function is used to find a blockindex in the headers database. */
dogecoin_blockindex * dogecoin_headersdb_find(dogecoin_headers_db* db, uint256 hash);
/* Returning the `chaintip` pointer. */
dogecoin_blockindex * dogecoin_headersdb_getchaintip(dogecoin_headers_db* db);
/* This function is called when we are trying to disconnect a header from the headers database. */
dogecoin_bool dogecoin_headersdb_disconnect_tip(dogecoin_headers_db* db);

/* This function is checking if the headers database has a checkpoint start. */
dogecoin_bool dogecoin_headersdb_has_checkpoint_start(dogecoin_headers_db* db);
/* This is a function that sets a checkpoint start. */
void dogecoin_headersdb_set_checkpoint_start(dogecoin_headers_db* db, uint256 hash, uint32_t height);

// interface function pointer bindings
static const dogecoin_headers_db_interface dogecoin_headers_db_interface_file = {
    (void* (*)(const dogecoin_chainparams*, dogecoin_bool))dogecoin_headers_db_new,
    (void (*)(void *))dogecoin_headers_db_free,
    (dogecoin_bool (*)(void *, const char *))dogecoin_headers_db_load,
    (void (*)(void* , vector *))dogecoin_headers_db_fill_block_locator,
    (dogecoin_blockindex *(*)(void* , struct const_buffer *, dogecoin_bool , dogecoin_bool *))dogecoin_headers_db_connect_hdr,

    (dogecoin_blockindex* (*)(void *))dogecoin_headersdb_getchaintip,
    (dogecoin_bool (*)(void *))dogecoin_headersdb_disconnect_tip,

    (dogecoin_bool (*)(void *))dogecoin_headersdb_has_checkpoint_start,
    (void (*)(void *, uint256, uint32_t))dogecoin_headersdb_set_checkpoint_start
};

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_HEADERSDB_FILE_H__
