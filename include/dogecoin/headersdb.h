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

#ifndef __LIBDOGECOIN_HEADERSDB_H__
#define __LIBDOGECOIN_HEADERSDB_H__

#include "dogecoin.h"
#include "blockchain.h"
#include "buffer.h"
#include "chainparams.h"

LIBDOGECOIN_BEGIN_DECL

#include <logdb/logdb.h>
#include <logdb/logdb_rec.h>

/* headers database interface, flexible function pointers in
   order to support multiple backends
*/
typedef struct dogecoin_headers_db_interface_
{
    /* init database handler */
    void* (*init)(const dogecoin_chainparams* chainparams, dogecoin_bool inmem_only);

    /* deallocs database handler */
    void (*free)(void *db);

    /* loads database from filename */
    dogecoin_bool (*load)(void *db, const char *filename);

    /* fill in blocklocator up to the tip */
    void (*fill_blocklocator_tip)(void* db, vector *blocklocators);

    /* connect (append) a header */
    dogecoin_blockindex *(*connect_hdr)(void* db, struct const_buffer *buf, dogecoin_bool load_process, dogecoin_bool *connected);

    /* get the chain tip */
    dogecoin_blockindex* (*getchaintip)(void *db);

    /* disconnect the tip and return true if it was possible */
    dogecoin_bool (*disconnect_tip)(void *db);

    /* check if we are using a pruned header db staring at a checkpoint */
    dogecoin_bool (*has_checkpoint_start)(void *db);

    /* set that we are using a checkpoint as basepoint at given height with given hash */
    void (*set_checkpoint_start)(void *db, uint256 hash, uint32_t height);
} dogecoin_headers_db_interface;

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_HEADERSDB_H__