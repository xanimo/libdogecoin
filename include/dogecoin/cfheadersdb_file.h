/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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
 * @file cfheadersdb_file.h
 * @brief File-backed storage for BIP157 compact filter headers.
 *
 * Stores compact filter headers (cfheaders) and compact filter data
 * (cfilters) to disk, mirroring Dogecoin Core's filter/basic/ directory
 * layout.  On startup the database is loaded back into the SPV client's
 * compact_filter_state, eliminating the need to re-download hundreds of
 * megabytes of filter headers from peers after each restart.
 *
 * File layout within the data directory:
 *   filter/basic/cfheaders.dat   — filter header chain (fixed 36-byte records)
 *   filter/basic/cfilters.dat    — raw filter data    (variable-length records)
 */

#ifndef __LIBDOGECOIN_CFHEADERSDB_FILE_H__
#define __LIBDOGECOIN_CFHEADERSDB_FILE_H__

#include <stdio.h>

#include <dogecoin/compact_filter.h>
#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/* ================================================================ */
/*  File format constants                                           */
/* ================================================================ */

/**
 * v2 file header: 4-byte magic + 4-byte version + 32-byte genesis_filter_header = 40 bytes.
 * v1 files (8-byte header, no genesis) are automatically deleted and rebuilt.
 */
#define CF_HEADERS_FILE_HDR_LEN  40

/**
 * Fixed-size cfheaders record: height (4 LE) + filter_header (32) = 36 bytes.
 * Records are appended in ascending height order.
 */
#define CF_HEADERS_FILE_REC_LEN  36

/**
 * Variable-length cfilters record header: height (4 LE) + block_hash (32)
 * + data_len (4 LE) = 40 bytes, followed by data_len bytes of filter data.
 */
#define CF_FILTERS_FILE_REC_HDR_LEN  40

/* ================================================================ */
/*  Compact filter headers database                                 */
/* ================================================================ */

/**
 * @brief File-backed database for compact filter headers.
 *
 * Mirrors dogecoin_headers_db for the BIP157 filter header chain.
 * When read_write is false (inmem_only mode), no file I/O is performed.
 */
typedef struct dogecoin_cfheaders_db_ {
    FILE         *file;         /**< Open file handle (NULL when inmem_only) */
    dogecoin_bool read_write;   /**< Whether file I/O is enabled */
    uint32_t      tip_height;   /**< Height of the last written filter header */
    uint256_t     tip_header;   /**< Filter header hash at tip_height */
} dogecoin_cfheaders_db;

/**
 * @brief File-backed database for compact filter data.
 *
 * Stores raw cfilter payloads keyed by block height and hash.
 * SPV clients typically process and discard filter data; set
 * read_write=false to skip disk I/O.
 */
typedef struct dogecoin_cfilters_db_ {
    FILE         *file;         /**< Open file handle (NULL when inmem_only) */
    dogecoin_bool read_write;   /**< Whether file I/O is enabled */
    uint32_t      tip_height;   /**< Height of the last written cfilter */
} dogecoin_cfilters_db;

/* ================================================================ */
/*  Compact filter headers DB API                                   */
/* ================================================================ */

/**
 * @brief Allocate a new compact filter headers database.
 * @param inmem_only  If true, no file I/O is performed (RAM-only mode).
 * @return New database object, or NULL on allocation failure.
 */
LIBDOGECOIN_API dogecoin_cfheaders_db* dogecoin_cfheaders_db_new(dogecoin_bool inmem_only);

/**
 * @brief Free a compact filter headers database and close its file.
 * @param db  The database to free.
 */
LIBDOGECOIN_API void dogecoin_cfheaders_db_free(dogecoin_cfheaders_db *db);

/**
 * @brief Open (or create) the cfheaders file and load all stored headers.
 *
 * On success, every filter header read from disk is appended to
 * @p state->filter_headers and @p state->cfheaders_tip_height is updated.
 *
 * @param db         The database object.
 * @param file_path  Path to cfheaders.dat, or NULL for the default location
 *                   (<datadir>/filter/basic/cfheaders.dat).
 * @param state      Compact filter state to populate on load.
 * @return true on success (file opened and records loaded).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfheaders_db_load(
    dogecoin_cfheaders_db *db,
    const char *file_path,
    dogecoin_compact_filter_state *state);

/**
 * @brief Append one filter header record to the cfheaders file.
 *
 * Writes height (4 LE) + filter_header (32) and flushes to disk.
 *
 * @param db             The database object.
 * @param height         Block height of the filter header.
 * @param filter_header  32-byte filter header hash.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfheaders_db_write(
    dogecoin_cfheaders_db *db,
    uint32_t height,
    const uint256_t filter_header);

/**
 * @brief Persist genesis_filter_header at file offset 8 (v2 format).
 *
 * Called once, right after the first cfheaders batch is received, to store
 * the filter header that precedes the cfheaders download start height.
 * Without this, cfilter validation cannot validate the first filter block.
 *
 * @param db                    The database object.
 * @param genesis_filter_header 32-byte filter header for height (cfh_start - 1).
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfheaders_db_write_genesis(
    dogecoin_cfheaders_db *db,
    const uint256_t genesis_filter_header);

/**
 * @brief Truncate cfheaders.dat to the v2 header only (clears all records).
 *
 * Used by the cfcheckpt handler when a fresh cfheaders download is needed
 * (e.g. invalid or incompatible previously-stored data).
 *
 * @param db  The database object.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfheaders_db_reset(dogecoin_cfheaders_db *db);

/* ================================================================ */
/*  Compact filters DB API                                          */
/* ================================================================ */

/**
 * @brief Allocate a new compact filter data database.
 * @param inmem_only  If true, no file I/O is performed.
 * @return New database object, or NULL on allocation failure.
 */
LIBDOGECOIN_API dogecoin_cfilters_db* dogecoin_cfilters_db_new(dogecoin_bool inmem_only);

/**
 * @brief Free a compact filter data database and close its file.
 * @param db  The database to free.
 */
LIBDOGECOIN_API void dogecoin_cfilters_db_free(dogecoin_cfilters_db *db);

/**
 * @brief Open (or create) the cfilters data file.
 *
 * Unlike cfheaders, filter data is not loaded back into RAM on startup;
 * only the file handle is prepared for subsequent writes.
 *
 * @param db         The database object.
 * @param file_path  Path to cfilters.dat, or NULL for the default location
 *                   (<datadir>/filter/basic/cfilters.dat).
 * @return true on success (file opened).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfilters_db_load(
    dogecoin_cfilters_db *db,
    const char *file_path);

/**
 * @brief Append one cfilter record to the cfilters file.
 *
 * Writes height (4 LE) + block_hash (32) + data_len (4 LE) + data bytes,
 * then flushes.
 *
 * @param db           The database object.
 * @param height       Block height of this cfilter.
 * @param block_hash   32-byte block hash.
 * @param filter_data  Raw encoded filter data.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cfilters_db_write(
    dogecoin_cfilters_db *db,
    uint32_t height,
    const uint256_t block_hash,
    const cstring *filter_data);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_CFHEADERSDB_FILE_H__ */
