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
 * @file filter_bootstrap.h
 * @brief BIP157 compact filter bootstrap package API.
 *
 * Implements Option 2 from the filter-bootstrap design:
 *   - Export: slice an existing local cfheaders.dat + cfilters.dat into
 *     fixed-height chunks and write a manifest file for CDN distribution.
 *   - Import: given a manifest, download each chunk (file:// or http://),
 *     verify SHA256 integrity and tip cfheader against compiled-in
 *     dogecoin_mainnet_cf_checkpoint_array, then append to the local DB.
 *
 * Trust model: the manifest points to chunk files; chunk data is verified
 * cryptographically against checkpoints committed in the binary.  A
 * tampered chunk will be rejected even from an untrusted CDN.
 *
 * Chunk boundaries align with multiples of FILTER_BOOTSTRAP_CHUNK_SIZE
 * (1 000 000 blocks), which are exact multiples of the 1 000-block
 * cf_checkpoint interval, so every chunk end falls on a known committed
 * filter header hash.
 */

#ifndef __LIBDOGECOIN_FILTER_BOOTSTRAP_H__
#define __LIBDOGECOIN_FILTER_BOOTSTRAP_H__

#include <stdint.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>

LIBDOGECOIN_BEGIN_DECL

/* ================================================================ */
/*  Constants                                                       */
/* ================================================================ */

#define FILTER_BOOTSTRAP_VERSION    1
#define FILTER_BOOTSTRAP_CHUNK_SIZE 1000000u   /**< Blocks per chunk */
#define FILTER_BOOTSTRAP_MANIFEST   "filter_bootstrap.manifest"

/* ================================================================ */
/*  Data types                                                      */
/* ================================================================ */

/** One entry in the manifest: describes a single chunk file pair. */
typedef struct dogecoin_bootstrap_chunk_ {
    uint32_t start_height;          /**< First block height in this chunk */
    uint32_t end_height;            /**< Last  block height in this chunk */
    char     cfheaders_url[1024];   /**< URL of the cfheaders chunk file  */
    char     cfilters_url[1024];    /**< URL of the cfilters chunk file   */
    uint8_t  cfheaders_sha256[32];  /**< Expected SHA256 of cfheaders chunk */
    uint8_t  cfilters_sha256[32];   /**< Expected SHA256 of cfilters chunk  */
    uint8_t  tip_cfheader[32];      /**< Filter header at end_height (LE)   */
} dogecoin_bootstrap_chunk;

/** In-memory representation of a parsed manifest file. */
typedef struct dogecoin_bootstrap_manifest_ {
    uint32_t                 version;
    char                     chain[16];
    uint32_t                 chunk_count;
    dogecoin_bootstrap_chunk *chunks;
} dogecoin_bootstrap_manifest;

/**
 * Progress callback fired after each chunk is fully downloaded and verified.
 *
 * @param chunk_idx    0-based index of the just-completed chunk
 * @param chunk_count  Total number of chunks in the manifest
 * @param bytes_done   Cumulative bytes downloaded so far
 * @param bytes_total  Total bytes expected (0 if unknown)
 * @param ctx          Caller-supplied context pointer
 */
typedef void (*dogecoin_bootstrap_progress_cb)(
    uint32_t chunk_idx,
    uint32_t chunk_count,
    uint64_t bytes_done,
    uint64_t bytes_total,
    void    *ctx);

/* ================================================================ */
/*  Export API                                                      */
/* ================================================================ */

/**
 * Export compact filter bootstrap chunks from an existing local filter DB.
 *
 * Reads cfheaders.dat and cfilters.dat (single streaming pass each),
 * splits them into FILTER_BOOTSTRAP_CHUNK_SIZE-block chunks, writes
 * chunk files to outdir, and produces a filter_bootstrap.manifest.
 *
 * Each chunk's tip cfheader is verified against the compiled-in
 * cf_checkpoint array before the manifest is written.
 *
 * @param cfheaders_src  Source cfheaders.dat path (NULL = default datadir)
 * @param cfilters_src   Source cfilters.dat path  (NULL = default datadir)
 * @param outdir         Directory to write chunk files and manifest
 * @param base_url       URL prefix used for chunk URLs in the manifest
 *                       (e.g. "https://bootstrap.dogecoin.org/filters/main/")
 * @param params         Chain parameters
 * @return true on success
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bootstrap_export(
    const char              *cfheaders_src,
    const char              *cfilters_src,
    const char              *outdir,
    const char              *base_url,
    const dogecoin_chainparams *params);

/* ================================================================ */
/*  Import API                                                      */
/* ================================================================ */

/**
 * Import compact filter bootstrap chunks into the local filter DB.
 *
 * Parses the manifest, then for each chunk:
 *   1. Downloads cfheaders chunk and cfilters chunk (file:// or http://)
 *   2. Verifies SHA256 of each downloaded file against the manifest
 *   3. Verifies the chunk's tip cfheader against the compiled-in
 *      dogecoin_mainnet_cf_checkpoint_array (or testnet equivalent)
 *   4. Appends records to cfheaders_dst / cfilters_dst
 *   5. Fires progress_cb if provided
 *
 * Chunks whose end_height is already covered by the local DB are skipped.
 *
 * @param manifest_path  Path to filter_bootstrap.manifest
 * @param cfheaders_dst  Destination cfheaders.dat (NULL = default datadir)
 * @param cfilters_dst   Destination cfilters.dat  (NULL = default datadir)
 * @param params         Chain parameters
 * @param progress_cb    Optional progress callback (may be NULL)
 * @param ctx            Context passed to progress_cb
 * @return true on success
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bootstrap_import(
    const char              *manifest_path,
    const char              *cfheaders_dst,
    const char              *cfilters_dst,
    const dogecoin_chainparams *params,
    dogecoin_bootstrap_progress_cb progress_cb,
    void                    *ctx);

/* ================================================================ */
/*  Manifest helpers                                                */
/* ================================================================ */

/**
 * Parse a manifest file into a dogecoin_bootstrap_manifest.
 * Caller must free with dogecoin_bootstrap_manifest_free().
 * Returns NULL on parse error.
 */
LIBDOGECOIN_API dogecoin_bootstrap_manifest* dogecoin_bootstrap_manifest_load(
    const char *manifest_path);

/** Free a manifest allocated by dogecoin_bootstrap_manifest_load(). */
LIBDOGECOIN_API void dogecoin_bootstrap_manifest_free(
    dogecoin_bootstrap_manifest *m);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_FILTER_BOOTSTRAP_H__ */
