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

#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define MKDIR_ONE(p) _mkdir(p)
#define CF_FTRUNCATE(fd, sz) _chsize((fd), (long)(sz))
#define CF_FILENO(f) _fileno(f)
#else
#include <unistd.h>
#define MKDIR_ONE(p) mkdir(p, 0755)
#define CF_FTRUNCATE(fd, sz) ftruncate((fd), (off_t)(sz))
#define CF_FILENO(f) fileno(f)
#endif

#include <errno.h>
#include <string.h>

#include <dogecoin/cfheadersdb_file.h>
#include <dogecoin/mem.h>
#include <dogecoin/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

/* Magic bytes and current file format version.
 * v2 format: magic(4) + version(4) + genesis_filter_header(32) + records(N*36)
 * v1 format: magic(4) + version(4) + records(N*36)  [obsolete, triggers rebuild] */
static const uint8_t cfhdr_magic[4]   = {0xCF, 0x68, 0x44, 0x52}; /* "CfhDR" */
static const uint8_t cfdata_magic[4]  = {0xCF, 0xDA, 0x54, 0x41}; /* "CfDATA" */
static const uint32_t cf_file_version = 2;

/* ================================================================ */
/*  Internal helpers                                                */
/* ================================================================ */

/**
 * Create a single directory, ignoring EEXIST.
 * Returns true on success (directory exists or was created).
 */
static dogecoin_bool mkdir_one(const char *path)
{
    if (MKDIR_ONE(path) == 0)
        return true;
#ifdef _WIN32
    return (errno == EEXIST);
#else
    return (errno == EEXIST);
#endif
}

/**
 * Ensure <base>/filter/basic/ exists, creating subdirectories as needed.
 * @p base must be a NUL-terminated path with no trailing slash.
 */
/* Build <base>/filter/basic/<chainname>, creating each level.
 *
 * The chain component is not cosmetic.  Without it every network shares one
 * cache: a regtest or testnet client loads the *mainnet* cfheaders/cfilters at
 * startup, rescans them, and matches mainnet blocks its peer has never heard of
 * -- then blocks forever waiting for them.  It also writes its own filters back
 * into the mainnet files, corrupting them for the next mainnet run. */
static dogecoin_bool ensure_filter_dir(const char *base, const dogecoin_chainparams *params)
{
    const char *chain = (params && params->chainname[0]) ? params->chainname : "main";
    size_t blen = strlen(base);
    char *dir = dogecoin_calloc(blen + 32 + strlen(chain), 1);
    if (!dir) return false;
    memcpy(dir, base, blen);

    /* The datadir itself may not exist yet: on a first run mkdir("<base>/filter")
       fails with ENOENT and every filter store silently falls back to no
       persistence, so the whole chain is refetched on each start. */
    dir[blen] = '\0';
    if (!mkdir_one(dir)) { dogecoin_free(dir); return false; }

    strcpy(dir + blen, "/filter");
    if (!mkdir_one(dir)) { dogecoin_free(dir); return false; }

    strcpy(dir + blen, "/filter/basic");
    if (!mkdir_one(dir)) { dogecoin_free(dir); return false; }

    sprintf(dir + blen, "/filter/basic/%s", chain);
    dogecoin_bool ok = mkdir_one(dir);
    dogecoin_free(dir);
    return ok;
}

/**
 * Build the default path for a filter file and store it in @p path_out.
 * Caller must call cstr_free(path_out, true) when done.
 */
/* <datadir>/filter/basic/<chainname>/<filename> -- see ensure_filter_dir() for
 * why the chain component matters. */
static void default_filter_path(cstring **path_out,
                                const dogecoin_chainparams *params,
                                const char *filename)
{
    const char *chain = (params && params->chainname[0]) ? params->chainname : "main";
    *path_out = cstr_new_sz(512);
    dogecoin_get_default_datadir(*path_out);
    /* Strip trailing NUL that dogecoin_get_default_datadir may append */
    while ((*path_out)->len > 0 &&
           (*path_out)->str[(*path_out)->len - 1] == '\0')
        (*path_out)->len--;
    cstr_append_buf(*path_out, "/filter/basic/", 14);
    cstr_append_buf(*path_out, chain, strlen(chain));
    cstr_append_c(*path_out, '/');
    cstr_append_buf(*path_out, filename, strlen(filename));
    cstr_append_c(*path_out, '\0');
}

/* Legacy chain-agnostic location, <datadir>/filter/basic/<filename>, used
 * before the layout was segregated per network.  Any such file was written by
 * whichever network happened to run last; only mainnet is migrated (below),
 * because only mainnet data is meaningful to keep. */
static void legacy_filter_path(cstring **path_out, const char *filename)
{
    *path_out = cstr_new_sz(512);
    dogecoin_get_default_datadir(*path_out);
    while ((*path_out)->len > 0 &&
           (*path_out)->str[(*path_out)->len - 1] == '\0')
        (*path_out)->len--;
    cstr_append_buf(*path_out, "/filter/basic/", 14);
    cstr_append_buf(*path_out, filename, strlen(filename));
    cstr_append_c(*path_out, '\0');
}

/* One-time migration of the pre-segregation cache into the mainnet directory.
 * Only runs for mainnet, only when the new path is absent and the legacy file
 * exists, and only via rename() -- so it is a no-op on a fresh install and
 * never silently discards data. */
static void migrate_legacy_filter_file(const dogecoin_chainparams *params,
                                       const char *filename,
                                       const char *new_path)
{
    if (!params || strcmp(params->chainname, "main") != 0) return;

    cstring *old_obj = NULL;
    legacy_filter_path(&old_obj, filename);

    /* Move without a prior stat() on either path. Checking that the
       destination is absent and then renaming onto it is a check-then-use:
       POSIX rename() replaces the destination silently, so anything created in
       between is destroyed. link() refuses with EEXIST instead, which is the
       atomic "do not clobber" this wants; MSVC's rename() already fails that
       way. ENOENT simply means there is nothing to migrate. */
    int moved;
#ifdef WIN32
    moved = (rename(old_obj->str, new_path) == 0);
#else
    moved = (link(old_obj->str, new_path) == 0);
    if (moved) unlink(old_obj->str);
#endif
    if (moved) {
        printf("cfdb: migrated %s to per-chain location %s\n",
               old_obj->str, new_path);
    } else if (errno != ENOENT && errno != EEXIST) {
        fprintf(stderr, "cfdb: could not migrate %s to %s: %s\n",
                old_obj->str, new_path, strerror(errno));
    }
    cstr_free(old_obj, true);
}

/**
 * Write the v2 file header: magic(4) + version(4) + genesis_filter_header(32).
 * genesis bytes are initialised to zero; call dogecoin_cfheaders_db_write_genesis
 * to fill them in once the first cfheaders batch arrives.
 */
static dogecoin_bool write_file_header(FILE *f, const uint8_t *magic)
{
    if (fwrite(magic, 4, 1, f) != 1) return false;
    uint32_t v = htole32(cf_file_version);
    if (fwrite(&v, 4, 1, f) != 1) return false;
    uint8_t zeros[32];
    memset(zeros, 0, 32);
    return (fwrite(zeros, 32, 1, f) == 1);
}

/**
 * Read the file header and return the version number.
 * Returns 0 on bad magic or read error; callers treat anything < 2 as stale.
 */
static uint32_t read_file_version(FILE *f, const uint8_t *expected_magic)
{
    uint8_t buf[8];
    rewind(f);
    if (fread(buf, 8, 1, f) != 1) return 0;
    if (memcmp(buf, expected_magic, 4) != 0) return 0;
    return le32toh(*(uint32_t *)(buf + 4));
}

/* ================================================================ */
/*  cfheaders DB                                                    */
/* ================================================================ */

dogecoin_cfheaders_db* dogecoin_cfheaders_db_new(const dogecoin_chainparams *params, dogecoin_bool inmem_only)
{
    dogecoin_cfheaders_db *db = dogecoin_calloc(1, sizeof(*db));
    db->params      = params;
    db->read_write  = !inmem_only;
    db->tip_height  = 0;
    memset(db->tip_header, 0, 32);
    return db;
}

void dogecoin_cfheaders_db_free(dogecoin_cfheaders_db *db)
{
    if (!db) return;
    if (db->file) {
        dogecoin_file_commit(db->file);
        fclose(db->file);
        db->file = NULL;
    }
    dogecoin_free(db);
}

dogecoin_bool dogecoin_cfheaders_db_load(
    dogecoin_cfheaders_db *db,
    const char *file_path,
    dogecoin_compact_filter_state *state)
{
    if (!db || !state) return false;
    if (!db->read_write) return true;  /* inmem_only: nothing to do */

    /* Resolve file path */
    cstring *path_obj = NULL;
    const char *path = file_path;
    if (!path) {
        cstring *datadir = cstr_new_sz(512);
        dogecoin_get_default_datadir(datadir);
        while (datadir->len > 0 && datadir->str[datadir->len - 1] == '\0')
            datadir->len--;
        cstr_append_c(datadir, '\0');
        ensure_filter_dir(datadir->str, db->params);
        cstr_free(datadir, true);

        default_filter_path(&path_obj, db->params, "cfheaders.dat");
        path = path_obj->str;
        migrate_legacy_filter_file(db->params, "cfheaders.dat", path);
    }

    /* Open first and judge the handle, rather than stat()ing the path and then
       opening it: between those two the file can be replaced. fstat on the
       descriptor describes the file actually opened. */
    db->file = fopen(path, "r+b");
    if (db->file) {
        struct stat sb;
        if (fstat(CF_FILENO(db->file), &sb) != 0 ||
            sb.st_size < (long)CF_HEADERS_FILE_HDR_LEN) {
            fclose(db->file);
            db->file = NULL;
        }
    }

    if (db->file) {
        {
            uint32_t ver = read_file_version(db->file, cfhdr_magic);
            if (ver >= 2) {
                /* v2 file: read genesis_filter_header then records */
                if (fread(state->genesis_filter_header, 32, 1, db->file) == 1) {
                    size_t loaded = 0;
                    uint32_t first_height = 0;
                    uint8_t rec[CF_HEADERS_FILE_REC_LEN];
                    printf("Loading compact filter headers from disk...\n");
                    while (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, db->file) == 1) {
                        uint32_t height;
                        memcpy(&height, rec, 4);
                        height = le32toh(height);
                        if (loaded == 0) first_height = height;
                        uint256_t *fh = dogecoin_calloc(1, 32);
                        memcpy(fh, rec + 4, 32);
                        vector_add(state->filter_headers, fh);
                        db->tip_height = height;
                        memcpy(db->tip_header, fh, 32);
                        loaded++;
                        if (loaded % 100000 == 0) {
                            printf("\r  %zu filter headers loaded (height %u)", loaded, height);
                            fflush(stdout);
                        }
                    }
                    if (loaded > 0) {
                        printf("\r  %zu filter headers loaded, heights %u..%u\n",
                               loaded, first_height, db->tip_height);
                        state->cfheaders_tip_height  = db->tip_height;
                        state->cfheaders_base_height = first_height;
                        memcpy(state->cfheaders_tip_hash, db->tip_header, 32);
                    }
                    fseek(db->file, 0, SEEK_END);
                    if (path_obj) cstr_free(path_obj, true);
                    return true;
                }
            }
            /* v1 or unreadable: close and delete, will recreate below */
            if (ver < 2)
                fprintf(stderr, "cfheadersdb: v%u file detected; rebuilding as v2 "
                        "(cfheaders will re-download)\n", ver);
            fclose(db->file);
            db->file = NULL;
        }
    }

    /* Create fresh v2 file. "w+b" truncates an existing file, so no separate
       remove() is needed -- and removing it drops another check-then-use. */
    db->file = dogecoin_fopen_private(path, "w+b");
    if (!db->file) {
        /* `path` aliases path_obj->str, so it must outlive this message --
         * freeing path_obj before the fprintf was a heap-use-after-free. */
        fprintf(stderr, "cfheadersdb: cannot open %s: %s\n", path, strerror(errno));
        if (path_obj) cstr_free(path_obj, true);
        return false;
    }
    if (path_obj) cstr_free(path_obj, true);
    if (!write_file_header(db->file, cfhdr_magic)) {
        fprintf(stderr, "cfheadersdb: failed to write file header\n");
        fclose(db->file);
        db->file = NULL;
        return false;
    }
    return true;
}

dogecoin_bool dogecoin_cfheaders_db_write(
    dogecoin_cfheaders_db *db,
    uint32_t height,
    const uint256_t filter_header)
{
    if (!db || !db->read_write || !db->file) return true; /* no-op when inmem */

    uint8_t rec[CF_HEADERS_FILE_REC_LEN];
    uint32_t h_le = htole32(height);
    memcpy(rec, &h_le, 4);
    memcpy(rec + 4, filter_header, 32);

    if (fwrite(rec, CF_HEADERS_FILE_REC_LEN, 1, db->file) != 1) {
        fprintf(stderr, "cfheadersdb: write failed at height %u\n", height);
        return false;
    }

    db->tip_height = height;
    memcpy(db->tip_header, filter_header, 32);
    return true;
}

dogecoin_bool dogecoin_cfheaders_db_flush(dogecoin_cfheaders_db *db)
{
    if (!db || !db->read_write || !db->file) return true;
    dogecoin_file_commit(db->file);
    return true;
}

dogecoin_bool dogecoin_cfheaders_db_write_genesis(
    dogecoin_cfheaders_db *db,
    const uint256_t genesis_filter_header)
{
    if (!db || !db->read_write || !db->file) return true;

    long saved = ftell(db->file);
    if (fseek(db->file, 8, SEEK_SET) != 0) return false;
    dogecoin_bool ok = (fwrite(genesis_filter_header, 32, 1, db->file) == 1);
    dogecoin_file_commit(db->file);
    fseek(db->file, saved, SEEK_SET);
    return ok;
}

dogecoin_bool dogecoin_cfheaders_db_reset(dogecoin_cfheaders_db *db)
{
    if (!db || !db->read_write || !db->file) return true;

    fflush(db->file);
    if (CF_FTRUNCATE(CF_FILENO(db->file), (long)CF_HEADERS_FILE_HDR_LEN) != 0) {
        fprintf(stderr, "cfheadersdb: truncate failed: %s\n", strerror(errno));
        return false;
    }
    fseek(db->file, 0, SEEK_END);
    db->tip_height = 0;
    memset(db->tip_header, 0, 32);
    return true;
}

/* ================================================================ */
/*  cfilters DB                                                     */
/* ================================================================ */

dogecoin_cfilters_db* dogecoin_cfilters_db_new(const dogecoin_chainparams *params, dogecoin_bool inmem_only)
{
    dogecoin_cfilters_db *db = dogecoin_calloc(1, sizeof(*db));
    db->params     = params;
    db->read_write = !inmem_only;
    db->tip_height = 0;
    return db;
}

void dogecoin_cfilters_db_free(dogecoin_cfilters_db *db)
{
    if (!db) return;
    if (db->file) {
        dogecoin_file_commit(db->file);
        fclose(db->file);
        db->file = NULL;
    }
    dogecoin_free(db);
}

dogecoin_bool dogecoin_cfilters_db_load(
    dogecoin_cfilters_db *db,
    const char *file_path)
{
    if (!db) return false;
    if (!db->read_write) return true;

    cstring *path_obj = NULL;
    const char *path = file_path;
    if (!path) {
        cstring *datadir = cstr_new_sz(512);
        dogecoin_get_default_datadir(datadir);
        while (datadir->len > 0 && datadir->str[datadir->len - 1] == '\0')
            datadir->len--;
        cstr_append_c(datadir, '\0');
        ensure_filter_dir(datadir->str, db->params);
        cstr_free(datadir, true);

        default_filter_path(&path_obj, db->params, "cfilters.dat");
        path = path_obj->str;
        migrate_legacy_filter_file(db->params, "cfilters.dat", path);
    }

    /* Judge the handle, not the path. stat() then fopen() is a check-then-use:
       the file can be replaced in between, and fstat on the descriptor
       describes the file actually opened. Mirrors the cfheaders store. */
    dogecoin_bool create = false;
    db->file = fopen(path, "r+b");
    if (db->file) {
        struct stat sb;
        if (fstat(CF_FILENO(db->file), &sb) != 0 || sb.st_size < 8) {
            fclose(db->file);
            db->file = NULL;
        }
    }
    if (!db->file) {
        /* Private, like the cfheaders store: a filter store an attacker can
           rewrite makes an SPV client miss its own transactions. "w+b"
           truncates, so no separate remove() is needed. */
        db->file = dogecoin_fopen_private(path, "w+b");
        create = true;
    }

    if (!db->file) {
        /* Same aliasing rule as the cfheaders path above: `path` points into
         * path_obj, so it cannot be freed before this message is formatted. */
        fprintf(stderr, "cfiltersdb: cannot open %s: %s\n", path, strerror(errno));
        if (path_obj) cstr_free(path_obj, true);
        return false;
    }
    if (path_obj) cstr_free(path_obj, true);

    if (create) {
        if (!write_file_header(db->file, cfdata_magic)) {
            fprintf(stderr, "cfiltersdb: failed to write file header\n");
            fclose(db->file);
            db->file = NULL;
            return false;
        }
        return true;
    }

    /* Existing file — verify header and seek to end for appends */
    if (read_file_version(db->file, cfdata_magic) == 0) {
        fprintf(stderr, "cfiltersdb: bad magic or unsupported version\n");
        fclose(db->file);
        db->file = NULL;
        return false;
    }

    /* Skip the remaining 32 bytes of the file header (magic+version already
     * consumed by read_file_version; seek to the first record). */
    if (fseek(db->file, CF_HEADERS_FILE_HDR_LEN, SEEK_SET) != 0) {
        fclose(db->file);
        db->file = NULL;
        return false;
    }

    /* Scan records to find the tip height (variable-length; must iterate) */
    while (true) {
        uint8_t hdr[CF_FILTERS_FILE_REC_HDR_LEN];
        if (fread(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, db->file) != 1) break;
        uint32_t height, data_len;
        memcpy(&height,   hdr,      4); height   = le32toh(height);
        memcpy(&data_len, hdr + 36, 4); data_len = le32toh(data_len);
        db->tip_height = height;
        if (fseek(db->file, (long)data_len, SEEK_CUR) != 0) break;
    }

    fseek(db->file, 0, SEEK_END);
    return true;
}

dogecoin_bool dogecoin_cfilters_db_write(
    dogecoin_cfilters_db *db,
    uint32_t height,
    const uint256_t block_hash,
    const cstring *filter_data)
{
    if (!db || !db->read_write || !db->file) return true;
    if (!filter_data) return false;

    uint8_t hdr[CF_FILTERS_FILE_REC_HDR_LEN];
    uint32_t h_le   = htole32(height);
    uint32_t dl_le  = htole32((uint32_t)filter_data->len);

    memcpy(hdr,      &h_le,  4);
    memcpy(hdr + 4,  block_hash, 32);
    memcpy(hdr + 36, &dl_le, 4);

    if (fwrite(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, db->file) != 1)
        return false;
    if (filter_data->len > 0 &&
        fwrite(filter_data->str, filter_data->len, 1, db->file) != 1)
        return false;

    dogecoin_file_commit(db->file);
    db->tip_height = height;
    return true;
}

dogecoin_bool dogecoin_cfilters_db_iterate(
    dogecoin_cfilters_db *db,
    dogecoin_bool (*cb)(uint32_t height, const uint256_t block_hash,
                        const uint8_t *filter_data, uint32_t data_len,
                        void *ctx),
    void *ctx)
{
    if (!db || !db->file || !cb) return false;

    /* Rewind past the file header to the first record. */
    if (fseek(db->file, CF_HEADERS_FILE_HDR_LEN, SEEK_SET) != 0)
        return false;

    uint8_t hdr[CF_FILTERS_FILE_REC_HDR_LEN];
    while (fread(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, db->file) == 1) {
        uint32_t height, data_len;
        uint256_t block_hash;
        memcpy(&height,     hdr,      4); height   = le32toh(height);
        memcpy(block_hash,  hdr + 4,  32);
        memcpy(&data_len,   hdr + 36, 4); data_len = le32toh(data_len);

        if (data_len == 0) {
            if (!cb(height, block_hash, NULL, 0, ctx)) break;
            continue;
        }

        /* data_len comes straight off disk, so it is only as trustworthy as the
           file. A cfilter record cannot legitimately be larger than the P2P
           message that delivered it, so reject anything beyond that rather than
           asking the allocator for up to 4 GiB on a corrupt or tampered file
           (CWE-400). The subsequent short fread would fail, but only after the
           allocation has already been attempted. */
        if (data_len > DOGECOIN_MAX_P2P_MSG_SIZE)
            return false;

        uint8_t *buf = dogecoin_malloc(data_len);
        if (!buf) return false;
        if (fread(buf, data_len, 1, db->file) != 1) {
            dogecoin_free(buf);
            return false;
        }
        dogecoin_bool cont = cb(height, block_hash, buf, data_len, ctx);
        dogecoin_free(buf);
        if (!cont) break;
    }

    /* Restore write position at end of file. */
    fseek(db->file, 0, SEEK_END);
    return true;
}
