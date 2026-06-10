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
static dogecoin_bool ensure_filter_dir(const char *base)
{
    /* Build <base>/filter */
    size_t blen = strlen(base);
    char *dir = dogecoin_calloc(blen + 20, 1);
    memcpy(dir, base, blen);

    strcpy(dir + blen, "/filter");
    if (!mkdir_one(dir)) { dogecoin_free(dir); return false; }

    strcpy(dir + blen, "/filter/basic");
    dogecoin_bool ok = mkdir_one(dir);
    dogecoin_free(dir);
    return ok;
}

/**
 * Build the default path for a filter file and store it in @p path_out.
 * Caller must call cstr_free(path_out, true) when done.
 */
static void default_filter_path(cstring **path_out, const char *filename)
{
    *path_out = cstr_new_sz(512);
    dogecoin_get_default_datadir(*path_out);
    /* Strip trailing NUL that dogecoin_get_default_datadir may append */
    while ((*path_out)->len > 0 &&
           (*path_out)->str[(*path_out)->len - 1] == '\0')
        (*path_out)->len--;
    cstr_append_buf(*path_out, "/filter/basic/", 14);
    cstr_append_buf(*path_out, filename, strlen(filename));
    cstr_append_c(*path_out, '\0');
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

dogecoin_cfheaders_db* dogecoin_cfheaders_db_new(dogecoin_bool inmem_only)
{
    dogecoin_cfheaders_db *db = dogecoin_calloc(1, sizeof(*db));
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
        ensure_filter_dir(datadir->str);
        cstr_free(datadir, true);

        default_filter_path(&path_obj, "cfheaders.dat");
        path = path_obj->str;
    }

    struct stat sb;
    dogecoin_bool create = (stat(path, &sb) != 0) || (sb.st_size < (long)CF_HEADERS_FILE_HDR_LEN);

    if (!create) {
        db->file = fopen(path, "r+b");
        if (db->file) {
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
        remove(path);
    }

    /* Create fresh v2 file */
    db->file = fopen(path, "w+b");
    if (path_obj) cstr_free(path_obj, true);
    if (!db->file) {
        fprintf(stderr, "cfheadersdb: cannot open %s: %s\n", path, strerror(errno));
        return false;
    }
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

dogecoin_cfilters_db* dogecoin_cfilters_db_new(dogecoin_bool inmem_only)
{
    dogecoin_cfilters_db *db = dogecoin_calloc(1, sizeof(*db));
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
        ensure_filter_dir(datadir->str);
        cstr_free(datadir, true);

        default_filter_path(&path_obj, "cfilters.dat");
        path = path_obj->str;
    }

    struct stat sb;
    dogecoin_bool create = (stat(path, &sb) != 0) || (sb.st_size < 8);

    db->file = fopen(path, create ? "w+b" : "r+b");
    if (path_obj) cstr_free(path_obj, true);

    if (!db->file) {
        fprintf(stderr, "cfiltersdb: cannot open %s: %s\n", path, strerror(errno));
        return false;
    }

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
