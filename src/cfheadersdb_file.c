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
#define MKDIR_ONE(p) _mkdir(p)
#else
#define MKDIR_ONE(p) mkdir(p, 0755)
#endif

#include <errno.h>
#include <string.h>

#include <dogecoin/cfheadersdb_file.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

/* Magic bytes and current file format version */
static const uint8_t cfhdr_magic[4]   = {0xCF, 0x68, 0x44, 0x52}; /* "CfhDR" */
static const uint8_t cfdata_magic[4]  = {0xCF, 0xDA, 0x54, 0x41}; /* "CfDATA" */
static const uint32_t cf_file_version = 1;

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
 * Write magic + version file header to an open file positioned at offset 0.
 */
static dogecoin_bool write_file_header(FILE *f, const uint8_t *magic)
{
    if (fwrite(magic, 4, 1, f) != 1) return false;
    uint32_t v = htole32(cf_file_version);
    return (fwrite(&v, 4, 1, f) == 1);
}

/**
 * Verify the magic + version header of an already-open file.
 * Returns false on mismatch or version too new.
 */
static dogecoin_bool check_file_header(FILE *f, const uint8_t *expected_magic)
{
    uint8_t buf[8];
    rewind(f);
    if (fread(buf, 8, 1, f) != 1) return false;
    if (memcmp(buf, expected_magic, 4) != 0) return false;
    uint32_t ver = le32toh(*(uint32_t *)(buf + 4));
    return (ver <= cf_file_version);
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
        /* Ensure the filter/basic/ directory exists first */
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

    /* Determine whether we are creating or opening an existing file */
    struct stat sb;
    dogecoin_bool create = (stat(path, &sb) != 0);

    db->file = fopen(path, create ? "a+b" : "r+b");
    if (path_obj) cstr_free(path_obj, true);

    if (!db->file) {
        fprintf(stderr, "cfheadersdb: cannot open %s: %s\n", path, strerror(errno));
        return false;
    }

    if (create) {
        if (!write_file_header(db->file, cfhdr_magic)) {
            fprintf(stderr, "cfheadersdb: failed to write file header\n");
            fclose(db->file);
            db->file = NULL;
            return false;
        }
        return true;
    }

    /* Existing file — verify header */
    if (!check_file_header(db->file, cfhdr_magic)) {
        fprintf(stderr, "cfheadersdb: bad magic or unsupported version\n");
        fclose(db->file);
        db->file = NULL;
        return false;
    }

    /* Read all records and populate state->filter_headers */
    size_t loaded = 0;
    uint8_t rec[CF_HEADERS_FILE_REC_LEN]; /* height(4) + filter_header(32) */

    printf("Loading compact filter headers from disk...\n");

    while (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, db->file) == 1) {
        uint32_t height;
        memcpy(&height, rec, 4);
        height = le32toh(height);

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
        printf("\r  %zu filter headers loaded, tip at height %u\n", loaded, db->tip_height);
        state->cfheaders_tip_height = db->tip_height;
        memcpy(state->cfheaders_tip_hash, db->tip_header, 32);
    }

    /* Position file pointer at end for subsequent appends */
    fseek(db->file, 0, SEEK_END);
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
    dogecoin_file_commit(db->file);

    db->tip_height = height;
    memcpy(db->tip_header, filter_header, 32);
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
    dogecoin_bool create = (stat(path, &sb) != 0);

    db->file = fopen(path, create ? "a+b" : "r+b");
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
    if (!check_file_header(db->file, cfdata_magic)) {
        fprintf(stderr, "cfiltersdb: bad magic or unsupported version\n");
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
