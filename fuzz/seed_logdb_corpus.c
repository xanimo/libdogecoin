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

/*
 * Corpus seed generator for fuzz_logdb.
 *
 * fuzz_logdb drives logdb_record_deser_from_file() against a fresh
 * logdb_log_db (logdb_new(): sha256_init'd hashctx, NO file header
 * absorbed) reading exactly one record from an fmemopen'd buffer.
 *
 * A record ends with a SHA256 checksum over (running_ctx || record body),
 * so random bytes essentially never pass the memcmp() gate and the fuzzer
 * plateaus before reaching the record-accepted path. This tool emits
 * valid single-record buffers, computed against the SAME fresh-context
 * init the harness uses, so libFuzzer mutates outward from inputs that
 * already clear the checksum.
 *
 * It writes records by hand using the library's own ser/hash primitives,
 * mirroring logdb_write_record() exactly but over a fresh sha256 context
 * (no header), which is what the harness sees.
 *
 * Build (from a configured tree):
 *   clang -I include -I src/logdb/include seed_logdb_corpus.c \
 *       .libs/libdogecoin.a src/secp256k1/.libs/libsecp256k1.a -o seed_logdb
 * Run:
 *   ./seed_logdb CORPUS_DIR
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/sha2.h>
#include <dogecoin/cstr.h>
#include <dogecoin/serialize.h>
#include <logdb/logdb_core.h>
#include <logdb/logdb_rec.h>

/* Must match logdb_core.c. record_magic is the per-record start marker;
 * hashlen is the truncated-SHA length the default db uses. */
static const uint8_t RECORD_MAGIC[8] =
    { 0x88, 0x61, 0xAD, 0xFC, 0x5A, 0x11, 0x22, 0xF8 };
#define HASHLEN 16  /* kLOGDB_DEFAULT_HASH_LEN */

/* Build one valid record buffer for a fresh (header-less) hash context,
 * exactly as the harness's logdb_new() db would expect to read it.
 *
 * On-disk record layout consumed by logdb_record_deser_from_file (note
 * mode is a STANDALONE byte, and the body-hashcheck appears TWICE, once
 * before mode and once after the value, with hashlen = 16):
 *
 *   magic[8]
 *   hashcheck[16]               (body-start indicator, arbitrary bytes;
 *                                deser only feeds it to the SHA context,
 *                                never validates it against the body)
 *   mode[1]
 *   varint(klen) | key
 *   [ varint(vlen) | value ]    (WRITE only)
 *   hashcheck[16]               (body-end indicator, same note as above)
 *   finalcheck[16]              (sha256(running_ctx), first 16 bytes)
 *
 * The running ctx absorbs, in order:
 *   magic, hashcheck, mode, varint(klen), key,
 *   [varint(vlen), value,] hashcheck
 * then is finalized; the first hashlen(=16) bytes are finalcheck.
 *
 * The two hashcheck blocks are NOT verified against the body by the
 * reader (it only memcmp()s the final checksum), so we use a fixed
 * indicator value for them and let the final SHA bind the whole record.
 */
static void put_varlen(cstring *s, uint32_t v) {
    ser_varlen(s, v);  /* CompactSize, same encoder the reader's varint expects */
}

static cstring *build_record(uint8_t mode, const char *key, size_t klen,
                             const char *val, size_t vlen) {
    /* fixed body-start/-end indicator (16 bytes); value is irrelevant to
     * validation, it only needs to be consistent between the bytes we
     * emit and the bytes we feed the hash. */
    uint8_t indicator[HASHLEN];
    memset(indicator, 0xA5, sizeof(indicator));

    /* encode the body field-by-field in reader order */
    cstring *kv = cstr_new_sz(64);
    put_varlen(kv, (uint32_t)klen);
    if (klen) cstr_append_buf(kv, key, klen);
    if (mode == RECORD_TYPE_WRITE) {
        put_varlen(kv, (uint32_t)vlen);
        if (vlen) cstr_append_buf(kv, val, vlen);
    }

    /* running context: magic | indicator | mode | kv | indicator */
    sha256_context ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, RECORD_MAGIC, 8);
    sha256_write(&ctx, indicator, HASHLEN);
    sha256_write(&ctx, &mode, 1);
    sha256_write(&ctx, (const uint8_t *)kv->str, kv->len);
    sha256_write(&ctx, indicator, HASHLEN);

    uint8_t finalhash[SHA256_DIGEST_LENGTH];
    sha256_context ctx_final = ctx;
    sha256_finalize(&ctx_final, finalhash);

    /* assemble bytes in reader order */
    cstring *out = cstr_new_sz(64 + kv->len);
    cstr_append_buf(out, RECORD_MAGIC, 8);
    cstr_append_buf(out, indicator, HASHLEN);
    cstr_append_buf(out, &mode, 1);
    cstr_append_buf(out, kv->str, kv->len);
    cstr_append_buf(out, indicator, HASHLEN);
    cstr_append_buf(out, finalhash, HASHLEN);  /* only first HASHLEN bytes read */

    cstr_free(kv, true);
    return out;
}

static void dump(const char *dir, const char *name, cstring *buf) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return; }
    fwrite(buf->str, 1, buf->len, f);
    fclose(f);
    printf("wrote %s (%zu bytes)\n", path, buf->len);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s CORPUS_DIR\n", argv[0]);
        return 1;
    }
    const char *dir = argv[1];

    struct { uint8_t mode; const char *k; size_t kl; const char *v; size_t vl; const char *name; } cases[] = {
        { RECORD_TYPE_WRITE,  "k",    1,   "v",    1,   "seed_write_tiny" },
        { RECORD_TYPE_WRITE,  "addr", 4,   "value12bytes", 12, "seed_write_small" },
        { RECORD_TYPE_ERASE,  "k",    1,   "",     0,   "seed_erase" },
        { RECORD_TYPE_WRITE,  "",     0,   "",     0,   "seed_write_empty" },
        { RECORD_TYPE_WRITE,  "longkey_padding_0123456789", 26,
                              "longval_padding_0123456789abcdef", 32, "seed_write_long" },
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        cstring *b = build_record(cases[i].mode, cases[i].k, cases[i].kl,
                                  cases[i].v, cases[i].vl);
        dump(dir, cases[i].name, b);
        cstr_free(b, true);
    }
    return 0;
}
