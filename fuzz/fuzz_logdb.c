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
 * libFuzzer harness for logdb_record_deser_from_file.
 *
 * logdb is the append-only record store backing the wallet/headers DBs.
 * The per-record deserializer reads attacker-controlled varint key/value
 * lengths and fread()s that many bytes, making it the natural target for
 * the stack-overflow + unbounded-allocation hardening in PR #345.
 *
 * The real function reads from a FILE* (db->file). We wrap the fuzz input
 * in an in-memory stream via fmemopen so no disk I/O is required.
 *
 * Build:  ./configure CC=clang CFLAGS="-fsanitize=fuzzer-no-link" --enable-fuzz && make fuzz
 * Run:    ./fuzz/fuzz_logdb CORPUS_DIR -max_len=100000
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <dogecoin/dogecoin.h>
#include <logdb/logdb_core.h>
#include <logdb/logdb_rec.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* fmemopen requires a non-NULL, non-empty buffer. */
    FILE *f = fmemopen((void *)data, size, "rb");
    if (!f) return 0;

    logdb_log_db *db = logdb_new();
    if (!db) { fclose(f); return 0; }
    db->file = f;

    logdb_record *rec = logdb_record_new();
    enum logdb_error error = LOGDB_SUCCESS;

    /* Single record parse: exercises magic/hash/mode reads, both
     * varint-length fields, and the cstr_resize + fread loops. */
    logdb_record_deser_from_file(rec, db, &error);

    logdb_record_free(rec);

    /* Detach the stream before logdb_free so it doesn't fclose a
     * second time (we own f here). */
    db->file = NULL;
    logdb_free(db);
    fclose(f);
    return 0;
}
