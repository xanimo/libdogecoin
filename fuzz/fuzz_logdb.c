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
