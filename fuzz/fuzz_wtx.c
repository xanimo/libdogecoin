/*
 * libFuzzer harness for dogecoin_wallet_wtx_deserialize.
 *
 * Parses an untrusted on-disk wallet transaction record:
 *   uint32 height | uint256 tx_hash_cache | serialized dogecoin_tx
 *
 * This is the read path exercised when loading a wallet file, so the
 * input is fully attacker-controlled if a wallet .dat is tampered with.
 * Directly targets the record-length / truncation handling hardened in
 * PR #342 (wtx reclen DoS) and the alloc/free balance touched by #318.
 *
 * Build:  ./configure CC=clang CFLAGS="-fsanitize=fuzzer-no-link" --enable-fuzz && make fuzz
 * Run:    ./fuzz/fuzz_wtx CORPUS_DIR -max_len=100000
 */
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/wallet.h>
#include <dogecoin/buffer.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    dogecoin_wtx *wtx = dogecoin_wallet_wtx_new();
    struct const_buffer buf = { data, size };

    /* Return value intentionally ignored: we care about memory-safety of
     * the parse on both the success and failure paths, including
     * truncated headers (height/hash) and embedded-tx truncation. */
    dogecoin_wallet_wtx_deserialize(wtx, &buf);

    dogecoin_wallet_wtx_free(wtx);
    return 0;
}
