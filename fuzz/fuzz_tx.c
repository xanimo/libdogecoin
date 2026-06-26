/*
 * libFuzzer harness for dogecoin_tx_deserialize.
 *
 * Build:  ./configure CC=clang CFLAGS="-fsanitize=fuzzer-no-link" --enable-fuzz && make fuzz
 * Run:    ./fuzz/fuzz_tx CORPUS_DIR -max_len=100000
 */
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    dogecoin_tx *tx = dogecoin_tx_new();
    size_t consumed = 0;
    dogecoin_tx_deserialize((const unsigned char *)data, size, tx, &consumed);
    dogecoin_tx_free(tx);

    return 0;
}
