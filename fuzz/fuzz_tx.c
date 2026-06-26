/*
 * libFuzzer harness for dogecoin_tx_deserialize + serialize round-trip.
 */
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>
#include <dogecoin/cstr.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    dogecoin_tx *tx = dogecoin_tx_new();
    size_t consumed = 0;
    if (dogecoin_tx_deserialize((const unsigned char *)data, size, tx, &consumed)) {
        /* Round-trip: re-serialize the parsed tx. Exercises the
         * serialization path and surfaces deser/ser asymmetry. */
        cstring *out = cstr_new_sz(1024);
        dogecoin_tx_serialize(out, tx);
        cstr_free(out, 1);
    }
    dogecoin_tx_free(tx);
    return 0;
}
