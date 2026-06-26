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
