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
 * libFuzzer harness for the wallet record deserializers — the parsers that
 * turn bytes read from a wallet file on disk into wallet structures. A
 * corrupt or hostile wallet file flows straight into these, so they are an
 * untrusted-input surface distinct from the network/tx/PSBT harnesses.
 *
 * Two targets, both consuming a const_buffer of attacker-controlled bytes:
 *   - dogecoin_wallet_wtx_deserialize:  height + tx-hash-cache + a full nested
 *     transaction (chains into dogecoin_tx_deserialize).
 *   - dogecoin_wallet_addr_deserialize: pubkeyhash + type + childindex + flags.
 *
 * The fuzzer input is split: the first byte selects/So both parsers are
 * exercised, the remainder is the record body. A leading selector byte routes
 * to one parser or the other so libFuzzer can specialise each path; both are
 * reached across the corpus.
 *
 * Successful wtx parses are round-tripped where a serializer exists, to
 * surface deser/ser asymmetry (matching the fuzz_tx pattern). The addr struct
 * has no public serializer, so it is parsed only.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/wallet.h>
#include <dogecoin/buffer.h>
#include <dogecoin/chainparams.h>

/* addr deserializer is non-static but not declared in a public header;
 * prototype it here so we can link the real symbol. */
extern dogecoin_bool dogecoin_wallet_addr_deserialize(
    dogecoin_wallet_addr* waddr, const dogecoin_chainparams* params,
    struct const_buffer* buf);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    uint8_t selector = data[0];
    const uint8_t *body = data + 1;
    size_t body_len = size - 1;

    struct const_buffer buf = { body, body_len };

    if (selector & 1) {
        /* wtx record: height + hash cache + nested tx */
        dogecoin_wtx *wtx = dogecoin_wallet_wtx_new();
        if (wtx) {
            struct const_buffer b = buf;
            (void)dogecoin_wallet_wtx_deserialize(wtx, &b);
            dogecoin_wallet_wtx_free(wtx);
        }
    } else {
        /* addr record */
        dogecoin_wallet_addr *waddr = dogecoin_wallet_addr_new();
        if (waddr) {
            struct const_buffer b = buf;
            (void)dogecoin_wallet_addr_deserialize(waddr, &dogecoin_chainparams_main, &b);
            dogecoin_wallet_addr_free(waddr);
        }
    }

    return 0;
}
