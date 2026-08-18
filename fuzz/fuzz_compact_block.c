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
 * libFuzzer harness for the BIP152 compact block deserializers.
 *
 * All four parse peer-supplied bytes before any validation:
 *
 *   cmpctblock   header | nonce | vec<shortid[6]> | vec<prefilled txn>
 *   getblocktxn  block_hash | vec<differentially-encoded index>
 *   blocktxn     block_hash | vec<transaction>
 *   sendcmpct    announce (1) | version (8)
 *
 * cmpctblock and getblocktxn are the interesting pair. Both carry indices that
 * are differentially encoded, so the parser accumulates a running total from
 * attacker-controlled deltas -- the place an overflow or an out-of-range index
 * would come from. cmpctblock additionally interleaves prefilled transactions
 * with short IDs, so the two vectors have to stay consistent with each other.
 *
 * The first input byte selects the target so one corpus covers all four.
 *
 * Build:  ./configure CC=clang CFLAGS="-fsanitize=fuzzer-no-link" --enable-fuzz && make fuzz
 * Run:    ./fuzz/fuzz_compact_block CORPUS_DIR -max_len=100000
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/buffer.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/compact_block.h>
#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    uint8_t selector = data[0];
    struct const_buffer buf = { data + 1, size - 1 };

    switch (selector & 0x03) {
    /* These _free functions release the container as well as its members, so
       the structs have to come from their paired _new rather than the stack.
       A stack struct here is an immediate ASAN bad-free -- which is how the
       first version of this harness failed, two executions in. */
    case 0: {
        dogecoin_compact_block *cmpctblk = dogecoin_compact_block_new();
        if (cmpctblk) {
            dogecoin_compact_block_deserialize(cmpctblk, &buf,
                                               &dogecoin_chainparams_main);
            dogecoin_compact_block_free(cmpctblk);
        }
        break;
    }
    case 1: {
        dogecoin_getblocktxn *req = dogecoin_getblocktxn_new();
        if (req) {
            dogecoin_getblocktxn_deserialize(req, &buf);
            dogecoin_getblocktxn_free(req);
        }
        break;
    }
    case 2: {
        dogecoin_blocktxn *resp = dogecoin_blocktxn_new();
        if (resp) {
            dogecoin_blocktxn_deserialize(resp, &buf);
            dogecoin_blocktxn_free(resp);
        }
        break;
    }
    case 3: {
        /* Cheap by comparison, but it is the message that decides whether
           compact blocks are enabled at all and which version is negotiated,
           so it is worth covering rather than assuming a 9-byte parser is
           uninteresting. */
        dogecoin_bool high_bandwidth = false;
        uint64_t version = 0;
        dogecoin_p2p_msg_sendcmpct_deser(&high_bandwidth, &version, &buf);
        break;
    }
    }
    return 0;
}
