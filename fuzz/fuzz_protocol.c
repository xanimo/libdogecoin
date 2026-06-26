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
 * libFuzzer harness for p2p message deserializers in protocol.c.
 *
 * Primary target: dogecoin_p2p_deser_msg_getheaders, which parses an
 * untrusted, unauthenticated getheaders message (a block-locator vector
 * plus a hashstop). Also exercises the version-message deserializer.
 *
 * The first input byte selects which parser to drive, so one corpus can
 * cover multiple message types.
 *
 * Build:  ./configure CC=clang CFLAGS="-fsanitize=fuzzer-no-link" --enable-fuzz && make fuzz
 * Run:    ./fuzz/fuzz_protocol CORPUS_DIR -max_len=100000
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/protocol.h>
#include <dogecoin/buffer.h>
#include <dogecoin/vector.h>
#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>

static void free_locator(void *p) { dogecoin_free(p); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    uint8_t selector = data[0];
    struct const_buffer buf = { data + 1, size - 1 };

    switch (selector & 0x01) {
    case 0: {
        /* getheaders: block-locator vector + hashstop */
        vector_t *locators = vector_new(8, free_locator);
        uint256_t hashstop;
        memset(hashstop, 0, sizeof(hashstop));
        dogecoin_p2p_deser_msg_getheaders(locators, hashstop, &buf);
        vector_free(locators, true);
        break;
    }
    case 1: {
        /* version message */
        dogecoin_p2p_version_msg msg;
        memset(&msg, 0, sizeof(msg));
        dogecoin_p2p_msg_version_deser(&msg, &buf);
        break;
    }
    }
    return 0;
}
