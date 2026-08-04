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
 * libFuzzer harness for dogecoin_psbt_deserialize + serialize round-trip.
 *
 * Drives the BIP174 PSBT parser (src/psbt.c) on untrusted bytes. The parser
 * walks attacker-controlled key/value maps with varint-prefixed lengths and
 * fixed-size pubkey copies, so it is a natural target for memory-safety and
 * unbounded-allocation defects. This harness exercises:
 *   - deser_psbt_kv: the klen/vlen varint allocation path (PR #352, kv-OOM)
 *   - the BIP32 derivation handlers: the klen==34 pubkey-copy guard
 *     in both the input and output maps (PR #353, heap overflow)
 *   - the global/input/output map state machine and free() paths
 *
 * On a successful parse it re-serializes the PSBT to also exercise the
 * serializer and surface deser/ser asymmetry. dogecoin_psbt_deserialize
 * owns the *out allocation: on success the caller frees it; on failure it
 * sets *out = NULL and frees internally, so the harness only frees on
 * success.
 *
 * The checked-in regression corpus at test/fuzz_corpus/psbt/ (including the
 * crash-eea3d... input that reproduced the #353 overflow pre-fix) should be
 * passed as a seed/replay directory so the harness proves those fixes hold.
 */
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/psbt.h>
#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    dogecoin_psbt *psbt = NULL;
    if (dogecoin_psbt_deserialize(data, size, &psbt) && psbt) {
        /* Round-trip: re-serialize the parsed PSBT. Exercises the
         * serialization path and surfaces deser/ser asymmetry. */
        cstring *out = dogecoin_psbt_serialize(psbt);
        if (out) cstr_free(out, 1);
        dogecoin_psbt_free(psbt);
    }
    /* On failure dogecoin_psbt_deserialize sets *out = NULL and frees its
     * own internal allocation, so there is nothing to free here. */
    return 0;
}
