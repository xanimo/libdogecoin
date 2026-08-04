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

#include <stddef.h>

#include <test/utest.h>

/* libdogecoin.h is deliberately the only header this file includes.
 *
 * dogecoin_chainparams is declared twice by design -- once in the public
 * libdogecoin.h, once in the internal chainparams.h -- so that the installed
 * header stays self-contained and a consumer needs exactly one include. The
 * objects (dogecoin_chainparams_main and friends) are defined once, in
 * chainparams.c, against the internal declaration and read through the public
 * one.
 *
 * The cost of two declarations is that they can drift, and they did: the public
 * copy was missing genesisblockchainwork. That field sits in the middle rather
 * than at the end, so it was not a harmless truncation -- every field after it
 * landed 32 bytes early. A consumer reading default_port through the public
 * header read at offset 84 while the object had it at 116, landing in the first
 * four bytes of the chainwork. No compile error, no warning.
 *
 * Including both headers here to compare them is not possible: C forbids
 * redefining a struct tag even identically. So this file does the next best
 * thing and reads the exported objects exactly as a consumer does, through the
 * public declaration alone. The values below agree only if that declaration
 * describes the same layout chainparams.c was compiled with. Drift shifts the
 * offsets and these comparisons fail. */
#include <dogecoin/libdogecoin.h>

void test_chainparams_abi()
{
    /* Fields before the divergence. If these fail the symbol itself is wrong,
       not the layout. */
    u_assert_str_eq(dogecoin_chainparams_main.chainname, "main");
    u_assert_int_eq(dogecoin_chainparams_main.b58prefix_pubkey_address, 0x1e);
    u_assert_int_eq(dogecoin_chainparams_main.b58prefix_secret_address, 0x9e);
    u_assert_uint32_eq(dogecoin_chainparams_main.b58prefix_bip32_pubkey, 0x02facafd);

    /* genesisblockchainwork, the field that was missing. Mainnet's is
       0x00100010 in the low word, stored little-endian. Reading it proves the
       public declaration has the field rather than skipping past it. */
    u_assert_int_eq(dogecoin_chainparams_main.genesisblockchainwork[0], 0x10);
    u_assert_int_eq(dogecoin_chainparams_main.genesisblockchainwork[2], 0x10);

    /* The field immediately after it. This is the assertion the old layout
       failed, and the one a consumer would have hit first. */
    u_assert_int_eq(dogecoin_chainparams_main.default_port, 22556);
    u_assert_int_eq(dogecoin_chainparams_test.default_port, 44556);
    u_assert_int_eq(dogecoin_chainparams_regtest.default_port, 18332);

    /* Further past the shift: the seed list moves by the same 32 bytes, so the
       old layout read into the middle of a hostname. */
    u_assert_str_eq(dogecoin_chainparams_main.dnsseeds[0].domain, "seed.multidoge.org");

    /* Trailing fields the public header did not declare at all.

       strict_id and auxpow_id are both typed dogecoin_bool, but only the first
       is a boolean: auxpow_id carries the AuxPoW chain ID, 0x62 for Dogecoin on
       every network. dogecoin_bool is a uint8_t, so a chain ID above 255 would
       truncate silently. Dogecoin's does not, and retyping it is a separate
       change -- asserted here as the value it actually holds, not as true. */
    u_assert_int_eq(dogecoin_chainparams_main.strict_id, true);
    u_assert_int_eq(dogecoin_chainparams_test.strict_id, false);
    u_assert_int_eq(dogecoin_chainparams_main.auxpow_id, 0x62);
    u_assert_int_eq(dogecoin_chainparams_regtest.auxpow_id, 0x62);

    /* minimumchainwork, the last field in the struct, so reading it correctly
       means the whole extent lines up. Deliberately not pow_limit: its byte
       order is being changed under separate review, and this test should fail
       on layout drift only. */
    u_assert_int_eq(dogecoin_chainparams_main.minimumchainwork[0], 0x9b);
    u_assert_int_eq(dogecoin_chainparams_main.minimumchainwork[1], 0xa4);
    u_assert_int_eq(dogecoin_chainparams_regtest.minimumchainwork[0], 0x02);

    /* Whole-struct size and the two offsets that moved. A consumer that
       stack-allocates or copies a dogecoin_chainparams gets these wrong when the
       declaration is short, and the damage is silent. */
    u_assert_uint32_eq((uint32_t)sizeof(dogecoin_chainparams), 2236);
    u_assert_uint32_eq((uint32_t)offsetof(dogecoin_chainparams, default_port), 116);
    u_assert_uint32_eq((uint32_t)offsetof(dogecoin_chainparams, dnsseeds), 120);
}
