/*
 The MIT License (MIT)

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
 * Entropy assertions for the RNG and key generation paths.
 *
 * test_random() checks that dogecoin_random_bytes() RETURNS true. It does not
 * examine what was written to the buffer. A source that reports success while
 * emitting constant, counter-derived, or truncated output therefore passes the
 * existing suite unchanged.
 *
 * That combination -- an entropy source silently degraded, reporting success,
 * with no test inspecting its output -- is the exact shape of the Coldcard
 * ngu.random failure disclosed in 2026, which went undetected for five years
 * and affected every device feature drawing on the RNG.
 *
 * libdogecoin has the same structural exposure in dogecoin_privkey_gen():
 *
 *     do {
 *         res = dogecoin_random_bytes(privkey->privkey, 32, 0);
 *         if (!res) return false;
 *     } while (dogecoin_ecc_verify_privatekey(privkey->privkey) == 0);
 *
 * RNG output becomes the secp256k1 private key directly, with no derivation
 * in between -- the same path Block's disclosure identified as worst-case,
 * because the derived address is a public validation oracle for an attacker
 * enumerating a collapsed keyspace.
 *
 * These tests assert on OUTPUT rather than return codes. They are deliberately
 * coarse: each bound below is chosen so that a correct CSPRNG fails with
 * probability far below 2^-40, while a degraded source fails immediately.
 * They are not a statistical test suite and are not a substitute for one; they
 * are a tripwire for catastrophic degradation.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test/utest.h>

#include <dogecoin/ecc.h>
#include <dogecoin/key.h>
#include <dogecoin/random.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>

#define SAMPLES   64
#define KEYLEN    32

/* A uniform 256-bit value has expected popcount 128 with stddev 8. Bounds of
   [64, 192] are 8 sigma out; a correct RNG fails with p < 2^-49 per sample.
   Counter-derived, all-zero, or all-ones output fails on the first sample. */
#define POPCOUNT_MIN 64
#define POPCOUNT_MAX 192

static int popcount_buf(const unsigned char* b, size_t len)
{
    static const unsigned char tbl[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    size_t i;
    int n = 0;
    for (i = 0; i < len; i++)
        n += tbl[b[i] & 0x0f] + tbl[(b[i] >> 4) & 0x0f];
    return n;
}

static int buf_is_zero(const unsigned char* b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        if (b[i] != 0) return 0;
    return 1;
}

void test_rng_entropy()
{
    unsigned char samples[SAMPLES][KEYLEN];
    unsigned char keys[SAMPLES][KEYLEN];
    int i, j, pc;

    dogecoin_random_init();

    /* ---------------------------------------------------------------
     * 1. dogecoin_random_bytes must actually write entropy.
     *    Zero the buffer first: a source that returns true without
     *    writing leaves it zeroed, and that must fail here.
     * --------------------------------------------------------------- */
    for (i = 0; i < SAMPLES; i++) {
        dogecoin_mem_zero(samples[i], KEYLEN);
        u_assert_int_eq(dogecoin_random_bytes(samples[i], KEYLEN, 0), true);
        u_assert_int_eq(buf_is_zero(samples[i], KEYLEN), 0);
        pc = popcount_buf(samples[i], KEYLEN);
        u_assert_int_eq(pc >= POPCOUNT_MIN && pc <= POPCOUNT_MAX, 1);
    }

    /* Successive draws must differ. Two equal 32-byte draws from a correct
       source has probability 2^-256; from a stuck source, probability 1. */
    for (i = 1; i < SAMPLES; i++)
        u_assert_mem_not_eq(samples[0], samples[i], KEYLEN);

    /* ---------------------------------------------------------------
     * 2. No byte position may be constant across all samples.
     *    Catches truncated reads that zero-pad a short buffer, and
     *    fixed-prefix output. For a correct source the probability that
     *    any given position is constant across 64 draws is 256*(1/256)^63.
     * --------------------------------------------------------------- */
    for (j = 0; j < KEYLEN; j++) {
        int varied = 0;
        for (i = 1; i < SAMPLES; i++) {
            if (samples[i][j] != samples[0][j]) { varied = 1; break; }
        }
        u_assert_int_eq(varied, 1);
    }

    /* ---------------------------------------------------------------
     * 3. The same properties on generated private keys.
     *    dogecoin_privkey_gen() feeds RNG output straight into the key,
     *    so this is the surface an attacker enumerates.
     * --------------------------------------------------------------- */
    for (i = 0; i < SAMPLES; i++) {
        dogecoin_key k;
        dogecoin_privkey_init(&k);
        u_assert_int_eq(dogecoin_privkey_gen(&k), true);
        u_assert_int_eq(dogecoin_privkey_is_valid(&k), 1);
        memcpy_safe(keys[i], k.privkey, KEYLEN);
        dogecoin_privkey_cleanse(&k);

        u_assert_int_eq(buf_is_zero(keys[i], KEYLEN), 0);

        /* A counter- or small-integer-derived key has almost all bits clear.
           This is the assertion that fails on the Coldcard failure mode. */
        pc = popcount_buf(keys[i], KEYLEN);
        u_assert_int_eq(pc >= POPCOUNT_MIN && pc <= POPCOUNT_MAX, 1);

        /* The top half must not be uniformly zero: that is what a short
           read, a 128-bit seed widened to 256, or a small counter looks
           like. Probability for a correct source: 2^-128. */
        u_assert_int_eq(buf_is_zero(keys[i], KEYLEN / 2), 0);
    }

    /* No two generated keys may collide. */
    for (i = 0; i < SAMPLES; i++)
        for (j = i + 1; j < SAMPLES; j++)
            u_assert_mem_not_eq(keys[i], keys[j], KEYLEN);

    /* Keys must not be sequential. A counter source produces keys differing
       by a constant delta; check the low word is not simply incrementing. */
    for (i = 1; i < SAMPLES; i++) {
        int same_prefix = (memcmp(keys[i], keys[i - 1], KEYLEN - 4) == 0);
        u_assert_int_eq(same_prefix, 0);
    }

    /* ---------------------------------------------------------------
     * 4. Per-byte-position variety across generated keys, as in (2).
     * --------------------------------------------------------------- */
    for (j = 0; j < KEYLEN; j++) {
        int varied = 0;
        for (i = 1; i < SAMPLES; i++) {
            if (keys[i][j] != keys[0][j]) { varied = 1; break; }
        }
        u_assert_int_eq(varied, 1);
    }
}
