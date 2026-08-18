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
 * Regression tests for deterministic ECDSA nonces (RFC 6979).
 *
 * Every signing path in src/ecc.c currently passes
 * secp256k1_nonce_function_rfc6979 explicitly. These tests exist to fail
 * loudly if that ever changes -- for example if a signing path is rewired to
 * a randomised nonce for blinding, or a hardware backend is introduced that
 * supplies its own k.
 *
 * Why this matters more than a typical test:
 *
 *   s = k^-1 (z + r*d) mod n
 *
 * Sign two different messages under one key with the same k and both
 * signatures share an r. Subtracting the two s equations cancels d and yields
 * k = (z1 - z2)/(s1 - s2), after which d = (s1*k - z1)/r. Two modular
 * inversions and the private key is gone. A duplicate r is also visible to
 * anyone reading the chain, so an RNG regression here is not merely a bug --
 * it is a remotely exploitable key disclosure that an attacker can scan for.
 *
 * A biased nonce is worse in one respect: no r collision occurs, so the
 * duplicate-r scan finds nothing, while the key still falls to lattice
 * reduction given enough signatures.
 *
 * Determinism is the property that forecloses both at once, because k becomes
 * a function of (privkey, message) with no entropy source in the path.
 *
 * The properties asserted here are:
 *   1. Same key, same message  -> byte-identical signature (reproducibility)
 *   2. Same key, diff messages -> different r (no reuse)
 *   3. Diff keys, same message -> different signature (k depends on the key)
 *   4. All four public signing entry points hold 1-3
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

#define SIG_DER_MAX 74
#define SIG_COMPACT 64
/* The recoverable signers write 65 bytes, not 64: _fcomp puts a 27+recid[+4]
   header at sigrec[0] and the 64-byte r||s at &sigrec[1], and the plain
   recoverable variant reports *outlen = 65 even though it serialises 64. Sizing
   these buffers at SIG_COMPACT overflowed them by a byte -- adjacent on the
   stack, so cmp1's overflow landed in cmp2[0] and the comparison failed on
   aarch64 while passing on x86_64, which is what a stack overflow looks like. */
#define SIG_RECOVERABLE 65
#define NUM_ROUNDS  8

/* Two distinct message hashes. */
static const char* HASH_A =
    "26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a";
static const char* HASH_B =
    "9d1e0e2d9459d06523ad13e28a4093c2316baafe7aec5b25f30eba2e113599c4";

/* The r component of an ECDSA signature is the first 32 bytes of the
   compact (64-byte) encoding. Reuse of k is visible as an equal r. */
#define R_LEN 32

void test_rfc6979()
{
    dogecoin_key key_a, key_b;
    uint8_t hash_a[32], hash_b[32];

    unsigned char der1[SIG_DER_MAX], der2[SIG_DER_MAX];
    size_t der1len, der2len;
    unsigned char cmp1[SIG_RECOVERABLE], cmp2[SIG_RECOVERABLE], cmp3[SIG_RECOVERABLE];
    size_t cmp1len, cmp2len, cmp3len;
    int recid1, recid2;
    int i;

    /* dogecoin_ecc_start() is called once by the test harness. */
    dogecoin_random_init();

    memcpy_safe(hash_a, utils_hex_to_uint8(HASH_A), 32);
    memcpy_safe(hash_b, utils_hex_to_uint8(HASH_B), 32);

    dogecoin_privkey_init(&key_a);
    dogecoin_privkey_gen(&key_a);
    u_assert_int_eq(dogecoin_privkey_is_valid(&key_a), 1);

    dogecoin_privkey_init(&key_b);
    dogecoin_privkey_gen(&key_b);
    u_assert_int_eq(dogecoin_privkey_is_valid(&key_b), 1);

    /* ---------------------------------------------------------------
     * 1. Reproducibility: signing the same hash twice under the same key
     *    must return byte-identical output. This is the assertion that
     *    fails the instant an RNG enters the nonce path.
     * --------------------------------------------------------------- */
    der1len = der2len = SIG_DER_MAX;
    u_assert_int_eq(dogecoin_key_sign_hash(&key_a, hash_a, der1, &der1len), true);
    u_assert_int_eq(dogecoin_key_sign_hash(&key_a, hash_a, der2, &der2len), true);
    u_assert_uint32_eq(der1len, der2len);
    u_assert_mem_eq(der1, der2, der1len);

    /* Repeat across several rounds so a low-entropy or intermittently
       seeded RNG cannot pass by coincidence. */
    for (i = 0; i < NUM_ROUNDS; i++) {
        der2len = SIG_DER_MAX;
        u_assert_int_eq(dogecoin_key_sign_hash(&key_a, hash_a, der2, &der2len), true);
        u_assert_uint32_eq(der1len, der2len);
        u_assert_mem_eq(der1, der2, der1len);
    }

    /* ---------------------------------------------------------------
     * 2. No nonce reuse: different messages under one key must not share
     *    an r. An equal r here is the on-chain signature of a catastrophic
     *    RNG failure and permits direct private key recovery.
     * --------------------------------------------------------------- */
    cmp1len = cmp2len = SIG_COMPACT;
    u_assert_int_eq(dogecoin_key_sign_hash_compact(&key_a, hash_a, cmp1, &cmp1len), true);
    u_assert_int_eq(dogecoin_key_sign_hash_compact(&key_a, hash_b, cmp2, &cmp2len), true);
    u_assert_uint32_eq(cmp1len, SIG_COMPACT);
    u_assert_uint32_eq(cmp2len, SIG_COMPACT);
    u_assert_mem_not_eq(cmp1, cmp2, R_LEN);

    /* ---------------------------------------------------------------
     * 3. Key separation: the same message under a different key must
     *    produce a different nonce, hence a different r. If k depended
     *    only on the message, every signer would collide with every other
     *    signer on any commonly signed payload.
     * --------------------------------------------------------------- */
    cmp3len = SIG_COMPACT;
    u_assert_int_eq(dogecoin_key_sign_hash_compact(&key_b, hash_a, cmp3, &cmp3len), true);
    u_assert_mem_not_eq(cmp1, cmp3, R_LEN);

    /* ---------------------------------------------------------------
     * 4. The same three properties on the compact path, so a regression
     *    confined to one entry point is still caught.
     * --------------------------------------------------------------- */
    cmp2len = SIG_COMPACT;
    u_assert_int_eq(dogecoin_key_sign_hash_compact(&key_a, hash_a, cmp2, &cmp2len), true);
    u_assert_mem_eq(cmp1, cmp2, SIG_COMPACT);

    /* Recoverable variant: signature and recovery id must both be stable. */
    cmp1len = cmp2len = SIG_COMPACT;
    recid1 = recid2 = -1;
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable(
                        &key_a, hash_a, cmp1, &cmp1len, &recid1), true);
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable(
                        &key_a, hash_a, cmp2, &cmp2len, &recid2), true);
    u_assert_mem_eq(cmp1, cmp2, SIG_COMPACT);
    u_assert_int_eq(recid1, recid2);

    cmp2len = SIG_COMPACT;
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable(
                        &key_a, hash_b, cmp2, &cmp2len, &recid2), true);
    u_assert_mem_not_eq(cmp1, cmp2, R_LEN);

    /* Compressed-recoverable variant. */
    cmp1len = cmp2len = SIG_COMPACT;
    recid1 = recid2 = -1;
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable_fcomp(
                        &key_a, hash_a, cmp1, &cmp1len, &recid1), true);
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable_fcomp(
                        &key_a, hash_a, cmp2, &cmp2len, &recid2), true);
    u_assert_mem_eq(cmp1, cmp2, SIG_COMPACT);
    u_assert_int_eq(recid1, recid2);

    cmp2len = SIG_COMPACT;
    u_assert_int_eq(dogecoin_key_sign_hash_compact_recoverable_fcomp(
                        &key_a, hash_b, cmp2, &cmp2len, &recid2), true);
    u_assert_mem_not_eq(cmp1, cmp2, R_LEN);

    /* ---------------------------------------------------------------
     * 5. Freshly generated keys must not collide on r for a fixed message.
     *    A constant or counter-derived nonce would show up here.
     * --------------------------------------------------------------- */
    for (i = 0; i < NUM_ROUNDS; i++) {
        dogecoin_key k;
        dogecoin_privkey_init(&k);
        dogecoin_privkey_gen(&k);
        cmp2len = SIG_COMPACT;
        u_assert_int_eq(dogecoin_key_sign_hash_compact(&k, hash_a, cmp2, &cmp2len), true);
        u_assert_mem_not_eq(cmp3, cmp2, R_LEN);
        dogecoin_privkey_cleanse(&k);
    }

    dogecoin_privkey_cleanse(&key_a);
    dogecoin_privkey_cleanse(&key_b);
}
