/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2024 bluezr                                          *
 * Copyright (c) 2024 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test/utest.h>

#include <dogecoin/bip38.h>
#include <dogecoin/random.h>
#include <dogecoin/utils.h>

void test_random_init_cb(void)
{
}

dogecoin_bool test_random_bytes_cb(uint8_t* buf, uint32_t len, const uint8_t update_seed)
{
    (void)(update_seed);
    for (uint32_t i = 0; i < len; i++)
        buf[i] = 0;
    return false;
}

void test_random()
{
    unsigned char r_buf[32];
    dogecoin_mem_zero(r_buf, 32);
    dogecoin_random_init();
    dogecoin_bool ret = dogecoin_random_bytes(r_buf, 32, 0);
    u_assert_int_eq(ret, true);
    unsigned char r_buf64[64];
    dogecoin_mem_zero(r_buf64, 64);
    dogecoin_random_init();
    dogecoin_bool ret64 = dogecoin_random_bytes(r_buf64, 64, 0);
    u_assert_int_eq(ret64, true);

    fast_random_context* this = init_fast_random_context(true, (const uint256_t*)r_buf);
    fast_random_context* this2 = init_fast_random_context(true, (const uint256_t*)r_buf);
    dogecoin_mem_zero(r_buf, 32);
    this->rng->output(this->rng, r_buf, 32);
    this2->rng->output(this2->rng, r_buf, 32);

    assert(this->randbool == this2->randbool);
    u_assert_int_eq(this->randbits(this, 3), this2->randbits(this2, 3));
    u_assert_uint32_eq(this->rand32(this), this2->rand32(this2));
    u_assert_uint64_eq(this->rand64(this), this->rand64(this2));
    uint256_t* r256_1 = this->rand256(this);
    uint256_t* r256_2 = this2->rand256(this2);
    u_assert_mem_eq(r256_1, r256_2, 32);
    dogecoin_free(r256_1);
    dogecoin_free(r256_2);
    free_fast_random_context(this);
    free_fast_random_context(this2);

    fast_random_context* this3 = init_fast_random_context(false, 0);
    fast_random_context* this4 = init_fast_random_context(false, 0);
    u_assert_uint32_not_eq(this3->rand32(this3), this4->rand32(this4));
    u_assert_uint64_not_eq(this3->rand64(this3), this4->rand64(this4));
    uint256_t* r256_3 = this3->rand256(this3);
    uint256_t* r256_4 = this4->rand256(this4);
    u_assert_mem_not_eq(r256_3, r256_4, 32);
    dogecoin_free(r256_3);
    dogecoin_free(r256_4);
    free_fast_random_context(this3);
    free_fast_random_context(this4);

    dogecoin_rnd_mapper mymapper = {test_random_init_cb, test_random_bytes_cb};
    dogecoin_rnd_set_mapper(mymapper);
    u_assert_int_eq(dogecoin_random_bytes(r_buf, 32, 0), false);
    for (uint8_t i = 0; i < 32; ++i)
        u_assert_int_eq(r_buf[i], 0);
    // switch back to the default random callback mapper
    dogecoin_rnd_set_mapper_default();
}


/* --- regression: a failing RNG must report false, never a truthy value --- */

static void rnd_noop_init(void) {}

/* Fails correctly: reports false and leaves the buffer alone. */
static dogecoin_bool rnd_fail_false(uint8_t* buf, uint32_t len, const uint8_t update_seed)
{
    (void)buf; (void)len; (void)update_seed;
    return false;
}

/* --- regression: a failing RNG must not yield key material --- */

static void rng_prop_init(void) {}

static dogecoin_bool rng_prop_fail(uint8_t* buf, uint32_t len, const uint8_t update_seed)
{
    (void)buf; (void)len; (void)update_seed;
    return false;
}

/* Fails the way the WIN32 branch used to: `return -1` from a function whose
   return type is dogecoin_bool. */
static dogecoin_bool rnd_fail_minus_one(uint8_t* buf, uint32_t len, const uint8_t update_seed)
{
    (void)buf; (void)len; (void)update_seed;
    return (dogecoin_bool)-1;
}

/*
 * dogecoin_bool is a uint8_t, so `return -1` reaches the caller as 255 -- a
 * true value. The WIN32 path did exactly that on both of its failure exits
 * (CryptGenRandom failure, and no RNG provider at all), so every caller
 * written as `if (!dogecoin_random_bytes(...))` saw success while buf still
 * held whatever was on the stack.
 *
 * The second half of this test pins that hazard as an executable fact rather
 * than a comment: if the convention or the underlying type ever changes, this
 * is where it surfaces.
 */
void test_random_failure_is_false()
{
    dogecoin_rnd_mapper mapper;
    uint8_t buf[32];
    dogecoin_bool r;

    /* A correct failure is exactly false, and callers can test it. */
    mapper.dogecoin_random_init = rnd_noop_init;
    mapper.dogecoin_random_bytes = rnd_fail_false;
    dogecoin_rnd_set_mapper(mapper);

    memset(buf, 0xAB, sizeof(buf));
    r = dogecoin_random_bytes(buf, sizeof(buf), 0);
    u_assert_int_eq((int)r, 0);
    u_assert_true(!r);

    /* The trap this change removes: -1 survives as 255 and is truthy, so the
       caller's `if (!r)` never fires. */
    mapper.dogecoin_random_bytes = rnd_fail_minus_one;
    dogecoin_rnd_set_mapper(mapper);

    r = dogecoin_random_bytes(buf, sizeof(buf), 0);
    u_assert_int_eq((int)r, 255);
    /* Spelled out rather than u_assert_true(r): that macro compares against 1,
       and the whole point here is that 255 is not 1 yet is still true. */
    u_assert_int_eq(r ? 1 : 0, 1);
    u_assert_int_eq((int)(!r), 0);

    dogecoin_rnd_set_mapper_default();

    /* And the real RNG still succeeds and writes the buffer. */
    memset(buf, 0, sizeof(buf));
    u_assert_true(dogecoin_random_bytes(buf, sizeof(buf), 0));
}

/*
 * Eleven call sites discarded dogecoin_random_bytes' return value, six of them
 * in BIP38 -- including seedb, which derives factorb and thence the private
 * key. With the return ignored, an RNG failure produced a key from whatever was
 * already in the buffer.
 *
 * Driving the real failure path is not possible from a test, so this installs a
 * mapper that always fails and checks the callers behave: the encrypt paths
 * must refuse rather than mint a key.
 */
void test_random_failure_propagates()
{
    dogecoin_rnd_mapper mapper;
    uint8_t privkey[DOGECOIN_ECKEY_PKEY_LENGTH];
    char encrypted[128];
    char confirmation[128];
    size_t enc_sz, conf_sz;
    uint32_t lot = 12345, sequence = 42;

    mapper.dogecoin_random_init = rng_prop_init;
    mapper.dogecoin_random_bytes = rng_prop_fail;
    dogecoin_rnd_set_mapper(mapper);

    /* EC-multiplied encryption reaches seedb and the owner entropy. It must
       fail rather than return a key derived from an unwritten buffer. */
    enc_sz = sizeof(encrypted);
    conf_sz = sizeof(confirmation);
    u_assert_int_eq((int)dogecoin_bip38_encrypt_ec_multiplied(
        "passphrase", true, false, 0, 0, "DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y",
        privkey, encrypted, &enc_sz, confirmation, &conf_sz), 0);

    /* Same with lot/sequence, which additionally goes through the owner
       entropy path. */
    enc_sz = sizeof(encrypted);
    conf_sz = sizeof(confirmation);
    u_assert_int_eq((int)dogecoin_bip38_encrypt_ec_multiplied(
        "passphrase", true, true, 100000, 7, "DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y",
        privkey, encrypted, &enc_sz, confirmation, &conf_sz), 0);

    /*
     * Isolate the seedb site. encrypt_from_intermediate takes a ready-made
     * intermediate code -- the BIP38 spec vector -- so the owner entropy is
     * already fixed and the RNG is reached for seedb alone. Without the check
     * at that site this call still returns a key, because nothing upstream
     * fails first.
     */
    enc_sz = sizeof(encrypted);
    conf_sz = sizeof(confirmation);
    u_assert_int_eq((int)dogecoin_bip38_encrypt_from_intermediate(
        "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
        true, NULL, "DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y",
        encrypted, &enc_sz, confirmation, &conf_sz), 0);

    /* dogecoin_bip38_generate_lot_sequence returns void and is public API, so
       it signals failure with lot 0 -- a value every consumer of these already
       rejects. */
    dogecoin_bip38_generate_lot_sequence(&lot, &sequence);
    u_assert_uint32_eq(lot, 0U);
    u_assert_uint32_eq(sequence, 0U);

    dogecoin_rnd_set_mapper_default();

    /* And with the real RNG restored, the same call succeeds. */
    enc_sz = sizeof(encrypted);
    conf_sz = sizeof(confirmation);
    u_assert_int_eq((int)dogecoin_bip38_encrypt_ec_multiplied(
        "passphrase", true, false, 0, 0, "DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y",
        privkey, encrypted, &enc_sz, confirmation, &conf_sz), 1);
}
