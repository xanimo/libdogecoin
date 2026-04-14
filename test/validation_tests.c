/**********************************************************************
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include <dogecoin/cstr.h>
#include <dogecoin/validation.h>

#include <test/utest.h>

void test_validation()
{
    /* get_chainid returns the upper 16 bits from nVersion */
    u_assert_uint32_eq(get_chainid(0x00620102), 0x62);
    u_assert_uint32_eq(get_chainid(0xABCD0000), 0xABCD);
    u_assert_uint32_eq(get_chainid(1), 0);

    /* bit 8 indicates auxpow; low bits may vary */
    u_assert_int_eq(is_auxpow(0x00000100), true);
    u_assert_int_eq(is_auxpow(0x00000101), true);
    u_assert_int_eq(is_auxpow(0x00000002), false);

    /* legacy accepts v1 and the special v2-with-zero-chainid case */
    u_assert_int_eq(is_legacy(1), true);
    u_assert_int_eq(is_legacy(2), true);
    /* non-zero chain ID v2 and auxpow versions are not legacy */
    u_assert_int_eq(is_legacy(0x00620002), false);
    u_assert_int_eq(is_legacy(0x00620102), false);

    cstring* header_a = cstr_new_sz(80);
    cstring* header_b = cstr_new_sz(80);
    uint256_t hash_a;
    uint256_t hash_b;

    cstr_append_buf(header_a, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80);
    cstr_append_buf(header_b, "12345678901234567890123456789012345678901234567890123456789012345678901234567891", 80);

    /* same input must hash identically */
    u_assert_int_eq(dogecoin_block_header_scrypt_hash(header_a, &hash_a), true);
    u_assert_int_eq(dogecoin_block_header_scrypt_hash(header_a, &hash_b), true);
    u_assert_mem_eq(hash_a, hash_b, sizeof(hash_a));

    /* one-byte-different input should not produce the same hash */
    u_assert_int_eq(dogecoin_block_header_scrypt_hash(header_b, &hash_b), true);
    u_assert_mem_not_eq(hash_a, hash_b, sizeof(hash_a));

    cstr_free(header_a, true);
    cstr_free(header_b, true);
}

void test_validation_version_signed()
{
    /* 0x00620102: chain id 0x62 in bits 16..31, auxpow bit (0x100) set, low version bits = 2. */
    u_assert_uint32_eq(get_chainid((int32_t)0x00620102), 0x62);
    /* -1 keeps all bits set in two's complement, so chain id extraction yields 0xFFFF. */
    u_assert_uint32_eq(get_chainid(-1), 0xFFFF);
    /* INT32_MIN has only the sign bit set, so upper 16 bits are 0x8000. */
    u_assert_uint32_eq(get_chainid(INT32_MIN), 0x8000);

    /* Exact auxpow flag bit set. */
    u_assert_int_eq(is_auxpow((int32_t)0x00000100), true);
    /* No auxpow flag bit set. */
    u_assert_int_eq(is_auxpow((int32_t)0x00000002), false);
    /* -1 has auxpow bit set because all bits are 1. */
    u_assert_int_eq(is_auxpow(-1), true);
    /* INT32_MIN sets only bit 31, not auxpow bit 8. */
    u_assert_int_eq(is_auxpow(INT32_MIN), false);

    /* Legacy version 1. */
    u_assert_int_eq(is_legacy(1), true);
    /* Legacy special-case version 2 with chain id 0. */
    u_assert_int_eq(is_legacy(2), true);
    /* Version 2 plus non-zero chain id is not treated as legacy. */
    u_assert_int_eq(is_legacy((int32_t)0x00020002), false);
    /* Negative non-legacy version. */
    u_assert_int_eq(is_legacy(-1), false);
}
