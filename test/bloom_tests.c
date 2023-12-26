/**********************************************************************
 * Copyright (c) 2012 The Bitcoin developers                          *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>
#include <assert.h>
#include <dogecoin/sha2.h>
#include <dogecoin/bloom.h>
#include <dogecoin/wallet.h>
#include <test/utest.h>

static const char *data1 = "foo";
static const char *data2 = "bar";

void test_bloom()
{
	unsigned char md1[SHA256_DIGEST_LENGTH];
	unsigned char md2[SHA256_DIGEST_LENGTH];

	sha256_raw((unsigned char *)data1, strlen(data1), md1);
	sha256_raw((unsigned char *)data2, strlen(data2), md2);

	struct bloom bloom;

	assert(bloom_init(&bloom, 1000, 0.001, 0, 0) == true);

	bloom_insert(&bloom, md1, sizeof(md1));

	assert(bloom_contains(&bloom, md1, sizeof(md1)) == true);
	assert(bloom_contains(&bloom, md2, sizeof(md2)) == false);

	cstring *ser = cstr_new_sz(1024);
	ser_bloom(ser, &bloom);

	struct bloom bloom2;
	__bloom_init(&bloom2);

	struct const_buffer buf = { ser->str, ser->len };

	assert(deser_bloom(&bloom2, &buf) == true);

	assert(bloom.nHashFuncs == bloom2.nHashFuncs);
	assert(bloom.vData->len == bloom2.vData->len);
	assert(memcmp(bloom.vData->str, bloom2.vData->str, bloom2.vData->len) == 0);

	assert(bloom_contains(&bloom2, md1, sizeof(md1)) == true);
	assert(bloom_contains(&bloom2, md2, sizeof(md2)) == false);

	bloom_free(&bloom2);

	bloom_free(&bloom);

	cstr_free(ser, true);

    char* address = "D6JQ6C48u9yYYarubpzdn2tbfvEq12vqeY DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y DBcR32NXYtFy6p4nzSrnVVyYLjR42VxvwR";

    dogecoin_wallet* wallet = dogecoin_wallet_init(&dogecoin_chainparams_main, address, NULL, 0, 0, false, false, -1, false);
    struct bloom bloom3;
    assert(bloom_init(&bloom3, wallet->waddr_vector->len, 0.001, 0, BLOOM_UPDATE_ALL) == true);
    unsigned int i = 0;
    for (; i < wallet->waddr_vector->len; i++) {
        dogecoin_wallet_addr* waddr = vector_idx(wallet->waddr_vector, i);
        bloom_insert(&bloom3, waddr->pubkeyhash, sizeof(waddr->pubkeyhash));
        assert(bloom_contains(&bloom3, waddr->pubkeyhash, sizeof(waddr->pubkeyhash)) == true);
    }

    assert(bloom_size_ok(&bloom3));
    cstring *compactsize = cstr_new_sz(0);
    ser_compact_size(compactsize, bloom3.vData->len);
    size_t filterlength = bloom3.vData->len;
    cstring *ser2 = cstr_new_sz(9 + compactsize->len + filterlength);
    ser_bloom(ser2, &bloom3);
    cstr_free(compactsize, true);
    printf("%s\n", utils_uint8_to_hex((const uint8_t*)ser2->str, ser2->len));
    printf("%s\n", utils_uint8_to_hex((const uint8_t*)bloom3.vData->str, bloom3.vData->len));

    struct bloom bloom4;
    __bloom_init(&bloom4);

    struct const_buffer buf2 = { ser2->str, ser2->len };
    assert(deser_bloom(&bloom4, &buf2) == true);
    assert(bloom3.nHashFuncs == bloom4.nHashFuncs);
    assert(bloom3.vData->len == bloom4.vData->len);
    assert(memcmp(bloom3.vData->str, bloom4.vData->str, bloom4.vData->len) == 0);

    bloom_free(&bloom4);

    bloom_free(&bloom3);

    cstr_free(ser2, true);
    dogecoin_wallet_free(wallet);
}