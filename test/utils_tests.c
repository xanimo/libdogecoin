/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022-2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <test/utest.h>

#include <assert.h>
#include <dogecoin/utils.h>

  /* test a buffer overflow protection */
static const char hash_buffer_exc[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c128969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";

static const char hex2[] = "AA969cdfFFffFF3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";

void test_utils()
    {
    size_t outlen = 0;
    unsigned char data[] = { 0x00, 0xFF, 0x00, 0xAA, 0x00, 0xFF, 0x00, 0xAA };
    char hash[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";
    char hex[sizeof(data) * 2 + 1];
    unsigned char data2[sizeof(data)];
    uint8_t* hash_bin = utils_hex_to_uint8(hash);
    char* new = utils_uint8_to_hex(hash_bin, 32);
    unsigned char data3[64];
    assert(strncmp(new, hash, 64) == 0);

    utils_clear_buffers();

    utils_bin_to_hex(data, sizeof(data), hex);
    assert(strcmp(hex, "00ff00aa00ff00aa") == 0);

    utils_hex_to_bin(hex, data2, strlen(hex), &outlen);
    assert(outlen == 8);
    assert(memcmp(data, data2, outlen) == 0);
    utils_hex_to_uint8(hash_buffer_exc);

    /* test upper and lowercase A / F */
    utils_hex_to_bin(hex2, data3, strlen(hex2), &outlen);
    utils_hex_to_uint8(hex2);
    utils_clear_buffers();
    }

void test_net_flag_defined() {
    assert(dogecoin_network_enabled()==true);
}

void test_net_flag_not_defined() {
    assert(dogecoin_network_enabled()==false);
}

void test_base64() {
    static const char* vstrIn[]  = {"","f","fo","foo","foob","fooba","foobar"};
    static const char* vstrOut[] = {"","Zg==","Zm8=","Zm9v","Zm9vYg==","Zm9vYmE=","Zm9vYmFy"};
    for (unsigned int i=0; i<sizeof(vstrIn)/sizeof(vstrIn[0]); i++)
    {
    	int input_length = strlen(vstrIn[i]);
        unsigned char* enc_output = dogecoin_uchar_vla(1+(sizeof(char)*base64_encoded_size(input_length)));
        unsigned int enc_out_len = base64_encode((unsigned char*)vstrIn[i], input_length, enc_output);
        u_assert_str_eq((const char*)enc_output, vstrOut[i]);
        unsigned char* dec_output = dogecoin_uchar_vla(base64_decoded_size(strlen((const char*)enc_output)+1)+1);
        unsigned int dec_out_len = base64_decode(enc_output, enc_out_len, dec_output);
        u_assert_str_eq((const char*)dec_output, vstrIn[i]);
        u_assert_int_eq(input_length, dec_out_len);
        dogecoin_free(enc_output);
        dogecoin_free(dec_output);
    }
}

#if defined(USE_DIT) && defined(__aarch64__)
/* Read PSTATE.DIT for direct test verification (mirrors src/utils.c). */
static unsigned dit_test_read_bit(void)
{
    uint64_t v = 0;
    __asm__ volatile("mrs %0, S3_3_C4_C2_5" : "=r"(v));
    return (unsigned)((v >> 24) & 1);
}
#endif

void test_dit()
{
    dogecoin_bool dit_supported = is_DIT_supported();
    dogecoin_bool first_enable = enable_DIT();
    debug_print("DIT test: supported=%d first_enable_result=%d\n", (int)dit_supported, (int)first_enable);

    if (dit_supported) {
        u_assert_int_eq(first_enable, true);
#if defined(USE_DIT) && defined(__aarch64__)
        /* enable_DIT() must actually have set PSTATE.DIT on this thread. */
        u_assert_int_eq(dit_test_read_bit(), 1u);
#endif
        disable_DIT();
#if defined(USE_DIT) && defined(__aarch64__)
        /* Prior bit was 0 (not previously enabled), so disable_DIT() must clear it. */
        u_assert_int_eq(dit_test_read_bit(), 0u);
#endif
        debug_print("%s", "DIT test: disabled after first enable\n");
        dogecoin_bool second_enable = enable_DIT();
        debug_print("DIT test: second_enable_result=%d\n", (int)second_enable);
        u_assert_int_eq(second_enable, true);
#if defined(USE_DIT) && defined(__aarch64__)
        u_assert_int_eq(dit_test_read_bit(), 1u);
#endif
        disable_DIT();
#if defined(USE_DIT) && defined(__aarch64__)
        u_assert_int_eq(dit_test_read_bit(), 0u);
        /* A second disable_DIT() with no prior enable_DIT() must be a no-op. */
        disable_DIT();
        u_assert_int_eq(dit_test_read_bit(), 0u);

        /* Nested enable/disable: only the outermost pair should toggle DIT. */
        dogecoin_bool outer = enable_DIT();
        u_assert_int_eq(outer, true);
        u_assert_int_eq(dit_test_read_bit(), 1u);
        dogecoin_bool inner = enable_DIT();
        u_assert_int_eq(inner, true);
        u_assert_int_eq(dit_test_read_bit(), 1u);
        disable_DIT();
        /* Inner disable must not clear DIT while the outer scope is still active. */
        u_assert_int_eq(dit_test_read_bit(), 1u);
        disable_DIT();
        /* Outer disable restores the prior (cleared) bit. */
        u_assert_int_eq(dit_test_read_bit(), 0u);
#endif
        debug_print("%s", "DIT test: disabled after second enable\n");
    } else {
        /* On platforms without DIT, both enable and supported must report false. */
        u_assert_int_eq(first_enable, false);
        disable_DIT();
        debug_print("%s", "DIT test: disabled (DIT not supported)\n");
    }
}
