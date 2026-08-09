/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022-2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <errno.h>
#include <unistd.h>
#include <test/utest.h>

#include <assert.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif
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


/*
 * print_header() ignored a failed fopen: the error branch printed a message and
 * fell through to print_image(), which ran fgets() on a NULL FILE*, and then to
 * fclose(NULL). Opening a file that is not there is ordinary input, so this
 * crashed on ordinary input. print_image() is LIBDOGECOIN_API, so it is
 * reachable with NULL from outside this file as well.
 */

/* utils_hex_to_bin dereferences every argument. outLen is the one that invites
   a NULL -- it is a size out-parameter, which callers conventionally decline,
   and the crash landed on the last line after the conversion had already
   succeeded. */
void test_utils_hex_to_bin_null_guards()
{
    unsigned char out[4];
    size_t outlen = 0xdeadbeef;

    /* outLen declined: must convert and not crash */
    memset(out, 0xAA, sizeof(out));
    utils_hex_to_bin("01020304", out, 8, NULL);
    u_assert_int_eq(out[0], 0x01);
    u_assert_int_eq(out[1], 0x02);
    u_assert_int_eq(out[2], 0x03);
    u_assert_int_eq(out[3], 0x04);

    /* still reports the length when asked */
    memset(out, 0xAA, sizeof(out));
    utils_hex_to_bin("01020304", out, 8, &outlen);
    u_assert_int_eq((int)outlen, 4);
    u_assert_int_eq(out[3], 0x04);

    /* a NULL input or destination reports zero rather than writing anything */
    outlen = 0xdeadbeef;
    utils_hex_to_bin(NULL, out, 8, &outlen);
    u_assert_int_eq((int)outlen, 0);

    outlen = 0xdeadbeef;
    utils_hex_to_bin("01020304", NULL, 8, &outlen);
    u_assert_int_eq((int)outlen, 0);

    /* and neither combination crashes with outLen also declined */
    utils_hex_to_bin(NULL, NULL, 8, NULL);
}

void test_utils_null_file_guards()
{
    /* Must return quietly rather than dereferencing the NULL FILE*. */
    print_image(NULL);

    /* A path that cannot be opened must not crash. */
    print_header("this-path-does-not-exist-libdogecoin-test");

    /* NULL path was already guarded; assert it stays that way. */
    print_header(NULL);
}

/*
 * slice() is LIBDOGECOIN_API and had no in-tree callers, which is why neither
 * defect was noticed:
 *
 *   strncpy(result, str + start, end - start);
 *
 * strncpy writes no terminator when it copies its full count, and the count was
 * always exactly the number of bytes copied -- so result came back unterminated
 * for every input, and a caller printing it read past the buffer. Separately,
 * `end - start` is size_t arithmetic, so end < start wrapped to a length near
 * SIZE_MAX and strncpy ran until it hit the source NUL or a fault.
 */
void test_utils_slice()
{
    char buf[64];

    /* Ordinary slice, and it must be terminated. */
    memset(buf, 'X', sizeof(buf));
    slice("abcdefghij", buf, 2, 5);
    u_assert_str_eq(buf, "cde");
    u_assert_int_eq((int)strlen(buf), 3);

    /* Whole string. */
    memset(buf, 'X', sizeof(buf));
    slice("abcdef", buf, 0, 6);
    u_assert_str_eq(buf, "abcdef");

    /* end < start used to wrap to a huge count. Must yield an empty string. */
    memset(buf, 'X', sizeof(buf));
    slice("abcdefghij", buf, 5, 2);
    u_assert_str_eq(buf, "");

    /* end == start is an empty slice, not a one-byte read. */
    memset(buf, 'X', sizeof(buf));
    slice("abcdefghij", buf, 3, 3);
    u_assert_str_eq(buf, "");

    /* start past the end of the source must not read past it. */
    memset(buf, 'X', sizeof(buf));
    slice("abc", buf, 10, 20);
    u_assert_str_eq(buf, "");

    /* end past the end of the source clamps rather than over-reading. */
    memset(buf, 'X', sizeof(buf));
    slice("abc", buf, 1, 99);
    u_assert_str_eq(buf, "bc");

    /* NULL arguments are refused rather than dereferenced. */
    slice(NULL, buf, 0, 1);
    slice("abc", NULL, 0, 1);
}

/*
 * The wallet database and the sealed seed files were created with plain
 * fopen(), so their mode came from the process umask -- 0664 under the common
 * 0002, i.e. readable by every local user and writable by the group.
 *
 * The wallet database holds the master public key, which is enough to derive
 * every address and reconstruct the wallet's transaction history. The seal
 * files hold encrypted seeds and mnemonics; encryption means a leak is not an
 * immediate compromise, but handing out the ciphertext invites an offline
 * attack on a password-derived key.
 */
void test_utils_fopen_private()
{
#ifndef _WIN32
    /* A private directory of our own, rather than a fixed name in the working
       directory: two test runs in the same tree would otherwise share the file,
       and every stat()-then-open below would be a real check-then-use against a
       path anyone can pre-create. mkdtemp gives us 0700 and a name nobody can
       predict. */
    char dir[] = "/tmp/dogecoin_fopen_priv_XXXXXX";
    u_assert_true(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/f.tmp", dir);
    struct stat st;
    FILE* fp;

    fp = dogecoin_fopen_private(path, "wb");
    u_assert_true(fp != NULL);
    fputc('x', fp);
    /* fstat the descriptor we hold, not the path. Re-resolving the name would
       ask about whatever is there now rather than the file that was opened --
       the same check-then-use the function under test exists to avoid. */
    u_assert_int_eq(fstat(fileno(fp), &st), 0);
    /* Owner read/write only: no group or other bits at all. */
    u_assert_int_eq((int)(st.st_mode & 07777), 0600);
    u_assert_int_eq((int)(st.st_mode & (S_IRWXG | S_IRWXO)), 0);
    fclose(fp);

    /* Reopening must not widen the mode of a file that already exists. */
    fp = dogecoin_fopen_private(path, "a+b");
    u_assert_true(fp != NULL);
    u_assert_int_eq(fstat(fileno(fp), &st), 0);
    u_assert_int_eq((int)(st.st_mode & 07777), 0600);
    fclose(fp);

    remove(path);

    /* NULL arguments are refused rather than passed through. */
    u_assert_true(dogecoin_fopen_private(NULL, "wb") == NULL);
    u_assert_true(dogecoin_fopen_private(path, NULL) == NULL);
#endif

    /* "r" must not create. O_RDWR|O_CREAT used to be unconditional, so asking
       to open an existing file created an empty one instead of failing -- on
       the wallet path that turns "open my wallet" into "start a new one". */
    remove(path);
    fp = dogecoin_fopen_private(path, "rb");
    u_assert_true(fp == NULL);
    /* Nothing was created: a second open of the same mode still fails. Asking
       stat() instead would re-resolve the path, which is the pattern being
       tested against. */
    fp = dogecoin_fopen_private(path, "rb");
    u_assert_true(fp == NULL);

    /* "wx": exclusive create, which is what replaced the access()-then-open
       race in seal.c. Refuses an existing file and will not follow a symlink
       planted between the two calls the old pattern needed. */
    fp = dogecoin_fopen_private(path, "wbx");
    u_assert_true(fp != NULL);
    u_assert_int_eq(fstat(fileno(fp), &st), 0);
    u_assert_int_eq((int)(st.st_mode & 07777), 0600);
    fclose(fp);

    fp = dogecoin_fopen_private(path, "wbx");
    u_assert_true(fp == NULL);
    u_assert_int_eq(errno, EEXIST);

    remove(path);
    rmdir(dir);
}

