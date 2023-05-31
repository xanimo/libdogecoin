/**********************************************************************
 * Copyright (c) 2023 bluezr                                          *
 * Copyright (c) 2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/uint256.h>
#include <dogecoin/arith_uint256.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

// Convert vector to base_uint, via uint256 blob
base_uint* base_uintV(const vector* vch) {
    uint256* u = uint256_u(vch);
    return uint_to_arith(u);
}

// Convert vector to base_uint, via uint256 blob
base_uint* base_uintU(const uint256* u256) {
    return uint_to_arith(u256);
}

void shiftArrayRight(unsigned char* to, const unsigned char* from, unsigned int arrayLength, unsigned int bitsToShift) {
    for (unsigned int T=0; T < arrayLength; ++T)
    {
        unsigned int F = (T+bitsToShift/8);
        if (F < arrayLength)
            to[T]  = from[F] >> (bitsToShift%8);
        else
            to[T] = 0;
        if (F + 1 < arrayLength)
            to[T] |= from[(F+1)] << (8-bitsToShift%8);
    }
}

void shiftArrayLeft(unsigned char* to, const unsigned char* from, unsigned int arrayLength, unsigned int bitsToShift) {
    for (unsigned int T=0; T < arrayLength; ++T)
    {
        if (T >= bitsToShift/8)
        {
            unsigned int F = T-bitsToShift/8;
            to[T]  = from[F] << (bitsToShift%8);
            if (T >= bitsToShift/8+1)
                to[T] |= from[F-1] >> (8-bitsToShift%8);
        }
        else {
            to[T] = 0;
        }
    }
}

bool almostEqual(double d1, double d2)
{
    return fabs(d1-d2) <= 4*fabs(d1)*__DBL_EPSILON__;
}

void foo (int i)
{
  printf ("foo %d!\n", i);
}

void bar (int i)
{
  printf ("%d bar!\n", i);
}

void message (void (*func)(int), int times)
{
  int j;
  for (j=0; j<times; ++j)
    func (j);  /* (*func) (j); would be equivalent. */
}

void example (int want_foo) 
{
  void (*pf)(int) = &bar; /* The & is optional. */
  if (want_foo)
    pf = foo;
  message (pf, 5);
}

void test_arith_uint256() {
    example(1);
    // vector* tmp = vector_new(1, free);
    const unsigned char R1Array[] =
        "\x9c\x52\x4a\xdb\xcf\x56\x11\x12\x2b\x29\x12\x5e\x5d\x35\xd2\xd2"
        "\x22\x81\xaa\xb5\x33\xf0\x08\x32\xd5\x56\xb1\xf9\xea\xe5\x1d\x7d";
    const char R1ArrayHex[] = "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c";
    const double R1Ldouble = 0.4887374590559308955; // R1L equals roughly R1Ldouble * 2^256
    // tmp = uchar_arr_to_vec(R1Array);
    // const base_uint* R1L = base_uintV(tmp);
    // char* R1_string = utils_uint8_to_hex((uint8_t*)R1Array, 32);
    printf("%s\n", utils_uint8_to_hex(R1Array, 32));
    int r1_index = start_hash();
    hash* h = find_hash(r1_index);
    set_hash(r1_index, R1Array, typename(R1Array[0]));
    print_hash(r1_index);

    const uint64_t R1LLow64 = 0x121156cfdb4a529cULL;
    int r164_index = start_hash();
    set_hash(r164_index, R1LLow64, typename(R1LLow64));
    print_hash(r164_index);

    const unsigned char R2Array[] =
        "\x70\x32\x1d\x7c\x47\xa5\x6b\x40\x26\x7e\x0a\xc3\xa6\x9c\xb6\xbf"
        "\x13\x30\x47\xa3\x19\x2d\xda\x71\x49\x13\x72\xf0\xb4\xca\x81\xd7";
    int r2_index = start_hash();
    set_hash(r2_index, R2Array, typename(R2Array[0]));
    print_hash(r2_index);

    const char R1LplusR2L[] = "549FB09FEA236A1EA3E31D4D58F1B1369288D204211CA751527CFC175767850C";
    int r1_plus_r2_index = start_hash();
    set_hash(r1_plus_r2_index, R1LplusR2L, typename(R1LplusR2L[0]));
    print_hash(r1_plus_r2_index);

    const unsigned char ZeroArray[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    int zero_index = start_hash();
    set_hash(zero_index, ZeroArray, typename(ZeroArray[0]));
    print_hash(zero_index);

    const unsigned char OneArray[] =
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    int one_index = start_hash();
    set_hash(one_index, OneArray, typename(OneArray[0]));
    print_hash(one_index);

    const unsigned char MaxArray[] =
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    int max_index = start_hash();
    set_hash(max_index, MaxArray, typename(MaxArray[0]));
    print_hash(max_index);
    // tmp = uchar_arr_to_vec(MaxArray);
    // const base_uint* MaxL = base_uintV(tmp);

    // const base_uint* HalfL = (base_uint_shift_left(OneL, 255));
    int half_index = start_hash();
    print_hash(one_index);
    h = find_hash(one_index);
    shift_left(half_index, *h->data, 255);
    print_hash(one_index);
    print_hash(half_index);
    set_hash(half_index, *h->data, typename(h->data[0]));
    print_hash(half_index);

    int num_index = start_hash();
    hash* num = find_hash(num_index);

    set_hash(num_index, 0, typename(0));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x00123456, typename(0x00123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x01003456, typename(0x01003456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x02000056, typename(0x02000056));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x03000000, typename(0x03000000));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x04000000, typename(0x04000000));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x00923456, typename(0x00923456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x01803456, typename(0x01803456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x02800056, typename(0x02800056));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x03800000, typename(0x03800000));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x04800000, typename(0x04800000));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x01123456, typename(0x01123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000000012");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x01120000U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    // Make sure that we don't generate compacts with the 0x00800000 bit set
    // set_hash(num_index, 0x80, typename(0x80));
    // num = 0x80;
    // u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x02008000U);

    set_hash(num_index, 0x01fe0000, typename(0x01fe0000));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "000000000000000000000000000000000000000000000000000000000000007e");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x01fe0000U);
    u_assert_int_eq(num->checks.negative, true);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x02123456, typename(0x02123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000001234");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x02123400U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x03123456, typename(0x03123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000000123456");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x03123456U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x04123456, typename(0x04123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000012345600");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x04123456U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x04923456, typename(0x04923456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000012345600");
    u_assert_uint32_eq(get_compact(&num->x, true), 0x04923456U);
    u_assert_int_eq(num->checks.negative, true);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x05009234, typename(0x05009234));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "0000000000000000000000000000000000000000000000000000000092340000");
    u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x05009234U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0x20123456, typename(0x20123456));
    print_hash(num_index);
    u_assert_str_eq(get_hash_by_index(num_index), "1234560000000000000000000000000000000000000000000000000000000000");
    // u_assert_uint32_eq(get_compact(&num->x, num->checks.negative), 0x20123456U);
    // u_assert_uint32_eq(get_compact_hash(num_index), 0x20123456U);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, false);

    set_hash(num_index, 0xff123456, typename(0xff123456));
    print_hash(num_index);
    u_assert_int_eq(num->checks.negative, false);
    u_assert_int_eq(num->checks.overflow, true);


    remove_all_hashes();

    // constructors, equality, inequality
    u_assert_int_eq(1, 0 + 1);


    // dogecoin_free(R1L);
    // dogecoin_free(R2L);
    // dogecoin_free(OneL);
    // dogecoin_free(MaxL);
    // dogecoin_free(ZeroL);
    // vector_free(tmp, false);
}
