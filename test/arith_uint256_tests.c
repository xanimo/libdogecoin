/**********************************************************************
 * Copyright (c) 2023 bluezr                                          *
 * Copyright (c) 2023 The Dogecoin Foundation                         *
 * Copyright (c) 2023 The Dogecoin Developers                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <assert.h>
#include <stdlib.h>

#include <dogecoin/arith_uint256.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

// Check if doing _A_ _OP_ _B_ results in the same as applying _OP_ onto each
// element of Aarray and Barray, and then converting the result into a arith_uint256.
#define CHECKBITWISEOPERATOR(_A_,_B_,_OP_)                              \
    for (unsigned int i = 0; i < 32; ++i) { TmpArray[i] = _A_##Array[i] _OP_ _B_##Array[i]; } \
    u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(_A_##L _OP_ _B_##L));

#define CHECKASSIGNMENTOPERATOR(_A_,_B_,_OP_)                           \
    TmpL = _A_##L; TmpL _OP_##= _B_##L; u_assert_true(TmpL == (_A_##L _OP_ _B_##L));

dogecoin_bool almostEqual(double d1, double d2)
{
    return fabs(d1-d2) <= 4*fabs(d1)*__DBL_EPSILON__;
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

void test_arith_uint256() {
    const unsigned char R1Array[] =
        "\x9c\x52\x4a\xdb\xcf\x56\x11\x12\x2b\x29\x12\x5e\x5d\x35\xd2\xd2"
        "\x22\x81\xaa\xb5\x33\xf0\x08\x32\xd5\x56\xb1\xf9\xea\xe5\x1d\x7d";
    const char R1ArrayHex[] = "7D1DE5EAF9B156D53208F033B5AA8122D2d2355d5e12292b121156cfdb4a529c";
    const double R1Ldouble = 0.4887374590559308955; // R1L equals roughly R1Ldouble * 2^256
    const arith_uint256* R1L = init_arith_uint256();
    memcpy_safe(R1L->pn, R1Array, sizeof R1Array);
    const uint64_t R1LLow64 = 0x121156cfdb4a529cULL;

    const unsigned char R2Array[] =
        "\x70\x32\x1d\x7c\x47\xa5\x6b\x40\x26\x7e\x0a\xc3\xa6\x9c\xb6\xbf"
        "\x13\x30\x47\xa3\x19\x2d\xda\x71\x49\x13\x72\xf0\xb4\xca\x81\xd7";
    const arith_uint256* R2L = init_arith_uint256();
    memcpy_safe(R2L->pn, R2Array, sizeof R2Array);

    const char R1LplusR2L[] = "549FB09FEA236A1EA3E31D4D58F1B1369288D204211CA751527CFC175767850C";

    const unsigned char ZeroArray[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const arith_uint256* ZeroL = init_arith_uint256();
    memcpy_safe(ZeroL->pn, ZeroArray, sizeof ZeroArray);

    const unsigned char OneArray[] =
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const arith_uint256* OneL = init_arith_uint256();
    memcpy_safe(OneL->pn, OneArray, sizeof OneArray);

    const unsigned char MaxArray[] =
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const arith_uint256* MaxL = init_arith_uint256();
    memcpy_safe(MaxL->pn, MaxArray, sizeof MaxArray);

    const arith_uint256* HalfL = init_arith_uint256();
    memcpy_safe(HalfL->pn, OneL->pn, sizeof OneL->pn);
    arith_shift_left(HalfL, 255);

    // constructors, equality, inequality
    u_assert_int_eq(1, 0 + 1);
    u_assert_str_eq(to_string(R1L->pn), to_string(R1Array));
    u_assert_str_eq(to_string(R2L->pn), to_string(R2Array));
    u_assert_str_eq(to_string(ZeroL->pn), to_string(ZeroArray));
    u_assert_str_eq(to_string(OneL->pn), to_string(OneArray));
    u_assert_str_eq(to_string(MaxL->pn), to_string(MaxArray));
    u_assert_true(OneL->pn != ZeroArray);

    // == and !=
    u_assert_true(R1L != R2L);
    u_assert_true(ZeroL != OneL);
    u_assert_true(OneL != ZeroL);
    u_assert_true(MaxL != ZeroL);
    // u_assert_true((~MaxL) == ZeroL);
    u_assert_str_eq(to_string(base_uint_xor(base_uint_xor(R1L, R2L), R1L)->pn), to_string(R2L->pn));

    uint64_t tmp64 = 0xc4dab720d9c7acaaULL;
    for (unsigned int i = 0; i < 256; ++i) {
        arith_shift_left(OneL, i);
        u_assert_true(ZeroL != OneL);
        arith_shift_left(OneL, i);
        u_assert_true(OneL != ZeroL);
        arith_shift_left(OneL, i);
        u_assert_true(R1L != base_uint_xor(R1L, OneL));
        arith_shift_left(OneL, i);
        u_assert_true(base_uint_xor(arith_from_uint64(tmp64), OneL) != tmp64);
    }
    arith_shift_left(OneL, 256);
    u_assert_true(to_string(ZeroL->pn) == to_string(OneL->pn));

    // String Constructor and Copy Constructor
    u_assert_true(to_string(arith_from_uchar(concat("0x", to_string(R1L)))) == to_string(R1L));
    u_assert_true(to_string(arith_from_uchar(concat("0x", to_string(R2L)))) == to_string(R2L));
    u_assert_true(to_string(arith_from_uchar(concat("0x", to_string(OneL)))) == to_string(OneL));
    u_assert_true(to_string(arith_from_uchar(concat("0x", to_string(MaxL)))) == to_string(MaxL));
    u_assert_true(to_string(arith_from_uchar(to_string(R1L))) == to_string(R1L));
    u_assert_true(to_string(arith_from_uchar(concat(concat("   ", to_string(R1L)), "   "))) == to_string(R1L));
    u_assert_true(to_string(arith_from_uchar(to_string(""))) == to_string(ZeroL));
    u_assert_true(to_string(R1L) == to_string(arith_from_uchar(R1ArrayHex)));
    u_assert_true(to_string(arith_from_uint64(R1L)) == to_string(R1L));
    u_assert_true((to_string(arith_from_uint64(base_uint_xor(base_uint_xor(R1L, R2L), R2L)))) == to_string(R1L));
    u_assert_true(to_string(arith_from_uint64(ZeroL)) == to_string(ZeroL));
    u_assert_true(to_string(arith_from_uint64(OneL)) == to_string(OneL));

    // // uint64_t constructor
    u_assert_true(to_string(base_uint_and(R1L, arith_from_uint64("0xffffffffffffffff"))) == to_string(arith_from_uint64(R1LLow64)));
    u_assert_true(to_string(ZeroL) == to_string(arith_from_uint64(0)));
    u_assert_true(to_string(OneL) == to_string(arith_from_uint64(1)));
    u_assert_true(to_string(arith_from_uint64("0xffffffffffffffff")) == to_string(arith_from_uint64(0xffffffffffffffffULL)));

    // // Assignment (from base_uint)
    arith_uint256* tmpL = ~*ZeroL->pn; u_assert_true(tmpL == ~*ZeroL->pn);
    tmpL = ~*OneL->pn; u_assert_true(tmpL == ~*OneL->pn);
    tmpL = ~*R1L->pn; u_assert_true(tmpL == ~*R1L->pn);
    tmpL = ~*R2L->pn; u_assert_true(tmpL == ~*R2L->pn);
    tmpL = ~*MaxL->pn; u_assert_true(tmpL == ~*MaxL->pn);

    // // "<<"  ">>"  "<<="  ">>="
    unsigned char TmpArray[32];
    arith_uint256 TmpL;
    for (unsigned int i = 0; i < 256; ++i)
    {
        shiftArrayLeft(TmpArray, OneArray, 32, i);
        arith_shift_left(OneL, i);
        u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(OneL));
        TmpL = *OneL; arith_shift_left(&TmpL, i);
        arith_shift_left(OneL, i);
        u_assert_true(to_string(&TmpL) == to_string(OneL));
        arith_shift_right(HalfL, (255 - i));
        arith_shift_left(OneL, i);
        u_assert_true(to_string(HalfL) == to_string(OneL));
        TmpL = *HalfL; arith_shift_right(&TmpL, (255 - i));
        arith_shift_left(OneL, i);
        u_assert_true(to_string(&TmpL) == to_string(OneL));

        shiftArrayLeft(TmpArray, R1Array, 32, i);
        arith_shift_left(R1L, i);
        u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(R1L));
        TmpL = *R1L; arith_shift_left(&TmpL, i);
        arith_shift_left(R1L, i);
        u_assert_true(to_string(&TmpL) == to_string(R1L));

        shiftArrayRight(TmpArray, R1Array, 32, i);
        arith_shift_right(R1L, i);
        u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(R1L));
        TmpL = *R1L; arith_shift_right(&TmpL, i);
        arith_shift_right(R1L, i);
        u_assert_true(to_string(&TmpL) == to_string(R1L));

        shiftArrayLeft(TmpArray, MaxArray, 32, i);
        arith_shift_left(MaxL, i);
        u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(MaxL));
        TmpL = *MaxL; arith_shift_left(&TmpL, i);
        arith_shift_left(MaxL, i);
        u_assert_true(to_string(&TmpL) == to_string(MaxL));

        shiftArrayRight(TmpArray, MaxArray, 32, i);
        arith_shift_right(MaxL, i);
        u_assert_true(to_string(arith_from_uchar(TmpArray)) == to_string(MaxL));
        TmpL = *MaxL; arith_shift_right(&TmpL, i);
        arith_shift_right(MaxL, i);
        u_assert_true(to_string(&TmpL) == to_string(MaxL));
    }
    arith_uint256 c1L = *arith_from_uint64(0x0123456789abcdefULL);
    arith_shift_left(&c1L, 128);
    arith_uint256 c2L = c1L;
    for (unsigned int i = 0; i < 128; ++i) {
        arith_shift_left(&c1L, i);
        arith_shift_right(&c2L, (128 - i));
        u_assert_true(to_string(&c1L) == to_string(&c2L));
    }
    for (unsigned int i = 128; i < 256; ++i) {
        arith_shift_left(&c1L, i);
        arith_shift_right(&c2L, (i - 128));
        u_assert_true(to_string(&c1L) == to_string(&c2L));
    }

    // // !    ~    -
    u_assert_true(!*ZeroL->pn);
    u_assert_true(!(!OneL));
    for (unsigned int i = 0; i < 256; ++i) {
        arith_shift_left(OneL, i);
        u_assert_true(!(!(OneL)));
    }
    u_assert_true(!(!R1L));
    u_assert_true(!(!MaxL));

    // u_assert_true(~ZeroL == MaxL);

    dogecoin_mem_zero(&TmpArray, 32);
    for (unsigned int i = 0; i < 32; ++i) { TmpArray[i] = ~R1Array[i]; }
    // u_assert_true(to_string(arith_from_uchar(&TmpArray)) == to_string(~*R1L->pn));

    u_assert_true(-*ZeroL->pn == *ZeroL->pn);
    u_assert_true(-*R1L->pn == (~*R1L->pn)+1);
    for (unsigned int i = 0; i < 256; ++i) {
        arith_shift_left(OneL, i);
        arith_shift_left(MaxL, i);
        u_assert_true(-*OneL->pn == *MaxL->pn);
    }

    // unsigned char TmpArray[32];
    // arith_uint256 R1, R2, Zero, Max;
    // CHECKBITWISEOPERATOR(R1,R2,|);
    // CHECKBITWISEOPERATOR(R1,R2,^)
    // CHECKBITWISEOPERATOR(R1,R2,&)
    // CHECKBITWISEOPERATOR(R1,Zero,|)
    // CHECKBITWISEOPERATOR(R1,Zero,^)
    // CHECKBITWISEOPERATOR(R1,Zero,&)
    // CHECKBITWISEOPERATOR(R1,Max,|)
    // CHECKBITWISEOPERATOR(R1,Max,^)
    // CHECKBITWISEOPERATOR(R1,Max,&)
    // CHECKBITWISEOPERATOR(Zero,R1,|)
    // CHECKBITWISEOPERATOR(Zero,R1,^)
    // CHECKBITWISEOPERATOR(Zero,R1,&)
    // CHECKBITWISEOPERATOR(Max,R1,|)
    // CHECKBITWISEOPERATOR(Max,R1,^)
    // CHECKBITWISEOPERATOR(Max,R1,&)

    // arith_uint256 TmpL;
    // CHECKASSIGNMENTOPERATOR(R1,R2,|)
    // CHECKASSIGNMENTOPERATOR(R1,R2,^)
    // CHECKASSIGNMENTOPERATOR(R1,R2,&)
    // CHECKASSIGNMENTOPERATOR(R1,Zero,|)
    // CHECKASSIGNMENTOPERATOR(R1,Zero,^)
    // CHECKASSIGNMENTOPERATOR(R1,Zero,&)
    // CHECKASSIGNMENTOPERATOR(R1,Max,|)
    // CHECKASSIGNMENTOPERATOR(R1,Max,^)
    // CHECKASSIGNMENTOPERATOR(R1,Max,&)
    // CHECKASSIGNMENTOPERATOR(Zero,R1,|)
    // CHECKASSIGNMENTOPERATOR(Zero,R1,^)
    // CHECKASSIGNMENTOPERATOR(Zero,R1,&)
    // CHECKASSIGNMENTOPERATOR(Max,R1,|)
    // CHECKASSIGNMENTOPERATOR(Max,R1,^)
    // CHECKASSIGNMENTOPERATOR(Max,R1,&)

    uint64_t Tmp64 = 0xe1db685c9a0b47a2ULL;
    TmpL = *R1L;
    memcpy_safe(&TmpL, base_uint_or(&TmpL, arith_from_uint64(Tmp64)), 32);
    u_assert_true(to_string(&TmpL.pn) == to_string(base_uint_or(R1L, arith_from_uint64(Tmp64))));
    TmpL = *R1L; base_uint_or(&TmpL, set_arith_uint256(0));
    u_assert_true(to_string(&TmpL.pn) == to_string(R1L));
    memcpy_safe(&TmpL, base_uint_xor(&TmpL, set_arith_uint256(0)), 32);
    u_assert_true(to_string(&TmpL.pn) == to_string(R1L));
    memcpy_safe(&TmpL, base_uint_xor(&TmpL, arith_from_uint64(Tmp64)), 32);
    u_assert_true(to_string(&TmpL.pn) == to_string(base_uint_xor(R1L, arith_from_uint64(Tmp64))));

    dogecoin_mem_zero(&TmpL, 32);
    for (unsigned int i = 0; i < 256; ++i) {
        arith_shift_left(OneL, i);
        memcpy_safe(&TmpL, OneL, 32);
        u_assert_true(&TmpL >= ZeroL && &TmpL > ZeroL && ZeroL < &TmpL && ZeroL <= &TmpL);
        u_assert_true(&TmpL >= 0 && &TmpL > 0 && 0 < &TmpL && 0 <= &TmpL);
        memcpy_safe(&TmpL, base_uint_or(&TmpL, R1L), 32);
        u_assert_true(&TmpL >= R1L ); u_assert_true((&TmpL == R1L) != (&TmpL > R1L)); u_assert_true((&TmpL == R1L) || !( &TmpL <= R1L));
        u_assert_true(R1L <= &TmpL); u_assert_true((R1L == &TmpL) != (R1L < &TmpL)); u_assert_true((&TmpL == R1L) || !( R1L >= &TmpL));
        u_assert_true(!(&TmpL < R1L)); u_assert_true(!(R1L > &TmpL));
    }

    dogecoin_mem_zero(&TmpL, 32);
    memcpy_safe(R1L, R1Array, 32);
    u_assert_true(hash_to_string(base_uint_add(R1L, R2L)) == to_string(utils_hex_to_uint8(R1LplusR2L)));
    memcpy_safe(&TmpL, base_uint_add(&TmpL, R1L), 32);
    u_assert_true(to_string(&TmpL) == to_string(R1L));
    memcpy_safe(&TmpL, base_uint_add(&TmpL, R2L), 32);
    u_assert_true(to_string(&TmpL) == to_string(base_uint_add(R1L, R2L)));
    u_assert_true(to_string(base_uint_add(OneL, MaxL)) == to_string(ZeroL));
    u_assert_true(to_string(base_uint_add(MaxL, OneL)) == to_string(ZeroL));
    for (unsigned int i = 1; i < 256; ++i) {
        arith_shift_right(MaxL, i);
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(base_uint_add(MaxL, OneL)) == to_string(HalfL));
        arith_shift_right(MaxL, i);
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(base_uint_add(OneL, MaxL)) == to_string(HalfL));
        arith_shift_right(MaxL, i);
        memcpy_safe(&TmpL, MaxL, 32);
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(base_uint_add(&TmpL, OneL)) == to_string(HalfL));
        arith_shift_right(MaxL, i);
        memcpy_safe(&TmpL, MaxL, 32);
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(base_uint_add(&TmpL, set_arith_uint256(1))) == to_string(HalfL));
        arith_shift_right(MaxL, i);
        memcpy_safe(&TmpL, MaxL, 32);
        arith_shift_right(MaxL, i);
        TmpL.pn[0]++;
        u_assert_true(to_string(&TmpL) == to_string(MaxL));
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(&TmpL) == to_string(HalfL));
    }
    u_assert_true(to_string(base_uint_add(arith_from_uint64(0xbedc77e27940a7ULL), arith_from_uint64(0xee8d836fce66fbULL))) == to_string(set_arith_uint256(base_uint_add(arith_from_uint64(0xbedc77e27940a7ULL), arith_from_uint64(0xee8d836fce66fbULL)))));
    memcpy_safe(&TmpL, arith_from_uint64(0xbedc77e27940a7ULL), 32);
    memcpy_safe(&TmpL, base_uint_add(&TmpL, arith_from_uint64(0xee8d836fce66fbULL)), 32);
    u_assert_true(to_string(&TmpL) == to_string(set_arith_uint256(base_uint_add(arith_from_uint64(0xbedc77e27940a7ULL), arith_from_uint64(0xee8d836fce66fbULL)))));
    memcpy_safe(&TmpL, base_uint_sub(&TmpL, arith_from_uint64(0xee8d836fce66fbULL)), 32);
    u_assert_true(to_string(&TmpL) == to_string(arith_from_uint64(0xbedc77e27940a7ULL)));
    memcpy_safe(&TmpL, R1L, 32);
    ++TmpL.pn[0];
    u_assert_true(to_string(&TmpL) == to_string(base_uint_add(R1L, set_arith_uint256(1))));

    arith_uint256 a, b;
    memcpy_safe(&a, R1L, 32);
    memcpy_safe(&b, R2L, 32);
    arith_negate(&b);
    u_assert_true(to_string(base_uint_sub(&a, &b)) == to_string(base_uint_add(R1L, R2L)));
    memcpy_safe(&a, R1L, 32);
    arith_negate(OneL);
    memcpy_safe(&b, OneL, 32);
    u_assert_true(to_string(&a) == to_string(&b));
    for (unsigned int i = 1; i < 256; ++i) {
        arith_shift_right(MaxL, i);
        arith_negate(OneL);
        arith_shift_right(HalfL, (i - 1));
        u_assert_true(to_string(base_uint_sub(MaxL, OneL))  == to_string(HalfL));
        arith_shift_right(HalfL, (i - 1));
        arith_shift_right(MaxL, i);
        u_assert_true(to_string(base_uint_sub(HalfL, OneL)) == to_string(MaxL));
        arith_shift_right(HalfL, (i - 1));
        memcpy_safe(&TmpL, HalfL, 32);
        TmpL.pn[0]--;
        u_assert_true(to_string(&TmpL) == to_string(HalfL));
        arith_shift_right(MaxL, i);
        u_assert_true(to_string(&TmpL) == to_string(MaxL));
        arith_shift_right(HalfL, (i - 1));
        memcpy_safe(&TmpL, HalfL, 32);
        --TmpL.pn[0];
        u_assert_true(to_string(&TmpL) == to_string(MaxL));
    }
    memcpy_safe(&TmpL, R1L, 32);
    --TmpL.pn[0];
    u_assert_true(to_string(&TmpL) == to_string(R1L - 1));

    u_assert_true(hash_to_string(base_uint_mult(R1L, R1L)) == to_string(utils_hex_to_uint8("62a38c0486f01e45879d7910a7761bf30d5237e9873f9bff3642a732c4d84f10")));
    u_assert_true(hash_to_string(base_uint_mult(R1L, R2L)) == to_string(utils_hex_to_uint8("de37805e9986996cfba76ff6ba51c008df851987d9dd323f0e5de07760529c40")));
    u_assert_true(to_string(base_uint_mult(R1L, ZeroL)) == to_string(ZeroL));
    u_assert_true(to_string(base_uint_mult(R1L, OneL)) == to_string(R1L));
    memcpy_safe(&a, base_uint_mult(R1L, MaxL), 32);
    memcpy_safe(&b, R1L, 32);
    arith_negate(&b);
    u_assert_true(to_string(&a) == to_string(&b));
    u_assert_true(to_string(base_uint_mult(R1L, MaxL)) == to_string(&b));
    u_assert_true(to_string(base_uint_mult(R2L, R1L)) == to_string(base_uint_mult(R1L, R2L)));
    u_assert_true(hash_to_string(base_uint_mult(R2L, R2L)) == to_string(utils_hex_to_uint8("ac8c010096767d3cae5005dec28bb2b45a1d85ab7996ccd3e102a650f74ff100")));
    u_assert_true(to_string(base_uint_mult(R2L, ZeroL)) == to_string(ZeroL));
    u_assert_true(to_string(base_uint_mult(R2L, OneL)) == to_string(ZeroL));
    memcpy_safe(&b, R2L, 32);
    arith_negate(&b);
    u_assert_true(to_string(base_uint_mult(R2L, MaxL)) == to_string(&b));

    u_assert_true(to_string(base_uint_mult(MaxL, MaxL)) == to_string(OneL));

    u_assert_true((*R1L->pn * 0) == 0);
    u_assert_true((*R1L->pn * 1) == *R1L->pn);
    memcpy_safe(R1L, R1Array, 32);
    u_assert_true(hash_to_string(base_uint_mul(R1L, 3)) == to_string(utils_hex_to_uint8("7759b1c0ed14047f961ad09b20ff83687876a0181a367b813634046f91def7d4")));
    u_assert_true(hash_to_string(base_uint_mul(R2L, (int)0x87654321UL)) == to_string(utils_hex_to_uint8("23f7816e30c4ae2017257b7a0fa64d60402f5234d46e746b61c960d09a26d070")));

    uint256 x;
    memcpy_safe(&x, (uint8_t*)utils_hex_to_uint8("AD7133AC1977FA2B7"), strlen("AD7133AC1977FA2B7") / 2 + 1);
    printf("%" PRIu64 "\n", x);
    // printf("%s\n", utils_uint8_to_hex(x, (strlen("AD7133AC1977FA2B7") / 2) * 4));
    // printf("%d\n", strlen("ECD751716") / 2);
    // printf("%d\n", strlen("AD7133AC1977FA2B7") / 2);
    // printf("%s\n", utils_uint8_to_hex(uint256S("AD7133AC1977FA2B7"), 32));
    arith_uint256* D1L = init_arith_uint256();
    memcpy_safe(D1L->pn, (uint8_t*)utils_hex_to_uint8("AD7133AC1977FA2B7"), strlen("AD7133AC1977FA2B7") / 2 + 1);
    arith_uint256* D2L = uint_to_arith(uint256S("ECD751716"));
    // D1L = utils_hex_to_uint8(hash_to_string(D1L));
    printf("%s\n", to_string(R1L));
    printf("%s\n", to_string(D1L));
    // printf("%s\n", to_string(base_uint_div(R1L, D1L)));
//     u_assert_true((R1L / D1L).ToString() == "00000000000000000b8ac01106981635d9ed112290f8895545a7654dde28fb3a");
//     u_assert_true((R1L / D2L).ToString() == "000000000873ce8efec5b67150bad3aa8c5fcb70e947586153bf2cec7c37c57a");
//     u_assert_true(R1L / OneL == R1L);
//     u_assert_true(R1L / MaxL == ZeroL);
    // u_assert_true(base_uint_div(MaxL, R1L) == 2);
//     u_assert_true_THROW(R1L / ZeroL, uint_error);
//     u_assert_true((R2L / D1L).ToString() == "000000000000000013e1665895a1cc981de6d93670105a6b3ec3b73141b3a3c5");
//     u_assert_true((R2L / D2L).ToString() == "000000000e8f0abe753bb0afe2e9437ee85d280be60882cf0bd1aaf7fa3cc2c4");
//     u_assert_true(R2L / OneL == R2L);
//     u_assert_true(R2L / MaxL == ZeroL);
//     u_assert_true(MaxL / R2L == 1);
//     u_assert_true_THROW(R2L / ZeroL, uint_error);

//     u_assert_true(R1L.GetHex() == R1L.ToString());
//     u_assert_true(R2L.GetHex() == R2L.ToString());
//     u_assert_true(OneL.GetHex() == OneL.ToString());
//     u_assert_true(MaxL.GetHex() == MaxL.ToString());
    utils_uint256_sethex(hash_to_string(R1L), &TmpL);
    u_assert_true(hash_to_string(&TmpL) == hash_to_string(R1L));
    utils_uint256_sethex(hash_to_string(R2L), &TmpL);
    u_assert_true(hash_to_string(&TmpL) == hash_to_string(R2L));
    utils_uint256_sethex(hash_to_string(ZeroL), &TmpL);
    u_assert_true(hash_to_string(&TmpL) == hash_to_string(set_arith_uint256(0)));
    utils_uint256_sethex(hash_to_string(HalfL), &TmpL);
    u_assert_true(hash_to_string(&TmpL) == hash_to_string(HalfL));

    utils_uint256_sethex(hash_to_string(R1L), &TmpL);
//     u_assert_true(R1L.size() == 32);
//     u_assert_true(R2L.size() == 32);
//     u_assert_true(ZeroL.size() == 32);
//     u_assert_true(MaxL.size() == 32);
    u_assert_true(get_low64(*R1L)  == R1LLow64);
    u_assert_true(get_low64(*HalfL) == 0x0000000000000000ULL);
    memcpy_safe(OneL, OneArray, 32);
    u_assert_true(get_low64(*OneL) == 0x0000000000000001ULL);

    // for (unsigned int i = 0; i < 255; ++i) {
    //     arith_shift_left(OneL, i);
    //     printf("%lf\n", ldexp(1.0,i));
    //     printf("%lf\n", getdouble(OneL));
    //     u_assert_true(getdouble(OneL) == ldexp(1.0,i));
    // }
    // u_assert_true(getdouble(ZeroL) == 0.0);
    // for (int i = 256; i > 53; --i) {
    //     arith_shift_right(R1L, (256 - i));
    //     printf("%lf\n", getdouble(R1L));
    //     printf("%lf\n", ldexp(R1Ldouble,i));
    //     u_assert_true(almostEqual(getdouble(R1L), ldexp(R1Ldouble,i)));
    // }
    // arith_shift_right(R1L, 192);
    // uint64_t R1L64part = get_low64(*R1L);
    // for (int i = 53; i > 0; --i) // doubles can store all integers in {0,...,2^54-1} exactly
    // {
    //     arith_shift_right(R1L, (256 - i));
    //     u_assert_true(getdouble(R1L) == (double)(R1L64part >> (64-i)));
    // }

    arith_uint256 num;
    dogecoin_bool fNegative;
    dogecoin_bool fOverflow;
    memcpy_safe(&num.pn, set_compact(&num, 0, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == to_string("0000000000000000000000000000000000000000000000000000000000000000"));
    u_assert_true(get_compact(&num, fOverflow) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x00123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x01003456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x02000056, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x03000000, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x04000000, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x00923456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x01803456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x02800056, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x03800000, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x04800000, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x01123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000000012")));
    u_assert_true(get_compact(&num, fNegative) == 0x01120000U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

//     // Make sure that we don't generate compacts with the 0x00800000 bit set
    *num.pn = 0x80;
    u_assert_true(get_compact(&num, fNegative) == 0x02008000U);

    memcpy_safe(&num, set_compact(&num, 0x01fedcba, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("000000000000000000000000000000000000000000000000000000000000007e")));
    u_assert_true(get_compact(&num, fNegative) == 0x01fe0000U);
    u_assert_true(fNegative == true);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x02123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000001234")));
    u_assert_true(get_compact(&num, fNegative) == 0x02123400U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x03123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000000123456")));
    u_assert_true(get_compact(&num, fNegative) == 0x03123456U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x04123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000012345600")));
    u_assert_true(get_compact(&num, fNegative) == 0x04123456U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x04923456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000012345600")));
    u_assert_true(get_compact(&num, fNegative) == 0x04923456U);
    u_assert_true(fNegative == true);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x05009234, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("0000000000000000000000000000000000000000000000000000000012345600")));
    u_assert_true(get_compact(&num, fNegative) == 0x05009234U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0x20123456, &fNegative, &fOverflow), 32);
    u_assert_true(to_string(&num) == hash_to_string(utils_hex_to_uint8("1234560000000000000000000000000000000000000000000000000000000000")));
    u_assert_true(get_compact(&num, fNegative) == 0x20123456U);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == false);

    memcpy_safe(&num, set_compact(&num, 0xff123456, &fNegative, &fOverflow), 32);
    u_assert_true(fNegative == false);
    u_assert_true(fOverflow == true);

    // ~R1L give a base_uint<256>
    u_assert_true((~~*R1L->pn >> 10) == (*R1L->pn >> 10));
    u_assert_true((~~*R1L->pn << 10) == (*R1L->pn << 10));
    u_assert_true(!(~~*R1L->pn < *R1L->pn));
    u_assert_true(~~*R1L->pn <= *R1L->pn);
    u_assert_true(!(~~*R1L->pn > *R1L->pn));
    u_assert_true(~~*R1L->pn >= *R1L->pn);
    u_assert_true(!(*R1L->pn < ~~*R1L->pn));
    u_assert_true(*R1L->pn <= ~~*R1L->pn);
    u_assert_true(!(*R1L->pn > ~~*R1L->pn));
    u_assert_true(*R1L->pn >= ~~*R1L->pn);

    u_assert_true(~~*R1L->pn + *R2L->pn == *R1L->pn + ~~*R2L->pn);
    u_assert_true(~~*R1L->pn - *R2L->pn == *R1L->pn - ~~*R2L->pn);
    u_assert_true(~*R1L->pn != *R1L->pn); u_assert_true(*R1L->pn != ~*R1L->pn);
//     unsigned char TmpArray[32];
//     CHECKBITWISEOPERATOR(~R1,R2,|)
//     CHECKBITWISEOPERATOR(~R1,R2,^)
//     CHECKBITWISEOPERATOR(~R1,R2,&)
//     CHECKBITWISEOPERATOR(R1,~R2,|)
//     CHECKBITWISEOPERATOR(R1,~R2,^)
//     CHECKBITWISEOPERATOR(R1,~R2,&)
}
