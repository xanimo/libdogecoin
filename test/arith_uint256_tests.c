/**********************************************************************
 * Copyright (c) 2023 bluezr                                          *
 * Copyright (c) 2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/uint256.h>
#include <dogecoin/arith_uint256.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

// Convert vector to arith_uint256, via uint256 blob
arith_uint256* arith_uint256V(const vector* vch) {
    uint256* u = uint256_u(vch);
    return uint_to_arith(u);
}

void test_arith_uint256() {

    const unsigned char R1Array[] =
        "\x9c\x52\x4a\xdb\xcf\x56\x11\x12\x2b\x29\x12\x5e\x5d\x35\xd2\xd2"
        "\x22\x81\xaa\xb5\x33\xf0\x08\x32\xd5\x56\xb1\xf9\xea\xe5\x1d\x7d";
    const char R1ArrayHex[] = "7D1DE5EAF9B156D53208F033B5AA8122D2d2355d5e12292b121156cfdb4a529c";
    const double R1Ldouble = 0.4887374590559308955; // R1L equals roughly R1Ldouble * 2^256
    const arith_uint256* R1L = arith_uint256V(uchar_arr_to_vec(R1Array));
    const uint64_t R1LLow64 = 0x121156cfdb4a529cULL;

    const unsigned char R2Array[] =
        "\x70\x32\x1d\x7c\x47\xa5\x6b\x40\x26\x7e\x0a\xc3\xa6\x9c\xb6\xbf"
        "\x13\x30\x47\xa3\x19\x2d\xda\x71\x49\x13\x72\xf0\xb4\xca\x81\xd7";
    const arith_uint256* R2L = arith_uint256V(uchar_arr_to_vec(R2Array));

    const char R1LplusR2L[] = "549FB09FEA236A1EA3E31D4D58F1B1369288D204211CA751527CFC175767850C";

    const unsigned char ZeroArray[] =
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const arith_uint256* ZeroL = arith_uint256V(uchar_arr_to_vec(ZeroArray));

    const unsigned char OneArray[] =
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const arith_uint256* OneL = arith_uint256V(uchar_arr_to_vec(OneArray));

    const unsigned char MaxArray[] =
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const arith_uint256* MaxL = arith_uint256V(uchar_arr_to_vec(MaxArray));

    // const arith_uint256* HalfL = (OneL << 255);

    // constructors, equality, inequality
    u_assert_int_eq(1, 0 + 1);
    u_assert_str_eq(R1L->to_string((void*)R1L), to_string((uint8_t*)R1Array));
    u_assert_str_eq(R2L->to_string((void*)R2L), to_string((uint8_t*)R2Array));
    u_assert_str_eq(ZeroL->to_string((void*)ZeroL), to_string((uint8_t*)ZeroArray));
    u_assert_str_eq(OneL->to_string((void*)OneL), to_string((uint8_t*)OneArray));
    u_assert_str_eq(MaxL->to_string((void*)OneL), to_string((uint8_t*)MaxArray));
    // u_assert_str_not_eq(OneL->to_string((void*)OneL), to_string((uint8_t*)ZeroArray));

//     // == and !=
    assert(R1L != R2L);
    assert(ZeroL != OneL);
    assert(OneL != ZeroL);
    assert(MaxL != ZeroL);
//     assert(~MaxL == ZeroL);
//     assert( ((R1L ^ R2L) ^ R1L) == R2L);

    // uint64_t Tmp64 = 0xc4dab720d9c7acaaULL;
    // unsigned int i = 0;
    // for (; i < 256; ++i)
    // {
    //     assert(ZeroL != (base_uint_shift_left(OneL, i)));
    //     assert((base_uint_shift_left(OneL, i)) != ZeroL);
    //     // assert(R1L != (R1L ^ (base_uint_shift_left(OneL, i))));
    //     // assert(((arith_uint256(Tmp64) ^ (OneL << i) ) != Tmp64 ));
    // }
    // assert(ZeroL == (base_uint_shift_left(OneL, 256)));

//     // String Constructor and Copy Constructor
//     assert(arith_uint256("0x"+R1L.ToString()) == R1L);
//     assert(arith_uint256("0x"+R2L.ToString()) == R2L);
//     assert(arith_uint256("0x"+ZeroL.ToString()) == ZeroL);
//     assert(arith_uint256("0x"+OneL.ToString()) == OneL);
//     assert(arith_uint256("0x"+MaxL.ToString()) == MaxL);
//     assert(arith_uint256(R1L.ToString()) == R1L);
//     assert(arith_uint256("   0x"+R1L.ToString()+"   ") == R1L);
//     assert(arith_uint256("") == ZeroL);
//     assert(R1L == arith_uint256(R1ArrayHex));
//     assert(arith_uint256(R1L) == R1L);
//     assert((arith_uint256(R1L^R2L)^R2L) == R1L);
//     assert(arith_uint256(ZeroL) == ZeroL);
//     assert(arith_uint256(OneL) == OneL);

//     // uint64_t constructor
//     assert( (R1L & arith_uint256("0xffffffffffffffff")) == arith_uint256(R1LLow64));
//     assert(ZeroL == arith_uint256(0));
//     assert(OneL == arith_uint256(1));
//     assert(arith_uint256("0xffffffffffffffff") == arith_uint256(0xffffffffffffffffULL));

//     // Assignment (from base_uint)
//     arith_uint256 tmpL = ~ZeroL; assert(tmpL == ~ZeroL);
//     tmpL = ~OneL; assert(tmpL == ~OneL);
//     tmpL = ~R1L; assert(tmpL == ~R1L);
//     tmpL = ~R2L; assert(tmpL == ~R2L);
//     tmpL = ~MaxL; assert(tmpL == ~MaxL);
// }

// void shiftArrayRight(unsigned char* to, const unsigned char* from, unsigned int arrayLength, unsigned int bitsToShift)
// {
//     for (unsigned int T=0; T < arrayLength; ++T)
//     {
//         unsigned int F = (T+bitsToShift/8);
//         if (F < arrayLength)
//             to[T]  = from[F] >> (bitsToShift%8);
//         else
//             to[T] = 0;
//         if (F + 1 < arrayLength)
//             to[T] |= from[(F+1)] << (8-bitsToShift%8);
//     }
// }

// void shiftArrayLeft(unsigned char* to, const unsigned char* from, unsigned int arrayLength, unsigned int bitsToShift)
// {
//     for (unsigned int T=0; T < arrayLength; ++T)
//     {
//         if (T >= bitsToShift/8)
//         {
//             unsigned int F = T-bitsToShift/8;
//             to[T]  = from[F] << (bitsToShift%8);
//             if (T >= bitsToShift/8+1)
//                 to[T] |= from[F-1] >> (8-bitsToShift%8);
//         }
//         else {
//             to[T] = 0;
//         }
//     }
// }

// ( shifts ) { // "<<"  ">>"  "<<="  ">>="
//     unsigned char TmpArray[32];
//     arith_uint256 TmpL;
//     for (unsigned int i = 0; i < 256; ++i)
//     {
//         shiftArrayLeft(TmpArray, OneArray, 32, i);
//         assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (OneL << i));
//         TmpL = OneL; TmpL <<= i;
//         assert(TmpL == (OneL << i));
//         assert((HalfL >> (255-i)) == (OneL << i));
//         TmpL = HalfL; TmpL >>= (255-i);
//         assert(TmpL == (OneL << i));

//         shiftArrayLeft(TmpArray, R1Array, 32, i);
//         assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (R1L << i));
//         TmpL = R1L; TmpL <<= i;
//         assert(TmpL == (R1L << i));

//         shiftArrayRight(TmpArray, R1Array, 32, i);
//         assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (R1L >> i));
//         TmpL = R1L; TmpL >>= i;
//         assert(TmpL == (R1L >> i));

//         shiftArrayLeft(TmpArray, MaxArray, 32, i);
//         assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (MaxL << i));
//         TmpL = MaxL; TmpL <<= i;
//         assert(TmpL == (MaxL << i));

//         shiftArrayRight(TmpArray, MaxArray, 32, i);
//         assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (MaxL >> i));
//         TmpL = MaxL; TmpL >>= i;
//         assert(TmpL == (MaxL >> i));
//     }
//     arith_uint256 c1L = arith_uint256(0x0123456789abcdefULL);
//     arith_uint256 c2L = c1L << 128;
//     for (unsigned int i = 0; i < 128; ++i) {
//         assert((c1L << i) == (c2L >> (128-i)));
//     }
//     for (unsigned int i = 128; i < 256; ++i) {
//         assert((c1L << i) == (c2L << (i-128)));
//     }
// }

// ( unaryOperators ) // !    ~    -
// {
//     assert(!ZeroL);
//     assert(!(!OneL));
//     for (unsigned int i = 0; i < 256; ++i)
//         assert(!(!(OneL<<i)));
//     assert(!(!R1L));
//     assert(!(!MaxL));

//     assert(~ZeroL == MaxL);

//     unsigned char TmpArray[32];
//     for (unsigned int i = 0; i < 32; ++i) { TmpArray[i] = ~R1Array[i]; }
//     assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (~R1L));

//     assert(-ZeroL == ZeroL);
//     assert(-R1L == (~R1L)+1);
//     for (unsigned int i = 0; i < 256; ++i)
//         assert(-(OneL<<i) == (MaxL << i));
// }


// // Check if doing _A_ _OP_ _B_ results in the same as applying _OP_ onto each
// // element of Aarray and Barray, and then converting the result into a arith_uint256.
// #define CHECKBITWISEOPERATOR(_A_,_B_,_OP_)                              \
//     for (unsigned int i = 0; i < 32; ++i) { TmpArray[i] = _A_##Array[i] _OP_ _B_##Array[i]; } \
//     assert(arith_uint256V(vector*(TmpArray,TmpArray+32)) == (_A_##L _OP_ _B_##L));

// #define CHECKASSIGNMENTOPERATOR(_A_,_B_,_OP_)                           \
//     TmpL = _A_##L; TmpL _OP_##= _B_##L; assert(TmpL == (_A_##L _OP_ _B_##L));

// ( bitwiseOperators )
// {
//     unsigned char TmpArray[32];

//     CHECKBITWISEOPERATOR(R1,R2,|)
//     CHECKBITWISEOPERATOR(R1,R2,^)
//     CHECKBITWISEOPERATOR(R1,R2,&)
//     CHECKBITWISEOPERATOR(R1,Zero,|)
//     CHECKBITWISEOPERATOR(R1,Zero,^)
//     CHECKBITWISEOPERATOR(R1,Zero,&)
//     CHECKBITWISEOPERATOR(R1,Max,|)
//     CHECKBITWISEOPERATOR(R1,Max,^)
//     CHECKBITWISEOPERATOR(R1,Max,&)
//     CHECKBITWISEOPERATOR(Zero,R1,|)
//     CHECKBITWISEOPERATOR(Zero,R1,^)
//     CHECKBITWISEOPERATOR(Zero,R1,&)
//     CHECKBITWISEOPERATOR(Max,R1,|)
//     CHECKBITWISEOPERATOR(Max,R1,^)
//     CHECKBITWISEOPERATOR(Max,R1,&)

//     arith_uint256 TmpL;
//     CHECKASSIGNMENTOPERATOR(R1,R2,|)
//     CHECKASSIGNMENTOPERATOR(R1,R2,^)
//     CHECKASSIGNMENTOPERATOR(R1,R2,&)
//     CHECKASSIGNMENTOPERATOR(R1,Zero,|)
//     CHECKASSIGNMENTOPERATOR(R1,Zero,^)
//     CHECKASSIGNMENTOPERATOR(R1,Zero,&)
//     CHECKASSIGNMENTOPERATOR(R1,Max,|)
//     CHECKASSIGNMENTOPERATOR(R1,Max,^)
//     CHECKASSIGNMENTOPERATOR(R1,Max,&)
//     CHECKASSIGNMENTOPERATOR(Zero,R1,|)
//     CHECKASSIGNMENTOPERATOR(Zero,R1,^)
//     CHECKASSIGNMENTOPERATOR(Zero,R1,&)
//     CHECKASSIGNMENTOPERATOR(Max,R1,|)
//     CHECKASSIGNMENTOPERATOR(Max,R1,^)
//     CHECKASSIGNMENTOPERATOR(Max,R1,&)

//     uint64_t Tmp64 = 0xe1db685c9a0b47a2ULL;
//     TmpL = R1L; TmpL |= Tmp64;  assert(TmpL == (R1L | arith_uint256(Tmp64)));
//     TmpL = R1L; TmpL |= 0; assert(TmpL == R1L);
//     TmpL ^= 0; assert(TmpL == R1L);
//     TmpL ^= Tmp64;  assert(TmpL == (R1L ^ arith_uint256(Tmp64)));
// }

// ( comparison ) // <= >= < >
// {
//     arith_uint256 TmpL;
//     for (unsigned int i = 0; i < 256; ++i) {
//         TmpL= OneL<< i;
//         assert( TmpL >= ZeroL && TmpL > ZeroL && ZeroL < TmpL && ZeroL <= TmpL);
//         assert( TmpL >= 0 && TmpL > 0 && 0 < TmpL && 0 <= TmpL);
//         TmpL |= R1L;
//         assert( TmpL >= R1L ); assert( (TmpL == R1L) != (TmpL > R1L)); assert( (TmpL == R1L) || !( TmpL <= R1L));
//         assert( R1L <= TmpL ); assert( (R1L == TmpL) != (R1L < TmpL)); assert( (TmpL == R1L) || !( R1L >= TmpL));
//         assert(! (TmpL < R1L)); assert(! (R1L > TmpL));
//     }
// }

// ( plusMinus )
// {
//     arith_uint256 TmpL = 0;
//     assert(R1L+R2L == arith_uint256(R1LplusR2L));
//     TmpL += R1L;
//     assert(TmpL == R1L);
//     TmpL += R2L;
//     assert(TmpL == R1L + R2L);
//     assert(OneL+MaxL == ZeroL);
//     assert(MaxL+OneL == ZeroL);
//     for (unsigned int i = 1; i < 256; ++i) {
//         assert( (MaxL >> i) + OneL == (HalfL >> (i-1)) );
//         assert( OneL + (MaxL >> i) == (HalfL >> (i-1)) );
//         TmpL = (MaxL>>i); TmpL += OneL;
//         assert( TmpL == (HalfL >> (i-1)) );
//         TmpL = (MaxL>>i); TmpL += 1;
//         assert( TmpL == (HalfL >> (i-1)) );
//         TmpL = (MaxL>>i);
//         assert( TmpL++ == (MaxL>>i) );
//         assert( TmpL == (HalfL >> (i-1)));
//     }
//     assert(arith_uint256(0xbedc77e27940a7ULL) + 0xee8d836fce66fbULL == arith_uint256(0xbedc77e27940a7ULL + 0xee8d836fce66fbULL));
//     TmpL = arith_uint256(0xbedc77e27940a7ULL); TmpL += 0xee8d836fce66fbULL;
//     assert(TmpL == arith_uint256(0xbedc77e27940a7ULL+0xee8d836fce66fbULL));
//     TmpL -= 0xee8d836fce66fbULL;  assert(TmpL == 0xbedc77e27940a7ULL);
//     TmpL = R1L;
//     assert(++TmpL == R1L+1);

//     assert(R1L -(-R2L) == R1L+R2L);
//     assert(R1L -(-OneL) == R1L+OneL);
//     assert(R1L - OneL == R1L+(-OneL));
//     for (unsigned int i = 1; i < 256; ++i) {
//         assert((MaxL>>i) - (-OneL)  == (HalfL >> (i-1)));
//         assert((HalfL >> (i-1)) - OneL == (MaxL>>i));
//         TmpL = (HalfL >> (i-1));
//         assert(TmpL-- == (HalfL >> (i-1)));
//         assert(TmpL == (MaxL >> i));
//         TmpL = (HalfL >> (i-1));
//         assert(--TmpL == (MaxL >> i));
//     }
//     TmpL = R1L;
//     assert(--TmpL == R1L-1);
// }

// ( multiply )
// {
//     assert((R1L * R1L).ToString() == "62a38c0486f01e45879d7910a7761bf30d5237e9873f9bff3642a732c4d84f10");
//     assert((R1L * R2L).ToString() == "de37805e9986996cfba76ff6ba51c008df851987d9dd323f0e5de07760529c40");
//     assert((R1L * ZeroL) == ZeroL);
//     assert((R1L * OneL) == R1L);
//     assert((R1L * MaxL) == -R1L);
//     assert((R2L * R1L) == (R1L * R2L));
//     assert((R2L * R2L).ToString() == "ac8c010096767d3cae5005dec28bb2b45a1d85ab7996ccd3e102a650f74ff100");
//     assert((R2L * ZeroL) == ZeroL);
//     assert((R2L * OneL) == R2L);
//     assert((R2L * MaxL) == -R2L);

//     assert(MaxL * MaxL == OneL);

//     assert((R1L * 0) == 0);
//     assert((R1L * 1) == R1L);
//     assert((R1L * 3).ToString() == "7759b1c0ed14047f961ad09b20ff83687876a0181a367b813634046f91def7d4");
//     assert((R2L * 0x87654321UL).ToString() == "23f7816e30c4ae2017257b7a0fa64d60402f5234d46e746b61c960d09a26d070");
// }

// ( divide )
// {
//     arith_uint256 D1L("AD7133AC1977FA2B7");
//     arith_uint256 D2L("ECD751716");
//     assert((R1L / D1L).ToString() == "00000000000000000b8ac01106981635d9ed112290f8895545a7654dde28fb3a");
//     assert((R1L / D2L).ToString() == "000000000873ce8efec5b67150bad3aa8c5fcb70e947586153bf2cec7c37c57a");
//     assert(R1L / OneL == R1L);
//     assert(R1L / MaxL == ZeroL);
//     assert(MaxL / R1L == 2);
//     assert_THROW(R1L / ZeroL, uint_error);
//     assert((R2L / D1L).ToString() == "000000000000000013e1665895a1cc981de6d93670105a6b3ec3b73141b3a3c5");
//     assert((R2L / D2L).ToString() == "000000000e8f0abe753bb0afe2e9437ee85d280be60882cf0bd1aaf7fa3cc2c4");
//     assert(R2L / OneL == R2L);
//     assert(R2L / MaxL == ZeroL);
//     assert(MaxL / R2L == 1);
//     assert_THROW(R2L / ZeroL, uint_error);
// }


// bool almostEqual(double d1, double d2)
// {
//     return fabs(d1-d2) <= 4*fabs(d1)*numeric_limits<double>::epsilon();
// }

// ( methods ) // GetHex SetHex size() GetLow64 GetSerializeSize, Serialize, Unserialize
// {
//     assert(R1L.GetHex() == R1L.ToString());
//     assert(R2L.GetHex() == R2L.ToString());
//     assert(OneL.GetHex() == OneL.ToString());
//     assert(MaxL.GetHex() == MaxL.ToString());
//     arith_uint256 TmpL(R1L);
//     assert(TmpL == R1L);
//     TmpL.SetHex(R2L.ToString());   assert(TmpL == R2L);
//     TmpL.SetHex(ZeroL.ToString()); assert(TmpL == 0);
//     TmpL.SetHex(HalfL.ToString()); assert(TmpL == HalfL);

//     TmpL.SetHex(R1L.ToString());
//     assert(R1L.size() == 32);
//     assert(R2L.size() == 32);
//     assert(ZeroL.size() == 32);
//     assert(MaxL.size() == 32);
//     assert(R1L.GetLow64()  == R1LLow64);
//     assert(HalfL.GetLow64() ==0x0000000000000000ULL);
//     assert(OneL.GetLow64() ==0x0000000000000001ULL);

//     for (unsigned int i = 0; i < 255; ++i)
//     {
//         assert((OneL << i).getdouble() == ldexp(1.0,i));
//     }
//     assert(ZeroL.getdouble() == 0.0);
//     for (int i = 256; i > 53; --i)
//         assert(almostEqual((R1L>>(256-i)).getdouble(), ldexp(R1Ldouble,i)));
//     uint64_t R1L64part = (R1L>>192).GetLow64();
//     for (int i = 53; i > 0; --i) // doubles can store all integers in {0,...,2^54-1} exactly
//     {
//         assert((R1L>>(256-i)).getdouble() == (double)(R1L64part >> (64-i)));
//     }
// }

// (bignum_SetCompact)
// {
//     arith_uint256 num;
//     bool fNegative;
//     bool fOverflow;
//     num.SetCompact(0, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x00123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x01003456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x02000056, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x03000000, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x04000000, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x00923456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x01803456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x02800056, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x03800000, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x04800000, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x01123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000000012");
//     u_assert_str_eq(num.GetCompact(), 0x01120000U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     // Make sure that we don't generate compacts with the 0x00800000 bit set
//     num = 0x80;
//     u_assert_str_eq(num.GetCompact(), 0x02008000U);

//     num.SetCompact(0x01fedcba, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "000000000000000000000000000000000000000000000000000000000000007e");
//     u_assert_str_eq(num.GetCompact(true), 0x01fe0000U);
//     u_assert_str_eq(fNegative, true);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x02123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000001234");
//     u_assert_str_eq(num.GetCompact(), 0x02123400U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x03123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000000123456");
//     u_assert_str_eq(num.GetCompact(), 0x03123456U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x04123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000012345600");
//     u_assert_str_eq(num.GetCompact(), 0x04123456U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x04923456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000012345600");
//     u_assert_str_eq(num.GetCompact(true), 0x04923456U);
//     u_assert_str_eq(fNegative, true);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x05009234, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "0000000000000000000000000000000000000000000000000000000092340000");
//     u_assert_str_eq(num.GetCompact(), 0x05009234U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0x20123456, &fNegative, &fOverflow);
//     u_assert_str_eq(num.GetHex(), "1234560000000000000000000000000000000000000000000000000000000000");
//     u_assert_str_eq(num.GetCompact(), 0x20123456U);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, false);

//     num.SetCompact(0xff123456, &fNegative, &fOverflow);
//     u_assert_str_eq(fNegative, false);
//     u_assert_str_eq(fOverflow, true);
// }


// ( getmaxcoverage ) // some more tests just to get 100% coverage
// {
//     // ~R1L give a base_uint<256>
//     assert((~~R1L >> 10) == (R1L >> 10));
//     assert((~~R1L << 10) == (R1L << 10));
//     assert(!(~~R1L < R1L));
//     assert(~~R1L <= R1L);
//     assert(!(~~R1L > R1L));
//     assert(~~R1L >= R1L);
//     assert(!(R1L < ~~R1L));
//     assert(R1L <= ~~R1L);
//     assert(!(R1L > ~~R1L));
//     assert(R1L >= ~~R1L);

//     assert(~~R1L + R2L == R1L + ~~R2L);
//     assert(~~R1L - R2L == R1L - ~~R2L);
//     assert(~R1L != R1L); assert(R1L != ~R1L);
//     unsigned char TmpArray[32];
//     CHECKBITWISEOPERATOR(~R1,R2,|)
//     CHECKBITWISEOPERATOR(~R1,R2,^)
//     CHECKBITWISEOPERATOR(~R1,R2,&)
//     CHECKBITWISEOPERATOR(R1,~R2,|)
//     CHECKBITWISEOPERATOR(R1,~R2,^)
//     CHECKBITWISEOPERATOR(R1,~R2,&)
// }
}
