/*

 The MIT License (MIT)
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_DOGECOIN_H__
#define __LIBDOGECOIN_DOGECOIN_H__

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t dogecoin_bool; //!serialize, c/c++ save bool

#ifndef __cplusplus
#ifndef true
/* Defining `true` to be `1`. */
#define true 1
#endif

#ifndef false
/* A macro that defines `false` to be `0`. */
#define false 0
#endif
#endif //__cplusplus

#ifdef __cplusplus
#define LIBDOGECOIN_BEGIN_DECL extern "C" {
#define LIBDOGECOIN_END_DECL }
#else
#define LIBDOGECOIN_BEGIN_DECL /* empty */
#define LIBDOGECOIN_END_DECL   /* empty */
#endif

#ifndef LIBDOGECOIN_API
#if defined(_WIN32)
#ifdef LIBDOGECOIN_BUILD
#define LIBDOGECOIN_API __declspec(dllexport)
#else
#define LIBDOGECOIN_API
#endif
#elif defined(__GNUC__) && defined(LIBDOGECOIN_BUILD)
#define LIBDOGECOIN_API __attribute__((visibility("default")))
#else
#define LIBDOGECOIN_API
#endif
#endif

#if defined(_MSC_VER)
#include <BaseTsd.h>
/**
 * The ssize_t type is a signed integer type that is at least 32 bits in size.
 */
typedef SSIZE_T ssize_t;
#endif

/* This is the length of the uncompressed public key. */
#define DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH 65
/* Defining the length of the compressed public key. */
#define DOGECOIN_ECKEY_COMPRESSED_LENGTH 33
/* Defining the length of the public key. */
#define DOGECOIN_ECKEY_PKEY_LENGTH 32
/* Defining the length of the hash. */
#define DOGECOIN_HASH_LENGTH 32

/* This is a macro that returns the minimum of two integers. */
#define DOGECOIN_MIN(a, b) (((a) < (b)) ? (a) : (b))
/* This is a macro that returns the maximum of two integers. */
#define DOGECOIN_MAX(a, b) (((a) > (b)) ? (a) : (b))

LIBDOGECOIN_BEGIN_DECL

/**
 * An array of 32 bytes.
 */
typedef uint8_t uint256[32];
/**
 * An array of 20 bytes.
 */
typedef uint8_t uint160[20];

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_DOGECOIN_H__
