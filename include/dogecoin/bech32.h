/* Copyright (c) 2017 Pieter Wuille
 * Copyright (c) 2023 bluezr
 * Copyright (c) 2023 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __LIBDOGECOIN_BECH32_H__
#define __LIBDOGECOIN_BECH32_H__

#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/** Encode a Bech32 string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the null-terminated human readable part.
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *  Returns 1 if successful.
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len
);

/** Decode a Bech32 string
 *
 *  Out: hrp:      Pointer to a buffer of size strlen(input) - 6. Will be
 *                 updated to contain the null-terminated human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *  Returns 1 if succesful.
 */
int bech32_decode(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input
);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BECH32_H__