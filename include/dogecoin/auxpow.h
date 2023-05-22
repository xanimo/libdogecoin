/*

 The MIT License (MIT)

 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_AUXPOW__
#define __LIBDOGECOIN_AUXPOW__

#include <dogecoin/block.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

typedef struct _merkle_tx {
    static const uint256 ABANDON_HASH;
    dogecoin_tx* tx;
    uint256 hash;
    uint256* merkle_branch;
    int index;
} merkle_tx;

typedef struct merkle_tx {
    uint256* merkle_branch;
    int index;
    dogecoin_block_header parent_block;
} auxpow;

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_AUXPOW__
