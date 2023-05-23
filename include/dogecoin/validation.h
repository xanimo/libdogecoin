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

#ifndef __LIBDOGECOIN_VALIDATION_H__
#define __LIBDOGECOIN_VALIDATION_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/block.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

static int32_t VERSION_AUXPOW = (1 << 8);

LIBDOGECOIN_API const inline int32_t get_chainid(int32_t version);
LIBDOGECOIN_API const inline dogecoin_bool is_auxpow(int32_t version);
LIBDOGECOIN_API const inline dogecoin_bool is_legacy(int32_t version);
LIBDOGECOIN_API dogecoin_bool check_auxpow(dogecoin_auxpow_block block, dogecoin_chainparams* params);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_VALIDATION_H__