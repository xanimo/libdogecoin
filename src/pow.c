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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <dogecoin/arith_uint256.h>
#include <dogecoin/pow.h>
#include <dogecoin/utils.h>

dogecoin_bool check_pow(uint256* hash, unsigned int nbits, dogecoin_chainparams *params) {
    dogecoin_bool f_negative, f_overflow;
    arith_uint256 target;
    target = set_compact(target, nbits, &f_negative, &f_overflow);
    arith_uint256 h;
    h = uint_to_arith((const uint256*)hash);
    char* hash_str = hash_to_string((const uint8_t*)&h);
    char* target_str = hash_to_string((const uint8_t*)&target);
    printf("hash: %s\n", utils_uint8_to_hex((const uint8_t*)hash, 32));
    printf("hash_str: %s\n", hash_str);
    printf("hash: %s\n", utils_uint8_to_hex((const uint8_t*)&target.pn[0], 32));
    printf("target_str: %s\n", target_str);
    if (f_negative || f_overflow || memcmp(&target, &params->pow_limit, 4) > 0) {
        printf("%s:%d:%s : AUX POW is not valid : %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    if (strcmp(hash_str, target_str) > 0) {
        printf("%s:%d:%s : AUX POW is not valid : %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        return false;
    }
    return true;
}
