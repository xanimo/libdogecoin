/*

 The MIT License (MIT)

 Copyright (c) 2021 libbtc

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

#include <btc/base58.h>
#include <btc/chainparams.h>

#include "trezor-crypto/base58.h"
#include "trezor-crypto/segwit_addr.h"

static const HasherType BTC_HASHER = HASHER_SHA2D;

int btc_base58_decode(void* bin, size_t* binszp, const char* b58)
{
    return b58tobin(bin, binszp, b58);
}

int btc_b58check(const void* bin, size_t binsz, const char* base58str)
{
    return b58check(bin, binsz, BTC_HASHER, base58str);
}

int btc_base58_encode(char* b58, size_t* b58sz, const void* data, size_t binsz)
{
    return b58enc(b58, b58sz, data, binsz);
}

int btc_base58_encode_check(const uint8_t* data, int datalen, char* str, int strsize)
{
    return base58_encode_check(data, datalen, BTC_HASHER, str, strsize);
}

int btc_base58_decode_check(const char* str, uint8_t* data, size_t datalen)
{
    int res = base58_decode_check(str, BTC_HASHER, data, datalen);
    if (res > 0) {
        res += 4;
    }
    return res;
}

btc_bool btc_p2pkh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char *addrout, int len) {
    uint8_t hash160[sizeof(uint160)+1];
    hash160[0] = chain->b58prefix_pubkey_address;
    memcpy(hash160 + 1, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(uint160)+1, addrout, len) > 0);
}

btc_bool btc_p2sh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char* addrout,
                                    int len)
{
    uint8_t hash160[sizeof(uint160) + 1];
    hash160[0] = chain->b58prefix_script_address;
    memcpy(hash160 + 1, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(uint160) + 1, addrout, len) > 0);
}

btc_bool btc_p2wpkh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char *addrout) {
    return segwit_addr_encode(addrout, chain->bech32_hrp, 0, hashin, sizeof(uint160));
}
