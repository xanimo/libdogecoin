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

#include <dogecoin/pow.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

int32_t get_chainid(int32_t version) {
    return version >> 16;
}

dogecoin_bool is_auxpow(int32_t version) {
    return (version & VERSION_AUXPOW) == 256;
}

dogecoin_bool is_legacy(int32_t version) {
    return version == 1
        // Dogecoin: We have a random v2 block with no AuxPoW, treat as legacy
        || (version == 2 && get_chainid(version) == 0);
}

dogecoin_bool check_auxpow(dogecoin_auxpow_block block, dogecoin_chainparams* params) {
    /* Except for legacy blocks with full version 1, ensure that
       the chain ID is correct.  Legacy blocks are not allowed since
       the merge-mining start, which is checked in AcceptBlockHeader
       where the height is known.  */
    if (!is_legacy(block.header->version) && params->strict_id && get_chainid(block.header->version) != params->auxpow_id)
        printf("%s : block does not have our chain ID"
                " (got %d, expected %d, full nVersion %d) : %s\n",
                __func__, get_chainid(block.header->version),
                params->auxpow_id, block.header->version, strerror(errno));
        return false;

    /* If there is no auxpow, just check the block hash.  */
    if (!block.header->auxpow->is) {
        if (is_auxpow(block.header->version))
            printf("%s : no auxpow on block with auxpow version : %s\n", __func__, strerror(errno));
            return false;

        uint256 auxpow_hash;
        dogecoin_get_auxpow_hash(block.header->version, auxpow_hash);
        if (!check_pow(&auxpow_hash, block.header->bits, params))
            printf("%s : non-AUX proof of work failed : %s\n", __func__, strerror(errno));
            return false;

        return true;
    }

    /* We have auxpow.  Check it.  */

    if (!is_auxpow(block.header->version))
        printf("%s : auxpow on block with non-auxpow version : %s\n", __func__, strerror(errno));
        return false;

    uint256 block_header_hash;
    dogecoin_block_header_hash(block.header, block_header_hash);
    if (!block.header->auxpow->check(&block_header_hash, get_chainid(block.header->version), params))
        printf("%s : AUX POW is not valid : %s\n", __func__, strerror(errno));
        return false;

    uint256 parent_hash;
    dogecoin_block_header_hash(block.parent_header, parent_hash); // todo: swap with scrypt block header hash
    if (!check_pow(&parent_hash, block.parent_header->bits, params))
        printf("%s : AUX POW is not valid : %s\n", __func__, strerror(errno));
        return false;

    return true;
}
