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

#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

const inline int32_t get_chainid(int version) {
    return version >> 16;
}

const inline dogecoin_bool is_auxpow(int version) {
    return version & VERSION_AUXPOW;
}

const inline dogecoin_bool is_legacy(int version) {
    return version == 1
        // Dogecoin: We have a random v2 block with no AuxPoW, treat as legacy
        || (version == 2 && get_chainid(version) == 0);
}

dogecoin_bool check_auxpow(const dogecoin_block_header block, dogecoin_chainparams* params) {
    /* Except for legacy blocks with full version 1, ensure that
       the chain ID is correct.  Legacy blocks are not allowed since
       the merge-mining start, which is checked in AcceptBlockHeader
       where the height is known.  */
    if (!is_legacy(block.version) && params->strict_id && get_chainid(block.version) != params->auxpow_id)
        return error("%s : block does not have our chain ID"
                     " (got %d, expected %d, full nVersion %d)",
                     __func__, get_chainid(block.version),
                     params->auxpow_id, block.version);

    /* If there is no auxpow, just check the block hash.  */
    if (!block.auxpow) {
        if (is_auxpow(block.version))
            return error("%s : no auxpow on block with auxpow version",
                         __func__);

        uint256 auxpow_hash;
        dogecoin_get_auxpow_hash(block.version, auxpow_hash);
        if (!CheckProofOfWork(auxpow_hash, block.bits, params))
            return error("%s : non-AUX proof of work failed", __func__);

        return true;
    }

    /* We have auxpow.  Check it.  */

    if (!is_auxpow(block.version))
        return error("%s : auxpow on block with non-auxpow version", __func__);

    // if (!block.auxpow->check(dogecoin_hash(), get_chainid(block.version), params))
    //     return error("%s : AUX POW is not valid", __func__);
    // if (!CheckProofOfWork(block.auxpow->getParentBlockPoWHash(), block.bits, params))
    //     return error("%s : AUX proof of work failed", __func__);

    return true;
}
