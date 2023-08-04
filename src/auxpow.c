/*

 The MIT License (MIT)

 Copyright (c) 2009-2010 Satoshi Nakamoto
 Copyright (c) 2011 Vince Durham
 Copyright (c) 2009-2014 The Bitcoin developers
 Copyright (c) 2014-2016 Daniel Kraft
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

// #include <dogecoin/blockchain.h>
// #include <dogecoin/utils.h>
#include <dogecoin/hash.h>
#include <dogecoin/auxpow.h>

// const uint256* ABANDON_HASH(...uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

// void SetMerkleBranch(dogecoin_blockindex* pindex, int posInBlock) {
//     // Update the tx's hashBlock
//     uint256 hash;
//     dogecoin_block_header_hash(&pindex->header, hash);

//     // set the position of the transaction in the block
//     nIndex = posInBlock;
// }

// void InitMerkleBranch(const dogecoin_blockheader* block, int posInBlock)
// {
//     hashBlock = block.GetHash();
//     nIndex = posInBlock;
//     vMerkleBranch = BlockMerkleBranch(block, nIndex);
// }

// int GetDepthInMainChain(const dogecoin_blockindex* &pindexRet) const
// {
//     if (hashUnset())
//         return 0;

//     AssertLockHeld(cs_main);

//     // Find the block it claims to be in
//     BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
//     if (mi == mapBlockIndex.end())
//         return 0;
//     dogecoin_blockindex* pindex = (*mi).second;
//     if (!pindex || !chainActive.Contains(pindex))
//         return 0;

//     pindexRet = pindex;
//     return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
// }

// int GetBlocksToMaturity() const
// {
//     if (!IsCoinBase())
//         return 0;
//     int nCoinbaseMaturity = Params().GetConsensus(chainActive.Height()).nCoinbaseMaturity;
//     return std::max(0, (nCoinbaseMaturity + 1) - GetDepthInMainChain());
// }


// bool AcceptToMemoryPool(const CAmount& nAbsurdFee, CValidationState& state)
// {
//     return ::AcceptToMemoryPool(mempool, state, tx, true, NULL, NULL, false, nAbsurdFee);
// }

int get_expected_index (uint32_t nNonce, int nChainId, unsigned h)
{
  // Choose a pseudo-random slot in the chain merkle tree
  // but have it be fixed for a size/nonce/chain combination.
  //
  // This prevents the same work from being used twice for the
  // same chain while reducing the chance that two chains clash
  // for the same slot.

  /* This computation can overflow the uint32 used.  This is not an issue,
     though, since we take the mod against a power-of-two in the end anyway.
     This also ensures that the computation is, actually, consistent
     even if done in 64 bits as it was in the past on some systems.

     Note that h is always <= 30 (enforced by the maximum allowed chain
     merkle branch length), so that 32 bits are enough for the computation.  */

  uint32_t rand = nNonce;
  rand = rand * 1103515245 + 12345;
  rand += nChainId;
  rand = rand * 1103515245 + 12345;

  return rand % (1 << h);
}

uint256* check_merkle_branch(uint256 hash, const vector* parent_coinbase_merkle, unsigned int n_index) {
    if (n_index == (unsigned int)-1) return dogecoin_uint256_vla(1);
    unsigned int i = n_index;
    for (; i < n_index; i++) {
        uint256 pcm;
        memcpy(pcm, vector_idx(parent_coinbase_merkle, i), 32);
        if (i & 1)
            *hash = Hash(UBEGIN(*pcm), UEND(*pcm), UBEGIN(hash), UEND(hash));
        else
            *hash = Hash(UBEGIN(hash), UEND(hash), UBEGIN(*pcm), UEND(*pcm));
        i >>= 1;
    }
    return (uint256*)*&hash;
}

void init_aux_pow(dogecoin_block_header* header) {
    /* Set auxpow flag right now, since we take the block hash below.  */
    header->auxpow->is = true;

    /* Build a minimal coinbase script input for merge-mining.  */
    const uint256 block_hash;
    dogecoin_block_header_hash(header, (uint8_t*)block_hash);
    vector* input = vector_new(1, free);
    char* hexbuf = utils_uint8_to_hex((const uint8_t*)block_hash, DOGECOIN_HASH_LENGTH);
    utils_reverse_hex(hexbuf, DOGECOIN_HASH_LENGTH*2);
    memcpy_safe((void*)block_hash, utils_hex_to_uint8(hexbuf), 32);
    vector_add(input, (void*)block_hash);

    /* Fake a parent-block coinbase with just the required input
        script and no outputs.  */
    dogecoin_tx* coinbase = dogecoin_tx_new();
    vector_resize(coinbase->vin, 1);
    const uint256 empty_hash;
    dogecoin_tx_in* tx_in = coinbase->vin->data[0];
    memcpy_safe(tx_in->prevout.hash, empty_hash, 32);
    // dogecoin_script script;
    tx_in->script_sig = input->data[0];
    assert(coinbase->vout->len==0);
    // CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

    // /* Build a fake parent block with the coinbase.  */
    // CBlock parent;
    // parent.nVersion = 1;
    // parent.vtx.resize(1);
    // parent.vtx[0] = coinbaseRef;
    // parent.hashMerkleRoot = BlockMerkleRoot(parent);

    // /* Construct the auxpow object.  */
    // header.SetAuxpow(new CAuxPow(coinbaseRef));
    // assert (header.auxpow->vChainMerkleBranch.empty());
    // header.auxpow->nChainIndex = 0;
    // assert (header.auxpow->vMerkleBranch.empty());
    // header.auxpow->nIndex = 0;
    // header.auxpow->parentBlock = parent;
}
