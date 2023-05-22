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

// bool
// CAuxPow::check(const uint256& hashAuxBlock, int nChainId,
//                const Consensus::Params& params) const
// {
//     if (nIndex != 0)
//         return error("AuxPow is not a generate");

//     if (params.fStrictChainId && parentBlock.GetChainId () == nChainId)
//         return error("Aux POW parent has our chain ID");

//     if (vChainMerkleBranch.size() > 30)
//         return error("Aux POW chain merkle branch too long");

//     // Check that the chain merkle root is in the coinbase
//     const uint256 nRootHash
//       = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
//     std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
//     std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

//     // Check that we are in the parent block merkle tree
//     if (CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex)
//           != parentBlock.hashMerkleRoot)
//         return error("Aux POW merkle root incorrect");

//     const CScript script = tx->vin[0].scriptSig;

//     // Check that the same work is not submitted twice to our chain.
//     //

//     CScript::const_iterator pcHead =
//         std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));

//     CScript::const_iterator pc =
//         std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

//     if (pc == script.end())
//         return error("Aux POW missing chain merkle root in parent coinbase");

//     if (pcHead != script.end())
//     {
//         // Enforce only one chain merkle root by checking that a single instance of the merged
//         // mining header exists just before.
//         if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader)))
//             return error("Multiple merged mining headers in coinbase");
//         if (pcHead + sizeof(pchMergedMiningHeader) != pc)
//             return error("Merged mining header is not just before chain merkle root");
//     }
//     else
//     {
//         // For backward compatibility.
//         // Enforce only one chain merkle root by checking that it starts early in the coinbase.
//         // 8-12 bytes are enough to encode extraNonce and nBits.
//         if (pc - script.begin() > 20)
//             return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
//     }


//     // Ensure we are at a deterministic point in the merkle leaves by hashing
//     // a nonce and our chain ID and comparing to the index.
//     pc += vchRootHash.size();
//     if (script.end() - pc < 8)
//         return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

//     uint32_t nSize;
//     memcpy(&nSize, &pc[0], 4);
//     nSize = le32toh(nSize);
//     const unsigned merkleHeight = vChainMerkleBranch.size();
//     if (nSize != (1u << merkleHeight))
//         return error("Aux POW merkle branch size does not match parent coinbase");

//     uint32_t nNonce;
//     memcpy(&nNonce, &pc[4], 4);
//     nNonce = le32toh (nNonce);
//     if (nChainIndex != get_expected_index (nNonce, nChainId, merkleHeight))
//         return error("Aux POW wrong index");

//     return true;
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

uint256* check_merkle_branch(uint256 hash, const vector* parent_coinbase_merkle, int n_index) {
    if (n_index == -1) return dogecoin_uint256_vla(1);
    unsigned int i = n_index;
    for (; i < n_index; i++) {
        uint256 pcm;
        memcpy(pcm, vector_idx(parent_coinbase_merkle, i), 32);
        if (i & 1)
            hash = Hash(BEGIN(*pcm), END(*pcm), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(*pcm), END(*pcm));
        i >>= 1;
    }
    return hash;
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
    dogecoin_script script;
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
