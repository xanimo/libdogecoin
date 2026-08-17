/*

 The MIT License (MIT)

 Copyright (c) 2018 Bitcoin Core developers
 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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

/**
 * @file cf_checkpoints.h
 * @brief BIP157 compact filter header checkpoints.
 *
 * Kept apart from chainparams so that several thousand lines of generated
 * filter-header data do not sit in the middle of the chain parameter
 * definitions, and so that adding block checkpoints and adding filter
 * checkpoints touch different files.
 */

#ifndef __LIBDOGECOIN_CF_CHECKPOINTS_H__
#define __LIBDOGECOIN_CF_CHECKPOINTS_H__

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief BIP 157 compact filter header checkpoint.
 *
 * The spacing is per network and is not CFCHECKPT_INTERVAL on both:
 *
 *   mainnet   every  1,000 blocks
 *   testnet   every 10,000 blocks
 *
 * CFCHECKPT_INTERVAL (1000) is the protocol quantity -- getcfcheckpt asks a
 * peer for filter headers at multiples of 1000, and that is fixed by BIP157.
 * These arrays are our own trust anchors, and testnet is an order of magnitude
 * longer than mainnet, so storing every 1000th there would cost ten times the
 * entries for anchors nobody disputes.
 *
 * The consequence is worth stating rather than leaving to be discovered: on
 * testnet only every tenth entry of a getcfcheckpt response has a local anchor
 * to be checked against. The nine between are accepted on the strength of the
 * filter header chain alone.
 */
typedef struct dogecoin_cf_checkpoint_ {
    uint32_t height;           /**< Block height; a multiple of the network's
                                    checkpoint spacing above, not necessarily
                                    of CFCHECKPT_INTERVAL */
    const char* filter_header; /**< Filter header hash as 64-char hex string */
} dogecoin_cf_checkpoint;

/* BIP157 compact filter header checkpoints per network. */
extern const dogecoin_cf_checkpoint dogecoin_mainnet_cf_checkpoint_array[];
extern const size_t dogecoin_mainnet_cf_checkpoint_count;
extern const dogecoin_cf_checkpoint dogecoin_testnet_cf_checkpoint_array[];
extern const size_t dogecoin_testnet_cf_checkpoint_count;
extern const dogecoin_cf_checkpoint dogecoin_regtest_cf_checkpoint_array[];
extern const size_t dogecoin_regtest_cf_checkpoint_count;

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_CF_CHECKPOINTS_H__ */
