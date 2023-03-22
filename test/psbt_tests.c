/**********************************************************************
 * Copyright (c) 2023 bluezr                                          *
 * Copyright (c) 2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "utest.h"

#include <dogecoin/address.h>
#include <dogecoin/buffer.h>
#include <dogecoin/key.h>
#include <dogecoin/psbt.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/rmd160.h>

void test_psbt() {
    psbt_input* input = new_psbt_input();

    psbt_output* output = new_psbt_output();

    psbt* psbt = new_psbt();
    assert(psbt_isnull(psbt));

    dogecoin_psbt_output_free(output);
    dogecoin_psbt_input_free(input);
    dogecoin_psbt_free(psbt);
}

// sign_witness(script_code, i):
//     for key, sighash_type in psbt.inputs[i].items:
//         if sighash_type == None:
//             sighash_type = SIGHASH_ALL
//         if IsMine(key) and IsAcceptable(sighash_type):
//             sign(witness_sighash(script_code, i, input))

// sign_non_witness(script_code, i):
//     for key, sighash_type in psbt.inputs[i].items:
//         if sighash_type == None:
//             sighash_type = SIGHASH_ALL
//         if IsMine(key) and IsAcceptable(sighash_type):
//             sign(non_witness_sighash(script_code, i, input))

// for input, i in enumerate(psbt.inputs):
//     if witness_utxo.exists:
//         if redeemScript.exists:
//             assert(witness_utxo.scriptPubKey == P2SH(redeemScript))
//             script = redeemScript
//         else:
//             script = witness_utxo.scriptPubKey
//         if IsP2WPKH(script):
//             sign_witness(P2PKH(script[2:22]), i)
//         else if IsP2WSH(script):
//             assert(script == P2WSH(witnessScript))
//             sign_witness(witnessScript, i)
//     else if non_witness_utxo.exists:
//         assert(sha256d(non_witness_utxo) == psbt.tx.input[i].prevout.hash)
//         if redeemScript.exists:
//             assert(non_witness_utxo.vout[psbt.tx.input[i].prevout.n].scriptPubKey == P2SH(redeemScript))
//             sign_non_witness(redeemScript, i)
//         else:
//             sign_non_witness(non_witness_utxo.vout[psbt.tx.input[i].prevout.n].scriptPubKey, i)
//     else:
//         assert False
