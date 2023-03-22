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

#ifndef __LIBDOGECOIN_PSBT_H__
#define __LIBDOGECOIN_PSBT_H__

#include <stdbool.h>

#include <dogecoin/buffer.h>
#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/eckey.h>
#include <dogecoin/tx.h>
#include <dogecoin/uthash.h>

LIBDOGECOIN_BEGIN_DECL

// Magic bytes
static const uint8_t PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff};

// Global types
static const uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;

// Input types
static const uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
static const uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
static const uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
static const uint8_t PSBT_IN_SIGHASH = 0x03;
static const uint8_t PSBT_IN_REDEEMSCRIPT = 0x04;
static const uint8_t PSBT_IN_WITNESSSCRIPT = 0x05;
static const uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
static const uint8_t PSBT_IN_SCRIPTSIG = 0x07;
static const uint8_t PSBT_IN_SCRIPTWITNESS = 0x08;

// Output types
static const uint8_t PSBT_OUT_REDEEMSCRIPT = 0x00;
static const uint8_t PSBT_OUT_WITNESSSCRIPT = 0x01;
static const uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;

// The separator is 0x00. Reading this in means that the unserializer can interpret it
// as a 0 length key which indicates that this is the separator. The separator has no value.
static const uint8_t PSBT_SEPARATOR = 0x00;

typedef struct psbt_input {
    int idx;
    dogecoin_tx_in* non_witness_utxo;
    dogecoin_tx_out* witness_utxo;
    cstring* redeem_script;
    cstring* witness_script;
    cstring* final_script_sig;
    cstring* final_script_witness;
    vector* hd_keypaths;
    vector* partial_sigs;
    vector* unknown;
    int sighash_type;
    UT_hash_handle hh;
} psbt_input;

typedef struct psbt_output {
    int idx;
    cstring* redeem_script;
    cstring* witness_script;
    vector* hd_keypaths;
    UT_hash_handle hh;
} psbt_output;

#define MAX_LENGTH 100

typedef struct psbt {
    int idx;
    dogecoin_tx* tx;
    psbt_input* inputs[MAX_LENGTH];
    psbt_output* outputs[MAX_LENGTH];
    vector* unknown;
    UT_hash_handle hh;
} psbt;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static psbt_input *psbt_inputs = NULL;
static psbt_output *psbt_outputs = NULL;
static psbt *psbts = NULL;
#pragma GCC diagnostic pop

LIBDOGECOIN_API psbt_input* new_psbt_input();
LIBDOGECOIN_API void add_psbt_input(psbt_input *psbt_input);
LIBDOGECOIN_API psbt_input* find_psbt_input(int idx);
LIBDOGECOIN_API void remove_psbt_input(psbt_input *psbt_input);
LIBDOGECOIN_API void dogecoin_psbt_input_free(psbt_input* psbt_input);
LIBDOGECOIN_API int start_psbt_input();

LIBDOGECOIN_API psbt_output* new_psbt_output();
LIBDOGECOIN_API void add_psbt_output(psbt_output *psbt_output);
LIBDOGECOIN_API psbt_output* find_psbt_output(int idx);
LIBDOGECOIN_API void remove_psbt_output(psbt_output *psbt_output);
LIBDOGECOIN_API void dogecoin_psbt_output_free(psbt_output* psbt_output);
LIBDOGECOIN_API int start_psbt_output();

LIBDOGECOIN_API psbt* new_psbt();
LIBDOGECOIN_API void add_psbt(psbt *psbt);
LIBDOGECOIN_API psbt* find_psbt(int idx);
LIBDOGECOIN_API void remove_psbt(psbt *psbt);
LIBDOGECOIN_API void dogecoin_psbt_free(psbt* psbt);
LIBDOGECOIN_API int start_psbt();

LIBDOGECOIN_API bool psbt_isnull(psbt* psbt);
LIBDOGECOIN_API bool psbt_input_isnull(psbt_input* input);
LIBDOGECOIN_API bool psbt_output_isnull(psbt_output* output);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_PSBT_H__
