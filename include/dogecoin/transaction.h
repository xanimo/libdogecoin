/*
 The MIT License (MIT)
 
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_TRANSACTION_H__
#define __LIBDOGECOIN_TRANSACTION_H__

#include <stdlib.h>    /* malloc       */
#include <stddef.h>    /* offsetof     */
#include <stdio.h>     /* printf       */
#include <string.h>    /* memset       */
#include <dogecoin/uthash.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>
#include <dogecoin/core.h>
#include <dogecoin/crypto.h>

LIBDOGECOIN_BEGIN_DECL

/* hashmap functions */
typedef struct working_transaction {
    int idx;
    dogecoin_tx* transaction;
    UT_hash_handle hh;
} working_transaction;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static working_transaction *transactions = NULL;
#pragma GCC diagnostic pop
// instantiates a new transaction
LIBDOGECOIN_API working_transaction* new_transaction();

LIBDOGECOIN_API void add_transaction(working_transaction *working_tx);

LIBDOGECOIN_API working_transaction* find_transaction(int idx);

LIBDOGECOIN_API void remove_transaction(working_transaction *working_tx);

LIBDOGECOIN_API void remove_all();

LIBDOGECOIN_API void print_transactions();

LIBDOGECOIN_API void count_transactions();

LIBDOGECOIN_API int by_id();

LIBDOGECOIN_API const char *getl(const char *prompt);

LIBDOGECOIN_API const char *get_raw_tx(const char *prompt_tx);

LIBDOGECOIN_API const char *get_private_key(const char *prompt_key);

LIBDOGECOIN_API int start_transaction(); // #returns  an index of a transaction to build in memory.  (1, 2, etc) ..   

LIBDOGECOIN_API int save_raw_transaction(int txindex, const char* hexadecimal_transaction);

LIBDOGECOIN_API int add_utxo(int txindex, char* hex_utxo_txid, int vout); // #returns 1 if success.

LIBDOGECOIN_API int add_output(int txindex, char* destinationaddress, char* amount);

// 'closes the inputs', specifies the recipient, specifies the amnt-to-subtract-as-fee, and returns the raw tx..
// out_dogeamount == just an echoback of the total amount specified in the addutxos for verification
LIBDOGECOIN_API char* finalize_transaction(int txindex, char* destinationaddress, char* subtractedfee, char* out_dogeamount_for_verification, char* public_key);

LIBDOGECOIN_API char* get_raw_transaction(int txindex); // #returns 0 if not closed, returns rawtx again if closed/created.

LIBDOGECOIN_API void clear_transaction(int txindex); // #clears a tx in memory. (overwrites)

// sign a given inputted transaction with a given private key, and return a hex signed transaction.
// we may want to add such things to 'advanced' section:
// locktime, possibilities for multiple outputs, data, sequence.
LIBDOGECOIN_API int sign_raw_transaction(int inputindex, char* incomingrawtx, char* scripthex, int sighashtype, char* privkey);

LIBDOGECOIN_API int sign_indexed_raw_transaction(int txindex, int inputindex, char* incomingrawtx, char* scripthex, int sighashtype, char* privkey);

LIBDOGECOIN_API int sign_transaction(int txindex, char* script_pubkey, char* privkey);

LIBDOGECOIN_API int store_raw_transaction(char* incomingrawtx);

#define DOGECOIN_TX_SEQUENCE_FINAL 0xffffffff
#define DOGECOIN_TX_VERSION_1 1
#define DOGECOIN_TX_VERSION_2 2
#define DOGECOIN_TX_IS_ELEMENTS 1
#define DOGECOIN_TX_IS_ISSUANCE 2
#define DOGECOIN_TX_IS_PEGIN 4
#define DOGECOIN_TX_IS_COINBASE 8

#define DOGECOIN_SATOSHI_PER_BTC 100000000
#define DOGECOIN_BTC_MAX 21000000

#define DOGECOIN_TXHASH_LEN 32 /** Size of a transaction hash in bytes */

#define DOGECOIN_TX_FLAG_USE_WITNESS   0x1 /* Encode witness data if present */
#define DOGECOIN_TX_FLAG_USE_ELEMENTS  0x2 /* Encode/Decode as an elements transaction */
#define DOGECOIN_TX_FLAG_ALLOW_PARTIAL 0x4 /* Allow partially complete transactions */
/* Note: This flag encodes/parses transactions that are ambiguous to decode.
   Unless you have a good reason to do so you will most likely not need it */
#define DOGECOIN_TX_FLAG_PRE_BIP144    0x8 /* Encode/Decode using pre-BIP 144 serialisation */

#define DOGECOIN_TX_FLAG_BLINDED_INITIAL_ISSUANCE 0x1

#define DOGECOIN_TX_DUMMY_NULL 0x1 /* An empty witness item */
#define DOGECOIN_TX_DUMMY_SIG  0x2 /* A dummy signature */
#define DOGECOIN_TX_DUMMY_SIG_LOW_R  0x4 /* A dummy signature created with EC_FLAG_GRIND_R */

/** Sighash flags for transaction signing */
#define DOGECOIN_SIGHASH_DEFAULT      0x00
#define DOGECOIN_SIGHASH_ALL          0x01
#define DOGECOIN_SIGHASH_NONE         0x02
#define DOGECOIN_SIGHASH_SINGLE       0x03
#define DOGECOIN_SIGHASH_FORKID       0x40
#define DOGECOIN_SIGHASH_RANGEPROOF   0x40  /* Liquid/Elements only */
#define DOGECOIN_SIGHASH_ANYPREVOUT   0x40 /* BIP118 only */
#define DOGECOIN_SIGHASH_ANYPREVOUTANYSCRIPT 0xc0 /* BIP118 only */
#define DOGECOIN_SIGHASH_ANYONECANPAY 0x80

#define DOGECOIN_SIGHASH_MASK         0x1f /* Mask for determining ALL/NONE/SINGLE */
#define DOGECOIN_SIGHASH_TR_IN_MASK   0xc0 /* Taproot mask for determining input hash type */

#define DOGECOIN_TX_ASSET_CT_EMPTY_PREFIX    0x00
#define DOGECOIN_TX_ASSET_CT_EXPLICIT_PREFIX 0x01
#define DOGECOIN_TX_ASSET_CT_VALUE_PREFIX_A  0x08
#define DOGECOIN_TX_ASSET_CT_VALUE_PREFIX_B  0x09
#define DOGECOIN_TX_ASSET_CT_ASSET_PREFIX_A  0x0a
#define DOGECOIN_TX_ASSET_CT_ASSET_PREFIX_B  0x0b
#define DOGECOIN_TX_ASSET_CT_NONCE_PREFIX_A  0x02
#define DOGECOIN_TX_ASSET_CT_NONCE_PREFIX_B  0x03

#define DOGECOIN_TX_ASSET_TAG_LEN 32
#define DOGECOIN_TX_ASSET_CT_VALUE_LEN 33 /* version byte + 32 bytes */
#define DOGECOIN_TX_ASSET_CT_VALUE_UNBLIND_LEN 9 /* version byte + 8 bytes */
#define DOGECOIN_TX_ASSET_CT_ASSET_LEN 33 /* version byte + 32 bytes */
#define DOGECOIN_TX_ASSET_CT_NONCE_LEN 33 /* version byte + 32 bytes */
#define DOGECOIN_TX_ASSET_CT_LEN 33       /* version byte + 32 bytes */

#define DOGECOIN_TX_ISSUANCE_FLAG (1 << 31)
#define DOGECOIN_TX_PEGIN_FLAG (1 << 30)
#define DOGECOIN_TX_INDEX_MASK 0x3fffffff

#define DOGECOIN_NO_CODESEPARATOR 0xffffffff /* No BIP342 code separator position */

struct dogecoin_map;
#ifdef SWIG
struct libdogecoin_tx_input;
struct libdogecoin_tx_output;
struct libdogecoin_tx;
#else
/** A transaction witness item */
struct libdogecoin_tx_witness_item {
    unsigned char *witness;
    size_t witness_len;
};

/** A transaction witness stack */
struct libdogecoin_tx_witness_stack {
    struct libdogecoin_tx_witness_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A transaction input */
struct libdogecoin_tx_input {
    unsigned char txhash[DOGECOIN_TXHASH_LEN];
    uint32_t index;
    uint32_t sequence;
    unsigned char *script;
    size_t script_len;
    struct libdogecoin_tx_witness_stack *witness;
    uint8_t features;
};

/** A transaction output */
struct libdogecoin_tx_output {
    uint64_t satoshi;
    unsigned char *script;
    size_t script_len;
    uint8_t features;
};

/** A parsed bitcoin transaction */
struct libdogecoin_tx {
    uint32_t version;
    uint32_t locktime;
    struct libdogecoin_tx_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct libdogecoin_tx_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new witness stack.
 *
 * :param allocation_len: The number of items to pre-allocate space for.
 * :param output: Destination for the resulting witness stack.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_init_alloc(
    size_t allocation_len,
    struct libdogecoin_tx_witness_stack **output);

/**
 * Create a copy of a witness stack.
 *
 * :param stack: The witness stack to copy.
 * :param output: Destination for the resulting copy.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_clone_alloc(
    const struct libdogecoin_tx_witness_stack *stack,
    struct libdogecoin_tx_witness_stack **output);

/**
 * Add a witness to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param witness: The witness data to add to the stack.
 * :param witness_len: Length of ``witness`` in bytes.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_add(
    struct libdogecoin_tx_witness_stack *stack,
    const unsigned char *witness,
    size_t witness_len);

/**
 * Add a dummy witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param flags: ``DOGECOIN_TX_DUMMY_`` Flags indicating the type of dummy to add.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_add_dummy(
    struct libdogecoin_tx_witness_stack *stack,
    uint32_t flags);

/**
 * Set a witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param index: Index of the item to set. The stack will grow if needed to this many items.
 * :param witness: The witness data to add to the stack.
 * :param witness_len: Length of ``witness`` in bytes.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_set(
    struct libdogecoin_tx_witness_stack *stack,
    size_t index,
    const unsigned char *witness,
    size_t witness_len);

/**
 * Set a dummy witness item to a witness stack.
 *
 * :param stack: The witness stack to add to.
 * :param index: Index of the item to set. The stack will grow if needed to this many items.
 * :param flags: ``DOGECOIN_TX_DUMMY_`` Flags indicating the type of dummy to set.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_set_dummy(
    struct libdogecoin_tx_witness_stack *stack,
    size_t index,
    uint32_t flags);

/**
 * Free a transaction witness stack allocated by `libdogecoin_tx_witness_stack_init_alloc`.
 *
 * :param stack: The transaction witness stack to free.
 */
LIBDOGECOIN_API int libdogecoin_tx_witness_stack_free(
    struct libdogecoin_tx_witness_stack *stack);

/**
 * Allocate and initialize a new transaction input.
 *
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `DOGECOIN_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param output: Destination for the resulting transaction input.
 */
LIBDOGECOIN_API int libdogecoin_tx_input_init_alloc(
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct libdogecoin_tx_witness_stack *witness,
    struct libdogecoin_tx_input **output);

/**
 * Free a transaction input allocated by `libdogecoin_tx_input_init_alloc`.
 *
 * :param input: The transaction input to free.
 */
LIBDOGECOIN_API int libdogecoin_tx_input_free(struct libdogecoin_tx_input *input);

/**
 * Initialize a new transaction output.
 *
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param output: Transaction output to initialize.
 */
LIBDOGECOIN_API int libdogecoin_tx_output_init(uint64_t satoshi,
                                        const unsigned char *script,
                                        size_t script_len,
                                        struct libdogecoin_tx_output *output);

/**
 * Allocate and initialize a new transaction output.
 *
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param output: Destination for the resulting transaction output.
 */
LIBDOGECOIN_API int libdogecoin_tx_output_init_alloc(
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    struct libdogecoin_tx_output **output);

/**
 * Create a new copy of a transaction output.
 *
 * :param tx_output_in: The transaction output to clone.
 * :param output: Destination for the resulting transaction output copy.
 */
LIBDOGECOIN_API int libdogecoin_tx_output_clone_alloc(
    const struct libdogecoin_tx_output *tx_output_in,
    struct libdogecoin_tx_output **output);

/**
 * Create a new copy of a transaction output in place.
 *
 * :param tx_output_in: The transaction output to clone.
 * :param output: Destination for the resulting transaction output copy.
 *
 * .. note:: ``output`` is overwritten in place, and not cleared first.
 */
LIBDOGECOIN_API int libdogecoin_tx_output_clone(
    const struct libdogecoin_tx_output *tx_output_in,
    struct libdogecoin_tx_output *output);

/**
 * Free a transaction output allocated by `libdogecoin_tx_output_init_alloc`.
 *
 * :param output: The transaction output to free.
 */
LIBDOGECOIN_API int libdogecoin_tx_output_free(struct libdogecoin_tx_output *output);

/**
 * Allocate and initialize a new transaction.
 *
 * :param version: The version of the transaction.
 * :param locktime: The locktime of the transaction.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param output: Destination for the resulting transaction output.
 */
LIBDOGECOIN_API int libdogecoin_tx_init_alloc(
    uint32_t version,
    uint32_t locktime,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    struct libdogecoin_tx **output);

/**
 * Create a new copy of a transaction.
 *
 * :param tx: The transaction to clone.
 * :param flags: Flags controlling transaction creation. Must be 0.
 * :param output: Destination for the resulting transaction copy.
 */
LIBDOGECOIN_API int libdogecoin_tx_clone_alloc(
    const struct libdogecoin_tx *tx,
    uint32_t flags,
    struct libdogecoin_tx **output);

/**
 * Add a transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param input: The transaction input to add to ``tx``.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_input(
    struct libdogecoin_tx *tx,
    const struct libdogecoin_tx_input *input);

/**
 * Add a transaction input to a transaction at a given position.
 *
 * :param tx: The transaction to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param input: The transaction input to add to ``tx``.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_input_at(
    struct libdogecoin_tx *tx,
    uint32_t index,
    const struct libdogecoin_tx_input *input);

/**
 * Add a transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `DOGECOIN_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_raw_input(
    struct libdogecoin_tx *tx,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct libdogecoin_tx_witness_stack *witness,
    uint32_t flags);

/**
 * Add a transaction input to a transaction in a given position.
 *
 * :param tx: The transaction to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `DOGECOIN_TXHASH_LEN`.
 * :param utxo_index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling input creation. Must be 0.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_raw_input_at(
    struct libdogecoin_tx *tx,
    uint32_t index,
    const unsigned char *txhash,
    size_t txhash_len,
    uint32_t utxo_index,
    uint32_t sequence,
    const unsigned char *script,
    size_t script_len,
    const struct libdogecoin_tx_witness_stack *witness,
    uint32_t flags);

/**
 * Remove a transaction input from a transaction.
 *
 * :param tx: The transaction to remove the input from.
 * :param index: The zero-based index of the input to remove.
 */
LIBDOGECOIN_API int libdogecoin_tx_remove_input(
    struct libdogecoin_tx *tx,
    size_t index);

/**
 * Set the scriptsig for an input in a transaction.
 *
 * :param tx: The transaction to operate on.
 * :param index: The zero-based index of the input to set the script on.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 */
LIBDOGECOIN_API int libdogecoin_tx_set_input_script(
    const struct libdogecoin_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness stack for an input in a transaction.
 *
 * :param tx: The transaction to operate on.
 * :param index: The zero-based index of the input to set the witness stack on.
 * :param stack: The transaction witness stack to set.
 */

LIBDOGECOIN_API int libdogecoin_tx_set_input_witness(
    const struct libdogecoin_tx *tx,
    size_t index,
    const struct libdogecoin_tx_witness_stack *stack);

/**
 * Add a transaction output to a transaction.
 *
 * :param tx: The transaction to add the output to.
 * :param output: The transaction output to add to ``tx``.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_output(
    struct libdogecoin_tx *tx,
    const struct libdogecoin_tx_output *output);

/**
 * Add a transaction output to a transaction at a given position.
 *
 * :param tx: The transaction to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param output: The transaction output to add to ``tx``.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_output_at(
    struct libdogecoin_tx *tx,
    uint32_t index,
    const struct libdogecoin_tx_output *output);

/**
 * Add a transaction output to a transaction.
 *
 * :param tx: The transaction to add the output to.
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_raw_output(
    struct libdogecoin_tx *tx,
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags);

/**
 * Add a transaction output to a transaction at a given position.
 *
 * :param tx: The transaction to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param satoshi: The amount of the output in satoshi.
 * :param script: The scriptPubkey for the output.
 * :param script_len: Size of ``script`` in bytes.
 * :param flags: Flags controlling output creation. Must be 0.
 */
LIBDOGECOIN_API int libdogecoin_tx_add_raw_output_at(
    struct libdogecoin_tx *tx,
    uint32_t index,
    uint64_t satoshi,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags);

/**
 * Remove a transaction output from a transaction.
 *
 * :param tx: The transaction to remove the output from.
 * :param index: The zero-based index of the output to remove.
 */
LIBDOGECOIN_API int libdogecoin_tx_remove_output(
    struct libdogecoin_tx *tx,
    size_t index);

/**
 * Get the number of inputs in a transaction that have witness data.
 *
 * :param tx: The transaction to get the witnesses count from.
 * :param written: Destination for the number of witness-containing inputs.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_witness_count(
    const struct libdogecoin_tx *tx,
    size_t *written);

/**
 * Free a transaction allocated by `libdogecoin_tx_init_alloc`.
 *
 * :param tx: The transaction to free.
 */
// LIBDOGECOIN_API int libdogecoin_tx_free(struct libdogecoin_tx *tx);

/**
 * Return the txid of a transaction.
 *
 * :param tx: The transaction to compute the txid of.
 * :param bytes_out: Destination for the txid.
 * FIXED_SIZED_OUTPUT(len, bytes_out, DOGECOIN_TXHASH_LEN)
 *
 * .. note:: The txid is expensive to compute.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_txid(
    const struct libdogecoin_tx *tx,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return the length of transaction once serialized into bytes.
 *
 * :param tx: The transaction to find the serialized length of.
 * :param flags: ``DOGECOIN_TX_FLAG_`` Flags controlling serialization options.
 * :param written: Destination for the length of the serialized bytes.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_length(
    const struct libdogecoin_tx *tx,
    uint32_t flags,
    size_t *written);

/**
 * Create a transaction from its serialized bytes.
 *
 * :param bytes: Bytes to create the transaction from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param flags: ``DOGECOIN_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting transaction.
 */
LIBDOGECOIN_API int libdogecoin_tx_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    struct libdogecoin_tx **output);

/**
 * Create a transaction from its serialized bytes in hexadecimal.
 *
 * :param hex: Hexadecimal string containing the transaction.
 * :param flags: ``DOGECOIN_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting transaction.
 */
LIBDOGECOIN_API int libdogecoin_tx_from_hex(
    const char *hex,
    uint32_t flags,
    struct libdogecoin_tx **output);

/**
 * Serialize a transaction to bytes.
 *
 * :param tx: The transaction to serialize.
 * :param flags: ``DOGECOIN_TX_FLAG_`` Flags controlling serialization options.
 * :param bytes_out: Destination for the serialized transaction.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the length of the serialized transaction.
 */
LIBDOGECOIN_API int libdogecoin_tx_to_bytes(
    const struct libdogecoin_tx *tx,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Serialize a transaction to hex.
 *
 * :param tx: The transaction to serialize.
 * :param flags: ``DOGECOIN_TX_FLAG_`` Flags controlling serialization options.
 * :param output: Destination for the resulting hexadecimal string.
 *
 * .. note:: The string returned should be freed using `dogecoin_free_string`.
 */
LIBDOGECOIN_API int libdogecoin_tx_to_hex(
    const struct libdogecoin_tx *tx,
    uint32_t flags,
    char **output);

/**
 * Get the weight of a transaction.
 *
 * :param tx: The transaction to get the weight of.
 * :param written: Destination for the weight.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_weight(
    const struct libdogecoin_tx *tx,
    size_t *written);

/**
 * Get the virtual size of a transaction.
 *
 * :param tx: The transaction to get the virtual size of.
 * :param written: Destination for the virtual size.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_vsize(
    const struct libdogecoin_tx *tx,
    size_t *written);

/**
 * Compute transaction vsize from transaction weight.
 *
 * :param weight: The weight to convert to a virtual size.
 * :param written: Destination for the virtual size.
 */
LIBDOGECOIN_API int libdogecoin_tx_vsize_from_weight(
    size_t weight,
    size_t *written);

/**
 * Compute the total sum of all outputs in a transaction.
 *
 * :param tx: The transaction to compute the total from.
 * :param value_out: Destination for the output total.
 */
LIBDOGECOIN_API int libdogecoin_tx_get_total_output_satoshi(
    const struct libdogecoin_tx *tx,
    uint64_t *value_out);

/**
 * Create a BTC transaction for signing and return its hash.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Size of ``script`` in bytes.
 * :param satoshi: The amount spent by the input being signed for. Only used if
 *|     flags includes `DOGECOIN_TX_FLAG_USE_WITNESS`, pass 0 otherwise.
 * :param sighash: ``DOGECOIN_SIGHASH_`` flags specifying the type of signature desired.
 * :param flags: `DOGECOIN_TX_FLAG_USE_WITNESS` to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
LIBDOGECOIN_API int libdogecoin_tx_get_btc_signature_hash(
    const struct libdogecoin_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create a BTC transaction for taproot signing and return its hash.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param scripts: Map of input index to (unprefixed) scriptCodes for each input in ``tx``.
 * :param values: The value in satoshi for each input in ``tx``.
 * :param num_values: The number of elements in ``values``.
 * :param tapleaf_script: BIP342 tapscript being spent.
 * :param tapleaf_script_len: Length of ``tapleaf_script`` in bytes.
 * :param key_version: Version of pubkey in tapscript. Must be set to 0x00 or 0x01.
 * :param codesep_position: BIP342 codeseparator position or ``DOGECOIN_NO_CODESEPARATOR`` if none.
 * :param annex: BIP341 annex, or NULL if none.
 * :param annex_len: Length of ``annex`` in bytes.
 * :param sighash: ``DOGECOIN_SIGHASH_`` flags specifying the type of signature desired.
 * :param flags: Flags controlling signature generation. Must be 0.
 * :param bytes_out: Destination for the resulting signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
*/
LIBDOGECOIN_API int libdogecoin_tx_get_btc_taproot_signature_hash(
    const struct libdogecoin_tx *tx,
    size_t index,
    const struct dogecoin_map *scripts,
    const uint64_t *values,
    size_t num_values,
    const unsigned char *tapleaf_script,
    size_t tapleaf_script_len,
    uint32_t key_version,
    uint32_t codesep_position,
    const unsigned char *annex,
    size_t annex_len,
    uint32_t sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create a transaction for signing and return its hash.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Size of ``script`` in bytes.
 * :param extra: Extra bytes to include in the transaction preimage.
 * :param extra_len: Size of ``extra`` in bytes.
 * :param extra_offset: Offset within the preimage to store ``extra``. To store
 *|     it at the end of the preimage, use 0xffffffff.
 * :param satoshi: The amount spent by the input being signed for. Only used if
 *|     flags includes `DOGECOIN_TX_FLAG_USE_WITNESS`, pass 0 otherwise.
 * :param sighash: ``DOGECOIN_SIGHASH_`` flags specifying the type of signature desired.
 * :param tx_sighash: The 32bit sighash value to include in the preimage to hash.
 *|     This must be given in host CPU endianess; For normal Bitcoin signing
 *|     the value of ``sighash`` should be given.
 * :param flags: `DOGECOIN_TX_FLAG_USE_WITNESS` to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
LIBDOGECOIN_API int libdogecoin_tx_get_signature_hash(
    const struct libdogecoin_tx *tx,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    const unsigned char *extra,
    size_t extra_len,
    uint32_t extra_offset,
    uint64_t satoshi,
    uint32_t sighash,
    uint32_t tx_sighash,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Determine if a transaction is a coinbase transaction.
 *
 * :param tx: The transaction to check.
 * :param written: 1 if the transaction is a coinbase transaction, otherwise 0.
 */
// LIBDOGECOIN_API int libdogecoin_tx_is_coinbase(
//     const struct libdogecoin_tx *tx,
//     size_t *written);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_TRANSACTION_H__
