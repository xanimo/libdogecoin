#ifndef __LIBDOGECOIN_PSBT_H__
#define __LIBDOGECOIN_PSBT_H__

#include <dogecoin/bip32.h>
#include <dogecoin/map.h>
#include <dogecoin/transaction.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT Version number */
#define DOGECOIN_PSBT_VERSION_0 0x0
#define DOGECOIN_PSBT_VERSION_2 0x2
#define DOGECOIN_PSBT_HIGHEST_VERSION 0x2

/* Create an elements PSET */
#define DOGECOIN_PSBT_INIT_PSET 0x1

/* Ignore scriptsig and witness when adding an input */
#define DOGECOIN_PSBT_FLAG_NON_FINAL 0x1

/* Key prefix for proprietary keys in our unknown maps */
#define DOGECOIN_PSBT_PROPRIETARY_TYPE 0xFC

/*** psbt-txmod Transaction modification flags */
#define DOGECOIN_PSBT_TXMOD_INPUTS 0x1 /* Inputs can be modified */
#define DOGECOIN_PSBT_TXMOD_OUTPUTS 0x2 /* Outputs can be modified */
#define DOGECOIN_PSBT_TXMOD_SINGLE 0x4 /* SIGHASH_SINGLE signature is present */
#define DOGECOIN_PSET_TXMOD_RESERVED 0x1 /* Elements: Reserved: not used and ignored if set */

#define DOGECOIN_PSBT_PARSE_FLAG_STRICT 0x1 /* Parse strictly according to the PSBT/PSET spec */

/** Include redundant information to match some buggy PSBT implementations */
#define DOGECOIN_PSBT_SERIALIZE_FLAG_REDUNDANT 0x1

#define DOGECOIN_PSBT_EXTRACT_NON_FINAL 0x1 /* Extract without final scriptsig and witness */

#define DOGECOIN_PSBT_FINALIZE_NO_CLEAR 0x1 /* Finalize without clearing redeem/witness scripts etc */

/*** psbt-id-flags PSBT ID calculation flags */
#define DOGECOIN_PSBT_ID_BIP370 0x0 /* BIP370 compatible */
#define DOGECOIN_PSBT_ID_AS_V2 0x1 /* Compute PSBT v0 IDs like v2 by setting inputs sequence to 0 */
#define DOGECOIN_PSBT_ID_USE_LOCKTIME 0x2 /* Do not set locktime to 0 before calculating id */

/* Output blinding status */
#define DOGECOIN_PSET_BLINDED_NONE     0x0 /* Unblinded */
#define DOGECOIN_PSET_BLINDED_REQUIRED 0x1 /* Blinding key present with no other blinding data */
#define DOGECOIN_PSET_BLINDED_PARTIAL  0x2 /* Blinding key present with partial blinding data */
#define DOGECOIN_PSET_BLINDED_FULL     0x4 /* Blinding key present with full blinding data */

#define DOGECOIN_PSET_BLIND_ALL 0xffffffff /* Blind all outputs in dogecoin_psbt_blind */

#define DOGECOIN_SCALAR_OFFSET_LEN 32 /* Length of a PSET scalar offset */

struct ext_key;

#ifdef SWIG
struct dogecoin_psbt_input;
struct dogecoin_psbt_output;
struct dogecoin_psbt;
#else

/** A PSBT input */
struct dogecoin_psbt_input {
    unsigned char txhash[DOGECOIN_TXHASH_LEN]; /* 'previous txid' */
    uint32_t index;
    uint32_t sequence;
    struct libdogecoin_tx *utxo;
    struct libdogecoin_tx_output *witness_utxo;
    struct libdogecoin_tx_witness_stack *final_witness;
    struct dogecoin_map keypaths;
    struct dogecoin_map signatures;
    struct dogecoin_map unknowns;
    uint32_t sighash;
    uint32_t required_locktime; /* Required tx locktime or 0 if not given */
    uint32_t required_lockheight; /* Required tx lockheight or 0 if not given */
    struct dogecoin_map preimages; /* Preimage hash to data keyed by PSBT keytype + hash */
    struct dogecoin_map psbt_fields; /* Binary fields keyed by PSBT keytype */
    struct dogecoin_map taproot_leaf_signatures;
    struct dogecoin_map taproot_leaf_scripts;
    /* Hashes and paths for taproot bip32 derivation path */
    struct dogecoin_map taproot_leaf_hashes;
    struct dogecoin_map taproot_leaf_paths;
};

/** A PSBT output */
struct dogecoin_psbt_output {
    struct dogecoin_map keypaths;
    struct dogecoin_map unknowns;
    uint64_t amount;
    uint32_t has_amount;
    unsigned char *script;
    size_t script_len;
    struct dogecoin_map psbt_fields; /* Binary fields keyed by PSBT keytype */
    /* Map of 1-based position to taproot leaf script, in depth first order.
    * TODO: replace this with actual TR representaion when TR implemented */
    struct dogecoin_map taproot_tree;
    /* Hashes and paths for taproot bip32 derivation path */
    struct dogecoin_map taproot_leaf_hashes;
    struct dogecoin_map taproot_leaf_paths;
};

/** A partially signed bitcoin transaction */
struct dogecoin_psbt {
    unsigned char magic[5];
    struct libdogecoin_tx *tx;
    struct dogecoin_psbt_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct dogecoin_psbt_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
    struct dogecoin_map unknowns;
    struct dogecoin_map global_xpubs;
    uint32_t version;
    uint32_t tx_version;
    uint32_t fallback_locktime;
    uint32_t has_fallback_locktime;
    uint32_t tx_modifiable_flags;
};
#endif /* SWIG */

/**
 * Set the previous txid in an input.
 *
 * :param input: The input to update.
 * :param txhash: The previous hash for this input.
 * :param txhash_len: Length of ``txhash`` in bytes. Must be `DOGECOIN_TXHASH_LEN`.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_previous_txid(
    struct dogecoin_psbt_input *input,
    const unsigned char *txhash,
    size_t txhash_len);

/**
 * Set the output index in an input.
 *
 * :param input: The input to update.
 * :param index: The index of the spent output for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_output_index(
    struct dogecoin_psbt_input *input,
    uint32_t index);

/**
 * Set the sequence number in an input.
 *
 * :param input: The input to update.
 * :param sequence: The sequence number for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_sequence(
    struct dogecoin_psbt_input *input,
    uint32_t sequence);

/**
 * Clear the sequence number in an input.
 *
 * :param input: The input to update.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_clear_sequence(
    struct dogecoin_psbt_input *input);

/**
 * Set the utxo in an input.
 *
 * :param input: The input to update.
 * :param utxo: The (non witness) utxo for this input if it exists.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_utxo(
    struct dogecoin_psbt_input *input,
    const struct libdogecoin_tx *utxo);

/**
 * Set the witness_utxo in an input.
 *
 * :param input: The input to update.
 * :param witness_utxo: The witness utxo for this input if it exists.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_witness_utxo(
    struct dogecoin_psbt_input *input,
    const struct libdogecoin_tx_output *witness_utxo);

/**
 * Set the witness_utxo in an input from a transaction output.
 *
 * :param input: The input to update.
 * :param utxo: The transaction containing the output to add.
 * :param index: The output index in ``utxo`` to add.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_witness_utxo_from_tx(
    struct dogecoin_psbt_input *input,
    const struct libdogecoin_tx *utxo,
    uint32_t index);

/**
 * Set the redeem_script in an input.
 *
 * :param input: The input to update.
 * :param script: The redeem script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_redeem_script(
    struct dogecoin_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an input.
 *
 * :param input: The input to update.
 * :param script: The witness script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_witness_script(
    struct dogecoin_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the final_scriptsig in an input.
 *
 * :param input: The input to update.
 * :param final_scriptsig: The scriptSig for this input.
 * :param final_scriptsig_len: Length of ``final_scriptsig`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_final_scriptsig(
    struct dogecoin_psbt_input *input,
    const unsigned char *final_scriptsig,
    size_t final_scriptsig_len);

/**
 * Set the final witness in an input.
 *
 * :param input: The input to update.
 * :param witness: The witness stack for the input, or NULL if not present.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_final_witness(
    struct dogecoin_psbt_input *input,
    const struct libdogecoin_tx_witness_stack *witness);

/**
 * Set the keypaths in an input.
 *
 * :param input: The input to update.
 * :param map_in: The HD keypaths for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_keypaths(
    struct dogecoin_psbt_input *input,
    const struct dogecoin_map *map_in);

/**
 * Find a keypath matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_find_keypath(
    struct dogecoin_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an input.
 *
 * :param input: The input to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_keypath_add(
    struct dogecoin_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the partial signatures in an input.
 *
 * :param input: The input to update.
 * :param map_in: The partial signatures for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_signatures(
    struct dogecoin_psbt_input *input,
    const struct dogecoin_map *map_in);

/**
 * Find a partial signature matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_find_signature(
    struct dogecoin_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Add a pubkey/partial signature item to an input.
 *
 * :param input: The input to add the partial signature to.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param sig: The DER-encoded signature plus sighash byte to add.
 * :param sig_len: The length of ``sig`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_add_signature(
    struct dogecoin_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *sig,
    size_t sig_len);

/**
 * Set the unknown values in an input.
 *
 * :param input: The input to update.
 * :param map_in: The unknown key value pairs for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_unknowns(
    struct dogecoin_psbt_input *input,
    const struct dogecoin_map *map_in);

/**
 * Find an unknown item matching a key in an input.
 *
 * :param input: The input to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_find_unknown(
    struct dogecoin_psbt_input *input,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Set the sighash type in an input.
 *
 * :param input: The input to update.
 * :param sighash: The sighash type for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_sighash(
    struct dogecoin_psbt_input *input,
    uint32_t sighash);

/**
 * Set the required lock time in an input.
 *
 * :param input: The input to update.
 * :param required_locktime: The required locktime for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_required_locktime(
    struct dogecoin_psbt_input *input,
    uint32_t required_locktime);

/**
 * Clear the required lock time in an input.
 *
 * :param input: The input to update.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_clear_required_locktime(
    struct dogecoin_psbt_input *input);

/**
 * Set the required lock height in an input.
 *
 * :param input: The input to update.
 * :param required_lockheight: The required locktime for this input.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_set_required_lockheight(
    struct dogecoin_psbt_input *input,
    uint32_t required_lockheight);

/**
 * Clear the required lock height in an input.
 *
 * :param input: The input to update.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_clear_required_lockheight(
    struct dogecoin_psbt_input *input);

/**
 * Determine if a PSBT input is finalized.
 *
 * :param input: The input to check.
 * :param written: On success, set to one if the input is finalized, otherwise zero.
 */
LIBDOGECOIN_API int dogecoin_psbt_input_is_finalized(
    const struct dogecoin_psbt_input *input,
    size_t *written);

/**
 * Set the redeem_script in an output.
 *
 * :param output: The input to update.
 * :param script: The redeem script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_redeem_script(
    struct dogecoin_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an output.
 *
 * :param output: The output to update.
 * :param script: The witness script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_witness_script(
    struct dogecoin_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the keypaths in an output.
 *
 * :param output: The output to update.
 * :param map_in: The HD keypaths for this output.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_keypaths(
    struct dogecoin_psbt_output *output,
    const struct dogecoin_map *map_in);

/**
 * Find a keypath matching a pubkey in an output.
 *
 * :param output: The output to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_find_keypath(
    struct dogecoin_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an output.
 *
 * :param output: The output to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `EC_PUBLIC_KEY_LEN`.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_keypath_add(
    struct dogecoin_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the unknown map in an output.
 *
 * :param output: The output to update.
 * :param map_in: The unknown key value pairs for this output.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_unknowns(
    struct dogecoin_psbt_output *output,
    const struct dogecoin_map *map_in);

/**
 * Find an unknown item matching a key in an output.
 *
 * :param output: The output to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_find_unknown(
    struct dogecoin_psbt_output *output,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Set the amount in an output.
 *
 * :param output: The output to update.
 * :param amount: The amount for this output.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_amount(
    struct dogecoin_psbt_output *output,
    uint64_t amount);

/**
 * Clear the amount in an output.
 *
 * :param output: The output to update.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_clear_amount(
    struct dogecoin_psbt_output *output);

/**
 * Set the script in an output.
 *
 * :param output: The output to update.
 * :param script: The script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_psbt_output_set_script(
    struct dogecoin_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Allocate and initialize a new PSBT.
 *
 * :param version: The version of the PSBT. Must be ``DOGECOIN_PSBT_VERSION_0`` or ``DOGECOIN_PSBT_VERSION_2``.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param flags: Flags controlling psbt creation. Must be 0 or DOGECOIN_PSBT_INIT_PSET.
 * :param output: Destination for the resulting PSBT output.
 */
LIBDOGECOIN_API int dogecoin_psbt_init_alloc(
    uint32_t version,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    uint32_t flags,
    struct dogecoin_psbt **output);

#ifndef SWIG_PYTHON
/**
 * Free a PSBT allocated by `dogecoin_psbt_init_alloc`.
 *
 * :param psbt: The PSBT to free.
 */
LIBDOGECOIN_API int dogecoin_psbt_free(
    struct dogecoin_psbt *psbt);
#endif /* SWIG_PYTHON */

/**
 * Set the version for a PSBT.
 *
 * :param psbt: The PSBT to set the version for.
 * :param flags: Flags controlling the version upgrade/downgrade. Must be 0.
 * :param version: The version to use for the PSBT. Must be ``DOGECOIN_PSBT_VERSION_0``
 *|    or ``DOGECOIN_PSBT_VERSION_2``.
 *
 * .. note:: This call converts the PSBT in place to the specified version.
 */
LIBDOGECOIN_API int dogecoin_psbt_set_version(
    struct dogecoin_psbt *psbt,
    uint32_t flags,
    uint32_t version);

/**
 * Return the BIP-370 unique id of a PSBT.
 *
 * :param psbt: The PSBT to compute the id of.
 * :param flags: :ref:`psbt-id-flags`.
 * :param bytes_out: Destination for the id.
 * FIXED_SIZED_OUTPUT(len, bytes_out, DOGECOIN_TXHASH_LEN)
 *
 * .. note:: The id is expensive to compute.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_id(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return the calculated transaction lock time of a PSBT.
 *
 * :param psbt: The PSBT to compute the lock time of. Must be a v2 PSBT.
 * :param written: Destination for the calculated transaction lock time.
 *
 * .. note:: The calculated lock time may change as the PSBT is modified.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_locktime(
    const struct dogecoin_psbt *psbt,
    size_t *written);

/**
 * Determine if all PSBT inputs are finalized.
 *
 * :param psbt: The PSBT to check.
 * :param written: On success, set to one if the PSBT is finalized, otherwise zero.
 */
LIBDOGECOIN_API int dogecoin_psbt_is_finalized(
    const struct dogecoin_psbt *psbt,
    size_t *written);

/**
 * Set the global transaction for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction for.
 * :param tx: The transaction to set.
 *
 * The global transaction can only be set on a newly created version 0 PSBT.
 * After this call completes the PSBT will have empty inputs and outputs for
 * each input and output in the transaction ``tx`` given.
 */
LIBDOGECOIN_API int dogecoin_psbt_set_global_tx(
    struct dogecoin_psbt *psbt,
    const struct libdogecoin_tx *tx);

/**
 * Set the transaction version for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction version for. Must be a v2 PSBT.
 * :param version: The version to use for the transaction. Must be at least 2.
 */
LIBDOGECOIN_API int dogecoin_psbt_set_tx_version(
    struct dogecoin_psbt *psbt,
    uint32_t version);

/**
 * Get the transaction version of a PSBT.
 *
 * :param psbt: The PSBT to get the transaction version for. Must be v2 PSBT.
 * :param written: Destination for the PSBT's transaction version.
 *
 * .. note:: Returns the default version 2 if none has been explicitly set.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_tx_version(
    const struct dogecoin_psbt *psbt,
    size_t *written);

/**
 * Set the fallback locktime for a PSBT.
 *
 * :param psbt: The PSBT to set the fallback locktime for.
 * :param locktime: The fallback locktime to set.
 *
 * Sets the fallback locktime field in the transaction.
 * Cannot be set on V0 PSBTs.
 */
LIBDOGECOIN_API int dogecoin_psbt_set_fallback_locktime(
    struct dogecoin_psbt *psbt,
    uint32_t locktime);

/**
 * Clear the fallback locktime for a PSBT.
 *
 * :param psbt: The PSBT to update.
 */
LIBDOGECOIN_API int dogecoin_psbt_clear_fallback_locktime(
    struct dogecoin_psbt *psbt);

/**
 * Set the transaction modifiable flags for a PSBT.
 *
 * :param psbt: The PSBT to set the flags for.
 * :param flags: :ref:`psbt-txmod` indicating what can be modified.
 */
LIBDOGECOIN_API int dogecoin_psbt_set_tx_modifiable_flags(
    struct dogecoin_psbt *psbt,
    uint32_t flags);

/**
 * Add a transaction input to a PSBT at a given position.
 *
 * :param psbt: The PSBT to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param flags: Flags controlling input insertion. Must be 0 or `DOGECOIN_PSBT_FLAG_NON_FINAL`.
 * :param input: The transaction input to add.
 */
LIBDOGECOIN_API int dogecoin_psbt_add_tx_input_at(
    struct dogecoin_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct libdogecoin_tx_input *input);

/**
 * Remove a transaction input from a PSBT.
 *
 * :param psbt: The PSBT to remove the input from.
 * :param index: The zero-based index of the input to remove.
 */
LIBDOGECOIN_API int dogecoin_psbt_remove_input(
    struct dogecoin_psbt *psbt,
    uint32_t index);

/**
 * Return a BIP32 derived key matching a keypath in a PSBT input.
 *
 * :param psbt: The PSBT containing the input whose keypaths to search.
 * :param index: The zero-based index of the input in the PSBT.
 * :param subindex: The zero-based index of the keypath to start searching from.
 * :param flags: Flags controlling the keypath search. Must be 0.
 * :param hdkey: The BIP32 parent key to derive matches from.
 * :param output: Destination for the resulting derived key, if any.
 *
 * .. note:: See `dogecoin_map_keypath_get_bip32_key_from_alloc`.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_bip32_key_from_alloc(
    const struct dogecoin_psbt *psbt,
    size_t index,
    size_t subindex,
    uint32_t flags,
    const struct ext_key *hdkey,
    struct ext_key **output);

/**
 * Get the length of the scriptPubKey or redeem script from a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script length from.
 * :param written: Destination for the length of the script.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_signing_script_len(
    const struct dogecoin_psbt *psbt,
    size_t index,
    size_t *written);

/**
 * Get the scriptPubKey or redeem script from a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param bytes_out: Destination for the scriptPubKey or redeem script.
 * :param len: Length of ``bytes`` in bytes.
 * :param written: Destination for the number of bytes written to bytes_out.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_signing_script(
    const struct dogecoin_psbt *psbt,
    size_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Get the length of the scriptCode for signing a PSBT input.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param script: scriptPubKey/redeem script from `dogecoin_psbt_get_input_signing_script`.
 * :param script_len: Length of ``script`` in bytes.
 * :param written: Destination for the length of the scriptCode.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_scriptcode_len(
    const struct dogecoin_psbt *psbt,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    size_t *written);

/**
 * Get the scriptCode for signing a PSBT input given its scriptPubKey/redeem script.
 *
 * :param psbt: The PSBT containing the input to get from.
 * :param index: The zero-based index of the input to get the script from.
 * :param script: scriptPubKey/redeem script from `dogecoin_psbt_get_input_signing_script`.
 * :param script_len: Length of ``script`` in bytes.
 * :param bytes_out: Destination for the scriptCode.
 * :param len: Length of ``bytes`` in bytes.
 * :param written: Destination for the number of bytes written to bytes_out.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_scriptcode(
    const struct dogecoin_psbt *psbt,
    size_t index,
    const unsigned char *script,
    size_t script_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a transaction for signing a PSBT input and return its hash.
 *
 * :param psbt: The PSBT containing the input to compute a signature hash for.
 * :param index: The zero-based index of the PSBT input to sign.
 * :param tx: The transaction to generate the signature hash from.
 * :param script: The (unprefixed) scriptCode for the input being signed.
 * :param script_len: Length of ``script`` in bytes.
 * :param flags: Flags controlling signature hash generation. Must be 0.
 * :param bytes_out: Destination for the signature hash.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_signature_hash(
    struct dogecoin_psbt *psbt,
    size_t index,
    const struct libdogecoin_tx *tx,
    const unsigned char *script,
    size_t script_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Add a transaction output to a PSBT at a given position.
 *
 * :param psbt: The PSBT to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param flags: Flags controlling output insertion. Must be 0.
 * :param output: The transaction output to add.
 */
LIBDOGECOIN_API int dogecoin_psbt_add_tx_output_at(
    struct dogecoin_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct libdogecoin_tx_output *output);

/**
 * Remove a transaction output from a PSBT.
 *
 * :param psbt: The PSBT to remove the output from.
 * :param index: The zero-based index of the output to remove.
 */
LIBDOGECOIN_API int dogecoin_psbt_remove_output(
    struct dogecoin_psbt *psbt,
    uint32_t index);

/**
 * Create a PSBT from its serialized bytes.
 *
 * :param bytes: Bytes to create the PSBT from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param flags: `DOGECOIN_PSBT_PARSE_FLAG_STRICT` or 0.
 * :param output: Destination for the resulting PSBT.
 */
LIBDOGECOIN_API int dogecoin_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    struct dogecoin_psbt **output);

/**
 * Get the length of a PSBT when serialized to bytes.
 *
 * :param psbt: the PSBT.
 * :param flags: Flags controlling length determination. Must be 0.
 * :param written: Destination for the length in bytes when serialized.
 */
LIBDOGECOIN_API int dogecoin_psbt_get_length(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    size_t *written);

/**
 * Serialize a PSBT to bytes.
 *
 * :param psbt: the PSBT to serialize.
 * :param flags: Flags controlling serialization. Must be 0.
 * :param bytes_out: Destination for the serialized PSBT.
 * :param len: Length of ``bytes`` in bytes (use `dogecoin_psbt_get_length`).
 * :param written: number of bytes written to bytes_out.
 */
LIBDOGECOIN_API int dogecoin_psbt_to_bytes(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a PSBT from its serialized base64 string.
 *
 * :param base64: Base64 string to create the PSBT from.
 * :param flags: `DOGECOIN_PSBT_PARSE_FLAG_STRICT` or 0.
 * :param output: Destination for the resulting PSBT.
 */
LIBDOGECOIN_API int dogecoin_psbt_from_base64(
    const char *base64,
    uint32_t flags,
    struct dogecoin_psbt **output);

/**
 * Serialize a PSBT to a base64 string.
 *
 * :param psbt: the PSBT to serialize.
 * :param flags: Flags controlling serialization. Must be 0.
 * :param output: Destination for the resulting serialized PSBT.
 */
LIBDOGECOIN_API int dogecoin_psbt_to_base64(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    char **output);

/**
 * Combine the metadata from a source PSBT into another PSBT.
 *
 * :param psbt: the PSBT to combine into.
 * :param source: the PSBT to copy data from.
 */
LIBDOGECOIN_API int dogecoin_psbt_combine(
    struct dogecoin_psbt *psbt,
    const struct dogecoin_psbt *source);

/**
 * Clone a PSBT into a newly allocated copy.
 *
 * :param psbt: the PSBT to clone.
 * :param flags: Flags controlling PSBT creation. Must be 0.
 * :param output: Destination for the resulting cloned PSBT.
 */
LIBDOGECOIN_API int dogecoin_psbt_clone_alloc(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    struct dogecoin_psbt **output);

/**
 * Blind a PSBT.
 *
 * :param psbt: PSBT to blind. Directly modifies this PSBT.
 * :param values: Integer map of input index to value for the callers inputs.
 * :param vbfs: Integer map of input index to value blinding factor for the callers inputs.
 * :param assets: Integer map of input index to asset tags for the callers inputs.
 * :param abfs: Integer map of input index to asset blinding factors for the callers inputs.
 * :param entropy: Random entropy for asset and blinding factor generation.
 * :param entropy_len: Size of ``entropy`` in bytes. Must be a multiple
 *|    of 5 * `BLINDING_FACTOR_LEN` for each non-fee output to be blinded, with
 *|    an additional 2 * `BLINDING_FACTOR_LEN` bytes for any issuance outputs.
 * :param output_index: The zero based index of the output to blind, or `DOGECOIN_PSET_BLIND_ALL`.
 * :param flags: Flags controlling blinding. Must be 0.
 * :param output: Destination for a map of integer output index to the
 *|    ephemeral private key used to blind the output. Ignored if NULL.
 */
LIBDOGECOIN_API int dogecoin_psbt_blind(
    struct dogecoin_psbt *psbt,
    const struct dogecoin_map *values,
    const struct dogecoin_map *vbfs,
    const struct dogecoin_map *assets,
    const struct dogecoin_map *abfs,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t output_index,
    uint32_t flags,
    struct dogecoin_map *output);

/**
 * Blind a PSBT.
 *
 * As per `dogecoin_psbt_blind`, but allocates the ``output`` map.
 */
LIBDOGECOIN_API int dogecoin_psbt_blind_alloc(
    struct dogecoin_psbt *psbt,
    const struct dogecoin_map *values,
    const struct dogecoin_map *vbfs,
    const struct dogecoin_map *assets,
    const struct dogecoin_map *abfs,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t output_index,
    uint32_t flags,
    struct dogecoin_map **output);

/**
 * Sign PSBT inputs corresponding to a given private key.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param key: Private key to sign PSBT with.
 * :param key_len: Length of ``key`` in bytes. Must be `EC_PRIVATE_KEY_LEN`.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the signing algorithm.
 */
LIBDOGECOIN_API int dogecoin_psbt_sign(
    struct dogecoin_psbt *psbt,
    const unsigned char *key,
    size_t key_len,
    uint32_t flags);

/**
 * Sign PSBT inputs corresponding to a given BIP32 parent key.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param hdkey: The parent extended key to derive signing keys from.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the signing algorithm.
 */
LIBDOGECOIN_API int dogecoin_psbt_sign_bip32(
    struct dogecoin_psbt *psbt,
    const struct ext_key *hdkey,
    uint32_t flags);

/**
 * Sign a single PSBT input with a given BIP32 key.
 *
 * :param psbt: PSBT containing the input to sign. Directly modifies this PSBT.
 * :param index: The zero-based index of the input in the PSBT.
 * :param subindex: The zero-based index of the keypath to start searching from.
 * :param txhash: The signature hash to sign, from `dogecoin_psbt_get_input_signature_hash`.
 * :param txhash_len: Size of ``txhash`` in bytes. Must be `DOGECOIN_TXHASH_LEN`.
 * :param hdkey: The derived extended key to sign with.
 * :param flags: Flags controlling signing. Must be 0 or EC_FLAG_GRIND_R.
 */
LIBDOGECOIN_API int dogecoin_psbt_sign_input_bip32(
    struct dogecoin_psbt *psbt,
    size_t index,
    size_t subindex,
    const unsigned char *txhash,
    size_t txhash_len,
    const struct ext_key *hdkey,
    uint32_t flags);

/**
 * Finalize a PSBT.
 *
 * :param psbt: PSBT to finalize. Directly modifies this PSBT.
 * :param flags: Flags controlling finalization. Must be 0 or `DOGECOIN_PSBT_FINALIZE_NO_CLEAR`.
 *
 * .. note:: This call does not return an error if no finalization is
 * performed. Use `dogecoin_psbt_is_finalized` or `dogecoin_psbt_input_is_finalized`
 * to determine the finalization status after calling.
 */
LIBDOGECOIN_API int dogecoin_psbt_finalize(
    struct dogecoin_psbt *psbt,
    uint32_t flags);

/**
 * Finalize a PSBT input.
 *
 * :param psbt: PSBT whose input to finalize. Directly modifies this PSBT.
 * :param index: The zero-based index of the input in the PSBT to finalize.
 * :param flags: Flags controlling finalization. Must be 0 or `DOGECOIN_PSBT_FINALIZE_NO_CLEAR`.
 *
 * .. note:: This call does not return an error if no finalization is
 * performed. Use `dogecoin_psbt_is_finalized` or `dogecoin_psbt_input_is_finalized`
 * to determine the finalization status after calling.
 */
LIBDOGECOIN_API int dogecoin_psbt_finalize_input(
    struct dogecoin_psbt *psbt,
    size_t index,
    uint32_t flags);

/**
 * Extract a network transaction from a finalized PSBT.
 *
 * :param psbt: PSBT to extract from.
 * :param flags: Flags controlling signing. Must be 0 or `DOGECOIN_PSBT_EXTRACT_NON_FINAL`.
 * :param output: Destination for the resulting transaction.
 */
LIBDOGECOIN_API int dogecoin_psbt_extract(
    const struct dogecoin_psbt *psbt,
    uint32_t flags,
    struct libdogecoin_tx **output);

/**
 * Determine if a PSBT is an elements PSBT.
 *
 * :param psbt: The PSBT to check.
 * :param written: 1 if the PSBT is an elements PSBT, otherwise 0.
 */
LIBDOGECOIN_API int dogecoin_psbt_is_elements(
    const struct dogecoin_psbt *psbt,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* __LIBDOGECOIN_PSBT_H__ */
