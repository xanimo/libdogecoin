#ifndef __LIBDOGECOIN_PSBT_MEMBERS_H__
#define __LIBDOGECOIN_PSBT_MEMBERS_H__ 1

/* Accessors for PSBT/PSET members */
#include <dogecoin/dogecoin.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT */

LIBDOGECOIN_API int dogecoin_psbt_get_global_tx_alloc(const struct dogecoin_psbt *psbt, struct dogecoin_tx **output);
LIBDOGECOIN_API int dogecoin_psbt_get_version(const struct dogecoin_psbt *psbt, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_num_inputs(const struct dogecoin_psbt *psbt, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_num_outputs(const struct dogecoin_psbt *psbt, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_fallback_locktime(const struct dogecoin_psbt *psbt, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_has_fallback_locktime(const struct dogecoin_psbt *psbt, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_tx_modifiable_flags(const struct dogecoin_psbt *psbt, size_t *written);

/* Inputs */
LIBDOGECOIN_API int dogecoin_psbt_get_input_utxo_alloc(const struct dogecoin_psbt *psbt, size_t index, struct dogecoin_tx **output);
LIBDOGECOIN_API int dogecoin_psbt_get_input_witness_utxo_alloc(const struct dogecoin_psbt *psbt, size_t index, struct dogecoin_tx_output **output);
/* Returns the witness UTXO if present, otherwise the correct output from the non-witness UTXO tx */
LIBDOGECOIN_API int dogecoin_psbt_get_input_best_utxo_alloc(const struct dogecoin_psbt *psbt, size_t index, struct dogecoin_tx_output **output);
LIBDOGECOIN_API int dogecoin_psbt_get_input_redeem_script(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_redeem_script_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_witness_script(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_witness_script_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_final_scriptsig(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_final_scriptsig_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_final_witness_alloc(const struct dogecoin_psbt *psbt, size_t index, struct dogecoin_tx_witness_stack **output);
LIBDOGECOIN_API int dogecoin_psbt_get_input_keypaths_size(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_find_input_keypath(const struct dogecoin_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_keypath(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_keypath_len(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_signatures_size(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_find_input_signature(const struct dogecoin_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_signature(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_signature_len(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_unknowns_size(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_find_input_unknown(const struct dogecoin_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_unknown(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_unknown_len(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_input_sighash(const struct dogecoin_psbt *psbt, size_t index, size_t *written);

/**
 * FIXED_SIZED_OUTPUT(len, bytes_out, DOGECOIN_TXHASH_LEN)
 */
LIBDOGECOIN_API int dogecoin_psbt_get_input_previous_txid(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len);

LIBDOGECOIN_API int dogecoin_psbt_get_input_output_index(const struct dogecoin_psbt *psbt, size_t index, uint32_t *value_out);
LIBDOGECOIN_API int dogecoin_psbt_get_input_sequence(const struct dogecoin_psbt *psbt, size_t index, uint32_t *value_out);
LIBDOGECOIN_API int dogecoin_psbt_get_input_required_locktime(const struct dogecoin_psbt *psbt, size_t index, uint32_t *value_out);
LIBDOGECOIN_API int dogecoin_psbt_get_input_required_lockheight(const struct dogecoin_psbt *psbt, size_t index, uint32_t *value_out);

LIBDOGECOIN_API int dogecoin_psbt_set_input_utxo(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_tx *utxo);
LIBDOGECOIN_API int dogecoin_psbt_set_input_witness_utxo(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_tx_output *witness_utxo);
LIBDOGECOIN_API int dogecoin_psbt_set_input_witness_utxo_from_tx(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_tx *utxo, uint32_t utxo_index);

LIBDOGECOIN_API int dogecoin_psbt_set_input_redeem_script(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_input_witness_script(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_input_final_scriptsig(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_input_final_witness(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_tx_witness_stack *final_witness);
LIBDOGECOIN_API int dogecoin_psbt_set_input_keypaths(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_map *map_in);
LIBDOGECOIN_API int dogecoin_psbt_set_input_signatures(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_map *map_in);
LIBDOGECOIN_API int dogecoin_psbt_add_input_signature(struct dogecoin_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len, const unsigned char *sig, size_t sig_len);
LIBDOGECOIN_API int dogecoin_psbt_set_input_unknowns(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_map *map_in);
LIBDOGECOIN_API int dogecoin_psbt_set_input_sighash(struct dogecoin_psbt *psbt, size_t index, uint32_t sighash);
LIBDOGECOIN_API int dogecoin_psbt_set_input_previous_txid(struct dogecoin_psbt *psbt, size_t index, const unsigned char *txhash, size_t txhash_len);
LIBDOGECOIN_API int dogecoin_psbt_set_input_output_index(struct dogecoin_psbt *psbt, size_t index, uint32_t output_index);
LIBDOGECOIN_API int dogecoin_psbt_set_input_sequence(struct dogecoin_psbt *psbt, size_t index, uint32_t sequence);
LIBDOGECOIN_API int dogecoin_psbt_clear_input_sequence(struct dogecoin_psbt *psbt, size_t index);
LIBDOGECOIN_API int dogecoin_psbt_set_input_required_locktime(struct dogecoin_psbt *psbt, size_t index, uint32_t locktime);
LIBDOGECOIN_API int dogecoin_psbt_clear_input_required_locktime(struct dogecoin_psbt *psbt, size_t index);
LIBDOGECOIN_API int dogecoin_psbt_has_input_required_locktime(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_set_input_required_lockheight(struct dogecoin_psbt *psbt, size_t index, uint32_t lockheight);
LIBDOGECOIN_API int dogecoin_psbt_clear_input_required_lockheight(struct dogecoin_psbt *psbt, size_t index);
LIBDOGECOIN_API int dogecoin_psbt_has_input_required_lockheight(const struct dogecoin_psbt *psbt, size_t index, size_t *written);

/* Outputs */
LIBDOGECOIN_API int dogecoin_psbt_get_output_redeem_script(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_redeem_script_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_witness_script(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_witness_script_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_keypaths_size(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_find_output_keypath(const struct dogecoin_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_keypath(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_keypath_len(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_unknowns_size(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_find_output_unknown(const struct dogecoin_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_unknown(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_unknown_len(const struct dogecoin_psbt *psbt, size_t index, size_t subindex, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_script(const struct dogecoin_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_script_len(const struct dogecoin_psbt *psbt, size_t index, size_t *written);
LIBDOGECOIN_API int dogecoin_psbt_get_output_amount(const struct dogecoin_psbt *psbt, size_t index, uint64_t *value_out);
LIBDOGECOIN_API int dogecoin_psbt_has_output_amount(const struct dogecoin_psbt *psbt, size_t index, size_t *written);

LIBDOGECOIN_API int dogecoin_psbt_set_output_redeem_script(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_output_witness_script(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_output_keypaths(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_map *map_in);
LIBDOGECOIN_API int dogecoin_psbt_set_output_unknowns(struct dogecoin_psbt *psbt, size_t index, const struct dogecoin_map *map_in);
LIBDOGECOIN_API int dogecoin_psbt_set_output_script(struct dogecoin_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
LIBDOGECOIN_API int dogecoin_psbt_set_output_amount(struct dogecoin_psbt *psbt, size_t index, uint64_t amount);
LIBDOGECOIN_API int dogecoin_psbt_clear_output_amount(struct dogecoin_psbt *psbt, size_t index);

#ifdef __cplusplus
}
#endif

#endif /* __LIBDOGECOIN_PSBT_MEMBERS_H__ */
