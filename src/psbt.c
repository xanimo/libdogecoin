#include <dogecoin/internal.h>

#include <dogecoin/script.h>
#include <dogecoin/psbt.h>
#include <dogecoin/psbt_members.h>

#include <limits.h>
#include <dogecoin/psbt_io.h>
#include <dogecoin/script_int.h>
#include <dogecoin/script.h>
#include <dogecoin/pullpush.h>

/* TODO:
 * - When setting utxo in an input via the psbt (in the SWIG
 *   case), check the txid matches the input (see is_matching_txid() call
 *   in the signing code).
 * - When signing, validate the existing signatures and refuse to sign if
 *   any are incorrect. This prevents others pretending to sign and then
 *   gaining our signature without having provided theirs.
 * - Signing of multisig inputs is not implemented.
 * - Change detection is not implemented, something like:
 *   dogecoin_psbt_is_related_output(psbt, index, ext_key, written) could
 *   identify whether the given output pays to an address from ext_key.
 * - (V2) If we support adding/moving PSBT inputs, check lock time consistency
 *   when we do so.
 */

/* All allowed flags for dogecoin_psbt_get_id() */
#define PSBT_ID_ALL_FLAGS (DOGECOIN_PSBT_ID_AS_V2 | DOGECOIN_PSBT_ID_USE_LOCKTIME)

/* All allowed flags for dogecoin_psbt_from_[bytes|base64]() */
#define PSBT_ALL_PARSE_FLAGS (DOGECOIN_PSBT_PARSE_FLAG_STRICT)

static const uint8_t PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};
static const uint8_t PSET_MAGIC[5] = {'p', 's', 'e', 't', 0xff};

#define MAX_INVALID_SATOSHI ((uint64_t) -1)
/* Note we mask given indices regardless of PSBT/PSET, since enormous
 * indices can never be valid on BTC either */
#define MASK_INDEX(index) ((index) & DOGECOIN_TX_INDEX_MASK)

#define TR_MAX_MERKLE_PATH_LEN 128u

static int tx_clone_alloc(const struct libdogecoin_tx *src, struct libdogecoin_tx **dst) {
    return libdogecoin_tx_clone_alloc(src, 0, dst);
}

static bool is_matching_txid(const struct libdogecoin_tx *tx,
                             const unsigned char *txid, size_t txid_len)
{
    unsigned char src_txid[DOGECOIN_TXHASH_LEN];
    bool ret;

    if (!tx || !txid || txid_len != DOGECOIN_TXHASH_LEN)
        return false;

    if (libdogecoin_tx_get_txid(tx, src_txid, sizeof(src_txid)) != DOGECOIN_OK)
        return false;

    ret = memcmp(src_txid, txid, txid_len) == 0;
    dogecoin_clear(src_txid, sizeof(src_txid));
    return ret;
}

static bool psbt_is_valid(const struct dogecoin_psbt *psbt)
{
    if (!psbt)
        return false;
    if (psbt->version == PSBT_0) {
        /* v0 may have a tx; number of PSBT in/outputs must match */
        if ((psbt->tx ? psbt->tx->num_inputs  : 0) != psbt->num_inputs ||
            (psbt->tx ? psbt->tx->num_outputs  : 0) != psbt->num_outputs)
            return false;
    } else {
        /* v2 must not have a tx */
        if (psbt->version != PSBT_2 || psbt->tx)
            return false;
    }
    return true;
}

static bool psbt_can_modify(const struct dogecoin_psbt *psbt, uint32_t flags)
{
    return psbt && (psbt->version == PSBT_0 || ((psbt->tx_modifiable_flags & flags) == flags));
}

#ifdef BUILD_ELEMENTS
static bool utxo_has_explicit_value(const struct libdogecoin_tx_output *utxo)
{
    return utxo && utxo->value && utxo->value_len && utxo->value[0] == 1u;
}

static bool utxo_has_explicit_asset(const struct libdogecoin_tx_output *utxo)
{
    return utxo && utxo->asset && utxo->asset_len && utxo->asset[0] == 1u;
}
#endif /* BUILD_ELEMENTS */

static struct dogecoin_psbt_input *psbt_get_input(const struct dogecoin_psbt *psbt, size_t index)
{
    if (!psbt || index >= psbt->num_inputs ||
        (psbt->version == PSBT_0 && (!psbt->tx || index >= psbt->tx->num_inputs)))
        return NULL;
    return &psbt->inputs[index];
 }

static struct dogecoin_psbt_output *psbt_get_output(const struct dogecoin_psbt *psbt, size_t index)
{
    if (!psbt || index >= psbt->num_outputs ||
        (psbt->version == PSBT_0 && (!psbt->tx || index >= psbt->tx->num_outputs)))
        return NULL;
    return &psbt->outputs[index];
}

static const struct libdogecoin_tx_output *utxo_from_input(const struct dogecoin_psbt *psbt,
                                                     const struct dogecoin_psbt_input *input)
{
    if (psbt && input) {
        if (input->witness_utxo)
            return input->witness_utxo;
        if (input->utxo) {
            if (psbt->version == PSBT_2 && input->index < input->utxo->num_outputs)
                return &input->utxo->outputs[input->index];
            if (psbt->tx && psbt->num_inputs == psbt->tx->num_inputs) {
                /* Get the UTXO output index from the global tx */
                size_t input_index = input - psbt->inputs;
                size_t output_index = psbt->tx->inputs[input_index].index;
                if (output_index < input->utxo->num_outputs)
                    return &input->utxo->outputs[output_index];
            }
        }
    }
    return NULL;
}

/* Set a struct member on a parent struct */
#define SET_STRUCT(PARENT, NAME, STRUCT_TYPE, CLONE_FN, FREE_FN) \
    int PARENT ## _set_ ## NAME(struct PARENT *parent, const struct STRUCT_TYPE *p) { \
        int ret = DOGECOIN_OK; \
        struct STRUCT_TYPE *new_p = NULL; \
        if (!parent) return DOGECOIN_EINVAL; \
        if (p && (ret = CLONE_FN(p, &new_p)) != DOGECOIN_OK) return ret; \
        FREE_FN(parent->NAME); \
        parent->NAME = new_p; \
        return ret; \
    }

/* Set/find in and add a map value member on a parent struct */
#define SET_MAP(PARENT, NAME, ADD_POST) \
    int PARENT ## _set_ ## NAME ## s(struct PARENT *parent, const struct dogecoin_map *map_in) { \
        if (!parent) return DOGECOIN_EINVAL; \
        return dogecoin_map_assign(&parent->NAME ## s, map_in); \
    } \
    int PARENT ## _find_ ## NAME(struct PARENT *parent, \
                                 const unsigned char *key, size_t key_len, \
                                 size_t *written) { \
        if (written) *written = 0; \
        if (!parent) return DOGECOIN_EINVAL; \
        return dogecoin_map_find(&parent->NAME ## s, key, key_len, written); \
    } \
    int PARENT ## _add_ ## NAME ## ADD_POST(struct PARENT *parent, \
                                            const unsigned char *key, size_t key_len, \
                                            const unsigned char *value, size_t value_len) { \
        if (!parent) return DOGECOIN_EINVAL; \
        return dogecoin_map_add(&parent->NAME ## s, key, key_len, value, value_len); \
    }

/* Add a keypath to parent structs keypaths member */
#define ADD_KEYPATH(PARENT) \
    int PARENT ## _keypath_add(struct PARENT *parent, \
                               const unsigned char *pub_key, size_t pub_key_len, \
                               const unsigned char *fingerprint, size_t fingerprint_len, \
                               const uint32_t *child_path, size_t child_path_len) { \
        if (!parent) return DOGECOIN_EINVAL; \
        return dogecoin_map_keypath_add(&parent->keypaths, pub_key, pub_key_len, \
                                     fingerprint, fingerprint_len, \
                                     child_path, child_path_len); \
    }

static int map_field_get_len(const struct dogecoin_map *map_in,
                             uint32_t type, size_t *written)
{
    size_t index;
    int ret;

    if (written)
        *written = 0;
    if (!map_in || !written)
        return DOGECOIN_EINVAL;
    ret = dogecoin_map_find_integer(map_in, type, &index);
    if (ret == DOGECOIN_OK && index)
        *written = map_in->items[index - 1].value_len; /* Found */
    return ret;
}

static int map_field_get(const struct dogecoin_map *map_in, uint32_t type,
                         unsigned char *bytes_out, size_t len,
                         size_t *written)
{
    size_t index;
    int ret;

    if (written)
        *written = 0;
    if (!map_in || !bytes_out || !written)
        return DOGECOIN_EINVAL;
    ret = dogecoin_map_find_integer(map_in, type, &index);
    if (ret == DOGECOIN_OK && index) {
        /* Found */
        const struct dogecoin_map_item *item = map_in->items + index - 1;
        *written = item->value_len;
        if (len >= item->value_len)
            memcpy(bytes_out, item->value, item->value_len);
    }
    return ret;
}

static int map_field_set(struct dogecoin_map *map_in, uint32_t type,
                         const unsigned char *val, size_t val_len)
{
    if (!map_in || BYTES_INVALID(val, val_len))
        return DOGECOIN_EINVAL;

    if (!val)
        return dogecoin_map_remove_integer(map_in, type);
    return dogecoin_map_replace_integer(map_in, type, val, val_len);
}

/* Methods for a binary buffer field from a PSET input/output */
#define MAP_INNER_FIELD(typ, name, FT, mapname) \
    int dogecoin_psbt_ ## typ ## _get_ ## name ## _len(const struct dogecoin_psbt_ ## typ *p, \
                                                    size_t * written) { \
        return map_field_get_len(p ? &p->mapname : NULL, FT, written); \
    } \
    int dogecoin_psbt_ ## typ ## _get_ ## name(const struct dogecoin_psbt_ ## typ *p, \
                                            unsigned char *bytes_out, size_t len, size_t * written) { \
        return map_field_get(p ? &p->mapname : NULL, FT, bytes_out, len, written); \
    } \
    int dogecoin_psbt_ ## typ ## _clear_ ## name(struct dogecoin_psbt_ ## typ *p) { \
        return dogecoin_map_remove_integer(p ? &p->mapname : NULL, FT); \
    } \
    int dogecoin_psbt_ ## typ ## _set_ ## name(struct dogecoin_psbt_ ## typ *p, \
                                            const unsigned char *value, size_t value_len) { \
        return map_field_set(p ? &p->mapname : NULL, FT, value, value_len); \
    }

int dogecoin_psbt_input_is_finalized(const struct dogecoin_psbt_input *input,
                                  size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !written)
        return DOGECOIN_EINVAL;
    if (input->final_witness ||
        dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
        *written = 1;
    return DOGECOIN_OK;
}

SET_STRUCT(dogecoin_psbt_input, utxo, libdogecoin_tx,
           tx_clone_alloc, libdogecoin_tx_free)
int dogecoin_psbt_input_set_witness_utxo(struct dogecoin_psbt_input *input, const struct libdogecoin_tx_output *utxo)
{
    int ret = DOGECOIN_OK;
    struct libdogecoin_tx_output *new_utxo = NULL;
    if (!input)
        return DOGECOIN_EINVAL;
    if (utxo && (ret = libdogecoin_tx_output_clone_alloc(utxo, &new_utxo)) != DOGECOIN_OK)
        return ret;
    libdogecoin_tx_output_free(input->witness_utxo);
    input->witness_utxo = new_utxo;
    return ret;
}

int dogecoin_psbt_input_set_witness_utxo_from_tx(struct dogecoin_psbt_input *input,
                                              const struct libdogecoin_tx *utxo, uint32_t index)
{
    if (!utxo || index >= utxo->num_outputs)
        return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_set_witness_utxo(input, utxo->outputs + index);
}
MAP_INNER_FIELD(input, redeem_script, PSBT_IN_REDEEM_SCRIPT, psbt_fields)
MAP_INNER_FIELD(input, witness_script, PSBT_IN_WITNESS_SCRIPT, psbt_fields)
MAP_INNER_FIELD(input, final_scriptsig, PSBT_IN_FINAL_SCRIPTSIG, psbt_fields)
SET_STRUCT(dogecoin_psbt_input, final_witness, libdogecoin_tx_witness_stack,
           libdogecoin_tx_witness_stack_clone_alloc, libdogecoin_tx_witness_stack_free)
SET_MAP(dogecoin_psbt_input, keypath,)
ADD_KEYPATH(dogecoin_psbt_input)
SET_MAP(dogecoin_psbt_input, signature, _internal)
int dogecoin_psbt_input_add_signature(struct dogecoin_psbt_input *input,
                                   const unsigned char *pub_key, size_t pub_key_len,
                                   const unsigned char *sig, size_t sig_len)
{
    if (input && sig && sig_len) {
        const unsigned char sighash = sig[sig_len - 1];
        if (!sighash || (input->sighash && input->sighash != sighash))
            return DOGECOIN_EINVAL; /* Incompatible sighash */
    }
    return dogecoin_psbt_input_add_signature_internal(input, pub_key, pub_key_len,
                                                   sig, sig_len);
}
SET_MAP(dogecoin_psbt_input, unknown,)
int dogecoin_psbt_input_set_previous_txid(struct dogecoin_psbt_input *input,
                                       const unsigned char *txhash, size_t len)
{
    if (!input || BYTES_INVALID_N(txhash, len, DOGECOIN_TXHASH_LEN))
        return DOGECOIN_EINVAL;
    if (len)
        memcpy(input->txhash, txhash, DOGECOIN_TXHASH_LEN);
    else
        dogecoin_clear(input->txhash, DOGECOIN_TXHASH_LEN);
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_set_sighash(struct dogecoin_psbt_input *input, uint32_t sighash)
{
    size_t i;

    if (!input)
        return DOGECOIN_EINVAL;
    /* Note we do not skip this check if sighash == input->sighash.
     * This is because we set the loaded value again after reading a PSBT
     * input, in order to ensure the loaded signatures are compatible with
     * it (since they can be read in any order).
     */
    if (sighash) {
        for (i = 0; i < input->signatures.num_items; ++i) {
            const struct dogecoin_map_item *item = &input->signatures.items[i];
            if (!item->value || !item->value_len ||
                sighash != item->value[item->value_len - 1]) {
                /* Cannot set a sighash that is incompatible with existing sigs */
                return DOGECOIN_EINVAL;
            }
        }
    }
    input->sighash = sighash;
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_set_output_index(struct dogecoin_psbt_input *input, uint32_t index)
{
    if (!input)
        return DOGECOIN_EINVAL;
    /* The PSBT index ignores any elements issuance/pegin flags */
    input->index = MASK_INDEX(index);
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_set_sequence(struct dogecoin_psbt_input *input, uint32_t sequence)
{
    if (!input)
        return DOGECOIN_EINVAL;
    input->sequence = sequence;
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_clear_sequence(struct dogecoin_psbt_input *input)
{
    return dogecoin_psbt_input_set_sequence(input, DOGECOIN_TX_SEQUENCE_FINAL);
}

int dogecoin_psbt_input_set_required_locktime(struct dogecoin_psbt_input *input, uint32_t locktime)
{
    if (!input || !locktime || locktime < PSBT_LOCKTIME_MIN_TIMESTAMP)
        return DOGECOIN_EINVAL;
    input->required_locktime = locktime;
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_clear_required_locktime(struct dogecoin_psbt_input *input)
{
    if (!input)
        return DOGECOIN_EINVAL;
    input->required_locktime = 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_set_required_lockheight(struct dogecoin_psbt_input *input, uint32_t lockheight)
{
    if (!input || !lockheight || lockheight >= PSBT_LOCKTIME_MIN_TIMESTAMP)
        return DOGECOIN_EINVAL;
    input->required_lockheight = lockheight;
    return DOGECOIN_OK;
}

int dogecoin_psbt_input_clear_required_lockheight(struct dogecoin_psbt_input *input)
{
    if (!input)
        return DOGECOIN_EINVAL;
    input->required_lockheight = 0;
    return DOGECOIN_OK;
}

/* Verify a DER encoded ECDSA sig plus sighash byte */
static int der_sig_verify(const unsigned char *der, size_t der_len)
{
    unsigned char sig[EC_SIGNATURE_LEN];
    if (der_len)
        return dogecoin_ec_sig_from_der(der, der_len - 1, sig, sizeof(sig));
    return DOGECOIN_EINVAL;
}

static int pubkey_sig_verify(const unsigned char *key, size_t key_len,
                             const unsigned char *val, size_t val_len)
{
    int ret = dogecoin_ec_public_key_verify(key, key_len);
    if (ret == DOGECOIN_OK)
        ret = der_sig_verify(val, val_len);
    return ret;
}

static int map_leaf_hashes_verify(const unsigned char *key, size_t key_len,
                                  const unsigned char *val, size_t val_len)
{
    int ret = dogecoin_ec_xonly_public_key_verify(key, key_len);
    if (ret == DOGECOIN_OK) {
        if (BYTES_INVALID(val, val_len) || (val_len && val_len % SHA256_LEN) ||
            val_len > TR_MAX_MERKLE_PATH_LEN * SHA256_LEN)
            ret = DOGECOIN_EINVAL;
    }
    return ret;
}

static int psbt_input_field_verify(uint32_t field_type,
                                   const unsigned char *val, size_t val_len)
{
    if (val) {
        switch (field_type) {
        case PSBT_IN_REDEEM_SCRIPT:
        case PSBT_IN_WITNESS_SCRIPT:
        case PSBT_IN_FINAL_SCRIPTSIG:
        case PSBT_IN_POR_COMMITMENT:
            /* Scripts, or UTF-8 proof of reserves message */
            return val_len ? DOGECOIN_OK : DOGECOIN_EINVAL;
        case PSBT_IN_TAP_KEY_SIG:
            /* 64 or 65 byte Schnorr signature TODO: Add constants */
            return val_len == 64 || val_len == 65 ? DOGECOIN_OK : DOGECOIN_EINVAL;
        case PSBT_IN_TAP_INTERNAL_KEY:
        case PSBT_IN_TAP_MERKLE_ROOT:
            /* 32 byte x-only pubkey, or 32 byte merkle hash */
            return val_len == SHA256_LEN ? DOGECOIN_OK : DOGECOIN_EINVAL;
        default:
            break;
        }
    }
    return DOGECOIN_EINVAL;
}

static int psbt_map_input_field_verify(const unsigned char *key, size_t key_len,
                                       const unsigned char *val, size_t val_len)
{
    return key ? DOGECOIN_EINVAL : psbt_input_field_verify(key_len, val, val_len);
}

static int psbt_output_field_verify(uint32_t field_type,
                                    const unsigned char *val, size_t val_len)
{
    switch (field_type) {
    case PSBT_OUT_REDEEM_SCRIPT:
    case PSBT_OUT_WITNESS_SCRIPT:
        /* Scripts */
        return val_len ? DOGECOIN_OK : DOGECOIN_EINVAL;
    case PSBT_OUT_TAP_INTERNAL_KEY:
        /* 32 byte x-only pubkey */
        return val && val_len == SHA256_LEN ? DOGECOIN_OK : DOGECOIN_EINVAL;
    case PSBT_OUT_TAP_TREE:
        /* FIXME: validate the tree is in the expected encoded format */
        return val && val_len >= 4 ? DOGECOIN_OK : DOGECOIN_EINVAL;
    default:
        break;
    }
    return DOGECOIN_EINVAL;
}

static int psbt_map_output_field_verify(const unsigned char *key, size_t key_len,
                                        const unsigned char *val, size_t val_len)
{
    return key ? DOGECOIN_EINVAL : psbt_output_field_verify(key_len, val, val_len);
}

static void psbt_input_init(struct dogecoin_psbt_input *input)
{
    dogecoin_clear(input, sizeof(*input));
    dogecoin_map_init(0, dogecoin_keypath_public_key_verify, &input->keypaths);
    dogecoin_map_init(0, pubkey_sig_verify, &input->signatures);
    dogecoin_map_init(0, NULL, &input->unknowns);
    dogecoin_map_init(0, dogecoin_map_hash_preimage_verify, &input->preimages);
    dogecoin_map_init(0, psbt_map_input_field_verify, &input->psbt_fields);
    dogecoin_map_init(0, NULL /* FIXME */, &input->taproot_leaf_signatures);
    dogecoin_map_init(0, NULL /* FIXME */, &input->taproot_leaf_scripts);
    dogecoin_map_init(0, map_leaf_hashes_verify, &input->taproot_leaf_hashes);
    dogecoin_map_init(0, dogecoin_keypath_xonly_public_key_verify, &input->taproot_leaf_paths);
}

static int psbt_input_free(struct dogecoin_psbt_input *input, bool free_parent)
{
    if (input) {
        libdogecoin_tx_free(input->utxo);
        libdogecoin_tx_output_free(input->witness_utxo);
        libdogecoin_tx_witness_stack_free(input->final_witness);
        dogecoin_map_clear(&input->keypaths);
        dogecoin_map_clear(&input->signatures);
        dogecoin_map_clear(&input->unknowns);
        dogecoin_map_clear(&input->preimages);
        dogecoin_map_clear(&input->psbt_fields);
        dogecoin_map_clear(&input->taproot_leaf_signatures);
        dogecoin_map_clear(&input->taproot_leaf_scripts);
        dogecoin_map_clear(&input->taproot_leaf_hashes);
        dogecoin_map_clear(&input->taproot_leaf_paths);

        dogecoin_clear(input, sizeof(*input));
        if (free_parent)
            dogecoin_free(input);
    }
    return DOGECOIN_OK;
}

MAP_INNER_FIELD(output, redeem_script, PSBT_OUT_REDEEM_SCRIPT, psbt_fields)
MAP_INNER_FIELD(output, witness_script, PSBT_OUT_WITNESS_SCRIPT, psbt_fields)
SET_MAP(dogecoin_psbt_output, keypath,)
ADD_KEYPATH(dogecoin_psbt_output)
SET_MAP(dogecoin_psbt_output, unknown,)

int dogecoin_psbt_output_set_amount(struct dogecoin_psbt_output *output, uint64_t amount)
{
    if (!output)
        return DOGECOIN_EINVAL;
    output->amount = amount;
    output->has_amount = 1u;
    return DOGECOIN_OK;
}

int dogecoin_psbt_output_clear_amount(struct dogecoin_psbt_output *output)
{
    if (!output)
        return DOGECOIN_EINVAL;
    output->amount = 0;
    output->has_amount = 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_output_set_script(struct dogecoin_psbt_output *output,
                                 const unsigned char *bytes, size_t len)
{
    if (!output)
        return DOGECOIN_EINVAL;
    return replace_bytes(bytes, len, &output->script, &output->script_len);
}


#ifdef BUILD_ELEMENTS
int dogecoin_psbt_output_set_blinder_index(struct dogecoin_psbt_output *output, uint32_t index)
{
    if (!output)
        return DOGECOIN_EINVAL;
    output->blinder_index = index;
    output->has_blinder_index = 1u;
    return DOGECOIN_OK;
}

int dogecoin_psbt_output_clear_blinder_index(struct dogecoin_psbt_output *output)
{
    if (!output)
        return DOGECOIN_EINVAL;
    output->blinder_index = 0;
    output->has_blinder_index = 0;
    return DOGECOIN_OK;
}

MAP_INNER_FIELD(output, value_commitment, PSET_OUT_VALUE_COMMITMENT, pset_fields)
MAP_INNER_FIELD(output, asset, PSET_OUT_ASSET, pset_fields)
MAP_INNER_FIELD(output, asset_commitment, PSET_OUT_ASSET_COMMITMENT, pset_fields)
MAP_INNER_FIELD(output, value_rangeproof, PSET_OUT_VALUE_RANGEPROOF, pset_fields)
MAP_INNER_FIELD(output, asset_surjectionproof, PSET_OUT_ASSET_SURJECTION_PROOF, pset_fields)
MAP_INNER_FIELD(output, blinding_public_key, PSET_OUT_BLINDING_PUBKEY, pset_fields)
MAP_INNER_FIELD(output, ecdh_public_key, PSET_OUT_ECDH_PUBKEY, pset_fields)
MAP_INNER_FIELD(output, value_blinding_rangeproof, PSET_OUT_BLIND_VALUE_PROOF, pset_fields)
MAP_INNER_FIELD(output, asset_blinding_surjectionproof, PSET_OUT_BLIND_ASSET_PROOF, pset_fields)

static int psbt_output_get_blinding_state(const struct dogecoin_psbt_output *output, uint64_t *written)
{
    const struct dogecoin_map_item *p;
    uint32_t ft;

    *written = 0;
    for (ft = PSET_OUT_VALUE_COMMITMENT; ft <= PSET_OUT_ECDH_PUBKEY; ++ft) {
        if (PSET_OUT_BLINDING_FIELDS & PSET_FT(ft)) {
            if ((p = dogecoin_map_get_integer(&output->pset_fields, ft))) {
                *written |= PSET_FT(ft);
                if ((ft == PSET_OUT_BLINDING_PUBKEY || ft == PSET_OUT_ECDH_PUBKEY) &&
                    dogecoin_ec_public_key_verify(p->value, p->value_len) != DOGECOIN_OK)
                    return DOGECOIN_ERROR; /* Invalid */
            }
        }
    }
    return DOGECOIN_OK;
}

int dogecoin_psbt_output_get_blinding_status(const struct dogecoin_psbt_output *output,
                                          uint32_t flags, size_t *written)
{
    uint64_t state;

    if (written)
        *written = DOGECOIN_PSET_BLINDED_NONE;
    if (!output || flags || !written)
        return DOGECOIN_EINVAL;

    if (psbt_output_get_blinding_state(output, &state) != DOGECOIN_OK)
        return DOGECOIN_ERROR;

    if (PSET_BLINDING_STATE_REQUIRED(state)) {
        if (PSET_BLINDING_STATE_FULL(state))
            *written = DOGECOIN_PSET_BLINDED_FULL;
        else if (PSET_BLINDING_STATE_PARTIAL(state))
            *written = DOGECOIN_PSET_BLINDED_PARTIAL;
        else
            *written = DOGECOIN_PSET_BLINDED_REQUIRED;
    }
    return DOGECOIN_OK;
}

/* Verify that unblinded values, their commitment, and commitment proof
 * are provided/elided where required, and proofs are valid if provided.
 */
static bool pset_check_proof(const struct dogecoin_psbt *psbt,
                             const struct dogecoin_psbt_input *in,
                             const struct dogecoin_psbt_output *out,
                             uint64_t value_bit,
                             uint64_t commitment_key, uint64_t proof_key, uint32_t flags)
{
    const bool is_mandatory = !!out; /* Both output commitments/values are mandatory */
    const bool is_utxo_value = in && (value_bit == PSET_FT(PSET_IN_EXPLICIT_VALUE));
    const bool is_utxo_asset = in && (value_bit == PSET_FT(PSET_IN_EXPLICIT_ASSET));
    const struct dogecoin_map *pset_fields = out ? &out->pset_fields : &in->pset_fields;
    const struct dogecoin_map_item *item, *proof;
    struct dogecoin_map_item commitment, asset;
    uint64_t value = 0;
    bool has_value = false, has_explicit = false, do_verify = true;;
    int ret;

    dogecoin_clear(&commitment, sizeof(commitment));
    dogecoin_clear(&asset, sizeof(asset));

    /* Get the explicit proof, if any */
    proof = dogecoin_map_get_integer(pset_fields, proof_key);

    /* Get the unblinded asset or value and its commitment, if any.
     * For value rangeproofs, also get the asset commitment: 'asset' is
     * - The unblinded asset value for asset surjection proofs, or
     * - The asset commitment, for value rangeproofs.
     */
    if (is_utxo_value || is_utxo_asset) {
        /* Get explicit value and commitments from the inputs UTXO */
        const struct libdogecoin_tx_output *utxo = utxo_from_input(psbt, in);
        has_value = is_utxo_value && in->has_amount;
        value = in->amount;
        if (utxo) {
            if (is_utxo_value) {
                commitment.value = utxo->value;
                commitment.value_len = utxo->value_len;
                asset.value = utxo->asset;
                asset.value_len = utxo->asset_len;
                has_explicit = has_value;
            } else {
                commitment.value = utxo->asset;
                commitment.value_len = utxo->asset_len;
                if ((item = dogecoin_map_get_integer(pset_fields, PSET_IN_EXPLICIT_ASSET)) != NULL) {
                    memcpy(&asset, item, sizeof(asset));
                    has_explicit = true;
                }
            }
        }
    } else {
        /* Get commitment from the PSET fields map */
        if ((item = dogecoin_map_get_integer(pset_fields, commitment_key)) != NULL)
            memcpy(&commitment, item, sizeof(commitment));

        if (in) {
            /* Input issuance/re-issuance proofs */
            if (value_bit == PSET_FT(PSET_IN_ISSUANCE_VALUE))
                value = in->issuance_amount;
            else
                value = in->inflation_keys; /* PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT) */
            has_value = value != 0;
            has_explicit = has_value;
            /* FIXME: Elements doesn't currently ever generate or validate issuance
             *        proofs; its not immediately clear what the asset commitment
             *        should be for the rangeproof either */
            do_verify = false;
        } else {
            /* Output value/asset proofs */
            if (value_bit == PSBT_FT(PSBT_OUT_AMOUNT)) {
                value = out->amount;
                has_value = out->has_amount;
                has_explicit = has_value;
                if ((item = dogecoin_map_get_integer(pset_fields, PSET_OUT_ASSET_COMMITMENT)) != NULL)
                    memcpy(&asset, item, sizeof(asset));
            } else {
                /* PSET_FT(PSET_OUT_ASSET) */
                if ((item = dogecoin_map_get_integer(pset_fields, PSET_OUT_ASSET)) != NULL) {
                    memcpy(&asset, item, sizeof(asset));
                    has_explicit = true;
                }
            }
        }
    }

    if (proof && !commitment.value)
        return false; /* Proof without commitment value */
    if (commitment.value) {
        if (!has_explicit)
            return true; /* Explicit value has been removed, nothing to prove */
        if (!proof && (flags & DOGECOIN_PSBT_PARSE_FLAG_STRICT))
            return false; /* value and commitment without range/surjection proof */
    } else if (!has_explicit && is_mandatory) {
        /* No value, commitment or proof for a mandatory field - invalid */
        return false;
    }

    if (!proof || !commitment.value || !has_explicit)
        return true; /* Nothing to validate */

    /* Validate the proof */
    if (has_value) {
        if (!do_verify) {
            ret = DOGECOIN_OK;
        } else if (!asset.value || !asset.value_len) {
            /* For value rangeproofs, the asset commitment is mandatory
             * to allow verification, although the PSET spec misses this */
            ret = DOGECOIN_EINVAL;
        } else
            ret = dogecoin_explicit_rangeproof_verify(proof->value, proof->value_len, value,
                                                   commitment.value, commitment.value_len,
                                                   asset.value, asset.value_len);
    } else {
        ret = dogecoin_explicit_surjectionproof_verify(proof->value, proof->value_len,
                                                    asset.value, asset.value_len,
                                                    commitment.value, commitment.value_len);
    }
    return ret == DOGECOIN_OK;
}
#endif /* BUILD_ELEMENTS */

static void psbt_output_init(struct dogecoin_psbt_output *output)
{
    dogecoin_clear(output, sizeof(*output));
    dogecoin_map_init(0, dogecoin_keypath_public_key_verify, &output->keypaths);
    dogecoin_map_init(0, NULL, &output->unknowns);
    dogecoin_map_init(0, psbt_map_output_field_verify, &output->psbt_fields);
    dogecoin_map_init(0, NULL, &output->taproot_tree);
    dogecoin_map_init(0, map_leaf_hashes_verify, &output->taproot_leaf_hashes);
    dogecoin_map_init(0, dogecoin_keypath_xonly_public_key_verify, &output->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
    dogecoin_map_init(0, pset_map_output_field_verify, &output->pset_fields);
#endif /* BUILD_ELEMENTS */
}

static int psbt_output_free(struct dogecoin_psbt_output *output, bool free_parent)
{
    if (output) {
        dogecoin_map_clear(&output->keypaths);
        dogecoin_map_clear(&output->unknowns);
        clear_and_free(output->script, output->script_len);
        dogecoin_map_clear(&output->psbt_fields);
        dogecoin_map_clear(&output->taproot_tree);
        dogecoin_map_clear(&output->taproot_leaf_hashes);
        dogecoin_map_clear(&output->taproot_leaf_paths);
#ifdef BUILD_ELEMENTS
        dogecoin_map_clear(&output->pset_fields);
#endif /* BUILD_ELEMENTS */

        dogecoin_clear(output, sizeof(*output));
        if (free_parent)
            dogecoin_free(output);
    }
    return DOGECOIN_OK;
}

static int dogecoin_psbt_init(uint32_t version, size_t num_inputs, size_t num_outputs,
                           size_t num_unknowns, uint32_t flags,
                           struct dogecoin_psbt *psbt_out)
{
    int ret;

    if (psbt_out)
        dogecoin_clear(psbt_out, sizeof(*psbt_out));
    if ((version != PSBT_0 && version != PSBT_2) || !psbt_out)
        return DOGECOIN_EINVAL; /* Only v0/v2 are specified/supported */
#ifdef BUILD_ELEMENTS
    if (flags & ~DOGECOIN_PSBT_INIT_PSET ||
        (flags & DOGECOIN_PSBT_INIT_PSET && version != PSBT_2))
        return DOGECOIN_EINVAL;
#else
    if (flags)
        return DOGECOIN_EINVAL;
#endif /* BUILD_ELEMENTS */

    if (num_inputs)
        psbt_out->inputs = libdogecoin_calloc(num_inputs * sizeof(struct dogecoin_psbt_input));
    if (num_outputs)
        psbt_out->outputs = libdogecoin_calloc(num_outputs * sizeof(struct dogecoin_psbt_output));

    ret = dogecoin_map_init(num_unknowns, NULL, &psbt_out->unknowns);
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_init(0, dogecoin_keypath_bip32_verify, &psbt_out->global_xpubs);
#ifdef BUILD_ELEMENTS
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_init(0, scalar_verify, &psbt_out->global_scalars);
#endif /* BUILD_ELEMENTS */

    if (ret != DOGECOIN_OK ||
        (num_inputs && !psbt_out->inputs) ||
        (num_outputs && !psbt_out->outputs)) {
        dogecoin_free(psbt_out->inputs);
        dogecoin_free(psbt_out->outputs);
        dogecoin_map_clear(&psbt_out->unknowns);
        dogecoin_clear(psbt_out, sizeof(psbt_out));
        return ret != DOGECOIN_OK ? ret : DOGECOIN_ENOMEM;
    }

    psbt_out->version = version;
    psbt_out->tx_version = 2u; /* Minimum tx version is 2 */
    /* Both inputs and outputs can be added to a newly created PSBT */
    psbt_out->tx_modifiable_flags = DOGECOIN_PSBT_TXMOD_INPUTS | DOGECOIN_PSBT_TXMOD_OUTPUTS;

#ifdef BUILD_ELEMENTS
    if (flags & DOGECOIN_PSBT_INIT_PSET)
        memcpy(psbt_out->magic, PSET_MAGIC, sizeof(PSET_MAGIC));
    else
#endif /* BUILD_ELEMENTS */
    memcpy(psbt_out->magic, PSBT_MAGIC, sizeof(PSBT_MAGIC));
    psbt_out->inputs_allocation_len = num_inputs;
    psbt_out->outputs_allocation_len = num_outputs;
    psbt_out->tx = NULL;
    return DOGECOIN_OK;
}

int dogecoin_psbt_init_alloc(uint32_t version, size_t num_inputs, size_t num_outputs,
                          size_t num_unknowns, uint32_t flags, struct dogecoin_psbt **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct dogecoin_psbt);
    ret = dogecoin_psbt_init(version, num_inputs, num_outputs, num_unknowns, flags, *output);
    if (ret != DOGECOIN_OK) {
        dogecoin_free(*output);
        *output = NULL;
    }
    return ret;
}

static void psbt_claim_allocated_inputs(struct dogecoin_psbt *psbt, size_t num_inputs, size_t num_outputs)
{
    size_t i;

    /* Requires num_inputs/outputs are <= the allocated lengths */
    psbt->num_inputs = num_inputs;
    for (i = 0; i < num_inputs; i++) {
        psbt_input_init(psbt->inputs + i);
        psbt->inputs[i].sequence = DOGECOIN_TX_SEQUENCE_FINAL;
    }
    psbt->num_outputs = num_outputs;
    for (i = 0; i < num_outputs; i++)
        psbt_output_init(psbt->outputs + i);
}

int dogecoin_psbt_free(struct dogecoin_psbt *psbt)
{
    size_t i;
    if (psbt) {
        libdogecoin_tx_free(psbt->tx);
        for (i = 0; i < psbt->num_inputs; ++i)
            psbt_input_free(&psbt->inputs[i], false);

        dogecoin_free(psbt->inputs);
        for (i = 0; i < psbt->num_outputs; ++i)
            psbt_output_free(&psbt->outputs[i], false);

        dogecoin_free(psbt->outputs);
        dogecoin_map_clear(&psbt->unknowns);
        dogecoin_map_clear(&psbt->global_xpubs);
#ifdef BUILD_ELEMENTS
        dogecoin_map_clear(&psbt->global_scalars);
#endif /* BUILD_ELEMENTS */
        clear_and_free(psbt, sizeof(*psbt));
    }
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_global_tx_alloc(const struct dogecoin_psbt *psbt, struct libdogecoin_tx **output)
{
    OUTPUT_CHECK;
    if (!psbt || psbt->version != PSBT_0)
        return DOGECOIN_EINVAL;
    if (!psbt->tx)
        return DOGECOIN_OK; /* Return a NULL tx if not present */
    return tx_clone_alloc(psbt->tx, output);
}

#define PSBT_GET(name, v) \
    int dogecoin_psbt_get_ ## name(const struct dogecoin_psbt *psbt, size_t *written) { \
        if (written) \
            *written = 0; \
        if (!psbt || !written || (v == PSBT_2 && psbt->version != v)) \
            return DOGECOIN_EINVAL; \
        *written = psbt->name; \
        return DOGECOIN_OK; \
    }

PSBT_GET(version, PSBT_0)
PSBT_GET(num_inputs, PSBT_0)
PSBT_GET(num_outputs, PSBT_0)
PSBT_GET(fallback_locktime, PSBT_2)
PSBT_GET(tx_version, PSBT_2)
PSBT_GET(tx_modifiable_flags, PSBT_2)

int dogecoin_psbt_has_fallback_locktime(const struct dogecoin_psbt *psbt, size_t *written)
{
    if (written)
        *written = 0;
    if (!psbt || !written || psbt->version != PSBT_2)
        return DOGECOIN_EINVAL;
    *written = psbt->has_fallback_locktime ? 1 : 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_set_tx_version(struct dogecoin_psbt *psbt, uint32_t tx_version) {
    if (!psbt || psbt->version != PSBT_2 || tx_version < 2u)
        return DOGECOIN_EINVAL;
    psbt->tx_version = tx_version;
    return DOGECOIN_OK;
}

int dogecoin_psbt_set_fallback_locktime(struct dogecoin_psbt *psbt, uint32_t locktime) {
    if (!psbt || psbt->version != PSBT_2)
        return DOGECOIN_EINVAL;
    psbt->fallback_locktime = locktime;
    psbt->has_fallback_locktime = 1u;
    return DOGECOIN_OK;
}

int dogecoin_psbt_clear_fallback_locktime(struct dogecoin_psbt *psbt) {
    if (!psbt || psbt->version != PSBT_2)
        return DOGECOIN_EINVAL;
    psbt->fallback_locktime = 0u;
    psbt->has_fallback_locktime = 0u;
    return DOGECOIN_OK;
}

int dogecoin_psbt_set_tx_modifiable_flags(struct dogecoin_psbt *psbt, uint32_t flags) {
    if (!psbt || psbt->version != PSBT_2 ||
        (flags & ~PSBT_TXMOD_ALL_FLAGS))
        return DOGECOIN_EINVAL;
    psbt->tx_modifiable_flags = flags;
    return DOGECOIN_OK;
}

#ifdef BUILD_ELEMENTS
int dogecoin_psbt_get_global_scalars_size(const struct dogecoin_psbt *psbt, size_t *written)
{
    if (written) *written = 0;
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 || !written)
        return DOGECOIN_EINVAL;
    *written = psbt->global_scalars.num_items;
    return DOGECOIN_OK;
}

int dogecoin_psbt_find_global_scalar(struct dogecoin_psbt *psbt,
                                  const unsigned char *scalar, size_t scalar_len,
                                  size_t *written)
{
    if (written) *written = 0;
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return DOGECOIN_EINVAL;
    return dogecoin_map_find(&psbt->global_scalars, scalar, scalar_len, written);
}

int dogecoin_psbt_get_global_scalar(const struct dogecoin_psbt *psbt, size_t index,
                                 unsigned char *bytes_out, size_t len)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 ||
        index >= psbt->global_scalars.num_items ||
        !bytes_out || len != DOGECOIN_SCALAR_OFFSET_LEN)
        return DOGECOIN_EINVAL;
    memcpy(bytes_out, psbt->global_scalars.items[index].key, len);
    return DOGECOIN_OK;
}

int dogecoin_psbt_add_global_scalar(struct dogecoin_psbt *psbt,
                                 const unsigned char *scalar, size_t scalar_len)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return DOGECOIN_EINVAL;
    return dogecoin_map_add(&psbt->global_scalars, scalar, scalar_len, NULL, 0);
}

int dogecoin_psbt_set_global_scalars(struct dogecoin_psbt *psbt, const struct dogecoin_map *map_in)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0)
        return DOGECOIN_EINVAL;
    return dogecoin_map_assign(&psbt->global_scalars, map_in);
}

int dogecoin_psbt_set_pset_modifiable_flags(struct dogecoin_psbt *psbt, uint32_t flags)
{
    if (!psbt_is_valid(psbt) || psbt->version == PSBT_0 || flags & ~PSET_TXMOD_ALL_FLAGS)
        return DOGECOIN_EINVAL;
    psbt->pset_modifiable_flags = flags & ~DOGECOIN_PSET_TXMOD_RESERVED;
    return DOGECOIN_OK;
}

PSBT_GET(pset_modifiable_flags, PSBT_2)
#endif /* BUILD_ELEMENTS */

int dogecoin_psbt_is_finalized(const struct dogecoin_psbt *psbt,
                            size_t *written)
{
    size_t i;

    if (written)
        *written = 0;
    if (!psbt_is_valid(psbt) || !written)
        return DOGECOIN_EINVAL;

    for (i = 0; i < psbt->num_inputs; ++i) {
        if (!psbt->inputs[i].final_witness &&
            !dogecoin_map_get_integer(&psbt->inputs[i].psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
            return DOGECOIN_OK; /* Non fully finalized */
    }
    /* We are finalized if we have inputs since they are all finalized */
    *written = psbt->num_inputs ?  1 : 0;
    return DOGECOIN_OK;
}

static int psbt_set_global_tx(struct dogecoin_psbt *psbt, struct libdogecoin_tx *tx, bool do_clone)
{
    struct libdogecoin_tx *new_tx = NULL;
    struct dogecoin_psbt_input *new_inputs = NULL;
    struct dogecoin_psbt_output *new_outputs = NULL;
    size_t i;
    int ret;

    if (!psbt_is_valid(psbt) || !tx || psbt->tx || psbt->version != PSBT_0)
        return DOGECOIN_EINVAL; /* PSBT must be v0 and completely empty */

    for (i = 0; i < tx->num_inputs; ++i)
        if (tx->inputs[i].script || tx->inputs[i].witness)
            return DOGECOIN_EINVAL; /* tx mustn't have scriptSigs or witnesses */

    if (do_clone && (ret = tx_clone_alloc(tx, &new_tx)) != DOGECOIN_OK)
        return ret;

    if (psbt->inputs_allocation_len < tx->num_inputs) {
        new_inputs = dogecoin_malloc(tx->num_inputs * sizeof(struct dogecoin_psbt_input));
        for (i = 0; i < tx->num_inputs; ++i)
            psbt_input_init(&new_inputs[i]);
    }

    if (psbt->outputs_allocation_len < tx->num_outputs) {
        new_outputs = dogecoin_malloc(tx->num_outputs * sizeof(struct dogecoin_psbt_output));
        for (i = 0; i < tx->num_outputs; ++i)
            psbt_output_init(&new_outputs[i]);
    }

    if ((psbt->inputs_allocation_len < tx->num_inputs && !new_inputs) ||
        (psbt->outputs_allocation_len < tx->num_outputs && !new_outputs)) {
        dogecoin_free(new_inputs);
        dogecoin_free(new_outputs);
        libdogecoin_tx_free(new_tx);
        return DOGECOIN_ENOMEM;
    }

    if (new_inputs) {
        dogecoin_free(psbt->inputs);
        psbt->inputs = new_inputs;
        psbt->inputs_allocation_len = tx->num_inputs;
    }
    if (new_outputs) {
        dogecoin_free(psbt->outputs);
        psbt->outputs = new_outputs;
        psbt->outputs_allocation_len = tx->num_outputs;
    }
    psbt->num_inputs = tx->num_inputs;
    psbt->num_outputs = tx->num_outputs;
    psbt->tx = do_clone ? new_tx : tx;
    return DOGECOIN_OK;
}

int dogecoin_psbt_set_global_tx(struct dogecoin_psbt *psbt, const struct libdogecoin_tx *tx)
{
    return psbt_set_global_tx(psbt, (struct libdogecoin_tx *)tx, true);
}

#ifdef BUILD_ELEMENTS
static int add_commitment(const unsigned char *value, size_t value_len,
                          uint32_t ft, uint32_t ft_commitment,
                          struct dogecoin_map *map_in)
{
    if (value_len <= 1)
        return DOGECOIN_OK; /* Empty or null commitment */
    if (*value == 0x1) {
        /* Asset isn't blinded: add it as the non-commitment field */
        return dogecoin_map_add_integer(map_in, ft, value + 1, value_len - 1);
    }
    return dogecoin_map_add_integer(map_in, ft_commitment, value, value_len);
}

static int add_commitment_amount(const unsigned char *value, size_t value_len,
                                 uint32_t ft_commitment,
                                 uint64_t *amount, uint32_t *has_amount,
                                 struct dogecoin_map *map_in)
{
    *amount = 0;
    *has_amount = 0;
    if (value_len <= 1)
        return DOGECOIN_OK; /* Empty or null commitment */
    if (*value == 0x1) {
        /* Asset isn't blinded: add the explicit value and mark it present */
        if (libdogecoin_tx_confidential_value_to_satoshi(value, value_len, amount) != DOGECOIN_OK)
            return DOGECOIN_EINVAL;
        *has_amount = *value != 0;
        return DOGECOIN_OK;
    }
    return dogecoin_map_add_integer(map_in, ft_commitment, value, value_len);
}

static int psbt_input_from_tx_input_issuance(const struct libdogecoin_tx_input *txin,
                                             struct dogecoin_psbt_input *dst)
{
    uint32_t has_amount;
    int ret = add_commitment_amount(txin->issuance_amount, txin->issuance_amount_len,
                                    PSET_IN_ISSUANCE_VALUE_COMMITMENT,
                                    &dst->issuance_amount, &has_amount,
                                    &dst->pset_fields);
    if (ret == DOGECOIN_OK && txin->issuance_amount_rangeproof)
        ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_VALUE_RANGEPROOF,
                                    txin->issuance_amount_rangeproof,
                                    txin->issuance_amount_rangeproof_len);
    if (ret == DOGECOIN_OK)
        ret = add_commitment_amount(txin->inflation_keys, txin->inflation_keys_len,
                                    PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                                    &dst->inflation_keys, &has_amount,
                                    &dst->pset_fields);
    if (ret == DOGECOIN_OK && txin->inflation_keys_rangeproof)
        ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF,
                                    txin->inflation_keys_rangeproof,
                                    txin->inflation_keys_rangeproof_len);
    if (ret == DOGECOIN_OK && !mem_is_zero(txin->blinding_nonce, sizeof(txin->blinding_nonce)))
        ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_BLINDING_NONCE,
                                    txin->blinding_nonce, sizeof(txin->blinding_nonce));
    if (ret == DOGECOIN_OK && !mem_is_zero(txin->entropy, sizeof(txin->entropy)))
        ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_IN_ISSUANCE_ASSET_ENTROPY,
                                    txin->entropy, sizeof(txin->entropy));
    return ret;
}

static int psbt_input_from_tx_input_pegin(const struct libdogecoin_tx_input *txin,
                                          struct dogecoin_psbt_input *dst)
{
    (void)txin;
    (void)dst;
    return DOGECOIN_ERROR; /* FIXME: Implement peg-in fields */
}
#endif /* BUILD_ELEMENTS */

static int psbt_input_from_tx_input(struct dogecoin_psbt *psbt,
                                    const struct libdogecoin_tx_input *txin,
                                    bool is_pset, struct dogecoin_psbt_input *dst)
{
    int ret = DOGECOIN_OK;

    psbt_input_init(dst);
    if (psbt->version == PSBT_0)
        return DOGECOIN_OK; /* Nothing to do */

    memcpy(dst->txhash, txin->txhash, DOGECOIN_TXHASH_LEN);
    dst->index = MASK_INDEX(txin->index);
    dst->sequence = txin->sequence;

    if (psbt->version == PSBT_2) {
        if (is_pset) {
#ifdef BUILD_ELEMENTS
            if (txin->features & DOGECOIN_TX_IS_ISSUANCE)
                ret = psbt_input_from_tx_input_issuance(txin, dst);
            if (ret == DOGECOIN_OK && txin->features & DOGECOIN_TX_IS_PEGIN)
                ret = psbt_input_from_tx_input_pegin(txin, dst);
#endif /* BUILD_ELEMENTS */
        }
    }
    if (ret != DOGECOIN_OK)
        psbt_input_free(dst, false);
    return ret;
}

int dogecoin_psbt_add_tx_input_at(struct dogecoin_psbt *psbt,
                               uint32_t index, uint32_t flags,
                               const struct libdogecoin_tx_input *txin)
{
    struct libdogecoin_tx_input txin_copy;
    size_t is_pset;
    int ret = DOGECOIN_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        (flags & ~DOGECOIN_PSBT_FLAG_NON_FINAL) || index > psbt->num_inputs || !txin)
        return DOGECOIN_EINVAL;

    if (!psbt_can_modify(psbt, DOGECOIN_PSBT_TXMOD_INPUTS))
        return DOGECOIN_EINVAL; /* FIXME: DOGECOIN_PSBT_TXMOD_SINGLE */

    if ((ret = dogecoin_psbt_is_elements(psbt, &is_pset)) != DOGECOIN_OK)
        return ret;

    if (psbt->num_inputs >= psbt->inputs_allocation_len &&
        (ret = array_grow((void *)&psbt->inputs, psbt->num_inputs,
                          &psbt->inputs_allocation_len,
                          sizeof(*psbt->inputs))) != DOGECOIN_OK)
        return ret;

    memcpy(&txin_copy, txin, sizeof(*txin));
    if (flags & DOGECOIN_PSBT_FLAG_NON_FINAL) {
        /* Clear scriptSig and witness before adding */
        txin_copy.script = NULL;
        txin_copy.script_len = 0;
        txin_copy.witness = NULL;
    }

    if (psbt->version == PSBT_0)
        ret = libdogecoin_tx_add_input_at(psbt->tx, index, &txin_copy);

    if (ret == DOGECOIN_OK) {
        struct dogecoin_psbt_input tmp, *dst = psbt->inputs + index;

        ret = psbt_input_from_tx_input(psbt, &txin_copy, !!is_pset, &tmp);
        if (ret == DOGECOIN_OK) {
            memmove(dst + 1, dst, (psbt->num_inputs - index) * sizeof(*psbt->inputs));
            memcpy(dst, &tmp, sizeof(tmp));
            dogecoin_clear(&tmp, sizeof(tmp));
            psbt->num_inputs += 1;
        }
    }

    if (ret != DOGECOIN_OK && psbt->version == PSBT_0)
        libdogecoin_tx_remove_input(psbt->tx, index);
    dogecoin_clear(&txin_copy, sizeof(txin_copy));
    return ret;
}

int dogecoin_psbt_remove_input(struct dogecoin_psbt *psbt, uint32_t index)
{
    int ret = DOGECOIN_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        index >= psbt->num_inputs)
        return DOGECOIN_EINVAL;

    if (!psbt_can_modify(psbt, DOGECOIN_PSBT_TXMOD_INPUTS))
        return DOGECOIN_EINVAL; /* FIXME: DOGECOIN_PSBT_TXMOD_SINGLE */

    if (psbt->version == PSBT_0)
        ret = libdogecoin_tx_remove_input(psbt->tx, index);
    if (ret == DOGECOIN_OK) {
        struct dogecoin_psbt_input *to_remove = psbt->inputs + index;
        bool need_single = false;
        size_t i;
        if (psbt->version == PSBT_2 &&
            (to_remove->sighash & DOGECOIN_SIGHASH_MASK) == DOGECOIN_SIGHASH_SINGLE) {
            /* Remove SINGLE from tx modifiable flags if no longer needed */
            for (i = 0; i < psbt->num_inputs && !need_single; ++i) {
                need_single |= i != index &&
                               (psbt->inputs[i].sighash & DOGECOIN_SIGHASH_MASK) == DOGECOIN_SIGHASH_SINGLE;
            }
            if (!need_single)
                psbt->tx_modifiable_flags &= ~DOGECOIN_PSBT_TXMOD_SINGLE;
        }
        psbt_input_free(to_remove, false);
        memmove(to_remove, to_remove + 1,
                (psbt->num_inputs - index - 1) * sizeof(*to_remove));
        psbt->num_inputs -= 1;
    }
    return ret;
}

static int psbt_output_from_tx_output(struct dogecoin_psbt *psbt,
                                      const struct libdogecoin_tx_output *txout,
                                      bool is_pset, struct dogecoin_psbt_output *dst)
{
    int ret;

    psbt_output_init(dst);
    if (psbt->version == PSBT_0)
        return DOGECOIN_OK; /* Nothing to do */

    ret = replace_bytes(txout->script, txout->script_len,
                        &dst->script, &dst->script_len);
    if (ret == DOGECOIN_OK) {
        /* Note we check for wallys sentinel indicating no explicit satoshi */
        dst->has_amount = txout->satoshi != MAX_INVALID_SATOSHI;
        dst->amount = dst->has_amount ? txout->satoshi : 0;
        if (is_pset) {
#ifdef BUILD_ELEMENTS
            ret = add_commitment(txout->asset, txout->asset_len,
                                 PSET_OUT_ASSET, PSET_OUT_ASSET_COMMITMENT,
                                 &dst->pset_fields);
            if (ret == DOGECOIN_OK)
                ret = add_commitment_amount(txout->value, txout->value_len,
                                            PSET_OUT_VALUE_COMMITMENT,
                                            &dst->amount, &dst->has_amount,
                                            &dst->pset_fields);
            if (ret == DOGECOIN_OK && txout->nonce_len)
                ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_OUT_BLINDING_PUBKEY,
                                            txout->nonce, txout->nonce_len);
            if (ret == DOGECOIN_OK && txout->surjectionproof_len)
                ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_OUT_ASSET_SURJECTION_PROOF,
                                            txout->surjectionproof, txout->surjectionproof_len);
            if (ret == DOGECOIN_OK && txout->rangeproof_len)
                ret = dogecoin_map_add_integer(&dst->pset_fields, PSET_OUT_VALUE_RANGEPROOF,
                                            txout->rangeproof, txout->rangeproof_len);
#endif /* BUILD_ELEMENTS */
        }
    }
    if (ret != DOGECOIN_OK)
        psbt_output_free(dst, false);
    return ret;
}

int dogecoin_psbt_add_tx_output_at(struct dogecoin_psbt *psbt,
                                uint32_t index, uint32_t flags,
                                const struct libdogecoin_tx_output *txout)
{
    size_t is_pset;
    int ret = DOGECOIN_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        flags || index > psbt->num_outputs || !txout)
        return DOGECOIN_EINVAL;

    if (!psbt_can_modify(psbt, DOGECOIN_PSBT_TXMOD_OUTPUTS))
        return DOGECOIN_EINVAL; /* FIXME: DOGECOIN_PSBT_TXMOD_SINGLE */

    if ((ret = dogecoin_psbt_is_elements(psbt, &is_pset)) != DOGECOIN_OK)
        return ret;

    if (psbt->num_outputs >= psbt->outputs_allocation_len &&
        (ret = array_grow((void *)&psbt->outputs, psbt->num_outputs,
                          &psbt->outputs_allocation_len,
                          sizeof(*psbt->outputs))) != DOGECOIN_OK)
        return ret;

    if (psbt->version == PSBT_0)
        ret = libdogecoin_tx_add_output_at(psbt->tx, index, txout);

    if (ret == DOGECOIN_OK) {
        struct dogecoin_psbt_output tmp, *dst = psbt->outputs + index;

        ret = psbt_output_from_tx_output(psbt, txout, !!is_pset, &tmp);
        if (ret == DOGECOIN_OK) {
            memmove(dst + 1, dst, (psbt->num_outputs - index) * sizeof(*psbt->outputs));
            memcpy(dst, &tmp, sizeof(tmp));
            dogecoin_clear(&tmp, sizeof(tmp));
            psbt->num_outputs += 1;
        }
    }

    if (ret != DOGECOIN_OK && psbt->version == PSBT_0)
        libdogecoin_tx_remove_output(psbt->tx, index);
    return ret;
}

int dogecoin_psbt_remove_output(struct dogecoin_psbt *psbt, uint32_t index)
{
    int ret = DOGECOIN_OK;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx) ||
        index >= psbt->num_outputs)
        return DOGECOIN_EINVAL;

    if (!psbt_can_modify(psbt, DOGECOIN_PSBT_TXMOD_OUTPUTS))
        return DOGECOIN_EINVAL; /* FIXME: DOGECOIN_PSBT_TXMOD_SINGLE */

    if (psbt->version == PSBT_0)
        ret = libdogecoin_tx_remove_output(psbt->tx, index);
    if (ret == DOGECOIN_OK) {
        struct dogecoin_psbt_output *to_remove = psbt->outputs + index;
        psbt_output_free(to_remove, false);
        memmove(to_remove, to_remove + 1,
                (psbt->num_outputs - index - 1) * sizeof(*to_remove));
        psbt->num_outputs -= 1;
    }
    return ret;
}

/* Stricter version of pull_subfield_end which insists there's nothing left. */
static void subfield_nomore_end(const unsigned char **cursor, size_t *max,
                                const unsigned char *subcursor,
                                const size_t submax)
{
    if (submax) {
        pull_failed(cursor, max);
    } else {
        pull_subfield_end(cursor, max, subcursor, submax);
    }
}

static uint8_t pull_u8_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint8_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_u8(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint32_t pull_le32_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint32_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_le32(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint64_t pull_le64_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_le64(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static uint64_t pull_varint_subfield(const unsigned char **cursor, size_t *max)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t ret;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = pull_varint(&val, &val_len);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static void pull_varlength_buff(const unsigned char **cursor, size_t *max,
                                const unsigned char **dst, size_t *len)
{
    *len = pull_varlength(cursor, max);
    *dst = pull_skip(cursor, max, *len);
}

static int pull_output_varbuf(const unsigned char **cursor, size_t *max,
                              struct dogecoin_psbt_output *output,
                              int (*set_fn)(struct dogecoin_psbt_output *, const unsigned char *, size_t))
{
    const unsigned char *val;
    size_t val_len;
    pull_varlength_buff(cursor, max, &val, &val_len);
    return val_len ? set_fn(output, val, val_len) : DOGECOIN_OK;
}

static void pull_varint_buff(const unsigned char **cursor, size_t *max,
                             const unsigned char **dst, size_t *len)
{
    uint64_t varint_len = pull_varint(cursor, max);
    *len = varint_len;
    *dst = pull_skip(cursor, max, varint_len);
}

static int pull_map_item(const unsigned char **cursor, size_t *max,
                         const unsigned char *key, size_t key_len,
                         struct dogecoin_map *map_in)
{
    const unsigned char *val;
    size_t val_len;

    pull_varlength_buff(cursor, max, &val, &val_len);
    return map_add(map_in, key, key_len, val_len ? val : NULL, val_len, false, false);
}

static int pull_preimage(const unsigned char **cursor, size_t *max,
                         size_t type, const unsigned char *key, size_t key_len,
                         struct dogecoin_map *map_in)
{
    const unsigned char *val;
    size_t val_len;

    pull_varlength_buff(cursor, max, &val, &val_len);
    return map_add_preimage_and_hash(map_in, key, key_len, val, val_len, type, false);
}

static int pull_tx(const unsigned char **cursor, size_t *max,
                   uint32_t tx_flags, struct libdogecoin_tx **tx_out)
{
    const unsigned char *val;
    size_t val_len;
    int ret;

    if (*tx_out)
        ret = DOGECOIN_EINVAL; /* Duplicate */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    ret = libdogecoin_tx_from_bytes(val, val_len, tx_flags, tx_out);
    pull_subfield_end(cursor, max, val, val_len);
    return ret;
}

#ifdef BUILD_ELEMENTS
typedef size_t (*commitment_len_fn_t)(const unsigned char *);

static bool pull_commitment(const unsigned char **cursor, size_t *max,
                            const unsigned char **dst, size_t *len,
                            commitment_len_fn_t len_fn)
{
    if (!*cursor || !*max)
        return false;

    if (!(*len = len_fn(*cursor)))
        return false; /* Invalid commitment */
    if (!(*dst = pull_skip(cursor, max, *len)))
        return false;
    if (*len == 1u) {
        *dst = NULL; /* NULL commitment */
        *len = 0;
    }
    return true;
}
#endif /* BUILD_ELEMENTS */

static int pull_tx_output(const unsigned char **cursor, size_t *max,
                          bool is_pset, struct libdogecoin_tx_output **txout_out)
{
    const unsigned char *val, *script;
    size_t val_len, script_len;
    uint64_t satoshi;
    int ret;

    (void)is_pset;
    if (*txout_out)
        return DOGECOIN_EINVAL; /* Duplicate */
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);

#ifdef BUILD_ELEMENTS
    if (is_pset) {
        const unsigned char *asset, *value, *nonce;
        size_t asset_len, value_len, nonce_len;

        if (!pull_commitment(&val, &val_len, &asset, &asset_len,
                             confidential_asset_length_from_bytes) ||
            !pull_commitment(&val, &val_len, &value, &value_len,
                             confidential_value_length_from_bytes) ||
            !pull_commitment(&val, &val_len, &nonce, &nonce_len,
                             confidential_nonce_length_from_bytes))
            return DOGECOIN_EINVAL;

        /* Note unlike non-Elements, script can be empty for fee outputs */
        pull_varint_buff(&val, &val_len, &script, &script_len);
        ret = libdogecoin_tx_elements_output_init_alloc(script, script_len, asset, asset_len,
                                                  value, value_len, nonce, nonce_len,
                                                  NULL, 0, NULL, 0, txout_out);
        subfield_nomore_end(cursor, max, val, val_len);
        return ret;
    }
#endif /* BUILD_ELEMENTS */
    satoshi = pull_le64(&val, &val_len);
    pull_varint_buff(&val, &val_len, &script, &script_len);
    if (!script || !script_len)
        return DOGECOIN_EINVAL;
    ret = libdogecoin_tx_output_init_alloc(satoshi, script, script_len, txout_out);
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

static int pull_witness(const unsigned char **cursor, size_t *max,
                        struct libdogecoin_tx_witness_stack **witness_out)
{
    const unsigned char *val;
    size_t val_len;
    uint64_t num_witnesses, i;
    int ret;

    if (*witness_out)
        ret = DOGECOIN_EINVAL; /* Duplicate */

    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    num_witnesses = pull_varint(&val, &val_len);
    ret = libdogecoin_tx_witness_stack_init_alloc(num_witnesses, witness_out);

    for (i = 0; ret == DOGECOIN_OK && i < num_witnesses; ++i) {
        const unsigned char *wit;
        size_t wit_len;
        pull_varint_buff(&val, &val_len, &wit, &wit_len);
        ret = libdogecoin_tx_witness_stack_set(*witness_out, i, wit, wit_len);
    }
    subfield_nomore_end(cursor, max, val, val_len);
    return ret;
}

/* Rewind cursor to prekey, and append unknown key/value to unknowns */
static int pull_unknown_key_value(const unsigned char **cursor, size_t *max,
                                  const unsigned char *pre_key,
                                  struct dogecoin_map *unknowns)
{
    const unsigned char *key, *val;
    size_t key_len, val_len;

    /* If we've already failed, it's invalid */
    if (!*cursor)
        return DOGECOIN_EINVAL;

    /* We have to unwind a bit, to get entire key again. */
    *max += (*cursor - pre_key);
    *cursor = pre_key;

    pull_varlength_buff(cursor, max, &key, &key_len);
    pull_varlength_buff(cursor, max, &val, &val_len);

    return map_add(unknowns, key, key_len, val, val_len, false, false);
}

static uint64_t pull_field_type(const unsigned char **cursor, size_t *max,
                                const unsigned char **key, size_t *key_len,
                                bool is_pset, bool *is_pset_ft)
{
    uint64_t field_type;
    *is_pset_ft = false;
    pull_subfield_start(cursor, max, *key_len, key, key_len);
    field_type = pull_varint(key, key_len);
    if (is_pset && field_type == DOGECOIN_PSBT_PROPRIETARY_TYPE) {
#ifdef BUILD_ELEMENTS
        const size_t pset_key_len = pull_varlength(key, key_len);
        if (is_pset_key(*key, pset_key_len)) {
            pull_skip(key, key_len, PSET_PREFIX_LEN);
            field_type = pull_varint(key, key_len);
            *is_pset_ft = true;
        }
#endif /* BUILD_ELEMENTS */
    }
    return field_type;
}

static int pull_taproot_leaf_signature(const unsigned char **cursor, size_t *max,
                                       const unsigned char **key, size_t *key_len,
                                       struct dogecoin_map *leaf_sigs)
{
    /* TODO: use schnorr/taproot constants here */
    const unsigned char *val, *xonly_hash;
    size_t val_len;

    /* key = x-only pubkey + leaf hash */
    if (*key_len != 64u || !(xonly_hash = pull_skip(key, key_len, *key_len)))
        return DOGECOIN_EINVAL;
    subfield_nomore_end(cursor, max, *key, *key_len);

    pull_varlength_buff(cursor, max, &val, &val_len);
    if (!val || (val_len != 64u && val_len != 65))
        return DOGECOIN_EINVAL; /* Invalid signature length */
    return map_add(leaf_sigs, xonly_hash, 64u, val, val_len, false, false);
}

static bool is_valid_control_block_len(size_t ctrl_len)
{
    return ctrl_len >= 33u && ctrl_len <= 33u + 128u * 32u &&
           ((ctrl_len - 33u) % 32u) == 0;
}

static int pull_taproot_leaf_script(const unsigned char **cursor, size_t *max,
                                    const unsigned char **key, size_t *key_len,
                                    struct dogecoin_map *leaf_scripts)
{
    /* TODO: use taproot constants here */
    const unsigned char *ctrl, *val;
    size_t ctrl_len = *key_len, val_len;

    ctrl = pull_skip(key, key_len, ctrl_len);
    if (!ctrl || !is_valid_control_block_len(ctrl_len))
        return DOGECOIN_EINVAL;
    subfield_nomore_end(cursor, max, *key, *key_len);

    pull_varlength_buff(cursor, max, &val, &val_len);
    if (!val || !val_len)
        return DOGECOIN_EINVAL;

    return map_add(leaf_scripts, ctrl, ctrl_len, val, val_len, false, false);
}

static int pull_taproot_derivation(const unsigned char **cursor, size_t *max,
                                   const unsigned char **key, size_t *key_len,
                                   struct dogecoin_map *leaf_hashes,
                                   struct dogecoin_map *leaf_paths)
{
    const unsigned char *xonly = *key, *hashes, *val;
    size_t xonly_len = *key_len, num_hashes, hashes_len, val_len;
    int ret;

    if (xonly_len != EC_XONLY_PUBLIC_KEY_LEN)
        return DOGECOIN_EINVAL;;
    pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_len);
    num_hashes = pull_varint(&val, &val_len);
    hashes_len = num_hashes * SHA256_LEN;
    if (!(hashes = pull_skip(&val, &val_len, hashes_len)))
        return DOGECOIN_EINVAL;

    if (val_len < sizeof(uint32_t) || val_len % sizeof(uint32_t))
        return DOGECOIN_EINVAL; /* Invalid fingerprint + path */

    ret = map_add(leaf_hashes, xonly, xonly_len,
                  hashes_len ? hashes : NULL, hashes_len, false, false);
    if (ret == DOGECOIN_OK) {
        ret = map_add(leaf_paths, xonly, xonly_len, val, val_len, false, false);
        if (ret == DOGECOIN_OK) {
            pull_skip(&val, &val_len, val_len);
            subfield_nomore_end(cursor, max, val, val_len);
        }
    }
    return ret;
}

static struct dogecoin_psbt *pull_psbt(const unsigned char **cursor, size_t *max)
{
    struct dogecoin_psbt *psbt = NULL;
    const unsigned char *magic = pull_skip(cursor, max, sizeof(PSBT_MAGIC));
    int ret = DOGECOIN_EINVAL;

    if (magic && !memcmp(magic, PSBT_MAGIC, sizeof(PSBT_MAGIC)))
        ret = dogecoin_psbt_init_alloc(0, 0, 0, 8, 0, &psbt);
#ifdef BUILD_ELEMENTS
    else if (magic && !memcmp(magic, PSET_MAGIC, sizeof(PSET_MAGIC)))
        ret = dogecoin_psbt_init_alloc(2, 0, 0, 8, DOGECOIN_PSBT_INIT_PSET, &psbt);
#endif /* BUILD_ELEMENTS */
    return ret == DOGECOIN_OK ? psbt : NULL;
}

static int pull_psbt_input(const struct dogecoin_psbt *psbt,
                           const unsigned char **cursor, size_t *max,
                           uint32_t tx_flags, uint32_t flags,
                           struct dogecoin_psbt_input *result)
{
    size_t key_len, val_len;
    const unsigned char *pre_key = *cursor, *val_p;
    const bool is_pset = (tx_flags & DOGECOIN_TX_FLAG_USE_ELEMENTS) != 0;
    uint64_t mandatory = psbt->version == PSBT_0 ? PSBT_IN_MANDATORY_V0 : PSBT_IN_MANDATORY_V2;
    uint64_t disallowed = psbt->version == PSBT_0 ? PSBT_IN_DISALLOWED_V0 : PSBT_IN_DISALLOWED_V2;
    uint64_t keyset = 0;
    int ret = DOGECOIN_OK;

    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }

    /* Default any non-zero input values */
    result->sequence = DOGECOIN_TX_SEQUENCE_FINAL;

    /* Read key value pairs */
    while (ret == DOGECOIN_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        const uint64_t raw_field_type = field_type;
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_IN_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_IN_MAX;
            if (is_known)
                field_bit = PSBT_FT(field_type);
        }

        /* Process based on type */
        if (is_known) {
            if (keyset & field_bit && (!(field_bit & PSBT_IN_REPEATABLE))) {
                ret = DOGECOIN_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_IN_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_IN_NON_WITNESS_UTXO:
                ret = pull_tx(cursor, max, tx_flags, &result->utxo);
                break;
            case PSBT_IN_WITNESS_UTXO:
                ret = pull_tx_output(cursor, max, is_pset, &result->witness_utxo);
                break;
            case PSBT_IN_PARTIAL_SIG:
                ret = pull_map_item(cursor, max, key, key_len, &result->signatures);
                break;
            case PSBT_IN_SIGHASH_TYPE:
                result->sighash = pull_le32_subfield(cursor, max);
                break;
            case PSBT_IN_BIP32_DERIVATION:
                ret = pull_map_item(cursor, max, key, key_len, &result->keypaths);
                break;
            case PSBT_IN_FINAL_SCRIPTWITNESS:
                ret = pull_witness(cursor, max, &result->final_witness);
                break;
            case PSBT_IN_RIPEMD160:
            case PSBT_IN_SHA256:
            case PSBT_IN_HASH160:
            case PSBT_IN_HASH256:
                ret = pull_preimage(cursor, max, field_type, key, key_len, &result->preimages);
                break;
            case PSBT_IN_REDEEM_SCRIPT:
            case PSBT_IN_WITNESS_SCRIPT:
            case PSBT_IN_FINAL_SCRIPTSIG:
            case PSBT_IN_POR_COMMITMENT:
            case PSBT_IN_TAP_KEY_SIG:
            case PSBT_IN_TAP_INTERNAL_KEY:
            case PSBT_IN_TAP_MERKLE_ROOT:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = dogecoin_map_add_integer(&result->psbt_fields, raw_field_type,
                                            val_p, val_len);
                break;
            case PSBT_IN_PREVIOUS_TXID:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = dogecoin_psbt_input_set_previous_txid(result, val_p, val_len);
                break;
            case PSBT_IN_OUTPUT_INDEX:
                result->index = pull_le32_subfield(cursor, max);
                if (is_pset && (result->index & ~DOGECOIN_TX_INDEX_MASK) &&
                    (flags & DOGECOIN_PSBT_PARSE_FLAG_STRICT))
                    ret = DOGECOIN_EINVAL;
                result->index = MASK_INDEX(result->index);
                break;
            case PSBT_IN_SEQUENCE:
                result->sequence = pull_le32_subfield(cursor, max);
                break;
            case PSBT_IN_REQUIRED_TIME_LOCKTIME:
                ret = dogecoin_psbt_input_set_required_locktime(result, pull_le32_subfield(cursor, max));
                break;
            case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
                ret = dogecoin_psbt_input_set_required_lockheight(result, pull_le32_subfield(cursor, max));
                break;
            case PSBT_IN_TAP_SCRIPT_SIG:
                ret = pull_taproot_leaf_signature(cursor, max, &key, &key_len,
                                                  &result->taproot_leaf_signatures);
                break;
            case PSBT_IN_TAP_LEAF_SCRIPT:
                ret = pull_taproot_leaf_script(cursor, max, &key, &key_len,
                                               &result->taproot_leaf_scripts);
                break;
            case PSBT_IN_TAP_BIP32_DERIVATION:
                ret = pull_taproot_derivation(cursor, max, &key, &key_len,
                                              &result->taproot_leaf_hashes,
                                              &result->taproot_leaf_paths);
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_IN_EXPLICIT_VALUE):
                ret = dogecoin_psbt_input_set_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_ISSUANCE_VALUE):
                ret = dogecoin_psbt_input_set_issuance_amount(result,
                                                           pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_PEG_IN_VALUE):
                ret = dogecoin_psbt_input_set_pegin_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT):
                ret = dogecoin_psbt_input_set_inflation_keys(result,
                                                          pull_le64_subfield(cursor, max));
                break;
            case PSET_FT(PSET_IN_PEG_IN_TX):
                /* Note 0 for tx_flags here as peg-in tx is from the base chain */
                ret = pull_tx(cursor, max, 0, &result->pegin_tx);
                break;
            case PSET_FT(PSET_IN_PEG_IN_WITNESS):
                ret = pull_witness(cursor, max, &result->pegin_witness);
                break;
            case PSET_FT(PSET_IN_ISSUANCE_VALUE_COMMITMENT):
            case PSET_FT(PSET_IN_ISSUANCE_VALUE_RANGEPROOF):
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF):
            case PSET_FT(PSET_IN_PEG_IN_TXOUT_PROOF):
            case PSET_FT(PSET_IN_PEG_IN_GENESIS_HASH):
            case PSET_FT(PSET_IN_PEG_IN_CLAIM_SCRIPT):
            case PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT):
            case PSET_FT(PSET_IN_ISSUANCE_BLINDING_NONCE):
            case PSET_FT(PSET_IN_ISSUANCE_ASSET_ENTROPY):
            case PSET_FT(PSET_IN_UTXO_RANGEPROOF):
            case PSET_FT(PSET_IN_ISSUANCE_BLIND_VALUE_PROOF):
            case PSET_FT(PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF):
            case PSET_FT(PSET_IN_VALUE_PROOF):
            case PSET_FT(PSET_IN_EXPLICIT_ASSET):
            case PSET_FT(PSET_IN_ASSET_PROOF):
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = dogecoin_map_add_integer(&result->pset_fields, raw_field_type,
                                            val_p, val_len);
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            /* Unknown case without elements or for unknown proprietary types */
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
        }
        pre_key = *cursor;
    }

    if (mandatory && (keyset & mandatory) != mandatory)
        ret = DOGECOIN_EINVAL; /* Mandatory field is missing */
    else if (disallowed && (keyset & disallowed))
        ret = DOGECOIN_EINVAL; /* Disallowed field present */

    if (ret == DOGECOIN_OK && result->sighash) {
        /* Verify that the sighash provided matches any signatures given */
        ret = dogecoin_psbt_input_set_sighash(result, result->sighash);
    }

#ifdef BUILD_ELEMENTS
    if (ret == DOGECOIN_OK && is_pset) {
        const uint32_t strict_flags = flags | DOGECOIN_PSBT_PARSE_FLAG_STRICT;
        /* Commitment key isn't used for PSET_IN_EXPLICIT_VALUE/ASSET */
        const uint64_t unused_key = 0xffffffff;

        /* Explicit values are only valid if we have an input UTXO */
#define PSET_UTXO_BITS (PSET_FT(PSBT_IN_NON_WITNESS_UTXO) | PSET_FT(PSBT_IN_WITNESS_UTXO))

        if (!pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_ISSUANCE_VALUE),
                              PSET_IN_ISSUANCE_VALUE_COMMITMENT,
                              PSET_IN_ISSUANCE_BLIND_VALUE_PROOF, flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT),
                              PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                              PSET_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF, flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_EXPLICIT_VALUE),
                              unused_key, PSET_IN_VALUE_PROOF, strict_flags) ||
            !pset_check_proof(psbt, result, NULL, PSET_FT(PSET_IN_EXPLICIT_ASSET),
                              unused_key, PSET_IN_ASSET_PROOF, strict_flags))
            ret = DOGECOIN_EINVAL;
    }
#endif /* BUILD_ELEMENTS */
    (void)flags; /* For non-elements builds */
    return ret;
}

static int pull_psbt_output(const struct dogecoin_psbt *psbt,
                            const unsigned char **cursor, size_t *max,
                            uint32_t tx_flags, uint32_t flags,
                            struct dogecoin_psbt_output *result)
{
    size_t key_len, val_len;
    const unsigned char *pre_key = *cursor, *val_p;
    const bool is_pset = (tx_flags & DOGECOIN_TX_FLAG_USE_ELEMENTS) != 0;
    uint64_t mandatory = psbt->version == PSBT_0 ? PSBT_OUT_MANDATORY_V0 : PSBT_OUT_MANDATORY_V2;
    uint64_t disallowed = psbt->version == PSBT_0 ? PSBT_OUT_DISALLOWED_V0 : PSBT_OUT_DISALLOWED_V2;
    uint64_t keyset = 0;
    int ret = DOGECOIN_OK;

    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }

    /* Read key value pairs */
    while (ret == DOGECOIN_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        const uint64_t raw_field_type = field_type;
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_OUT_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_OUT_MAX;
            if (is_known)
                field_bit = PSBT_FT(field_type);
        }

        /* Process based on type */
        if (is_known) {
            if (keyset & field_bit && (!(field_bit & PSBT_OUT_REPEATABLE))) {
                ret = DOGECOIN_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_OUT_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_OUT_BIP32_DERIVATION:
                ret = pull_map_item(cursor, max, key, key_len, &result->keypaths);
                break;
            case PSBT_OUT_AMOUNT:
                ret = dogecoin_psbt_output_set_amount(result, pull_le64_subfield(cursor, max));
                break;
            case PSBT_OUT_SCRIPT:
                ret = pull_output_varbuf(cursor, max, result,
                                         dogecoin_psbt_output_set_script);
                break;
            case PSBT_OUT_REDEEM_SCRIPT:
            case PSBT_OUT_WITNESS_SCRIPT:
            case PSBT_OUT_TAP_INTERNAL_KEY:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = dogecoin_map_add_integer(&result->psbt_fields, raw_field_type,
                                            val_p, val_len);
                break;
            case PSBT_OUT_TAP_TREE:
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                /* Add the leaf to the map keyed by its (1-based) position */
                ret = dogecoin_map_add_integer(&result->taproot_tree,
                                            result->taproot_tree.num_items + 1,
                                            val_p, val_len);
                break;
            case PSBT_OUT_TAP_BIP32_DERIVATION:
                ret = pull_taproot_derivation(cursor, max, &key, &key_len,
                                              &result->taproot_leaf_hashes,
                                              &result->taproot_leaf_paths);
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_OUT_BLINDER_INDEX):
                result->blinder_index = pull_le32_subfield(cursor, max);
                result->has_blinder_index = 1u;
                break;
            case PSET_FT(PSET_OUT_VALUE_COMMITMENT):
            case PSET_FT(PSET_OUT_ASSET):
            case PSET_FT(PSET_OUT_ASSET_COMMITMENT):
            case PSET_FT(PSET_OUT_VALUE_RANGEPROOF):
            case PSET_FT(PSET_OUT_ASSET_SURJECTION_PROOF):
            case PSET_FT(PSET_OUT_BLINDING_PUBKEY):
            case PSET_FT(PSET_OUT_ECDH_PUBKEY):
            case PSET_FT(PSET_OUT_BLIND_VALUE_PROOF):
            case PSET_FT(PSET_OUT_BLIND_ASSET_PROOF):
                pull_varlength_buff(cursor, max, &val_p, &val_len);
                ret = dogecoin_map_add_integer(&result->pset_fields, raw_field_type,
                                            val_p, val_len);
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
        }
        pre_key = *cursor;
    }
#ifdef BUILD_ELEMENTS
    if (is_pset) {
        /* Amount must be removed if commitments are present; therefore
         * unlike PSBT v2 it is not unconditionally mandatory */
        mandatory &= ~PSBT_FT(PSBT_OUT_AMOUNT);
    }
#endif /* BUILD_ELEMENTS */

    if (mandatory && (keyset & mandatory) != mandatory)
        ret = DOGECOIN_EINVAL; /* Mandatory field is missing*/
    else if (disallowed && (keyset & disallowed))
        ret = DOGECOIN_EINVAL; /* Disallowed field present */

#ifdef BUILD_ELEMENTS
    if (ret == DOGECOIN_OK && is_pset) {
        if (!pset_check_proof(psbt, NULL, result, PSBT_FT(PSBT_OUT_AMOUNT),
                              PSET_OUT_VALUE_COMMITMENT,
                              PSET_OUT_BLIND_VALUE_PROOF, flags) ||
            !pset_check_proof(psbt, NULL, result, PSET_FT(PSET_OUT_ASSET),
                              PSET_OUT_ASSET_COMMITMENT,
                              PSET_OUT_BLIND_ASSET_PROOF, flags))
            ret = DOGECOIN_EINVAL;
    }
#endif /* BUILD_ELEMENTS */
    (void)flags; /* For non-elements builds */
    return ret;
}

int dogecoin_psbt_from_bytes(const unsigned char *bytes, size_t len,
                          uint32_t flags, struct dogecoin_psbt **output)
{
    const unsigned char **cursor = &bytes;
    const unsigned char *pre_key;
    size_t *max = &len, i, key_len, input_count = 0, output_count = 0;
    uint32_t tx_flags = 0, pre144flag = DOGECOIN_TX_FLAG_PRE_BIP144;
    uint64_t mandatory, disallowed, keyset = 0;
    bool is_pset = false;
    int ret = DOGECOIN_OK;

    OUTPUT_CHECK;
    if (!bytes || len < sizeof(PSBT_MAGIC) || (flags & ~PSBT_ALL_PARSE_FLAGS) || !output)
        return DOGECOIN_EINVAL;

    if (!(*output = pull_psbt(cursor, max)))
        return DOGECOIN_EINVAL;

    if (memcmp((*output)->magic, PSBT_MAGIC, sizeof(PSBT_MAGIC))) {
        is_pset = true;
        tx_flags |= DOGECOIN_TX_FLAG_USE_ELEMENTS; /* Elements PSET */
        pre144flag = 0;
    }
    /* Reset modifiable flags for loaded PSBTs */
    (*output)->tx_modifiable_flags = 0;
#ifdef BUILD_ELEMENTS
    (*output)->pset_modifiable_flags = 0;
#endif /* BUILD_ELEMENTS */

    /* Read globals first */
    pre_key = *cursor;
    while (ret == DOGECOIN_OK && (key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key;
        bool is_pset_ft;
        uint64_t field_type = pull_field_type(cursor, max, &key, &key_len, is_pset, &is_pset_ft);
        uint64_t field_bit;
        bool is_known;

        if (is_pset_ft) {
            is_known = field_type <= PSET_GLOBAL_MAX;
            if (is_known) {
                field_type = PSET_FT(field_type);
                field_bit = field_type;
            }
        } else {
            is_known = field_type <= PSBT_GLOBAL_MAX || field_type == PSBT_GLOBAL_VERSION;
            if (is_known) {
                if (field_type == PSBT_GLOBAL_VERSION)
                    field_bit = PSBT_GLOBAL_VERSION_BIT;
                else
                    field_bit = PSBT_FT(field_type);
            }
        }

        /* Process based on type */
        if (is_known) {
            struct libdogecoin_tx *tx = NULL;

            if (keyset & field_bit && (!(field_bit & PSBT_GLOBAL_REPEATABLE))) {
                ret = DOGECOIN_EINVAL; /* Duplicate value */
                break;
            }
            keyset |= field_bit;
            if (field_bit & PSBT_GLOBAL_HAVE_KEYDATA)
                pull_subfield_end(cursor, max, key, key_len);
            else
                subfield_nomore_end(cursor, max, key, key_len);

            switch (field_type) {
            case PSBT_GLOBAL_UNSIGNED_TX:
                if ((ret = pull_tx(cursor, max, tx_flags | pre144flag, &tx)) == DOGECOIN_OK)
                    ret = psbt_set_global_tx(*output, tx, false);
                if (ret != DOGECOIN_OK)
                    libdogecoin_tx_free(tx);
                break;
            case PSBT_GLOBAL_XPUB:
                ret = pull_map_item(cursor, max, key, key_len, &(*output)->global_xpubs);
                break;
            case PSBT_GLOBAL_VERSION:
                (*output)->version = pull_le32_subfield(cursor, max);
                if ((*output)->version != PSBT_0 && (*output)->version != PSBT_2)
                    ret = DOGECOIN_EINVAL; /* Unsupported version number */
                break;
            case PSBT_GLOBAL_INPUT_COUNT:
                input_count = pull_varint_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_OUTPUT_COUNT:
                output_count = pull_varint_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_TX_VERSION:
                (*output)->tx_version = pull_le32_subfield(cursor, max);
                break;
            case PSBT_GLOBAL_FALLBACK_LOCKTIME:
                (*output)->fallback_locktime = pull_le32_subfield(cursor, max);
                (*output)->has_fallback_locktime = 1u;
                break;
            case PSBT_GLOBAL_TX_MODIFIABLE:
                (*output)->tx_modifiable_flags = pull_u8_subfield(cursor, max);
                if ((*output)->tx_modifiable_flags & ~PSBT_TXMOD_ALL_FLAGS)
                    ret = DOGECOIN_EINVAL; /* Invalid flags */
                break;
#ifdef BUILD_ELEMENTS
            case PSET_FT(PSET_GLOBAL_SCALAR): {
                const unsigned char *workaround;
                size_t workaround_len;

                /* Work around an elements bug with scalars */
                pull_varlength_buff(cursor, max, &workaround, &workaround_len);
                ret = map_add(&(*output)->global_scalars, key, key_len, NULL, 0, false, false);
                break;
            }
            case PSET_FT(PSET_GLOBAL_TX_MODIFIABLE):
                (*output)->pset_modifiable_flags = pull_u8_subfield(cursor, max);
                /* Ignore the reserved flag if set */
                (*output)->pset_modifiable_flags &= ~DOGECOIN_PSET_TXMOD_RESERVED;
                if ((*output)->pset_modifiable_flags & ~PSET_TXMOD_ALL_FLAGS)
                    ret = DOGECOIN_EINVAL; /* Invalid flags */
                break;
#endif /* BUILD_ELEMENTS */
            default:
                goto unknown;
            }
        } else {
unknown:
            ret = pull_unknown_key_value(cursor, max, pre_key, &(*output)->unknowns);
        }
        pre_key = *cursor;
    }

    mandatory = (*output)->version == PSBT_0 ? PSBT_GLOBAL_MANDATORY_V0 : PSBT_GLOBAL_MANDATORY_V2;
    disallowed = (*output)->version == PSBT_0 ? PSBT_GLOBAL_DISALLOWED_V0 : PSBT_GLOBAL_DISALLOWED_V2;
    if (!is_pset) {
        /* PSBT: Remove mandatory/disallowed PSET fields */
        mandatory &= PSBT_FT_MASK;
        disallowed &= PSBT_FT_MASK;
    }
    if (mandatory && (keyset & mandatory) != mandatory)
        ret = DOGECOIN_EINVAL; /* Mandatory field is missing*/
    else if (disallowed && (keyset & disallowed))
        ret = DOGECOIN_EINVAL; /* Disallowed field present */

    if (ret == DOGECOIN_OK && (*output)->version == PSBT_2) {
        if ((*output)->tx_version < 2)
            ret = DOGECOIN_EINVAL; /* Tx version must be >= 2 */
        else {
            struct dogecoin_psbt tmp;
            ret = dogecoin_psbt_init((*output)->version, input_count, output_count, 0, 0, &tmp);
            if (ret == DOGECOIN_OK) {
                /* Steal the allocated input/output arrays */
                (*output)->inputs = tmp.inputs;
                (*output)->inputs_allocation_len = tmp.inputs_allocation_len;
                (*output)->outputs = tmp.outputs;
                (*output)->outputs_allocation_len = tmp.outputs_allocation_len;
                psbt_claim_allocated_inputs(*output, input_count, output_count);
            }
        }
    }

    /* Read inputs */
    for (i = 0; ret == DOGECOIN_OK && i < (*output)->num_inputs; ++i)
        ret = pull_psbt_input(*output, cursor, max, tx_flags,flags,
                              (*output)->inputs + i);

    /* Read outputs */
    for (i = 0; ret == DOGECOIN_OK && i < (*output)->num_outputs; ++i)
        ret = pull_psbt_output(*output, cursor, max, tx_flags, flags,
                               (*output)->outputs + i);

    if (ret == DOGECOIN_OK && !*cursor)
        ret = DOGECOIN_EINVAL; /* Ran out of data */

    if (ret != DOGECOIN_OK) {
        dogecoin_psbt_free(*output);
        *output = NULL;
    }
    return ret;
}

int dogecoin_psbt_get_length(const struct dogecoin_psbt *psbt, uint32_t flags, size_t *written)
{
    return dogecoin_psbt_to_bytes(psbt, flags, NULL, 0, written);
}

static void push_psbt_key(unsigned char **cursor, size_t *max,
                          uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(type) + extra_len);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}

#ifdef BUILD_ELEMENTS
static void push_pset_key(unsigned char **cursor, size_t *max,
                          uint64_t type, const void *extra, size_t extra_len)
{
    const size_t prefix_len = 6u; /* PROPRIETARY_TYPE + len("pset") + "pset" */
    push_varint(cursor, max, prefix_len + varint_get_length(type) + extra_len);
    push_varint(cursor, max, DOGECOIN_PSBT_PROPRIETARY_TYPE);
    push_varbuff(cursor, max, PSET_MAGIC, PSET_PREFIX_LEN);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}
#endif /* BUILD_ELEMENTS */

static void push_key(unsigned char **cursor, size_t *max,
                     uint64_t type, bool is_pset,
                     const void *extra, size_t extra_len)
{
    (void)is_pset;
#ifdef BUILD_ELEMENTS
    if (is_pset)
        push_pset_key(cursor, max, type, extra, extra_len);
    else
#endif
    push_psbt_key(cursor, max, type, extra, extra_len);
}

static int push_length_and_tx(unsigned char **cursor, size_t *max,
                              const struct libdogecoin_tx *tx, uint32_t flags)
{
    int ret;
    size_t tx_len;
    unsigned char *p;

    if ((ret = libdogecoin_tx_get_length(tx, flags, &tx_len)) != DOGECOIN_OK)
        return ret;

    push_varint(cursor, max, tx_len);

    /* TODO: convert libdogecoin_tx to use push  */
    if (!(p = push_bytes(cursor, max, NULL, tx_len)))
        return DOGECOIN_OK; /* We catch this in caller. */

    return libdogecoin_tx_to_bytes(tx, flags, p, tx_len, &tx_len);
}

static void push_witness_stack_impl(unsigned char **cursor, size_t *max,
                                    const struct libdogecoin_tx_witness_stack *witness)
{
    size_t i;

    push_varint(cursor, max, witness->num_items);
    for (i = 0; i < witness->num_items; ++i) {
        push_varbuff(cursor, max, witness->items[i].witness,
                     witness->items[i].witness_len);
    }
}

static void push_witness_stack(unsigned char **cursor, size_t *max,
                               uint64_t type, bool is_pset,
                               const struct libdogecoin_tx_witness_stack *witness)
{
    size_t wit_len = 0;
    push_witness_stack_impl(NULL, &wit_len, witness); /* calculate length */

    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, wit_len);
    push_witness_stack_impl(cursor, max, witness);
}

static void push_psbt_varbuff(unsigned char **cursor, size_t *max,
                              uint64_t type, bool is_pset,
                              const unsigned char *bytes, size_t bytes_len)
{
    if (bytes) {
        push_key(cursor, max, type, is_pset, NULL, 0);
        push_varbuff(cursor, max, bytes, bytes_len);
    }
}

static void push_psbt_le32(unsigned char **cursor, size_t *max,
                           uint64_t type, bool is_pset, uint32_t value)
{
    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, sizeof(value));
    push_le32(cursor, max, value);
}

static void push_psbt_le64(unsigned char **cursor, size_t *max,
                           uint64_t type, bool is_pset, uint64_t value)
{
    push_key(cursor, max, type, is_pset, NULL, 0);
    push_varint(cursor, max, sizeof(value));
    push_le64(cursor, max, value);
}

static void push_map(unsigned char **cursor, size_t *max,
                     const struct dogecoin_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct dogecoin_map_item *item = map_in->items + i;
        push_varbuff(cursor, max, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static void push_psbt_map(unsigned char **cursor, size_t *max,
                          uint64_t type, bool is_pset,
                          const struct dogecoin_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct dogecoin_map_item *item = map_in->items + i;
        push_key(cursor, max, type, is_pset, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static int push_preimages(unsigned char **cursor, size_t *max,
                          const struct dogecoin_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct dogecoin_map_item *item = map_in->items + i;
        const uint64_t type = item->key[0];

        push_key(cursor, max, type, false, item->key + 1, item->key_len - 1);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return DOGECOIN_OK;
}

static int push_taproot_leaf_signatures(unsigned char **cursor, size_t *max, size_t ft,
                                        const struct dogecoin_map *leaf_sigs)
{
    size_t i;

    for (i = 0; i < leaf_sigs->num_items; ++i) {
        const struct dogecoin_map_item *item = leaf_sigs->items + i;
        push_key(cursor, max, ft, false, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return DOGECOIN_OK;
}

static int push_taproot_leaf_scripts(unsigned char **cursor, size_t *max, size_t ft,
                                     const struct dogecoin_map *leaf_scripts)
{
    size_t i;

    for (i = 0; i < leaf_scripts->num_items; ++i) {
        const struct dogecoin_map_item *item = leaf_scripts->items + i;

        if (!is_valid_control_block_len(item->key_len) || !item->value_len)
            return DOGECOIN_EINVAL;

        push_key(cursor, max, ft, false, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
    return DOGECOIN_OK;
}

static size_t get_taproot_derivation_size(size_t num_hashes, size_t path_len)
{
    return varint_get_length(num_hashes) + num_hashes * SHA256_LEN +
           sizeof(uint32_t) + path_len * sizeof(uint32_t);
}

static int push_taproot_derivation(unsigned char **cursor, size_t *max, size_t ft,
                                   const struct dogecoin_map *leaf_hashes,
                                   const struct dogecoin_map *leaf_paths)
{
    size_t i, index, num_hashes, num_children;
    const struct dogecoin_map_item *hashes, *path;
    int ret;

    for (i = 0; i < leaf_paths->num_items; ++i) {
        /* Find the hashes to write with this xonly keys path */
        path = leaf_paths->items + i;
        if (path->value_len < sizeof(uint32_t) || path->value_len % sizeof(uint32_t))
            return DOGECOIN_EINVAL; /* Invalid fingerprint + path */

        ret = dogecoin_map_find(leaf_hashes, path->key, path->key_len, &index);
        if (ret != DOGECOIN_OK || !index)
            return DOGECOIN_EINVAL; /* Corresponding hashes not found */

        hashes = leaf_hashes->items + index - 1;
        num_hashes = hashes->value_len / SHA256_LEN;
        num_children = path->value_len / sizeof(uint32_t) - 1;

        /* Key is the x-only pubkey */
        push_key(cursor, max, ft, false, path->key, path->key_len);
        /* Compute and write the length of the associated data */
        push_varint(cursor, max, get_taproot_derivation_size(num_hashes, num_children));
        /* <hashes len> <leaf hash>* */
        push_varint(cursor, max, num_hashes); /* Not the length as BIP371 suggests */
        push_bytes(cursor, max, hashes->value, hashes->value_len);
        /* <4 byte fingerprint> <32-bit uint>* */
        push_bytes(cursor, max, path->value, path->value_len);
    }
    return DOGECOIN_OK;
}

#ifdef BUILD_ELEMENTS
static bool push_commitment(unsigned char **cursor, size_t *max,
                            const unsigned char *commitment, size_t commitment_len)
{
    if (!BYTES_VALID(commitment, commitment_len))
        return false;
    if (!commitment)
        push_u8(cursor, max, 0); /* NULL commitment */
    else
        push_bytes(cursor, max, commitment, commitment_len);
    return true;
}
#endif /* BUILD_ELEMENTS */

static int push_tx_output(unsigned char **cursor, size_t *max,
                          bool is_pset, const struct libdogecoin_tx_output *txout)
{
#ifdef BUILD_ELEMENTS
    if (is_pset) {
        if (!push_commitment(cursor, max, txout->asset, txout->asset_len) ||
            !push_commitment(cursor, max, txout->value, txout->value_len) ||
            !push_commitment(cursor, max, txout->nonce, txout->nonce_len))
            return DOGECOIN_EINVAL;
        push_varbuff(cursor, max, txout->script, txout->script_len);
    } else
#endif /* BUILD_ELEMENTS */
    {
        (void)is_pset;
        push_le64(cursor, max, txout->satoshi);
        push_varbuff(cursor, max, txout->script, txout->script_len);
    }
    return DOGECOIN_OK;
}

static int push_varbuff_from_map(unsigned char **cursor, size_t *max,
                                 uint64_t type, uint32_t key, bool is_pset,
                                 const struct dogecoin_map *map_in)
{
    size_t index;
    int ret = dogecoin_map_find_integer(map_in, key, &index);
    if (ret == DOGECOIN_OK && index) {
        const struct dogecoin_map_item *item = map_in->items + index - 1;
        push_psbt_varbuff(cursor, max, type, is_pset,
                          item->value, item->value_len);
    }
    return ret;
}

static int push_psbt_input(const struct dogecoin_psbt *psbt,
                           unsigned char **cursor, size_t *max,
                           uint32_t tx_flags, uint32_t flags,
                           const struct dogecoin_psbt_input *input)
{
    const bool is_pset = (tx_flags & DOGECOIN_TX_FLAG_USE_ELEMENTS) != 0;
    int ret;
    const struct dogecoin_map_item *final_scriptsig;

    /* Non witness utxo */
    if (input->utxo) {
        push_psbt_key(cursor, max, PSBT_IN_NON_WITNESS_UTXO, NULL, 0);
        if ((ret = push_length_and_tx(cursor, max,
                                      input->utxo,
                                      DOGECOIN_TX_FLAG_USE_WITNESS)) != DOGECOIN_OK)
            return ret;
    }

    /* Witness utxo */
    if (input->witness_utxo) {
        size_t txout_len = 0;
        push_psbt_key(cursor, max, PSBT_IN_WITNESS_UTXO, NULL, 0);
        /* Push the txout length then its contents */
        ret = push_tx_output(NULL, &txout_len, is_pset, input->witness_utxo);
        if (ret == DOGECOIN_OK) {
            push_varint(cursor, max, txout_len);
            ret = push_tx_output(cursor, max, is_pset, input->witness_utxo);
        }
        if (ret != DOGECOIN_OK)
            return ret;
    }

    final_scriptsig = dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG);
    if ((!input->final_witness && !final_scriptsig) ||
        (flags & DOGECOIN_PSBT_SERIALIZE_FLAG_REDUNDANT)) {
        /* BIP-0174 is clear that once finalized, these members should be
         * removed from the PSBT and therefore obviously not serialized.
         * If an input is finalized eternally (by setting final_witness/
         * final_scriptsig directly), then these fields may still be present
         * in the PSBT. By default, wally will not serialize them in that case
         * unless DOGECOIN_PSBT_SERIALIZE_FLAG_REDUNDANT is given, since doing so
         * violates the spec and makes the PSBT unnecessarily larger.
         * DOGECOIN_PSBT_SERIALIZE_FLAG_REDUNDANT is supported to allow matching
         * the buggy behaviour of other implementations, since it seems there
         * is already code incorrectly relying on this behaviour in the wild.
         */
        /* Partial sigs */
        push_psbt_map(cursor, max, PSBT_IN_PARTIAL_SIG, false, &input->signatures);
        /* Sighash type */
        if (input->sighash)
            push_psbt_le32(cursor, max, PSBT_IN_SIGHASH_TYPE, false, input->sighash);

        if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_REDEEM_SCRIPT,
                                         PSBT_IN_REDEEM_SCRIPT,
                                         false, &input->psbt_fields)) != DOGECOIN_OK)
            return ret;

        if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_WITNESS_SCRIPT,
                                         PSBT_IN_WITNESS_SCRIPT,
                                         false, &input->psbt_fields)) != DOGECOIN_OK)
            return ret;

        /* Keypaths */
        push_psbt_map(cursor, max, PSBT_IN_BIP32_DERIVATION, false, &input->keypaths);
    }

    if (final_scriptsig)
        push_psbt_varbuff(cursor, max, PSBT_IN_FINAL_SCRIPTSIG, false,
                          final_scriptsig->value, final_scriptsig->value_len);

    /* Final scriptWitness */
    if (input->final_witness)
        push_witness_stack(cursor, max, PSBT_IN_FINAL_SCRIPTWITNESS,
                           false, input->final_witness);

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_POR_COMMITMENT,
                                     PSBT_IN_POR_COMMITMENT,
                                     false, &input->psbt_fields)) != DOGECOIN_OK)
        return ret;

    if ((ret = push_preimages(cursor, max, &input->preimages)) != DOGECOIN_OK)
        return ret;

    if (psbt->version == PSBT_2) {
        if (mem_is_zero(input->txhash, DOGECOIN_TXHASH_LEN))
            return DOGECOIN_EINVAL; /* No previous txid provided */
        push_psbt_varbuff(cursor, max, PSBT_IN_PREVIOUS_TXID, false,
                          input->txhash, sizeof(input->txhash));

        push_psbt_le32(cursor, max, PSBT_IN_OUTPUT_INDEX, false, input->index);

        if (input->sequence != DOGECOIN_TX_SEQUENCE_FINAL)
            push_psbt_le32(cursor, max, PSBT_IN_SEQUENCE, false, input->sequence);

        if (input->required_locktime)
            push_psbt_le32(cursor, max, PSBT_IN_REQUIRED_TIME_LOCKTIME, false, input->required_locktime);

        if (input->required_lockheight)
            push_psbt_le32(cursor, max, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, false, input->required_lockheight);
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_KEY_SIG,
                                     PSBT_IN_TAP_KEY_SIG,
                                     false, &input->psbt_fields)) != DOGECOIN_OK)
        return ret;

    if ((ret = push_taproot_leaf_signatures(cursor, max, PSBT_IN_TAP_SCRIPT_SIG,
                                            &input->taproot_leaf_signatures)) != DOGECOIN_OK)
        return ret;

    if ((ret = push_taproot_leaf_scripts(cursor, max, PSBT_IN_TAP_LEAF_SCRIPT,
                                         &input->taproot_leaf_scripts)) != DOGECOIN_OK)
        return ret;

    if (input->taproot_leaf_hashes.num_items) {
        ret = push_taproot_derivation(cursor, max, PSBT_IN_TAP_BIP32_DERIVATION,
                                      &input->taproot_leaf_hashes,
                                      &input->taproot_leaf_paths);
        if (ret != DOGECOIN_OK)
            return ret;
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_INTERNAL_KEY,
                                     PSBT_IN_TAP_INTERNAL_KEY,
                                     false, &input->psbt_fields)) != DOGECOIN_OK)
        return ret;
    if ((ret = push_varbuff_from_map(cursor, max, PSBT_IN_TAP_MERKLE_ROOT,
                                     PSBT_IN_TAP_MERKLE_ROOT,
                                     false, &input->psbt_fields)) != DOGECOIN_OK)
        return ret;

#ifdef BUILD_ELEMENTS
    if (is_pset && psbt->version == PSBT_2) {
        uint32_t ft;
        for (ft = PSET_IN_ISSUANCE_VALUE; ft <= PSET_IN_MAX; ++ft) {
            switch (ft) {
            case PSET_IN_EXPLICIT_VALUE:
                /* Note we only output an explicit value if we have its proof */
                if (input->has_amount && dogecoin_map_get_integer(&input->pset_fields, PSET_IN_VALUE_PROOF))
                    push_psbt_le64(cursor, max, ft, true, input->amount);
                break;
            case PSET_IN_ISSUANCE_VALUE:
                if (input->issuance_amount)
                    push_psbt_le64(cursor, max, ft, true, input->issuance_amount);
                break;
            case PSET_IN_PEG_IN_TX:
                if (input->pegin_tx) {
                    push_key(cursor, max, ft, true, NULL, 0);
                    if ((ret = push_length_and_tx(cursor, max, input->pegin_tx,
                                                  DOGECOIN_TX_FLAG_USE_WITNESS)) != DOGECOIN_OK)
                        return ret;
                }
                break;
            case PSET_IN_PEG_IN_VALUE:
                if (input->pegin_amount)
                    push_psbt_le64(cursor, max, ft, true, input->pegin_amount);
                break;
            case PSET_IN_PEG_IN_WITNESS:
                if (input->pegin_witness)
                    push_witness_stack(cursor, max, ft,
                                       true, input->pegin_witness);
                break;
            case PSET_IN_ISSUANCE_INFLATION_KEYS_AMOUNT:
                if (input->inflation_keys)
                    push_psbt_le64(cursor, max, ft, true, input->inflation_keys);
                break;
            default:
                ret = push_varbuff_from_map(cursor, max, ft, ft, true,
                                            &input->pset_fields);
                if (ret != DOGECOIN_OK)
                    return ret;
                break;
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    /* Unknowns */
    push_map(cursor, max, &input->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return DOGECOIN_OK;
}

static int push_psbt_output(const struct dogecoin_psbt *psbt,
                            unsigned char **cursor, size_t *max, bool is_pset,
                            const struct dogecoin_psbt_output *output)
{
    size_t i;
    unsigned char dummy = 0;
    int ret;

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_REDEEM_SCRIPT,
                                     PSBT_OUT_REDEEM_SCRIPT,
                                     false, &output->psbt_fields)) != DOGECOIN_OK)
        return ret;

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_WITNESS_SCRIPT,
                                     PSBT_OUT_WITNESS_SCRIPT,
                                     false, &output->psbt_fields)) != DOGECOIN_OK)
        return ret;

    /* Keypaths */
    push_psbt_map(cursor, max, PSBT_OUT_BIP32_DERIVATION, false, &output->keypaths);

    if (psbt->version == PSBT_2) {
        if (!is_pset && (!output->has_amount || !output->script || !output->script_len))
            return DOGECOIN_EINVAL; /* Must be provided */

        if (output->has_amount)
            push_psbt_le64(cursor, max, PSBT_OUT_AMOUNT, false, output->amount);

        /* Core/Elements always write the script; if missing its written as empty */
        push_psbt_varbuff(cursor, max, PSBT_OUT_SCRIPT, false,
                          output->script ? output->script : &dummy,
                          output->script_len);
    }

    if ((ret = push_varbuff_from_map(cursor, max, PSBT_OUT_TAP_INTERNAL_KEY,
                                     PSBT_OUT_TAP_INTERNAL_KEY,
                                     false, &output->psbt_fields)) != DOGECOIN_OK)
        return ret;

    for (i = 0; i < output->taproot_tree.num_items; ++i) {
        ret = push_varbuff_from_map(cursor, max, PSBT_OUT_TAP_TREE, i + 1,
                                    false, &output->taproot_tree);
        if (ret != DOGECOIN_OK)
            return ret;
    }

    if (output->taproot_leaf_hashes.num_items) {
        ret = push_taproot_derivation(cursor, max, PSBT_OUT_TAP_BIP32_DERIVATION,
                                      &output->taproot_leaf_hashes,
                                      &output->taproot_leaf_paths);
        if (ret != DOGECOIN_OK)
            return ret;
    }

#ifdef BUILD_ELEMENTS
    if (is_pset && psbt->version == PSBT_2) {
        uint32_t ft;
        for (ft = PSET_OUT_VALUE_COMMITMENT; ft <= PSET_OUT_MAX; ++ft) {
            switch (ft) {
            case PSET_OUT_BLINDER_INDEX:
                if (output->has_blinder_index)
                    push_psbt_le32(cursor, max, ft, true, output->blinder_index);
                break;
            default:
                ret = push_varbuff_from_map(cursor, max, ft, ft, true,
                                            &output->pset_fields);
                if (ret != DOGECOIN_OK)
                    return ret;
                break;
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    /* Unknowns */
    push_map(cursor, max, &output->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return DOGECOIN_OK;
}

int dogecoin_psbt_to_bytes(const struct dogecoin_psbt *psbt, uint32_t flags,
                        unsigned char *bytes_out, size_t len,
                        size_t *written)
{
    unsigned char *cursor = bytes_out;
    size_t max = len, i, is_pset;
    uint32_t tx_flags;
    int ret;

    if (written)
        *written = 0;

    if (!psbt_is_valid(psbt) || flags & ~DOGECOIN_PSBT_SERIALIZE_FLAG_REDUNDANT ||
        !written)
        return DOGECOIN_EINVAL;

    if ((ret = dogecoin_psbt_is_elements(psbt, &is_pset)) != DOGECOIN_OK)
        return ret;

    tx_flags = is_pset ? DOGECOIN_TX_FLAG_USE_ELEMENTS : 0;
    push_bytes(&cursor, &max, psbt->magic, sizeof(psbt->magic));

    /* Global tx */
    if (psbt->tx) {
        push_psbt_key(&cursor, &max, PSBT_GLOBAL_UNSIGNED_TX, NULL, 0);
        ret = push_length_and_tx(&cursor, &max, psbt->tx,
                                 DOGECOIN_TX_FLAG_ALLOW_PARTIAL | DOGECOIN_TX_FLAG_PRE_BIP144);
        if (ret != DOGECOIN_OK)
            return ret;
    }
    /* Global XPubs */
    push_psbt_map(&cursor, &max, PSBT_GLOBAL_XPUB, false, &psbt->global_xpubs);

    if (psbt->version == PSBT_2) {
        size_t n;
        unsigned char buf[sizeof(uint8_t) + sizeof(uint64_t)];

        push_psbt_le32(&cursor, &max, PSBT_GLOBAL_TX_VERSION, false, psbt->tx_version);

        if (psbt->has_fallback_locktime)
            push_psbt_le32(&cursor, &max, PSBT_GLOBAL_FALLBACK_LOCKTIME, false, psbt->fallback_locktime);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_INPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_inputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_OUTPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_outputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        if (psbt->tx_modifiable_flags) {
            push_psbt_key(&cursor, &max, PSBT_GLOBAL_TX_MODIFIABLE, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint8_t));
            push_u8(&cursor, &max, psbt->tx_modifiable_flags & 0xff);
        }
#ifdef BUILD_ELEMENTS
        push_psbt_map(&cursor, &max, PSET_GLOBAL_SCALAR, true, &psbt->global_scalars);

        if (psbt->pset_modifiable_flags) {
            push_key(&cursor, &max, PSET_GLOBAL_TX_MODIFIABLE, true, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint8_t));
            push_u8(&cursor, &max, psbt->pset_modifiable_flags);
        }
#endif /* BUILD_ELEMENTS */
    }

    if (psbt->version == PSBT_2)
        push_psbt_le32(&cursor, &max, PSBT_GLOBAL_VERSION, false, psbt->version);

    /* Unknowns */
    push_map(&cursor, &max, &psbt->unknowns);

    /* Separator */
    push_u8(&cursor, &max, PSBT_SEPARATOR);

    /* Push each input and output */
    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct dogecoin_psbt_input *input = &psbt->inputs[i];
        if ((ret = push_psbt_input(psbt, &cursor, &max, tx_flags, flags, input)) != DOGECOIN_OK)
            return ret;
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        const struct dogecoin_psbt_output *output = &psbt->outputs[i];
        if ((ret = push_psbt_output(psbt, &cursor, &max, !!is_pset, output)) != DOGECOIN_OK)
            return ret;
    }

    if (cursor == NULL) {
        /* Once cursor is NULL, max holds how many bytes we needed */
        *written = len + max;
    } else {
        *written = len - max;
    }

    return DOGECOIN_OK;
}

int dogecoin_psbt_from_base64(const char *base64, uint32_t flags, struct dogecoin_psbt **output)
{
    unsigned char *decoded;
    size_t max_len, written;
    int ret;

    OUTPUT_CHECK;
    if ((ret = dogecoin_base64_get_maximum_length(base64, 0, &max_len)) != DOGECOIN_OK)
        return ret;

    /* Allocate the buffer to decode into */
    if ((decoded = dogecoin_malloc(max_len)) == NULL)
        return DOGECOIN_ENOMEM;

    /* Decode the base64 psbt into binary */
    if ((ret = dogecoin_base64_to_bytes(base64, 0, decoded, max_len, &written)) != DOGECOIN_OK)
        goto done;

    if (written <= sizeof(PSBT_MAGIC)) {
        ret = DOGECOIN_EINVAL; /* Not enough bytes for the magic + any data */
        goto done;
    }
    if (written > max_len) {
        ret = DOGECOIN_ERROR; /* Max len too small, should never happen! */
        goto done;
    }

    /* decode the psbt */
    ret = dogecoin_psbt_from_bytes(decoded, written, flags, output);

done:
    clear_and_free(decoded, max_len);
    return ret;
}

int dogecoin_psbt_to_base64(const struct dogecoin_psbt *psbt, uint32_t flags, char **output)
{
    unsigned char *buff;
    size_t len, written;
    int ret;

    OUTPUT_CHECK;

    if ((ret = dogecoin_psbt_get_length(psbt, flags, &len)) != DOGECOIN_OK)
        return ret;

    if ((buff = dogecoin_malloc(len)) == NULL)
        return DOGECOIN_ENOMEM;

    /* Get psbt bytes */
    if ((ret = dogecoin_psbt_to_bytes(psbt, flags, buff, len, &written)) != DOGECOIN_OK)
        goto done;

    if (written != len) {
        ret = DOGECOIN_ERROR; /* Length calculated incorrectly */
        goto done;
    }

    /* Base64 encode */
    ret = dogecoin_base64_from_bytes(buff, len, 0, output);

done:
    clear_and_free(buff, len);
    return ret;
}

static int combine_txs(struct libdogecoin_tx **dst, struct libdogecoin_tx *src)
{
    if (!dst)
        return DOGECOIN_EINVAL;

    if (!*dst && src)
        return tx_clone_alloc(src, dst);

    return DOGECOIN_OK;
}

static int combine_map_if_empty(struct dogecoin_map *dst, const struct dogecoin_map *src)
{
    if (!dst->num_items && src->num_items)
        return dogecoin_map_combine(dst, src);
    return DOGECOIN_OK;
}

#ifdef BUILD_ELEMENTS
static int combine_map_item(struct dogecoin_map *dst, const struct dogecoin_map *src, uint32_t ft)
{
    if (!dogecoin_map_get_integer(dst, ft)) {
        const struct dogecoin_map_item *src_item;
        if ((src_item = dogecoin_map_get_integer(src, ft)))
            return dogecoin_map_add_integer(dst, ft, src_item->value, src_item->value_len);
    }
    return DOGECOIN_OK;
}

static int merge_value_commitment(struct dogecoin_map *dst_fields, uint64_t *dst_amount,
                                  const struct dogecoin_map *src_fields, uint64_t src_amount,
                                  uint32_t ft, bool for_clone)
{
    const struct dogecoin_map_item *dst_commitment, *src_commitment;
    bool have_dst_commitment, have_src_commitment;
    int ret;

    dst_commitment = dogecoin_map_get_integer(dst_fields, ft);
    have_dst_commitment = dst_commitment && dst_commitment->value_len != 1u;
    src_commitment = dogecoin_map_get_integer(src_fields, ft);
    have_src_commitment = src_commitment && src_commitment->value_len != 1u;

    if (for_clone || (!*dst_amount && !have_dst_commitment && src_amount)) {
        /* We don't have an amount or a commitment for one, copy source amount */
        *dst_amount = src_amount;
    }
    if (!have_dst_commitment && have_src_commitment) {
        /* Source has an amount commitment, copy it and clear our value */
        ret = dogecoin_map_replace_integer(dst_fields, ft,
                                        src_commitment->value, src_commitment->value_len);
        if (ret != DOGECOIN_OK)
            return ret;
        if (!for_clone) {
            /* Not cloning: clear the amount when we have a committment to it */
            *dst_amount = 0;
        }
    }
    return DOGECOIN_OK;
}
#endif /* BUILD_ELEMENTS */

static int combine_input(struct dogecoin_psbt_input *dst,
                         const struct dogecoin_psbt_input *src,
                         bool is_pset, bool for_clone)
{
    int ret;

    if (for_clone && mem_is_zero(dst->txhash, DOGECOIN_TXHASH_LEN)) {
        memcpy(dst->txhash, src->txhash, DOGECOIN_TXHASH_LEN);
        dst->index = src->index;
    } else if (memcmp(dst->txhash, src->txhash, DOGECOIN_TXHASH_LEN) ||
               dst->index != src->index)
        return DOGECOIN_EINVAL; /* Mismatched inputs */

    if (dst->sequence == DOGECOIN_TX_SEQUENCE_FINAL)
        dst->sequence = src->sequence;

    if ((ret = combine_txs(&dst->utxo, src->utxo)) != DOGECOIN_OK)
        return ret;

    if (!dst->witness_utxo && src->witness_utxo) {
        ret = libdogecoin_tx_output_clone_alloc(src->witness_utxo, &dst->witness_utxo);
        if (ret != DOGECOIN_OK)
            return ret;
    }

    if (!dst->final_witness && src->final_witness &&
        (ret = dogecoin_psbt_input_set_final_witness(dst, src->final_witness)) != DOGECOIN_OK)
        return ret;
    if ((ret = dogecoin_map_combine(&dst->keypaths, &src->keypaths)) != DOGECOIN_OK)
        return ret;
    if ((ret = dogecoin_map_combine(&dst->signatures, &src->signatures)) != DOGECOIN_OK)
        return ret;
    if ((ret = dogecoin_map_combine(&dst->unknowns, &src->unknowns)) != DOGECOIN_OK)
        return ret;
    if (!dst->sighash && src->sighash)
        dst->sighash = src->sighash;
    if (!dst->required_locktime && src->required_locktime)
        dst->required_locktime = src->required_locktime;
    if (!dst->required_lockheight && src->required_lockheight)
        dst->required_lockheight = src->required_lockheight;
    if ((ret = dogecoin_map_combine(&dst->preimages, &src->preimages)) != DOGECOIN_OK)
        return ret;
    if ((ret = dogecoin_map_combine(&dst->psbt_fields, &src->psbt_fields)) != DOGECOIN_OK)
        return ret;
    if ((ret = combine_map_if_empty(&dst->taproot_leaf_signatures, &src->taproot_leaf_signatures)) != DOGECOIN_OK)
        return ret;
    if ((ret = combine_map_if_empty(&dst->taproot_leaf_scripts, &src->taproot_leaf_scripts)) != DOGECOIN_OK)
        return ret;
    if (!dst->taproot_leaf_hashes.num_items && !dst->taproot_leaf_paths.num_items &&
        src->taproot_leaf_hashes.num_items && src->taproot_leaf_paths.num_items) {
        ret = dogecoin_map_combine(&dst->taproot_leaf_hashes, &src->taproot_leaf_hashes);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_map_combine(&dst->taproot_leaf_paths, &src->taproot_leaf_paths);
    }
    if (ret == DOGECOIN_OK && is_pset) {
#ifdef BUILD_ELEMENTS
        uint32_t ft;
        if (ret == DOGECOIN_OK && !dst->has_amount && src->has_amount) {
            dst->amount = src->amount;
            dst->has_amount = 1u;
        }

        if (ret == DOGECOIN_OK)
            ret = merge_value_commitment(&dst->pset_fields, &dst->issuance_amount,
                                         &src->pset_fields, src->issuance_amount,
                                         PSET_IN_ISSUANCE_VALUE_COMMITMENT, for_clone);

        if (ret == DOGECOIN_OK)
            ret = merge_value_commitment(&dst->pset_fields, &dst->inflation_keys,
                                         &src->pset_fields, src->inflation_keys,
                                         PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT, for_clone);
        if (ret == DOGECOIN_OK && !dst->pegin_amount && src->pegin_amount)
            dst->pegin_amount = src->pegin_amount;

        if (ret == DOGECOIN_OK)
            ret = combine_txs(&dst->pegin_tx, src->pegin_tx);

        if (ret == DOGECOIN_OK && !dst->pegin_witness && src->pegin_witness)
            ret = dogecoin_psbt_input_set_pegin_witness(dst, src->pegin_witness);

        for (ft = 0; ret == DOGECOIN_OK && ft <= PSET_IN_MAX; ++ft) {
            if (PSET_IN_MERGEABLE & PSET_FT(ft))
                ret = combine_map_item(&dst->pset_fields, &src->pset_fields, ft);
        }
#endif /* BUILD_ELEMENTS */
    }
    return ret;
}

static int combine_output(struct dogecoin_psbt_output *dst,
                          const struct dogecoin_psbt_output *src,
                          bool is_pset, bool for_clone)
{
    int ret = DOGECOIN_OK;
#ifdef BUILD_ELEMENTS
    size_t dst_asset, src_asset = 0;

    ret = dogecoin_map_find_integer(&dst->pset_fields, PSET_OUT_ASSET, &dst_asset);
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_find_integer(&src->pset_fields, PSET_OUT_ASSET, &src_asset);
    if (ret != DOGECOIN_OK)
        return ret;
#endif

    if (for_clone) {
        /* Copy amount, script (and asset, for elements) */
        if (!dst->has_amount && src->has_amount) {
            dst->amount = src->amount;
            dst->has_amount = src->has_amount;
        }
        if (!dst->script && src->script)
            ret = dogecoin_psbt_output_set_script(dst, src->script, src->script_len);
#ifdef BUILD_ELEMENTS
        if (ret == DOGECOIN_OK && is_pset && src_asset) {
            const struct dogecoin_map_item *src_p = src->pset_fields.items + src_asset - 1;
            ret = dogecoin_map_replace_integer(&dst->pset_fields, PSET_OUT_ASSET,
                                            src_p->value, src_p->value_len);
        }
#endif
    } else {
        /* Ensure amount, script (and asset, for elements) match */
        if (dst->has_amount != src->has_amount || dst->amount != src->amount ||
            dst->script_len != src->script_len ||
            memcmp(dst->script, src->script, src->script_len))
            ret = DOGECOIN_EINVAL; /* Mismatched amount or script */
        else if (is_pset) {
#ifdef BUILD_ELEMENTS
            const struct dogecoin_map_item *src_p = src->pset_fields.items + src_asset - 1;
            const struct dogecoin_map_item *dst_p = dst->pset_fields.items + dst_asset - 1;
            if (!dst_asset || !src_asset ||
                dst_p->value_len != DOGECOIN_TX_ASSET_TAG_LEN ||
                src_p->value_len != DOGECOIN_TX_ASSET_TAG_LEN ||
                memcmp(dst_p->value, src_p->value, DOGECOIN_TX_ASSET_TAG_LEN)) {
                ret = DOGECOIN_EINVAL; /* Mismatched asset */
            }
#endif
        }
    }

    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_combine(&dst->keypaths, &src->keypaths);
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_combine(&dst->unknowns, &src->unknowns);
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_combine(&dst->psbt_fields, &src->psbt_fields);
    if (ret == DOGECOIN_OK)
        ret = combine_map_if_empty(&dst->taproot_tree, &src->taproot_tree);

    if (ret == DOGECOIN_OK &&
        !dst->taproot_leaf_hashes.num_items && !dst->taproot_leaf_paths.num_items &&
        src->taproot_leaf_hashes.num_items && src->taproot_leaf_paths.num_items) {
        ret = dogecoin_map_combine(&dst->taproot_leaf_hashes, &src->taproot_leaf_hashes);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_map_combine(&dst->taproot_leaf_paths, &src->taproot_leaf_paths);
    }

#ifdef BUILD_ELEMENTS
    if (ret == DOGECOIN_OK && is_pset) {
        uint64_t dst_state, src_state;

        if (for_clone) {
            if (!dst->has_blinder_index && src->has_blinder_index) {
                dst->blinder_index = src->blinder_index;
                dst->has_blinder_index = src->has_blinder_index;
            }
            return dogecoin_map_combine(&dst->pset_fields, &src->pset_fields);
        }

        ret = psbt_output_get_blinding_state(dst, &dst_state);
        if (ret == DOGECOIN_OK)
            ret = psbt_output_get_blinding_state(src, &src_state);

        if (ret == DOGECOIN_OK && PSET_BLINDING_STATE_REQUIRED(dst_state) &&
            PSET_BLINDING_STATE_REQUIRED(src_state)) {
            /* Both outputs require blinding */
            if (!dst->blinder_index || dst->blinder_index != src->blinder_index ||
                !map_find_equal_integer(&dst->pset_fields, &src->pset_fields,
                                        PSET_OUT_BLINDING_PUBKEY))
                ret = DOGECOIN_EINVAL; /* Blinding index/pubkey do not match */
        }

        if (ret == DOGECOIN_OK && PSET_BLINDING_STATE_FULL(src_state)) {
            /* The source is fully blinded, either copy or verify the fields */
            uint32_t ft;
            for (ft = PSET_OUT_VALUE_COMMITMENT; ret == DOGECOIN_OK && ft <= PSET_OUT_ASSET_SURJECTION_PROOF; ++ft) {
                if (!(PSET_OUT_BLINDING_FIELDS & PSET_FT(ft)))
                    continue;
                if (PSET_BLINDING_STATE_FULL(dst_state)) {
                    /* Both fully blinded: verify */
                    if (!map_find_equal_integer(&dst->pset_fields, &src->pset_fields, ft))
                        ret = DOGECOIN_EINVAL; /* Fields do not match */
                } else {
                    /* Copy (overwriting if present) */
                    const struct dogecoin_map_item *from;
                    from = dogecoin_map_get_integer(&src->pset_fields, ft);
                    ret = dogecoin_map_replace_integer(&dst->pset_fields, ft,
                                                    from->value, from->value_len);
                }
            }
        }
    }
#endif /* BUILD_ELEMENTS */

    return ret;
}

static int psbt_combine(struct dogecoin_psbt *psbt, const struct dogecoin_psbt *src,
                        bool is_pset, bool for_clone)
{
    size_t i;
    int ret = DOGECOIN_OK;

    if (psbt->num_inputs != src->num_inputs || psbt->num_outputs != src->num_outputs)
        return DOGECOIN_EINVAL;

    if (!psbt->has_fallback_locktime) {
        psbt->fallback_locktime = src->fallback_locktime;
        psbt->has_fallback_locktime = src->has_fallback_locktime;
    }

    /* Take any extra flags from the source psbt that we don't have  */
    psbt->tx_modifiable_flags |= src->tx_modifiable_flags;

    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_inputs; ++i)
        ret = combine_input(&psbt->inputs[i], &src->inputs[i], is_pset, for_clone);

    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_outputs; ++i)
        ret = combine_output(&psbt->outputs[i], &src->outputs[i], is_pset, for_clone);

    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_combine(&psbt->unknowns, &src->unknowns);

    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_combine(&psbt->global_xpubs, &src->global_xpubs);

#ifdef BUILD_ELEMENTS
    if (ret == DOGECOIN_OK && is_pset) {
        psbt->pset_modifiable_flags |= src->pset_modifiable_flags;
        ret = dogecoin_map_combine(&psbt->global_scalars, &src->global_scalars);
    }
#endif /* BUILD_ELEMENTS */

    return ret;
}

int dogecoin_psbt_get_locktime(const struct dogecoin_psbt *psbt, size_t *locktime)
{
    bool only_locktime = false, only_lockheight = false;
    uint32_t max_locktime = 0, max_lockheight = 0;

    if (locktime)
        *locktime = 0;
    if (!psbt_is_valid(psbt) || psbt->version != PSBT_2 || !locktime)
        return DOGECOIN_EINVAL;

    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct dogecoin_psbt_input *pi = &psbt->inputs[i];

        const bool has_locktime = pi->required_locktime != 0;
        const bool has_lockheight = pi->required_lockheight != 0;

        only_locktime |= has_locktime && !has_lockheight;
        only_lockheight |= has_lockheight && !has_locktime;

        if (only_locktime && only_lockheight)
            return DOGECOIN_EINVAL; /* Conflicting lock types cannot be satisfied */

        if (has_locktime && max_locktime < pi->required_locktime)
            max_locktime = pi->required_locktime;

        if (has_lockheight && max_lockheight < pi->required_lockheight)
            max_lockheight = pi->required_lockheight;
    }

    if (only_locktime)
        *locktime = max_locktime;
    else if (only_lockheight)
        *locktime = max_lockheight;
    else {
        if (max_lockheight)
            *locktime = max_lockheight; /* Use height, even if time also given */
        else if (max_locktime)
            *locktime = max_locktime;
        else
            *locktime = psbt->has_fallback_locktime ? psbt->fallback_locktime : 0;
    }
    return DOGECOIN_OK;
}

#define BUILD_ITEM(n, ft) const struct dogecoin_map_item *n = dogecoin_map_get_integer(&src->pset_fields, ft)
#define BUILD_PARAM(n) n ? n->value : NULL, n ? n->value_len : 0

static int psbt_build_input(const struct dogecoin_psbt_input *src,
                            bool is_pset, bool unblinded, struct libdogecoin_tx *tx)
{
    if (is_pset) {
#ifndef BUILD_ELEMENTS
        (void)unblinded;
        return DOGECOIN_EINVAL;
#else
        BUILD_ITEM(issuance_blinding_nonce, PSET_IN_ISSUANCE_BLINDING_NONCE);
        BUILD_ITEM(issuance_asset_entropy, PSET_IN_ISSUANCE_ASSET_ENTROPY);
        BUILD_ITEM(issuance_amount_commitment, PSET_IN_ISSUANCE_VALUE_COMMITMENT);
        BUILD_ITEM(inflation_keys_commitment, PSET_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT);
        unsigned char issuance_amount[DOGECOIN_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        unsigned char inflation_keys[DOGECOIN_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        BUILD_ITEM(issuance_rangeproof, PSET_IN_ISSUANCE_VALUE_RANGEPROOF);
        BUILD_ITEM(inflation_keys_rangeproof, PSET_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF);
        struct dogecoin_map_item issuance_amount_item = { NULL, 0, issuance_amount, sizeof(issuance_amount) };
        struct dogecoin_map_item inflation_keys_item = { NULL, 0, inflation_keys, sizeof(inflation_keys) };
        int src_index = src->index;

        if (src->issuance_amount || src->inflation_keys || issuance_amount_commitment || inflation_keys_commitment)
            src_index |= DOGECOIN_TX_ISSUANCE_FLAG;

        if (src->pegin_amount || src->pegin_witness)
            src_index |= DOGECOIN_TX_PEGIN_FLAG;

        /* FIXME: Pegin parameters need to be set for pegins to work */
        /* NOTE: This is an area of PSET that needs improvement */

        if ((src->issuance_amount || src->inflation_keys) &&
            (unblinded || (!issuance_amount_commitment && !inflation_keys_commitment))) {
            /* We do not have issuance commitments, or the unblinded flag
             * has been given: Use the unblinded amounts */
            if (libdogecoin_tx_confidential_value_from_satoshi(src->issuance_amount,
                                                         issuance_amount,
                                                         sizeof(issuance_amount)) != DOGECOIN_OK ||
                libdogecoin_tx_confidential_value_from_satoshi(src->inflation_keys,
                                                         inflation_keys,
                                                         sizeof(inflation_keys)) != DOGECOIN_OK)
                return DOGECOIN_EINVAL;
            issuance_amount_commitment = &issuance_amount_item;
            inflation_keys_commitment = &inflation_keys_item;
        }

        return libdogecoin_tx_add_elements_raw_input(tx,
                                               src->txhash, DOGECOIN_TXHASH_LEN,
                                               src_index, src->sequence, NULL, 0, NULL,
                                               BUILD_PARAM(issuance_blinding_nonce),
                                               BUILD_PARAM(issuance_asset_entropy),
                                               BUILD_PARAM(issuance_amount_commitment),
                                               BUILD_PARAM(inflation_keys_commitment),
                                               BUILD_PARAM(issuance_rangeproof),
                                               BUILD_PARAM(inflation_keys_rangeproof), NULL, 0);
#endif /* BUILD_ELEMENTS */
    }
    return libdogecoin_tx_add_raw_input(tx, src->txhash, DOGECOIN_TXHASH_LEN,
                                  src->index, src->sequence, NULL, 0, NULL, 0);
}

static int psbt_build_output(const struct dogecoin_psbt_output *src,
                             bool is_pset, bool unblinded, struct libdogecoin_tx *tx)
{
    if (is_pset) {
#ifndef BUILD_ELEMENTS
        (void)unblinded;
        return DOGECOIN_EINVAL;
#else
        BUILD_ITEM(value_commitment, PSET_OUT_VALUE_COMMITMENT);
        BUILD_ITEM(value_rangeproof, PSET_OUT_VALUE_RANGEPROOF);
        BUILD_ITEM(asset, PSET_OUT_ASSET);
        BUILD_ITEM(asset_commitment, PSET_OUT_ASSET_COMMITMENT);
        BUILD_ITEM(asset_surjectionproof, PSET_OUT_ASSET_SURJECTION_PROOF);
        BUILD_ITEM(ecdh_public_key, PSET_OUT_ECDH_PUBKEY);
        unsigned char value[DOGECOIN_TX_ASSET_CT_VALUE_UNBLIND_LEN];
        unsigned char asset_u[DOGECOIN_TX_ASSET_CT_ASSET_LEN];
        struct dogecoin_map_item value_item = { NULL, 0, value, sizeof(value) };
        struct dogecoin_map_item asset_u_item = { NULL, 0, asset_u, sizeof(asset_u) };

        if (unblinded || (src->has_amount && !value_commitment)) {
            /* FIXME: Check the blind value proof */
            /* Use the unblinded amount */
            if (libdogecoin_tx_confidential_value_from_satoshi(src->amount,
                                                         value, sizeof(value)) != DOGECOIN_OK)
                return DOGECOIN_EINVAL;
            value_commitment = &value_item;
            value_rangeproof = NULL;
        }

        if (unblinded || !asset_commitment) {
            /* FIXME: Check the blind asset proof */
            if (!asset)
                asset_commitment = NULL;
            else {
                asset_u[0] = 0x1; /* Use the unblinded asset */
                if (asset->value_len != DOGECOIN_TX_ASSET_TAG_LEN)
                    return DOGECOIN_EINVAL;
                memcpy(asset_u + 1, asset->value, asset->value_len);
                asset_commitment = &asset_u_item;
            }
            asset_surjectionproof = NULL;
        }

        if (unblinded)
            ecdh_public_key = NULL;

        return libdogecoin_tx_add_elements_raw_output(tx,
                                                src->script, src->script_len,
                                                BUILD_PARAM(asset_commitment),
                                                BUILD_PARAM(value_commitment),
                                                BUILD_PARAM(ecdh_public_key),
                                                BUILD_PARAM(asset_surjectionproof),
                                                BUILD_PARAM(value_rangeproof), 0);
#endif /* BUILD_ELEMENTS */
    }
    if (!src->has_amount)
        return DOGECOIN_EINVAL;
    return libdogecoin_tx_add_raw_output(tx, src->amount, src->script, src->script_len, 0);
}

static int psbt_build_tx(const struct dogecoin_psbt *psbt, struct libdogecoin_tx **tx,
                         bool *is_pset, bool unblinded)
{
    size_t is_elements, locktime, i;
    int ret;

    *tx = NULL;
    *is_pset = 0;

    if (!psbt_is_valid(psbt) || (psbt->version == PSBT_0 && !psbt->tx))
        return DOGECOIN_EINVAL;

    if ((ret = dogecoin_psbt_is_elements(psbt, &is_elements)) != DOGECOIN_OK)
        return ret;
    *is_pset = !!is_elements;

    if (psbt->version == PSBT_0)
        return libdogecoin_tx_clone_alloc(psbt->tx, 0, tx);

    ret = dogecoin_psbt_get_locktime(psbt, &locktime);
    if (ret == DOGECOIN_OK)
        ret = libdogecoin_tx_init_alloc(psbt->tx_version, locktime, psbt->num_inputs, psbt->num_outputs, tx);

    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_inputs; ++i)
        ret = psbt_build_input(psbt->inputs + i, *is_pset, unblinded, *tx);

    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_outputs; ++i)
        ret = psbt_build_output(psbt->outputs + i, *is_pset, unblinded, *tx);

    if (ret != DOGECOIN_OK) {
        libdogecoin_tx_free(*tx);
        *tx = NULL;
    }
    return ret;
}

static int psbt_v0_to_v2(struct dogecoin_psbt *psbt)
{
    size_t i;

    /* Upgrade to v2 */
    psbt->version = PSBT_2;
    psbt->tx_version = psbt->tx->version;
    /* V0 only has the tx locktime, and no per-input locktimes,
     * so set the V2 fallback locktime to the tx locktime, unless
     * it is the default value of 0.
     */
    psbt->fallback_locktime = psbt->tx->locktime;
    psbt->has_fallback_locktime = psbt->fallback_locktime != 0;
    /* V0 PSBTs are implicitly modifiable; reflect that in our flags */
    psbt->tx_modifiable_flags = DOGECOIN_PSBT_TXMOD_INPUTS | DOGECOIN_PSBT_TXMOD_OUTPUTS;
    /* FIXME: Detect SIGHASH_SINGLE in any signatures present and
     * set DOGECOIN_PSBT_TXMOD_SINGLE if found.
     */

    for (i = 0; i < psbt->tx->num_inputs; ++i) {
        struct dogecoin_psbt_input *pi = &psbt->inputs[i];
        const struct libdogecoin_tx_input *txin = &psbt->tx->inputs[i];
        memcpy(pi->txhash, txin->txhash, sizeof(pi->txhash));
        pi->index = txin->index; /* No mask, since PSET is v2 only */
        pi->sequence = txin->sequence;
    }

    for (i = 0; i < psbt->tx->num_outputs; ++i) {
        struct dogecoin_psbt_output *po = &psbt->outputs[i];
        struct libdogecoin_tx_output *txout = &psbt->tx->outputs[i];
        /* We steal script directly from the tx output so this can't fail */
        po->script = txout->script;
        txout->script = NULL;
        po->script_len = txout->script_len;
        txout->script_len = 0;
        po->amount = txout->satoshi;
        po->has_amount = true;
    }

    libdogecoin_tx_free(psbt->tx);
    psbt->tx = NULL;
    return DOGECOIN_OK;
}

static int psbt_v2_to_v0(struct dogecoin_psbt *psbt)
{
    size_t i;
    bool is_pset;
    int ret = psbt_build_tx(psbt, &psbt->tx, &is_pset, false);

    if (ret != DOGECOIN_OK)
        return ret;

    for (i = 0; i < psbt->num_inputs; ++i) {
        struct dogecoin_psbt_input *pi = &psbt->inputs[i];
        pi->index = 0;
        pi->sequence = 0;
        pi->required_locktime = 0;
        pi->required_lockheight = 0;
    }

    for (i = 0; i < psbt->num_outputs; ++i) {
        struct dogecoin_psbt_output *po = &psbt->outputs[i];
        po->amount = 0;
        po->has_amount = false;
        clear_and_free_bytes(&po->script, &po->script_len);
    }

    psbt->version = PSBT_0;
    psbt->tx_version = 0;
    psbt->fallback_locktime = 0;
    psbt->has_fallback_locktime = false;
    psbt->tx_modifiable_flags = 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_set_version(struct dogecoin_psbt *psbt,
                           uint32_t flags,
                           uint32_t version)
{
    size_t is_pset;

    if (!psbt_is_valid(psbt) || flags || (version != PSBT_0 && version != PSBT_2))
        return DOGECOIN_EINVAL;

    if (psbt->version == version)
        return DOGECOIN_OK; /* No-op */

    if (dogecoin_psbt_is_elements(psbt, &is_pset) != DOGECOIN_OK || is_pset)
        return DOGECOIN_EINVAL; /* PSET only supports v2 */

    return psbt->version == PSBT_0 ? psbt_v0_to_v2(psbt) : psbt_v2_to_v0(psbt);
}

int dogecoin_psbt_get_id(const struct dogecoin_psbt *psbt, uint32_t flags, unsigned char *bytes_out, size_t len)
{
    struct libdogecoin_tx *tx;
    size_t i;
    bool is_pset;
    int ret;

    if ((flags & ~PSBT_ID_ALL_FLAGS) || !bytes_out || len != DOGECOIN_TXHASH_LEN)
        return DOGECOIN_EINVAL;

    if ((ret = psbt_build_tx(psbt, &tx, &is_pset, true)) == DOGECOIN_OK) {
        if (!(flags & DOGECOIN_PSBT_ID_USE_LOCKTIME)) {
            /* Set locktime to 0. This is what core/Elements do,
             * although the specs aren't fixed to describe this yet */
            tx->locktime = 0;
        }
        if (psbt->version == PSBT_2 || (flags & DOGECOIN_PSBT_ID_AS_V2)) {
            /* Set all inputs sequence numbers to 0 as per BIP-370 */
            for (i = 0; i < tx->num_inputs; ++i)
                tx->inputs[i].sequence = 0;
        }
        ret = libdogecoin_tx_get_txid(tx, bytes_out, len);
        libdogecoin_tx_free(tx);
    }
    return ret;
}

int dogecoin_psbt_combine(struct dogecoin_psbt *psbt, const struct dogecoin_psbt *src)
{
    unsigned char id[DOGECOIN_TXHASH_LEN], src_id[DOGECOIN_TXHASH_LEN];
    size_t is_pset;
    int ret;

    if (!psbt_is_valid(psbt) || !psbt_is_valid(src) || psbt->version != src->version)
        return DOGECOIN_EINVAL;

    if (psbt == src)
        return DOGECOIN_OK; /* Combine with self: no-op */

    if ((ret = dogecoin_psbt_get_id(psbt, 0, id, sizeof(id))) != DOGECOIN_OK)
        return ret;

    if ((ret = dogecoin_psbt_get_id(src, 0, src_id, sizeof(src_id))) == DOGECOIN_OK &&
        (ret = dogecoin_psbt_is_elements(psbt, &is_pset)) == DOGECOIN_OK) {
        if (memcmp(src_id, id, sizeof(id)) != 0)
            ret = DOGECOIN_EINVAL; /* Cannot combine different txs */
        else
            ret = psbt_combine(psbt, src, !!is_pset, false);
    }
    dogecoin_clear_2(id, sizeof(id), src_id, sizeof(src_id));
    return ret;
}

int dogecoin_psbt_clone_alloc(const struct dogecoin_psbt *psbt, uint32_t flags,
                           struct dogecoin_psbt **output)
{
    size_t is_pset;
    int ret;

    OUTPUT_CHECK;
    if (!psbt_is_valid(psbt) || flags || !output)
        return DOGECOIN_EINVAL;

    ret = dogecoin_psbt_is_elements(psbt, &is_pset);
    if (ret == DOGECOIN_OK)
        ret = dogecoin_psbt_init_alloc(psbt->version,
                                    psbt->inputs_allocation_len,
                                    psbt->outputs_allocation_len,
                                    psbt->unknowns.items_allocation_len,
                                    is_pset ? DOGECOIN_PSBT_INIT_PSET : 0,
                                    output);
    if (ret == DOGECOIN_OK) {
        (*output)->tx_version = psbt->tx_version;
        psbt_claim_allocated_inputs(*output, psbt->num_inputs, psbt->num_outputs);
        (*output)->tx_modifiable_flags = 0;
#ifdef BUILD_ELEMENTS
        (*output)->pset_modifiable_flags = 0;
#endif
        ret = psbt_combine(*output, psbt, !!is_pset, true);

        if (ret == DOGECOIN_OK && psbt->tx)
            ret = tx_clone_alloc(psbt->tx, &(*output)->tx);
        if (ret != DOGECOIN_OK) {
            dogecoin_psbt_free(*output);
            *output = NULL;
        }
    }
    return ret;
}

int dogecoin_psbt_get_input_bip32_key_from_alloc(const struct dogecoin_psbt *psbt,
                                              size_t index, size_t subindex,
                                              uint32_t flags,
                                              const struct ext_key *hdkey,
                                              struct ext_key **output)
{
    const struct dogecoin_psbt_input *inp = psbt_get_input(psbt, index);
    size_t sig_idx = 0;
    int ret;
    if (output)
        *output = NULL;
    if (!inp || flags || !hdkey || !output)
        return DOGECOIN_EINVAL;
    /* Find any matching key in the inputs keypaths */
    ret = dogecoin_map_keypath_get_bip32_key_from_alloc(&inp->keypaths, subindex,
                                                     hdkey, output);
    if (ret == DOGECOIN_OK && *output) {
        /* Found: Make sure we don't have a signature already */
        ret = dogecoin_map_find_bip32_public_key_from(&inp->signatures, 0,
                                                   *output, &sig_idx);
        if (ret == DOGECOIN_OK && sig_idx) {
            bip32_key_free(*output);
            *output = NULL;
        }
    }
    return ret;
}

static bool is_matching_redeem(const unsigned char *scriptpk, size_t scriptpk_len,
                               const unsigned char *redeem, size_t redeem_len)
{
    unsigned char p2sh[DOGECOIN_SCRIPTPUBKEY_P2SH_LEN];
    size_t p2sh_len;
    int ret = dogecoin_scriptpubkey_p2sh_from_bytes(redeem, redeem_len,
                                                 DOGECOIN_SCRIPT_HASH160,
                                                 p2sh, sizeof(p2sh), &p2sh_len);
    return ret == DOGECOIN_OK && p2sh_len == scriptpk_len &&
           !memcmp(p2sh, scriptpk, p2sh_len);
}

/* Get the scriptpubkey or redeem script from an input */
static int get_signing_script(const struct dogecoin_psbt *psbt, size_t index,
                              const unsigned char **script, size_t *script_len)
{
    const struct dogecoin_psbt_input *inp = psbt_get_input(psbt, index);
    const struct libdogecoin_tx_output *utxo = utxo_from_input(psbt, inp);
    const struct dogecoin_map_item *item;

    *script = NULL;
    *script_len = 0;
    if (!utxo)
        return DOGECOIN_EINVAL;

    item = dogecoin_map_get_integer(&inp->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (item) {
        if (!is_matching_redeem(utxo->script, utxo->script_len,
                                item->value, item->value_len))
            return DOGECOIN_EINVAL;
        *script = item->value;
        *script_len = item->value_len;
    } else {
        *script = utxo->script;
        *script_len = utxo->script_len;
    }
    if (BYTES_INVALID(*script, *script_len)) {
        *script = NULL;
        *script_len = 0;
        return DOGECOIN_EINVAL;
    }
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_input_signing_script_len(const struct dogecoin_psbt *psbt,
                                        size_t index, size_t *written)
{
    const unsigned char *p;
    return written ? get_signing_script(psbt, index, &p, written) : DOGECOIN_EINVAL;
}

int dogecoin_psbt_get_input_signing_script(const struct dogecoin_psbt *psbt,
                                        size_t index,
                                        unsigned char *bytes_out, size_t len,
                                        size_t *written)
{
    const unsigned char *p;
    int ret;
    if (written)
        *written = 0;
    if (!bytes_out || !len || !written)
        return DOGECOIN_EINVAL;
    ret = get_signing_script(psbt, index, &p, written);
    if (ret == DOGECOIN_OK && *written <= len)
        memcpy(bytes_out, p, *written);
    return ret;
}

static int get_scriptcode(const struct dogecoin_psbt *psbt, size_t index,
                          unsigned char *buff, size_t buff_len,
                          const unsigned char *scriptcode, size_t scriptcode_len,
                          const unsigned char **script, size_t *script_len)
{
    const struct dogecoin_psbt_input *inp = psbt_get_input(psbt, index);
    int ret;

    if (script)
        *script = NULL;
    if (script_len)
        *script_len = 0;
    if (!inp || !buff || buff_len != DOGECOIN_SCRIPTPUBKEY_P2PKH_LEN ||
        !scriptcode || !scriptcode_len || !script || !script_len)
        return DOGECOIN_EINVAL;

    if (inp->witness_utxo) {
        /* Segwit input */
        size_t script_type, written;

        ret = dogecoin_scriptpubkey_get_type(scriptcode, scriptcode_len, &script_type);

        if (ret == DOGECOIN_OK && script_type == DOGECOIN_SCRIPT_TYPE_P2WPKH) {
            /* P2WPKH */
            ret = dogecoin_scriptpubkey_p2pkh_from_bytes(&scriptcode[2],
                                                      HASH160_LEN, 0,
                                                      buff, buff_len,
                                                      &written);
            if (ret != DOGECOIN_OK || written > buff_len)
                return DOGECOIN_EINVAL;
            *script = buff; /* Return the scriptpubkey */
            *script_len = written;
            return DOGECOIN_OK;
        }

        if (ret == DOGECOIN_OK && script_type == DOGECOIN_SCRIPT_TYPE_P2WSH) {
            /* P2WSH */
            unsigned char p2wsh[DOGECOIN_SCRIPTPUBKEY_P2WSH_LEN];
            const struct dogecoin_map_item *wit_script;

            if (!(wit_script = dogecoin_map_get_integer(&inp->psbt_fields,
                                                     PSBT_IN_WITNESS_SCRIPT)))
                return DOGECOIN_EINVAL;
            ret = dogecoin_witness_program_from_bytes(wit_script->value,
                                                   wit_script->value_len,
                                                   DOGECOIN_SCRIPT_SHA256,
                                                   p2wsh, sizeof(p2wsh),
                                                   &written);
            if (ret != DOGECOIN_OK || written != sizeof(p2wsh) ||
                written != scriptcode_len || memcmp(p2wsh, scriptcode, written))
                return DOGECOIN_EINVAL;
            *script = wit_script->value; /* Return the witness script */
            *script_len = wit_script->value_len;
            return DOGECOIN_OK;
        }
        return DOGECOIN_EINVAL; /* Unknown scriptPubKey type/not enough info */
    }

    if (inp->utxo) {
        /* Non-segwit input */
        unsigned char txid[DOGECOIN_TXHASH_LEN];
        size_t is_pset;

        if ((ret = dogecoin_psbt_is_elements(psbt, &is_pset)) != DOGECOIN_OK || is_pset)
            return DOGECOIN_EINVAL; /* Elements doesn't support pre-segwit txs */

        ret = dogecoin_psbt_get_input_previous_txid(psbt, index, txid, sizeof(txid));
        if (ret != DOGECOIN_OK || !is_matching_txid(inp->utxo, txid, sizeof(txid)))
            return DOGECOIN_EINVAL; /* Prevout doesn't match input */
        *script = scriptcode;
        *script_len = scriptcode_len;
        return DOGECOIN_OK;
    }
    return DOGECOIN_EINVAL; /* Missing prevout data in input */
}

int dogecoin_psbt_get_input_scriptcode_len(const struct dogecoin_psbt *psbt, size_t index,
                                        const unsigned char *script, size_t script_len,
                                        size_t *written)
{
    unsigned char p2pkh[DOGECOIN_SCRIPTPUBKEY_P2PKH_LEN];
    const unsigned char *p;
    return get_scriptcode(psbt, index, p2pkh, sizeof(p2pkh),
                          script, script_len, &p, written);
}

int dogecoin_psbt_get_input_scriptcode(const struct dogecoin_psbt *psbt, size_t index,
                                    const unsigned char *script, size_t script_len,
                                    unsigned char *bytes_out, size_t len,
                                    size_t *written)
{
    unsigned char p2pkh[DOGECOIN_SCRIPTPUBKEY_P2PKH_LEN];
    const unsigned char *p;
    int ret;
    if (written)
        *written = 0;
    if (!bytes_out || !len || !written)
        return DOGECOIN_EINVAL;
    ret = get_scriptcode(psbt, index, p2pkh, sizeof(p2pkh),
                         script, script_len, &p, written);
    if (ret == DOGECOIN_OK && *written <= len)
        memcpy(bytes_out, p, *written);
    return ret;
}

int dogecoin_psbt_get_input_signature_hash(struct dogecoin_psbt *psbt, size_t index,
                                        const struct libdogecoin_tx *tx,
                                        const unsigned char *script, size_t script_len,
                                        uint32_t flags,
                                        unsigned char *bytes_out, size_t len)
{
    const struct dogecoin_psbt_input *inp = psbt_get_input(psbt, index);
    uint64_t satoshi;
    uint32_t sighash, sig_flags;
    size_t is_pset;
    int ret;

    if (!inp || !tx || flags)
        return DOGECOIN_EINVAL;

    if ((ret = dogecoin_psbt_is_elements(psbt, &is_pset)) != DOGECOIN_OK)
        return ret;

    sighash = inp->sighash ? inp->sighash : DOGECOIN_SIGHASH_ALL;
    if (sighash & 0xffffff00)
        return DOGECOIN_EINVAL;
    sig_flags = inp->witness_utxo ? DOGECOIN_TX_FLAG_USE_WITNESS : 0;

    if (is_pset) {
        if (!inp->witness_utxo)
            return DOGECOIN_EINVAL; /* Must be segwit */
#ifdef BUILD_ELEMENTS
        return libdogecoin_tx_get_elements_signature_hash(tx, index,
                                                    script, script_len,
                                                    inp->witness_utxo->value,
                                                    inp->witness_utxo->value_len,
                                                    sighash, sig_flags, bytes_out,
                                                    len);
#else
        return DOGECOIN_EINVAL; /* Unsupported */
#endif /* BUILD_ELEMENTS */
    }
    satoshi = inp->witness_utxo ? inp->witness_utxo->satoshi : 0;
    return libdogecoin_tx_get_btc_signature_hash(tx, index, script, script_len,
                                           satoshi, sighash, sig_flags,
                                           bytes_out, len);
}

int dogecoin_psbt_sign_input_bip32(struct dogecoin_psbt *psbt,
                                size_t index, size_t subindex,
                                const unsigned char *txhash, size_t txhash_len,
                                const struct ext_key *hdkey,
                                uint32_t flags)
{
    unsigned char sig[EC_SIGNATURE_LEN], der[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t der_len, pubkey_idx;
    uint32_t sighash;
    struct dogecoin_psbt_input *inp = psbt_get_input(psbt, index);
    int ret;

    if (!inp || !hdkey || hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE ||
        (flags & ~EC_FLAGS_ALL))
        return DOGECOIN_EINVAL;

    /* Find the public key this signature is for */
    ret = dogecoin_map_find_bip32_public_key_from(&inp->keypaths, subindex,
                                               hdkey, &pubkey_idx);
    if (ret != DOGECOIN_OK || !pubkey_idx)
        return DOGECOIN_EINVAL; /* Signing pubkey key not found */

    sighash = inp->sighash ? inp->sighash : DOGECOIN_SIGHASH_ALL;
    if (sighash & 0xffffff00)
        return DOGECOIN_EINVAL;

    /* Only grinding flag is relevant */
    flags = EC_FLAG_ECDSA | (flags & EC_FLAG_GRIND_R);
    /* Compute the sig */
    ret = dogecoin_ec_sig_from_bytes(hdkey->priv_key + 1, EC_PRIVATE_KEY_LEN,
                                  txhash, txhash_len, flags, sig, sizeof(sig));
    if (ret == DOGECOIN_OK) {
        /* Convert to DER, add sighash byte and store */
        ret = dogecoin_ec_sig_to_der(sig, sizeof(sig), der, sizeof(der), &der_len);
        if (ret == DOGECOIN_OK) {
            const struct dogecoin_map_item *pk;
            der[der_len++] = sighash & 0xff;
            pk = &inp->keypaths.items[pubkey_idx - 1];
            ret = dogecoin_psbt_input_add_signature(inp, pk->key, pk->key_len,
                                                 der, der_len);
        }
    }
    dogecoin_clear_2(sig, sizeof(sig), der, sizeof(der));
    return ret;
}

int dogecoin_psbt_sign_bip32(struct dogecoin_psbt *psbt,
                          const struct ext_key *hdkey, uint32_t flags)
{
    unsigned char p2pkh[DOGECOIN_SCRIPTPUBKEY_P2PKH_LEN];
    size_t i;
    bool is_pset;
    int ret;
    struct libdogecoin_tx *tx;

    if (!hdkey || hdkey->priv_key[0] != BIP32_FLAG_KEY_PRIVATE ||
        (flags & ~EC_FLAGS_ALL))
        return DOGECOIN_EINVAL;

    if ((ret = psbt_build_tx(psbt, &tx, &is_pset, false)) != DOGECOIN_OK)
        return ret;

    /* Go through each of the inputs */
    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_inputs; ++i) {
        unsigned char txhash[DOGECOIN_TXHASH_LEN];
        const unsigned char *script, *scriptcode;
        size_t script_len, scriptcode_len, subindex = 0;
        struct ext_key *derived = NULL;

        /* Get or derive a key for signing this input.
         * Note that we do not iterate subindex in this loop, so we will not
         * sign more than one signature that derives from the same parent key.
         */
        ret = dogecoin_psbt_get_input_bip32_key_from_alloc(psbt, i, subindex,
                                                        0, hdkey, &derived);
        if (!derived)
            continue; /* No key to sign with */

        /* Get the scriptpubkey or redeemscript */
        if (ret == DOGECOIN_OK)
            ret = get_signing_script(psbt, i, &script, &script_len);

        /* Get the actual script to sign with */
        if (ret == DOGECOIN_OK)
            ret = get_scriptcode(psbt, i, p2pkh, sizeof(p2pkh),
                                 script, script_len,
                                 &scriptcode, &scriptcode_len);

        /* Get the hash to sign */
        if (ret == DOGECOIN_OK)
            ret = dogecoin_psbt_get_input_signature_hash(psbt, i, tx,
                                                      scriptcode, scriptcode_len,
                                                      0, txhash, sizeof(txhash));
        /* Sign the input */
        if (ret == DOGECOIN_OK)
            ret = dogecoin_psbt_sign_input_bip32(psbt, i, subindex,
                                              txhash, sizeof(txhash),
                                              hdkey, flags);
        bip32_key_free(derived);
    }

    libdogecoin_tx_free(tx);
    return ret;
}

int dogecoin_psbt_sign(struct dogecoin_psbt *psbt,
                    const unsigned char *priv_key, size_t priv_key_len, uint32_t flags)
{
    struct ext_key hdkey;
    const uint32_t ver = BIP32_VER_MAIN_PRIVATE;
    int ret;

    /* Build a partial/non-derivable key, and use the bip32 signing impl */
    ret = psbt ? bip32_key_from_private_key(ver, priv_key, priv_key_len,
                                            &hdkey) : DOGECOIN_EINVAL;
    if (ret == DOGECOIN_OK)
        ret = dogecoin_psbt_sign_bip32(psbt, &hdkey, flags);
    dogecoin_clear(&hdkey, sizeof(hdkey));
    return ret;
}

static const struct dogecoin_map_item *get_sig(const struct dogecoin_psbt_input *input,
                                            size_t i, size_t n)
{
    return input->signatures.num_items != n ? NULL : &input->signatures.items[i];
}

static bool finalize_p2pkh(struct dogecoin_psbt_input *input)
{
    unsigned char script[DOGECOIN_SCRIPTSIG_P2PKH_MAX_LEN];
    size_t script_len;
    const struct dogecoin_map_item *sig = get_sig(input, 0, 1);

    if (!sig ||
        dogecoin_scriptsig_p2pkh_from_der(sig->key, sig->key_len,
                                       sig->value, sig->value_len,
                                       script, sizeof(script),
                                       &script_len) != DOGECOIN_OK)
        return false;

    return dogecoin_psbt_input_set_final_scriptsig(input, script, script_len) == DOGECOIN_OK;
}

static bool finalize_p2sh_wrapped(struct dogecoin_psbt_input *input)
{
    /* P2SH wrapped witness: add scriptSig pushing the redeemScript */
    const struct dogecoin_map_item *redeem_script;
    redeem_script = dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (redeem_script) {
        unsigned char script[DOGECOIN_SCRIPTSIG_MAX_LEN + 1];
        size_t script_len;
        if (dogecoin_script_push_from_bytes(redeem_script->value,
                                         redeem_script->value_len, 0,
                                         script, sizeof(script),
                                         &script_len) == DOGECOIN_OK &&
            script_len <= sizeof(script) &&
            dogecoin_psbt_input_set_final_scriptsig(input,
                                                 script, script_len) == DOGECOIN_OK)
            return true;
    }
    /* Failed: clear caller-created witness stack before returning */
    libdogecoin_tx_witness_stack_free(input->final_witness);
    input->final_witness = NULL;
    return false;
}

static bool finalize_p2wpkh(struct dogecoin_psbt_input *input)
{
    const struct dogecoin_map_item *sig = get_sig(input, 0, 1);

    if (!sig ||
        dogecoin_witness_p2wpkh_from_der(sig->key, sig->key_len,
                                      sig->value, sig->value_len,
                                      &input->final_witness) != DOGECOIN_OK)
        return false;

    if (!dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT))
        return true;
    return finalize_p2sh_wrapped(input);
}

static bool finalize_p2wsh(struct dogecoin_psbt_input *input)
{
    (void)input;
    return false; /* TODO */
}

static bool finalize_multisig(struct dogecoin_psbt_input *input,
                              const unsigned char *out_script, size_t out_script_len,
                              bool is_witness, bool is_p2sh)
{
    unsigned char sigs[EC_SIGNATURE_LEN * 15];
    uint32_t sighashes[15];
    const unsigned char *p = out_script, *end = p + out_script_len;
    size_t threshold, n_pubkeys, n_found = 0, i;
    bool ret = false;

    if (!script_is_op_n(out_script[0], false, &threshold) ||
        input->signatures.num_items < threshold ||
        !script_is_op_n(out_script[out_script_len - 2], false, &n_pubkeys) ||
        n_pubkeys > 15)
        goto fail; /* Failed to parse or invalid script */

    ++p; /* Skip the threshold */

    /* Collect signatures corresponding to pubkeys in the multisig script */
    for (i = 0; i < n_pubkeys && p < end; ++i) {
        size_t opcode_size, found_pubkey_len;
        const unsigned char *found_pubkey;
        const struct dogecoin_map_item *found_sig;
        size_t sig_index;

        if (script_get_push_size_from_bytes(p, end - p,
                                            &found_pubkey_len) != DOGECOIN_OK ||
            script_get_push_opcode_size_from_bytes(p, end - p,
                                                   &opcode_size) != DOGECOIN_OK)
            goto fail; /* Script is malformed, bail */

        p += opcode_size;
        found_pubkey = p;
        p += found_pubkey_len; /* Move to next pubkey push */

        /* Find the associated signature for this pubkey */
        if (dogecoin_map_find(&input->signatures,
                           found_pubkey, found_pubkey_len,
                           &sig_index) != DOGECOIN_OK || !sig_index)
            continue; /* Not found: try the next pubkey in the script */

        found_sig = &input->signatures.items[sig_index - 1];

        /* Sighash is appended to the DER signature */
        sighashes[n_found] = found_sig->value[found_sig->value_len - 1];
        /* Convert the DER signature to compact form */
        if (dogecoin_ec_sig_from_der(found_sig->value, found_sig->value_len - 1,
                                  sigs + n_found * EC_SIGNATURE_LEN,
                                  EC_SIGNATURE_LEN) != DOGECOIN_OK)
            continue; /* Failed to parse, try next pubkey */

        if (++n_found == threshold)
            break; /* We have enough signatures, ignore any more */
    }

    if (n_found != threshold)
        goto fail; /* Failed to find enough signatures */

    if (is_witness) {
        if (dogecoin_witness_multisig_from_bytes(out_script, out_script_len,
                                              sigs, n_found * EC_SIGNATURE_LEN,
                                              sighashes, n_found,
                                              0, &input->final_witness) != DOGECOIN_OK)
            goto fail;

        if (is_p2sh && !finalize_p2sh_wrapped(input))
            goto fail;
    } else {
        unsigned char script[DOGECOIN_SCRIPTSIG_MAX_LEN];
        size_t script_len;

        if (dogecoin_scriptsig_multisig_from_bytes(out_script, out_script_len,
                                                sigs, n_found * EC_SIGNATURE_LEN,
                                                sighashes, n_found, 0,
                                                script, sizeof(script), &script_len) != DOGECOIN_OK ||
            dogecoin_psbt_input_set_final_scriptsig(input, script, script_len) != DOGECOIN_OK)
            goto fail;
    }
    ret = true;
fail:
    dogecoin_clear_2(sigs, sizeof(sigs), sighashes, sizeof(sighashes));
    return ret;
}

int dogecoin_psbt_finalize_input(struct dogecoin_psbt *psbt, size_t index, uint32_t flags)
{
    struct dogecoin_psbt_input *input = psbt_get_input(psbt, index);
    const struct dogecoin_map_item *script;
    unsigned char *out_script = NULL;
    size_t out_script_len = 0, type = DOGECOIN_SCRIPT_TYPE_UNKNOWN;
    uint32_t utxo_index;
    bool is_witness = false, is_p2sh = false;

    if (!psbt_is_valid(psbt) || !input || (flags & ~DOGECOIN_PSBT_FINALIZE_NO_CLEAR))
        return DOGECOIN_EINVAL;

    if (dogecoin_psbt_get_input_output_index(psbt, index, &utxo_index) != DOGECOIN_OK)
        return DOGECOIN_EINVAL;

    if (input->final_witness ||
        dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG))
        goto done; /* Already finalized */

    /* Note that if we supply the non-witness utxo tx field (tx) for
     * witness inputs also, we'll need a different way to signal
     * p2sh-p2wpkh scripts */
    if (input->witness_utxo && input->witness_utxo->script_len) {
        out_script = input->witness_utxo->script;
        out_script_len = input->witness_utxo->script_len;
        is_witness = true;
    } else if (input->utxo && utxo_index < input->utxo->num_outputs) {
        struct libdogecoin_tx_output *utxo = &input->utxo->outputs[utxo_index];
        out_script = utxo->script;
        out_script_len = utxo->script_len;
    }
    script = dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
    if (script) {
        out_script = script->value;
        out_script_len = script->value_len;
        is_p2sh = true;
    }
    script = dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_WITNESS_SCRIPT);
    if (script) {
        out_script = script->value;
        out_script_len = script->value_len;
        is_witness = true;
    }

    if (out_script &&
        dogecoin_scriptpubkey_get_type(out_script, out_script_len, &type) != DOGECOIN_OK)
        return DOGECOIN_OK; /* Invalid/missing script */

    switch (type) {
    case DOGECOIN_SCRIPT_TYPE_P2PKH:
        if (!finalize_p2pkh(input))
            return DOGECOIN_OK;
        break;
    case DOGECOIN_SCRIPT_TYPE_P2WPKH:
        if (!finalize_p2wpkh(input))
            return DOGECOIN_OK;
        break;
    case DOGECOIN_SCRIPT_TYPE_P2WSH:
        if (!finalize_p2wsh(input))
            return DOGECOIN_OK;
        break;
    case DOGECOIN_SCRIPT_TYPE_MULTISIG:
        if (!finalize_multisig(input, out_script, out_script_len, is_witness, is_p2sh))
            return DOGECOIN_OK;
        break;
    default:
        return DOGECOIN_OK; /* Unhandled script type  */
    }

done:
    if (!(flags & DOGECOIN_PSBT_FINALIZE_NO_CLEAR)) {
        /* Clear non-final things */
        dogecoin_map_remove_integer(&input->psbt_fields, PSBT_IN_REDEEM_SCRIPT);
        dogecoin_map_remove_integer(&input->psbt_fields, PSBT_IN_WITNESS_SCRIPT);
        dogecoin_map_clear(&input->keypaths);
        dogecoin_map_clear(&input->signatures);
        input->sighash = 0;
    }
    return DOGECOIN_OK;
}

int dogecoin_psbt_finalize(struct dogecoin_psbt *psbt, uint32_t flags)
{
    size_t i;
    int ret = DOGECOIN_OK;

    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_inputs; ++i)
        ret = dogecoin_psbt_finalize_input(psbt, i, flags);
    return ret;
}

int dogecoin_psbt_extract(const struct dogecoin_psbt *psbt, uint32_t flags, struct libdogecoin_tx **output)
{
    struct libdogecoin_tx *result;
    size_t i;
    bool is_pset, for_final = !(flags & DOGECOIN_PSBT_EXTRACT_NON_FINAL);
    int ret;

    OUTPUT_CHECK;

    if (!psbt || flags & ~DOGECOIN_PSBT_EXTRACT_NON_FINAL)
        return DOGECOIN_EINVAL;

    if ((ret = psbt_build_tx(psbt, &result, &is_pset, false)) != DOGECOIN_OK)
        return ret;

    for (i = 0; for_final && i < psbt->num_inputs; ++i) {
        const struct dogecoin_psbt_input *input = &psbt->inputs[i];
        struct libdogecoin_tx_input *txin = &result->inputs[i];
        const struct dogecoin_map_item *final_scriptsig;

        final_scriptsig = dogecoin_map_get_integer(&input->psbt_fields, PSBT_IN_FINAL_SCRIPTSIG);

        if (!input->final_witness && !final_scriptsig) {
            ret = DOGECOIN_EINVAL;
            break;
        }

        if (final_scriptsig) {
            if (txin->script) {
                /* Our global tx shouldn't have a scriptSig */
                ret = DOGECOIN_EINVAL;
                break;
            }
            if (!clone_bytes(&txin->script,
                             final_scriptsig->value, final_scriptsig->value_len)) {
                ret = DOGECOIN_ENOMEM;
                break;
            }
            txin->script_len = final_scriptsig->value_len;
        }
        if (input->final_witness) {
            if (txin->witness) {
                /* Our global tx shouldn't have a witness */
                ret = DOGECOIN_EINVAL;
                break;
            }
            ret = libdogecoin_tx_witness_stack_clone_alloc(input->final_witness,
                                                     &txin->witness);
            if (ret != DOGECOIN_OK)
                break;
        }
    }

    if (ret == DOGECOIN_OK)
        *output = result;
    else
        libdogecoin_tx_free(result);
    return ret;
}

#ifdef BUILD_ELEMENTS
static int compute_final_vbf(struct dogecoin_psbt *psbt,
                             const unsigned char *input_scalar,
                             unsigned char *output_scalar,
                             unsigned char *vbf)
{
    size_t i;
    int ret = dogecoin_ec_scalar_subtract_from(output_scalar, EC_SCALAR_LEN,
                                            input_scalar, EC_SCALAR_LEN);
    if (ret == DOGECOIN_OK) {
        ret = dogecoin_ec_scalar_subtract_from(vbf, EC_SCALAR_LEN,
                                            output_scalar, EC_SCALAR_LEN);
        for (i = 0; ret == DOGECOIN_OK && i < psbt->global_scalars.num_items; ++i) {
            const struct dogecoin_map_item *scalar = psbt->global_scalars.items + i;
            ret = dogecoin_ec_scalar_subtract_from(vbf, EC_SCALAR_LEN,
                                                scalar->key, scalar->key_len);
        }
    }
    if (ret == DOGECOIN_OK && mem_is_zero(vbf, EC_SCALAR_LEN))
        ret = DOGECOIN_ERROR;
    if (ret == DOGECOIN_OK)
        ret = dogecoin_map_clear(&psbt->global_scalars);
    return ret;
}
#endif /* BUILD_ELEMENTS */

int dogecoin_psbt_blind(struct dogecoin_psbt *psbt,
                     const struct dogecoin_map *values,
                     const struct dogecoin_map *vbfs,
                     const struct dogecoin_map *assets,
                     const struct dogecoin_map *abfs,
                     const unsigned char *entropy, size_t entropy_len,
                     uint32_t output_index, uint32_t flags,
                     struct dogecoin_map *ephemeral_keys_out)
{
#ifdef BUILD_ELEMENTS
    const secp256k1_context *ctx = secp_ctx();
    unsigned char *fixed_input_tags, *ephemeral_input_tags, *input_abfs;
    unsigned char input_scalar[EC_SCALAR_LEN] = { 0 }, output_scalar[EC_SCALAR_LEN] = { 0 };
    unsigned char *output_statuses; /* Blinding status of each output */
    size_t i, num_to_blind = 0, num_blinded = 0;
    bool did_find_input = false, did_blind_output = false, did_blind_last = false;
    int ret = DOGECOIN_OK;

    if (!ctx)
        return DOGECOIN_ENOMEM;
#endif /* BUILD_ELEMENTS */

    if (!psbt_is_valid(psbt) || !psbt->num_inputs || !psbt->num_outputs ||
        !values || !vbfs || !assets || !abfs || flags ||
        (output_index != DOGECOIN_PSET_BLIND_ALL && output_index >= psbt->num_outputs) ||
        !entropy || !entropy_len)
        return DOGECOIN_EINVAL;
#ifndef BUILD_ELEMENTS
    (void)ephemeral_keys_out;
    return DOGECOIN_OK; /* No-op */
#else
    if (entropy_len % BLINDING_FACTOR_LEN)
        return DOGECOIN_EINVAL;
    output_statuses = libdogecoin_calloc(psbt->num_outputs * sizeof(unsigned char));
    fixed_input_tags = libdogecoin_calloc(psbt->num_inputs * ASSET_TAG_LEN);
    ephemeral_input_tags = libdogecoin_calloc(psbt->num_inputs * ASSET_GENERATOR_LEN);
    input_abfs = libdogecoin_calloc(psbt->num_inputs * BLINDING_FACTOR_LEN);
    if (!output_statuses || !fixed_input_tags || !ephemeral_input_tags || !input_abfs) {
        ret = DOGECOIN_ENOMEM;
        goto done;
    }

    /* Compute the input data needed to blind our outputs */
    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_inputs; ++i) {
        /* TODO: Handle issuance */
        const struct dogecoin_psbt_input *in = psbt->inputs + i;
        const struct libdogecoin_tx_output *utxo = utxo_from_input(psbt, in);
        unsigned char *ephemeral_input_tag = ephemeral_input_tags + i * ASSET_GENERATOR_LEN;
        const struct dogecoin_map_item *value;

        if (!utxo || !utxo->asset || utxo->asset_len != DOGECOIN_TX_ASSET_CT_ASSET_LEN)
            ret = DOGECOIN_EINVAL; /* UTXO not found */
        else
            ret = dogecoin_asset_generator_from_bytes(utxo->asset, utxo->asset_len, NULL, 0,
                                                   ephemeral_input_tag, ASSET_GENERATOR_LEN);
        if (ret != DOGECOIN_OK)
            goto done;

        if ((value = dogecoin_map_get_integer(values, i)) != NULL) {
            const struct dogecoin_map_item *asset = dogecoin_map_get_integer(assets, i);
            const struct dogecoin_map_item *abf = dogecoin_map_get_integer(abfs, i);
            const struct dogecoin_map_item *vbf = dogecoin_map_get_integer(vbfs, i);
            unsigned char tmp[EC_SCALAR_LEN];
            uint64_t satoshi;

            did_find_input = true; /* This input belongs to us */
            ret = libdogecoin_tx_confidential_value_to_satoshi(value->value, value->value_len,
                                                         &satoshi);
            if (ret != DOGECOIN_OK ||
                !asset || asset->value_len != ASSET_TAG_LEN ||
                !abf || abf->value_len != BLINDING_FACTOR_LEN ||
                !vbf || vbf->value_len != BLINDING_FACTOR_LEN) {
                ret = DOGECOIN_EINVAL;
                goto done;
            }

            memcpy(fixed_input_tags + i * ASSET_TAG_LEN, asset->value, asset->value_len);
            memcpy(input_abfs + i * BLINDING_FACTOR_LEN, abf->value, abf->value_len);
            /* Compute the input scalar */
            ret = dogecoin_asset_scalar_offset(satoshi, abf->value, abf->value_len,
                                            vbf->value, vbf->value_len, tmp, sizeof(tmp));
            if (ret == DOGECOIN_OK)
                ret = dogecoin_ec_scalar_add_to(input_scalar, sizeof(input_scalar),
                                             tmp, sizeof(tmp));
        } else {
            /* Not ours: use the UTXO asset commitment and leave asset blinder as 0 */
            memcpy(fixed_input_tags + i * ASSET_TAG_LEN,
                   utxo->asset + 1, utxo->asset_len - 1);
        }
    }

    /* Compute which outputs need blinding */
    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_outputs; ++i) {
        size_t status;
        ret = dogecoin_psbt_output_get_blinding_status(psbt->outputs + i, 0, &status);
        if (ret == DOGECOIN_OK) {
            output_statuses[i] = status & 0xff; /* Store as char to reduce memory use */
            num_blinded += status == DOGECOIN_PSET_BLINDED_FULL ? 1 : 0;
            num_to_blind += status == DOGECOIN_PSET_BLINDED_NONE ? 0 : 1;
        }
    }
    if (ret != DOGECOIN_OK || !num_to_blind || num_to_blind == num_blinded)
        goto done; /* Something failed, or there is nothing to do */

    if (!did_find_input) {
        ret = DOGECOIN_EINVAL; /* No matching inputs found, so no output can be blinded */
        goto done;
    }

    /* Blind each output that needs it */
    for (i = 0; ret == DOGECOIN_OK && i < psbt->num_outputs; ++i) {
        struct dogecoin_psbt_output *out = psbt->outputs + i;
        const unsigned char *abf = entropy;
        const unsigned char *vbf = abf + BLINDING_FACTOR_LEN;
        const unsigned char *ephemeral_key = vbf + BLINDING_FACTOR_LEN;
        const unsigned char *explicit_rangeproof_seed = ephemeral_key + BLINDING_FACTOR_LEN;
        const unsigned char *surjectionproof_seed = explicit_rangeproof_seed + BLINDING_FACTOR_LEN;
        const struct dogecoin_map_item *p = dogecoin_map_get_integer(&out->pset_fields, PSET_OUT_ASSET);
        const unsigned char *asset = p && p->value_len == ASSET_TAG_LEN ? p->value : NULL;
        unsigned char tmp[EC_SCALAR_LEN];
        unsigned char asset_commitment[ASSET_COMMITMENT_LEN];
        unsigned char value_commitment[ASSET_COMMITMENT_LEN];
        unsigned char vbf_buf[EC_SCALAR_LEN];
        const size_t entropy_per_output = 5;

        if (output_index != DOGECOIN_PSET_BLIND_ALL && output_index != i)
            continue; /* We havent been asked to blind this output */

        if (output_statuses[i] == DOGECOIN_PSET_BLINDED_FULL) {
            /* TODO: This is Elements logic, treating an existing blinded output as ours */
            did_blind_output = true;
            continue;
        }

        if (!out->has_blinder_index || !dogecoin_map_get_integer(values, out->blinder_index))
            continue; /* Not our output */

        if (!asset || !out->has_amount || entropy_len < BLINDING_FACTOR_LEN * entropy_per_output) {
            ret = DOGECOIN_EINVAL; /* Missing asset, value, or insufficient entropy */
            goto done;
        }
        entropy += BLINDING_FACTOR_LEN * entropy_per_output;
        entropy_len -= BLINDING_FACTOR_LEN * entropy_per_output;

        /* Compute the output scalar */
        ret = dogecoin_asset_scalar_offset(out->amount, abf, BLINDING_FACTOR_LEN,
                                        vbf, BLINDING_FACTOR_LEN, tmp, sizeof(tmp));
        if (ret == DOGECOIN_OK)
            ret = dogecoin_ec_scalar_add_to(output_scalar, sizeof(output_scalar),
                                         tmp, sizeof(tmp));

        if (++num_blinded == num_to_blind) {
            memcpy(vbf_buf, vbf, sizeof(vbf_buf));
            vbf = vbf_buf;
            ret = compute_final_vbf(psbt, input_scalar, output_scalar, vbf_buf);
            did_blind_last = ret == DOGECOIN_OK;
        }

        if (ret == DOGECOIN_OK)
            ret = dogecoin_asset_generator_from_bytes(asset, ASSET_TAG_LEN,
                                                   abf, BLINDING_FACTOR_LEN,
                                                   asset_commitment, ASSET_COMMITMENT_LEN);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_psbt_output_set_asset_commitment(out, asset_commitment,
                                                         ASSET_COMMITMENT_LEN);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_asset_value_commitment(out->amount, vbf, BLINDING_FACTOR_LEN,
                                               asset_commitment, ASSET_COMMITMENT_LEN,
                                               value_commitment, ASSET_COMMITMENT_LEN);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_psbt_output_set_value_commitment(out, value_commitment,
                                                         ASSET_COMMITMENT_LEN);
        if (ret == DOGECOIN_OK) {
            const struct dogecoin_map_item *blinding_pubkey;
            unsigned char rangeproof[ASSET_RANGEPROOF_MAX_LEN];
            size_t rangeproof_len;
            blinding_pubkey = dogecoin_map_get_integer(&out->pset_fields, PSET_OUT_BLINDING_PUBKEY);
            ret = dogecoin_asset_rangeproof(out->amount,
                                         blinding_pubkey->value, blinding_pubkey->value_len,
                                         ephemeral_key, EC_PRIVATE_KEY_LEN,
                                         asset, ASSET_TAG_LEN,
                                         abf, BLINDING_FACTOR_LEN,
                                         vbf, BLINDING_FACTOR_LEN,
                                         value_commitment, ASSET_COMMITMENT_LEN,
                                         out->script, out->script_len,
                                         asset_commitment, ASSET_COMMITMENT_LEN,
                                         1, 0, 52,
                                         rangeproof, sizeof(rangeproof),
                                         &rangeproof_len);
            if (ret == DOGECOIN_OK)
                ret = dogecoin_psbt_output_set_value_rangeproof(out, rangeproof,
                                                             rangeproof_len);
        }

        if (ret == DOGECOIN_OK) {
            unsigned char rangeproof[ASSET_EXPLICIT_RANGEPROOF_MAX_LEN];
            size_t rangeproof_len;
            ret = dogecoin_explicit_rangeproof(out->amount,
                                            explicit_rangeproof_seed, BLINDING_FACTOR_LEN,
                                            vbf, BLINDING_FACTOR_LEN,
                                            value_commitment, ASSET_COMMITMENT_LEN,
                                            asset_commitment, ASSET_COMMITMENT_LEN,
                                            rangeproof, sizeof(rangeproof),
                                            &rangeproof_len);
            if (ret == DOGECOIN_OK)
                ret = dogecoin_psbt_output_set_value_blinding_rangeproof(out, rangeproof,
                                                                      rangeproof_len);
        }

        if (ret == DOGECOIN_OK) {
            /* FIXME: When issuance is implemented, the input array lengths
             * may be different than psbt->num_inputs * X as passed here */
            unsigned char surjectionproof[ASSET_SURJECTIONPROOF_MAX_LEN];
            size_t surjectionproof_len;
            ret = dogecoin_asset_surjectionproof(asset, ASSET_TAG_LEN,
                                              abf, BLINDING_FACTOR_LEN,
                                              asset_commitment, ASSET_COMMITMENT_LEN,
                                              surjectionproof_seed, 32u,
                                              fixed_input_tags, psbt->num_inputs * ASSET_TAG_LEN,
                                              input_abfs, psbt->num_inputs * BLINDING_FACTOR_LEN,
                                              ephemeral_input_tags, psbt->num_inputs * ASSET_GENERATOR_LEN,
                                              surjectionproof, sizeof(surjectionproof),
                                              &surjectionproof_len);
            if (ret == DOGECOIN_OK) {
                if (surjectionproof_len > sizeof(surjectionproof))
                    ret = DOGECOIN_EINVAL; /* Should never happen */
                ret = dogecoin_psbt_output_set_asset_surjectionproof(out, surjectionproof,
                                                                  surjectionproof_len);
            }
        }

        if (ret == DOGECOIN_OK) {
            unsigned char surjectionproof[ASSET_EXPLICIT_SURJECTIONPROOF_LEN];
            ret = dogecoin_explicit_surjectionproof(asset, ASSET_TAG_LEN,
                                                 abf, BLINDING_FACTOR_LEN,
                                                 asset_commitment, ASSET_COMMITMENT_LEN,
                                                 surjectionproof, sizeof(surjectionproof));
            if (ret == DOGECOIN_OK)
                ret = dogecoin_psbt_output_set_asset_blinding_surjectionproof(out, surjectionproof,
                                                                           sizeof(surjectionproof));
        }

        if (ret == DOGECOIN_OK) {
            unsigned char pubkey[EC_PUBLIC_KEY_LEN];
            ret = dogecoin_ec_public_key_from_private_key(ephemeral_key, EC_PRIVATE_KEY_LEN,
                                                       pubkey, sizeof(pubkey));
            if (ret == DOGECOIN_OK) {
                ret = dogecoin_psbt_output_set_ecdh_public_key(out, pubkey, sizeof(pubkey));
                if (ret == DOGECOIN_OK && ephemeral_keys_out) {
                    /* Return the ephemeral private key for this output */
                    ret = dogecoin_map_add_integer(ephemeral_keys_out, i,
                                                ephemeral_key, EC_PRIVATE_KEY_LEN);
                }
            }
        }

        if (ret == DOGECOIN_OK) {
            did_blind_output = true;
        } else {
            /* FIXME: Delete blinding fields */
            break;
        }
    }

    if (ret == DOGECOIN_OK && !did_blind_output) {
        ret = DOGECOIN_EINVAL; /* We had outputs to blind but didn't blind anything */
        goto done;
    }

    if (ret == DOGECOIN_OK && !did_blind_last && !mem_is_zero(output_scalar, EC_SCALAR_LEN)) {
        ret = dogecoin_ec_scalar_subtract_from(output_scalar, EC_SCALAR_LEN,
                                            input_scalar, EC_SCALAR_LEN);
        if (ret == DOGECOIN_OK)
            ret = dogecoin_map_add(&psbt->global_scalars, output_scalar, EC_SCALAR_LEN, NULL, 0);
    }

done:
    if (ret != DOGECOIN_OK)
        dogecoin_map_clear(ephemeral_keys_out);
    clear_and_free(output_statuses, psbt->num_outputs * sizeof(unsigned char));
    clear_and_free(fixed_input_tags, psbt->num_inputs * ASSET_TAG_LEN);
    clear_and_free(ephemeral_input_tags, psbt->num_inputs * ASSET_GENERATOR_LEN);
    clear_and_free(input_abfs, psbt->num_inputs * BLINDING_FACTOR_LEN);
    return ret;
#endif /* BUILD_ELEMENTS */
}

int dogecoin_psbt_blind_alloc(struct dogecoin_psbt *psbt,
                           const struct dogecoin_map *values,
                           const struct dogecoin_map *vbfs,
                           const struct dogecoin_map *assets,
                           const struct dogecoin_map *abfs,
                           const unsigned char *entropy, size_t entropy_len,
                           uint32_t output_index, uint32_t flags,
                           struct dogecoin_map **output)
{
    int ret;

    OUTPUT_CHECK;
    OUTPUT_ALLOC(struct dogecoin_map);
    ret = dogecoin_psbt_blind(psbt, values, vbfs, assets, abfs,
                           entropy, entropy_len, output_index, flags, *output);
    if (ret != DOGECOIN_OK) {
        dogecoin_map_free(*output);
        *output = NULL;
    }
    return ret;
}

int dogecoin_psbt_is_elements(const struct dogecoin_psbt *psbt, size_t *written)
{
    if (written)
        *written = 0;
    if (!psbt || !written)
        return DOGECOIN_EINVAL;

    *written = memcmp(psbt->magic, PSET_MAGIC, sizeof(PSET_MAGIC)) ? 0 : 1;
    return DOGECOIN_OK;
}

/* Getters for maps in inputs/outputs */
#define PSBT_GET_K(typ, name) \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## s_size(const struct dogecoin_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return DOGECOIN_EINVAL; \
        *written = p->name ## s ? p->name ## s->num_items : 0; \
        return DOGECOIN_OK; \
    }

#define PSBT_GET_M(typ, name) \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## s_size(const struct dogecoin_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return DOGECOIN_EINVAL; \
        *written = p->name ## s.num_items; \
        return DOGECOIN_OK; \
    } \
    int dogecoin_psbt_find_ ## typ ## _ ## name(const struct dogecoin_psbt *psbt, size_t index, \
                                             const unsigned char *key, size_t key_len, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !key || !key_len || !written) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _find_ ## name(p, key, key_len, written); \
    } \
    int dogecoin_psbt_get_ ## typ ## _ ## name(const struct dogecoin_psbt *psbt, size_t index, \
                                            size_t subindex, unsigned char *bytes_out, size_t len, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !bytes_out || !len || !written || subindex >= p->name ## s.num_items) return DOGECOIN_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        if (*written <= len) \
            memcpy(bytes_out, p->name ## s.items[subindex].value, *written); \
        return DOGECOIN_OK; \
    } \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## _len(const struct dogecoin_psbt *psbt, size_t index, \
                                                    size_t subindex, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || subindex >= p->name ## s.num_items) return DOGECOIN_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        return DOGECOIN_OK; \
    }


/* Get a binary buffer value from an input/output */
#define PSBT_GET_B(typ, name, v) \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## _len(const struct dogecoin_psbt *psbt, size_t index, \
                                                    size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return DOGECOIN_EINVAL; \
        *written = p->name ## _len; \
        return DOGECOIN_OK; \
    } \
    int dogecoin_psbt_get_ ## typ ## _ ## name(const struct dogecoin_psbt *psbt, size_t index, \
                                            unsigned char *bytes_out, size_t len, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return DOGECOIN_EINVAL; \
        *written = p->name ## _len; \
        if (p->name ## _len <= len) \
            memcpy(bytes_out, p->name, p->name ## _len); \
        return DOGECOIN_OK; \
    }

/* Set a binary buffer value on an input/output */
#define PSBT_SET_B(typ, name, v) \
    int dogecoin_psbt_set_ ## typ ## _ ## name(struct dogecoin_psbt *psbt, size_t index, \
                                            const unsigned char *name, size_t name ## _len) { \
        if (!psbt || (v && psbt->version != v)) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), name, name ## _len); \
    }

/* Get an integer value from an input/output */
#define PSBT_GET_I(typ, name, inttyp, v) \
    int dogecoin_psbt_get_ ## typ ## _ ## name(const struct dogecoin_psbt *psbt, size_t index, \
                                            inttyp *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (v && psbt->version != v)) return DOGECOIN_EINVAL; \
        *written = p->name; \
        return DOGECOIN_OK; \
    }

/* Set an integer value on an input/output */
#define PSBT_SET_I(typ, name, inttyp, v) \
    int dogecoin_psbt_set_ ## typ ## _ ## name(struct dogecoin_psbt *psbt, size_t index, \
                                            inttyp val) { \
        if (!psbt || (v && psbt->version != v)) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), val); \
    }

/* Get a struct from an input/output */
#define PSBT_GET_S(typ, name, structtyp, clonefn) \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## _alloc(const struct dogecoin_psbt *psbt, size_t index, \
                                                      struct structtyp **output) { \
        const struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (output) *output = NULL; \
        if (!p || !output) return DOGECOIN_EINVAL; \
        return clonefn(p->name, output); \
    }

/* Set a struct on an input/output */
#define PSBT_SET_S(typ, name, structtyp) \
    int dogecoin_psbt_set_ ## typ ## _ ## name(struct dogecoin_psbt *psbt, size_t index, \
                                            const struct structtyp *p) { \
        return dogecoin_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), p); \
    }

/* Methods for a binary fields */
#define PSBT_FIELD(typ, name, ver) \
    int dogecoin_psbt_get_ ## typ ## _ ## name ## _len(const struct dogecoin_psbt *psbt, \
                                                    size_t index, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (ver && psbt->version != ver)) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _get_ ## name ## _len(p, written); \
    } \
    int dogecoin_psbt_get_ ## typ ## _ ## name(const struct dogecoin_psbt *psbt, size_t index, \
                                            unsigned char *bytes_out, size_t len, size_t *written) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || (ver && psbt->version != ver)) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _get_ ## name(p, bytes_out, len, written); \
    } \
    int dogecoin_psbt_clear_ ## typ ## _ ## name(struct dogecoin_psbt *psbt, size_t index) { \
        struct dogecoin_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (!p || (ver && psbt->version != ver)) return DOGECOIN_EINVAL; \
        return dogecoin_psbt_ ## typ ## _clear_ ## name(p); \
    } \
    PSBT_SET_B(typ, name, ver)


PSBT_GET_S(input, utxo, libdogecoin_tx, tx_clone_alloc)
PSBT_GET_S(input, witness_utxo, libdogecoin_tx_output, libdogecoin_tx_output_clone_alloc)
int dogecoin_psbt_get_input_best_utxo_alloc(const struct dogecoin_psbt *psbt, size_t index,
                                         struct libdogecoin_tx_output **output)
{
    const struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    const struct libdogecoin_tx_output *utxo = p ? utxo_from_input(psbt, p) : NULL;
    if (output) *output = NULL;
    if (!utxo || !output) return DOGECOIN_EINVAL;
    return libdogecoin_tx_output_clone_alloc(utxo, output);
}
PSBT_FIELD(input, redeem_script, PSBT_0)
PSBT_FIELD(input, witness_script, PSBT_0)
PSBT_FIELD(input, final_scriptsig, PSBT_0)
PSBT_GET_S(input, final_witness, libdogecoin_tx_witness_stack, libdogecoin_tx_witness_stack_clone_alloc)
PSBT_GET_M(input, keypath)
PSBT_GET_M(input, signature)
PSBT_GET_M(input, unknown)
PSBT_GET_I(input, sighash, size_t, PSBT_0)
int dogecoin_psbt_get_input_previous_txid(const struct dogecoin_psbt *psbt, size_t index,
                                       unsigned char *bytes_out, size_t len)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    const unsigned char *txid;
    if (!p || !bytes_out || len != DOGECOIN_TXHASH_LEN)
        return DOGECOIN_EINVAL;
    txid = psbt->version == PSBT_0 ? psbt->tx->inputs[index].txhash : p->txhash;
    memcpy(bytes_out, txid, DOGECOIN_TXHASH_LEN);
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_input_output_index(const struct dogecoin_psbt *psbt, size_t index,
                                      uint32_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return DOGECOIN_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->inputs[index].index : p->index;
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_input_sequence(const struct dogecoin_psbt *psbt, size_t index,
                                  uint32_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return DOGECOIN_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->inputs[index].sequence : p->sequence;
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_input_required_locktime(const struct dogecoin_psbt *psbt,
                                           size_t index, uint32_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    if (!p->required_locktime) return DOGECOIN_EINVAL;
    *written = p->required_locktime;
    return DOGECOIN_OK;
}

int dogecoin_psbt_has_input_required_locktime(const struct dogecoin_psbt *psbt,
                                           size_t index, size_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    *written = p->required_locktime != 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_input_required_lockheight(const struct dogecoin_psbt *psbt,
                                             size_t index, uint32_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    if (!p->required_lockheight) return DOGECOIN_EINVAL;
    *written = p->required_lockheight;
    return DOGECOIN_OK;
}

int dogecoin_psbt_has_input_required_lockheight(const struct dogecoin_psbt *psbt,
                                             size_t index, size_t *written)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    *written = p->required_lockheight != 0;
    return DOGECOIN_OK;
}

PSBT_SET_S(input, utxo, libdogecoin_tx)
PSBT_SET_S(input, witness_utxo, libdogecoin_tx_output)
int dogecoin_psbt_set_input_witness_utxo_from_tx(struct dogecoin_psbt *psbt, size_t index,
                                              const struct libdogecoin_tx *utxo, uint32_t utxo_index)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    return dogecoin_psbt_input_set_witness_utxo_from_tx(p, utxo, utxo_index);
}
PSBT_SET_S(input, final_witness, libdogecoin_tx_witness_stack)
PSBT_SET_S(input, keypaths, dogecoin_map)
PSBT_SET_S(input, signatures, dogecoin_map)
int dogecoin_psbt_add_input_signature(struct dogecoin_psbt *psbt, size_t index,
                                   const unsigned char *pub_key, size_t pub_key_len,
                                   const unsigned char *sig, size_t sig_len)
{
    struct dogecoin_psbt_input *p = psbt_get_input(psbt, index);
    int ret;
    if (!p)
        return DOGECOIN_EINVAL;
    ret = dogecoin_psbt_input_add_signature(p, pub_key, pub_key_len, sig, sig_len);
    if (ret == DOGECOIN_OK && psbt->version == PSBT_2) {
        /* Update tx_modifiable_flags based on what the signature covers */
        const unsigned char sighash = sig[sig_len - 1];
        if (!(sighash & DOGECOIN_SIGHASH_ANYONECANPAY))
            psbt->tx_modifiable_flags &= ~DOGECOIN_PSBT_TXMOD_INPUTS;
        if ((sighash & DOGECOIN_SIGHASH_MASK) != DOGECOIN_SIGHASH_NONE)
            psbt->tx_modifiable_flags &= ~DOGECOIN_PSBT_TXMOD_OUTPUTS;
        if ((sighash & DOGECOIN_SIGHASH_MASK) == DOGECOIN_SIGHASH_SINGLE)
            psbt->tx_modifiable_flags |= DOGECOIN_PSBT_TXMOD_SINGLE;
    }
    return ret;
}

PSBT_SET_S(input, unknowns, dogecoin_map)
PSBT_SET_I(input, sighash, uint32_t, PSBT_0)
PSBT_SET_B(input, previous_txid, PSBT_2)
PSBT_SET_I(input, output_index, uint32_t, PSBT_2)
PSBT_SET_I(input, sequence, uint32_t, PSBT_2)
int dogecoin_psbt_clear_input_sequence(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_clear_sequence(psbt_get_input(psbt, index));
}
PSBT_SET_I(input, required_locktime, uint32_t, PSBT_2)
int dogecoin_psbt_clear_input_required_locktime(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_clear_required_locktime(psbt_get_input(psbt, index));
}
PSBT_SET_I(input, required_lockheight, uint32_t, PSBT_2)
int dogecoin_psbt_clear_input_required_lockheight(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_clear_required_lockheight(psbt_get_input(psbt, index));
}

#ifdef BUILD_ELEMENTS
PSBT_GET_I(input, amount, uint64_t, PSBT_2)
int dogecoin_psbt_clear_input_amount(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_clear_amount(psbt_get_input(psbt, index));
}
PSBT_GET_I(input, issuance_amount, uint64_t, PSBT_2)
PSBT_GET_I(input, inflation_keys, uint64_t, PSBT_2)
PSBT_GET_I(input, pegin_amount, uint64_t, PSBT_2)

PSBT_SET_I(input, amount, uint64_t, PSBT_2)
PSBT_SET_I(input, issuance_amount, uint64_t, PSBT_2)
PSBT_SET_I(input, inflation_keys, uint64_t, PSBT_2)
PSBT_SET_I(input, pegin_amount, uint64_t, PSBT_2)

PSBT_FIELD(input, amount_rangeproof, PSBT_2)
PSBT_FIELD(input, asset, PSBT_2)
PSBT_FIELD(input, asset_surjectionproof, PSBT_2)
PSBT_FIELD(input, issuance_amount_commitment, PSBT_2)
PSBT_FIELD(input, issuance_amount_rangeproof, PSBT_2)
PSBT_FIELD(input, issuance_blinding_nonce, PSBT_2)
PSBT_FIELD(input, issuance_asset_entropy, PSBT_2)
PSBT_FIELD(input, issuance_amount_blinding_rangeproof, PSBT_2)
PSBT_FIELD(input, pegin_claim_script, PSBT_2)
PSBT_FIELD(input, pegin_genesis_blockhash, PSBT_2)
PSBT_FIELD(input, pegin_txout_proof, PSBT_2)
PSBT_FIELD(input, inflation_keys_commitment, PSBT_2)
PSBT_FIELD(input, inflation_keys_rangeproof, PSBT_2)
PSBT_FIELD(input, inflation_keys_blinding_rangeproof, PSBT_2)
PSBT_FIELD(input, utxo_rangeproof, PSBT_2)
int dogecoin_psbt_generate_input_explicit_proofs(
    struct dogecoin_psbt *psbt, size_t index,
    uint64_t satoshi,
    const unsigned char *asset, size_t asset_len,
    const unsigned char *abf, size_t abf_len,
    const unsigned char *vbf, size_t vbf_len,
    const unsigned char *entropy, size_t entropy_len)
{
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_input_generate_explicit_proofs(psbt_get_input(psbt, index), satoshi,
                                                     asset, asset_len,
                                                     abf, abf_len,
                                                     vbf, vbf_len,
                                                     entropy, entropy_len);
}
#endif /* BUILD_ELEMENTS */

PSBT_FIELD(output, redeem_script, PSBT_0)
PSBT_FIELD(output, witness_script, PSBT_0)
PSBT_GET_M(output, keypath)
PSBT_GET_M(output, unknown)
PSBT_GET_I(output, amount, uint64_t, PSBT_2)
int dogecoin_psbt_has_output_amount(const struct dogecoin_psbt *psbt, size_t index, size_t *written) {
    struct dogecoin_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    *written = p->has_amount ? 1 : 0;
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_output_script_len(const struct dogecoin_psbt *psbt, size_t index,
                                     size_t *written) {
    struct dogecoin_psbt_output *p = psbt_get_output(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return DOGECOIN_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->outputs[index].script_len : p->script_len;
    return DOGECOIN_OK;
}

int dogecoin_psbt_get_output_script(const struct dogecoin_psbt *psbt, size_t index,
                                 unsigned char *bytes_out, size_t len, size_t *written) {
    struct dogecoin_psbt_output *p = psbt_get_output(psbt, index);
    if (written)
        *written = 0;
    if (!p || !written)
        return DOGECOIN_EINVAL;
    *written = psbt->version == PSBT_0 ? psbt->tx->outputs[index].script_len : p->script_len;
    if (*written <= len && *written)
        memcpy(bytes_out,
               psbt->version == PSBT_0 ? psbt->tx->outputs[index].script : p->script,
               *written);
    return DOGECOIN_OK;
}

PSBT_SET_S(output, keypaths, dogecoin_map)
PSBT_SET_S(output, unknowns, dogecoin_map)
PSBT_SET_I(output, amount, uint64_t, PSBT_2)
int dogecoin_psbt_clear_output_amount(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_output_clear_amount(psbt_get_output(psbt, index));
}
PSBT_SET_B(output, script, PSBT_2)


#ifdef BUILD_ELEMENTS
PSBT_GET_I(output, blinder_index, uint32_t, PSBT_2)
int dogecoin_psbt_has_output_blinder_index(const struct dogecoin_psbt *psbt, size_t index, size_t *written) {
    struct dogecoin_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = 0;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    *written = p->has_blinder_index ? 1 : 0;
    return DOGECOIN_OK;
}

PSBT_SET_I(output, blinder_index, uint32_t, PSBT_2)
int dogecoin_psbt_clear_output_blinder_index(struct dogecoin_psbt *psbt, size_t index) {
    if (!psbt || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_output_clear_blinder_index(psbt_get_output(psbt, index));
}

PSBT_FIELD(output, value_commitment, PSBT_2)
PSBT_FIELD(output, asset, PSBT_2)
PSBT_FIELD(output, asset_commitment, PSBT_2)
PSBT_FIELD(output, value_rangeproof, PSBT_2)
PSBT_FIELD(output, asset_surjectionproof, PSBT_2)
PSBT_FIELD(output, blinding_public_key, PSBT_2)
PSBT_FIELD(output, ecdh_public_key, PSBT_2)
PSBT_FIELD(output, value_blinding_rangeproof, PSBT_2)
PSBT_FIELD(output, asset_blinding_surjectionproof, PSBT_2)
int dogecoin_psbt_get_output_blinding_status(const struct dogecoin_psbt *psbt, size_t index, uint32_t flags, size_t *written)
{
    struct dogecoin_psbt_output *p = psbt_get_output(psbt, index);
    if (written) *written = DOGECOIN_PSET_BLINDED_NONE;
    if (!p || !written || psbt->version != PSBT_2) return DOGECOIN_EINVAL;
    return dogecoin_psbt_output_get_blinding_status(p, flags, written);
}
#undef MAX_INVALID_SATOSHI
#endif /* BUILD_ELEMENTS */
