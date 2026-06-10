# Libdogecoin PSBT API

## Table of Contents

- [Libdogecoin PSBT API](#libdogecoin-psbt-api)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Six-Role Pipeline](#six-role-pipeline)
  - [Wire Format](#wire-format)
    - [Global Map](#global-map)
    - [Per-Input Map](#per-input-map)
    - [Per-Output Map](#per-output-map)
  - [Data Structures](#data-structures)
    - [dogecoin\_psbt\_partialsig](#dogecoin_psbt_partialsig)
    - [dogecoin\_psbt\_keypath](#dogecoin_psbt_keypath)
    - [dogecoin\_psbt\_input](#dogecoin_psbt_input)
    - [dogecoin\_psbt\_output](#dogecoin_psbt_output)
    - [dogecoin\_psbt](#dogecoin_psbt)
  - [API Reference](#api-reference)
    - [Lifecycle](#lifecycle)
      - [dogecoin\_psbt\_new](#dogecoin_psbt_new)
      - [dogecoin\_psbt\_free](#dogecoin_psbt_free)
    - [Creator Role](#creator-role)
      - [dogecoin\_psbt\_create](#dogecoin_psbt_create)
    - [Serialization](#serialization)
      - [dogecoin\_psbt\_to\_hex](#dogecoin_psbt_to_hex)
      - [dogecoin\_psbt\_from\_hex](#dogecoin_psbt_from_hex)
      - [dogecoin\_psbt\_to\_base64](#dogecoin_psbt_to_base64)
      - [dogecoin\_psbt\_from\_base64](#dogecoin_psbt_from_base64)
    - [Updater Role](#updater-role)
      - [dogecoin\_psbt\_input\_set\_utxo](#dogecoin_psbt_input_set_utxo)
      - [dogecoin\_psbt\_input\_set\_redeemscript](#dogecoin_psbt_input_set_redeemscript)
      - [dogecoin\_psbt\_input\_set\_sighash](#dogecoin_psbt_input_set_sighash)
      - [dogecoin\_psbt\_input\_add\_keypath](#dogecoin_psbt_input_add_keypath)
    - [Signer Role](#signer-role)
      - [dogecoin\_psbt\_sign](#dogecoin_psbt_sign)
      - [dogecoin\_psbt\_sign\_input](#dogecoin_psbt_sign_input)
    - [Combiner Role](#combiner-role)
      - [dogecoin\_psbt\_combine](#dogecoin_psbt_combine)
    - [Finalizer Role](#finalizer-role)
      - [dogecoin\_psbt\_finalize](#dogecoin_psbt_finalize)
      - [dogecoin\_psbt\_finalize\_input](#dogecoin_psbt_finalize_input)
    - [Extractor Role](#extractor-role)
      - [dogecoin\_psbt\_extract](#dogecoin_psbt_extract)
    - [Validation Helpers](#validation-helpers)
      - [dogecoin\_psbt\_is\_valid](#dogecoin_psbt_is_valid)
      - [dogecoin\_psbt\_is\_finalized](#dogecoin_psbt_is_finalized)
  - [CLI Commands (such)](#cli-commands-such)
    - [psbt\_create](#psbt_create)
    - [psbt\_decode](#psbt_decode)
    - [psbt\_sign](#psbt_sign)
    - [psbt\_finalize](#psbt_finalize)
    - [psbt\_extract](#psbt_extract)
  - [End-to-End C Example](#end-to-end-c-example)

---

## Introduction

Partially Signed Dogecoin Transactions (PSBT) implement [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) (PSBTv0) and [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) (PSBTv2). PSBT is a wire format that wraps an unsigned transaction together with per-input metadata — previous outputs, redeem scripts, partial signatures, BIP32 derivation paths — so that multiple independent parties (hardware wallets, air-gapped signers, co-signers in a multisig quorum) can each contribute signatures without ever sharing private keys or needing a live network connection.

A PSBT travels through up to six well-defined roles before the final signed transaction is produced:

| Role | Responsibility |
|------|----------------|
| Creator | Constructs the unsigned transaction and wraps it in a PSBT |
| Updater | Attaches UTXOs, redeem scripts, and key derivation paths to each input |
| Signer | Adds one or more partial signatures |
| Combiner | Merges PSBTs from multiple signers into one |
| Finalizer | Converts partial signatures into a complete `scriptSig` for each input |
| Extractor | Removes the PSBT envelope and returns the broadcast-ready signed transaction |

The canonical wire encoding uses **base64**. The raw binary format can also be exchanged as **hex** for tooling convenience.

---

## Six-Role Pipeline

```
[Creator]  dogecoin_psbt_create(tx)
    │
    ▼  ── serialize / transport ──────────────────────────────────
[Updater]  dogecoin_psbt_input_set_utxo(psbt, idx, prev_tx)
           dogecoin_psbt_input_set_redeemscript(psbt, idx, ...)   (P2SH)
    │
    ▼  ── serialize / transport ──────────────────────────────────
[Signer]   dogecoin_psbt_sign(psbt, &privkey)
    │
    ▼  ── serialize / transport (repeat for each co-signer) ──────
[Combiner] dogecoin_psbt_combine(dst, src)
    │
    ▼
[Finalizer] dogecoin_psbt_finalize(psbt)
    │
    ▼
[Extractor] tx = dogecoin_psbt_extract(psbt)
            ── broadcast tx ──────────────────────────────────────
```

---

## Wire Format

A PSBT begins with the 5-byte magic `psbt\xff` (`0x70 0x73 0x62 0x74 0xFF`) followed by a series of key-value maps separated by `0x00` terminators.

```
<magic: 5 bytes>
<global key-value pairs>
0x00                       ← end of global map
<input 0 key-value pairs>
0x00                       ← end of input 0 map
...
<input N-1 key-value pairs>
0x00                       ← end of input N-1 map
<output 0 key-value pairs>
0x00                       ← end of output 0 map
...
<output M-1 key-value pairs>
0x00                       ← end of output M-1 map
```

Each key-value entry is:

```
<varint: key length> <key bytes> <varint: value length> <value bytes>
```

### Global Map

| Key type | Key data | Value |
|----------|----------|-------|
| `0x00` | (empty) | Serialized unsigned transaction |
| `0x01` | 78-byte BIP32 xpub | Master fingerprint + derivation path |
| `0xFB` | (empty) | PSBT version (BIP370; `0x02000000` for v2) |

### Per-Input Map

| Key type | Key data | Value |
|----------|----------|-------|
| `0x00` | (empty) | Full previous transaction (non-witness UTXO) |
| `0x02` | 33-byte compressed public key | DER signature + sighash byte |
| `0x03` | (empty) | Sighash type (`uint32_t LE`) |
| `0x04` | (empty) | Redeem script (P2SH) |
| `0x06` | 33-byte compressed public key | BIP32 fingerprint + derivation path |
| `0x07` | (empty) | Final `scriptSig` (set by the finalizer) |

### Per-Output Map

| Key type | Key data | Value |
|----------|----------|-------|
| `0x00` | (empty) | Redeem script (P2SH change output) |
| `0x02` | 33-byte compressed public key | BIP32 fingerprint + derivation path |

---

## Data Structures

All structures are defined in `include/dogecoin/psbt.h`.

### dogecoin_psbt_partialsig

One partial signature contributed by a single signer. The key is the compressed public key; the value is a DER-encoded signature with the sighash type byte appended.

```c
typedef struct dogecoin_psbt_partialsig {
    uint8_t pubkey[PSBT_MAX_PUBKEY_LEN];  /* 33 bytes compressed */
    size_t  pubkey_len;
    uint8_t sig[PSBT_MAX_SIG_LEN];        /* DER sig (≤73 bytes) + sighash byte */
    size_t  sig_len;
} dogecoin_psbt_partialsig;
```

### dogecoin_psbt_keypath

BIP32 derivation path attached to a public key, enabling hardware wallets to locate the correct signing key.

```c
typedef struct dogecoin_psbt_keypath {
    uint8_t  pubkey[PSBT_MAX_PUBKEY_LEN];
    size_t   pubkey_len;
    uint32_t fingerprint;  /* 4-byte master key fingerprint */
    uint32_t *path;        /* array of BIP32 path components */
    size_t   path_len;
} dogecoin_psbt_keypath;
```

### dogecoin_psbt_input

Per-input metadata. Fields are optional; unset fields are `NULL` / zero.

```c
typedef struct dogecoin_psbt_input {
    dogecoin_tx *non_witness_utxo;      /* 0x00: full previous tx */
    cstring     *redeem_script;         /* 0x04: P2SH redeem script */
    cstring     *final_script_sig;      /* 0x07: finalized scriptSig */
    uint32_t     sighash_type;          /* 0x03: sighash flag (0 = use SIGHASH_ALL) */
    dogecoin_bool has_sighash_type;

    dogecoin_psbt_partialsig *partial_sigs;
    size_t                    num_partial_sigs;

    dogecoin_psbt_keypath    *keypaths;
    size_t                    num_keypaths;
} dogecoin_psbt_input;
```

### dogecoin_psbt_output

Per-output metadata. Currently holds an optional P2SH redeem script and BIP32 keypath entries for change outputs.

```c
typedef struct dogecoin_psbt_output {
    cstring *redeem_script;
    dogecoin_psbt_keypath *keypaths;
    size_t                 num_keypaths;
} dogecoin_psbt_output;
```

### dogecoin_psbt

The top-level PSBT container.

```c
typedef struct dogecoin_psbt {
    dogecoin_tx         *tx;          /* unsigned transaction */
    uint32_t             version;     /* PSBT_VERSION_0 or PSBT_VERSION_2 */

    dogecoin_psbt_input  *inputs;
    size_t                num_inputs;

    dogecoin_psbt_output *outputs;
    size_t                num_outputs;
} dogecoin_psbt;
```

---

## API Reference

Include `dogecoin/libdogecoin.h` (or `dogecoin/psbt.h` for internal use).

---

### Lifecycle

#### dogecoin_psbt_new

```c
dogecoin_psbt* dogecoin_psbt_new(void);
```

Allocate an empty PSBT with no transaction and no inputs or outputs. Useful when constructing a PSBT by hand before calling `dogecoin_psbt_deserialize`.

_C usage:_
```c
dogecoin_psbt* psbt = dogecoin_psbt_new();
/* ... populate fields ... */
dogecoin_psbt_free(psbt);
```

---

#### dogecoin_psbt_free

```c
void dogecoin_psbt_free(dogecoin_psbt* psbt);
```

Free a PSBT and all owned memory (transaction, inputs, outputs, partial sigs, keypaths, scripts). Safe to call with `NULL`.

_C usage:_
```c
dogecoin_psbt_free(psbt);
```

---

### Creator Role

#### dogecoin_psbt_create

```c
dogecoin_psbt* dogecoin_psbt_create(const dogecoin_tx* tx);
```

Wrap an unsigned transaction in a new PSBT (BIP174 §7.1 creator role). The transaction must have all inputs with **empty** `scriptSig` fields; if any input already has a non-empty script the function returns `NULL`. The transaction is deep-copied into the PSBT.

Returns a newly allocated `dogecoin_psbt*` on success, `NULL` on failure. Caller frees with `dogecoin_psbt_free`.

_C usage:_
```c
dogecoin_tx* tx = dogecoin_tx_new();
/* ... add inputs and outputs ... */
dogecoin_psbt* psbt = dogecoin_psbt_create(tx);
dogecoin_tx_free(tx);  /* PSBT owns its own copy */
if (!psbt) { /* handle error */ }
```

---

### Serialization

#### dogecoin_psbt_to_hex

```c
char* dogecoin_psbt_to_hex(const dogecoin_psbt* psbt);
```

Serialize the PSBT to a lowercase hex string. The returned string is heap-allocated; **caller must free with `dogecoin_free()`**.

_C usage:_
```c
char* hex = dogecoin_psbt_to_hex(psbt);
printf("psbt: %s\n", hex);
dogecoin_free(hex);
```

---

#### dogecoin_psbt_from_hex

```c
dogecoin_bool dogecoin_psbt_from_hex(const char* hex, dogecoin_psbt** out);
```

Deserialize a PSBT from a hex string. On success, `*out` points to a newly allocated `dogecoin_psbt`; caller frees with `dogecoin_psbt_free`. Returns `false` on parse error.

_C usage:_
```c
dogecoin_psbt* psbt = NULL;
if (!dogecoin_psbt_from_hex(hex_str, &psbt)) {
    /* parse error */
}
/* use psbt ... */
dogecoin_psbt_free(psbt);
```

---

#### dogecoin_psbt_to_base64

```c
char* dogecoin_psbt_to_base64(const dogecoin_psbt* psbt);
```

Serialize the PSBT to a base64 string — the canonical PSBT wire encoding defined by BIP174. The returned string is heap-allocated; **caller must free with `dogecoin_free()`**.

_C usage:_
```c
char* b64 = dogecoin_psbt_to_base64(psbt);
printf("PSBT: %s\n", b64);
dogecoin_free(b64);
```

---

#### dogecoin_psbt_from_base64

```c
dogecoin_bool dogecoin_psbt_from_base64(const char* b64, dogecoin_psbt** out);
```

Deserialize a PSBT from a base64 string. On success, `*out` points to a newly allocated `dogecoin_psbt`; caller frees with `dogecoin_psbt_free`. Returns `false` on parse error.

_C usage:_
```c
dogecoin_psbt* psbt = NULL;
if (!dogecoin_psbt_from_base64(b64_str, &psbt)) {
    /* parse error */
}
dogecoin_psbt_free(psbt);
```

---

### Updater Role

The updater attaches metadata to inputs and outputs so that downstream signers have everything they need to compute sighashes.

#### dogecoin_psbt_input_set_utxo

```c
dogecoin_bool dogecoin_psbt_input_set_utxo(
    dogecoin_psbt* psbt, size_t idx, const dogecoin_tx* utxo);
```

Attach the full previous transaction for input `idx` (BIP174 PSBT_IN_NON_WITNESS_UTXO, key type `0x00`). The signer needs this to look up the `scriptPubKey` of the output being spent and to compute the correct sighash. The UTXO transaction is deep-copied. Returns `false` if `idx` is out of range.

_C usage:_
```c
dogecoin_tx* prev_tx = /* load or build the previous tx */;
dogecoin_psbt_input_set_utxo(psbt, 0, prev_tx);
dogecoin_tx_free(prev_tx);  /* PSBT owns its own copy */
```

---

#### dogecoin_psbt_input_set_redeemscript

```c
dogecoin_bool dogecoin_psbt_input_set_redeemscript(
    dogecoin_psbt* psbt, size_t idx, const uint8_t* script, size_t len);
```

Attach a P2SH redeem script for input `idx` (key type `0x04`). Required when spending a P2SH output so the finalizer can construct a valid `scriptSig`. Returns `false` if `idx` is out of range.

---

#### dogecoin_psbt_input_set_sighash

```c
dogecoin_bool dogecoin_psbt_input_set_sighash(
    dogecoin_psbt* psbt, size_t idx, uint32_t sighash_type);
```

Override the sighash type for input `idx` (key type `0x03`). If not set, signers default to `SIGHASH_ALL` (`0x01`). Returns `false` if `idx` is out of range.

---

#### dogecoin_psbt_input_add_keypath

```c
dogecoin_bool dogecoin_psbt_input_add_keypath(
    dogecoin_psbt* psbt, size_t idx,
    const uint8_t* pubkey, size_t pubkey_len,
    uint32_t fingerprint, const uint32_t* path, size_t path_len);
```

Add a BIP32 derivation path entry for a public key on input `idx` (key type `0x06`). Hardware wallets use this to locate the signing key without scanning the full keystore. `fingerprint` is the 4-byte master key fingerprint; `path` is an array of `path_len` hardened/unhardened BIP32 index values. Returns `false` if `idx` is out of range.

---

### Signer Role

#### dogecoin_psbt_sign

```c
dogecoin_bool dogecoin_psbt_sign(dogecoin_psbt* psbt, const dogecoin_key* privkey);
```

Attempt to add a partial signature for every input that can be signed with `privkey`. An input is signable when it has a `non_witness_utxo` whose output scriptPubKey matches the public key derived from `privkey`. Returns `true` if at least one input was signed, `false` if none matched.

The function adds a DER-encoded signature (with sighash type byte appended) to `input.partial_sigs`. It does **not** finalize the input.

_C usage:_
```c
dogecoin_key priv;
dogecoin_privkey_init(&priv);
dogecoin_privkey_decode_wif("QThTEryCwuNN...", &dogecoin_chainparams_main, &priv);

if (!dogecoin_psbt_sign(psbt, &priv)) {
    printf("No inputs matched this key.\n");
}
dogecoin_privkey_cleanse(&priv);
```

---

#### dogecoin_psbt_sign_input

```c
dogecoin_bool dogecoin_psbt_sign_input(
    dogecoin_psbt* psbt, size_t idx, const dogecoin_key* privkey);
```

Sign a specific input by index. Follows the same rules as `dogecoin_psbt_sign` but targets only input `idx`. Useful in multisig workflows where each co-signer controls a known input. Returns `false` if the input lacks a UTXO or the key does not match the scriptPubKey.

---

### Combiner Role

#### dogecoin_psbt_combine

```c
dogecoin_bool dogecoin_psbt_combine(dogecoin_psbt* dst, const dogecoin_psbt* src);
```

Merge partial signatures (and other per-input metadata) from `src` into `dst`. Both PSBTs must wrap the same unsigned transaction (same number of inputs). New partial signatures from `src` that are not already present in `dst` are appended. Returns `false` if the input counts differ.

_C usage:_
```c
/* Alice and Bob each sign their own copy, then a combiner merges them. */
dogecoin_psbt_combine(alice_psbt, bob_psbt);
/* alice_psbt now has both Alice's and Bob's partial sigs */
```

---

### Finalizer Role

#### dogecoin_psbt_finalize

```c
dogecoin_bool dogecoin_psbt_finalize(dogecoin_psbt* psbt);
```

Build a complete `final_script_sig` for every input that has enough partial signatures. For P2PKH inputs a single signature is sufficient; for P2SH multisig inputs at least M signatures must be present. Returns `true` only when **all** inputs have been finalized.

_C usage:_
```c
if (!dogecoin_psbt_finalize(psbt)) {
    printf("Not all inputs finalized — more signatures required.\n");
}
```

---

#### dogecoin_psbt_finalize_input

```c
dogecoin_bool dogecoin_psbt_finalize_input(dogecoin_psbt* psbt, size_t idx);
```

Finalize a single input by index. Returns `false` if the input has no partial signatures or if `idx` is out of range.

---

### Extractor Role

#### dogecoin_psbt_extract

```c
dogecoin_tx* dogecoin_psbt_extract(const dogecoin_psbt* psbt);
```

Produce a fully-signed `dogecoin_tx` from a finalized PSBT. The returned transaction has each input's `scriptSig` populated from the corresponding `final_script_sig`. Returns `NULL` if any input lacks a `final_script_sig`. The caller owns the returned transaction and must free it with `dogecoin_tx_free`.

_C usage:_
```c
dogecoin_tx* signed_tx = dogecoin_psbt_extract(psbt);
if (!signed_tx) {
    printf("PSBT not fully finalized.\n");
} else {
    /* serialize and broadcast signed_tx */
    dogecoin_tx_free(signed_tx);
}
```

---

### Validation Helpers

#### dogecoin_psbt_is_valid

```c
dogecoin_bool dogecoin_psbt_is_valid(const dogecoin_psbt* psbt);
```

Return `true` if the PSBT passes basic sanity checks: non-NULL, has an unsigned transaction, and the input/output counts match the transaction's vin/vout counts.

---

#### dogecoin_psbt_is_finalized

```c
dogecoin_bool dogecoin_psbt_is_finalized(const dogecoin_psbt* psbt);
```

Return `true` if every input has a non-NULL `final_script_sig`. A finalized PSBT is ready for extraction.

---

## CLI Commands (such)

The `such` CLI exposes five PSBT commands. All commands accept a PSBT in **hex** via `-x`.

### psbt_create

```
./such -c psbt_create -x <unsigned_tx_hex>
```

Wrap an unsigned transaction in a PSBT and print the resulting PSBT as both hex and base64.

```
$ ./such -c psbt_create -x 0200000001b4455e...00000000
psbt_hex: 70736274ff01005502...000000
psbt_base64: cHNidP8BAFU...AAAA
```

Returns exit code `1` if `-x` is absent or the hex is not a valid unsigned transaction (non-empty scriptSigs are rejected).

---

### psbt_decode

```
./such -c psbt_decode -x <psbt_hex>
```

Decode a PSBT and print a summary of its contents: version, input/output counts, validity, finalization state, and per-input status.

```
$ ./such -c psbt_decode -x 70736274ff...
psbt_version: 0
psbt_inputs: 1
psbt_outputs: 1
psbt_valid: true
psbt_finalized: false
input[0].has_utxo: false
input[0].partial_sigs: 0
input[0].finalized: false
```

---

### psbt_sign

```
./such -c psbt_sign -x <psbt_hex> -p <wif_privkey>
```

Add a partial signature to every input whose scriptPubKey matches the given key. Prints the updated PSBT hex and base64. Returns exit code `1` if no inputs were signed (key mismatch or missing UTXO).

> **Note:** The PSBT must have UTXOs attached (via the updater role) before signing.  
> Use `psbt_decode` to confirm `input[N].has_utxo: true` before calling `psbt_sign`.

```
$ ./such -c psbt_sign -x <psbt_with_utxo_hex> -p QThTEryCwuNN...
psbt_hex: 70736274ff...
psbt_base64: cHNidP8B...
```

---

### psbt_finalize

```
./such -c psbt_finalize -x <psbt_hex>
```

Finalize all inputs and print the updated PSBT hex and base64. Returns exit code `1` if any input cannot be finalized (insufficient signatures).

```
$ ./such -c psbt_finalize -x <signed_psbt_hex>
psbt_hex: 70736274ff...
psbt_base64: cHNidP8B...
```

---

### psbt_extract

```
./such -c psbt_extract -x <psbt_hex>
```

Extract the fully-signed transaction and print its raw hex. Returns exit code `1` if the PSBT is not fully finalized.

```
$ ./such -c psbt_extract -x <finalized_psbt_hex>
tx_hex: 02000000...
```

---

## End-to-End C Example

The following example demonstrates the complete BIP174 pipeline for a single-signer P2PKH transaction. A full working version is also in `contrib/examples/example.c`.

```c
#include "libdogecoin.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    dogecoin_ecc_start();

    /* ── 1. Creator: generate a keypair and build the previous tx ── */
    dogecoin_key priv;
    dogecoin_privkey_init(&priv);
    dogecoin_privkey_gen(&priv);

    dogecoin_pubkey pub;
    dogecoin_pubkey_init(&pub);
    pub.compressed = true;
    dogecoin_pubkey_from_key(&priv, &pub);

    char addr[P2PKHLEN];
    dogecoin_pubkey_getaddr_p2pkh(&pub, &dogecoin_chainparams_main, addr);

    /* Build a fake UTXO: 10 DOGE P2PKH output to our address */
    dogecoin_tx* prev_tx = dogecoin_tx_new();
    dogecoin_tx_add_address_out(prev_tx, &dogecoin_chainparams_main,
                                1000000000LL /* 10 DOGE */, addr);

    /* Build the unsigned spending tx via the transaction builder */
    const char* dest = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
    int tix = start_transaction();
    add_utxo(tix, "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 0);
    add_output(tix, dest, "9.9");
    char* unsigned_hex = finalize_transaction(tix, dest, "0.1", "10", addr);

    size_t hlen = strlen(unsigned_hex);
    unsigned char* buf = dogecoin_uchar_vla(hlen / 2 + 1);
    size_t blen = 0;
    utils_hex_to_bin(unsigned_hex, buf, hlen, &blen);

    dogecoin_tx* spend_tx = dogecoin_tx_new();
    dogecoin_tx_deserialize(buf, blen, spend_tx, NULL);
    dogecoin_free(buf);
    remove_all();

    dogecoin_psbt* psbt = dogecoin_psbt_create(spend_tx);
    dogecoin_tx_free(spend_tx);

    /* ── 2. Serialize for transport ── */
    char* b64 = dogecoin_psbt_to_base64(psbt);
    printf("Unsigned PSBT: %s\n\n", b64);
    dogecoin_free(b64);

    /* ── 3. Updater: attach the UTXO ── */
    dogecoin_psbt_input_set_utxo(psbt, 0, prev_tx);
    dogecoin_tx_free(prev_tx);

    /* ── 4. Signer: add partial signature ── */
    dogecoin_psbt_sign(psbt, &priv);

    /* ── 5. Finalizer: build final_script_sig ── */
    dogecoin_psbt_finalize(psbt);

    /* ── 6. Extractor: pull out the signed tx ── */
    dogecoin_tx* signed_tx = dogecoin_psbt_extract(psbt);

    uint256_t txhash;
    dogecoin_tx_hash(signed_tx, txhash);
    char txhash_hex[65];
    utils_bin_to_hex(txhash, 32, txhash_hex);
    printf("Signed tx hash: %s\n", txhash_hex);

    dogecoin_tx_free(signed_tx);
    dogecoin_psbt_free(psbt);
    dogecoin_pubkey_cleanse(&pub);
    dogecoin_privkey_cleanse(&priv);
    dogecoin_ecc_stop();
    return 0;
}
```

Build against the static library:

```sh
gcc example.c .libs/libdogecoin.a \
    -I./include/dogecoin -lpthread -levent -levent_core -levent_extra -lm \
    -o psbt_example
./psbt_example
```
