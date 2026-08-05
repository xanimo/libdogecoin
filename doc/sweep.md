# Paper Wallet Sweeping and BIP38 Support

This document describes BIP-0038 private key encryption and paper-wallet sweeping in libdogecoin. The library builds and signs transactions; **your application** supplies UTXOs, fees, destination, and broadcast (same split as dogecoin-wallet uses with BlockCypher + bitcoinj).

## Including the Headers

```c
#include <dogecoin/bip38.h>
#include <dogecoin/sweep.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/ecc.h>
```

`libdogecoin.h` documents these APIs inline but does not include `bip38.h` / `sweep.h` (keeps enclave and minimal builds lean). Include the headers above when calling BIP38 or sweep functions.

Call `dogecoin_ecc_start()` before any signing or BIP38 scrypt work, and `dogecoin_ecc_stop()` when finished.

## Architecture (lib vs app)

| Responsibility | Application (e.g. dogecoin-wallet) | libdogecoin |
|----------------|-------------------------------------|-------------|
| Scan / paste `6P…` BIP38 key | Yes | Decrypt via `dogecoin_bip38_decrypt` |
| Passphrase UI | Yes | — |
| Find UTXOs (indexer, node, wallet DB) | Yes | — |
| `txid`, `vout`, amount per coin | Yes | `dogecoin_sweep_options_set_utxo` / `add_utxo` |
| Fee policy | Yes | `dogecoin_sweep_options_set_fee` |
| Destination address | Yes | `dogecoin_sweep_options_set_destination` |
| Build + sign sweep tx | — | `dogecoin_sweep_paper_wallet` |
| Broadcast | Yes (or `WITH_NET`) | Optional `dogecoin_sweep_broadcast_transaction` |

## BIP-0038 API

Passphrases are NFC-normalized (Unicode) before scrypt, per BIP-0038. Non-EC encrypt uses Dogecoin `D…` addresses; decrypt also accepts legacy Bitcoin interoperability vectors.

```c
// Non-EC (0x42): encrypt an existing private key
dogecoin_bip38_encrypt(privkey, passphrase, doge_address, compressed, enc_out, &enc_sz);

// EC-multiplied (0x43): two-party flow
dogecoin_bip38_generate_intermediate_code(passphrase, use_lot, lot, seq, NULL, intermediate, &isz);
dogecoin_bip38_encrypt_from_intermediate(intermediate, compressed, NULL, "D…", enc, &esz, confirm, &csz);
// Or one-shot: dogecoin_bip38_encrypt_ec_multiplied(passphrase, compressed, use_lot, lot, seq, "D…", priv, enc, &esz, confirm, &csz);

// Decrypt (0x42 and 0x43)
dogecoin_bip38_decrypt(enc_key, passphrase, privkey_out, &compressed);
dogecoin_bip38_decrypt_ex(enc_key, passphrase, BIP38_ADDRESS_MATCH_MAINNET, privkey_out, &compressed);
/* BIP38_ADDRESS_MATCH_INTEROP — testnet/regtest + legacy Bitcoin P2PKH for BIP-0038 vectors */
dogecoin_bip38_decrypt_passphrase(enc_key, passphrase_bytes, passphrase_len, privkey_out, &compressed);
dogecoin_bip38_decrypt_passphrase_ex(enc_key, passphrase_bytes, passphrase_len, BIP38_ADDRESS_MATCH_MAINNET, privkey_out, &compressed);
dogecoin_bip38_encrypt_passphrase(privkey, passphrase_bytes, passphrase_len, "D…", compressed, enc, &esz);
dogecoin_bip38_decrypt_with_lot_sequence(enc_key, passphrase, privkey_out, &compressed, &lot, &seq);
dogecoin_bip38_decrypt_with_lot_sequence_ex(enc_key, passphrase, BIP38_ADDRESS_MATCH_MAINNET, privkey_out, &compressed, &lot, &seq);

// Owner verifies printer confirmation code (cfrm38…)
dogecoin_bip38_confirm_passphrase(passphrase, confirm_code, address_out, sizeof(address_out), &compressed, &lot, &seq);
dogecoin_bip38_confirm_passphrase_ex(passphrase, confirm_code, BIP38_ADDRESS_MATCH_MAINNET, address_out, sizeof(address_out), &compressed, &lot, &seq);

// WIF helpers (chain-specific secret prefix from dogecoin_chainparams)
dogecoin_bip38_private_key_to_wif(privkey, chain, compressed, wif_out, &wif_sz);
dogecoin_bip38_wif_to_private_key(wif, chain, privkey_out, &compressed);

// Introspection / validation
dogecoin_bip38_is_valid(enc_key);
dogecoin_bip38_is_intermediate_code(intermediate);
dogecoin_bip38_is_confirmation_code(confirm_code);
dogecoin_bip38_is_compressed(enc_key);
dogecoin_bip38_is_ec_multiplied(enc_key);
dogecoin_bip38_has_lot_sequence(enc_key);
dogecoin_bip38_get_address_hash(enc_key, hash4_out);
dogecoin_bip38_verify_address_hash(enc_key, "D…");
dogecoin_bip38_get_flag_byte(enc_key, &flag);
dogecoin_bip38_generate_lot_sequence(&lot, &seq);
```

Paper wallet wrapper (decrypt + derive `D…` address):

```c
dogecoin_paper_wallet* w = dogecoin_paper_wallet_new();
dogecoin_paper_wallet_set_encrypted(w, "6P…", "passphrase", &dogecoin_chainparams_main);
// or: dogecoin_paper_wallet_set_wif(w, wif, chain);
// or: dogecoin_paper_wallet_set_hex(w, hex_privkey, true /* compressed */, chain);

char address[36];
dogecoin_paper_wallet_get_address(w, address, sizeof(address));
uint8_t privkey[32];
dogecoin_paper_wallet_get_private_key(w, privkey);
char wif[PRIVKEYWIFLEN];
dogecoin_paper_wallet_get_wif(w, wif, sizeof(wif));
dogecoin_bool ok = dogecoin_paper_wallet_is_valid(w);
dogecoin_paper_wallet_free(w);
```

`dogecoin_paper_wallet_set_encrypted()` uses Dogecoin-mainnet BIP38 decrypt semantics (`BIP38_ADDRESS_MATCH_MAINNET`). For strict Bitcoin-only BIP-0038 interop vectors, call `dogecoin_bip38_decrypt_ex()` with `BIP38_ADDRESS_MATCH_INTEROP` directly.

### Address-match semantics (quick reference)

| API | Mode | Accepts |
|-----|------|---------|
| `dogecoin_bip38_decrypt()` | mainnet (default) | Dogecoin mainnet P2PKH address hash |
| `dogecoin_bip38_decrypt_ex(..., INTEROP, ...)` | interoperability | mainnet + testnet + regtest + legacy Bitcoin `1…` P2PKH |
| `dogecoin_bip38_confirm_passphrase()` | mainnet (default) | Same mainnet check; outputs matching `D…` address |
| `dogecoin_bip38_confirm_passphrase_ex(..., INTEROP, ...)` | interoperability | Same multi-chain/legacy matching as decrypt interop |
| `dogecoin_paper_wallet_set_encrypted()` | mainnet wrapper | Decrypt via `MAINNET`; address from your `chain_params` |
| `dogecoin_bip38_verify_address_hash()` | literal helper | Embedded hash vs one address string you supply (no mode flag) |

Official BIP-0038 reference vectors that use legacy Bitcoin addresses require `BIP38_ADDRESS_MATCH_INTEROP` on the `_ex` decrypt/confirm helpers — plain `dogecoin_bip38_decrypt()` will reject them by design.

### Scrypt note

BIP38 passphrase KDF uses RFC 7914 scrypt with caller-chosen `N/r/p` via `dogecoin_scrypt_rfc7914()` in `scrypt.c`. That is separate from the fixed PoW entry point `scrypt_1024_1_1_256()` (mining parameters, 32-byte output). BIP38 calls the RFC helper internally; applications normally do not call it directly.

## Sweep API — caller supplies chain data

### Single UTXO

```c
dogecoin_sweep_options* opt = dogecoin_sweep_options_new(&dogecoin_chainparams_main);
dogecoin_sweep_options_set_destination(opt, "D…");
dogecoin_sweep_options_set_fee(opt, 1000, 1000, 1000000); /* per-byte, min, max koinu */
dogecoin_sweep_options_set_utxo(opt, txid_hex, vout, "12.5"); /* amount in DOGE */

dogecoin_sweep_result* r = dogecoin_sweep_paper_wallet(wallet, opt);
if (r->success) {
    /* or use accessors: */
    dogecoin_sweep_result_get_transaction_hex(r);
    dogecoin_sweep_result_get_transaction_id(r);
    dogecoin_sweep_result_get_amount_swept(r);
    dogecoin_sweep_result_get_fee_paid(r);
    dogecoin_sweep_result_get_destination_address(r);
} else {
    dogecoin_sweep_result_get_error(r);
}
dogecoin_sweep_result_free(r);
```

Fee estimate before building (uses UTXO count on `opt`):

```c
uint64_t est = dogecoin_sweep_estimate_fee(wallet, opt);
```

### Multiple UTXOs (same private key — “empty wallet” sweep)

Use when your indexer returns several coins at one address (like dogecoin-wallet `emptyWallet`):

```c
dogecoin_sweep_options_set_destination(opt, "D…");
dogecoin_sweep_options_set_fee(opt, fee_per_byte, min_fee, max_fee);
dogecoin_sweep_options_add_utxo(opt, txid1, vout1, "50.0");
dogecoin_sweep_options_add_utxo(opt, txid2, vout2, "50.0");
/* dogecoin_sweep_options_utxo_count(opt) == 2 */

dogecoin_sweep_result* r = dogecoin_sweep_paper_wallet(wallet, opt);
```

`set_utxo` replaces the list with one entry; `add_utxo` appends.

### Multiple paper wallets (one UTXO each)

```c
dogecoin_paper_wallet wallets[2];
/* ... initialize each wallet (WIF or BIP38) ... */
/* options must have exactly wallet_count UTXOs, in matching order */
dogecoin_sweep_options_add_utxo(opt, txid_a, 0, "10.0");
dogecoin_sweep_options_add_utxo(opt, txid_b, 1, "20.0");
dogecoin_sweep_result* r = dogecoin_sweep_multiple_paper_wallets(wallets, 2, opt);
```

### Fee mapping from “per kB” (wallet UI)

Many wallets expose fee per kilobyte. Convert before `set_fee`:

```c
uint64_t per_byte = dogecoin_sweep_fee_per_kb_to_per_byte(fee_per_kb_koinu);
dogecoin_sweep_options_set_fee(opt, per_byte, min_fee, max_fee);
```

Fee estimate uses ~180 vbytes per P2PKH input + one P2PKH output.

### Optional: RBF and locktime

```c
dogecoin_sweep_options_set_rbf(opt, true);      /* nSequence 0xfffffffd */
dogecoin_sweep_options_set_locktime(opt, height_or_timestamp);
```

### Step-by-step (unsigned → sign → validate)

```c
dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, opt);
dogecoin_sweep_sign_transaction(tx, wallet);
dogecoin_sweep_validate_transaction(tx, wallet, opt);
dogecoin_tx_free(tx);
```

### Broadcast (optional build flag)

With `WITH_NET`:

```c
dogecoin_sweep_broadcast_transaction(tx, chain, txid_out, sizeof(txid_out));
```

Otherwise broadcast `r->transaction_hex` with your own node/RPC.

### Balance (optional `WITH_WALLET`)

Local wallet DB only — not a chain indexer:

```c
uint64_t bal;
dogecoin_sweep_get_balance("D…", chain, &bal);
```

## Security

1. Use strong BIP38 passphrases; scrypt may take tens of seconds (run off UI thread in apps).
2. Clear sensitive buffers after use (`dogecoin_mem_zero` on privkeys).
3. Verify decrypted keys match expected address (`dogecoin_bip38_verify_address_hash`).
4. Confirm `txid` / `vout` / amounts from a trusted source before signing.

## Validation and stats

After signing, `dogecoin_sweep_validate_transaction` checks that inputs are signed, the destination appears in outputs, output value matches the fee math from your UTXO list, and optional RBF / locktime flags match.

```c
dogecoin_sweep_validate_transaction(tx, wallet, opt);

uint64_t inputs, outputs, in_value, out_value, fee;
dogecoin_sweep_get_stats(tx, opt, &inputs, &outputs, &in_value, &out_value, &fee);
/* Pass opt (with UTXO amounts) so in_value and fee are filled; NULL leaves them zero. */
```

## Example program

`contrib/examples/sweep_example.c` shows WIF and BIP38 sweep flows (offline, no broadcast).

`contrib/examples/mainnet_sweep_driver.c` is a CLI driver for the full sweep API on mainnet (create, sign, validate, optional broadcast). Built automatically by `contrib/mainnet_bip38_sweep_test.sh`, or manually:

```bash
gcc contrib/examples/mainnet_sweep_driver.c .libs/libdogecoin.a \
    $(pkg-config --libs libevent) -lpthread -Iinclude -Iinclude/dogecoin \
    -o mainnet_sweep_driver
```

### Mainnet end-to-end test script

`contrib/mainnet_bip38_sweep_test.sh` runs unit tests, builds the sweep driver, sweeps all UTXOs from a funded address via the sweep API (with optional BIP38 encrypt/decrypt round trip), and exercises SPV checkpoint sync. **Requires** a funded mainnet wallet via environment variables (no credentials in the script):

```bash
export FUNDED_WIF="your_mainnet_wif"
export FUNDED_ADDR="your_D_address"
# optional: SKIP_BROADCAST=1
./contrib/mainnet_bip38_sweep_test.sh
```

Build from the repo root after `make`:

```bash
gcc contrib/examples/sweep_example.c .libs/libdogecoin.a -Iinclude/dogecoin -o sweep_example
```

## Testing

Tests live in `test/sweep_tests.c`, run via `test_sweep()` in the unified `tests` binary:

```bash
make check    # autotools
# or ./tests after build
```

## API reference

### `bip38.h` — encryption / decryption

| Function | Purpose |
|----------|---------|
| `dogecoin_bip38_encrypt` | Non-EC (0x42) encrypt existing key with passphrase + address |
| `dogecoin_bip38_encrypt_passphrase` | Non-EC encrypt with explicit passphrase byte length (NFC) |
| `dogecoin_bip38_decrypt` | Decrypt 0x42 or 0x43 key (mainnet address-hash match) |
| `dogecoin_bip38_decrypt_ex` | Decrypt with `BIP38_ADDRESS_MATCH_MAINNET` or `_INTEROP` |
| `dogecoin_bip38_decrypt_passphrase` | Decrypt with explicit passphrase bytes |
| `dogecoin_bip38_decrypt_passphrase_ex` | Decrypt with passphrase bytes + address-match mode |
| `dogecoin_bip38_decrypt_with_lot_sequence` | EC decrypt; returns lot/sequence when present |
| `dogecoin_bip38_decrypt_with_lot_sequence_ex` | Same with explicit address-match mode |
| `dogecoin_bip38_generate_intermediate_code` | Owner-side EC intermediate (`passphrase…`) |
| `dogecoin_bip38_encrypt_from_intermediate` | Printer-side EC encrypt from intermediate |
| `dogecoin_bip38_encrypt_ec_multiplied` | One-shot EC encrypt (+ optional confirmation) |
| `dogecoin_bip38_confirm_passphrase` | Verify confirmation code (mainnet address out) |
| `dogecoin_bip38_confirm_passphrase_ex` | Verify confirmation; `INTEROP` matches decrypt interop chains |
| `dogecoin_bip38_private_key_to_wif` | Raw 32-byte key → WIF for chain |
| `dogecoin_bip38_wif_to_private_key` | WIF → raw key |
| `dogecoin_bip38_is_valid` | Valid `6P…` encrypted key |
| `dogecoin_bip38_is_intermediate_code` | Valid `passphrase…` intermediate |
| `dogecoin_bip38_is_confirmation_code` | Valid `cfrm…` confirmation |
| `dogecoin_bip38_is_compressed` | Compressed pubkey flag in key |
| `dogecoin_bip38_is_ec_multiplied` | 0x43 EC-multiplied type |
| `dogecoin_bip38_has_lot_sequence` | Lot/sequence present |
| `dogecoin_bip38_get_address_hash` | Extract 4-byte address hash (valid BIP38 payload only) |
| `dogecoin_bip38_verify_address_hash` | Compare embedded hash to one address string |
| `dogecoin_bip38_get_flag_byte` | Raw BIP38 flag byte (valid payload; rejects bad magic/type/flags) |
| `dogecoin_bip38_generate_lot_sequence` | Random lot + sequence for EC flow |

Constants: `BIP38_ADDRESS_MATCH_MAINNET`, `BIP38_ADDRESS_MATCH_INTEROP`, buffer sizes (`BIP38_ENCRYPTED_KEY_LENGTH`, `BIP38_INTERMEDIATE_CODE_MAXLEN`, etc.) — see `include/dogecoin/bip38.h`.

### `sweep.h` — paper wallets and sweep

| Function | Purpose |
|----------|---------|
| `dogecoin_paper_wallet_new` / `_free` | Allocate / free paper wallet |
| `dogecoin_paper_wallet_set_wif` | Load from WIF |
| `dogecoin_paper_wallet_set_hex` | Load from hex private key |
| `dogecoin_paper_wallet_set_encrypted` | Load from BIP38 `6P…` + passphrase |
| `dogecoin_paper_wallet_get_address` | Derived P2PKH address |
| `dogecoin_paper_wallet_get_private_key` | 32-byte secret |
| `dogecoin_paper_wallet_get_wif` | WIF for chain |
| `dogecoin_paper_wallet_is_valid` | Wallet has key + address |
| `dogecoin_sweep_options_new` / `_free` | Options with defaults for chain |
| `dogecoin_sweep_options_set_destination` | Payout address |
| `dogecoin_sweep_options_set_fee` | Per-byte, min, max (koinu) |
| `dogecoin_sweep_options_set_rbf` | Replace-by-fee sequence |
| `dogecoin_sweep_options_set_locktime` | Transaction locktime |
| `dogecoin_sweep_options_set_utxo` | Replace UTXO list with one prevout |
| `dogecoin_sweep_options_add_utxo` | Append prevout (multi-UTXO sweep) |
| `dogecoin_sweep_options_utxo_count` | Number of configured prevouts |
| `dogecoin_sweep_fee_per_kb_to_per_byte` | Convert wallet UI fee units |
| `dogecoin_sweep_paper_wallet` | Build, sign, return result |
| `dogecoin_sweep_multiple_paper_wallets` | Multi-wallet / multi-UTXO sweep |
| `dogecoin_sweep_estimate_fee` | Fee estimate from options |
| `dogecoin_sweep_create_transaction` | Unsigned tx (`dogecoin_tx_free`) |
| `dogecoin_sweep_sign_transaction` | Sign existing tx |
| `dogecoin_sweep_validate_transaction` | Post-sign checks |
| `dogecoin_sweep_get_stats` | Input/output counts and values |
| `dogecoin_sweep_broadcast_transaction` | Broadcast (`WITH_NET`) |
| `dogecoin_sweep_get_balance` | Local wallet DB balance (`WITH_WALLET`) |
| `dogecoin_sweep_result_new` / `_free` | Result object lifecycle |
| `dogecoin_sweep_result_get_error` | Failure message |
| `dogecoin_sweep_result_get_transaction_hex` | Signed raw tx |
| `dogecoin_sweep_result_get_transaction_id` | Tx hash |
| `dogecoin_sweep_result_get_amount_swept` | Output to destination (koinu) |
| `dogecoin_sweep_result_get_fee_paid` | Fee (koinu) |
| `dogecoin_sweep_result_get_destination_address` | Destination string |

### Related

- `include/dogecoin/scrypt.h` — `dogecoin_scrypt_rfc7914()` (RFC 7914 KDF used by BIP38; normally called internally)
- `contrib/examples/sweep_example.c` — minimal offline integration sample
- `contrib/examples/mainnet_sweep_driver.c` — mainnet sweep API CLI driver
- `contrib/mainnet_bip38_sweep_test.sh` — mainnet E2E test (requires `FUNDED_WIF` / `FUNDED_ADDR`)
- `test/sweep_tests.c` — vectors and integration tests
