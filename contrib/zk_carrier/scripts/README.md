# `contrib/zk_carrier/scripts/` — ZK carrier end-to-end drivers

This directory consolidates the operator-facing end-to-end test drivers for
the ZK carrier flow. They sit next to the circom circuit
(`contrib/zk_carrier/circuits/`) and the snarkjs prover helper
(`contrib/zk_carrier/witness_helper.py`) so all ZK demo assets live under one
tree.

> **Note**: this is a libdogecoin-only end-to-end demo.  It is **not**
> integrated with any external Dogecoin Core ZK proofs work.  The demo
> runs entirely against this repo's own `range_proof.circom` + snarkjs
> proving + libdogecoin's rapidsnark/mcl/external-snarkjs verifier paths.

## Scripts

### `run_full_zk_carrier_demo.{sh,py}` — single-pair driver

End-to-end demo of the ZK carrier flow.

Steps performed:

1. `snarkjs groth16 fullprove` over the range-proof circuit (or any circuit
   you point at via `--wasm` / `--zkey`), via
   `contrib/zk_carrier/witness_helper.py`.
2. Encode the proof + public inputs into the canonical ZKP1 payload.
3. `such -c zk_commit` → SHA256d commitment + `OP_RETURN DZKC <mode> <commit>`
   scriptPubKey.
4. `such -c zk_add_commit_and_carrier_tx` → adds the OP_RETURN output and
   the chunked P2SH carrier outputs to a base unsigned tx.
5. `such -c sign_raw_tx` → signs the funding input with the WIF.
6. Broadcasts via `RPC_URL`, falls back to the local `sendtx` binary, then
   to `dogechain.info/api/v1/pushtx` when neither is configured.
7. Polls the configured explorer (`EXPLORER_BASE`) until the txid appears
   (timeout: 600 s).
8. Local verify: `such -c zk_extract_carrier` reassembles the payload from
   `TX_R_HEX` and prints the decoded header.

#### Network selection

* **`--mainnet`** (default, matching contrib/mainnet_falcon_test.sh pattern).
* **`--testnet`** to opt out.

#### WIF / address handling

The script never embeds a private key in source.  Resolution order:

1. `ZK_CARRIER_WIF` env var (operator-supplied).
2. `FUNDED_WIF` env var.
3. The mainnet default reused from `contrib/mainnet_falcon_test.sh` and
   friends:
   * WIF: `QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w`
   * Address: `DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr`

   This is the same key/address used by the existing mainnet PQC scripts in
   this branch family — it is **already public there** and is reused only
   so a single funded UTXO chain can be exercised across PQ + ZK demos.

If you don't want that, export `ZK_CARRIER_WIF` to your own WIF (and
`ZK_CARRIER_ADDR` if it differs from the WIF's natural address) before
running.

#### Logging

The script `tee`s every line of stdout/stderr to
`zk_carrier_demo_<UTC>.log` in the working directory.

#### Mainnet warnings

* This script signs and broadcasts real DOGE.  Do not run on mainnet
  without first running on testnet end-to-end.
* The funded UTXO and fee variables (`FUNDED_UTXO_TXID`,
  `FUNDED_UTXO_VALUE_KOINU`, `TX_FEE_KOINU`, `CARRIER_VALUE_KOINU`,
  `TX_R_FEE_KOINU`) must all be set explicitly — there is no auto-fund.
* The `--skip-broadcast` flag is the safe dry-run path: it stops after
  printing the commitment and OP_RETURN scriptPubKey.

#### Python entry point

`run_full_zk_carrier_demo.py` is a thin importable wrapper around the
shell script:

```python
from contrib.zk_carrier.scripts.run_full_zk_carrier_demo import run_demo
run_demo(["--testnet", "--skip-broadcast", "--low", "0",
          "--high", "1000000", "--amount", "42000"])
```

#### Out of scope (here)

* Full TX_R assembly via RPC.  The ZK carrier reuses the **identical**
  P2SH carrier shape as `contrib/mainnet_falcon_test.sh` (chunked scriptSig
  with 8-byte tag).  The demo prints the per-part scriptSig hexes; feed
  them into the same TX_R-builder helpers from `mainnet_falcon_test.sh` to
  produce a fully signed reveal transaction.  When you have the assembled
  hex, set `TX_R_HEX=...` and rerun the script — step 8 will verify it.

### `broadcast_set.sh` — multi-pair driver

Multi-pair sibling of `run_full_zk_carrier_demo.sh` and the ZK analogue
of `contrib/mainnet_dilithium2_test.sh` / `contrib/mainnet_raccoong_test.sh`.

Loops `N` times.  For each iteration it:

1. Picks the next unspent UTXO from `$FUNDED_ADDR` (or the chained change
   output from the previous iteration) and queries explorer APIs for its
   value + scriptPubKey.
2. Generates a fresh Groth16 proof via
   `contrib/zk_carrier/witness_helper.py` with a per-iteration `--amount`
   so each cycle commits a distinct payload.
3. Builds an unsigned base tx (1 input → 1 P2PKH change to `FUNDED_ADDR`),
   derives sighash, and uses
       `such -c zk_add_commit_and_carrier_tx`
   to append the ZKP1 OP_RETURN + P2SH carrier outputs.
4. Signs the funding input with `such -c sign` and broadcasts TX_C with
   `sendtx`.  Waits for the explorer to see TX_C.
5. Builds TX_R that spends every carrier output (one P2SH input per
   carrier part), pastes in the per-part scriptSigs already emitted by
   step 3, and broadcasts TX_R via `sendtx`.
6. Appends `tx_c.txid<TAB>tx_r.txid<TAB>commit<TAB>height_estimate` to a
   manifest.  Chains the next iteration off TX_C's change vout.

After the loop, optionally launches one `spvnode` scan over the whole height
range, producing the `[zk-commit]` on-chain validation lines (one triple per
pair).

See the script's own header comment block for the full prerequisite and
environment-variable reference; the same `ZK_CARRIER_WIF` /
`FUNDED_WIF` resolution rules apply.

## Run history

End-to-end mainnet runs of these drivers are auditable directly from
on-chain data — both Groth16 (in-process via mcl) and PLONK (external
snarkjs verifier) end-to-end mainnet pairs are represented. The canonical
TX_C / TX_R pairs are listed in
[`doc/spec/bip-zk-carrier-commitments.mediawiki`](../../../doc/spec/bip-zk-carrier-commitments.mediawiki)
(see the "Mainnet v1 cascade" and "Mainnet v2 cascade" sections); fetching
those txids from any Dogecoin node or block explorer reproduces every line
of evidence.

For the specific case of **full ZK validation using on-chain data only** —
i.e. every input the verifier needs (commit, payload, public inputs, proof,
verification key) is recovered from the mainnet TX_C/TX_R bytes alone — the
two v1 self-contained pairs (G1 Groth16 + Q1 PLONK) are exercised by
`validate_onchain_pairs.py` against the vk embedded inline in each reveal:

* Pair G1 (Groth16, ZKP1 v1) — TX_C `b70bc69f574b3044972d52a9a6eb33f00c2ed909b7346994aceec0c412e18354`,
  TX_R `68e6d111e5a5071f206e7933954fc60d9247201963b8bb7443b87e55dbcf14d7`
  at block height 6191613 (commit32 `80e2858dc6e584db6bd2c035e8156b9807f8b983590c6efaae08a82d85729d1e`).
* Pair Q1 (PLONK, ZKP1 v1) — TX_C `d0a099692c91bd2d069afbfa1334ec348e07d86381f97bbd891ff4a4732b4edc`,
  TX_R `0033342456d866cc66d9b3b647a7ac0cb7a55200138a54ff68b89683c47d82b5`
  at block height 6191616 (commit32 `52d47f210f4e185f11c4c28f71dc346b1b87a0ab5a69dcb84423e46239a34a5d`).

Run `validate_onchain_pairs.py` against these txids (the script fetches the
raw TX_C/TX_R hex from a public block explorer) and you get spvnode's
`[zk-commit]` cross-walk (Groth16 in-process PASSED via mcl+rapidsnark,
PLONK DELEGATED) plus the external `snarkjs verify` OK lines against the
EMBEDDED on-chain vk for both proof systems.

Legacy v0 reveals (Pairs A, B, P — vk not embedded on-chain) are
intentionally out of scope for this artifact; they appear in the same
validator output as `PASS-vk-rotated` (commitment binding only) since the
on-chain bytes alone are insufficient to run the verifier against them.
