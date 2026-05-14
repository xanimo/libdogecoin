
### Dogecoin Transaction Overview

The `dogecoin_tx` structure describes a dogecoin transaction in reply to getdata. When a bloom filter is applied tx objects are sent automatically for matching transactions following the merkleblock. It is composed of the following fields:

| Field Size      | Description | Data type | Comments |
| ----------- | ----------- | - | - |
| 4      | version       | uint32_t | Transaction data format version |
| 1+      | tx_in count       | var_int | Number of Transaction inputs (never zero) |
| 41+   | tx_in        | tx_in[] | A list of 1 or more transaction inputs or sources for coins |
| 1+      | tx_out count | var_int | Number of Transaction outputs |
| 9+   | tx_out        | tx_out[] | A list of 1 or more transaction outputs or destinations for coins |
| 4   | lock_time        | uint32_t | The block number or timestamp at which this transaction is unlocked: 0 == not locked, < 500000000 == Block number at which this transaction is unlocked, >= 500000000 == UNIX timestamp at which this transaction is unlocked. If all TxIn have final (0xffffffff) sequence numbers then lock_time is irrelevant. Otherwise, the transaction may not be added to a block until after lock_time (see NLockTime). |

`include/dogecoin/tx.h`:
```
typedef struct dogecoin_tx_ {
    int32_t version;
    vector_t* vin;
    vector_t* vout;
    uint32_t locktime;
} dogecoin_tx;
```

Every transaction is composed of inputs and outputs, which specify where the funds came from and where they will go. These are represented by the `dogecoin_tx_in` and `dogecoin_tx_out` structs below.

### Dogecoin Transaction Input
The `dogecoin_tx_in` structure consists of the following fields:
| Field Size      | Description | Data type | Comments |
| ----------- | ----------- | - | - |
| 36 | previous_output | outpoint | The previous output transaction reference, as an Outpoint structure |
| 1+ | script_length | var_int | The length of the signature script |
| ? | signature_script | uchar[] | Computational Script for confirming transaction authorization |
| 4 | sequence | uint32_t | Transaction version as defined by the sender. Intended for "replacement" of transactions when information is updated before inclusion into a block. |

`include/dogecoin/tx.h`:
```
typedef struct dogecoin_tx_in_ {
    dogecoin_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
} dogecoin_tx_in;
```

The `dogecoin_tx_outpoint` structure represented above as `prevout` consists of the following fields:
| Field Size      | Description | Data type | Comments |
| ----------- | ----------- | - | - |
| 32 | hash | char[32] | The hash of the referenced transaction |
| 4 | index | uint32_t | The index of the specific output in the transaction. The first output is 0, etc. |

`include/dogecoin/tx.h`:
```
typedef struct dogecoin_tx_outpoint_ {
    uint256_t hash;
    uint32_t n;
} dogecoin_tx_outpoint;
```

### Dogecoin Transaction Output
The `dogecoin_tx_out` structure consists of the following fields:
| Field Size      | Description | Data type | Comments |
| ----------- | ----------- | - | - |
| 8 | value | int64_t | Transaction value |
| 1+ | pk_script length | var_int | Length of the pk_script |
| ? | pk_script | uchar[] | Usually contains the public key as a dogecoin script setting up conditions to claim this output. |

`include/dogecoin/tx.h`:
```
typedef struct dogecoin_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} dogecoin_tx_out;
```

#### Standard Transaction to Dogecoin Address (pay-to-pubkey-hash)
The `dogecoin_script` structure consists of a series of pieces of information and operations related to the value of the transaction. When notating scripts, data to be pushed to the stack is generally enclosed in angle brackets and data push commands are omitted. Non-bracketed words are opcodes. These examples include the "OP_" prefix, but it is permissible to omit it. Thus "<pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG" may be abbreviated to "<pubkey1> <pubkey2> 2 CHECKMULTISIG". Note that there is a small number of standard script forms that are relayed from node to node; non-standard scripts are accepted if they are in a block, but nodes will not relay them.
```
scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
scriptSig: <sig> <pubKey>
```
To demonstrate how scripts look on the wire, here is a raw scriptPubKey:
```
  76       A9             14
OP_DUP OP_HASH160    Bytes to push

89 AB CD EF AB BA AB BA AB BA AB BA AB BA AB BA AB BA AB BA   88         AC
                      Data to push                     OP_EQUALVERIFY OP_CHECKSIG
```
##### **Note: scriptSig is in the input of the spending transaction and scriptPubKey is in the output of the previously unspent i.e. "available" transaction.**

Here is how each word is processed:
| Stack      | Script | Description |
| ----------- | ----------- | - |
| Empty | `<sig> <pubKey>` OP_DUP OP_HASH160 `<pubKeyHash>` OP_EQUALVERIFY OP_CHECKSIG | scriptSig and scriptPubKey are combined. |
| `<sig> <pubKey>` | OP_DUP OP_HASH160 `<pubKeyHash>` OP_EQUALVERIFY OP_CHECKSIG | Constants are added to the stack. |
| `<sig> <pubKey> <pubKey>` | OP_HASH160 `<pubKeyHash>` OP_EQUALVERIFY OP_CHECKSIG | Top stack item is duplicated. |
| `<sig> <pubKey> <pubHashA>` | `<pubKeyHash>` OP_EQUALVERIFY OP_CHECKSIG | Top stack item is hashed. |
| `<sig> <pubKey> <pubHashA> <pubKeyHash>` | OP_EQUALVERIFY OP_CHECKSIG | Constant added. |
| `<sig> <pubKey>` | OP_CHECKSIG | Equality is checked between the top two stack items. |
| true | Empty | Signature is checked for top two stack items. |

`include/dogecoin/tx.h`:
```
typedef struct dogecoin_script_ {
    int* data;
    size_t limit;   // Total size of the vector
    size_t current; //Number of vectors in it at present
} dogecoin_script;
```

##### * *The examples above were derived from https://en.bitcoin.it*

---

## End-to-End Multisig Workflow

The Essential Transaction API can build, finalize and sign **M-of-N P2SH multisig** transactions by combining the building blocks above (`start_transaction`, `add_utxo`, `add_output`, `finalize_transaction_ex`) with the lower-level [`dogecoin_script_build_multisig`](../include/dogecoin/script.h) helper for the redeem script and [`sign_indexed_raw_transaction_ex`](./transaction.md#sign_indexed_raw_transaction_ex) for per-cosigner signing.

The high-level recipe for spending an existing P2SH multisig UTXO is:

1. Compute the redeem script once from the ordered cosigner pubkeys and required-signatures count `M`. Hash160 + base58check encode it (mainnet `P2SH` version byte) to obtain the P2SH address — every cosigner must agree on the same canonical pubkey ordering.
2. `idx = start_transaction()`.
3. `add_utxo(idx, funding_txid, funding_vout)` for the P2SH-funding UTXO.
4. `add_output(idx, destination_address, amount_doge)` for each output (destination + change).
5. `finalize_transaction_ex(idx, destination, fee, total_input_value, change_address, ...)`.
6. Repeat `sign_indexed_raw_transaction_ex(idx, 0, redeem_script_hex, SIGHASH_ALL, cosigner_wif, ...)` `M` times — once per distinct cosigner — feeding the previously-returned hex back into the next call. After the `M`-th call the buffer holds the fully-signed scriptSig (`OP_0 sig_1 ... sig_M <redeem_script>`).
7. Broadcast the resulting hex (e.g. via the `sendtx` CLI tool).

The `script_pubkey` argument to `sign_indexed_raw_transaction_ex` for a P2SH multisig spend is the **redeem script hex**, not the P2SH `scriptPubKey`. The library inserts the redeem script as the final scriptSig push automatically.

For a runnable C implementation, see [`contrib/examples/example.c`](../contrib/examples/example.c) and the `BEGIN MULTISIG P2SH EXAMPLE` section.

### Worked example: 2-of-3 multisig on mainnet

> **⚠️ DEMO KEYS — DO NOT SEND FUNDS TO THESE ADDRESSES.** The cosigner
> public keys, redeem scripts, P2SH addresses and funding TXIDs below are
> reproduced verbatim from past mainnet demonstration runs. The original
> cosigner private keys are intentionally **not** published — anyone with
> them would control the on-chain UTXO. Generate your own cosigner WIFs
> (preferably on testnet/regtest) when reproducing these flows locally.

The values below were reproduced on mainnet — the funding transaction was broadcast and confirmed against the public Dogecoin network during the original demonstration.

```text
cosigner_0_pub: 03f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f27
cosigner_1_pub: 038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2
cosigner_2_pub: 0262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c85

redeem_script_hex: 522103f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f2721038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2210262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c8553ae
p2sh_address:     A4WG8CySzTzVYNssp2iKf8eXmDzRwPrSWA
funding_txid:     42b886661e22889b5e4b11f7160d877dc41f6601139b7396a04a8056d2ad39e5
funding_vout:     0
funding_value:    0.05000000 DOGE
```

The redeem script decodes to `OP_2 <pub0> <pub1> <pub2> OP_3 OP_CHECKMULTISIG`. The same pubkeys (cosigner WIFs intentionally omitted) are used by the runnable derivation example in [`contrib/examples/example.c`](../contrib/examples/example.c). The key steps are:

1. Call `get_p2sh_multisig_address(pubkeys_hex, N, M, is_testnet, p2sh_addr, p2sh_addr_cap, redeem_hex, redeem_hex_cap)` to derive the P2SH address and redeem script hex from the ordered cosigner pubkeys.
2. Build the unsigned transaction with `start_transaction` / `add_utxo` / `add_output` / `finalize_transaction_ex`.
3. Call `sign_indexed_raw_transaction_ex(idx, 0, redeem_hex, SIGHASH_ALL, cosigner_wif, buf, cap)` once per cosigner (M times total), feeding each result back in as the next input. After the M-th call `buf` holds the fully-signed scriptSig (`OP_0 sig_1 ... sig_M <redeem_script>`).

The same flow can be driven entirely from the `such -c transaction` CLI submenu — see [`doc/tools.md`](./tools.md) for the keystroke-by-keystroke walkthrough.

### Worked example: 1-of-2 multisig on mainnet

```text
cosigner_0_pub: 02d20a240b999404f62026354aeca7e55984e9c8c289162b45fb0b7aff32dcca69
cosigner_1_pub: 029e30ca4b065e0fcc567f6eb44150cd7f675f27415f7f51ea6e6f8ef5564d1540

redeem_script_hex: 512102d20a240b999404f62026354aeca7e55984e9c8c289162b45fb0b7aff32dcca6921029e30ca4b065e0fcc567f6eb44150cd7f675f27415f7f51ea6e6f8ef5564d154052ae
p2sh_address:     A3PyYKKWFhrGCJci45grxrTy88HKJM6Vzp
funding_txid:     a2f8972be5338f0b5db9ff69a41d08b62aaf6b06cf11afd92719b662a49b5698
funding_vout:     0
funding_value:    0.05000000 DOGE
```

Same flow as above, but with `M = 1`, `N = 2`, and only one `sign_indexed_raw_transaction_ex` pass — either cosigner WIF is sufficient.

### Worked example: 3-of-5 multisig on mainnet

```text
cosigner_0_pub: 030ccd473a6023eabbd04331624712cff82370d6c706578325ba3b628db6c623de
cosigner_1_pub: 03e04e3251363bcfa2eca2c5225321b2744c175de983fab8506ba5fdd7b95a3703
cosigner_2_pub: 023de966b19e1d5bc7219d3756efffede0dfe6b5b9adaf9d234198eed19f8103c1
cosigner_3_pub: 03d74a5cb18625db07a7100ac03e6b8421ce4d62a2723b81ab4a3f76e33c309f18
cosigner_4_pub: 02043b49a30dd54e104a7125ffa800518da68bdd27a0751a0433140c254025e8c8

redeem_script_hex: 5321030ccd473a6023eabbd04331624712cff82370d6c706578325ba3b628db6c623de2103e04e3251363bcfa2eca2c5225321b2744c175de983fab8506ba5fdd7b95a370321023de966b19e1d5bc7219d3756efffede0dfe6b5b9adaf9d234198eed19f8103c12103d74a5cb18625db07a7100ac03e6b8421ce4d62a2723b81ab4a3f76e33c309f182102043b49a30dd54e104a7125ffa800518da68bdd27a0751a0433140c254025e8c855ae
p2sh_address:     AD9tSAqb47oqHVUK5HSUkVxB3Ft7Er97qh
funding_txid:     981e94eee01915b7573608a0258970870d085a011b4e64de2e43adc8f63189ca
funding_vout:     0
funding_value:    0.05000000 DOGE
```

With `M = 3`, `N = 5`, the spend requires **three** distinct `sign_indexed_raw_transaction_ex` passes using any three of the five cosigner WIFs — each pass consumes the previous result as `tmphex`.

### Negative example: invalid signature on a real multisig TX

The two failure modes below use the **real** 2-of-3 mainnet redeem script and P2SH from the worked example. Both are offline checks — no transaction is broadcast — and both demonstrate that an attacker cannot redeem the on-chain UTXO at `A4WG8CySzTzVYNssp2iKf8eXmDzRwPrSWA` without a correctly-ordered, in-script cosigner key.

**(a) Signing with a non-cosigner WIF.** Generate a fresh keypair that is *not* part of the 2-of-3 set and use it to sign a candidate spend of `42b886661e22889b5e4b11f7160d877dc41f6601139b7396a04a8056d2ad39e5:0`:

```
$ ./such -c generate_private_key
private key wif: QV3attackerKeyNotInRedeemScriptXXXXXXXXXXXXXXXXXXXXX
$ ./such -c generate_public_key -p QV3attackerKeyNotInRedeemScriptXXXXXXXXXXXXXXXXXXXXX
public key hex: 02attackerPubKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

$ ./such -c sign \
        -x <unsigned multisig spend hex> \
        -s 522103f59f55e1...0262bed3c8c9...53ae \
        -i 0 -h 1 \
        -p QV3attackerKeyNotInRedeemScriptXXXXXXXXXXXXXXXXXXXXX
```

`dogecoin_tx_sign_input` succeeds (any private key can produce *some* ECDSA signature over the sighash) but the resulting scriptSig pushes the attacker's compressed pubkey, which is **not** any of:

```
03f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f27
038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2
0262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c85
```

When this transaction reaches `OP_CHECKMULTISIG`, the interpreter walks the on-stack pubkey list looking for one that verifies each provided signature. Because the attacker's pubkey appears **nowhere** in the redeem script, no match is possible and the script evaluates to `false` — the spend is rejected by every node on the network. The same holds programmatically: feeding the produced hex into a second `sign_indexed_raw_transaction_ex` call with a *real* cosigner WIF cannot rescue it because the existing scriptSig push is consumed by `OP_CHECKMULTISIG` against a non-member key.

**(b) Tampering one byte of a cosigner pubkey in the redeem script.** Flip one nibble of `cosigner_0_pub` (e.g. last byte `27` → `28`) before calling `dogecoin_script_build_multisig`:

```
tampered_pub_0:    03f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f28
tampered_redeem:   522103f59f55e1...c1f2f28 21038abd7a... 210262bed3c8c9... 53ae
tampered_p2sh:     A<DIFFERENT_FROM_A4WG8CySz...>
```

`dogecoin_script_build_multisig` still produces a syntactically valid M-of-N script (the byte is a valid point on secp256k1 in many cases, and even if it isn't `dogecoin_pubkey_is_valid` rejects it before reaching the builder), but its hash160 — and therefore the resulting P2SH address — differs from the real on-chain `A4WG8CySzTzVYNssp2iKf8eXmDzRwPrSWA`. A transaction whose `scriptSig` reveals this tampered redeem script cannot satisfy the original P2SH `scriptPubKey` (`OP_HASH160 <hash160> OP_EQUAL`) on the funded output, so the spend is rejected at the P2SH equality check before `OP_CHECKMULTISIG` ever runs.

Together these cases demonstrate that:

- The set of redeeming pubkeys is locked in at funding time via the P2SH commitment; reordering, substituting, or tampering with any cosigner pubkey produces a different P2SH and cannot redeem the real UTXO.
- Within a valid redeem script, only signatures made by `M` distinct keys actually present in the script are accepted by `OP_CHECKMULTISIG`; signatures from non-cosigner keys (no matter how well-formed) are silently discarded by the interpreter and the spend fails.

---

## End-to-End CLI Multisig Workflow (`such` + `spvnode` + `sendtx`)

You can run a full CLI workflow for multisig from address generation through network broadcast and verification using the three bundled tools.

1. **Generate keys and compressed pubkeys with `such` (testnet example).**

       ./such -c generate_private_key -t
       ./such -c generate_public_key -p <wif_1> -t
       ./such -c generate_public_key -p <wif_2> -t

2. **Create the multisig redeem script and P2SH address in the transaction submenu.**

       ./such -c transaction

   Then choose:
   - `add transaction`
   - `multisig script/address`
   - enter `comma-separated compressed pubkeys`
   - enter `required signatures` (for example, `2` for a 2-of-2)

   Save the printed:
   - `multisig redeem script`
   - `multisig p2sh address`

3. **Watch that multisig address in `spvnode`.**

       ./spvnode -t -d -c -a "<multisig_p2sh_address>" -w "./multisig_wallet.db" -h "./multisig_headers.db" -b scan

   Keep the node running while testing, and stop with `Ctrl+C` when done.

4. **Build/finalize the raw transaction in `such` after the multisig UTXO is funded.**

       ./such -c transaction

   Use the transaction menu to:
   - add input(s) and output(s)
   - finalize transaction
   - print transaction hex

5. **Broadcast the raw transaction with `sendtx`.**

       ./sendtx -t <raw_tx_hex>

6. **Verify relay/confirmation with `spvnode`.**

   Continue scanning with the same watched address and wallet/header files to observe the transaction on-chain.

> **Important:** Use consistent network flags (`-t` for testnet or mainnet defaults) across all three tools.

For full worked mainnet examples (1-of-2, 2-of-3, 3-of-5) see the [Worked examples](#worked-example-2-of-3-multisig-on-mainnet) above.

### Reproducible mainnet test runs

The full CLI flow above is exercised end-to-end by [`contrib/mainnet_multisig_test.sh`](../contrib/mainnet_multisig_test.sh), which drives `such -c transaction` (no Python helpers), broadcasts each scenario's funding tx with `sendtx`, and waits for `spvnode` to match the watched P2SH inside a confirmed block (`Found relevant transaction!` from `dogecoin_wallet_check_transaction`). Both runs used the same funded mainnet wallet (supplied via the `FUNDED_WIF` / `FUNDED_ADDR` environment variables); each scenario chains its change output forward as the next scenario's input.

#### Run 1 — 2026-04-29T21:08:18Z

**2-of-3**

```text
p2sh_address:      A4WG8CySzTzVYNssp2iKf8eXmDzRwPrSWA
redeem_script_hex: 522103f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f2721038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2210262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c8553ae
cosigner_0_pub:    03f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f27
cosigner_1_pub:    038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2
cosigner_2_pub:    0262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c85
funding_txid:      42b886661e22889b5e4b11f7160d877dc41f6601139b7396a04a8056d2ad39e5
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       235s
```

**1-of-2**

```text
p2sh_address:      A3PyYKKWFhrGCJci45grxrTy88HKJM6Vzp
redeem_script_hex: 512102d20a240b999404f62026354aeca7e55984e9c8c289162b45fb0b7aff32dcca6921029e30ca4b065e0fcc567f6eb44150cd7f675f27415f7f51ea6e6f8ef5564d154052ae
cosigner_0_pub:    02d20a240b999404f62026354aeca7e55984e9c8c289162b45fb0b7aff32dcca69
cosigner_1_pub:    029e30ca4b065e0fcc567f6eb44150cd7f675f27415f7f51ea6e6f8ef5564d1540
funding_txid:      a2f8972be5338f0b5db9ff69a41d08b62aaf6b06cf11afd92719b662a49b5698
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       80s
```

**3-of-5**

```text
p2sh_address:      AD9tSAqb47oqHVUK5HSUkVxB3Ft7Er97qh
redeem_script_hex: 5321030ccd473a6023eabbd04331624712cff82370d6c706578325ba3b628db6c623de2103e04e3251363bcfa2eca2c5225321b2744c175de983fab8506ba5fdd7b95a370321023de966b19e1d5bc7219d3756efffede0dfe6b5b9adaf9d234198eed19f8103c12103d74a5cb18625db07a7100ac03e6b8421ce4d62a2723b81ab4a3f76e33c309f182102043b49a30dd54e104a7125ffa800518da68bdd27a0751a0433140c254025e8c855ae
cosigner_0_pub:    030ccd473a6023eabbd04331624712cff82370d6c706578325ba3b628db6c623de
cosigner_1_pub:    03e04e3251363bcfa2eca2c5225321b2744c175de983fab8506ba5fdd7b95a3703
cosigner_2_pub:    023de966b19e1d5bc7219d3756efffede0dfe6b5b9adaf9d234198eed19f8103c1
cosigner_3_pub:    03d74a5cb18625db07a7100ac03e6b8421ce4d62a2723b81ab4a3f76e33c309f18
cosigner_4_pub:    02043b49a30dd54e104a7125ffa800518da68bdd27a0751a0433140c254025e8c8
funding_txid:      981e94eee01915b7573608a0258970870d085a011b4e64de2e43adc8f63189ca
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       115s
```

#### Run 2 — 2026-05-07T21:18:54Z

**2-of-3**

```text
p2sh_address:      9u2Zzo3n5VRW5zyWTxGbmuZcTciw3qY3Lf
redeem_script_hex: 52210324d846852fd18148d05e5b120ed189b96756f876abef6137fce74f75a193f41a2102b6a0a4265e71ef4baf0eaf2fbc35c0efdeb3f0a6742266b8d757041fef7d0c0121029dccacbc949f8277fcab147b15428c8f7f5217f0e5717a148cc2b57b5b45c7d953ae
cosigner_0_pub:    0324d846852fd18148d05e5b120ed189b96756f876abef6137fce74f75a193f41a
cosigner_1_pub:    02b6a0a4265e71ef4baf0eaf2fbc35c0efdeb3f0a6742266b8d757041fef7d0c01
cosigner_2_pub:    029dccacbc949f8277fcab147b15428c8f7f5217f0e5717a148cc2b57b5b45c7d9
funding_txid:      b0803ab3c2b77c0a1a9bbf6ca47f623aa3d92a4fb41a639121c66032ce71d47c
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       55s
```

**1-of-2**

```text
p2sh_address:      A7RSUCi2JJ9i3jw5hTYGhZgzqBTzz72R5J
redeem_script_hex: 5121035f423b86034223c013127f1f393c9802e6ad18b37c37a71f3a81dac00f8d6399210374324ac9283f1c632b7d3b4c263f2e5e3791ad1e684e118692ecb82904302fd152ae
cosigner_0_pub:    035f423b86034223c013127f1f393c9802e6ad18b37c37a71f3a81dac00f8d6399
cosigner_1_pub:    0374324ac9283f1c632b7d3b4c263f2e5e3791ad1e684e118692ecb82904302fd1
funding_txid:      f997fbacf283ba2b2d94a50d70567071a230736c6632e1e80df50f2548feeb84
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       35s
```

**3-of-5**

```text
p2sh_address:      9xXRdKApUmJefMXpFJZiRUx24Zr2y43cFv
redeem_script_hex: 532102fc1ba4afb305f2debee81b57951675c5cb949ddb7bc9dab80a4cf7d7c1f8319a21030cea0f9f42bfdcff3e82557509c659ff7aee8e499c09fe38567ef6ba49c05dfb2103c20bc8bdda9da32d4bb4c59ad7fd6c52dc2fecabf51c3c3b6ac889841744b4d02103ca5f476dbae5918eb916b496bca2730b39a8fe496c8a0960afd6702ab6f69b032102b313f2a37865dd8acb4e66cfe83075fd3fccd297341a9fdf23acc2553849358c55ae
cosigner_0_pub:    02fc1ba4afb305f2debee81b57951675c5cb949ddb7bc9dab80a4cf7d7c1f8319a
cosigner_1_pub:    030cea0f9f42bfdcff3e82557509c659ff7aee8e499c09fe38567ef6ba49c05dfb
cosigner_2_pub:    03c20bc8bdda9da32d4bb4c59ad7fd6c52dc2fecabf51c3c3b6ac889841744b4d0
cosigner_3_pub:    03ca5f476dbae5918eb916b496bca2730b39a8fe496c8a0960afd6702ab6f69b03
cosigner_4_pub:    02b313f2a37865dd8acb4e66cfe83075fd3fccd297341a9fdf23acc2553849358c
funding_txid:      bdde9fa10108ff438abdf3304c2bb4f3f4340f186fce6964956e1be020a65b83
funding_vout:      0
funding_value:     0.05000000 DOGE
spv_elapsed:       135s
```
