# Libdogecoin Zero-Knowledge Proof Carrier API

## Table of Contents
- [Libdogecoin Zero-Knowledge Proof Carrier API](#libdogecoin-zero-knowledge-proof-carrier-api)
  - [Table of Contents](#table-of-contents)
  - [Abstract](#abstract)
  - [Specification](#specification)
    - [On-wire payload (`ZKP1`)](#on-wire-payload-zkp1)
    - [TX_C / TX_R shape](#tx_c--tx_r-shape)
    - [Mode selector](#mode-selector)
  - [Build flags](#build-flags)
  - [Primitives](#primitives)
    - [**dogecoin_zk_mode_t:**](#dogecoin_zk_mode_t)
    - [**dogecoin_zk_err_t:**](#dogecoin_zk_err_t)
  - [Carrier Encoding API](#carrier-encoding-api)
    - [**dogecoin_zk_encode_payload:**](#dogecoin_zk_encode_payload)
    - [**dogecoin_zk_decode_payload:**](#dogecoin_zk_decode_payload)
    - [**dogecoin_zk_get_commitment_hash:**](#dogecoin_zk_get_commitment_hash)
    - [**dogecoin_zk_build_opreturn_scriptpubkey:**](#dogecoin_zk_build_opreturn_scriptpubkey)
  - [Carrier Transaction API](#carrier-transaction-api)
    - [**dogecoin_zk_build_carrier_tx_c:**](#dogecoin_zk_build_carrier_tx_c)
    - [**dogecoin_zk_build_carrier_tx_r_scriptsigs:**](#dogecoin_zk_build_carrier_tx_r_scriptsigs)
    - [**dogecoin_zk_extract_carrier_payload:**](#dogecoin_zk_extract_carrier_payload)
    - [**dogecoin_tx_extract_zk_commit:**](#dogecoin_tx_extract_zk_commit)
  - [Verification API](#verification-api)
    - [**dogecoin_zk_verify_groth16:**](#dogecoin_zk_verify_groth16)
    - [**dogecoin_zk_verify_proof:**](#dogecoin_zk_verify_proof)
  - [Proof Generation API](#proof-generation-api)
    - [**dogecoin_zk_generate_groth16_proof:**](#dogecoin_zk_generate_groth16_proof)
    - [**dogecoin_zk_generate_plonk_proof:**](#dogecoin_zk_generate_plonk_proof)
  - [Errors](#errors)
    - [**dogecoin_zk_strerror:**](#dogecoin_zk_strerror)
  - [Tests](#tests)

## Abstract

This document explains the zero-knowledge proof carrier API within libdogecoin
(`src/zk_carrier/`, header `include/dogecoin/zk_carrier.h`). It is the
developer/integrator companion to the protocol spec
[`doc/spec/bip-zk-carrier-commitments.mediawiki`](spec/bip-zk-carrier-commitments.mediawiki)
and to the operator CLI in [`tools.md`](tools.md) (section *Zero-Knowledge
Proof Carrier (ZK) Commands*). End-to-end demo drivers live under
[`contrib/zk_carrier/scripts/`](../contrib/zk_carrier/scripts/).

The module extends the PQ carrier pattern (`src/pqc_carrier.c`) so that
succinct zero-knowledge proofs (Groth16 today, PLONK / STARK in future) can
be committed and revealed on the Dogecoin chain using exactly the same
TX_C (commit) + TX_R (reveal) flow. It implements the on-chain side of a
reserved-opcode proposal: a canonical wire format for ZK proofs
and a P2SH carrier transaction shape that lets full nodes and SPV clients
consume those proofs without a soft-fork-deployed interpreter on the
network yet.

The C library only verifies and packages. Proof generation lives outside
the library (snarkjs/circom client-side, or rapidsnark CLI on a host) so
libdogecoin stays mobile-friendly with no heavy runtime dependencies.

## Specification

### On-wire payload (`ZKP1`)

All multi-byte integers are big-endian.

| offset | size | field            | encoding           |
|-------:|-----:|------------------|--------------------|
| 0      | 4    | magic `"ZKP1"`   | ASCII              |
| 4      | 1    | mode             | `dogecoin_zk_mode_t` |
| 5      | 1    | version          | 0x00 (v0 legacy) or 0x01 (v1 vk-included) |
| 6      | 4    | circuit_id       | uint32             |
| 10     | 2    | public_inputs_len| uint16             |
| 12     | N    | public_inputs    | opaque bytes       |
| 12+N   | 4    | proof_len        | uint32             |
| 16+N   | M    | proof            | opaque bytes       |
| 16+N+M | 4    | vk_len           | uint32 (v1 only)   |
| 20+N+M | K    | vk               | opaque bytes (v1 only) |

`public_inputs`, `proof`, and (for v1) `vk` are typically the JSON blobs
emitted by snarkjs (`public.json`, `proof.json`, `verification_key.json`);
rapidsnark and mcl accept the same JSON when they verify on-chain. Carrying
JSON keeps the formats interchangeable across prover backends and avoids
a separate canonicalisation step.

**Version byte semantics:**
* **v0 (`0x00`)**: legacy format with no embedded vk. The verifier must obtain
  the verification key through an out-of-band channel. Retained for backwards
  compatibility; new deployments MUST NOT emit v0.
* **v1 (`0x01`)**: self-contained reveal. The vk is embedded in the payload so
  verification uses only on-chain bytes. RECOMMENDED for all new deployments.
  Because the vk is part of the canonical payload hashed to produce `commit32`,
  swapping the vk after publication invalidates the OP_RETURN commitment match.

### TX_C / TX_R shape

* **TX_C** ("commit"):
  * `vout 0 .. n-1`: existing outputs of the base tx (change, payments).
  * `vout n`: `OP_RETURN <push 37> "DZKC" <mode> <commit32>` — value 0,
    38 data bytes, well below the 83-byte standardness limit.
  * `vout n+1 .. n+parts`: P2SH carrier outputs, each
    `value = CARRIER_VALUE_KOINU` (≥ 1 DOGE to clear dust), scriptPubKey
    `OP_HASH160 <h160(redeem)> OP_EQUAL`. The redeem script is the same
    `OP_DROP×5 OP_1` pattern used by the PQ carrier.

* **TX_R** ("reveal"):
  * One input per carrier output, each with scriptSig produced by
    `dogecoin_zk_build_carrier_tx_r_scriptsigs`. The scriptSig layout is
    `<tag8> <part_index> <part_total> <pk_len_be16> <full_len_be16>
    <chunk0> <chunk1> ... <redeem>` — identical to the PQ carrier, with
    tag `"ZKP1FULL"`.
  * Outputs are operator-defined (typically a change output back to the
    funding address).

When a future reserved-opcode validator ships, an interpreter implementation will recognise the
OP_RETURN by leading `"DZKC"` tag, walk the inputs of the redeeming TX_R
to recover the payload (matching `"ZKP1FULL"`), look up the verification
key for `(mode, circuit_id)` in a consensus-anchored registry, and call
`dogecoin_zk_verify_proof`. Because the carrier shape is fixed today, that
interpreter can be added without invalidating any historical TX_R.

### Mode selector

| value | mode                       |
|-------|----------------------------|
| 0     | `DOGECOIN_ZK_MODE_GROTH16` |
| 1     | `DOGECOIN_ZK_MODE_PLONK`   |
| 2     | `DOGECOIN_ZK_MODE_STARK_S2`|

Future modes (e.g. Halo2, Bulletproofs) reserve higher integers; an
unknown mode byte returns `DOGECOIN_ZK_ERR_BAD_MODE` from the codec.

### Proof system verification paths

| Proof System | Prover              | Verifier Path                                  | Config Flag                       |
|--------------|---------------------|------------------------------------------------|-----------------------------------|
| Groth16      | snarkjs (off-box)   | rapidsnark (in-process)                        | `--with-rapidsnark`               |
| Groth16      | snarkjs (off-box)   | mcl BN254 (in-process)                         | `--with-mcl[=DIR]`                |
| Groth16      | snarkjs (off-box)   | snarkjs (delegated)                            | (no flag → DELEGATED)             |
| PLONK        | snarkjs (off-box)   | snarkjs (delegated; canonical PLONK verifier)  | (always DELEGATED)                |
| STARK        | (none)              | (none)                                         | (always NOT_IMPLEMENTED)          |

* **Groth16** verification is supported in-process via either rapidsnark or mcl when configured. Without either flag, verification is delegated to snarkjs.
* **PLONK** verification is delegated to snarkjs (the canonical PLONK reference verifier). libdogecoin's policy delegates proving off-box; PLONK verifying is also off-box.
* **STARK** has no canonical reference verifier wired up and currently returns NOT_IMPLEMENTED.

All proof generation for all systems occurs off-box (snarkjs / rapidsnark CLI / circom) — libdogecoin never embeds a prover to stay mobile-friendly.

## Build flags

* `--enable-zk-carrier` (default **on**) — compiles the module. Disable
  with `--disable-zk-carrier` to drop ~25 KB of code.
* `--with-rapidsnark` — links the rapidsnark Groth16 verifier (providing
  the `groth16_verify` C ABI) into libdogecoin so verification runs
  in-process. rapidsnark v0.0.8 is now vendored via
  `depends/packages/rapidsnark.mk`: setting `ZK_CARRIER=1` on the
  `depends/` invocation builds the upstream tarball
  (https://github.com/iden3/rapidsnark/releases/tag/v0.0.8) along with
  its `ffiasm` and `nlohmann/json` submodules and stages
  `librapidsnark.a / libfr.a / libfq.a` into
  `depends/${HOST}/lib/`.  The depends recipe builds the C++ verifier
  with `-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DUSE_ASM=NO -DUSE_OPENMP=OFF`
  so it links into libdogecoin's shared library, links against system
  `libgmp` (install `libgmp-dev` on Linux / `brew install gmp` on macOS),
  and is exercised end-to-end against on-chain mainnet pairs by
  `contrib/zk_carrier/scripts/validate_onchain_pairs.py` (Pair G1).
  Without `--with-rapidsnark` (or `--with-mcl`),
  `dogecoin_zk_verify_proof` returns `DOGECOIN_ZK_ERR_DELEGATED` and the
  demo script falls back to `snarkjs groth16 verify`.

  > **Note:** rapidsnark v0.0.8 ships only a Groth16 verifier — it has
  > no PLONK support upstream — so `dogecoin_zk_verify_proof` always
  > returns `DOGECOIN_ZK_ERR_DELEGATED` for `DOGECOIN_ZK_MODE_PLONK`
  > regardless of `--with-rapidsnark`.  PLONK reveals are validated by
  > `snarkjs plonk verify` against the vk embedded in the on-chain
  > reveal (Pair Q1 in `validate_onchain_pairs.py`).
* `--with-mcl[=DIR]` — links the herumi/mcl BN254 pairing library plus
  the in-process Groth16 verifier in `src/zk_carrier/zk_groth16_mcl.cpp`.
  This is the in-tree natively-buildable Groth16 verifier (vendored via
  `depends/packages/mcl.mk` when `ZK_CARRIER=1`) and is what the
  published mainnet PASSED runs use for in-process verification.
* `ZK_CARRIER=1` on the `depends/` invocation vendors herumi/mcl *and*
  iden3/rapidsnark v0.0.8 into the depends staging tree so `--with-mcl`
  and `--with-rapidsnark` find them without any system package install
  (system `libgmp` / `libgmp-dev` is still required for rapidsnark).

These flags are also summarised in [`tools.md`](tools.md) alongside the
CLI commands they unlock.

## Primitives

These functions implement the core functionality of the libdogecoin ZK
carrier and are described in depth below. You can access them through a
C program by including the `dogecoin/zk_carrier.h` header in the source
code and including `libdogecoin.a` at link time:

`gcc -o example example.c -ldogecoin`

---
### **dogecoin_zk_mode_t:**

```c
typedef enum {
    DOGECOIN_ZK_MODE_GROTH16  = 0,
    DOGECOIN_ZK_MODE_PLONK    = 1,
    DOGECOIN_ZK_MODE_STARK_S2 = 2  /* future STARK support */
} dogecoin_zk_mode_t;
```

Stable numeric proof-system selectors. These are the reserved-opcode mode
selector values aligned with the PQC carrier's design and embedded as a
single byte in the `ZKP1` payload and the `DZKC` OP_RETURN.

---
### **dogecoin_zk_err_t:**

```c
typedef enum {
    DOGECOIN_ZK_OK                = 0,
    DOGECOIN_ZK_ERR_INVALID_ARG   = -1,
    DOGECOIN_ZK_ERR_BAD_MAGIC     = -2,
    DOGECOIN_ZK_ERR_BAD_MODE      = -3,
    DOGECOIN_ZK_ERR_TRUNCATED     = -4,
    DOGECOIN_ZK_ERR_OOM           = -5,
    DOGECOIN_ZK_ERR_NOT_IMPLEMENTED = -6, /* PLONK / STARK / disabled prover */
    DOGECOIN_ZK_ERR_DELEGATED     = -7,   /* prover lives outside libdogecoin */
    DOGECOIN_ZK_ERR_VERIFY_FAIL   = -8
} dogecoin_zk_err_t;
```

Status codes returned by every ZK carrier entry point. Use
[`dogecoin_zk_strerror`](#dogecoin_zk_strerror) to convert to a
human-readable string.

## Carrier Encoding API

---
### **dogecoin_zk_encode_payload:**

`dogecoin_zk_err_t dogecoin_zk_encode_payload(dogecoin_zk_mode_t mode, uint32_t circuit_id, const uint8_t* public_inputs, size_t public_inputs_len, const uint8_t* proof, size_t proof_len, uint8_t** out_payload, size_t* out_payload_len);`

Encode a proof and its public inputs into the canonical `ZKP1` carrier
payload. The caller frees `*out_payload` with `dogecoin_free()`. Returns
`DOGECOIN_ZK_OK` on success; `DOGECOIN_ZK_ERR_INVALID_ARG` if any pointer
is NULL or a length exceeds the on-wire field bound.

_C usage:_
```c
#include "dogecoin/zk_carrier.h"

uint8_t* payload = NULL;
size_t   payload_len = 0;
dogecoin_zk_err_t rc = dogecoin_zk_encode_payload(
    DOGECOIN_ZK_MODE_GROTH16,
    /*circuit_id=*/1,
    public_json, public_json_len,
    proof_json,  proof_json_len,
    &payload, &payload_len);
if (rc != DOGECOIN_ZK_OK) {
    fprintf(stderr, "zk encode failed: %s\n", dogecoin_zk_strerror(rc));
}
```

---
### **dogecoin_zk_decode_payload:**

`dogecoin_zk_err_t dogecoin_zk_decode_payload(const uint8_t* payload, size_t payload_len, dogecoin_zk_mode_t* out_mode, uint32_t* out_circuit_id, const uint8_t** out_public_inputs, size_t* out_public_inputs_len, const uint8_t** out_proof, size_t* out_proof_len);`

Decode a canonical ZK carrier payload. All `out_*` pointers are aliased
into the input buffer (no allocation). The caller must keep `payload`
alive while using the decoded fields.

_C usage:_
```c
dogecoin_zk_mode_t mode;
uint32_t circuit_id;
const uint8_t *pub, *proof;
size_t pub_len, proof_len;
dogecoin_zk_err_t rc = dogecoin_zk_decode_payload(
    payload, payload_len,
    &mode, &circuit_id, &pub, &pub_len, &proof, &proof_len);
```

---
### **dogecoin_zk_get_commitment_hash:**

`dogecoin_zk_err_t dogecoin_zk_get_commitment_hash(const uint8_t* payload, size_t payload_len, uint8_t out_commitment[32]);`

Compute the TX_C commitment value, `SHA256d(payload)`. This is the 32-byte
digest embedded in the OP_RETURN of TX_C.

_C usage:_
```c
uint8_t commit[32];
dogecoin_zk_get_commitment_hash(payload, payload_len, commit);
```

---
### **dogecoin_zk_build_opreturn_scriptpubkey:**

`dogecoin_zk_err_t dogecoin_zk_build_opreturn_scriptpubkey(dogecoin_zk_mode_t mode, const uint8_t commitment[32], cstring** out_spk);`

Build the OP_RETURN scriptPubKey for TX_C: `OP_RETURN <push 37> "DZKC"
<mode> <commit32>`. The caller frees `*out_spk` with
`cstr_free(*out_spk, true)`.

_C usage:_
```c
cstring* spk = NULL;
dogecoin_zk_build_opreturn_scriptpubkey(
    DOGECOIN_ZK_MODE_GROTH16, commit, &spk);
/* attach spk to a TX_C output ... */
cstr_free(spk, true);
```

## Carrier Transaction API

---
### **dogecoin_zk_build_carrier_tx_c:**

`dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_c(dogecoin_tx* tx, const uint8_t* payload, size_t payload_len, dogecoin_zk_mode_t mode, uint64_t carrier_value, cstring** out_carrier_spk, uint8_t* out_part_total);`

Append the OP_RETURN commit output and the P2SH carrier outputs (one per
required reveal-part) to an existing in-progress transaction. Mirrors
`dogecoin_tx_add_*_commit` + `dogecoin_tx_add_pqc_carrier_outputs` in one
call.

`payload` is the payload that will later be revealed in TX_R. The number
of carrier outputs is derived from its length using the PQC chunking
constants. `carrier_value` is the per-output value in koinu (≥ dust).

On success, `*out_carrier_spk` is the P2SH scriptPubKey of the carrier
outputs (caller frees with `cstr_free(..., true)`) and `*out_part_total`
is the number of parts that TX_R will need to spend.

_C usage:_
```c
cstring* carrier_spk = NULL;
uint8_t  parts = 0;
dogecoin_zk_build_carrier_tx_c(
    tx_c, payload, payload_len,
    DOGECOIN_ZK_MODE_GROTH16,
    /*carrier_value=*/100000000UL, /* 1 DOGE per carrier output */
    &carrier_spk, &parts);
cstr_free(carrier_spk, true);
```

---
### **dogecoin_zk_build_carrier_tx_r_scriptsigs:**

`dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_r_scriptsigs(const uint8_t* payload, size_t payload_len, cstring*** out_scriptsigs, uint8_t* out_part_total);`

Build the per-part scriptSigs for TX_R. `*out_scriptsigs` is allocated
and contains `*out_part_total` cstrings; the caller frees each with
`cstr_free(..., true)` and the array itself with `dogecoin_free()`.

_C usage:_
```c
cstring** sigs = NULL;
uint8_t   parts = 0;
dogecoin_zk_build_carrier_tx_r_scriptsigs(
    payload, payload_len, &sigs, &parts);
for (uint8_t i = 0; i < parts; ++i) {
    /* attach sigs[i] to tx_r->vin[i].script_sig ... */
    cstr_free(sigs[i], true);
}
dogecoin_free(sigs);
```

---
### **dogecoin_zk_extract_carrier_payload:**

`dogecoin_zk_err_t dogecoin_zk_extract_carrier_payload(const dogecoin_tx* tx_r, uint8_t** out_payload, size_t* out_payload_len);`

Extract a previously-revealed payload from a TX_R by walking its inputs
and reassembling the carrier parts. The caller frees `*out_payload` with
`dogecoin_free()`.

_C usage:_
```c
uint8_t* payload = NULL;
size_t   payload_len = 0;
if (dogecoin_zk_extract_carrier_payload(tx_r, &payload, &payload_len) ==
    DOGECOIN_ZK_OK) {
    /* dogecoin_zk_decode_payload(payload, payload_len, ...) */
    dogecoin_free(payload);
}
```

---
### **dogecoin_tx_extract_zk_commit:**

`dogecoin_bool dogecoin_tx_extract_zk_commit(const dogecoin_tx* tx, dogecoin_zk_mode_t* out_mode, uint8_t out_commit32[32]);`

Walk a transaction's outputs looking for the canonical TX_C OP_RETURN
commitment script `OP_RETURN <push 37> "DZKC" <mode-byte> <commit32>`.
On the first match, write the mode and 32-byte commitment to the out
parameters and return `true`. Mirrors `dogecoin_tx_extract_falcon512_commit`
so the SPV layer can detect ZK commitments alongside Falcon / Dilithium /
Raccoon ones.

_C usage:_
```c
dogecoin_zk_mode_t mode;
uint8_t commit[32];
if (dogecoin_tx_extract_zk_commit(tx_c, &mode, commit)) {
    /* tx_c is a ZK TX_C: remember (mode, commit) until TX_R is seen */
}
```

## Verification API

---
### **dogecoin_zk_verify_groth16:**

`dogecoin_zk_err_t dogecoin_zk_verify_groth16(const uint8_t* vk_json, size_t vk_json_len, const uint8_t* public_json, size_t public_json_len, const uint8_t* proof_json, size_t proof_json_len);`

Verify a Groth16 proof. If libdogecoin was built with `--with-rapidsnark`
or `--with-mcl` (`HAVE_RAPIDSNARK` / `HAVE_MCL` defined) this calls into
the in-process verifier and returns `DOGECOIN_ZK_OK` or
`DOGECOIN_ZK_ERR_VERIFY_FAIL`. Otherwise it returns
`DOGECOIN_ZK_ERR_DELEGATED` so callers can fall back to off-box
verification (`snarkjs groth16 verify`).

`vk_json` is the snarkjs-style verification key, `public_json` is
`public.json`, and `proof_json` is `proof.json`; all three are passed
verbatim as bytes.

_C usage:_
```c
dogecoin_zk_err_t rc = dogecoin_zk_verify_groth16(
    vk, vk_len, pub, pub_len, proof, proof_len);
if (rc == DOGECOIN_ZK_OK)              puts("proof verified");
else if (rc == DOGECOIN_ZK_ERR_DELEGATED) puts("verify off-box");
else                                    puts(dogecoin_zk_strerror(rc));
```

---
### **dogecoin_zk_verify_proof:**

`dogecoin_zk_err_t dogecoin_zk_verify_proof(const uint8_t* payload, size_t payload_len, const uint8_t* vk_blob, size_t vk_blob_len);`

Verify any ZK payload by mode. Dispatches on the decoded
`dogecoin_zk_mode_t` to the proof-system specific verifier above. The
payload's public inputs and proof bytes are passed verbatim to the
verifier (proof systems are responsible for their own encoding — for
snarkjs/Groth16 they are JSON). PLONK currently returns
`DOGECOIN_ZK_ERR_DELEGATED` (verify off-box with `snarkjs plonk verify`);
STARK returns `DOGECOIN_ZK_ERR_NOT_IMPLEMENTED`.

_C usage:_
```c
dogecoin_zk_err_t rc = dogecoin_zk_verify_proof(
    payload, payload_len, vk, vk_len);
```

## Proof Generation API

These entry points are kept for surface-area completeness and to align with
reserved-opcode proposal terminology. **They always return
`DOGECOIN_ZK_ERR_DELEGATED`** in this build because libdogecoin's policy is
that proving lives in the wallet/UI (snarkjs) or on a host (rapidsnark CLI).
The contrib helper `contrib/zk_carrier/witness_helper.py` is the supported
way to drive the off-library prover.

---
### **dogecoin_zk_generate_groth16_proof:**

`dogecoin_zk_err_t dogecoin_zk_generate_groth16_proof(const uint8_t* witness_json, size_t witness_json_len, const char* circuit_path, uint8_t** out_proof, size_t* out_proof_len, uint8_t** out_public, size_t* out_public_len);`

Always returns `DOGECOIN_ZK_ERR_DELEGATED`. Use snarkjs or rapidsnark to
produce `proof.json` and `public.json`, then call
[`dogecoin_zk_encode_payload`](#dogecoin_zk_encode_payload).

---
### **dogecoin_zk_generate_plonk_proof:**

`dogecoin_zk_err_t dogecoin_zk_generate_plonk_proof(const uint8_t* witness_json, size_t witness_json_len, const char* circuit_path, uint8_t** out_proof, size_t* out_proof_len, uint8_t** out_public, size_t* out_public_len);`

Always returns `DOGECOIN_ZK_ERR_DELEGATED`. Use snarkjs to produce
`proof.json` and `public.json`, then call
[`dogecoin_zk_encode_payload`](#dogecoin_zk_encode_payload).

## Errors

---
### **dogecoin_zk_strerror:**

`const char* dogecoin_zk_strerror(dogecoin_zk_err_t err);`

Return a human-readable description of a `dogecoin_zk_err_t` value.
Never returns NULL.

_C usage:_
```c
fprintf(stderr, "zk: %s\n", dogecoin_zk_strerror(rc));
```

## Tests

`test/zk_carrier_tests.c` covers:

* Codec round-trip + tamper-detection on the commitment hash.
* `OP_RETURN DZKC` byte layout.
* TX_C / TX_R round-trip with multi-chunk payloads, ensuring extracted
  bytes match the original.
* Mode dispatch — PLONK and STARK return `NOT_IMPLEMENTED` from
  `dogecoin_zk_verify_proof`, regardless of build flags.
* Prover delegation — all `dogecoin_zk_generate_*_proof` entry points
  return the documented error codes (no silent stubbed proofs).
