# ZK carrier — circuits

This directory contains the reference circom circuit used by the ZK carrier
demos (`contrib/zk_carrier/scripts/`). Generated proving artifacts are **not**
committed; they are written under `contrib/zk_carrier/circuits/build/`, which is
ignored by git.

## Versions

These circuits are pinned to the following toolchain. Anything older than circom
2.1 will not parse `pragma circom 2.1.6`.

* circom: **2.1.6** (https://github.com/iden3/circom)
* snarkjs: **0.7.x** (https://github.com/iden3/snarkjs)
* circomlib: **2.0.5** (https://github.com/iden3/circomlib)

> Note: the helper generates a local ptau-12 powers-of-tau file, which only
> covers small circuits. Bump to ptau-14/16 if you grow the circuit beyond a few
> thousand constraints.

## Local artifact build

The one-shot build is `./build_circuit.sh`. It assumes `circom` 2.1.6,
`snarkjs` 0.7.x, and `circomlib` 2.x are available on the host. The helper will
create `build/circ_inc/circomlib` as a symlink to the installed circomlib circuit
folder when possible.

```bash
# Default: random Groth16 entropy (real single-contributor ceremony,
#          NOT byte-reproducible). Outputs are local build artifacts.
./build_circuit.sh

# Reproducible Groth16 ceremony: anyone running with the same HEX gets
# bit-identical zkeys + verification keys. Useful for CI, audits, and
# regression-testing the build pipeline; not a substitute for a real
# multi-party ceremony in production. HEX must be at least 64 hex chars
# (32 bytes) and must not be reused in any non-test setting.
./build_circuit.sh --deterministic-entropy 7c1c9d3e0f2a8b6543e9d1c4a07b58f23e96cba140d8e7f269b3a51e8d4c0f72

# Local audit: exports verification keys from the local zkeys and diffs them
# against build/verification_key*.json. No new entropy is consumed.
./build_circuit.sh --verify
```

The script's stages are:

1. Generate or reuse local ptau-12 powers-of-tau artifacts under `build/`.
2. Compile `range_proof.circom` → `.r1cs` / `.wasm` / `.sym` (deterministic
   given pinned circom + circomlib).
3. PLONK universal setup → `range_proof_plonk.zkey`.
4. Groth16 phase-2 setup + single-contributor `zkey contribute` →
   `range_proof.zkey`. Entropy source: `/dev/urandom` by default, or the
   `--deterministic-entropy HEX` value.
5. Export both `verification_key.json` and `verification_key_plonk.json`.

> Note: Running `./build_circuit.sh --deterministic-entropy HEX` from an empty `build/` directory is fully deterministic end-to-end—`snarkjs powersoftau new` is deterministic, and the script pipes your HEX into `powersoftau contribute`, so any two clean checkouts using the same HEX will produce identical ptau, zkey, and verification key files. If you run the script twice in the same checkout (with a random ptau the first time and cached ptau thereafter), verification keys may not match those from a clean build with the same HEX.

### Determinism summary

| artifact                     | reproducible from source? |
|------------------------------|---------------------------|
| `range_proof.r1cs/.wasm/.sym`| yes (circom + circomlib pinned) |
| `range_proof_plonk.zkey`     | yes when ptau input is identical |
| `verification_key_plonk.json`| yes when ptau input is identical |
| `range_proof.zkey`           | only with identical ptau + `--deterministic-entropy HEX` |
| `verification_key.json`      | only with identical ptau + `--deterministic-entropy HEX` |

## Manual / custom invocation

If you'd rather drive snarkjs directly:

```bash
# 1. Compile the circuit.
mkdir -p build/circ_inc
ln -sfn "$(npm root -g)/circomlib/circuits" build/circ_inc/circomlib
circom range_proof.circom --r1cs --wasm --sym --output build \
    -l ./build/circ_inc

# 2. Generate a local ptau and trusted-setup phase 2.
snarkjs powersoftau new bn128 12 build/pot12_0000.ptau -v
echo "demo entropy" | snarkjs powersoftau contribute \
    build/pot12_0000.ptau build/pot12_0001.ptau --name="demo" -v
snarkjs powersoftau prepare phase2 build/pot12_0001.ptau build/pot12_final.ptau -v
snarkjs groth16 setup build/range_proof.r1cs build/pot12_final.ptau build/range_proof_0000.zkey
snarkjs zkey contribute build/range_proof_0000.zkey build/range_proof.zkey \
    --name="demo contributor" -e="$(head -c 32 /dev/urandom | xxd -p)"
snarkjs zkey export verificationkey build/range_proof.zkey build/verification_key.json

# 3. Generate a proof for a concrete witness.
cat > input.json <<'JSON'
{ "low": "0", "high": "1000000", "amount": "42000" }
JSON
snarkjs groth16 fullprove input.json \
    build/range_proof_js/range_proof.wasm \
    build/range_proof.zkey \
    proof.json public.json

# 4. Verify off-box.
snarkjs groth16 verify build/verification_key.json public.json proof.json
```

## Driving the carrier flow

The Python helper `../witness_helper.py` runs proof generation and emits the
canonical ZK carrier payload bytes (`ZKP1` magic + headers + public + proof) that
`such -c zk_add_commit_and_carrier_tx` consumes.
