#!/usr/bin/env bash
# contrib/zk_carrier/circuits/build_circuit.sh
#
# Reproducible (or auditable) build for the ZK carrier range_proof circuit.
#
# Stages
#   1. Generate/reuse local phase-1 ptau artifacts under build/.
#   2. Compile range_proof.circom -> .r1cs / .wasm / .sym.   (deterministic)
#   3. PLONK setup -> range_proof_plonk.zkey.                 (deterministic)
#   4. Groth16 phase-2 setup + single-contributor ceremony
#      -> range_proof.zkey.                                   (random entropy
#         by default; pass --deterministic-entropy HEX to make the ceremony
#         bit-reproducible.)
#   5. Export both verification keys.
#
# Modes
#   (default)                       run all stages with random Groth16 entropy.
#   --deterministic-entropy HEX     use HEX as the snarkjs `-e=` value, making
#                                   the Groth16 ceremony bit-reproducible by
#                                   anyone who reruns with the same HEX.
#   --verify                        re-export both vkeys from locally-built
#                                   zkeys and diff against local vkey files.
#                                   No ceremony is run. Exits non-zero on any
#                                   mismatch or missing local artifacts.
#
# Pinned tool versions (see ./README.md):
#   circom    2.1.6
#   snarkjs   0.7.x
#   circomlib 2.0.5

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SRC_CIRCOM="$SCRIPT_DIR/range_proof.circom"
INC_DIR="$BUILD_DIR/circ_inc"

CIRCOM="${CIRCOM:-circom}"
SNARKJS="${SNARKJS:-snarkjs}"

MODE="build"
DETERMINISTIC_ENTROPY=""
OUT_DIR=""

usage() {
    cat <<EOF
Usage: $0 [options]
  --deterministic-entropy HEX   make the Groth16 ceremony bit-reproducible by
                                using HEX as snarkjs's contribute entropy.
                                Without this flag, fresh entropy is read from
                                /dev/urandom (a real single-contributor
                                ceremony, but not byte-reproducible).
  --verify                      do not run any ceremony; re-export both
                                verification_key files from the locally-built
                                zkeys and compare them to local copies. Exits
                                non-zero on any mismatch.
  --out DIR                     write artifacts to DIR instead of $BUILD_DIR
                                (still uses/reuses ptau files from $BUILD_DIR).
  -h, --help                    show this help.

Environment overrides:
  CIRCOM      circom binary (default: circom)
  SNARKJS     snarkjs binary (default: snarkjs)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deterministic-entropy)
            DETERMINISTIC_ENTROPY="$2"; shift ;;
        --verify)
            MODE="verify" ;;
        --out)
            OUT_DIR="$2"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [[ -n "$DETERMINISTIC_ENTROPY" ]]; then
    if ! [[ "$DETERMINISTIC_ENTROPY" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "ERROR: --deterministic-entropy must be a hex string" >&2
        exit 2
    fi
    # Require at least 32 bytes (64 hex chars) of entropy.  snarkjs hashes
    # the input, but accepting a short string would create a misleading
    # "ceremony" with trivially-low entropy.
    if (( ${#DETERMINISTIC_ENTROPY} < 64 )); then
        echo "ERROR: --deterministic-entropy must be at least 64 hex chars (32 bytes)" >&2
        exit 2
    fi
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"
mkdir -p "$OUT_DIR"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required tool not in PATH: $1" >&2
        echo "  install circom 2.1.6 and snarkjs 0.7.x first" >&2
        exit 2
    fi
}

# --------------------------- Stage 1: local ptau setup ------------------------
if [[ "$MODE" != "verify" ]]; then
    require_tool "$SNARKJS"
    echo "==> [1/5] preparing local ptau artifacts"
    PTAU0="$BUILD_DIR/pot12_0000.ptau"
    PTAU1="$BUILD_DIR/pot12_0001.ptau"
    PTAU_FINAL="$BUILD_DIR/pot12_final.ptau"
    if [[ ! -f "$PTAU_FINAL" ]]; then
        echo "    generating powers-of-tau (BN128, 2^12)"
        "$SNARKJS" powersoftau new bn128 12 "$PTAU0" -v
        if [[ -n "$DETERMINISTIC_ENTROPY" ]]; then
            echo "    contributing deterministic ptau entropy"
            echo "$DETERMINISTIC_ENTROPY" | "$SNARKJS" powersoftau contribute "$PTAU0" "$PTAU1" --name="build_circuit" -v
        else
            echo "    contributing random ptau entropy"
            echo "build_circuit ptau $(date -u +%s%N) $$" | "$SNARKJS" powersoftau contribute "$PTAU0" "$PTAU1" --name="build_circuit" -v
        fi
        "$SNARKJS" powersoftau prepare phase2 "$PTAU1" "$PTAU_FINAL" -v
    else
        echo "    reusing $PTAU_FINAL"
    fi
else
    echo "==> [verify] checking local zkey/vkey artifacts"
fi

# --verify mode checks locally-built verification keys still match what you'd
# export from the locally-built zkeys. No new entropy is consumed.
if [[ "$MODE" == "verify" ]]; then
    require_tool "$SNARKJS"

    TMPDIR_VERIFY="$(mktemp -d -t zkc-verify.XXXXXX)"
    trap 'rm -rf "$TMPDIR_VERIFY"' EXIT

    echo "==> [verify] exporting verification keys from local zkeys"
    for f in range_proof.zkey range_proof_plonk.zkey verification_key.json verification_key_plonk.json; do
        if [[ ! -f "$BUILD_DIR/$f" ]]; then
            echo "ERROR: missing local artifact: $BUILD_DIR/$f" >&2
            echo "  run $0 first to generate circuit build artifacts" >&2
            exit 2
        fi
    done
    "$SNARKJS" zkey export verificationkey \
        "$BUILD_DIR/range_proof.zkey" \
        "$TMPDIR_VERIFY/verification_key.json" >/dev/null
    "$SNARKJS" zkey export verificationkey \
        "$BUILD_DIR/range_proof_plonk.zkey" \
        "$TMPDIR_VERIFY/verification_key_plonk.json" >/dev/null

    rc=0
    for vk in verification_key.json verification_key_plonk.json; do
        if [[ ! -f "$BUILD_DIR/$vk" ]]; then
            echo "  FAIL  $vk missing from $BUILD_DIR" >&2
            rc=1
            continue
        fi
        if diff -q "$BUILD_DIR/$vk" "$TMPDIR_VERIFY/$vk" >/dev/null; then
            echo "  ok  $vk matches local copy"
        else
            echo "  FAIL  $vk differs from local copy" >&2
            diff -u "$BUILD_DIR/$vk" "$TMPDIR_VERIFY/$vk" || true
            rc=1
        fi
    done
    exit "$rc"
fi

# --------------------------- Stage 2: compile circuit ------------------------
require_tool "$CIRCOM"
require_tool "$SNARKJS"

if [[ ! -d "$INC_DIR/circomlib" ]]; then
    CIRCOMLIB_PARENT="${CIRCOMLIB_PARENT:-$(npm root -g 2>/dev/null || true)}"
    mkdir -p "$INC_DIR"
    if [[ -n "$CIRCOMLIB_PARENT" && -d "$CIRCOMLIB_PARENT/circomlib/circuits" ]]; then
        ln -sfn "$CIRCOMLIB_PARENT/circomlib/circuits" "$INC_DIR/circomlib"
    fi
fi

if [[ ! -d "$INC_DIR/circomlib" ]]; then
    echo "ERROR: circomlib include not found at $INC_DIR/circomlib" >&2
    echo "  install circomlib 2.x (npm install -g circomlib) or set CIRCOMLIB_PARENT" >&2
    exit 2
fi

echo "==> [2/5] compiling range_proof.circom"
"$CIRCOM" "$SRC_CIRCOM" \
    --r1cs --wasm --sym \
    --output "$OUT_DIR" \
    -l "$INC_DIR"

# --------------------------- Stage 3: PLONK setup (deterministic) ------------
echo "==> [3/5] PLONK setup (deterministic)"
"$SNARKJS" plonk setup \
    "$OUT_DIR/range_proof.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" \
    "$OUT_DIR/range_proof_plonk.zkey"

# --------------------------- Stage 4: Groth16 phase-2 ceremony ---------------
echo "==> [4/5] Groth16 phase-2 setup"
"$SNARKJS" groth16 setup \
    "$OUT_DIR/range_proof.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" \
    "$OUT_DIR/range_proof_0000.zkey"

if [[ -n "$DETERMINISTIC_ENTROPY" ]]; then
    echo "    contribute: deterministic (HEX from --deterministic-entropy)"
    CEREMONY_NAME="reproducible-build"
    "$SNARKJS" zkey contribute \
        "$OUT_DIR/range_proof_0000.zkey" \
        "$OUT_DIR/range_proof.zkey" \
        --name="$CEREMONY_NAME" \
        -e="$DETERMINISTIC_ENTROPY"
else
    echo "    contribute: random entropy from /dev/urandom (default)"
    CEREMONY_NAME="single-contributor-demo"
    RAND_ENTROPY="$(head -c 32 /dev/urandom | xxd -p -c 64)"
    if [[ -z "$RAND_ENTROPY" || ${#RAND_ENTROPY} -lt 64 ]]; then
        echo "ERROR: failed to read 32 bytes of entropy from /dev/urandom" >&2
        exit 3
    fi
    "$SNARKJS" zkey contribute \
        "$OUT_DIR/range_proof_0000.zkey" \
        "$OUT_DIR/range_proof.zkey" \
        --name="$CEREMONY_NAME" \
        -e="$RAND_ENTROPY"
    # Wipe ephemeral entropy from the shell.
    RAND_ENTROPY=""
fi

rm -f "$OUT_DIR/range_proof_0000.zkey"

# --------------------------- Stage 5: export verification keys ---------------
echo "==> [5/5] exporting verification keys"
"$SNARKJS" zkey export verificationkey \
    "$OUT_DIR/range_proof.zkey" \
    "$OUT_DIR/verification_key.json"
"$SNARKJS" zkey export verificationkey \
    "$OUT_DIR/range_proof_plonk.zkey" \
    "$OUT_DIR/verification_key_plonk.json"

echo
echo "==> done.  artifacts written to: $OUT_DIR"
if [[ -z "$DETERMINISTIC_ENTROPY" ]]; then
    echo "    note: range_proof.zkey used random entropy and is NOT byte-reproducible."
    echo "          The verification_key.json is what verifiers need; rerun with"
    echo "          --deterministic-entropy HEX to make the ceremony itself repeatable."
fi
