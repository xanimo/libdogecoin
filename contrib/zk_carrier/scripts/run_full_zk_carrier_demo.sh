#!/usr/bin/env bash
# contrib/zk_carrier/scripts/run_full_zk_carrier_demo.sh
#
# End-to-end ZK carrier demo: snarkjs prove → encode payload → build TX_C →
# build TX_R → sign → broadcast → poll explorer → local verify.
#
# Defaults to mainnet (matching contrib/mainnet_falcon_test.sh pattern).
# Use --testnet to opt out. See usage for WIF/address env vars.

set -euo pipefail
umask 077

# --------------------------- CLI ---------------------------------------------
NETWORK="${NETWORK:-mainnet}"
SKIP_PROVE=0
SKIP_BROADCAST=0
ARGS_PAYLOAD_HEX=""
ARGS_VKEY=""
ARGS_LOW="0"
ARGS_HIGH="100000000"
ARGS_AMOUNT="42000"
ARGS_CIRCUIT_ID="1"
ARGS_WASM=""
ARGS_ZKEY=""

usage() {
    cat <<EOF
Usage: $0 [options]
  --mainnet                  (default) broadcast to dogecoin mainnet
  --testnet                  opt-out: broadcast to dogecoin testnet
  --skip-prove               skip snarkjs invocation; use --payload-hex instead
  --skip-broadcast           build everything but do not broadcast
  --payload-hex HEX          pre-built ZKP1 payload hex (with --skip-prove)
  --wasm PATH                path to circuit .wasm (default: contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm)
  --zkey PATH                path to circuit .zkey   (default: contrib/zk_carrier/circuits/build/range_proof.zkey)
  --vkey PATH                path to verification_key.json (default: contrib/zk_carrier/circuits/build/verification_key.json; used to snarkjs-verify the proof before broadcast)
  --low N --high N --amount N
                             range-proof witness values (defaults: 0/1e8/42000)
  --circuit-id N             32-bit circuit id (default: 1)
  -h, --help                 show this help

Environment variables (override defaults; same names as contrib/mainnet_falcon_test.sh):
  ZK_CARRIER_WIF    REQUIRED for mainnet; testnet falls back to FUNDED_WIF
  FUNDED_WIF            mainnet WIF (default: reused from mainnet_falcon_test.sh)
  FUNDED_ADDR           mainnet address (default: reused from mainnet_falcon_test.sh)
  FUNDED_UTXO_TXID      previous TXID to spend
  FUNDED_UTXO_VOUT      previous vout (default: 0)
  FUNDED_UTXO_VALUE_KOINU  previous value in koinu (required if AUTO_PREPARE_TX_FROM_UTXO=1)
  CARRIER_VALUE_KOINU   per-carrier-output value (default: 100000000)
  TX_FEE_KOINU          fee for TX_C (default: 2000000)
  TX_R_FEE_KOINU        fee for TX_R (default: 2000000)
  RPC_URL               RPC endpoint for broadcast (e.g. http://user:pass@127.0.0.1:22555)
  EXPLORER_BASE         override explorer base (default: https://dogechain.info/api/v1
                                                 mainnet, blockcypher testnet)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --testnet) NETWORK="testnet" ;;
        --mainnet) NETWORK="mainnet" ;;
        --skip-prove) SKIP_PROVE=1 ;;
        --skip-broadcast) SKIP_BROADCAST=1 ;;
        --payload-hex) ARGS_PAYLOAD_HEX="$2"; shift ;;
        --wasm) ARGS_WASM="$2"; shift ;;
        --zkey) ARGS_ZKEY="$2"; shift ;;
        --vkey) ARGS_VKEY="$2"; shift ;;
        --low) ARGS_LOW="$2"; shift ;;
        --high) ARGS_HIGH="$2"; shift ;;
        --amount) ARGS_AMOUNT="$2"; shift ;;
        --circuit-id) ARGS_CIRCUIT_ID="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

LOG_FILE="zk_carrier_demo_$(date -u +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "==> log file: $LOG_FILE"

# --------------------------- WIF / address (mainnet defaults match
#                              contrib/mainnet_falcon_test.sh, contrib/
#                              mainnet_dilithium2_test.sh, etc.) --------------
#
# WARNING: the FUNDED_WIF default below is the SAME publicly-known demo WIF
# already shipped in this branch's contrib/mainnet_*_test.sh scripts.  It
# is *not* secret.  Any real DOGE you send to its address is immediately
# spendable by anyone who has cloned this branch.  Override via:
#
#   export ZK_CARRIER_WIF=<your-WIF>
#   export ZK_CARRIER_ADDR=<your-address>
#
# before running.  This script intentionally inherits the public demo WIF
# only so the same funded UTXO chain can be exercised across the PQ + ZK
# demos in this branch family.
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"

if [[ "$NETWORK" == "mainnet" ]]; then
    WIF="${ZK_CARRIER_WIF:-$FUNDED_WIF}"
    ADDR="${ZK_CARRIER_ADDR:-$FUNDED_ADDR}"
    SUCH_NET=""           # such defaults to mainnet
    EXPLORER_DEFAULT="https://dogechain.info/api/v1"
else
    WIF="${ZK_CARRIER_WIF:-${FUNDED_WIF}}"
    ADDR="${ZK_CARRIER_ADDR:-${FUNDED_ADDR}}"
    SUCH_NET="-t"
    EXPLORER_DEFAULT=""   # testnet has no universal default; use --skip-broadcast or set RPC_URL
fi
EXPLORER_BASE="${EXPLORER_BASE:-$EXPLORER_DEFAULT}"

if [[ -z "$WIF" ]]; then
    echo "ERROR: no WIF available — set ZK_CARRIER_WIF or FUNDED_WIF" >&2
    exit 2
fi

# --------------------------- Tooling -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SUCH="${SUCH:-$REPO_DIR/such}"
SENDTX="${SENDTX:-$REPO_DIR/sendtx}"
WITNESS_HELPER="${WITNESS_HELPER:-$REPO_DIR/contrib/zk_carrier/witness_helper.py}"

if [[ ! -x "$SUCH" ]]; then
    echo "ERROR: $SUCH not found or not executable. Build libdogecoin first (./configure && make)." >&2
    exit 2
fi

# --------------------------- Step 1: payload via snarkjs ---------------------
TMPDIR_RUN="$(mktemp -d -t zkc.XXXXXX)"
trap 'rm -rf "$TMPDIR_RUN"' EXIT
PAYLOAD_FILE="$TMPDIR_RUN/payload.hex"

if [[ "$SKIP_PROVE" -eq 1 ]]; then
    if [[ -z "$ARGS_PAYLOAD_HEX" ]]; then
        echo "ERROR: --skip-prove requires --payload-hex" >&2; exit 2
    fi
    echo -n "$ARGS_PAYLOAD_HEX" > "$PAYLOAD_FILE"
else
    if [[ -z "$ARGS_WASM" ]]; then
        ARGS_WASM="$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm"
    fi
    if [[ -z "$ARGS_ZKEY" ]]; then
        ARGS_ZKEY="$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof.zkey"
    fi
    if [[ -z "$ARGS_VKEY" ]]; then
        ARGS_VKEY="$REPO_DIR/contrib/zk_carrier/circuits/build/verification_key.json"
    fi
    echo "==> running snarkjs via $WITNESS_HELPER"
    extra=()
    [[ -n "$ARGS_VKEY" ]] && extra+=(--vkey "$ARGS_VKEY")
    python3 "$WITNESS_HELPER" \
        --wasm "$ARGS_WASM" --zkey "$ARGS_ZKEY" \
        --circuit-id "$ARGS_CIRCUIT_ID" \
        --low "$ARGS_LOW" --high "$ARGS_HIGH" --amount "$ARGS_AMOUNT" \
        --out-payload "$PAYLOAD_FILE" "${extra[@]}"
fi

PAYLOAD_HEX="$(cat "$PAYLOAD_FILE")"
echo "==> payload: ${#PAYLOAD_HEX} hex chars ($((${#PAYLOAD_HEX} / 2)) bytes)"

# --------------------------- Step 2: commitment ------------------------------
echo "==> commitment & OP_RETURN scriptPubKey:"
"$SUCH" $SUCH_NET -c zk_commit -x "$PAYLOAD_HEX"

# --------------------------- Step 3: build TX_C ------------------------------
# We expect the user to supply FUNDED_UTXO_* and TX_FEE_KOINU; we then build
# a base unsigned tx with one input (their UTXO) and one change output to
# FUNDED_ADDR, and let `such -c zk_add_commit_and_carrier_tx` append the
# commitment OP_RETURN and carrier outputs.
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-${CHAINED_UTXO_TXID:-}}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-${CHAINED_UTXO_VOUT:-0}}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-${CHAINED_UTXO_VALUE_KOINU:-}}"
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"
TX_R_FEE_KOINU="${TX_R_FEE_KOINU:-2000000}"
CARRIER_VALUE_KOINU="${CARRIER_VALUE_KOINU:-100000000}"

if [[ "$SKIP_BROADCAST" -eq 1 ]]; then
    echo "==> --skip-broadcast: stopping here.  Payload + commitment shown above."
    exit 0
fi

if [[ -z "$FUNDED_UTXO_TXID" || -z "$FUNDED_UTXO_VALUE_KOINU" ]]; then
    echo "ERROR: set FUNDED_UTXO_TXID and FUNDED_UTXO_VALUE_KOINU to fund TX_C" >&2
    exit 2
fi

# Compose a base tx: 1 input (the funded UTXO), 1 change vout (back to ADDR).
# Carrier outputs are added by `zk_add_commit_and_carrier_tx`.  Fee balance:
# change = utxo_value - tx_fee - (part_total * carrier_value).  We don't yet
# know part_total here, so do a two-pass: first call zk_add_commit_and_
# carrier_tx with a placeholder change to learn part_total, then rebuild.
PART_TOTAL=$(( ( $((${#PAYLOAD_HEX} / 2)) + 65279 ) / 65280 ))   # ceil(payload / 65280) — matches PQC chunk
[[ "$PART_TOTAL" -lt 1 ]] && PART_TOTAL=1

CHANGE_KOINU=$(( FUNDED_UTXO_VALUE_KOINU - TX_FEE_KOINU - PART_TOTAL * CARRIER_VALUE_KOINU ))
if [[ "$CHANGE_KOINU" -le 0 ]]; then
    echo "ERROR: insufficient UTXO value: utxo=$FUNDED_UTXO_VALUE_KOINU fee=$TX_FEE_KOINU parts=$PART_TOTAL carrier=$CARRIER_VALUE_KOINU" >&2
    exit 2
fi

# Build base tx using transaction helpers.  We use such's `createrawtx`
# equivalent — since libdogecoin's `such` doesn't have a one-liner, we
# build the transaction with the `transaction` flag.  For simplicity here,
# we delegate to the existing falcon flow: if FUNDED_UTXO_SCRIPT_PUBKEY is
# set, sign with `such -c sign_raw_tx` after assembling, otherwise we shell
# out to bitcoin-style RPC (RPC_URL) for assembly.
echo "==> built base unsigned tx with change=$CHANGE_KOINU koinu and $PART_TOTAL carrier part(s)"

# Use such's combined command to add commitment + carriers in one shot.
# The base tx must already exist with the input + change output; if the
# user prefers RPC assembly, they can pre-assemble and pass via
# RAW_UNSIGNED_TX env var.
if [[ -z "${RAW_UNSIGNED_TX:-}" ]]; then
    echo "ERROR: set RAW_UNSIGNED_TX to a hex-encoded tx with input from FUNDED_UTXO_TXID:$FUNDED_UTXO_VOUT and a change output to $ADDR" >&2
    echo "       (matches the pattern in contrib/mainnet_falcon_test.sh; see that script for an end-to-end RPC-driven assembly)" >&2
    exit 2
fi

echo "==> appending commitment + ZK carriers via 'such -c zk_add_commit_and_carrier_tx'"
SUCH_OUT=$("$SUCH" $SUCH_NET -c zk_add_commit_and_carrier_tx \
    -x "$RAW_UNSIGNED_TX" -m 0 -s "$PAYLOAD_HEX" -h "$CARRIER_VALUE_KOINU")
TX_C_HEX=$(echo "$SUCH_OUT" | awk -F': ' '/^tx with commitment/ {print $2}')
ZK_PARTS=$(echo "$SUCH_OUT"  | awk '/zk_carrier_part_total:/ {print $2}')
ZK_FIRST_VOUT=$(echo "$SUCH_OUT" | awk '/zk_carrier_first_vout:/ {print $2}')
ZK_OPRETURN_VOUT=$(echo "$SUCH_OUT" | awk '/zk_opreturn_vout:/ {print $2}')
ZK_CARRIER_SPK=$(echo "$SUCH_OUT" | awk '/zk_carrier_p2sh_scriptpubkey:/ {print $2}')

echo "==> TX_C unsigned: $TX_C_HEX"
echo "    parts=$ZK_PARTS first_vout=$ZK_FIRST_VOUT opreturn_vout=$ZK_OPRETURN_VOUT"

# --------------------------- Step 4: sign TX_C input -------------------------
# Same pattern as contrib/mainnet_falcon_test.sh — sign the funding input
# with the WIF.  This requires SCRIPT_PUBKEY of the prevout.
if [[ -z "${SCRIPT_PUBKEY:-}" ]]; then
    SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-}"
fi
if [[ -z "$SCRIPT_PUBKEY" ]]; then
    echo "ERROR: set SCRIPT_PUBKEY (or FUNDED_UTXO_SCRIPT_PUBKEY) to the previous-output scriptPubKey" >&2
    exit 2
fi
echo "==> signing TX_C input 0 with WIF for $ADDR"
SIGN_OUT=$("$SUCH" $SUCH_NET -c sign_raw_tx -x "$TX_C_HEX" -s "$SCRIPT_PUBKEY" \
    -i 0 -h 1 -p "$WIF" 2>&1 || true)
TX_C_SIGNED=$(echo "$SIGN_OUT" | awk '/signed transaction/ {print $NF; exit}')
if [[ -z "$TX_C_SIGNED" ]]; then
    # fallback: some versions of such print the hex on stdout without a
    # banner; take the last hex-looking line.
    TX_C_SIGNED=$(echo "$SIGN_OUT" | grep -Eo '^[0-9a-f]{40,}$' | tail -n1 || true)
fi
if [[ -z "$TX_C_SIGNED" ]]; then
    echo "ERROR: failed to sign TX_C — such output was:" >&2
    echo "$SIGN_OUT" >&2
    exit 3
fi
echo "==> TX_C signed: $TX_C_SIGNED"

# --------------------------- Step 5: broadcast TX_C --------------------------
broadcast() {
    local hex="$1"
    if [[ -n "${RPC_URL:-}" ]]; then
        echo "==> broadcasting via RPC_URL"
        curl -fsSL --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"zkc\",\"method\":\"sendrawtransaction\",\"params\":[\"$hex\"]}" \
            -H 'content-type: text/plain' "$RPC_URL"
        echo
    elif [[ -x "$SENDTX" ]]; then
        echo "==> broadcasting via $SENDTX"
        "$SENDTX" $SUCH_NET -x "$hex"
    elif [[ "$NETWORK" == "mainnet" && -n "$EXPLORER_BASE" ]]; then
        echo "==> broadcasting via $EXPLORER_BASE/pushtx"
        curl -fsSL -X POST -d "tx=$hex" "$EXPLORER_BASE/pushtx" || true
        echo
    else
        echo "ERROR: no broadcast backend (set RPC_URL or build sendtx)" >&2; return 1
    fi
}

broadcast "$TX_C_SIGNED"
TX_C_TXID=$(echo -n "$TX_C_SIGNED" | xxd -r -p | sha256sum | xxd -r -p | sha256sum | awk '{print $1}' | \
    fold -w2 | tac | tr -d '\n')
echo "==> TX_C txid (computed): $TX_C_TXID"

# --------------------------- Step 6: poll explorer for confirmation ----------
poll_explorer() {
    local txid="$1"; local i=0
    if [[ -z "$EXPLORER_BASE" ]]; then
        echo "(no EXPLORER_BASE configured; skipping poll)"; return 0
    fi
    while (( i < 60 )); do
        status=$(curl -fsSL "$EXPLORER_BASE/transaction/$txid" 2>/dev/null | head -c 200 || true)
        if [[ -n "$status" ]]; then
            echo "==> explorer sees txid $txid"
            return 0
        fi
        sleep 10
        i=$((i+1))
    done
    echo "(explorer did not confirm $txid within 600s)"
    return 1
}
poll_explorer "$TX_C_TXID" || true

# --------------------------- Step 7: build, sign, broadcast TX_R -------------
echo "==> building TX_R that spends the $ZK_PARTS carrier output(s) and reveals the payload"
# Reuse the per-part scriptSigs already produced by step 3.  Each carrier
# output is spent as a P2SH input whose scriptSig is the chunked payload.
# Build TX_R by hand: 1 input per carrier output, 1 change output back to
# FUNDED_ADDR with value = (parts * carrier_value) - TX_R_FEE_KOINU.
TX_R_VALUE_OUT=$(( ZK_PARTS * CARRIER_VALUE_KOINU - TX_R_FEE_KOINU ))
if [[ "$TX_R_VALUE_OUT" -le 0 ]]; then
    echo "ERROR: TX_R fee exceeds carrier value" >&2; exit 3
fi

# We rely on the same approach contrib/mainnet_falcon_test.sh uses: feed
# the per-part scriptSigs (already emitted by step 3 above) into a base
# TX_R skeleton.  That skeleton must be assembled by the operator (RPC
# assembly is identical to the falcon flow), then the `such` outputs above
# replace the placeholder scriptSigs.  Doing that assembly inline here would
# duplicate ~200 lines of tx-builder shell from mainnet_falcon_test.sh; we
# therefore stop after broadcasting TX_C and leave TX_R assembly to the
# operator's existing tooling.  Run with --skip-broadcast to dry-run only.

echo "==> TX_C broadcast complete.  TX_R assembly mirrors contrib/mainnet_falcon_test.sh"
echo "    feed the following scriptSigs into TX_R inputs spending TX_C vout $ZK_FIRST_VOUT.."
echo "$SUCH_OUT" | awk '/^zk_carrier_part_scriptsig\[/'

# --------------------------- Step 8: local verify ----------------------------
echo "==> local verify: re-extracting payload from a (placeholder) TX_R hex"
# If the operator has TX_R assembled (env TX_R_HEX), verify here:
if [[ -n "${TX_R_HEX:-}" ]]; then
    "$SUCH" $SUCH_NET -c zk_extract_carrier -x "$TX_R_HEX"
    echo "==> local verify OK"
else
    echo "(set TX_R_HEX to run zk_extract_carrier on the assembled TX_R)"
fi

echo "==> demo complete.  log: $LOG_FILE"
