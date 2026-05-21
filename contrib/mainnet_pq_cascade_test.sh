#!/bin/bash
#
# Mainnet PQ Cascade Runner (Falcon -> Dilithium2 -> Raccoon-G)
#
# Starts from a funded UTXO, runs each mainnet script, and passes the chained
# UTXO from one script to the next.
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
START_TXID="${START_TXID:-63d79b47b6d55b5143afb5f7782f9300da5d6a4837b5c9837a1769e3e0c44621}"
START_VOUT="${START_VOUT:-0}"
START_VALUE_KOINU="${START_VALUE_KOINU:-4194000000}"
START_SCRIPT_PUBKEY="${START_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}"
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"

run_stage() {
    local label="$1"
    local script_path="$2"
    local txid="$3"
    local vout="$4"
    local value_koinu="$5"
    local script_pubkey="$6"
    local stage_log
    local stage_tmp
    stage_log="$(mktemp "/tmp/${label}_cascade_XXXX.log")"

    (
        cd "$ROOT_DIR"
        NON_INTERACTIVE=1 \
        AUTO_BROADCAST=1 \
        NETWORK=mainnet \
        CARRIER_ENABLED=1 \
        SPV_REQUIRE_VALIDATION=1 \
        SPV_TIMEOUT_SECONDS="$SPV_TIMEOUT_SECONDS" \
        FUNDED_UTXO_TXID="$txid" \
        FUNDED_UTXO_VOUT="$vout" \
        FUNDED_UTXO_VALUE_KOINU="$value_koinu" \
        FUNDED_UTXO_SCRIPT_PUBKEY="$script_pubkey" \
        AUTO_PREPARE_TX_FROM_UTXO=1 \
        "contrib/${script_path}"
    ) | tee "$stage_log"

    stage_tmp="$(sed -n 's/^.*All test data saved in:[[:space:]]*//p' "$stage_log" | tail -n1)"
    if [ -z "$stage_tmp" ] || [ ! -f "$stage_tmp/tx_info.txt" ]; then
        echo "[ERROR] ${label}: failed to locate tx_info.txt (tmpdir='$stage_tmp')" >&2
        exit 1
    fi

    # shellcheck disable=SC1090
    source "$stage_tmp/tx_info.txt"
    if [ -z "${CHAINED_UTXO_TXID:-}" ] || [ -z "${CHAINED_UTXO_VOUT:-}" ] || [ -z "${CHAINED_UTXO_VALUE_KOINU:-}" ] || [ -z "${CHAINED_UTXO_SCRIPT_PUBKEY:-}" ]; then
        echo "[ERROR] ${label}: missing chained UTXO fields in $stage_tmp/tx_info.txt" >&2
        exit 1
    fi

    STAGE_NEXT_TXID="$CHAINED_UTXO_TXID"
    STAGE_NEXT_VOUT="$CHAINED_UTXO_VOUT"
    STAGE_NEXT_VALUE_KOINU="$CHAINED_UTXO_VALUE_KOINU"
    STAGE_NEXT_SCRIPT_PUBKEY="$CHAINED_UTXO_SCRIPT_PUBKEY"
}

echo "=========================================="
echo "  Mainnet PQ Cascade (Falcon->DIL2->RCG4)"
echo "=========================================="
echo "START_TXID=$START_TXID"
echo "START_VOUT=$START_VOUT"
echo "START_VALUE_KOINU=$START_VALUE_KOINU"
echo "START_SCRIPT_PUBKEY=$START_SCRIPT_PUBKEY"

run_stage falcon mainnet_falcon_test.sh "$START_TXID" "$START_VOUT" "$START_VALUE_KOINU" "$START_SCRIPT_PUBKEY"
NEXT_TXID="$STAGE_NEXT_TXID"
NEXT_VOUT="$STAGE_NEXT_VOUT"
NEXT_VALUE_KOINU="$STAGE_NEXT_VALUE_KOINU"
NEXT_SCRIPT_PUBKEY="$STAGE_NEXT_SCRIPT_PUBKEY"

run_stage dilithium2 mainnet_dilithium2_test.sh "$NEXT_TXID" "$NEXT_VOUT" "$NEXT_VALUE_KOINU" "$NEXT_SCRIPT_PUBKEY"
NEXT_TXID="$STAGE_NEXT_TXID"
NEXT_VOUT="$STAGE_NEXT_VOUT"
NEXT_VALUE_KOINU="$STAGE_NEXT_VALUE_KOINU"
NEXT_SCRIPT_PUBKEY="$STAGE_NEXT_SCRIPT_PUBKEY"

run_stage raccoong mainnet_raccoong_test.sh "$NEXT_TXID" "$NEXT_VOUT" "$NEXT_VALUE_KOINU" "$NEXT_SCRIPT_PUBKEY"
NEXT_TXID="$STAGE_NEXT_TXID"
NEXT_VOUT="$STAGE_NEXT_VOUT"
NEXT_VALUE_KOINU="$STAGE_NEXT_VALUE_KOINU"
NEXT_SCRIPT_PUBKEY="$STAGE_NEXT_SCRIPT_PUBKEY"

echo "=========================================="
echo "Cascade complete."
echo "Final chained UTXO:"
echo "  txid=$NEXT_TXID"
echo "  vout=$NEXT_VOUT"
echo "  value_koinu=$NEXT_VALUE_KOINU"
echo "  script_pubkey=$NEXT_SCRIPT_PUBKEY"
echo "=========================================="
