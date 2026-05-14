#!/bin/bash
#
# Mainnet Multisig Integration Test Script
#
# End-to-end mainnet test for funding M-of-N P2SH multisig addresses with the
# libdogecoin CLI tools (such, sendtx, spvnode). Modeled after
# contrib/mainnet_dilithium2_test.sh so that all prompt-driven and command-line
# steps are captured in a single log file.
#
# Required environment:
#   FUNDED_WIF / FUNDED_ADDR        - mainnet privkey/address that pays the
#                                     funding outputs. No default is shipped;
#                                     export both before running.
#   FUNDED_UTXO_TXID / VOUT / VALUE_KOINU
#                                   - one unspent P2PKH output owned by
#                                     FUNDED_ADDR. Each scenario chains its
#                                     change output forward.
#
# Optional environment:
#   SCENARIOS                       - space-separated "M-of-N" list. Default:
#                                     "2-of-3 1-of-2 3-of-5".
#   PER_OUTPUT_KOINU                - amount sent to each multisig output
#                                     (default 100000000 == 1 DOGE).
#   TX_FEE_KOINU                    - per-tx fee (default 2000000).
#   SPV_TIMEOUT_SECONDS             - per-scenario spvnode wait (default 1800).
#   RUN_LOG                         - target log file (default
#                                     test-logs/mainnet_multisig_e2e_<ts>.txt).
#
# Prerequisites:
#   - libdogecoin built (./such, ./sendtx, ./spvnode in CWD).
#   - curl, awk, sed, grep available.
#
# All transaction construction (multisig redeem script, P2SH address, raw
# unsigned tx, change output, signing) is done by driving `such -c transaction`
# interactively. No python/external helpers are used — the whole flow lives
# inside the libdogecoin CLI.
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ----------------------------- defaults --------------------------------------
NETWORK_FLAG=""                      # mainnet
TMPDIR=$(mktemp -d /tmp/multisig_e2e_XXXXXX)
chmod 700 "$TMPDIR"

# Funded mainnet wallet credentials. No defaults are committed; supply your
# own via environment variables before running this script.
FUNDED_WIF="${FUNDED_WIF:-}"
FUNDED_ADDR="${FUNDED_ADDR:-}"

# Starting UTXO that pays FUNDED_ADDR. Supply via environment variables.
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-}"

PER_OUTPUT_KOINU="${PER_OUTPUT_KOINU:-5000000}"
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"

SCENARIOS="${SCENARIOS:-2-of-3 1-of-2 3-of-5}"

SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"

REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((19180 + ($$ % 800)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"

mkdir -p test-logs
TS=$(date -u +%Y%m%d_%H%M%S)
RUN_LOG="${RUN_LOG:-$(pwd)/test-logs/mainnet_multisig_e2e_${TS}.txt}"
: > "$RUN_LOG"

# Relay success patterns (same as mainnet_dilithium2_test.sh)
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'
SENDTX_FATAL_PATTERN='Requested from nodes:[[:space:]]*0.*Seen on other nodes:[[:space:]]*0|not relayed back|very likely invalid'

# ----------------------------- logging helpers -------------------------------
info()    { echo -e "${BLUE}[INFO]${NC} $1"    | tee -a "$RUN_LOG"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$RUN_LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"   | tee -a "$RUN_LOG"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"     | tee -a "$RUN_LOG"; exit 1; }

run_and_log() {
    local label="$1"; shift
    echo "----- ${label}: $* -----" | tee -a "$RUN_LOG"
    "$@" 2>&1 | tee -a "$RUN_LOG"
    local rc=${PIPESTATUS[0]}
    echo "----- ${label} exit=${rc} -----" | tee -a "$RUN_LOG"
    return $rc
}

# ----------------------------- helpers ---------------------------------------
# koinu (uint64) -> "X.YYYYYYYY" DOGE string accepted by such finalize/add_output
koinu_to_doge() {
    awk -v k="$1" 'BEGIN{ printf "%d.%08d\n", k/100000000, k%100000000 }'
}


# ----------------------------- preflight -------------------------------------
check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -x "./$tool" ]; then
            error "$tool not found in CWD; build libdogecoin first"
        fi
    done
    command -v curl >/dev/null || error "curl is required"
    success "Tooling OK"
}

verify_funded_wallet() {
    info "Verifying provided funded WIF maps to expected mainnet address..."
    [ -n "$FUNDED_WIF" ]              || error "FUNDED_WIF is not set; export it before running"
    [ -n "$FUNDED_ADDR" ]             || error "FUNDED_ADDR is not set; export it before running"
    [ -n "$FUNDED_UTXO_TXID" ]        || error "FUNDED_UTXO_TXID is not set; export it before running"
    [ -n "$FUNDED_UTXO_VOUT" ]        || error "FUNDED_UTXO_VOUT is not set; export it before running"
    [ -n "$FUNDED_UTXO_VALUE_KOINU" ] || error "FUNDED_UTXO_VALUE_KOINU is not set; export it before running"
    local out
    out=$(./such -c generate_public_key -p "$FUNDED_WIF" 2>&1)
    echo "$out" | tee -a "$RUN_LOG"
    local got
    got=$(echo "$out" | sed -n 's/^p2pkh address:[[:space:]]*//p' | head -n1)
    [ "$got" = "$FUNDED_ADDR" ] || error "FUNDED_WIF maps to $got, expected $FUNDED_ADDR"
    success "Funded wallet OK ($FUNDED_ADDR)"
}

# ----------------------------- per-scenario ---------------------------------
generate_keypair_set() {
    # args: count -> populates $KEYS_WIF (array) and $KEYS_PUB (array)
    local n="$1"
    KEYS_WIF=()
    KEYS_PUB=()
    local i out wif pub
    for ((i=1; i<=n; i++)); do
        out=$(./such -c generate_private_key 2>&1)
        echo "$out" | tee -a "$RUN_LOG"
        wif=$(echo "$out" | sed -n 's/^private key wif:[[:space:]]*//p' | head -n1)
        [ -n "$wif" ] || error "Failed to generate cosigner #${i} private key"
        out=$(./such -c generate_public_key -p "$wif" 2>&1)
        echo "$out" | tee -a "$RUN_LOG"
        pub=$(echo "$out" | sed -n 's/^public key hex:[[:space:]]*//p' | head -n1)
        [ -n "$pub" ] || error "Failed to derive cosigner #${i} compressed pubkey"
        KEYS_WIF+=("$wif")
        KEYS_PUB+=("$pub")
    done
}

compute_redeem_via_such() {
    # Drives `such -c transaction` to compute the multisig redeem script and
    # mainnet P2SH address (submenu option 5). Network is switched to mainnet
    # so print_multisig_info uses mainnet chainparams.
    local M="$1"; local pubs_csv="$2"
    {
        echo "10"           # main: change network
        echo "1"            # mainnet
        echo "1"            # main: add transaction -> sub_menu
        echo "5"            # sub: multisig script/address
        echo "$pubs_csv"
        echo "$M"
        echo "9"            # sub: main menu
        echo "11"           # main: quit (WITH_NET)
        echo "10"           # fallback quit (no-NET)
    } | ./such -c transaction 2>&1
}

build_and_sign_funding_via_such() {
    # Drives `such -c transaction` interactively to:
    #   - switch to mainnet
    #   - add input (submenu 1) for FUNDED_UTXO_TXID:FUNDED_UTXO_VOUT
    #   - add output (submenu 2) sending PER_OUTPUT_KOINU to the P2SH address
    #   - finalize (submenu 3) which adds change back to FUNDED_ADDR
    #   - sign input 0 with FUNDED_WIF (submenu 4 -> 1) and print signed (3)
    # Caller must pass the precomputed P2SH multisig destination address.
    local p2sh_addr="$1"
    local in_value_doge per_out_doge fee_doge
    in_value_doge=$(koinu_to_doge "$FUNDED_UTXO_VALUE_KOINU")
    per_out_doge=$(koinu_to_doge "$PER_OUTPUT_KOINU")
    fee_doge=$(koinu_to_doge "$TX_FEE_KOINU")
    {
        echo "10"                       # main: change network
        echo "1"                        # mainnet
        echo "1"                        # main: add transaction -> sub_menu
        echo "1"                        # sub: add input
        echo "$FUNDED_UTXO_VOUT"        # vout index
        echo "$FUNDED_UTXO_TXID"        # prev txid
        echo "2"                        # sub: add output
        echo "$per_out_doge"            # amount in DOGE
        echo "$p2sh_addr"               # destination = mainnet P2SH
        echo "3"                        # sub: finalize
        echo "$p2sh_addr"               # re-enter destination for verification
        echo "$fee_doge"                # desired fee in DOGE
        echo "$in_value_doge"           # total amount being spent (input value)
        echo "$FUNDED_ADDR"             # senders/change address
        echo "4"                        # sub: sign transaction -> signing menu
        echo "1"                        # signing: sign input from current tx
        echo "0"                        # input index to sign
        echo "$FUNDED_WIF"               # private key
        echo "3"                        # signing: print signed
        echo "4"                        # signing: go back
        echo "9"                        # sub: main menu
        echo "11"                       # main: quit (WITH_NET build)
        echo "10"                       # fallback: quit (no-NET build)
    } | ./such -c transaction 2>&1
}

broadcast_with_retry() {
    local label="$1"; local signed_tx="$2"; local max_retries="${3:-$SENDTX_MAX_RETRIES}"
    local attempt=0 sendtx_output="" txid=""
    while [ "$attempt" -lt "$max_retries" ]; do
        attempt=$((attempt+1))
        info "Broadcast attempt $attempt/$max_retries for $label..."
        sendtx_output=$(run_and_log "sendtx $label attempt=$attempt" \
            ./sendtx -d -m 16 -s 30 $NETWORK_FLAG "$signed_tx" || true)
        txid=$(echo "$sendtx_output" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if echo "$sendtx_output" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_RESULT_TXID="$txid"
            success "$label broadcast accepted on attempt $attempt: $txid"
            return 0
        fi
        if echo "$sendtx_output" | grep -Eqi "$SENDTX_FATAL_PATTERN"; then
            warn "$label relay failed on attempt $attempt"
            [ "$attempt" -lt "$max_retries" ] && sleep 10
        elif [ -n "$txid" ]; then
            BROADCAST_RESULT_TXID="$txid"
            return 0
        fi
    done
    BROADCAST_RESULT_TXID="$txid"
    return 1
}

wait_for_rest_tx() {
    local txid="$1" timeout="$2"
    local start_ts now_ts txid_le rest_utxos rest_txs
    start_ts=$(date +%s)
    txid_le=$(echo "$txid" | sed 's/../& /g' | awk '{for(i=NF;i>=1;i--) printf $i}' | tr -d '\n')
    while true; do
        rest_utxos=$(curl -fsS "http://${REST_SERVER}/getUTXOs"        2>/dev/null || true)
        rest_txs=$(  curl -fsS "http://${REST_SERVER}/getTransactions" 2>/dev/null || true)
        if echo "$rest_utxos$rest_txs" | grep -Eqi "${txid}|${txid_le}"; then
            date +%s
            return 0
        fi
        now_ts=$(date +%s)
        if [ $((now_ts - start_ts)) -ge "$timeout" ]; then
            return 1
        fi
        sleep 1
    done
}

run_scenario() {
    local mn="$1"
    local M="${mn%-of-*}"
    local N="${mn#*-of-}"
    [ "$M" -ge 1 ] || error "scenario $mn: M must be >=1"
    [ "$N" -le 16 ] || error "scenario $mn: N must be <=16"
    [ "$M" -le "$N" ] || error "scenario $mn: M ($M) must be <= N ($N)"

    info "=== scenario ${M}-of-${N} ==="

    # 1. Cosigner keypairs
    info "[${mn}] Generating $N cosigner keypairs..."
    generate_keypair_set "$N"
    local pubs_csv
    pubs_csv=$(IFS=,; echo "${KEYS_PUB[*]}")

    # 2. Drive `such -c transaction` interactively (CLI only — no python) to
    #    compute the redeem script + mainnet P2SH address. The submenu's
    #    print_multisig_info uses chainparams set by the network switch.
    info "[${mn}] Computing multisig redeem script + P2SH via such transaction submenu (mainnet, $M-of-$N)..."
    local redeem_out
    redeem_out=$(compute_redeem_via_such "$M" "$pubs_csv")
    echo "$redeem_out" | tee -a "$RUN_LOG" >/dev/null
    REDEEM_HEX=$(echo "$redeem_out" | grep -o 'multisig redeem script:[[:space:]]*[0-9a-fA-F]*' | head -n1 | awk '{print $NF}')
    P2SH_ADDR=$( echo "$redeem_out" | grep -o 'multisig p2sh address:[[:space:]]*[A-Za-z0-9]*'   | head -n1 | awk '{print $NF}')
    [ -n "$REDEEM_HEX" ] || error "[${mn}] such submenu did not emit redeem script"
    [ -n "$P2SH_ADDR"  ] || error "[${mn}] such submenu did not emit P2SH address"
    case "$P2SH_ADDR" in
        A*|9*) : ;;  # mainnet P2SH starts with 'A' (or '9' for some hashes)
        *) error "[${mn}] unexpected non-mainnet P2SH address: $P2SH_ADDR (mainnet switch failed?)" ;;
    esac

    {
        echo "[${mn}] redeem_script_hex: $REDEEM_HEX"
        echo "[${mn}] p2sh_address:      $P2SH_ADDR"
        echo "[${mn}] cosigner_pubs:     $pubs_csv"
    } | tee -a "$RUN_LOG"

    # 2a. Recovery summary block (grep-friendly: search for 'RECOVERY_SUMMARY').
    # Spending the funded P2SH multisig later requires *all* of: M, N, the
    # ordered cosigner pubkeys (== order in redeem script), the cosigner WIFs,
    # the redeem script and the funding txid:vout. Emit them together so this
    # block is sufficient to recover the DOGE without re-running the test.
    {
        echo "===== RECOVERY_SUMMARY [${mn}] ====="
        echo "RECOVERY_SUMMARY scenario=${mn} M=${M} N=${N}"
        echo "RECOVERY_SUMMARY p2sh_address=${P2SH_ADDR}"
        echo "RECOVERY_SUMMARY redeem_script_hex=${REDEEM_HEX}"
        local _i
        for ((_i=0; _i<N; _i++)); do
            echo "RECOVERY_SUMMARY cosigner_${_i}_wif=${KEYS_WIF[$_i]}"
            echo "RECOVERY_SUMMARY cosigner_${_i}_pub=${KEYS_PUB[$_i]}"
        done
        echo "===== END RECOVERY_SUMMARY [${mn}] ====="
    } | tee -a "$RUN_LOG"

    # 3. Build & sign the funding tx in a fresh `such -c transaction` session
    #    using the precomputed P2SH address.
    info "[${mn}] Building & signing funding tx via such transaction submenu..."
    local sub_out
    sub_out=$(build_and_sign_funding_via_such "$P2SH_ADDR")
    echo "$sub_out" | tee -a "$RUN_LOG" >/dev/null

    if ! echo "$sub_out" | grep -Fq 'transaction input successfully signed!'; then
        error "[${mn}] such signing menu did not report success — see log"
    fi
    local signed_hex
    signed_hex=$(echo "$sub_out" | grep -o 'raw_tx:[[:space:]]*[0-9a-fA-F][0-9a-fA-F]*' | tail -n1 | awk '{print $NF}')
    [ -n "$signed_hex" ] || error "[${mn}] could not extract signed raw_tx from such submenu output"
    # Sanity: signed tx must reference our funding input txid (LE-encoded)
    local txid_le
    txid_le=$(echo "$FUNDED_UTXO_TXID" | sed 's/../& /g' | awk '{for(i=NF;i>=1;i--) printf $i}')
    if ! echo "$signed_hex" | grep -Fq "$txid_le"; then
        warn "[${mn}] signed tx does not contain expected input txid (LE) — continuing anyway"
    fi
    {
        echo "[${mn}] signed_funding_tx: $signed_hex"
    } | tee -a "$RUN_LOG"

    # Compute the chained change value (input - per-output - fee) that the
    # next scenario will spend from. finalize_transaction inside `such`
    # produces exactly this change value.
    NEXT_CHANGE=$((FUNDED_UTXO_VALUE_KOINU - PER_OUTPUT_KOINU - TX_FEE_KOINU))
    [ "$NEXT_CHANGE" -gt 0 ] || error "[${mn}] non-positive change $NEXT_CHANGE koinu"

    info "[${mn}] Broadcasting signed funding tx..."
    BROADCAST_RESULT_TXID=""
    if broadcast_with_retry "${mn}_funding" "$signed_hex"; then
        success "[${mn}] funding broadcast txid=$BROADCAST_RESULT_TXID"
    else
        error "[${mn}] funding broadcast failed after ${SENDTX_MAX_RETRIES} attempts"
    fi
    SCENARIO_TXID="$BROADCAST_RESULT_TXID"

    # Append the funding txid:vout to the recovery summary so the spending
    # transaction can be constructed later from the log alone.
    {
        echo "RECOVERY_SUMMARY scenario=${mn} funding_txid=${SCENARIO_TXID} funding_vout=0 funding_value_koinu=${PER_OUTPUT_KOINU}"
    } | tee -a "$RUN_LOG"

    # 5. Watch with spvnode (REST + log scan)
    info "[${mn}] Starting spvnode scan watching $P2SH_ADDR (timeout=${SPV_TIMEOUT_SECONDS}s)"
    local SPV_HDRS="$TMPDIR/spv_headers_${mn}.db"
    local SPV_WALL="$TMPDIR/spv_wallet_${mn}.db"
    local SPV_LOG="$TMPDIR/spvnode_${mn}.log"
    rm -f "$SPV_HDRS" "$SPV_WALL"
    : > "$SPV_LOG"
    # Run spvnode directly to a file (no pipeline tee, which block-buffers when
    # the next stage is a pipe and hides progress for minutes). We mirror the
    # log into RUN_LOG with a follower process that we kill at the end.
    stdbuf -oL -eL ./spvnode -h "$SPV_HDRS" -w "$SPV_WALL" \
        -u "$REST_SERVER" -c -d -x -p -b \
        -a "$P2SH_ADDR" scan >"$SPV_LOG" 2>&1 &
    local SPV_PID=$!
    ( tail -n +1 -F "$SPV_LOG" 2>/dev/null >> "$RUN_LOG" ) &
    local TAIL_PID=$!

    local found_ts=""
    local scan_start_ts
    scan_start_ts=$(date +%s)
    # Detection: REQUIRE the wallet's block-stage callback to fire. The line
    # "Found relevant transaction!" is printed exclusively by
    # dogecoin_wallet_check_transaction (src/wallet.c) which is wired to
    # client->sync_transaction in src/spv.c — that callback is invoked only
    # while parsing transactions inside a *block* received from a peer, never
    # for mempool-only txs. Matching this line therefore proves spvnode
    # actually scanned the confirmed block containing our P2SH funding tx.
    # Each scenario uses a freshly generated P2SH and its own SPV_LOG, so any
    # wallet match here is necessarily our funding tx.
    while true; do
        if grep -Fq 'Found relevant transaction!' "$SPV_LOG" 2>/dev/null; then
            found_ts=$(date +%s); break
        fi
        if ! kill -0 "$SPV_PID" 2>/dev/null; then
            warn "[${mn}] spvnode exited unexpectedly; tail of log:"
            tail -n 80 "$SPV_LOG" | tee -a "$RUN_LOG"
            break
        fi
        if [ $(( $(date +%s) - scan_start_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
            warn "[${mn}] spvnode timeout ${SPV_TIMEOUT_SECONDS}s; tail of log:"
            tail -n 80 "$SPV_LOG" | tee -a "$RUN_LOG"
            break
        fi
        sleep 5
    done

    if [ -n "$found_ts" ]; then
        local elapsed=$((found_ts - scan_start_ts))
        success "[${mn}] spvnode wallet matched watched P2SH in confirmed block after ${elapsed}s (txid=$SCENARIO_TXID)"
        {
            echo "[${mn}] SPV_TIMING tx_seen_at=${found_ts} elapsed_seconds=${elapsed}"
            echo "[${mn}] SPV_BLOCK_MATCH detected via wallet sync_transaction callback (Found relevant transaction!)"
        } | tee -a "$RUN_LOG"
        # capture surrounding context: the block-header line printed right
        # before "Start parsing N transactions..." plus the wallet match line.
        {
            echo "[${mn}] SPV_LOG_TX_CONTEXT (block scan + wallet match):"
            # 12 lines of leading context to include the block-hash|height|time|tx_count line
            grep -B 12 -A 1 'Found relevant transaction!' "$SPV_LOG" | head -80 || true
            echo "[${mn}] SPV_LOG_TAIL (last 50 lines):"
            tail -n 50 "$SPV_LOG"
        } | tee -a "$RUN_LOG"
    fi

    kill "$SPV_PID"  2>/dev/null || true
    wait "$SPV_PID"  2>/dev/null || true
    sleep 1
    kill "$TAIL_PID" 2>/dev/null || true
    wait "$TAIL_PID" 2>/dev/null || true

    if [ -z "$found_ts" ]; then
        error "[${mn}] spvnode did not observe txid $SCENARIO_TXID within ${SPV_TIMEOUT_SECONDS}s"
    fi

    # 6. Chain to next scenario: change vout = 1 of just-broadcast tx.
    FUNDED_UTXO_TXID="$SCENARIO_TXID"
    FUNDED_UTXO_VOUT=1
    FUNDED_UTXO_VALUE_KOINU="$NEXT_CHANGE"
    info "[${mn}] Next chained UTXO: ${FUNDED_UTXO_TXID}:${FUNDED_UTXO_VOUT} value=${FUNDED_UTXO_VALUE_KOINU}"
}

# ----------------------------- main -----------------------------------------
main() {
    {
        echo "=========================================="
        echo "  Mainnet Multisig Integration Test"
        echo "  start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "  scenarios: $SCENARIOS"
        echo "  funded:    $FUNDED_ADDR"
        echo "  starting UTXO: ${FUNDED_UTXO_TXID}:${FUNDED_UTXO_VOUT} (${FUNDED_UTXO_VALUE_KOINU} koinu)"
        echo "  per_output: $PER_OUTPUT_KOINU koinu  fee: $TX_FEE_KOINU koinu"
        echo "  log: $RUN_LOG"
        echo "=========================================="
    } | tee -a "$RUN_LOG"

    check_tools
    verify_funded_wallet

    for s in $SCENARIOS; do
        run_scenario "$s"
    done

    {
        echo "=========================================="
        echo "  All multisig scenarios completed OK"
        echo "  end: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "  log: $RUN_LOG"
        echo "=========================================="
    } | tee -a "$RUN_LOG"
}

main "$@"
