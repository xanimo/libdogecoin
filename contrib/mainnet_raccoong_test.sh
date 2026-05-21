#!/bin/bash
#
# Raccoon-G-44 Mainnet Integration Test Script
#
# Prerequisites:
#   - libdogecoin built with --enable-raccoon-g
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR=$(mktemp -d /tmp/raccoong_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0
BROADCAST_TXID=""
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"
REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((20080 + ($$ % 1000)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
CARRIER_ENABLED="${CARRIER_ENABLED:-1}"
# NOTE: FUNDED_WIF and FUNDED_ADDR must be supplied via the environment.
# Historical defaults referenced a real mainnet WIF used during PR validation
# and are intentionally removed: shipping a funded mainnet private key in a
# public repository would publish that key. Set both env vars before running.
FUNDED_WIF="${FUNDED_WIF:?FUNDED_WIF must be set (mainnet WIF of the funding key)}"
FUNDED_ADDR="${FUNDED_ADDR:?FUNDED_ADDR must be set (mainnet address corresponding to FUNDED_WIF)}"
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-${CHAINED_UTXO_TXID:-b6e065cbb0b42166a3fa0708c664df4a4a726e4b51ec47541634117dc7477c04}}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-${CHAINED_UTXO_VOUT:-0}}"
AUTO_PREPARE_TX_FROM_UTXO="${AUTO_PREPARE_TX_FROM_UTXO:-1}"
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"
TX_R_FEE_KOINU="${TX_R_FEE_KOINU:-100000000}"
# Raccoon-G needs 24 carrier outputs; default to 50000000 koinu (0.5 DOGE) each = 12 DOGE total.
# TX_R_FEE_KOINU=100000000 (1 DOGE) is adequate for ~38kB at ~0.026 DOGE/kB >> 0.01 DOGE/kB minimum.
CARRIER_VALUE_KOINU="${CARRIER_VALUE_KOINU:-50000000}"
# Minimum 10000000 koinu (0.1 DOGE) per carrier to avoid P2SH dust; adequate TX_R fee is
# ensured by TX_R_FEE_KOINU, not carrier value.
if [ "$CARRIER_VALUE_KOINU" -lt 10000000 ]; then
    CARRIER_VALUE_KOINU=10000000
fi
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-${CHAINED_UTXO_VALUE_KOINU:-}}"
FUNDED_UTXO_SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-${CHAINED_UTXO_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}}"
# Carrier P2SH address to watch in SPV (for TX_R carrier output visibility)
CARRIER_P2SH_WATCH_ADDR="${CARRIER_P2SH_WATCH_ADDR:-A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q}"
RUN_LOG="$TMPDIR/mainnet_raccoong_run.log"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"
# Relay success: "Seen on other nodes: N" where N > 0, or already-known responses.
# NOTE: "tx successfully sent to node" only means pushed to peer, NOT that it was accepted.
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'
SENDTX_FATAL_PATTERN='Requested from nodes:[[:space:]]*0.*Seen on other nodes:[[:space:]]*0|not relayed back|very likely invalid'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

lookup_utxo_value() {
    local txid="$1"; local vout="$2"; local val=""
    val=$(curl -sf "https://chain.so/api/v2/tx/DOGE/${txid}" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); o=d['data']['outputs'][${vout}]; print(int(float(o['value'])*1e8))" 2>/dev/null || true)
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null; then echo "$val"; return 0; fi
    val=$(curl -sf "https://api.blockcypher.com/v1/doge/main/txs/${txid}" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['outputs'][${vout}]['value'])" 2>/dev/null || true)
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null; then echo "$val"; return 0; fi
    return 1
}

debug_tx_hex() {
    local tx_hex="$1"; local label="${2:-TX}"
    python3 - "$tx_hex" "$label" <<'PYDEBUG'
import sys, struct
tx_hex = sys.argv[1]; label = sys.argv[2]; tx = bytes.fromhex(tx_hex); off = 0
def ru32(): global off; v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
def ru64(): global off; v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
def rvar():
    global off; b=tx[off]; off+=1
    if b<0xfd: return b
    if b==0xfd: v=struct.unpack_from('<H',tx,off)[0]; off+=2; return v
    if b==0xfe: v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
    v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
print(f"=== {label} Debug (size={len(tx)} bytes) ===")
ver=ru32(); print(f"  version: {ver}"); nin=rvar(); print(f"  inputs: {nin}")
for i in range(nin):
    ph=tx[off:off+32][::-1].hex(); off+=32; pi=ru32(); sl=rvar(); off+=sl; sq=ru32()
    print(f"    in[{i}]: txid={ph} vout={pi} scriptSig_len={sl}")
nout=rvar(); print(f"  outputs: {nout}")
for i in range(nout):
    val=ru64(); sl=rvar(); spk=tx[off:off+sl].hex(); off+=sl; vd=val/1e8
    kind="P2PKH" if spk.startswith('76a914') else "P2SH" if spk.startswith('a914') else "OP_RETURN" if spk.startswith('6a') else "unknown"
    dust_ok = "OK" if (val==0 and kind=="OP_RETURN") or val>=100000 else f"DUST(need>=0.001DOGE)"
    print(f"    out[{i}]: {val} koinu ({vd:.8f} DOGE) type={kind} dust={dust_ok}")
print(f"=== end {label} ===")
PYDEBUG
}

broadcast_with_retry() {
    local label="$1"; local signed_tx="$2"; local max_retries="${3:-$SENDTX_MAX_RETRIES}"
    local attempt=0; local sendtx_output="" txid=""
    while [ "$attempt" -lt "$max_retries" ]; do
        attempt=$((attempt + 1)); info "Broadcast attempt $attempt/$max_retries for $label..."
        sendtx_output=$(run_and_log "sendtx $label attempt=$attempt" ./sendtx -d -m 16 -s 30 $NETWORK_FLAG "$signed_tx" || true)
        echo "$sendtx_output" | sed 's/Error:/sendtx-note:/g' | tee -a "$RUN_LOG"
        txid=$(echo "$sendtx_output" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if echo "$sendtx_output" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_RESULT_TXID="$txid"; success "$label broadcast accepted on attempt $attempt: $txid"; return 0
        fi
        if echo "$sendtx_output" | grep -Eqi "$SENDTX_FATAL_PATTERN"; then
            echo -e "${YELLOW}[WARN]${NC} $label relay failed on attempt $attempt. Debugging TX format..."
            debug_tx_hex "$signed_tx" "$label" 2>&1 | tee -a "$RUN_LOG"
            [ "$attempt" -lt "$max_retries" ] && sleep 10
        elif [ -n "$txid" ]; then
            BROADCAST_RESULT_TXID="$txid"; return 0
        fi
    done
    BROADCAST_RESULT_TXID="$txid"; return 1
}

run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----" | tee -a "$RUN_LOG"
    "$@" 2>&1 | tee -a "$RUN_LOG"
    local rc=${PIPESTATUS[0]}
    echo "----- ${label} exit=${rc} -----" | tee -a "$RUN_LOG"
    return $rc
}

wait_for_rest_tx() {
    local txid="$1"
    local timeout="$2"
    local start_ts now_ts
    local txid_le
    local rest_utxos rest_txs
    start_ts=$(date +%s)
    txid_le=$(echo "$txid" | sed 's/../& /g' | awk '{for(i=NF;i>=1;i--) printf $i}' | tr -d '\n')
    while true; do
        rest_utxos=$(curl -fsS "http://${REST_SERVER}/getUTXOs" 2>/dev/null || true)
        rest_txs=$(curl -fsS "http://${REST_SERVER}/getTransactions" 2>/dev/null || true)
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

check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    if ! command -v curl &> /dev/null; then
        error "curl not found. Required for REST tx monitoring."
    fi
    if ! ./such -c help 2>&1 | grep -q raccoong_keygen; then
        error "libdogecoin not built with Raccoon-G support. Rebuild with --enable-raccoon-g"
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        info "SPV_REQUIRE_VALIDATION=0 — SPV validation will be skipped (broadcast-only mode)"
    fi
    success "All tools available"
}

load_mainnet_wallet() {
    info "Using provided funded mainnet wallet..."
    PRIVKEY_WIF="$FUNDED_WIF"
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/mainnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/mainnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    if [ "$TESTNET_ADDR" != "$FUNDED_ADDR" ]; then
        error "Provided WIF does not map to expected funded address"
    fi
    success "Mainnet funded wallet loaded: $TESTNET_ADDR"
}

prepare_tx_from_funded_utxo() {
    info "Constructing unsigned tx from configured funded UTXO..."
    local selected_txid selected_vout selected_value selected_script send_value
    selected_txid="$FUNDED_UTXO_TXID"
    selected_vout="$FUNDED_UTXO_VOUT"
    selected_value="$FUNDED_UTXO_VALUE_KOINU"
    selected_script="$FUNDED_UTXO_SCRIPT_PUBKEY"

    if [ -z "$selected_value" ]; then
        info "UTXO value not provided, attempting blockchain API lookup..."
        selected_value=$(lookup_utxo_value "$selected_txid" "$selected_vout" || true)
        if [ -n "$selected_value" ] && [ "$selected_value" -gt 0 ] 2>/dev/null; then
            info "Auto-detected UTXO value: $selected_value koinu"
            FUNDED_UTXO_VALUE_KOINU="$selected_value"
        else
            error "Failed to auto-detect UTXO value. Set FUNDED_UTXO_VALUE_KOINU manually."
        fi
    fi

    [ -n "$selected_txid" ] || error "FUNDED_UTXO_TXID is required"
    [ -n "$selected_vout" ] || error "FUNDED_UTXO_VOUT is required"
    [ -n "$selected_value" ] || error "FUNDED_UTXO_VALUE_KOINU is required"
    [ -n "$selected_script" ] || error "FUNDED_UTXO_SCRIPT_PUBKEY is required"
    if [ "$selected_value" -le "$TX_FEE_KOINU" ]; then
        error "FUNDED_UTXO_VALUE_KOINU must be greater than TX_FEE_KOINU"
    fi
    send_value=$((selected_value - TX_FEE_KOINU))

    RAW_UNSIGNED_TX=$(python3 - "$selected_txid" "$selected_vout" "$send_value" "$selected_script" <<'PY'
import sys
txid_hex = sys.argv[1].strip().lower()
vout = int(sys.argv[2])
value = int(sys.argv[3])
script_hex = sys.argv[4].strip().lower()

if len(txid_hex) != 64:
    raise SystemExit("invalid txid length")
if len(script_hex) % 2 != 0:
    raise SystemExit("invalid script hex length")

def le_u32(n): return n.to_bytes(4, "little", signed=False).hex()
def le_u64(n): return n.to_bytes(8, "little", signed=False).hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()

raw = (
    "01000000"
    + "01"
    + bytes.fromhex(txid_hex)[::-1].hex()
    + le_u32(vout)
    + "00"
    + "ffffffff"
    + "01"
    + le_u64(value)
    + varint(len(script_hex) // 2)
    + script_hex
    + "00000000"
)
print(raw)
PY
)
    SCRIPT_PUBKEY="$selected_script"
    success "Prepared RAW_UNSIGNED_TX from ${selected_txid}:${selected_vout} (same-address cascade output)"
}

generate_raccoong_keypair() {
    info "Generating Raccoon-G-44 keypair..."
    run_and_log "such raccoong_keygen" ./such -c raccoong_keygen | tee "$TMPDIR/raccoong_keys.txt"
    RACCOONG_PK=$(grep "^public key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    RACCOONG_SK=$(grep "^secret key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$RACCOONG_PK" ] || error "Failed to generate Raccoon-G keypair"
    [ -n "$RACCOONG_SK" ] || error "Failed to generate Raccoon-G keypair"
    if [ "$RACCOONG_PK" = "$RACCOONG_SK" ]; then
        error "Raccoon-G public and secret keys are identical; expected different key material"
    fi
    success "Raccoon-G-44 keypair generated"
}

derive_hd_child() {
    info "Deriving Raccoon-G child keys (non-hardened + hardened)..."
    CHAINCODE=$(printf '42%.0s' {1..32})
    run_and_log "such raccoong_hd_derive non-hardened" \
        ./such -c raccoong_hd_derive -p "$RACCOONG_SK" -s "$CHAINCODE" -i 7 -g 0 | tee "$TMPDIR/raccoong_hd_nonhardened.txt"
    run_and_log "such raccoong_hd_derive hardened" \
        ./such -c raccoong_hd_derive -p "$RACCOONG_SK" -s "$CHAINCODE" -i 7 -g 1 | tee "$TMPDIR/raccoong_hd_hardened.txt"
    run_and_log "such raccoong_hd_derive_pub" \
        ./such -c raccoong_hd_derive_pub -k "$RACCOONG_PK" -s "$CHAINCODE" -i 7 | tee "$TMPDIR/raccoong_hd_pub.txt"
}

build_transaction() {
    info "Build unsigned mainnet tx with such, then paste hex below:"
    if { [ -z "$RAW_UNSIGNED_TX" ] || [ -z "$SCRIPT_PUBKEY" ]; } && [ "$AUTO_PREPARE_TX_FROM_UTXO" -eq 1 ]; then
        prepare_tx_from_funded_utxo
    fi
    if [ -z "$RAW_UNSIGNED_TX" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "RAW_UNSIGNED_TX must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$RAW_UNSIGNED_TX" ]; then
        read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    else
        info "Using RAW_UNSIGNED_TX from environment"
    fi
    if [ -z "$SCRIPT_PUBKEY" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "SCRIPT_PUBKEY must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$SCRIPT_PUBKEY" ]; then
        read -p "Enter scriptPubKey hex for input 0: " SCRIPT_PUBKEY
    else
        info "Using SCRIPT_PUBKEY from environment"
    fi

    # Reject placeholder prevout (32-byte txid + 4-byte vout = 36 bytes = 72 hex chars).
    if echo "$RAW_UNSIGNED_TX" | grep -Eq '^0100000001(00){36}'; then
        error "Input transaction uses a zero prevout placeholder. Provide a real funded UTXO transaction."
    fi
    if echo "$SCRIPT_PUBKEY" | grep -Eq '^76a914(0){40}88ac$'; then
        error "scriptPubKey is a zero placeholder. Provide the real UTXO scriptPubKey."
    fi

    SIGHASH_OUTPUT=$(run_and_log "such tx_sighash32" ./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    echo "$SIGHASH_OUTPUT"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    [ -n "$TX_SIGHASH_HEX" ] || error "Failed to derive tx_sighash32"

    run_and_log "such raccoong_sign" ./such -c raccoong_sign -p "$RACCOONG_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/raccoong_sig.txt"
    RACCOONG_SIG=$(grep "^signature:" "$TMPDIR/raccoong_sig.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$RACCOONG_SIG" ] || error "Failed to sign tx_sighash32"

    run_and_log "such raccoong_commit" ./such -c raccoong_commit -k "$RACCOONG_PK" -s "$RACCOONG_SIG" | tee "$TMPDIR/raccoong_commit.txt"
    RACCOONG_COMMIT=$(grep "^commitment:" "$TMPDIR/raccoong_commit.txt" | cut -d: -f2 | tr -d ' ')
    [ "${#RACCOONG_COMMIT}" -eq 64 ] || error "Invalid commitment length"

    if [ "$CARRIER_ENABLED" -eq 1 ]; then
        info "Building TX_C with OP_RETURN commitment + P2SH carrier outputs..."
        ADD_COMMIT_AND_CARRIER_OUTPUT=$(run_and_log "such raccoong_add_commit_and_carrier_tx" ./such -c raccoong_add_commit_and_carrier_tx -x "$RAW_UNSIGNED_TX" -m "$RACCOONG_COMMIT" -k "$RACCOONG_PK" -s "$RACCOONG_SIG" -h "$CARRIER_VALUE_KOINU")
        echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | tee -a "$RUN_LOG"
        TX_C_UNSIGNED=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^tx with commitment and carrier outputs:/ {print $2; exit}' | tr -d ' ')
        CARRIER_PART_TOTAL=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_part_total:/ {print $2; exit}' | tr -d ' ')
        CARRIER_FIRST_VOUT=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_first_vout:/ {print $2; exit}' | tr -d ' ')
        CARRIER_SCRIPT_PUBKEY=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_p2sh_scriptpubkey:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_C_UNSIGNED" ] || error "Failed to append Raccoon-G commitment + carrier outputs"
        [ -n "$CARRIER_PART_TOTAL" ] || error "Missing carrier_part_total"
        [ -n "$CARRIER_FIRST_VOUT" ] || error "Missing carrier_first_vout"
        [ "$CARRIER_PART_TOTAL" -ge 1 ] || error "Invalid carrier_part_total"
        CARRIER_PART_SCRIPTSIGS=()
        for ((i=0; i<CARRIER_PART_TOTAL; i++)); do
            part_ss=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | sed -n "s/^carrier_part_scriptsig\\[$i\\]:[[:space:]]*//p" | head -n1 | tr -d ' ')
            [ -n "$part_ss" ] || error "Missing carrier_part_scriptsig[$i]"
            CARRIER_PART_SCRIPTSIGS+=("$part_ss")
        done
    else
        info "Building TX_C with OP_RETURN commitment only (no carrier)..."
        COMMIT_ONLY_OUTPUT=$(run_and_log "such raccoong_add_commit_tx" ./such -c raccoong_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$RACCOONG_COMMIT")
        echo "$COMMIT_ONLY_OUTPUT" | tee -a "$RUN_LOG"
        TX_C_UNSIGNED=$(echo "$COMMIT_ONLY_OUTPUT" | awk -F': ' '/^tx with commitment:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_C_UNSIGNED" ] || error "Failed to construct TX_C (commit-only)"
        CARRIER_PART_TOTAL=0
        CARRIER_FIRST_VOUT=0
        CARRIER_SCRIPT_PUBKEY=""
        CARRIER_PART_SCRIPTSIGS=()
        success "TX_C built in commitment-only mode (standard, relayable)"
    fi

    debug_tx_hex "$TX_C_UNSIGNED" "TX_C_unsigned" 2>&1 | tee -a "$RUN_LOG"

    info "Signing TX_C with secp256k1 on input 0..."
    SIGN_OUTPUT=$(run_and_log "such sign TX_C" ./such -c sign -x "$TX_C_UNSIGNED" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_OUTPUT" | tee -a "$RUN_LOG"
    TX_C_SIGNED=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_C_SIGNED" ] || error "Failed to sign TX_C"
    success "Signed TX_C"

    debug_tx_hex "$TX_C_SIGNED" "TX_C_signed" 2>&1 | tee -a "$RUN_LOG"

    TX_R_UNSIGNED=""
    TX_R_SIGNED=""
    TX_R_TXID=""
    DO_BROADCAST="n"
    if [ "$AUTO_BROADCAST" -eq 1 ]; then
        DO_BROADCAST="y"
    elif [ "$NON_INTERACTIVE" -eq 0 ]; then
        read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    fi
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        BROADCAST_RESULT_TXID=""
        if ! broadcast_with_retry "TX_C" "$TX_C_SIGNED"; then
            error "TX_C failed to relay after all retries. Check TX debug output above."
        fi
        TX_C_TXID="$BROADCAST_RESULT_TXID"
        [ -n "$TX_C_TXID" ] || error "Failed to parse TX_C txid"
        success "TX_C broadcast accepted/known: $TX_C_TXID"

        if [ "$CARRIER_ENABLED" -eq 1 ] && [ "$CARRIER_PART_TOTAL" -gt 0 ]; then
            info "Waiting for TX_C visibility before building TX_R..."
            wait_for_rest_tx "$TX_C_TXID" 120 >/dev/null || info "TX_C not yet visible via REST (continuing anyway)"

            TX_R_UNSIGNED=$(python3 - "$TX_C_TXID" "$CARRIER_FIRST_VOUT" "$CARRIER_PART_TOTAL" "$CARRIER_VALUE_KOINU" "$TX_R_FEE_KOINU" "$SCRIPT_PUBKEY" <<'PY'
import sys
txid_hex = sys.argv[1].strip().lower()
first_vout = int(sys.argv[2]); part_total = int(sys.argv[3])
carrier_value = int(sys.argv[4]); fee = int(sys.argv[5]); out_spk = sys.argv[6].strip().lower()
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()
if len(txid_hex) != 64 or part_total <= 0: raise SystemExit("invalid tx_r params")
total_in = carrier_value * part_total
if total_in <= fee: raise SystemExit("carrier total value must exceed tx_r fee")
send_value = total_in - fee
version = "01000000"
vin = []
prev_txid_le = bytes.fromhex(txid_hex)[::-1].hex()
for i in range(part_total):
    vin.append(prev_txid_le + le_u32(first_vout + i) + "00" + "ffffffff")
vout = le_u64(send_value) + varint(len(out_spk)//2) + out_spk
raw = version + varint(len(vin)) + "".join(vin) + "01" + vout + "00000000"
print(raw)
PY
)
            [ -n "$TX_R_UNSIGNED" ] || error "Failed to build TX_R unsigned"
            TX_R_SIGNED="$TX_R_UNSIGNED"
            for ((i=0; i<CARRIER_PART_TOTAL; i++)); do
                SET_SS_OUTPUT=$(run_and_log "such set_scriptsig TX_R[$i]" ./such -c set_scriptsig -x "$TX_R_SIGNED" -i "$i" -s "${CARRIER_PART_SCRIPTSIGS[$i]}")
                TX_R_SIGNED=$(echo "$SET_SS_OUTPUT" | awk -F': ' '/^tx with scriptsig set:/ {print $2; exit}' | tr -d ' ')
                [ -n "$TX_R_SIGNED" ] || error "Failed to set TX_R scriptSig for input $i"
            done
            info "Debugging TX_R format..."
            debug_tx_hex "$TX_R_SIGNED" "TX_R_signed" 2>&1 | tee -a "$RUN_LOG"

            BROADCAST_RESULT_TXID=""
            if ! broadcast_with_retry "TX_R" "$TX_R_SIGNED"; then
                info "TX_R failed to relay (P2SH carrier may be non-standard). Continuing with commitment-only."
            else
                TX_R_TXID="$BROADCAST_RESULT_TXID"
                success "TX_R broadcast accepted/known: $TX_R_TXID"
            fi
        fi

        BROADCAST_TXID="$TX_C_TXID"
        # Always chain from TX_C change output (vout[0]) — this carries the
        # bulk of the funds.  TX_R is a separate reveal tx whose output is
        # too small to fund subsequent cascade stages.
        CHAINED_UTXO_TXID="$TX_C_TXID"
        CHAINED_UTXO_VOUT=0
        if [ "$CARRIER_ENABLED" -eq 1 ] && [ "${CARRIER_PART_TOTAL:-0}" -gt 0 ]; then
            # TX_C change = input - fee - (carrier_parts × carrier_value)
            CHAINED_UTXO_VALUE_KOINU=$((FUNDED_UTXO_VALUE_KOINU - TX_FEE_KOINU - CARRIER_PART_TOTAL * CARRIER_VALUE_KOINU))
        else
            # Commit-only: change = input - fee
            CHAINED_UTXO_VALUE_KOINU=$((FUNDED_UTXO_VALUE_KOINU - TX_FEE_KOINU))
        fi
        CHAINED_UTXO_SCRIPT_PUBKEY="$SCRIPT_PUBKEY"
        {
            echo "CHAINED_UTXO"
            echo "chained_utxo_txid=$CHAINED_UTXO_TXID"
            echo "chained_utxo_vout=$CHAINED_UTXO_VOUT"
            echo "chained_utxo_value_koinu=$CHAINED_UTXO_VALUE_KOINU"
            echo "chained_utxo_script_pubkey=$CHAINED_UTXO_SCRIPT_PUBKEY"
        } | tee -a "$RUN_LOG"
        BROADCASTED=1
    else
        error "Broadcast is required for full-run mode"
    fi

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_C_UNSIGNED=$TX_C_UNSIGNED
TX_C_SIGNED=$TX_C_SIGNED
TX_C_TXID=${TX_C_TXID:-}
TX_R_UNSIGNED=${TX_R_UNSIGNED:-}
TX_R_SIGNED=${TX_R_SIGNED:-}
TX_R_TXID=${TX_R_TXID:-}
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
RACCOONG_SIG=$RACCOONG_SIG
RACCOONG_COMMIT=$RACCOONG_COMMIT
CARRIER_ENABLED=$CARRIER_ENABLED
CARRIER_VALUE_KOINU=$CARRIER_VALUE_KOINU
CARRIER_PART_TOTAL=${CARRIER_PART_TOTAL:-0}
CARRIER_FIRST_VOUT=${CARRIER_FIRST_VOUT:-0}
CARRIER_SCRIPT_PUBKEY=${CARRIER_SCRIPT_PUBKEY:-}
SIGNED_TX=$TX_C_SIGNED
OPRETURN_SCRIPT=6a2452434734${RACCOONG_COMMIT}
CHAINED_UTXO_TXID=${CHAINED_UTXO_TXID:-}
CHAINED_UTXO_VOUT=${CHAINED_UTXO_VOUT:-0}
CHAINED_UTXO_VALUE_KOINU=${CHAINED_UTXO_VALUE_KOINU:-}
CHAINED_UTXO_SCRIPT_PUBKEY=${CHAINED_UTXO_SCRIPT_PUBKEY:-}
EOF
}

monitor_spvnode() {
    if [ "${SPV_REQUIRE_VALIDATION:-1}" -ne 1 ]; then
        info "Step 7: SPV validation SKIPPED (SPV_REQUIRE_VALIDATION=0)"
        return 0
    fi
    info "Step 7: Monitor with spvnode"
    echo "Expected log:"
    echo "  [raccoong-commit] Valid at height=X txpos=Y commit=$RACCOONG_COMMIT"
    if [ "$BROADCASTED" -eq 1 ]; then
        local scan_start_ts
        local found_ts
        local elapsed_seconds
        local spv_pipe_pid
        local spv_exit_code
        local commit_match_line=""
        local expected_commit_source="source=op_return_only"
        local expected_commit_mode="op_return_only"
        if [ "$CARRIER_ENABLED" -eq 1 ] && [ -n "${TX_R_TXID:-}" ]; then
            expected_commit_source="source=carrier_scriptsig"
            expected_commit_mode="carrier_scriptsig"
        fi
        rm -f "$SPV_WALLET_FILE"
        info "Running spvnode scan with REST monitoring until txid and ${expected_commit_mode} commitment validation are both confirmed..."
        scan_start_ts=$(date +%s)
        : > "$TMPDIR/spvnode.log"
        stdbuf -oL -eL ./spvnode $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -w "$SPV_WALLET_FILE" -u "$REST_SERVER" -c -d -x -p -b -a "$TESTNET_ADDR ${CARRIER_P2SH_WATCH_ADDR:-}" scan | tee "$TMPDIR/spvnode.log" | tee -a "$RUN_LOG" &
        spv_pipe_pid=$!
        if ! found_ts=$(wait_for_rest_tx "$BROADCAST_TXID" "$SPV_TIMEOUT_SECONDS"); then
            echo "----- spvnode log tail -----"
            tail -n 120 "$TMPDIR/spvnode.log"
            kill "$spv_pipe_pid" 2>/dev/null || true
            set +e
            wait "$spv_pipe_pid"
            set -e
            error "Timed out waiting for txid $BROADCAST_TXID in /getUTXOs"
        fi
        elapsed_seconds=$((found_ts - scan_start_ts))
        success "Broadcast txid observed via REST after ${elapsed_seconds}s (txid=$BROADCAST_TXID)"
        {
            echo "SPV_TIMING"
            echo "txid_seen_via_rest_at=${found_ts}"
            echo "scan_elapsed_seconds=${elapsed_seconds}"
            echo "broadcast_txid=${BROADCAST_TXID}"
        } | tee -a "$TMPDIR/spvnode.log"
        while true; do
            commit_match_line=$(grep -F "[raccoong-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$RACCOONG_COMMIT" | grep -F "$expected_commit_source" | tail -n1 || true)
            if [ -n "$commit_match_line" ]; then
                success "spvnode confirmed ${expected_commit_mode} Raccoon-G commitment validation for expected commit"
                echo "$commit_match_line" | tee -a "$TMPDIR/spvnode.log"
                # Check for reveal validation (PQC signature verification + TX_R)
                reveal_line=$(grep -F "[raccoong-commit] Reveal validated" "$TMPDIR/spvnode.log" | grep -F "commit=$RACCOONG_COMMIT" | tail -n1 || true)
                if [ -n "$reveal_line" ]; then
                    success "spvnode confirmed Raccoon-G reveal (TX_R) validated with PQC signature"
                    echo "$reveal_line" | tee -a "$TMPDIR/spvnode.log"
                else
                    sighash_line=$(grep -F "[raccoong-commit] PQC signature verification PASSED" "$TMPDIR/spvnode.log" | tail -n1 || true)
                    if [ -n "$sighash_line" ]; then
                        success "spvnode confirmed Raccoon-G PQC signature verification PASSED"
                        echo "$sighash_line" | tee -a "$TMPDIR/spvnode.log"
                    fi
                fi
                break
            fi
            if [ "$CARRIER_ENABLED" -eq 1 ] && [ -n "${TX_R_TXID:-}" ]; then
                op_return_only_line=$(grep -F "[raccoong-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$RACCOONG_COMMIT" | grep -F "source=op_return_only" | tail -n1 || true)
                if [ -n "$op_return_only_line" ]; then
                    info "TX_C OP_RETURN commitment found; waiting for TX_R carrier_scriptsig match in a later block..."
                fi
            fi
            if ! kill -0 "$spv_pipe_pid" 2>/dev/null; then
                set +e
                wait "$spv_pipe_pid"
                spv_exit_code=$?
                set -e
                echo "----- spvnode log tail -----"
                tail -n 80 "$TMPDIR/spvnode.log"
                error "spvnode exited before ${expected_commit_mode} Raccoon-G commitment validation was observed (exit=${spv_exit_code})"
            fi
            if [ $(( $(date +%s) - found_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
                echo "----- spvnode log tail -----"
                tail -n 120 "$TMPDIR/spvnode.log"
                kill "$spv_pipe_pid" 2>/dev/null || true
                set +e
                wait "$spv_pipe_pid"
                set -e
                error "Timed out waiting for ${expected_commit_mode} Raccoon-G commitment validation after txid detection"
            fi
            sleep 1
        done
        if kill -0 "$spv_pipe_pid" 2>/dev/null; then
            info "Stopping spvnode scan after relevant transaction detection..."
            kill "$spv_pipe_pid" 2>/dev/null || true
            set +e
            wait "$spv_pipe_pid"
            set -e
        fi
    else
        error "Transaction was not broadcast; cannot continue full-run validation flow"
    fi
}

verify_commitment() {
    info "Step 8: Off-chain verification"
    local VERIFY_PK="$RACCOONG_PK"
    local VERIFY_SIG="$RACCOONG_SIG"
    success "Using known Raccoon-G key/signature pair from canonical P2SH carrier step"

    VERIFY_OUTPUT=$(./such -c raccoong_verify -k "$VERIFY_PK" -x "$TX_SIGHASH_HEX" -s "$VERIFY_SIG")
    echo "$VERIFY_OUTPUT"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/raccoong_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
        error "Off-chain Raccoon-G signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c raccoong_commit -k "$VERIFY_PK" -s "$VERIFY_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/raccoong_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    [ -n "$REGENERATED_COMMIT" ] || error "Failed to parse regenerated Raccoon-G commitment"
    if [ "$REGENERATED_COMMIT" != "$RACCOONG_COMMIT" ]; then
        error "Regenerated commitment does not match expected commitment"
    fi
    success "Off-chain Raccoon-G verification and commitment match passed"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Raccoon-G-44 Mainnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    load_mainnet_wallet
    generate_raccoong_keypair
    derive_hd_child
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
}

main
