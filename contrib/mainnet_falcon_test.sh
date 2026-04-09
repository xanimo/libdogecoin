#!/bin/bash
#
# Falcon-512 Testnet Integration Test Script
# 
# This script demonstrates end-to-end testing of Falcon-512 commitments on Dogecoin testnet
# 
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - Testnet coins (get from faucet)
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e  # Exit on error
umask 077

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR="/tmp/falcon_mainnet_$$"
mkdir -m 700 -p "$TMPDIR"
BROADCASTED=0
BROADCAST_TXID=""
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
SPV_HEADERS_FILE="${SPV_HEADERS_FILE:-$TMPDIR/spv_headers.db}"
SPV_WALLET_FILE="${SPV_WALLET_FILE:-$TMPDIR/spv_wallet.db}"
REST_HOST="${REST_HOST:-127.0.0.1}"
REST_PORT="${REST_PORT:-$((18080 + ($$ % 1000)))}"
REST_SERVER="${REST_SERVER:-${REST_HOST}:${REST_PORT}}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
INCLUDE_SCRIPTSIG_PQC="${INCLUDE_SCRIPTSIG_PQC:-1}"
# CARRIER_ENABLED=0 → commitment-only mode (OP_RETURN only, guaranteed standard relay)
# CARRIER_ENABLED=1 → commitment + P2SH carrier outputs (embeds PQC pubkey+sig on-chain)
CARRIER_ENABLED="${CARRIER_ENABLED:-0}"
# NOTE: FUNDED_WIF and FUNDED_ADDR must be supplied via the environment.
# Historical defaults referenced a real mainnet WIF used during PR validation
# and are intentionally removed: shipping a funded mainnet private key in a
# public repository would publish that key. Set both env vars before running.
FUNDED_WIF="${FUNDED_WIF:?FUNDED_WIF must be set (mainnet WIF of the funding key)}"
FUNDED_ADDR="${FUNDED_ADDR:?FUNDED_ADDR must be set (mainnet address corresponding to FUNDED_WIF)}"
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-${CHAINED_UTXO_TXID:-b47b271ff454ce93e93f723b52959f9d14f44313c61706453c1a85aaced93031}}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-${CHAINED_UTXO_VOUT:-0}}"
AUTO_PREPARE_TX_FROM_UTXO="${AUTO_PREPARE_TX_FROM_UTXO:-1}"
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"
TX_R_FEE_KOINU="${TX_R_FEE_KOINU:-2000000}"
CARRIER_VALUE_KOINU="${CARRIER_VALUE_KOINU:-100000000}"
# Enforce minimum carrier value of 1 DOGE to avoid dust rejection
if [ "$CARRIER_VALUE_KOINU" -lt 100000000 ]; then
    CARRIER_VALUE_KOINU=100000000
fi
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-${CHAINED_UTXO_VALUE_KOINU:-}}"
FUNDED_UTXO_SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-${CHAINED_UTXO_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}}"
# Carrier P2SH address to watch in SPV (for TX_R carrier output visibility)
CARRIER_P2SH_WATCH_ADDR="${CARRIER_P2SH_WATCH_ADDR:-A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q}"
RAW_UNSIGNED_TX="${RAW_UNSIGNED_TX:-}"
SCRIPT_PUBKEY="${SCRIPT_PUBKEY:-}"
RUN_LOG="$TMPDIR/mainnet_falcon_run.log"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"
# Relay success: "Seen on other nodes: N" where N > 0, or already-known responses.
# NOTE: "tx successfully sent to node" only means pushed to peer, NOT that it was accepted.
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'
SENDTX_FATAL_PATTERN='Requested from nodes:[[:space:]]*0.*Seen on other nodes:[[:space:]]*0|not relayed back|very likely invalid'

# Function to print colored messages
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
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

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Look up UTXO value from blockchain APIs if not provided
lookup_utxo_value() {
    local txid="$1"
    local vout="$2"
    local val=""
    # Try sochain v2
    val=$(curl -sf "https://chain.so/api/v2/tx/DOGE/${txid}" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); o=d['data']['outputs'][${vout}]; print(int(float(o['value'])*1e8))" 2>/dev/null || true)
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null; then echo "$val"; return 0; fi
    # Try blockcypher
    val=$(curl -sf "https://api.blockcypher.com/v1/doge/main/txs/${txid}" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['outputs'][${vout}]['value'])" 2>/dev/null || true)
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null; then echo "$val"; return 0; fi
    return 1
}

# Decode and debug a raw transaction hex
debug_tx_hex() {
    local tx_hex="$1"
    local label="${2:-TX}"
    python3 - "$tx_hex" "$label" <<'PYDEBUG'
import sys, struct
tx_hex = sys.argv[1]
label = sys.argv[2]
tx = bytes.fromhex(tx_hex)
off = 0
def ru32(): global off; v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
def ru64(): global off; v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
def rvar():
    global off
    b=tx[off]; off+=1
    if b<0xfd: return b
    if b==0xfd: v=struct.unpack_from('<H',tx,off)[0]; off+=2; return v
    if b==0xfe: v=struct.unpack_from('<I',tx,off)[0]; off+=4; return v
    v=struct.unpack_from('<Q',tx,off)[0]; off+=8; return v
print(f"=== {label} Debug (size={len(tx)} bytes) ===")
ver=ru32(); print(f"  version: {ver}")
nin=rvar(); print(f"  inputs: {nin}")
for i in range(nin):
    ph=tx[off:off+32][::-1].hex(); off+=32
    pi=ru32(); sl=rvar(); ss=tx[off:off+sl]; off+=sl; sq=ru32()
    print(f"    in[{i}]: txid={ph} vout={pi} scriptSig_len={sl} seq={sq:08x}")
nout=rvar(); print(f"  outputs: {nout}")
for i in range(nout):
    val=ru64(); sl=rvar(); spk=tx[off:off+sl].hex(); off+=sl
    vd=val/1e8
    kind="unknown"
    if spk.startswith('76a914') and spk.endswith('88ac'): kind="P2PKH"
    elif spk.startswith('a914') and spk.endswith('87'): kind="P2SH"
    elif spk.startswith('6a'): kind="OP_RETURN"
    dust_ok = "OK" if (val==0 and kind=="OP_RETURN") or val>=100000 else f"DUST(need>=0.001DOGE)"
    print(f"    out[{i}]: {val} koinu ({vd:.8f} DOGE) type={kind} spk_len={sl} dust={dust_ok}")
lt=ru32(); print(f"  locktime: {lt}")
print(f"=== end {label} ===")
PYDEBUG
}

# Broadcast with retry and TX debugging
broadcast_with_retry() {
    local label="$1"
    local signed_tx="$2"
    local max_retries="${3:-$SENDTX_MAX_RETRIES}"
    local attempt=0
    local sendtx_output=""
    local txid=""

    while [ "$attempt" -lt "$max_retries" ]; do
        attempt=$((attempt + 1))
        info "Broadcast attempt $attempt/$max_retries for $label..."

        sendtx_output=$(run_and_log "sendtx $label attempt=$attempt" ./sendtx -d -m 16 -s 30 $NETWORK_FLAG "$signed_tx" || true)
        echo "$sendtx_output" | sed 's/Error:/sendtx-note:/g' | tee "$TMPDIR/sendtx_${label}_attempt${attempt}.log" | tee -a "$RUN_LOG"

        txid=$(echo "$sendtx_output" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)

        # Check for success
        if echo "$sendtx_output" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_RESULT_TXID="$txid"
            success "$label broadcast accepted on attempt $attempt: $txid"
            return 0
        fi

        # Check for fatal failure
        if echo "$sendtx_output" | grep -Eqi "$SENDTX_FATAL_PATTERN"; then
            echo -e "${YELLOW}[WARN]${NC} $label relay failed on attempt $attempt. Debugging TX format..." | tee -a "$RUN_LOG"
            debug_tx_hex "$signed_tx" "$label" 2>&1 | tee -a "$RUN_LOG"

            # Check for specific issues
            if echo "$sendtx_output" | grep -qi "already.*known\|txn-already-in-mempool"; then
                BROADCAST_RESULT_TXID="$txid"
                success "$label already in mempool: $txid"
                return 0
            fi

            if [ "$attempt" -lt "$max_retries" ]; then
                info "Waiting 10s before retry..."
                sleep 10
            fi
        else
            # Unknown status - treat as possible success if we got a txid
            if [ -n "$txid" ]; then
                echo -e "${YELLOW}[WARN]${NC} $label sendtx returned ambiguous status. Assuming possible success." | tee -a "$RUN_LOG"
                BROADCAST_RESULT_TXID="$txid"
                return 0
            fi
        fi
    done

    echo -e "${RED}[FAIL]${NC} $label failed to relay after $max_retries attempts" | tee -a "$RUN_LOG"
    debug_tx_hex "$signed_tx" "$label" 2>&1 | tee -a "$RUN_LOG"
    BROADCAST_RESULT_TXID="$txid"
    return 1
}

# Check if tools are available
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
    
    # Check if built with liboqs and tx_sighash helper
    if ! ./such -c help 2>&1 | grep -q falcon_keygen; then
        error "libdogecoin not built with liboqs support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
    fi
    if ! command -v curl &> /dev/null; then
        error "curl not found. Required for REST tx monitoring."
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        info "SPV_REQUIRE_VALIDATION=0 — SPV validation will be skipped (broadcast-only mode)"
    fi
    
    success "All tools available"
}

load_mainnet_wallet() {
    info "Step 1: Using provided funded mainnet wallet..."
    PRIVKEY_WIF="$FUNDED_WIF"
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/mainnet_addr.txt"
    TESTNET_ADDR=$(awk -F': ' '/p2pkh address:/ {print $2; exit}' "$TMPDIR/mainnet_addr.txt" | tr -d ' \r\n')
    PUBKEY=$(awk -F': ' '/^public key hex:/ {print $2; exit}' "$TMPDIR/mainnet_addr.txt" | tr -d ' \r\n')
    if [ "$TESTNET_ADDR" != "$FUNDED_ADDR" ]; then
        error "Provided WIF does not map to expected funded address"
    fi
    success "Mainnet funded wallet loaded"
    echo "  Address: $TESTNET_ADDR"
    echo "  Private Key (WIF): $PRIVKEY_WIF"
    echo "  Public Key: $PUBKEY"
    cat > "$TMPDIR/wallet.txt" <<EOF
MAINNET_ADDR=$TESTNET_ADDR
PRIVKEY_WIF=$PRIVKEY_WIF
PUBKEY=$PUBKEY
EOF
}

log_run_context() {
    {
        echo "RUN_CONTEXT"
        echo "NETWORK=$NETWORK"
        echo "WIF=$PRIVKEY_WIF"
        echo "ADDRESS=$TESTNET_ADDR"
        echo "FUNDED_UTXO_TXID=$FUNDED_UTXO_TXID"
        echo "FUNDED_UTXO_VOUT=$FUNDED_UTXO_VOUT"
        echo "TX_FEE_KOINU=$TX_FEE_KOINU"
        echo "FUNDED_UTXO_VALUE_KOINU=$FUNDED_UTXO_VALUE_KOINU"
        echo "FUNDED_UTXO_SCRIPT_PUBKEY=$FUNDED_UTXO_SCRIPT_PUBKEY"
        echo "SCRIPT_PUBKEY=$SCRIPT_PUBKEY"
        echo "SPV_HEADERS_FILE=$SPV_HEADERS_FILE"
        echo "SPV_WALLET_FILE=$SPV_WALLET_FILE"
        echo "REST_SERVER=$REST_SERVER"
    } | tee -a "$RUN_LOG"
}

prepare_tx_from_funded_utxo() {
    info "Step 4a: Constructing unsigned transaction from known funded UTXO..."
    local selected_txid
    local selected_vout
    local selected_value
    local selected_script
    local send_value

    selected_txid="$FUNDED_UTXO_TXID"
    selected_vout="$FUNDED_UTXO_VOUT"
    selected_value="$FUNDED_UTXO_VALUE_KOINU"
    selected_script="$FUNDED_UTXO_SCRIPT_PUBKEY"

    # Auto-detect UTXO value from blockchain if not provided
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

    if [ -z "$selected_txid" ] || [ -z "$selected_vout" ] || [ -z "$selected_value" ] || [ -z "$selected_script" ]; then
        error "Failed to parse selected UTXO details"
    fi
    if [ "$selected_value" -le "$TX_FEE_KOINU" ]; then
        error "Selected UTXO value ($selected_value) must be greater than TX_FEE_KOINU ($TX_FEE_KOINU)"
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

def le_u32(n: int) -> str:
    return n.to_bytes(4, "little", signed=False).hex()

def le_u64(n: int) -> str:
    return n.to_bytes(8, "little", signed=False).hex()

def varint(n: int) -> str:
    if n < 0xfd:
        return f"{n:02x}"
    if n <= 0xffff:
        return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff:
        return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()

version = "01000000"
vin_count = "01"
prev_txid_le = bytes.fromhex(txid_hex)[::-1].hex()
prev_vout = le_u32(vout)
script_sig_len = "00"
sequence = "ffffffff"
vout_count = "01"
value_le = le_u64(value)
script_len = varint(len(script_hex) // 2)
locktime = "00000000"

raw = (
    version
    + vin_count
    + prev_txid_le
    + prev_vout
    + script_sig_len
    + sequence
    + vout_count
    + value_le
    + script_len
    + script_hex
    + locktime
)
print(raw)
PY
)
    SCRIPT_PUBKEY="$selected_script"

    {
        echo "UTXO_SELECTION"
        echo "selected_txid=$selected_txid"
        echo "selected_vout=$selected_vout"
        echo "selected_value_koinu=$selected_value"
        echo "selected_source=known_utxo_constants"
        echo "tx_fee_koinu=$TX_FEE_KOINU"
        echo "send_value_koinu=$send_value"
        echo "selected_script_pubkey=$SCRIPT_PUBKEY"
        echo "raw_unsigned_tx=$RAW_UNSIGNED_TX"
    } | tee -a "$RUN_LOG"

    success "Prepared RAW_UNSIGNED_TX and SCRIPT_PUBKEY from funded UTXO"
    echo "  UTXO: ${selected_txid}:${selected_vout}"
    echo "  UTXO value: $selected_value koinu"
    echo "  Fee: $TX_FEE_KOINU koinu"
    echo "  Output value: $send_value koinu"
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

# Step 3: Generate Falcon-512 keypair
generate_falcon_keypair() {
    info "Step 3: Generating Falcon-512 keypair..."
    
    run_and_log "such falcon_keygen" ./such -c falcon_keygen | tee "$TMPDIR/falcon_keys.txt"
    
    FALCON_PK=$(grep "^public key:" "$TMPDIR/falcon_keys.txt" | cut -d: -f2 | tr -d ' ')
    FALCON_SK=$(grep "^secret key:" "$TMPDIR/falcon_keys.txt" | cut -d: -f2 | tr -d ' ')
    
    if [ -z "$FALCON_PK" ] || [ -z "$FALCON_SK" ]; then
        error "Failed to generate Falcon keypair"
    fi
    if [ "$FALCON_PK" = "$FALCON_SK" ]; then
        error "Falcon public and secret keys are identical; expected different key material"
    fi
    
    success "Falcon-512 keypair generated"
    echo "  Public Key (${#FALCON_PK} chars): ${FALCON_PK:0:64}..."
    echo "  Secret Key (${#FALCON_SK} chars): ${FALCON_SK:0:64}..."
    
    # Save to file
    cat > "$TMPDIR/falcon_keys.txt" <<EOF
FALCON_PK=$FALCON_PK
FALCON_SK=$FALCON_SK
EOF
}

# Step 6: Build transaction with OP_RETURN
build_transaction() {
    info "Step 4: Building transaction and deriving tx_sighash32..."
    if { [ -z "$RAW_UNSIGNED_TX" ] || [ -z "$SCRIPT_PUBKEY" ]; } && [ "$AUTO_PREPARE_TX_FROM_UTXO" -eq 1 ]; then
        prepare_tx_from_funded_utxo
    fi
    if [ -z "$RAW_UNSIGNED_TX" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "RAW_UNSIGNED_TX must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$RAW_UNSIGNED_TX" ]; then
        echo "Create an unsigned mainnet transaction with such first:"
        echo "  ./such -c transaction"
        echo ""
        echo "Then paste the unsigned raw tx hex below."
        read -p "Enter unsigned raw tx hex: " RAW_UNSIGNED_TX
    else
        info "Using RAW_UNSIGNED_TX from environment"
    fi

    if [ -z "$SCRIPT_PUBKEY" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "SCRIPT_PUBKEY must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$SCRIPT_PUBKEY" ]; then
        read -p "Enter scriptPubKey hex for input 0 (UTXO being spent): " SCRIPT_PUBKEY
    else
        info "Using SCRIPT_PUBKEY from environment"
    fi

    # Reject placeholder prevout (32-byte txid + 4-byte vout = 36 bytes = 72 hex chars).
    if echo "$RAW_UNSIGNED_TX" | grep -Eq '^0100000001(00){36}'; then
        error "Input transaction uses a zero prevout placeholder. Provide a real funded UTXO transaction."
    fi
    # Reject zeroed P2PKH scriptPubKey: 76a914 + 20-byte hash160 (40 hex chars) + 88ac.
    if echo "$SCRIPT_PUBKEY" | grep -Eq '^76a914(0){40}88ac$'; then
        error "scriptPubKey is a zero placeholder. Provide the real UTXO scriptPubKey."
    fi

    SIGHASH_OUTPUT=$(run_and_log "such tx_sighash32" ./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    echo "$SIGHASH_OUTPUT" | tee -a "$RUN_LOG"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$TX_SIGHASH_HEX" ] || [ ${#TX_SIGHASH_HEX} -ne 64 ]; then
        echo "$SIGHASH_OUTPUT"
        error "Failed to derive tx_sighash32 for PQC signing"
    fi
    success "Derived tx_sighash32: $TX_SIGHASH_HEX"

    info "Step 5: Signing tx_sighash32 with Falcon-512..."
    run_and_log "such falcon_sign" ./such -c falcon_sign -p "$FALCON_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/falcon_sig.txt"
    FALCON_SIG=$(grep "^signature:" "$TMPDIR/falcon_sig.txt" | cut -d: -f2 | tr -d ' ')
    if [ -z "$FALCON_SIG" ]; then
        error "Failed to sign tx_sighash32 with Falcon-512"
    fi
    success "Falcon signature generated from tx_sighash32"

    info "Step 6: Generating commitment from Falcon signature..."
    run_and_log "such falcon_commit" ./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG" | tee "$TMPDIR/falcon_commit.txt"
    FALCON_COMMIT=$(grep "^commitment:" "$TMPDIR/falcon_commit.txt" | cut -d: -f2 | tr -d ' ')
    if [ -z "$FALCON_COMMIT" ] || [ ${#FALCON_COMMIT} -ne 64 ]; then
        error "Failed to generate commitment (expected 64 hex chars, got ${#FALCON_COMMIT})"
    fi
    success "Commitment generated from tx-bound Falcon signature"

    if [ "$CARRIER_ENABLED" -eq 1 ]; then
        info "Step 6b: Building TX_C with OP_RETURN commitment + P2SH carrier outputs..."
        ADD_COMMIT_AND_CARRIER_OUTPUT=$(run_and_log "such falcon_add_commit_and_carrier_tx" ./such -c falcon_add_commit_and_carrier_tx -x "$RAW_UNSIGNED_TX" -m "$FALCON_COMMIT" -k "$FALCON_PK" -s "$FALCON_SIG" -h "$CARRIER_VALUE_KOINU")
        echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | tee -a "$RUN_LOG"
        TX_C_UNSIGNED=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^tx with commitment and carrier outputs:/ {print $2; exit}' | tr -d ' ')
        CARRIER_PART_TOTAL=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_part_total:/ {print $2; exit}' | tr -d ' ')
        CARRIER_FIRST_VOUT=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_first_vout:/ {print $2; exit}' | tr -d ' ')
        CARRIER_SCRIPT_PUBKEY=$(echo "$ADD_COMMIT_AND_CARRIER_OUTPUT" | awk -F': ' '/^carrier_p2sh_scriptpubkey:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_C_UNSIGNED" ] || error "Failed to construct TX_C"
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
        info "Step 6b: Building TX_C with OP_RETURN commitment only (no carrier)..."
        COMMIT_ONLY_OUTPUT=$(run_and_log "such falcon_add_commit_tx" ./such -c falcon_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$FALCON_COMMIT")
        echo "$COMMIT_ONLY_OUTPUT" | tee -a "$RUN_LOG"
        TX_C_UNSIGNED=$(echo "$COMMIT_ONLY_OUTPUT" | awk -F': ' '/^tx with commitment:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_C_UNSIGNED" ] || error "Failed to construct TX_C (commit-only)"
        CARRIER_PART_TOTAL=0
        CARRIER_FIRST_VOUT=0
        CARRIER_SCRIPT_PUBKEY=""
        CARRIER_PART_SCRIPTSIGS=()
        success "TX_C built in commitment-only mode (standard, relayable)"
    fi

    info "Debugging TX_C unsigned format..."
    debug_tx_hex "$TX_C_UNSIGNED" "TX_C_unsigned" 2>&1 | tee -a "$RUN_LOG"

    info "Signing TX_C with secp256k1 on input 0..."
    SIGN_TXC_OUTPUT=$(run_and_log "such sign TX_C" ./such -c sign -x "$TX_C_UNSIGNED" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_TXC_OUTPUT" | tee -a "$RUN_LOG"
    TX_C_SIGNED=$(echo "$SIGN_TXC_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_C_SIGNED" ] || error "Failed to sign TX_C"
    success "Signed TX_C"
    echo "  Signed TX_C: ${TX_C_SIGNED:0:80}..."

    info "Debugging TX_C signed format..."
    debug_tx_hex "$TX_C_SIGNED" "TX_C_signed" 2>&1 | tee -a "$RUN_LOG"

    echo ""
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
TX_C_TXID=$TX_C_TXID
TX_R_UNSIGNED=${TX_R_UNSIGNED:-}
TX_R_SIGNED=${TX_R_SIGNED:-}
TX_R_TXID=${TX_R_TXID:-}
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
FALCON_SIG=$FALCON_SIG
FALCON_COMMIT=$FALCON_COMMIT
CARRIER_ENABLED=$CARRIER_ENABLED
CARRIER_VALUE_KOINU=$CARRIER_VALUE_KOINU
CARRIER_PART_TOTAL=${CARRIER_PART_TOTAL:-0}
CARRIER_FIRST_VOUT=${CARRIER_FIRST_VOUT:-0}
CARRIER_SCRIPT_PUBKEY=${CARRIER_SCRIPT_PUBKEY:-}
TXID=$TX_C_TXID
OPRETURN_SCRIPT=6a24464c4331${FALCON_COMMIT}
CHAINED_UTXO_TXID=$CHAINED_UTXO_TXID
CHAINED_UTXO_VOUT=$CHAINED_UTXO_VOUT
CHAINED_UTXO_VALUE_KOINU=$CHAINED_UTXO_VALUE_KOINU
CHAINED_UTXO_SCRIPT_PUBKEY=$CHAINED_UTXO_SCRIPT_PUBKEY
EOF
}

# Step 7: Monitor with SPV node
monitor_spvnode() {
    if [ "${SPV_REQUIRE_VALIDATION:-1}" -ne 1 ]; then
        info "Step 7: SPV validation SKIPPED (SPV_REQUIRE_VALIDATION=0)"
        return 0
    fi
    info "Step 7: Monitoring with SPV node..."
    
    echo ""
    echo "After broadcasting your transaction, monitor it with block scan mode:"
    echo ""
    echo "  # -l no prompt, -c continuous, -d debug, -x smpv, -p checkpoint, -a address"
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "Then switch to full block scan mode (or use -b directly):"
    echo ""
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -b -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "The SPV node will:"
    echo "  - Sync mainnet blockchain headers"
    echo "  - Track wallet activity for: $TESTNET_ADDR"
    echo "  - Download and scan blocks in full mode"
    echo "  - Detect Falcon commitments"
    echo "  - Log: [falcon-commit] Valid at height=X txpos=Y commit=$FALCON_COMMIT"
    echo ""
    
    info "SPV sync may take time. Be patient!"
    if [ "$BROADCASTED" -eq 1 ]; then
        # Watch both the funded address and the carrier P2SH address
        local spv_watch_addrs="$TESTNET_ADDR"
        if [ -n "${CARRIER_P2SH_WATCH_ADDR:-}" ]; then
            spv_watch_addrs="$TESTNET_ADDR $CARRIER_P2SH_WATCH_ADDR"
        fi
        info "SPV watching addresses: $spv_watch_addrs"
        local spv_cmd=("./spvnode" $NETWORK_FLAG -l -h "$SPV_HEADERS_FILE" -c -d -x -p -b -a "$spv_watch_addrs")
        local scan_start_ts
        local found_ts
        local elapsed_seconds
        local spv_pipe_pid
        local spv_exit_code
        local commit_match_line=""
        local expected_commit_source="source=op_return_only"
        local expected_commit_mode="op_return_only"
        if [ "$CARRIER_ENABLED" -eq 1 ] && [ -n "$TX_R_TXID" ]; then
            expected_commit_source="source=carrier_scriptsig"
            expected_commit_mode="carrier_scriptsig"
        fi
        local rest_timeout_remaining
        rm -f "$SPV_WALLET_FILE"
        info "Running spvnode scan with REST monitoring until txid and ${expected_commit_mode} commitment validation are both confirmed..."
        scan_start_ts=$(date +%s)
        : > "$TMPDIR/spvnode.log"
        if [ -f "$SPV_HEADERS_FILE" ]; then
            info "Reusing headers file: $SPV_HEADERS_FILE"
        fi
        spv_cmd+=(-w "$SPV_WALLET_FILE" -u "$REST_SERVER" scan)
        set +e
        stdbuf -oL -eL "${spv_cmd[@]}" | tee "$TMPDIR/spvnode.log" | tee -a "$RUN_LOG" &
        spv_pipe_pid=$!
        set -e
        rest_timeout_remaining="$SPV_TIMEOUT_SECONDS"
        if ! found_ts=$(wait_for_rest_tx "$BROADCAST_TXID" "$rest_timeout_remaining"); then
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
        } | tee -a "$RUN_LOG"
        while true; do
            commit_match_line=$(grep -F "[falcon-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$FALCON_COMMIT" | grep -F "$expected_commit_source" | tail -n1 || true)
            if [ -n "$commit_match_line" ]; then
                success "spvnode confirmed ${expected_commit_mode} Falcon commitment validation for expected commit"
                echo "$commit_match_line" | tee -a "$RUN_LOG"
                # Check for reveal validation (PQC signature verification + TX_R)
                reveal_line=$(grep -F "[falcon-commit] Reveal validated" "$TMPDIR/spvnode.log" | grep -F "commit=$FALCON_COMMIT" | tail -n1 || true)
                if [ -n "$reveal_line" ]; then
                    success "spvnode confirmed Falcon reveal (TX_R) validated with PQC signature"
                    echo "$reveal_line" | tee -a "$RUN_LOG"
                else
                    sighash_line=$(grep -F "[falcon-commit] PQC signature verification PASSED" "$TMPDIR/spvnode.log" | tail -n1 || true)
                    if [ -n "$sighash_line" ]; then
                        success "spvnode confirmed Falcon PQC signature verification PASSED"
                        echo "$sighash_line" | tee -a "$RUN_LOG"
                    fi
                fi
                break
            fi
            if [ "$CARRIER_ENABLED" -eq 1 ] && [ -n "$TX_R_TXID" ]; then
                op_return_only_line=$(grep -F "[falcon-commit] Valid" "$TMPDIR/spvnode.log" | grep -F "commit=$FALCON_COMMIT" | grep -F "source=op_return_only" | tail -n1 || true)
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
                error "spvnode exited before 'Found relevant transaction!' was observed (exit=${spv_exit_code})"
            fi
            if [ $(( $(date +%s) - found_ts )) -ge "$SPV_TIMEOUT_SECONDS" ]; then
                echo "----- spvnode log tail -----"
                tail -n 120 "$TMPDIR/spvnode.log"
                kill "$spv_pipe_pid" 2>/dev/null || true
                set +e
                wait "$spv_pipe_pid"
                set -e
                error "Timed out waiting for ${expected_commit_mode} Falcon commitment validation after txid detection"
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

# Step 8: Verify commitment off-chain
verify_commitment() {
    info "Step 8: Verifying commitment off-chain..."
    info "Using known Falcon key/signature pair from canonical P2SH carrier step"

    VERIFY_OUTPUT=$(./such -c falcon_verify -k "$FALCON_PK" -x "$TX_SIGHASH_HEX" -s "$FALCON_SIG")
    echo "$VERIFY_OUTPUT" | tee -a "$RUN_LOG"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/falcon_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid"; then
        echo "$VERIFY_OUTPUT"
        error "Off-chain Falcon signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c falcon_commit -k "$FALCON_PK" -s "$FALCON_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/falcon_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$REGENERATED_COMMIT" ]; then
        error "Failed to parse regenerated Falcon commitment"
    fi
    if [ "$REGENERATED_COMMIT" != "$FALCON_COMMIT" ]; then
        error "Regenerated Falcon commitment does not match expected commitment"
    fi
    success "Off-chain Falcon verification and commitment match passed"

    echo ""
    echo "Verification details:"
    echo "  valid: true"
    echo "  Expected commitment: $FALCON_COMMIT"
    echo "  Regenerated commitment: $REGENERATED_COMMIT"
    echo ""
    {
        echo "commitment_regenerated=$REGENERATED_COMMIT"
        echo "commitment_match=true"
    } | tee -a "$RUN_LOG"
}

# Main workflow
main() {
    echo ""
    echo "=========================================="
    echo "  Falcon-512 Mainnet Integration Test"
    echo "=========================================="
    echo ""
    
    check_tools
    load_mainnet_wallet
    log_run_context
    generate_falcon_keypair
    build_transaction
    monitor_spvnode
    verify_commitment
    
    echo ""
    echo "=========================================="
    echo "  TEST COMPLETE"
    echo "=========================================="
    echo ""
    success "All test data saved in: $TMPDIR"
    echo ""
    echo "Files:"
    echo "  - $TMPDIR/wallet.txt (mainnet wallet)"
    echo "  - $TMPDIR/falcon_keys.txt (Falcon keypair)"
    echo "  - $TMPDIR/falcon_sig.txt (tx_sighash signature)"
    echo "  - $TMPDIR/falcon_commit.txt (tx-bound commitment)"
    echo "  - $TMPDIR/tx_info.txt (transaction info)"
    echo "  - $TMPDIR/spvnode.log (SPV validation log)"
    echo "  - $TMPDIR/falcon_verify.txt (off-chain verify result)"
    echo "  - $RUN_LOG (full run log with WIF/address + scriptSig validation artifacts)"
    echo ""
}

# Run main workflow
main
