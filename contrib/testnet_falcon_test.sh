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
NETWORK="${NETWORK:-testnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR="/tmp/falcon_testnet_$$"
mkdir -m 700 -p "$TMPDIR"
BROADCASTED=0
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_FROM_HEIGHT="${SPV_FROM_HEIGHT:-0}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
# sendtx success must be explicit relay or explicit already-known acceptance.
RELAY_SUCCESS_PATTERN='tx successfully sent to node|already (broadcasted|known|have transaction)|txn-already-known'

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
    echo "----- ${label}: $* -----"
    "$@" 2>&1
    local rc=$?
    echo "----- ${label} exit=${rc} -----"
    return $rc
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if tools are available
check_tools() {
    info "Checking required tools..."
    
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    
    # Check if built with liboqs and tx_sighash helper
    if ! ./such -c help 2>&1 | grep -q falcon_keygen; then
        error "libdogecoin not built with liboqs support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        error "SPV_REQUIRE_VALIDATION must be 1 for full-run mode"
    fi
    
    success "All tools available"
}

# Step 1: Generate testnet wallet
generate_testnet_wallet() {
    info "Step 1: Generating testnet wallet..."

    if [ -n "$TESTNET_PRIVKEY_WIF" ]; then
        PRIVKEY_WIF="$TESTNET_PRIVKEY_WIF"
        echo "private key wif: $PRIVKEY_WIF" > "$TMPDIR/testnet_key.txt"
    else
        run_and_log "such generate_private_key" ./such -c generate_private_key $NETWORK_FLAG | tee "$TMPDIR/testnet_key.txt"
        PRIVKEY_WIF=$(grep "^private key wif:" "$TMPDIR/testnet_key.txt" | cut -d: -f2 | tr -d ' ')
    fi

    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/testnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    PUBKEY=$(grep "^public key hex:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    
    success "Testnet wallet generated"
    echo "  Address: $TESTNET_ADDR"
    echo "  Private Key (WIF): $PRIVKEY_WIF"
    echo "  Public Key: $PUBKEY"
    echo "  [FUNDING] Send ${NETWORK} DOGE to this address: $TESTNET_ADDR"
    
    # Save to file for later use
    cat > "$TMPDIR/wallet.txt" <<EOF
TESTNET_ADDR=$TESTNET_ADDR
PRIVKEY_WIF=$PRIVKEY_WIF
PUBKEY=$PUBKEY
EOF
}

# Step 2: Get testnet coins
get_testnet_coins() {
    info "Step 2: Getting testnet coins..."
    
    echo ""
    echo "=========================================="
    echo "  REQUEST TESTNET COINS"
    echo "=========================================="
    echo ""
    echo "Send ${NETWORK} DOGE to: $TESTNET_ADDR"
    echo "Wallet private key (WIF): $PRIVKEY_WIF"
    echo ""
    echo "Faucets:"
    echo "  1. https://faucet.doge.toys/"
    echo "  2. https://faucet.triangleplatform.com/dogecoin/testnet"
    echo "  3. https://dogecoin-faucet.ruan.dev/"
    echo "  4. Discord: Dogecoin community #testnet channel"
    echo "  5. Reddit: r/dogecoindev"
    echo ""
    echo "Note: some faucets require browser CAPTCHA or may rate-limit by IP."
    echo ""
    echo "[FAUCET] Preferred: https://faucet.doge.toys/"
    echo "[FAUCET] Request coins for address: $TESTNET_ADDR"
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        FAUCET_TXID="${FAUCET_TXID:-}"
        info "NON_INTERACTIVE=1, skipping funding prompt."
    else
        read -p "Optional faucet txid (for log): " FAUCET_TXID
        info "Press Enter after you have received coins..."
        read
    fi
    if [ -n "$FAUCET_TXID" ]; then
        echo "FAUCET_TXID=$FAUCET_TXID" > "$TMPDIR/faucet.txt"
    fi
    
    success "Assuming coins received. Continuing..."
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

    if [ -z "$RAW_UNSIGNED_TX" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        error "RAW_UNSIGNED_TX must be set in NON_INTERACTIVE mode"
    fi
    if [ -z "$RAW_UNSIGNED_TX" ]; then
        echo "Create an unsigned testnet transaction with such first:"
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
    echo "$SIGHASH_OUTPUT"
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

    ADD_COMMIT_OUTPUT=$(run_and_log "such falcon_add_commit_tx" ./such -c falcon_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$FALCON_COMMIT")
    echo "$ADD_COMMIT_OUTPUT"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$TX_WITH_COMMIT" ]; then
        echo "$ADD_COMMIT_OUTPUT"
        error "Failed to append Falcon commitment to transaction"
    fi

    TX_FOR_SIGNING="$TX_WITH_COMMIT"

    info "Signing transaction with commitment output..."
    SIGN_OUTPUT=$(run_and_log "such sign" ./such -c sign -x "$TX_FOR_SIGNING" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_OUTPUT"
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')

    if [ -z "$SIGNED_TX" ]; then
        echo "$SIGN_OUTPUT"
        error "Failed to sign transaction"
    fi

    success "Signed transaction with Falcon commitment ready"
    echo "  Signed TX: ${SIGNED_TX:0:80}..."
    echo ""
    DO_BROADCAST="n"
    if [ "$AUTO_BROADCAST" -eq 1 ]; then
        DO_BROADCAST="y"
    elif [ "$NON_INTERACTIVE" -eq 0 ]; then
        read -p "Broadcast now with sendtx? [y/N]: " DO_BROADCAST
    fi
    if [[ "$DO_BROADCAST" =~ ^[Yy]$ ]]; then
        SENDTX_OUTPUT=$(run_and_log "sendtx" ./sendtx $NETWORK_FLAG "$SIGNED_TX" || true)
        echo "$SENDTX_OUTPUT" | sed 's/Error:/sendtx-note:/g'
        if echo "$SENDTX_OUTPUT" | grep -Eqi "not relayed back|Seen on other nodes:[[:space:]]*0"; then
            error "sendtx reported non-relay (not relayed back / seen on other nodes: 0)"
        elif echo "$SENDTX_OUTPUT" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            success "Broadcast accepted or already known by peers"
            BROADCASTED=1
        else
            error "sendtx did not report a known relay/acceptance status"
        fi
    else
        error "Broadcast is required for full-run mode"
    fi

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_WITH_COMMIT=$TX_WITH_COMMIT
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
FALCON_SIG=$FALCON_SIG
FALCON_COMMIT=$FALCON_COMMIT
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a24464c4331${FALCON_COMMIT}
EOF
}

# Step 7: Monitor with SPV node
monitor_spvnode() {
    info "Step 7: Monitoring with SPV node..."
    
    echo ""
    echo "After broadcasting your transaction, monitor it with header-first sync:"
    echo ""
    echo "  # -l no prompt, -c continuous, -d debug, -x smpv, -p checkpoint, -a address"
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "Then switch to full block scan mode (or use -b directly):"
    echo ""
    echo "  ./spvnode $NETWORK_FLAG -l -c -d -x -p -b -a \"$TESTNET_ADDR\" scan"
    echo ""
    echo "The SPV node will:"
    echo "  - Sync testnet blockchain headers"
    echo "  - Track wallet activity for: $TESTNET_ADDR"
    echo "  - Download and scan blocks in full mode"
    echo "  - Detect Falcon commitments"
    echo "  - Log: [falcon-commit] Valid at height=X txpos=Y commit=$FALCON_COMMIT"
    echo ""
    
    info "SPV sync may take time. Be patient!"
    if [ "$BROADCASTED" -eq 1 ]; then
        info "Running spvnode scan (timeout ${SPV_TIMEOUT_SECONDS}s) and requiring Falcon validation log before next step..."
        set +e
        run_and_log "spvnode scan" timeout "$SPV_TIMEOUT_SECONDS" ./spvnode $NETWORK_FLAG -l -f "$SPV_FROM_HEIGHT" -c -d -x -p -b -a "$TESTNET_ADDR" scan > "$TMPDIR/spvnode.log" 2>&1
        SPV_EXIT=$?
        set -e
        cat "$TMPDIR/spvnode.log"
        if ! grep -Fq "[falcon-commit] Valid" "$TMPDIR/spvnode.log"; then
            echo "----- spvnode log tail -----"
            tail -n 80 "$TMPDIR/spvnode.log"
            if [ "$SPV_EXIT" -eq 124 ]; then
                error "spvnode timed out before Falcon commitment validation was observed"
            else
                error "Falcon commitment was not validated by spvnode before proceeding"
            fi
        else
            success "spvnode confirmed Falcon commitment validation"
        fi
    else
        error "Transaction was not broadcast; cannot continue full-run validation flow"
    fi
}

# Step 8: Verify commitment off-chain
verify_commitment() {
    info "Step 8: Verifying commitment off-chain..."
    local VERIFY_PK="$FALCON_PK"
    local VERIFY_SIG="$FALCON_SIG"

    VERIFY_OUTPUT=$(./such -c falcon_verify -k "$VERIFY_PK" -x "$TX_SIGHASH_HEX" -s "$VERIFY_SIG")
    echo "$VERIFY_OUTPUT"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/falcon_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid"; then
        echo "$VERIFY_OUTPUT"
        error "Off-chain Falcon signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c falcon_commit -k "$VERIFY_PK" -s "$VERIFY_SIG")
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
}

# Main workflow
main() {
    echo ""
    echo "=========================================="
    echo "  Falcon-512 Testnet Integration Test"
    echo "=========================================="
    echo ""
    
    check_tools
    generate_testnet_wallet
    get_testnet_coins
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
    echo "  - $TMPDIR/wallet.txt (testnet wallet)"
    echo "  - $TMPDIR/falcon_keys.txt (Falcon keypair)"
    echo "  - $TMPDIR/falcon_sig.txt (tx_sighash signature)"
    echo "  - $TMPDIR/falcon_commit.txt (tx-bound commitment)"
    echo "  - $TMPDIR/tx_info.txt (transaction info)"
    echo "  - $TMPDIR/spvnode.log (SPV validation log)"
    echo "  - $TMPDIR/falcon_verify.txt (off-chain verify result)"
    echo ""
}

# Run main workflow
main
