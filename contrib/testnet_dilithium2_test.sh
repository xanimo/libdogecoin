#!/bin/bash
#
# Dilithium2 Testnet Integration Test Script
#
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NETWORK="${NETWORK:-testnet}"
NETWORK_FLAG="-t"
if [ "$NETWORK" = "mainnet" ]; then
    NETWORK_FLAG=""
elif [ "$NETWORK" != "testnet" ]; then
    echo "Unsupported NETWORK value: $NETWORK (expected testnet|mainnet)" >&2
    exit 1
fi
TMPDIR=$(mktemp -d /tmp/dilithium2_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_FROM_HEIGHT="${SPV_FROM_HEIGHT:-0}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
SPV_NO_BROADCAST_TIMEOUT="${SPV_NO_BROADCAST_TIMEOUT:-30}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
# sendtx can report success either as immediate relay or as "already known".
RELAY_SUCCESS_PATTERN='tx successfully sent to node|already (broadcasted|known|have transaction)|txn-already-known'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
run_and_log() {
    local label="$1"
    shift
    echo "----- ${label}: $* -----"
    "$@" 2>&1
    local rc=$?
    echo "----- ${label} exit=${rc} -----"
    return $rc
}

check_tools() {
    info "Checking required tools..."
    for tool in such sendtx spvnode; do
        if [ ! -f "./$tool" ] && ! command -v $tool &> /dev/null; then
            error "$tool not found. Please build libdogecoin first."
        fi
    done
    if ! ./such -c help 2>&1 | grep -q dilithium2_keygen; then
        error "libdogecoin not built with Dilithium2 support. Rebuild with --enable-liboqs"
    fi
    if ! ./such -c help 2>&1 | grep -q tx_sighash32; then
        error "such missing tx_sighash32 command"
    fi
    if [ "$SPV_REQUIRE_VALIDATION" -ne 1 ]; then
        error "SPV_REQUIRE_VALIDATION must be 1 for full-run mode"
    fi
    success "All tools available"
}

generate_testnet_wallet() {
    info "Generating testnet wallet..."
    if [ -n "$TESTNET_PRIVKEY_WIF" ]; then
        PRIVKEY_WIF="$TESTNET_PRIVKEY_WIF"
    else
        run_and_log "such generate_private_key" ./such -c generate_private_key $NETWORK_FLAG | tee "$TMPDIR/testnet_key.txt"
        PRIVKEY_WIF=$(grep "^private key wif:" "$TMPDIR/testnet_key.txt" | cut -d: -f2 | tr -d ' ')
    fi
    run_and_log "such generate_public_key" ./such -c generate_public_key -p "$PRIVKEY_WIF" $NETWORK_FLAG | tee "$TMPDIR/testnet_addr.txt"
    TESTNET_ADDR=$(grep "p2pkh address:" "$TMPDIR/testnet_addr.txt" | cut -d: -f2 | tr -d ' ')
    success "Wallet ready: $TESTNET_ADDR"
    echo "  Private Key (WIF): $PRIVKEY_WIF"
    echo "  [FUNDING] Send testnet DOGE to this address: $TESTNET_ADDR"
}

get_testnet_coins() {
    echo ""
    echo "Send ${NETWORK} DOGE to: $TESTNET_ADDR"
    echo "Wallet private key (WIF): $PRIVKEY_WIF"
    echo "Faucet: https://faucet.doge.toys/"
    echo "[FAUCET] Request coins for address: $TESTNET_ADDR"
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        FAUCET_TXID="${FAUCET_TXID:-}"
        info "NON_INTERACTIVE=1, skipping funding prompt."
    else
        read -p "Optional faucet txid (for log): " FAUCET_TXID
        info "Press Enter after funding the address..."
        read
    fi
    if [ -n "$FAUCET_TXID" ]; then
        echo "FAUCET_TXID=$FAUCET_TXID" > "$TMPDIR/faucet.txt"
    fi
}

generate_dilithium2_keypair() {
    info "Generating Dilithium2 keypair..."
    run_and_log "such dilithium2_keygen" ./such -c dilithium2_keygen | tee "$TMPDIR/dilithium2_keys.txt"
    DILITHIUM2_PK=$(grep "^public key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    DILITHIUM2_SK=$(grep "^secret key:" "$TMPDIR/dilithium2_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_PK" ] || error "Failed to generate Dilithium2 keypair"
    success "Dilithium2 keypair generated"
}

sign_message_dilithium2() {
    info "Signing tx_sighash32 with Dilithium2..."
    run_and_log "such dilithium2_sign" ./such -c dilithium2_sign -p "$DILITHIUM2_SK" -x "$TX_SIGHASH_HEX" | tee "$TMPDIR/dilithium2_sig.txt"
    DILITHIUM2_SIG=$(grep "^signature:" "$TMPDIR/dilithium2_sig.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$DILITHIUM2_SIG" ] || error "Failed to sign tx_sighash32"
    success "tx_sighash32 signed"
}

generate_commitment() {
    info "Generating Dilithium2 commitment..."
    run_and_log "such dilithium2_commit" ./such -c dilithium2_commit -k "$DILITHIUM2_PK" -s "$DILITHIUM2_SIG" | tee "$TMPDIR/dilithium2_commit.txt"
    DILITHIUM2_COMMIT=$(grep "^commitment:" "$TMPDIR/dilithium2_commit.txt" | cut -d: -f2 | tr -d ' ')
    [ "${#DILITHIUM2_COMMIT}" -eq 64 ] || error "Invalid commitment length"
    success "Commitment generated: $DILITHIUM2_COMMIT"
}

build_transaction() {
    info "Build unsigned testnet tx with such, then paste hex below:"
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
    # Reject zeroed P2PKH scriptPubKey: 76a914 + 20-byte hash160 (40 hex chars) + 88ac.
    if echo "$SCRIPT_PUBKEY" | grep -Eq '^76a914(0){40}88ac$'; then
        error "scriptPubKey is a zero placeholder. Provide the real UTXO scriptPubKey."
    fi

    SIGHASH_OUTPUT=$(run_and_log "such tx_sighash32" ./such -c tx_sighash32 -x "$RAW_UNSIGNED_TX" -s "$SCRIPT_PUBKEY" -i 0 -h 1)
    echo "$SIGHASH_OUTPUT"
    TX_SIGHASH_HEX=$(echo "$SIGHASH_OUTPUT" | grep "^tx_sighash32:" | cut -d: -f2 | tr -d ' ')
    [ -n "$TX_SIGHASH_HEX" ] || error "Failed to derive tx_sighash32"
    [ "${#TX_SIGHASH_HEX}" -eq 64 ] || error "Invalid tx_sighash32 length"
    info "tx_sighash32: $TX_SIGHASH_HEX"
    sign_message_dilithium2
    generate_commitment

    ADD_COMMIT_OUTPUT=$(run_and_log "such dilithium2_add_commit_tx" ./such -c dilithium2_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$DILITHIUM2_COMMIT")
    echo "$ADD_COMMIT_OUTPUT"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_WITH_COMMIT" ] || error "Failed to append Dilithium2 commitment"

    TX_FOR_SIGNING="$TX_WITH_COMMIT"

    SIGN_OUTPUT=$(run_and_log "such sign" ./such -c sign -x "$TX_FOR_SIGNING" -s "$SCRIPT_PUBKEY" -i 0 -h 1 -p "$PRIVKEY_WIF" $NETWORK_FLAG)
    echo "$SIGN_OUTPUT"
    SIGNED_TX=$(echo "$SIGN_OUTPUT" | grep "^signed TX:" | cut -d: -f2- | tr -d ' ')
    [ -n "$SIGNED_TX" ] || error "Failed to sign transaction"

    cat > "$TMPDIR/tx_info.txt" <<EOF
RAW_UNSIGNED_TX=$RAW_UNSIGNED_TX
TX_WITH_COMMIT=$TX_WITH_COMMIT
SCRIPT_PUBKEY=$SCRIPT_PUBKEY
TX_SIGHASH_HEX=$TX_SIGHASH_HEX
DILITHIUM2_SIG=$DILITHIUM2_SIG
DILITHIUM2_COMMIT=$DILITHIUM2_COMMIT
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a2444494c32${DILITHIUM2_COMMIT}
EOF

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
}

monitor_spvnode() {
    info "Step 7: Monitor with spvnode"
    echo "Expected log:"
    echo "  [dilithium-commit] Valid at height=X txpos=Y commit=$DILITHIUM2_COMMIT"
    if [ "$BROADCASTED" -eq 1 ]; then
        info "Running spvnode scan (timeout ${SPV_TIMEOUT_SECONDS}s) and requiring Dilithium2 validation log before next step..."
        set +e
        run_and_log "spvnode scan" timeout "$SPV_TIMEOUT_SECONDS" ./spvnode $NETWORK_FLAG -l -f "$SPV_FROM_HEIGHT" -c -d -x -p -b -a "$TESTNET_ADDR" scan > "$TMPDIR/spvnode.log" 2>&1
        SPV_EXIT=$?
        set -e
        cat "$TMPDIR/spvnode.log"
        if ! grep -Fq "[dilithium-commit] Valid" "$TMPDIR/spvnode.log"; then
            echo "----- spvnode log tail -----"
            tail -n 80 "$TMPDIR/spvnode.log"
            if [ "$SPV_EXIT" -eq 124 ]; then
                error "spvnode timed out before Dilithium2 commitment validation was observed"
            else
                error "Dilithium2 commitment was not validated by spvnode before proceeding"
            fi
        else
            success "spvnode confirmed Dilithium2 commitment validation"
        fi
    else
        error "Transaction was not broadcast; cannot continue full-run validation flow"
    fi
}

verify_commitment() {
    info "Step 8: Off-chain verification"
    local VERIFY_PK="$DILITHIUM2_PK"
    local VERIFY_SIG="$DILITHIUM2_SIG"

    VERIFY_OUTPUT=$(./such -c dilithium2_verify -k "$VERIFY_PK" -x "$TX_SIGHASH_HEX" -s "$VERIFY_SIG")
    echo "$VERIFY_OUTPUT"
    echo "$VERIFY_OUTPUT" > "$TMPDIR/dilithium2_verify.txt"
    if ! echo "$VERIFY_OUTPUT" | grep -Eq "valid:[[:space:]]*true|VERIFIED: Signature is valid|VALID"; then
        echo "$VERIFY_OUTPUT"
        error "Off-chain Dilithium2 signature verification failed"
    fi

    COMMIT_OUTPUT=$(./such -c dilithium2_commit -k "$VERIFY_PK" -s "$VERIFY_SIG")
    echo "$COMMIT_OUTPUT" > "$TMPDIR/dilithium2_commit_verify.txt"
    REGENERATED_COMMIT=$(echo "$COMMIT_OUTPUT" | grep "^commitment:" | cut -d: -f2 | tr -d ' ')
    if [ -z "$REGENERATED_COMMIT" ]; then
        error "Failed to parse regenerated Dilithium2 commitment"
    fi
    if [ "$REGENERATED_COMMIT" != "$DILITHIUM2_COMMIT" ]; then
        error "Regenerated Dilithium2 commitment does not match expected commitment"
    fi
    success "Off-chain Dilithium2 verification and commitment match passed"
}

main() {
    echo ""
    echo "=========================================="
    echo "  Dilithium2 Testnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    generate_testnet_wallet
    get_testnet_coins
    generate_dilithium2_keypair
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
    echo "Files:"
    echo "  - $TMPDIR/tx_info.txt"
    echo "  - $TMPDIR/spvnode.log"
    echo "  - $TMPDIR/dilithium2_verify.txt"
}

main
