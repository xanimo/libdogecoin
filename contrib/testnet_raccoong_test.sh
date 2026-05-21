#!/bin/bash
#
# Raccoon-G-44 Testnet Integration Test Script
#
# Prerequisites:
#   - libdogecoin built with --enable-liboqs
#   - such, sendtx, and spvnode binaries in PATH or current directory
#

set -e
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
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
TMPDIR=$(mktemp -d /tmp/raccoong_testnet_XXXXXX)
chmod 700 "$TMPDIR"
BROADCASTED=0
SPV_TIMEOUT_SECONDS="${SPV_TIMEOUT_SECONDS:-1800}"
SPV_FROM_HEIGHT="${SPV_FROM_HEIGHT:-0}"
SPV_REQUIRE_VALIDATION="${SPV_REQUIRE_VALIDATION:-1}"
NON_INTERACTIVE="${NON_INTERACTIVE:-1}"
AUTO_BROADCAST="${AUTO_BROADCAST:-1}"
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
    if ! ./such -c help 2>&1 | grep -q raccoong_keygen; then
        error "libdogecoin not built with Raccoon-G support. Rebuild with --enable-liboqs"
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

generate_raccoong_keypair() {
    info "Generating Raccoon-G-44 keypair..."
    run_and_log "such raccoong_keygen" ./such -c raccoong_keygen | tee "$TMPDIR/raccoong_keys.txt"
    RACCOONG_PK=$(grep "^public key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    RACCOONG_SK=$(grep "^secret key:" "$TMPDIR/raccoong_keys.txt" | cut -d: -f2 | tr -d ' ')
    [ -n "$RACCOONG_PK" ] || error "Failed to generate Raccoon-G keypair"
    [ -n "$RACCOONG_SK" ] || error "Failed to generate Raccoon-G keypair"
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

    ADD_COMMIT_OUTPUT=$(run_and_log "such raccoong_add_commit_tx" ./such -c raccoong_add_commit_tx -x "$RAW_UNSIGNED_TX" -s "$RACCOONG_COMMIT")
    echo "$ADD_COMMIT_OUTPUT"
    TX_WITH_COMMIT=$(echo "$ADD_COMMIT_OUTPUT" | grep "^tx with commitment:" | cut -d: -f2- | tr -d ' ')
    [ -n "$TX_WITH_COMMIT" ] || error "Failed to append Raccoon-G commitment"

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
RACCOONG_SIG=$RACCOONG_SIG
RACCOONG_COMMIT=$RACCOONG_COMMIT
SIGNED_TX=$SIGNED_TX
OPRETURN_SCRIPT=6a2452434734${RACCOONG_COMMIT}
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
    echo "  [raccoong-commit] Valid at height=X txpos=Y commit=$RACCOONG_COMMIT"
    if [ "$BROADCASTED" -eq 1 ]; then
        info "Running spvnode scan and waiting for [raccoong-commit] Valid marker..."
        : > "$TMPDIR/spvnode.log"
        ./spvnode $NETWORK_FLAG -l -f "$SPV_FROM_HEIGHT" -c -d -x -p -b -a "$TESTNET_ADDR" scan > "$TMPDIR/spvnode.log" 2>&1 &
        SPV_PID=$!
        DEADLINE=$(( $(date +%s) + SPV_TIMEOUT_SECONDS ))
        FOUND_VALID=0

        while kill -0 "$SPV_PID" 2>/dev/null; do
            if grep -Fq "[raccoong-commit] Valid" "$TMPDIR/spvnode.log"; then
                FOUND_VALID=1
                break
            fi
            if [ "$(date +%s)" -ge "$DEADLINE" ]; then
                break
            fi
            sleep 3
        done

        if [ "$FOUND_VALID" -eq 1 ]; then
            kill "$SPV_PID" 2>/dev/null || true
            wait "$SPV_PID" 2>/dev/null || true
            cat "$TMPDIR/spvnode.log"
            success "spvnode confirmed Raccoon-G commitment validation"
        else
            kill "$SPV_PID" 2>/dev/null || true
            wait "$SPV_PID" 2>/dev/null || true
            cat "$TMPDIR/spvnode.log"
            echo "----- spvnode log tail -----"
            tail -n 80 "$TMPDIR/spvnode.log"
            error "spvnode did not emit [raccoong-commit] Valid before timeout (${SPV_TIMEOUT_SECONDS}s)"
        fi
    else
        error "Transaction was not broadcast; cannot continue full-run validation flow"
    fi
}

verify_commitment() {
    info "Step 8: Off-chain verification"
    local VERIFY_PK="$RACCOONG_PK"
    local VERIFY_SIG="$RACCOONG_SIG"

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
    echo "  Raccoon-G-44 Testnet Integration Test"
    echo "=========================================="
    echo ""
    check_tools
    generate_testnet_wallet
    get_testnet_coins
    generate_raccoong_keypair
    derive_hd_child
    build_transaction
    monitor_spvnode
    verify_commitment
    success "All test data saved in: $TMPDIR"
}

main
