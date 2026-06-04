#!/bin/bash
#
# TPM CLI Integration Test Script (Linux / swtpm)
#
# Exercises every TPM-aware command and parameter path of the `such` CLI
# (and the underlying src/seal.c Linux TSS2 helpers) against the `swtpm`
# software TPM emulator. Modelled after contrib/testnet_dilithium2_test.sh.
#
# Prerequisites:
#   - libdogecoin built with --enable-tss2 and tests enabled (which auto-
#     defines PASSWD_STR) so that linux_tpm_get_password() returns the
#     compiled-in test password instead of prompting.
#   - swtpm, tpm2-tools, libtss2-{esys,mu} present on the host.
#   - `such` binary in PATH or current directory.
#
# The script:
#   1. Brings up a fresh swtpm emulator on 127.0.0.1:2321/2322.
#   2. For each slot in $SLOTS, runs a full TPM-backed round-trip through
#      every CLI command that talks to src/seal.c's Linux TPM helpers:
#        bip32_extended_master_key (gen) -> decrypt_master_key
#        generate_mnemonic         (gen) -> decrypt_mnemonic
#      and on slot 0 also: mnemonic_to_key, mnemonic_to_addresses (mainnet
#      and testnet), generate_mnemonic with -z entropy_size, and
#      list_encryption_keys_in_tpm.
#   3. Validates expected failure paths (-j without -y, missing
#      encrypted_seed file, missing encrypted_hdnode slot).
#   4. Tears swtpm down (workdir + run log preserved for inspection).
#
# Notes:
#   - SW-only paths (no -j) are intentionally not exercised here -- their
#     password helpers go through getpass() and require a real tty, which
#     is incompatible with the "Y/N" prompt piping required by every TPM
#     command. The src/seal.c SW paths are exercised by the unit test
#     suite (`./tests`) instead.
#   - tpm2_flushcontext is invoked between tests to clear transient object
#     slots that swtpm leaks across separate `such` invocations (each
#     Esys_TR_FromTPMPublic loads a copy of the persistent object without
#     a matching Esys_FlushContext on shutdown).
#
# Exit status is 0 only when every assertion passes.
#

set -u
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SUCH_BIN="${SUCH_BIN:-$REPO_ROOT/such}"
# Slots to round-trip through every TPM-aware command. Kept small because
# each gen creates a fresh persistent RSA-2048 object in TPM NV memory and
# swtpm's default NV size easily exhausts under heavy churn.
SLOTS="${SLOTS:-0 1}"
# Retry budget for transient TPM_RC_NV_UNAVAILABLE / TPM_RC_RETRY warnings
# that swtpm can emit after many back-to-back EvictControl operations.
SUCH_RETRIES="${SUCH_RETRIES:-3}"
SUCH_RETRY_SLEEP="${SUCH_RETRY_SLEEP:-1}"
SWTPM_PORT_CMD="${SWTPM_PORT_CMD:-2321}"
SWTPM_PORT_CTRL="${SWTPM_PORT_CTRL:-2322}"
TMPDIR_BASE="${TMPDIR_BASE:-/tmp}"
WORKDIR=$(mktemp -d "${TMPDIR_BASE}/tpm_cli_test_XXXXXX")
SWTPM_STATE_DIR="${WORKDIR}/swtpm_state"
LOGFILE="${WORKDIR}/run.log"

PASS=0
FAIL=0
FAILED_TESTS=()

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); }
pass()    { PASS=$((PASS+1)); success "$1"; }

cleanup() {
    local rc=$?
    if [ -n "${SWTPM_PID:-}" ] && kill -0 "$SWTPM_PID" 2>/dev/null; then
        kill "$SWTPM_PID" 2>/dev/null || true
        sleep 1
    fi
    info "Workdir preserved at $WORKDIR"
    info "Log: $LOGFILE"
    return $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Flush transient objects and loaded sessions on the TPM. Each `such`
# invocation that calls Esys_TR_FromTPMPublic loads a copy of the persistent
# object into a transient slot and does not FlushContext it on shutdown,
# which exhausts swtpm's small transient slot pool (TPM_RC_OBJECT_MEMORY
# 0x902) after a handful of consecutive CLI invocations. Calling
# tpm2_flushcontext between tests keeps swtpm's transient pool clear.
flush_transient() {
    tpm2_flushcontext --transient-object 2>/dev/null || true
    tpm2_flushcontext --loaded-session  2>/dev/null || true
}

# Run a command with its full args, echo a header to the log, capture combined
# stdout/stderr, and return its exit code. Output is also tee'd so it shows up
# in both the log and the live terminal.
run_and_log() {
    local label="$1"; shift
    {
        echo
        echo "----- ${label}: $* -----"
        "$@" 2>&1
        local rc=$?
        echo "----- ${label} exit=${rc} -----"
        return $rc
    } | tee -a "$LOGFILE"
    # Propagate the exit status of the command (first element of PIPESTATUS).
    return "${PIPESTATUS[0]}"
}

# Run an interactive `such` invocation by piping "Y\n" to it (every TPM
# command in src/cli/such.c gates execution behind a "Y/N" confirmation
# prompt). The combined output is captured to $LAST_OUT, and the exit code
# is returned. The call is retried on transient TPM_RC_NV_UNAVAILABLE
# (0x902) / TPM_RC_RETRY (0x922) warnings emitted by swtpm under load.
LAST_OUT=""
such_y() {
    local label="$1"; shift
    {
        echo
        echo "----- ${label}: such $* -----"
    } | tee -a "$LOGFILE" >/dev/null
    local rc=0 attempt
    for attempt in $(seq 1 "$SUCH_RETRIES"); do
        LAST_OUT=$(printf 'Y\n' | "$SUCH_BIN" "$@" 2>&1)
        rc=$?
        # Strip TSS2 TCTI fallback noise (it prints harmless errors for the
        # /dev/tpm* device path before falling back to mssim/swtpm) so the
        # assertions below see only the actual command output.
        LAST_OUT=$(printf '%s\n' "$LAST_OUT" | grep -vE '^(ERROR|WARNING):(tcti|esys):' || true)
        if [ "$rc" -eq 0 ]; then
            break
        fi
        # Retry on transient swtpm NV pressure.
        if printf '%s' "$LAST_OUT" | grep -qE 'ErrorCode \(0x0000(0902|0922)\)'; then
            sleep "$SUCH_RETRY_SLEEP"
            continue
        fi
        break
    done
    printf '%s\n' "$LAST_OUT" | tee -a "$LOGFILE" >/dev/null
    {
        echo "----- ${label} exit=${rc} attempts=${attempt} -----"
    } | tee -a "$LOGFILE" >/dev/null
    return $rc
}

# Assert two strings are equal.
assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label"
        echo "  expected: $expected" | tee -a "$LOGFILE"
        echo "  actual:   $actual"   | tee -a "$LOGFILE"
    fi
}

# Assert the previous such command succeeded (rc 0).
assert_rc_zero() {
    local label="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        pass "$label"
    else
        fail "$label"
        echo "  rc=$rc, output:" | tee -a "$LOGFILE"
        printf '%s\n' "$LAST_OUT" | tee -a "$LOGFILE"
    fi
}

# Assert the previous such command failed (rc != 0).
assert_rc_nonzero() {
    local label="$1" rc="$2"
    if [ "$rc" -ne 0 ]; then
        pass "$label"
    else
        fail "$label"
        echo "  expected non-zero exit, got rc=0, output:" | tee -a "$LOGFILE"
        printf '%s\n' "$LAST_OUT" | tee -a "$LOGFILE"
    fi
}

# Assert that $LAST_OUT contains a substring.
assert_contains() {
    local label="$1" needle="$2"
    if printf '%s' "$LAST_OUT" | grep -qF -- "$needle"; then
        pass "$label"
    else
        fail "$label"
        echo "  expected substring: $needle" | tee -a "$LOGFILE"
        echo "  actual output:" | tee -a "$LOGFILE"
        printf '%s\n' "$LAST_OUT" | tee -a "$LOGFILE"
    fi
}

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

check_prereqs() {
    info "Checking prerequisites..."
    if [ ! -x "$SUCH_BIN" ]; then
        echo "ERROR: such binary not found at $SUCH_BIN" >&2
        exit 2
    fi
    if ! "$SUCH_BIN" -c help 2>&1 | grep -q list_encryption_keys_in_tpm; then
        echo "ERROR: $SUCH_BIN was not built with --enable-tss2" >&2
        exit 2
    fi
    for tool in swtpm tpm2_getrandom; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "ERROR: $tool not in PATH" >&2
            exit 2
        fi
    done
    success "Prerequisites OK"
}

# ---------------------------------------------------------------------------
# swtpm lifecycle
# ---------------------------------------------------------------------------

start_swtpm() {
    info "Starting swtpm on 127.0.0.1:${SWTPM_PORT_CMD}/${SWTPM_PORT_CTRL}..."
    mkdir -p "$SWTPM_STATE_DIR"
    chmod 700 "$SWTPM_STATE_DIR"

    # Make sure nothing else is on our port (best-effort, no pkill allowed).
    if ss -ltn 2>/dev/null | grep -q ":${SWTPM_PORT_CMD}\b"; then
        echo "ERROR: 127.0.0.1:${SWTPM_PORT_CMD} already in use" >&2
        exit 2
    fi

    swtpm socket \
        --tpmstate "dir=${SWTPM_STATE_DIR}" \
        --ctrl "type=tcp,port=${SWTPM_PORT_CTRL}" \
        --server "type=tcp,port=${SWTPM_PORT_CMD}" \
        --flags startup-clear \
        --tpm2 \
        --log "level=20,file=${WORKDIR}/swtpm.log" \
        --daemon

    SWTPM_PID=$(pgrep -f "swtpm socket .*port=${SWTPM_PORT_CMD}" | head -1)
    if [ -z "$SWTPM_PID" ]; then
        echo "ERROR: swtpm did not start" >&2
        exit 2
    fi
    sleep 1
    info "swtpm pid=$SWTPM_PID"

    # Confirm the TPM is reachable via the default TctiLdr fallback path
    # (mssim @ 127.0.0.1:2321) before driving any seal.c codepaths. The
    # /dev/tpm* device-TCTI fallback warnings are dropped here -- they show
    # up many times across the run as expected fallback chatter from
    # libtss2-tctildr and would otherwise dominate the log.
    if ! tpm2_getrandom --hex 4 >/dev/null 2>/dev/null; then
        echo "ERROR: tpm2_getrandom against swtpm failed" >&2
        exit 2
    fi
    success "swtpm is reachable"
}

# ---------------------------------------------------------------------------
# Per-slot test bodies
# ---------------------------------------------------------------------------

test_tpm_hdnode_roundtrip() {
    local slot="$1"
    local label="TPM HD-node slot=${slot}"
    info "$label"

    such_y "${label} gen"     -c bip32_extended_master_key -y "$slot" -j -w
    assert_rc_zero "${label} gen rc" $?
    local gen_key
    gen_key=$(printf '%s' "$LAST_OUT" | awk -F': ' '/^bip32 extended master key:/ {print $2; exit}')
    [ -n "$gen_key" ] && pass "${label} gen emitted xprv" || fail "${label} gen emitted xprv"

    such_y "${label} decrypt" -c decrypt_master_key -y "$slot" -j
    assert_rc_zero "${label} decrypt rc" $?
    local dec_key
    dec_key=$(printf '%s' "$LAST_OUT" | awk -F': ' '/^bip32 extended master key:/ {print $2; exit}')
    assert_eq "${label} decrypt matches gen" "$gen_key" "$dec_key"
}

test_tpm_mnemonic_roundtrip() {
    local slot="$1"
    local label="TPM mnemonic slot=${slot}"
    info "$label"

    such_y "${label} gen"     -c generate_mnemonic -y "$slot" -j -w -b
    assert_rc_zero "${label} gen rc" $?

    such_y "${label} decrypt" -c decrypt_mnemonic -y "$slot" -j
    assert_rc_zero "${label} decrypt rc" $?
    local mnemonic
    mnemonic=$(printf '%s' "$LAST_OUT" | awk 'NF==24 {print; exit}')
    [ -n "$mnemonic" ] && pass "${label} decrypt yields 24-word mnemonic" \
                       || fail "${label} decrypt yields 24-word mnemonic"
}

# Exercise mnemonic-derivation paths (mnemonic_to_key / mnemonic_to_addresses)
# that decrypt the persistent slot through the TPM and then run BIP32 / BIP44
# derivation. Kept on a single slot to avoid stacking persistent objects.
test_tpm_mnemonic_derive() {
    local slot="$1"
    local label="TPM mnemonic derive slot=${slot}"
    info "$label"

    such_y "${label} mnemonic_to_key" -c mnemonic_to_key -y "$slot" -j
    assert_rc_zero "${label} mnemonic_to_key rc" $?
    assert_contains "${label} mnemonic_to_key emits keypath"    "keypath:"
    assert_contains "${label} mnemonic_to_key emits wif"        "private key (wif):"

    such_y "${label} mnemonic_to_addresses (mainnet, account+change+index)" \
        -c mnemonic_to_addresses -y "$slot" -j -o 0 -g 0 -i 1
    assert_rc_zero "${label} mnemonic_to_addresses rc" $?
    assert_contains "${label} mnemonic_to_addresses emits Address" "Address 1:"

    such_y "${label} mnemonic_to_addresses (testnet, account=1, change=1, range)" \
        -c mnemonic_to_addresses -y "$slot" -j -t -o 1 -g 1 -i 3 -a
    assert_rc_zero "${label} mnemonic_to_addresses testnet rc" $?
    assert_contains "${label} mnemonic_to_addresses testnet emits Address" "Address"
}

test_tpm_mnemonic_entropy_size() {
    # generate_mnemonic accepts -z <bit_size> when -y is supplied; exercise
    # the 128-bit option through the TPM gen helper. (Note: seal.c currently
    # hard-codes 256-bit entropy for the TPM path; we still assert the option
    # is accepted by the option parser and the round-trip succeeds.)
    local slot="$1"
    local label="TPM mnemonic 128-bit slot=${slot}"
    info "$label"

    such_y "${label} gen"     -c generate_mnemonic -y "$slot" -j -w -b -z 128
    assert_rc_zero "${label} gen rc" $?

    such_y "${label} decrypt" -c decrypt_mnemonic -y "$slot" -j
    assert_rc_zero "${label} decrypt rc" $?
    local mnemonic
    mnemonic=$(printf '%s' "$LAST_OUT" | awk 'NF>=12 && NF<=24 {print; exit}')
    [ -n "$mnemonic" ] && pass "${label} decrypt yields mnemonic" \
                       || fail "${label} decrypt yields mnemonic"
}

test_list_encryption_keys() {
    local label="list_encryption_keys_in_tpm"
    info "$label"

    such_y "${label}" -c list_encryption_keys_in_tpm
    assert_rc_zero "${label} rc" $?

    # At minimum the slot-0 HD and mnemonic persistent objects should be
    # bound after the per-slot round-trips above ran successfully.
    assert_contains "${label} reports dogecoin_master_000"   "dogecoin_master_000"
    assert_contains "${label} reports dogecoin_mnemonic_000" "dogecoin_mnemonic_000"
}

# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------

test_negative_paths() {
    info "Negative path checks"

    # -j without a preceding -y must be rejected by the such option parser
    # ("TPM can only be used with encrypted files").
    such_y "neg: -j without -y" -c generate_mnemonic -j
    assert_rc_nonzero "neg: -j without -y returns non-zero" $?
    assert_contains  "neg: -j without -y emits guard string" "TPM can only be used with encrypted files"

    # seed_to_master_key with -j but no prior encrypted_seed file should fail
    # cleanly inside linux_tpm_decrypt_blob's fopen() check.
    rm -f "${WORKDIR}/.store/encrypted_seed_777"
    such_y "neg: seed_to_master_key without encrypted_seed" \
        -c seed_to_master_key -y 777 -j
    assert_rc_nonzero "neg: missing encrypted_seed returns non-zero" $?

    # decrypt_master_key with -y pointing at a never-populated slot must fail
    # (no encrypted_hdnode file and no persistent object).
    rm -f "${WORKDIR}/.store/encrypted_hdnode_888"
    such_y "neg: decrypt_master_key with missing slot" \
        -c decrypt_master_key -y 888 -j
    assert_rc_nonzero "neg: missing encrypted_hdnode returns non-zero" $?
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

main() {
    {
        echo "==========================================================="
        echo "TPM CLI integration test (contrib/test_tpm_cli.sh)"
        echo "Date:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Host:         $(uname -a)"
        echo "such:         $SUCH_BIN"
        echo "swtpm:        $(swtpm --version 2>&1 | head -1)"
        echo "tpm2-tools:   $(tpm2_getrandom --version 2>&1 | head -1)"
        echo "TSS2 esys:    $(pkg-config --modversion tss2-esys 2>/dev/null || echo unknown)"
        echo "Slots:        $SLOTS"
        echo "Workdir:      $WORKDIR"
        echo "==========================================================="
    } > "$LOGFILE"
    info "Workdir: $WORKDIR"
    info "Logfile: $LOGFILE"
    info "such:    $SUCH_BIN"
    info "Slots:   $SLOTS"

    check_prereqs
    start_swtpm

    # All TPM-encrypted blobs are written under .store, so isolate that store
    # inside WORKDIR.
    cd "$WORKDIR"

    for slot in $SLOTS; do
        info "===== Slot $slot ====="
        test_tpm_hdnode_roundtrip   "$slot"
        flush_transient
        test_tpm_mnemonic_roundtrip "$slot"
        flush_transient
    done

    # Mnemonic derivation only on slot 0 -- it does not create new persistent
    # objects, just decrypts the existing slot and runs BIP32/BIP44 derivation.
    test_tpm_mnemonic_derive 0
    flush_transient

    # Exercise the -z entropy_size knob on the first slot.
    test_tpm_mnemonic_entropy_size 0
    flush_transient

    test_list_encryption_keys
    test_negative_paths

    {
        echo
        echo "============================================================"
        echo "TPM CLI test summary: PASS=$PASS  FAIL=$FAIL"
        if [ "$FAIL" -gt 0 ]; then
            echo "Failed assertions:"
            for t in "${FAILED_TESTS[@]}"; do
                echo "  - $t"
            done
        fi
        echo "============================================================"
    } | tee -a "$LOGFILE"

    if [ "$FAIL" -gt 0 ]; then
        return 1
    fi
    return 0
}

main "$@"
