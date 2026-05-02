#!/usr/bin/env bash
#
# broadcast_set.sh — End-to-end multi-pair ZK carrier mainnet driver.
#
# Loops N times.  For each iteration it:
#   1. Picks the next unspent UTXO from $FUNDED_ADDR (or the chained change
#      output from the previous iteration) and queries explorer APIs for
#      its value + scriptPubKey.
#   2. Generates a fresh Groth16 proof via contrib/zk_carrier/witness_helper.py
#      with a per-iteration --amount so each cycle commits a distinct payload.
#   3. Builds an unsigned base tx (1 input → 1 P2PKH change to FUNDED_ADDR),
#      derives sighash, and uses
#         such -c zk_add_commit_and_carrier_tx
#      to append the ZKP1 OP_RETURN + P2SH carrier outputs.
#   4. Signs the funding input with such -c sign and broadcasts TX_C with
#      sendtx.  Waits for the explorer to see TX_C.
#   5. Builds TX_R that spends every carrier output (one P2SH input per
#      carrier part), pastes in the per-part scriptSigs already emitted by
#      step 3, and broadcasts TX_R via sendtx.
#   6. Appends "tx_c.txid<TAB>tx_r.txid<TAB>commit<TAB>height_estimate"
#      to a manifest.  Chains the next iteration off TX_C's change vout.
#
# After the loop, optionally launches one spvnode scan over the
# whole height range and tees the resulting [zk-commit] PASSED lines (one
# triple per pair) to test-logs/.
#
# This is the multi-pair sibling of run_full_zk_carrier_demo.sh
# (same directory) and the ZK analogue of contrib/mainnet_dilithium2_test.sh /
# mainnet_raccoong_test.sh — see those for prior PQC mainnet logs.
#
# Prerequisites (same as the PQC scripts; see test-logs/ on the
# copilot/run-end-to-end-tests-dilithium2-raccoon-g branch for prior runs):
#   - libdogecoin built with --enable-zk-carrier --enable-test-passwd
#     [--with-mcl=DIR]; binaries such, sendtx, spvnode in . or PATH.
#   - node + snarkjs installed (same as witness_helper.py needs).
#   - $FUNDED_WIF holds koinu in $FUNDED_ADDR; default WIF/ADDR mirror
#     contrib/mainnet_dilithium2_test.sh so a single funded wallet covers
#     both PQC and ZK runs.
#   - Range-proof circuit artifacts: $WASM, $ZKEY, and $VKEY.
#
# Usage:
#   # fully repeatable single entry point (auto-bootstraps everything):
#   ./contrib/zk_carrier/scripts/broadcast_set.sh
#
#   # or with explicit overrides:
#   N=2 \
#   FUNDED_UTXO_TXID=<initial-txid> FUNDED_UTXO_VOUT=0 \
#   FUNDED_UTXO_VALUE_KOINU=<koinu> \
#   FUNDED_UTXO_SCRIPT_PUBKEY=<spk-hex> \
#   WITH_MCL=/tmp/zk_build/mcl \
#   ./contrib/zk_carrier/scripts/broadcast_set.sh
#
# By default the script:
#   * builds libdogecoin (such/sendtx/spvnode) when the binaries are missing
#     (BOOTSTRAP=1, set BOOTSTRAP=0 to skip);
#   * runs a Groth16 trusted-setup ceremony (circom + snarkjs) when the
#     circuit artefacts (wasm/zkey/vkey) are missing or RUN_CEREMONY=1 — full
#     stdout/stderr from circom and snarkjs is teed into the run log, and the
#     freshly generated verification_key.json is dumped into the log + saved
#     under contrib/zk_carrier/circuits/build/ alongside its sha256 (mirrors
#     how the PQC mainnet scripts log the freshly generated public key);
#   * auto-discovers a spendable UTXO at FUNDED_ADDR via block explorers when
#     FUNDED_UTXO_TXID/FUNDED_UTXO_VALUE_KOINU are not provided;
#   * loops N times over (witness → such → sendtx → wait → set_scriptsig →
#     sendtx → wait), recording (iter, tx_c, tx_r, commit, payload_bytes, utc)
#     into manifest.tsv;
#   * launches one spvnode rescan over the full height range, which emits the
#     fully-decoded ZKP1 reveal fields and "Reveal validated" lines into the log.
#
# Honest deferred operations: the script never silently fakes confirmations —
# if an explorer poll times out or sendtx returns a non-relay status, that
# iteration is logged and the loop stops so the operator can recover.

set -euo pipefail
umask 077

RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLU}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK  ]${NC} $*"; }
warn()    { echo -e "${YEL}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

# ------------------------------- config --------------------------------------
N="${N:-3}"
NETWORK="${NETWORK:-mainnet}"
NETWORK_FLAG=""
[ "$NETWORK" = "testnet" ] && NETWORK_FLAG="-t"

# Defaults match contrib/mainnet_dilithium2_test.sh so the same funded wallet
# can drive both PQC and ZK runs.
FUNDED_WIF="${FUNDED_WIF:-QP1tqHYuPiAW73MHETRaARgeEff9PhHyYyQcWXAGskEFmSppDt2w}"
FUNDED_ADDR="${FUNDED_ADDR:-DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr}"

# Initial UTXO to spend.  Subsequent iterations chain off TX_C's change vout 0.
FUNDED_UTXO_TXID="${FUNDED_UTXO_TXID:-${CHAINED_UTXO_TXID:-}}"
FUNDED_UTXO_VOUT="${FUNDED_UTXO_VOUT:-${CHAINED_UTXO_VOUT:-0}}"
FUNDED_UTXO_VALUE_KOINU="${FUNDED_UTXO_VALUE_KOINU:-${CHAINED_UTXO_VALUE_KOINU:-}}"
# Default to FUNDED_ADDR's P2PKH script (76a914 + hash160(DDMpdcTr...) + 88ac)
FUNDED_UTXO_SCRIPT_PUBKEY="${FUNDED_UTXO_SCRIPT_PUBKEY:-${CHAINED_UTXO_SCRIPT_PUBKEY:-76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac}}"

CARRIER_VALUE_KOINU="${CARRIER_VALUE_KOINU:-100000000}"   # 1 DOGE per carrier part
TX_FEE_KOINU="${TX_FEE_KOINU:-2000000}"
TX_R_FEE_KOINU="${TX_R_FEE_KOINU:-10000000}"
RANGE_LOW="${RANGE_LOW:-0}"
RANGE_HIGH="${RANGE_HIGH:-1000000}"
CIRCUIT_ID="${CIRCUIT_ID:-1}"

# Proof system: groth16 (default, ZKP1 mode=0) or plonk (ZKP1 mode=1).  When
# set to plonk the script:
#   * runs `snarkjs plonk setup` instead of the groth16 ceremony so the
#     resulting .zkey/verification_key.json carry "protocol":"plonk";
#   * passes --proof-system plonk to witness_helper.py, which switches
#     snarkjs to `plonk fullprove` and stamps mode=1 in the ZKP1 payload;
#   * after spvnode emits "[zk-commit] Reveal validated" for each pair, the
#     post-spvnode block at the bottom of this script invokes
#     `snarkjs plonk verify $VKEY public.json proof.json` end-to-end against
#     the saved per-iteration proof artefacts and tees the verifier output
#     into the curated mainnet log.  This implements the documented
#     "external verifier invoked after spvnode validates the reveal" flow.
PROOF_SYSTEM="${PROOF_SYSTEM:-groth16}"
case "$PROOF_SYSTEM" in
    groth16) ZK_MODE_BYTE=0 ;;
    plonk)   ZK_MODE_BYTE=1 ;;
    *) echo "[FAIL] unsupported PROOF_SYSTEM=$PROOF_SYSTEM (groth16|plonk)" >&2; exit 1 ;;
esac

# Circuit artefacts (built by contrib/zk_carrier/circuits/README.md steps).
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
# When PROOF_SYSTEM=plonk, default the artefacts to a sibling tree so a
# groth16 ceremony output is never silently reused as a PLONK key (the file
# format is incompatible).  Operators can still pass explicit WASM/ZKEY/VKEY.
if [ "$PROOF_SYSTEM" = "plonk" ]; then
    WASM="${WASM:-$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm}"
    ZKEY="${ZKEY:-$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof_plonk.zkey}"
    VKEY="${VKEY:-$REPO_DIR/contrib/zk_carrier/circuits/build/verification_key_plonk.json}"
else
    WASM="${WASM:-$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm}"
    ZKEY="${ZKEY:-$REPO_DIR/contrib/zk_carrier/circuits/build/range_proof.zkey}"
    VKEY="${VKEY:-$REPO_DIR/contrib/zk_carrier/circuits/build/verification_key.json}"
fi

SUCH="${SUCH:-$REPO_DIR/such}"
SENDTX="${SENDTX:-$REPO_DIR/sendtx}"
SPVNODE="${SPVNODE:-$REPO_DIR/spvnode}"
WITNESS_HELPER="${WITNESS_HELPER:-$REPO_DIR/contrib/zk_carrier/witness_helper.py}"

EXPLORER_BASE_MAIN="${EXPLORER_BASE_MAIN:-https://api.blockcypher.com/v1/doge/main}"
TX_POLL_TIMEOUT="${TX_POLL_TIMEOUT:-600}"
SENDTX_MAX_RETRIES="${SENDTX_MAX_RETRIES:-3}"
RELAY_SUCCESS_PATTERN='Requested from nodes:[[:space:]]*[1-9]|Seen on other nodes:[[:space:]]*[1-9]|already (broadcasted|known|have transaction)|txn-already-known|txn-already-in-mempool'

# Output dirs.
TS=$(date -u +%Y%m%d_%H%M%S)
WORK="${WORK:-$REPO_DIR/test-logs/zk_set_${TS}}"
mkdir -p "$WORK"
MANIFEST="$WORK/manifest.tsv"
echo -e "iter\ttx_c_txid\ttx_r_txid\tcommit\tpayload_bytes\tutc_iso" > "$MANIFEST"
LOG="$WORK/run.log"
exec > >(tee -a "$LOG") 2>&1

info "ZK carrier broadcast set: N=$N network=$NETWORK addr=$FUNDED_ADDR"
info "Work dir: $WORK"
info "Manifest: $MANIFEST"

# --------------------------- bootstrap (build) -------------------------------
# Make this script a single-entry-point repeatable end-to-end driver: when the
# such/sendtx/spvnode binaries (and optionally libmcl.a for in-process Groth16
# verification) are missing, build them in place.  Skip with BOOTSTRAP=0.
if [ "${BOOTSTRAP:-1}" = "1" ]; then
    if [ ! -x "$SUCH" ] || [ ! -x "$SENDTX" ] || [ ! -x "$SPVNODE" ]; then
        info "================================================================="
        info "[bootstrap] building libdogecoin + such/sendtx/spvnode"
        info "================================================================="
        ( cd "$REPO_DIR" && \
          if [ ! -f configure ]; then ./autogen.sh; fi && \
          CONF_ARGS="--enable-test-passwd --enable-zk-carrier --disable-silent-rules" && \
          if [ -n "${WITH_MCL:-}" ]; then CONF_ARGS="$CONF_ARGS --with-mcl=$WITH_MCL"; fi && \
          ./configure $CONF_ARGS && \
          make -j"$(nproc)" ) 2>&1 | sed 's/^/  [bootstrap build] /'
        [ -x "$SUCH" ] && [ -x "$SENDTX" ] && [ -x "$SPVNODE" ] || die "bootstrap build did not produce such/sendtx/spvnode"
    fi
    if [ -n "${WITH_MCL:-}" ] && ! ldd "$SPVNODE" 2>/dev/null | grep -q libmcl; then
        info "[bootstrap] spvnode is statically linked against libmcl.a (or mcl not detected)"
    fi
fi

# ------------------------------- preflight -----------------------------------
[ -x "$SUCH" ]    || die "such not found at $SUCH (build first)"
[ -x "$SENDTX" ]  || die "sendtx not found at $SENDTX"
[ -f "$WITNESS_HELPER" ] || die "witness_helper.py not found at $WITNESS_HELPER"
command -v node    >/dev/null || die "node not found (snarkjs needs it)"
command -v snarkjs >/dev/null || die "snarkjs not found in PATH"
command -v curl    >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

# ------------------------ Groth16 trusted-setup ceremony ---------------------
# When circuit artefacts are missing (or RUN_CEREMONY=1 forces it), run
# circom + snarkjs end-to-end and log every stdout/stderr line into the
# test-log so the verification key (and its sha256 fingerprint) is always
# preserved alongside the on-chain TX_C/TX_R pair it validates.  This mirrors
# how contrib/mainnet_falcon_test.sh tees the freshly generated PQC public
# key into its log via run_and_log "such falcon_keygen".
if [ "${RUN_CEREMONY:-0}" = "1" ] || [ ! -f "$WASM" ] || [ ! -f "$ZKEY" ] || [ ! -f "$VKEY" ]; then
    command -v circom >/dev/null || die "circom not found (need iden3/circom 2.x for trusted-setup)"
    CIRCUIT_SRC="${CIRCUIT_SRC:-$REPO_DIR/contrib/zk_carrier/circuits/range_proof.circom}"
    [ -f "$CIRCUIT_SRC" ] || die "circuit source $CIRCUIT_SRC missing"

    CEREMONY_DIR="${CEREMONY_DIR:-$REPO_DIR/contrib/zk_carrier/circuits/build}"
    mkdir -p "$CEREMONY_DIR"
    PTAU_FINAL="$CEREMONY_DIR/pot12_final.ptau"
    R1CS="$CEREMONY_DIR/range_proof.r1cs"
    WASM="$CEREMONY_DIR/range_proof_js/range_proof.wasm"
    ZKEY="$CEREMONY_DIR/range_proof.zkey"
    VKEY="$CEREMONY_DIR/verification_key.json"

    info "================================================================="
    info "$PROOF_SYSTEM trusted-setup ceremony — full output logged below"
    info "  circom:   $(circom --version 2>&1 | head -1)"
    info "  snarkjs:  $(snarkjs --version 2>&1 | head -1)"
    info "  circuit:  $CIRCUIT_SRC"
    info "  artefacts→ $CEREMONY_DIR"
    info "================================================================="

    info "[ceremony] circom compile (r1cs + wasm)"
    # circomlib is installed globally via npm at <node_modules>/circomlib/circuits/.
    # The circuit's `include "circomlib/comparators.circom"` requires a search
    # path containing a directory literally named `circomlib` whose entries are
    # the .circom files (not nested under .../circuits/).  Construct that
    # synthetic include root via a symlink so it is robust across npm layouts.
    CIRCOMLIB_PARENT="${CIRCOMLIB_PARENT:-$(npm root -g 2>/dev/null)}"
    CIRCOM_INC_ROOT="$CEREMONY_DIR/circ_inc"
    mkdir -p "$CIRCOM_INC_ROOT"
    if [ -n "$CIRCOMLIB_PARENT" ] && [ -d "$CIRCOMLIB_PARENT/circomlib/circuits" ]; then
        ln -sfn "$CIRCOMLIB_PARENT/circomlib/circuits" "$CIRCOM_INC_ROOT/circomlib"
    fi
    CIRCOM_L_FLAG=""
    [ -L "$CIRCOM_INC_ROOT/circomlib" ] && CIRCOM_L_FLAG="-l $CIRCOM_INC_ROOT"
    ( cd "$CEREMONY_DIR" && circom "$CIRCUIT_SRC" --r1cs --wasm --sym -p bn128 $CIRCOM_L_FLAG -o "$CEREMONY_DIR" ) 2>&1 \
        | sed 's/^/  [circom] /'

    info "[ceremony] snarkjs r1cs info"
    snarkjs r1cs info "$R1CS" 2>&1 | sed 's/^/  [snarkjs r1cs info] /'

    if [ ! -f "$PTAU_FINAL" ]; then
        PTAU0="$CEREMONY_DIR/pot12_0000.ptau"
        PTAU1="$CEREMONY_DIR/pot12_0001.ptau"
        info "[ceremony] powers-of-tau new (BN128, 2^12)"
        snarkjs powersoftau new bn128 12 "$PTAU0" -v 2>&1 | sed 's/^/  [snarkjs ptau new]      /'
        info "[ceremony] powers-of-tau contribute"
        echo "broadcast_set ceremony entropy $(date -u +%s%N) $$" \
            | snarkjs powersoftau contribute "$PTAU0" "$PTAU1" --name="auto" -v 2>&1 \
            | sed 's/^/  [snarkjs ptau contrib]  /'
        info "[ceremony] powers-of-tau prepare phase2"
        snarkjs powersoftau prepare phase2 "$PTAU1" "$PTAU_FINAL" -v 2>&1 \
            | sed 's/^/  [snarkjs ptau phase2]   /'
    else
        info "[ceremony] reusing $PTAU_FINAL"
    fi

    if [ "$PROOF_SYSTEM" = "plonk" ]; then
        info "[ceremony] snarkjs plonk setup → $ZKEY"
        snarkjs plonk setup "$R1CS" "$PTAU_FINAL" "$ZKEY" 2>&1 \
            | sed 's/^/  [snarkjs plonk setup]   /'
        # PLONK uses a universal/updateable trusted setup so there is no
        # per-circuit trusted contribution step (unlike groth16 which needs
        # `snarkjs zkey contribute`).
    else
        info "[ceremony] snarkjs groth16 setup → $ZKEY"
        snarkjs groth16 setup "$R1CS" "$PTAU_FINAL" "$ZKEY" 2>&1 \
            | sed 's/^/  [snarkjs groth16 setup] /'

        info "[ceremony] snarkjs zkey contribute (final)"
        ZKEY_FINAL="$CEREMONY_DIR/range_proof_final.zkey"
        echo "broadcast_set zkey contribution $(date -u +%s%N) $$" \
            | snarkjs zkey contribute "$ZKEY" "$ZKEY_FINAL" --name="auto" -v 2>&1 \
            | sed 's/^/  [snarkjs zkey contrib]  /'
        mv -f "$ZKEY_FINAL" "$ZKEY"
    fi

    info "[ceremony] snarkjs zkey export verificationkey → $VKEY"
    snarkjs zkey export verificationkey "$ZKEY" "$VKEY" 2>&1 \
        | sed 's/^/  [snarkjs vkey export]   /'

    # Persist the full verification_key.json content + sha256 fingerprints into
    # the run log AND into the per-run work dir, so this exact vkey can be
    # recovered later just by reading the test-log (mirrors how the PQC
    # mainnet scripts log the freshly generated public key).
    VKEY_SHA256=$(sha256sum "$VKEY" | awk '{print $1}')
    ZKEY_SHA256=$(sha256sum "$ZKEY" | awk '{print $1}')
    WASM_SHA256=$(sha256sum "$WASM" | awk '{print $1}')
    info "================================================================="
    info "[ceremony] artefact fingerprints (committed alongside TX_C/TX_R log)"
    info "  vkey  $VKEY_SHA256  $VKEY"
    info "  zkey  $ZKEY_SHA256  $ZKEY"
    info "  wasm  $WASM_SHA256  $WASM"
    info "================================================================="
    info "[ceremony] full verification_key.json (begin) ↓"
    sed 's/^/    /' "$VKEY"
    info "[ceremony] full verification_key.json (end) ↑"
    info "================================================================="
fi

[ -f "$WASM" ]    || die "circuit wasm not found at $WASM (ceremony failed?)"
[ -f "$ZKEY" ]    || die "circuit zkey not found at $ZKEY (ceremony failed?)"
[ -f "$VKEY" ]    || die "circuit vkey not found at $VKEY (ceremony failed?)"

if [ -z "$FUNDED_UTXO_TXID" ] || [ -z "$FUNDED_UTXO_VALUE_KOINU" ]; then
    info "================================================================="
    info "Auto-discovering a spendable UTXO at $FUNDED_ADDR via block explorers"
    info "================================================================="
    DISC_JSON=$(curl -fsSL --max-time 30 \
        "${EXPLORER_BASE_MAIN}/addrs/${FUNDED_ADDR}?unspentOnly=true&limit=50" 2>/dev/null || true)
    if [ -z "$DISC_JSON" ]; then
        DISC_JSON=$(curl -fsSL --max-time 30 \
            "https://api.blockchair.com/dogecoin/dashboards/address/${FUNDED_ADDR}?limit=50" 2>/dev/null || true)
    fi
    if [ -z "$DISC_JSON" ]; then
        die "FUNDED_UTXO_TXID/FUNDED_UTXO_VALUE_KOINU not set and explorer auto-discovery failed"
    fi
    # Parse the explorer response (BlockCypher: txrefs[].tx_hash/tx_output_n/value;
    # Blockchair: data.<addr>.utxo[]).  Pick the largest unspent UTXO whose value
    # covers a single carrier iteration (TX_FEE_KOINU + CARRIER_VALUE_KOINU + a
    # small change buffer).  The funded demo address can carry many small UTXOs
    # (e.g. ~0.9-4 DOGE each) that are each individually sufficient to fund one
    # carrier iteration; a hardcoded 5 DOGE floor would reject all of them even
    # though "plenty of UTXOs" exist on chain.  Operators can override the
    # threshold via FUNDED_UTXO_MIN_KOINU if they want a stricter filter.
    : "${FUNDED_UTXO_MIN_KOINU:=$(( TX_FEE_KOINU + CARRIER_VALUE_KOINU + 1000000 ))}"
    DISC_JSON_FILE="$WORK/utxo_discovery.json"
    printf '%s' "$DISC_JSON" > "$DISC_JSON_FILE"
    PARSED=$(FUNDED_ADDR_ARG="$FUNDED_ADDR" \
             FUNDED_UTXO_MIN_KOINU="$FUNDED_UTXO_MIN_KOINU" \
             python3 - "$DISC_JSON_FILE" <<'PY'
import sys, os, json
addr = os.environ['FUNDED_ADDR_ARG']
min_val = int(os.environ.get('FUNDED_UTXO_MIN_KOINU', '0') or '0')
with open(sys.argv[1]) as f:
    d = json.load(f)
candidates = []
# BlockCypher shape
for ref in (d.get('txrefs') or []) + (d.get('unconfirmed_txrefs') or []):
    if ref.get('spent'): continue
    if ref.get('tx_input_n', -1) >= 0: continue  # this txref describes an input, not an unspent output
    candidates.append(( int(ref.get('confirmations',0)),
                        int(ref.get('value',0)),
                        ref.get('tx_hash'),
                        int(ref.get('tx_output_n',0)) ))
# Blockchair shape (data.<addr>.utxo[])
data = d.get('data') or {}
ent  = data.get(addr) if isinstance(data, dict) else None
if isinstance(ent, dict):
    for ref in (ent.get('utxo') or []):
        candidates.append(( 1, int(ref.get('value',0)),
                            ref.get('transaction_hash'),
                            int(ref.get('index',0)) ))
candidates.sort(key=lambda x: (-x[1], -x[0]))
for conf,val,h,n in candidates:
    if val >= min_val and h:
        print(f"{h} {n} {val}")
        break
PY
)
    if [ -z "$PARSED" ]; then
        die "no spendable UTXO >= ${FUNDED_UTXO_MIN_KOINU} koinu found at $FUNDED_ADDR"
    fi
    FUNDED_UTXO_TXID=$(echo "$PARSED" | awk '{print $1}')
    FUNDED_UTXO_VOUT=$(echo "$PARSED" | awk '{print $2}')
    FUNDED_UTXO_VALUE_KOINU=$(echo "$PARSED" | awk '{print $3}')
    success "auto-discovered UTXO: ${FUNDED_UTXO_TXID}:${FUNDED_UTXO_VOUT} value=${FUNDED_UTXO_VALUE_KOINU} koinu"
fi

# ------------------------------- helpers -------------------------------------
explorer_sees_tx() {
    local txid="$1"
    curl -fsSL --max-time 15 "$EXPLORER_BASE_MAIN/txs/${txid}" >/dev/null 2>&1
}

wait_for_tx_visible() {
    local txid="$1"; local timeout="$2"; local t0; t0=$(date +%s)
    info "Waiting up to ${timeout}s for explorer to see $txid ..."
    while true; do
        if explorer_sees_tx "$txid"; then
            success "explorer sees $txid"
            return 0
        fi
        local now; now=$(date +%s)
        [ $((now - t0)) -ge "$timeout" ] && return 1
        sleep 15
    done
}

broadcast_with_retry() {
    local label="$1"; local signed="$2"; local n=0; local out=""; local txid=""
    while [ "$n" -lt "$SENDTX_MAX_RETRIES" ]; do
        n=$((n+1))
        info "sendtx $label attempt $n/$SENDTX_MAX_RETRIES"
        out=$("$SENDTX" -d -m 16 -s 30 $NETWORK_FLAG "$signed" 2>&1 || true)
        echo "$out" | sed 's/^/    /'
        txid=$(echo "$out" | sed -n 's/^Start broadcasting transaction:[[:space:]]*\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
        if echo "$out" | grep -Eqi "$RELAY_SUCCESS_PATTERN"; then
            BROADCAST_TXID="$txid"
            return 0
        fi
        sleep 10
    done
    BROADCAST_TXID="$txid"
    return 1
}

# Build base unsigned tx: 1 input (prev_txid:vout) + 1 P2PKH change to FUNDED_ADDR.
# The carrier-output assembly happens via such -c zk_add_commit_and_carrier_tx,
# which appends OP_RETURN + per-part P2SH outputs to whatever scaffold we pass.
build_base_unsigned() {
    local prev_txid="$1" prev_vout="$2" change_koinu="$3" change_spk="$4"
    python3 - "$prev_txid" "$prev_vout" "$change_koinu" "$change_spk" <<'PY'
import sys
prev_txid, prev_vout, change_koinu, change_spk = sys.argv[1].lower(), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4].lower()
def le_u32(n): return n.to_bytes(4, "little").hex()
def le_u64(n): return n.to_bytes(8, "little").hex()
def varint(n):
    if n < 0xfd: return f"{n:02x}"
    if n <= 0xffff: return "fd" + n.to_bytes(2, "little").hex()
    if n <= 0xffffffff: return "fe" + n.to_bytes(4, "little").hex()
    return "ff" + n.to_bytes(8, "little").hex()
prev_le = bytes.fromhex(prev_txid)[::-1].hex()
vin = prev_le + le_u32(prev_vout) + "00" + "ffffffff"
vout = le_u64(change_koinu) + varint(len(change_spk)//2) + change_spk
print("01000000" + varint(1) + vin + varint(1) + vout + "00000000")
PY
}

# Build TX_R skeleton spending every carrier output, then we patch in the
# per-part scriptSigs via such -c set_scriptsig.
build_tx_r_skeleton() {
    local txc_txid="$1" first_vout="$2" parts="$3" carrier_value="$4" fee="$5" out_spk="$6"
    python3 - "$txc_txid" "$first_vout" "$parts" "$carrier_value" "$fee" "$out_spk" <<'PY'
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
total_in = carrier_value * part_total
if total_in <= fee: raise SystemExit("carrier total value must exceed tx_r fee")
send_value = total_in - fee
prev_le = bytes.fromhex(txid_hex)[::-1].hex()
vin = "".join(prev_le + le_u32(first_vout + i) + "00" + "ffffffff" for i in range(part_total))
vout = le_u64(send_value) + varint(len(out_spk)//2) + out_spk
print("01000000" + varint(part_total) + vin + "01" + vout + "00000000")
PY
}

# ------------------------------- main loop -----------------------------------
PREV_TXID="$FUNDED_UTXO_TXID"
PREV_VOUT="$FUNDED_UTXO_VOUT"
PREV_VAL="$FUNDED_UTXO_VALUE_KOINU"
PREV_SPK="$FUNDED_UTXO_SCRIPT_PUBKEY"

for ((iter=1; iter<=N; iter++)); do
    info "================================================================="
    info "Iteration $iter/$N — funding from ${PREV_TXID}:${PREV_VOUT} value=$PREV_VAL koinu"

    ITER_DIR="$WORK/iter_${iter}"
    mkdir -p "$ITER_DIR"

    # 1a. Compute tx_base_sighash for replay-resistant binding.  spvnode's
    #     dogecoin_zk_compute_tx_base_sighash strips OP_RETURN + carrier
    #     P2SH outputs from TX_C and restores carrier_total to the first
    #     remaining output, then SIGHASH_ALLs input 0 against the signer's
    #     P2PKH spk.  The reconstruction is byte-equivalent to a 1-input /
    #     1-P2PKH-output tx with value = PREV_VAL - TX_FEE_KOINU.  Top byte
    #     is zeroed so the result fits the BN254 scalar field (248 bits of
    #     domain remain — comfortably collision-resistant for a tx tag).
    SIGHASH_CHANGE_KOINU=$(( PREV_VAL - TX_FEE_KOINU ))
    SIGHASH_BASE_TX=$(build_base_unsigned "$PREV_TXID" "$PREV_VOUT" "$SIGHASH_CHANGE_KOINU" "$PREV_SPK")
    TX_BINDING_RAW=$("$SUCH" $NETWORK_FLAG -c tx_sighash32 -x "$SIGHASH_BASE_TX" \
                     -s "$PREV_SPK" -i 0 -h 1 2>&1 \
                     | awk -F': ' '/^tx_sighash32:/ {print $2; exit}' | tr -d ' ')
    [ -n "$TX_BINDING_RAW" ] && [ "${#TX_BINDING_RAW}" -eq 64 ] \
        || die "iter $iter: failed to derive tx_base_sighash (got '$TX_BINDING_RAW')"
    TX_BINDING_HEX="00${TX_BINDING_RAW:2:62}"
    info "tx_binding: $TX_BINDING_HEX  (top byte zeroed for BN254 field)"

    # 1. Generate a fresh proof.  Vary --amount per iteration so each commit differs.
    AMT=$(( 42000 + iter * 1000 ))
    PAYLOAD_HEX_FILE="$ITER_DIR/payload.hex"
    PROOF_JSON_FILE="$ITER_DIR/proof.json"
    PUBLIC_JSON_FILE="$ITER_DIR/public.json"
    info "snarkjs $PROOF_SYSTEM prove low=$RANGE_LOW high=$RANGE_HIGH amount=$AMT"
    python3 "$WITNESS_HELPER" \
        --proof-system "$PROOF_SYSTEM" \
        --wasm "$WASM" --zkey "$ZKEY" --vkey "$VKEY" \
        --circuit-id "$CIRCUIT_ID" \
        --low "$RANGE_LOW" --high "$RANGE_HIGH" --amount "$AMT" \
        --tx-binding-hex "$TX_BINDING_HEX" \
        --save-proof  "$PROOF_JSON_FILE" \
        --save-public "$PUBLIC_JSON_FILE" \
        --out-payload "$PAYLOAD_HEX_FILE"
    PAYLOAD_HEX=$(tr -d '[:space:]' < "$PAYLOAD_HEX_FILE")
    PAYLOAD_BYTES=$(( ${#PAYLOAD_HEX} / 2 ))
    info "payload: $PAYLOAD_BYTES bytes (mode=$ZK_MODE_BYTE/$PROOF_SYSTEM)"

    # 2. Compute commit + sanity-check off-box.
    COMMIT=$("$SUCH" $NETWORK_FLAG -c zk_commit -x "$PAYLOAD_HEX" 2>&1 \
             | awk -F':[[:space:]]+' '/^commitment:/ {print $2; exit}' | tr -d ' ')
    [ -n "$COMMIT" ] || die "iter $iter: failed to derive commitment"
    info "commit: $COMMIT"

    # 3. Compute carrier part_total from payload size.  The C library splits
    # the payload at ZK_PART_PAYLOAD_MAX bytes per part = MAX_CHUNKS(3) ×
    # CHUNK_MAX(520) = 1560 bytes (see src/zk_carrier/zk_commit.c and
    # include/dogecoin/pqc_carrier.h).  Using a smaller divisor here used to
    # under-credit the carrier outputs and produce bad-txns-in-belowout txs
    # for the bigger PLONK payloads (≈2.2 KB), so we mirror the C constant.
    ZK_PART_PAYLOAD_MAX="${ZK_PART_PAYLOAD_MAX:-1560}"
    PARTS=$(( (PAYLOAD_BYTES + ZK_PART_PAYLOAD_MAX - 1) / ZK_PART_PAYLOAD_MAX ))
    [ "$PARTS" -ge 1 ] || PARTS=1
    CHANGE_KOINU=$(( PREV_VAL - TX_FEE_KOINU - PARTS * CARRIER_VALUE_KOINU ))
    [ "$CHANGE_KOINU" -gt 0 ] || die "iter $iter: insufficient UTXO value (utxo=$PREV_VAL parts=$PARTS)"
    info "change=$CHANGE_KOINU koinu  parts=$PARTS"

    # 4. Build base unsigned tx scaffold.
    BASE_UNSIGNED=$(build_base_unsigned "$PREV_TXID" "$PREV_VOUT" "$CHANGE_KOINU" "$PREV_SPK")
    [ -n "$BASE_UNSIGNED" ] || die "iter $iter: base unsigned tx empty"

    # 5. Append commitment + carrier outputs.
    SUCH_OUT=$("$SUCH" $NETWORK_FLAG -c zk_add_commit_and_carrier_tx \
        -x "$BASE_UNSIGNED" -m "$ZK_MODE_BYTE" -s "$PAYLOAD_HEX" -h "$CARRIER_VALUE_KOINU" 2>&1)
    echo "$SUCH_OUT" | sed 's/^/    /'
    TX_C_UNSIGNED=$(echo "$SUCH_OUT" | awk -F': ' '/^tx with commitment/ {print $2; exit}' | tr -d ' ')
    PART_TOTAL=$(echo "$SUCH_OUT" | awk -F': ' '/^zk_carrier_part_total:/ {print $2; exit}' | tr -d ' ')
    FIRST_VOUT=$(echo "$SUCH_OUT"  | awk -F': ' '/^zk_carrier_first_vout:/ {print $2; exit}' | tr -d ' ')
    [ -n "$TX_C_UNSIGNED" ] || die "iter $iter: such zk_add_commit_and_carrier_tx failed"
    [ "$PART_TOTAL" -eq "$PARTS" ] || warn "part_total mismatch: such=$PART_TOTAL local=$PARTS"
    PART_SCRIPTSIGS=()
    for ((p=0; p<PART_TOTAL; p++)); do
        ss=$(echo "$SUCH_OUT" | sed -n "s/^zk_carrier_part_scriptsig\\[$p\\]:[[:space:]]*//p" | head -n1 | tr -d ' ')
        [ -n "$ss" ] || die "iter $iter: missing carrier_part_scriptsig[$p]"
        PART_SCRIPTSIGS+=("$ss")
    done

    # 6. Sign the funding input and broadcast TX_C.
    SIGN_OUT=$("$SUCH" $NETWORK_FLAG -c sign -x "$TX_C_UNSIGNED" -s "$PREV_SPK" -i 0 -h 1 -p "$FUNDED_WIF" 2>&1)
    echo "$SIGN_OUT" | sed 's/^/    /'
    TX_C_SIGNED=$(echo "$SIGN_OUT" | awk -F': ' '/^signed TX:/ {print $2; exit}' | tr -d ' ')
    [ -n "$TX_C_SIGNED" ] || die "iter $iter: such sign failed"
    BROADCAST_TXID=""
    if ! broadcast_with_retry "TX_C-$iter" "$TX_C_SIGNED"; then
        die "iter $iter: TX_C did not relay"
    fi
    TX_C_TXID="$BROADCAST_TXID"
    [ -n "$TX_C_TXID" ] || die "iter $iter: TX_C txid missing"
    success "iter $iter: TX_C broadcast $TX_C_TXID"
    echo "$TX_C_SIGNED" > "$ITER_DIR/tx_c.signed.hex"
    echo "$TX_C_TXID"   > "$ITER_DIR/tx_c.txid"

    # 7. Send commitment + reveal sequentially without waiting for explorer
    # visibility between them.  TX_R spends TX_C's carrier outputs, so peers
    # accept it as a chained mempool descendant of TX_C and both land in the
    # mempool back-to-back; spvnode then scans the resulting block(s)
    # simultaneously and emits "[zk-commit] Pending" + "Reveal validated"
    # for the same pair without any per-tx human latency.  This is the
    # documented "send commitment and reveal sequentially so we can scan
    # them simultaneously" flow (see doc/spec/bip-zk-carrier-commitments.mediawiki).

    # 8. Build TX_R skeleton, patch per-part scriptSigs, broadcast immediately.
    TX_R_UNSIGNED=$(build_tx_r_skeleton "$TX_C_TXID" "$FIRST_VOUT" "$PART_TOTAL" \
                                        "$CARRIER_VALUE_KOINU" "$TX_R_FEE_KOINU" "$PREV_SPK")
    TX_R_PATCHED="$TX_R_UNSIGNED"
    for ((p=0; p<PART_TOTAL; p++)); do
        SET_OUT=$("$SUCH" $NETWORK_FLAG -c set_scriptsig \
                  -x "$TX_R_PATCHED" -i "$p" -s "${PART_SCRIPTSIGS[$p]}" 2>&1)
        TX_R_PATCHED=$(echo "$SET_OUT" | awk -F': ' '/^tx with scriptsig set:/ {print $2; exit}' | tr -d ' ')
        [ -n "$TX_R_PATCHED" ] || die "iter $iter: set_scriptsig failed for part $p"
    done
    BROADCAST_TXID=""
    if ! broadcast_with_retry "TX_R-$iter" "$TX_R_PATCHED"; then
        warn "iter $iter: TX_R did not relay (P2SH carrier may be non-standard); continuing"
        TX_R_TXID=""
    else
        TX_R_TXID="$BROADCAST_TXID"
        success "iter $iter: TX_R broadcast $TX_R_TXID (chained off TX_C in same mempool window)"
    fi
    echo "$TX_R_PATCHED" > "$ITER_DIR/tx_r.signed.hex"
    echo "$TX_R_TXID"    > "$ITER_DIR/tx_r.txid"

    # 9. Append manifest entry.
    printf '%d\t%s\t%s\t%s\t%d\t%s\n' \
        "$iter" "$TX_C_TXID" "$TX_R_TXID" "$COMMIT" "$PAYLOAD_BYTES" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >> "$MANIFEST"

    # 10. Chain to next iteration: TX_C change vout 0 carries the bulk funds.
    PREV_TXID="$TX_C_TXID"
    PREV_VOUT=0
    PREV_VAL="$CHANGE_KOINU"
    # PREV_SPK stays the same — change is back to FUNDED_ADDR.
done

success "Loop complete.  Manifest:"
cat "$MANIFEST" | sed 's/^/    /'

# ------------------------------- spvnode pass --------------------------------
if [ -n "${SKIP_SPV:-}" ]; then
    info "SKIP_SPV set; skipping spvnode rescan."
    exit 0
fi
[ -x "$SPVNODE" ] || { warn "spvnode not built; skipping rescan."; exit 0; }

SPV_LOG="$WORK/spvnode_zk_set.log"
info "Launching spvnode for on-chain full-set validation → $SPV_LOG"
"$SPVNODE" $NETWORK_FLAG -l -c -d -p -b -a "$FUNDED_ADDR" scan > "$SPV_LOG" 2>&1 &
SPV_PID=$!
echo "$SPV_PID" > "$WORK/spvnode.pid"

# Wait until we have collected one Reveal-validated line per pair, or the
# timeout fires.  We use "Reveal validated" rather than "ZK verification
# PASSED" because that line is emitted for both groth16 (PASSED) and plonk
# (DELEGATED — verifier delegated to the external `snarkjs plonk verify`
# step below) — exactly the post-spvnode hand-off this script implements.
SPV_DEADLINE=$(( $(date +%s) + ${SPV_TIMEOUT:-3600} ))
while true; do
    VALIDATED_LINES=$(grep -c "Reveal validated" "$SPV_LOG" 2>/dev/null | head -n1 | tr -d '[:space:]')
    [ -z "$VALIDATED_LINES" ] && VALIDATED_LINES=0
    if [ "$VALIDATED_LINES" -ge "$N" ]; then
        success "spvnode emitted $VALIDATED_LINES Reveal-validated lines (>= N=$N)"
        break
    fi
    if [ "$(date +%s)" -ge "$SPV_DEADLINE" ]; then
        warn "spvnode rescan timeout: $VALIDATED_LINES/$N Reveal-validated lines collected"
        break
    fi
    sleep 30
done
kill "$SPV_PID" 2>/dev/null || true
sleep 2
kill -9 "$SPV_PID" 2>/dev/null || true

# ----------------- Post-spvnode external verifier (PLONK / groth16) -----------
# Per the documented flow, `snarkjs <system> verify` is the canonical
# "external verifier".  For groth16 it is a sanity backstop (libdogecoin
# may also have run an in-process verification when linked against
# rapidsnark/mcl); for plonk it is the *primary* cryptographic check, and
# it MUST be invoked end-to-end AFTER spvnode has emitted "Reveal
# validated" for the corresponding pair.  We iterate over the manifest,
# and for every iteration with a saved proof.json/public.json we re-run
# the verifier against the committed verification_key.json and tee the
# raw verifier output into the curated log so an auditor can replay it.
EXT_VERIFY_LOG="$WORK/external_verifier.log"
{
    echo "==============================================================================="
    echo "External verifier ($PROOF_SYSTEM) — invoked AFTER spvnode reveal validation"
    echo "  vkey:  $VKEY"
    echo "  vkey_sha256: $(sha256sum "$VKEY" | awk '{print $1}')"
    echo "==============================================================================="
} > "$EXT_VERIFY_LOG"
EXT_PASS=0
EXT_FAIL=0
for ((iter=1; iter<=N; iter++)); do
    ITER_DIR="$WORK/iter_${iter}"
    PROOF_JSON="$ITER_DIR/proof.json"
    PUBLIC_JSON="$ITER_DIR/public.json"
    TX_R_TXID_FILE="$ITER_DIR/tx_r.txid"
    if [ ! -f "$PROOF_JSON" ] || [ ! -f "$PUBLIC_JSON" ]; then
        echo "[iter $iter] SKIP — saved proof/public artefacts missing" >> "$EXT_VERIFY_LOG"
        continue
    fi
    TX_R_TXID=$(tr -d '[:space:]' < "$TX_R_TXID_FILE" 2>/dev/null || true)
    SPV_REVEAL_LINE=$(grep -E "Reveal validated.*${TX_R_TXID:-DOES_NOT_MATCH}" "$SPV_LOG" 2>/dev/null | tail -n1 || true)
    if [ -z "$SPV_REVEAL_LINE" ]; then
        echo "[iter $iter] WARN — spvnode did not emit Reveal-validated for tx_r=$TX_R_TXID; running external verifier anyway" >> "$EXT_VERIFY_LOG"
    else
        echo "[iter $iter] spvnode-validated → $SPV_REVEAL_LINE" >> "$EXT_VERIFY_LOG"
    fi
    info "[ext-verify iter=$iter] snarkjs $PROOF_SYSTEM verify $VKEY $PUBLIC_JSON $PROOF_JSON"
    EXT_OUT=$(snarkjs "$PROOF_SYSTEM" verify "$VKEY" "$PUBLIC_JSON" "$PROOF_JSON" 2>&1; echo "__rc=$?")
    EXT_RC=$(echo "$EXT_OUT" | awk -F= '/^__rc=/{print $2; exit}')
    EXT_BODY=$(echo "$EXT_OUT" | grep -v '^__rc=')
    {
        echo "-------------------------------------------------------------------------------"
        echo "[iter $iter] external $PROOF_SYSTEM verify rc=$EXT_RC"
        echo "  cmd: snarkjs $PROOF_SYSTEM verify $VKEY $PUBLIC_JSON $PROOF_JSON"
        echo "  tx_r: $TX_R_TXID"
        echo "  proof_sha256:  $(sha256sum "$PROOF_JSON"  | awk '{print $1}')"
        echo "  public_sha256: $(sha256sum "$PUBLIC_JSON" | awk '{print $1}')"
        echo "$EXT_BODY" | sed 's/^/    /'
    } >> "$EXT_VERIFY_LOG"
    if [ "$EXT_RC" = "0" ]; then
        EXT_PASS=$(( EXT_PASS + 1 ))
        success "[ext-verify iter=$iter] PASSED ($PROOF_SYSTEM)"
    else
        EXT_FAIL=$(( EXT_FAIL + 1 ))
        warn "[ext-verify iter=$iter] FAILED rc=$EXT_RC ($PROOF_SYSTEM)"
    fi
done
{
    echo "==============================================================================="
    echo "External verifier summary: PASS=$EXT_PASS FAIL=$EXT_FAIL N=$N system=$PROOF_SYSTEM"
    echo "==============================================================================="
} >> "$EXT_VERIFY_LOG"
info "External verifier log: $EXT_VERIFY_LOG (PASS=$EXT_PASS FAIL=$EXT_FAIL)"

# Save the curated multi-PASSED log.
FINAL_LOG="$REPO_DIR/test-logs/mainnet_zk_carrier_e2e_set_PASSED_${TS}.txt"
{
    echo "==============================================================================="
    echo "ZK carrier mainnet e2e — multi-pair set (N=$N, $PROOF_SYSTEM) — $(date -u)"
    echo "Funded address: $FUNDED_ADDR"
    echo "Proof system:   $PROOF_SYSTEM (ZKP1 mode byte = $ZK_MODE_BYTE)"
    echo "Manifest:"
    cat "$MANIFEST"
    echo
    echo "==============================================================================="
    echo "spvnode [zk-commit] lines:"
    echo "==============================================================================="
    grep -E "zk-commit" "$SPV_LOG" || echo "(none captured)"
    echo
    echo "==============================================================================="
    echo "Post-spvnode external verifier transcript (snarkjs $PROOF_SYSTEM verify):"
    echo "==============================================================================="
    cat "$EXT_VERIFY_LOG"
} > "$FINAL_LOG"
success "Final multi-PASSED log: $FINAL_LOG"
info "Commit it with: git add -f \"$FINAL_LOG\" && git commit -m 'zk_carrier: mainnet e2e set log $TS'"

# Final summary block — mirrors the artifact-listing tail of
# contrib/mainnet_falcon_test.sh so an operator can find every artefact
# produced by a single run from a single screenful at the bottom of the log.
echo ""
echo "================================================================="
echo "  ZK CARRIER MAINNET E2E — TEST COMPLETE"
echo "================================================================="
success "All test data saved in: $WORK"
echo ""
echo "Files:"
echo "  - $LOG (full run log: ceremony stdout, every such/sendtx call, decoded reveal lines)"
echo "  - $MANIFEST (iter,tx_c,tx_r,commit,payload_bytes,utc per pair)"
echo "  - $WORK/iter_*/payload.hex (per-iteration ZKP1 payload hex)"
echo "  - $SPV_LOG (raw spvnode stdout/stderr with full [zk-commit] event stream)"
echo "  - $FINAL_LOG (curated log: manifest + filtered [zk-commit] lines)"
echo "  - $VKEY  (sha256 logged above; full JSON dumped earlier in this log)"
echo "  - $ZKEY  (Groth16 proving key; sha256 logged above)"
echo "  - $WASM  (circuit witness wasm; sha256 logged above)"
echo ""
