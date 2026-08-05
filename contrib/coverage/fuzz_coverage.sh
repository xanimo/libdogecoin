#!/usr/bin/env bash
# fuzz_coverage.sh — measure source coverage achieved by the libFuzzer
# harnesses, per the audit plan's reachability requirement: the assurance
# case needs to show what attack surface the fuzzers actually exercise,
# not just that they ran.
#
# Usage:
#   contrib/coverage/fuzz_coverage.sh [corpus_root]
#
#   corpus_root (optional): directory containing one corpus subdirectory
#   per target, named after the target (corpus_root/fuzz_tx, ...).
#   Targets with no corpus subdirectory get one generated in-place via a
#   short bounded fuzz run (SEED_RUNS inputs), so the script is usable
#   with zero prior state. Bring a real accumulated corpus for numbers
#   that mean anything: generated mini-corpora measure "what a few
#   minutes of fuzzing reaches", not "what the harness can reach".
#
# Environment:
#   SEED_RUNS   inputs per target when generating a corpus (default 20000)
#   MAX_LEN     -max_len passed to libFuzzer            (default 8192)
#   OUT_DIR     report output directory                 (default coverage-report)
#   LLVM_SUFFIX suffix for llvm tools, e.g. "-18"       (default autodetected)
#
# Requires: clang with matching llvm-profdata/llvm-cov, autotools, and a
# tree configured per the invocation below (the script reconfigures).
#
# Outputs (under $OUT_DIR):
#   html/index.html      browsable line-level coverage
#   summary.txt          llvm-cov report over first-party src/
#   uncovered.txt        first-party files sorted by uncovered lines,
#                        i.e. the priority list for the next harness

set -euo pipefail

CORPUS_ROOT="${1:-fuzz-corpora}"
SEED_RUNS="${SEED_RUNS:-20000}"
MAX_LEN="${MAX_LEN:-8192}"
OUT_DIR="${OUT_DIR:-coverage-report}"

# --- locate llvm tools matched to clang ---------------------------------
if [ -n "${LLVM_SUFFIX:-}" ]; then
    PROFDATA="llvm-profdata${LLVM_SUFFIX}"; COV="llvm-cov${LLVM_SUFFIX}"
elif command -v llvm-profdata >/dev/null 2>&1; then
    PROFDATA="llvm-profdata"; COV="llvm-cov"
else
    # try the versioned name matching clang's major version
    CLANG_MAJ="$(clang --version | sed -n 's/.*clang version \([0-9]*\).*/\1/p' | head -1)"
    PROFDATA="llvm-profdata-${CLANG_MAJ}"; COV="llvm-cov-${CLANG_MAJ}"
fi
command -v "$PROFDATA" >/dev/null || { echo "error: $PROFDATA not found" >&2; exit 1; }
command -v "$COV"      >/dev/null || { echo "error: $COV not found" >&2; exit 1; }

# --- build with coverage instrumentation --------------------------------
# Library objects need -fprofile-instr-generate -fcoverage-mapping so the
# coverage lands in src/, not just the harness files. The profile runtime
# must also be present at link; per-target LDFLAGS in Makefile.am are
# fixed, but automake always appends configure-level LDFLAGS, so it goes
# in there.
echo "== configuring with coverage instrumentation =="
./autogen.sh >/dev/null
./configure CC=clang CXX=clang++ \
    CFLAGS="-fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping -g -O1" \
    LDFLAGS="-fprofile-instr-generate" \
    --enable-static --disable-shared \
    --enable-fuzz >/dev/null

echo "== building harnesses =="
make -C src/secp256k1 >/dev/null 2>&1 || true
make fuzz fuzz/seed_logdb_corpus -j"$(nproc)" >/dev/null

TARGETS=""
for t in fuzz_tx fuzz_block fuzz_wtx fuzz_logdb fuzz_psbt fuzz_protocol; do
    [ -x "fuzz/$t" ] && TARGETS="$TARGETS $t"
done
echo "targets:$TARGETS"

# --- ensure a corpus per target, then replay under profiling ------------
mkdir -p "$CORPUS_ROOT" "$OUT_DIR"
rm -f "$OUT_DIR"/*.profraw "$OUT_DIR"/merged.profdata

for t in $TARGETS; do
    corpus="$CORPUS_ROOT/$t"
    if [ ! -d "$corpus" ] || [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
        echo "== $t: no corpus found, generating ($SEED_RUNS runs) =="
        mkdir -p "$corpus"
        # logdb gets checksum-valid seeds first so post-checksum paths count
        if [ "$t" = "fuzz_logdb" ] && [ -x fuzz/seed_logdb_corpus ]; then
            ./fuzz/seed_logdb_corpus "$corpus"
        fi
        LLVM_PROFILE_FILE=/dev/null ./fuzz/$t "$corpus" \
            -runs="$SEED_RUNS" -max_len="$MAX_LEN" \
            -rss_limit_mb=2048 -malloc_limit_mb=1024 >/dev/null 2>&1 || {
            echo "warning: $t exited nonzero during corpus generation (crash?); continuing with partial corpus" >&2
        }
    fi
    n=$(ls "$corpus" | wc -l)
    echo "== $t: replaying corpus ($n inputs) under profiling =="
    # bare file arguments = execute each input once, then exit
    LLVM_PROFILE_FILE="$OUT_DIR/$t.%p.profraw" ./fuzz/$t "$corpus"/* \
        -rss_limit_mb=2048 >/dev/null 2>&1 || {
        echo "warning: $t crashed during replay; profile up to crash point retained" >&2
    }
done

# --- merge and report ----------------------------------------------------
echo "== merging profiles =="
"$PROFDATA" merge -sparse "$OUT_DIR"/*.profraw -o "$OUT_DIR/merged.profdata"

# report against one binary with -object for the rest so shared library
# code is attributed once
set -- $TARGETS
FIRST="fuzz/$1"; shift
OBJECTS=""
for t in "$@"; do OBJECTS="$OBJECTS -object fuzz/$t"; done

# first-party scope: src/*.c at top level (vendored trees have their own
# directories and are excluded by the regex)
SCOPE='-ignore-filename-regex=(secp256k1|libevent|intel|logdb/|openenclave|optee|raccoon_g|zk_carrier|utf8proc|fuzz/)'

echo "== generating reports =="
"$COV" report "$FIRST" $OBJECTS \
    -instr-profile="$OUT_DIR/merged.profdata" $SCOPE \
    > "$OUT_DIR/summary.txt"

"$COV" show "$FIRST" $OBJECTS \
    -instr-profile="$OUT_DIR/merged.profdata" $SCOPE \
    -format=html -output-dir="$OUT_DIR/html"

# priority list: first-party .c files sorted by line coverage ascending
# (llvm-cov columns: Filename Regions MissedRegions Cover Functions
#  MissedFunctions Executed Lines MissedLines Cover Branches ...).
# Missed Lines is the absolute count that most directly answers "where
# is the biggest unexercised attack surface".
awk 'NR>2 && $1 ~ /\.c$/ {
        lines_cover=$(NF-3); missed_lines=$(NF-4);
        gsub("%","",lines_cover);
        printf "%6s%% lines  %8s missed  %s\n", lines_cover, missed_lines, $1
     }' "$OUT_DIR/summary.txt" 2>/dev/null | sort -n > "$OUT_DIR/uncovered.txt" || true

echo
echo "== totals =="
tail -1 "$OUT_DIR/summary.txt"
echo
echo "reports: $OUT_DIR/summary.txt, $OUT_DIR/uncovered.txt, $OUT_DIR/html/index.html"
