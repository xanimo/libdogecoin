#!/usr/bin/env bash
# sanitizer_sweep.sh — reproducible ASan+UBSan sweep of the libdogecoin test
# suite, for the security assurance case.
#
# Runs the full `tests` binary under sanitizers over a clean checkout and
# records every finding. The intent is documentation, not fixing: it enumerates
# which sanitizer faults are reachable on the target branch so they can be tied
# to their fix PRs.
#
# Two passes are run because the two sanitizers recover differently:
#   * UBSan pass: undefined behavior is recoverable, so a single run enumerates
#     ALL reachable UB sites (the process continues past each).
#   * ASan pass: a real memory fault is not recoverable; ASan halts at the first
#     one. The pass therefore reports the first-reached memory error. If that is
#     fixed, a re-run reveals the next. This is noted in the output so a reader
#     does not mistake "one ASan finding" for "only one exists."
#
# Usage:   contrib/assurance/sanitizer_sweep.sh [output_log]
# Env:     JOBS (default nproc)
# Requires: clang, autotools, libevent-dev. Run from a clean tree.
# Exit 0 if the sweep completed; findings are data, not errors.

set -uo pipefail

OUT="${1:-sanitizer_sweep.log}"
JOBS="${JOBS:-$(nproc)}"

build_and_run() {
    local label="$1" san_cflags="$2" san_ldflags="$3"
    echo "[*] [$label] configuring..." | tee -a "$OUT"
    make distclean >/dev/null 2>&1
    ./autogen.sh >/dev/null 2>&1
    ./configure CC=clang CXX=clang++ \
        CFLAGS="$san_cflags -fno-omit-frame-pointer -g -O1" \
        CXXFLAGS="$san_cflags -fno-omit-frame-pointer -g -O1" \
        LDFLAGS="$san_ldflags" \
        --enable-static --disable-shared >/dev/null 2>&1
    make -C src/secp256k1 >/dev/null 2>&1
    echo "[*] [$label] building test suite..." | tee -a "$OUT"
    if ! make tests -j"$JOBS" >/dev/null 2>&1; then
        echo "[!] [$label] build failed" | tee -a "$OUT"; return 1
    fi
    echo "[*] [$label] running tests..." | tee -a "$OUT"
    echo "----- BEGIN $label OUTPUT -----" >>"$OUT"
    ./tests >>"$OUT" 2>&1
    echo "----- END $label OUTPUT (test exit $?) -----" >>"$OUT"
}

{
  echo "=== libdogecoin sanitizer sweep ==="
  echo "date:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit:    $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "branch:    $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "clang:     $(clang --version | head -1)"
  echo "==================================="
  echo
} | tee "$OUT"

# Pass 1: UBSan (recoverable) — enumerates all UB sites in one run.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:report_error_type=1"
build_and_run "UBSAN" "-fsanitize=undefined" "-fsanitize=undefined"

# Pass 2: ASan (+leaks). Halts at first memory fault by nature.
export ASAN_OPTIONS="abort_on_error=0:halt_on_error=0:detect_leaks=1"
build_and_run "ASAN" "-fsanitize=address" "-fsanitize=address"

{
  echo
  echo "=== sweep summary ==="
  printf 'UBSan runtime errors:    %s\n' "$(grep -c 'runtime error:' "$OUT")"
  printf 'AddressSanitizer errors: %s\n' "$(grep -c 'ERROR: AddressSanitizer' "$OUT")"
  printf 'LeakSanitizer errors:    %s\n' "$(grep -c 'ERROR: LeakSanitizer' "$OUT")"
  echo
  echo "distinct finding messages:"
  grep -E 'runtime error:|ERROR: AddressSanitizer|ERROR: LeakSanitizer' "$OUT" \
    | sed -E 's/^.*(runtime error:|ERROR: (AddressSanitizer|LeakSanitizer))/\1/' \
    | sort | uniq -c | sort -rn
  echo
  echo "NOTE: ASan halts at the first unrecovered memory fault; if one is shown,"
  echo "re-run after fixing it to reveal any subsequent memory findings."
  echo "====================="
} | tee -a "$OUT"

echo "[*] sweep complete — log at ${OUT}"
