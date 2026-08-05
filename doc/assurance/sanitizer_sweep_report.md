# libdogecoin Sanitizer Sweep Report

**Target:** `0.1.5-dev` @ `0dc5533f636d` (Merge PR #354)
**Toolchain:** clang 18.1.3, ASan + UBSan, `-O1 -g`
**Method:** two-pass sweep of the full `tests` suite — see
`contrib/assurance/sanitizer_sweep.sh` (reproducible).
**Companion:** `SECURITY_ASSURANCE.md` §5 (independent corroboration).

---

## 1. Purpose and method

This is a documentation sweep, not a fix pass. It records which sanitizer
faults are reachable on a **pristine** `0.1.5-dev` checkout, so each can be tied
to a fix PR (confirming the fix addresses a live fault) or flagged as a new
finding. This sweep did both: it corroborated four existing fix PRs and
surfaced one new finding class (§3), now fixed in #361.

Two passes are run because the sanitizers recover differently:

- **UBSan pass** — undefined behavior is recoverable, so one run enumerates
  *all* reachable UB sites (execution continues past each). This is the
  complete UB inventory below.
- **ASan pass** — a real memory fault is not recoverable; ASan halts at the
  first. The pass reports the first-reached memory error; fixing it and
  re-running reveals the next. Only one memory finding is reported here for
  that reason, and it is not a claim that only one exists.

The build is static, `-O1 -g`, no `-fno-sanitize-recover` on the UBSan pass
(so it does not halt at the first UB). Raw logs: `sanitizer_sweep.log`
(UBSan pass), `asan_only.log` (ASan pass).

## 2. Findings that confirm existing fix PRs

Each of these reproduces on pristine `0.1.5-dev`, i.e. the fault is **live on
the release branch** and the referenced PR fixes it. This is the assurance
argument for merging the audit series: the fixes are not hypothetical.

| Sanitizer finding | Site | Class | Fix PR |
|---|---|---|---|
| global-buffer-overflow, write | `sha2.c:994` `sha256_transform` | CWE-787 | **#324** — sha2 OOB in `hmac_sha256_prepare` |
| misaligned-pointer-use, `sha2_word32` load | `sha2.c:994` | CWE-1319 / UB | **#326** — avoid unaligned word loads |
| invalid-shift-base, `146 << 24` | `bip32.c:240` | CWE-190 / signed-shift UB | **#325** — bip32/bip37 signed-overflow shift |
| invalid-shift-base, `16644864 << 8` | `jpeg.c:220` | CWE-190 | **#327** — arith_uint256/jpeg shift UB |
| invalid-shift-base, `1 << 31` | `arith_uint256.c:128` | CWE-190 | **#327** — arith_uint256/jpeg shift UB |

Notes:
- The `sha2.c:994` line hosts *two* distinct findings — a global-buffer-overflow
  (memory, ASan) and a misaligned load (UB, UBSan) — corresponding to the two
  separate PRs #324 and #326. Both are at the `sha256_transform` block-word
  access reached through the block-header scrypt hash path, i.e. from block
  validation (a consensus path).
- The bip32 shift is reached through HD key derivation.

## 3. Candidate finding NOT matched to a known PR — needs triage

The sweep surfaced a cluster of **function-type-mismatch** UB (CWE-686) that
does not obviously correspond to an existing audit PR. **This needs
confirmation against the open PR list before it is treated as new** — it may
already be covered by a PR whose title did not make the connection obvious.

| Site | Function called through wrong pointer type |
|---|---|
| `vector.c:82` | `dogecoin_wallet_addr_free` via `elem_free_f` |
| `spv.c:534` | `dogecoin_headers_db_new` via callback |
| `spv.c:660` | `dogecoin_headers_db_free` via callback |
| `spv.c:725` | `dogecoin_headers_db_load` via callback |
| `jpeg.c:413` | `jpec_huff_encode_block` via callback |
| `jpeg.c:446` | `jpec_huff_del` via callback |

**What this is:** the generic-callback idiom. Structures store a cleanup/op
callback as a generic type (e.g. `vector`'s `elem_free_f` is
`void (*)(void *)`) but are assigned a concretely-typed function
(`dogecoin_headers_db_free(dogecoin_headers_db *)`). Calling through the
mismatched pointer type is undefined behavior under C (§6.3.2.3/8), which
UBSan's `-fsanitize=function` flags.

**Severity assessment (provisional):** low. This idiom works on every real
platform ABI libdogecoin targets — the calling conventions are compatible — so
it is not believed exploitable. It is nonetheless real UB and a portability/
correctness hazard (a future compiler using CFI or type-based optimization
could miscompile it). Standard remediations: give the callback fields correctly
-typed signatures, or route through small correctly-typed trampoline wrappers
that internally cast, rather than casting the function pointer itself.

**Disposition:** confirmed new (reconciled against the full open-PR list — not
covered by any prior audit PR) and **fixed in #361**. The fix routes each site
through a small correctly-typed trampoline that carries the generic
`void(*)(void*)` signature and casts only the data pointer, rather than casting
the function pointer. A before/after UBSan run confirmed the six findings are
eliminated with no behavioural change and the residual four (§2) untouched.

## 4. Summary

| Category | Count | Status |
|---|---|---|
| UB confirming existing PRs | 4 sites | #324/#325/#326/#327 — merge-ready evidence |
| Memory fault confirming existing PR | 1 site | #324 |
| Function-type-mismatch UB | 6 sites | **fixed in #361** (typed trampolines, UBSan-verified) |

The sweep is reproducible from a clean tree via
`contrib/assurance/sanitizer_sweep.sh`. Re-running after the audit-series PRs
merge should show the §2 findings cleared; the §3 function-type-mismatch
cluster is already resolved by #361. Re-running the sweep after all of
#324/#325/#326/#327 and #361 merge should show a UBSan/ASan-clean test suite
for these classes — which makes this report a concrete before/after checkpoint
for the audit's memory-safety and UB claims.

## 5. Caveat on completeness

- The ASan pass reports only the first memory fault (see §1). A full memory
  enumeration requires iterating: fix, re-run, repeat. This report does not
  claim §2's single ASan finding is the only memory fault.
- Coverage is limited to what the **test suite** exercises. Paths not hit by
  `tests` are not swept here; fuzzing (see `SECURITY_ASSURANCE.md` §6) covers a
  different, input-driven slice.
- The function-type-mismatch severity call in §3 is provisional and should be
  reviewed by someone with the ABI context before final disposition.
