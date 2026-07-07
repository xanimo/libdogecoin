# libdogecoin Security Assurance Case

**Status:** Living document — draft
**Scope target:** `0.1.5-dev` and derived release branches
**Companion:** `libdogecoin_audit_plan.md` (the plan this executes)
**Last updated:** see git history

---

## 1. What this document is

This is the assurance case for the libdogecoin security audit: a single place
that states what the audit defends against, how the codebase was exercised
against it, what was found and where each finding is being fixed, and what is
explicitly out of scope. It is written to be legible to an outside reviewer —
someone who was not in the room — so that "libdogecoin was audited" can be
substantiated rather than asserted.

It is deliberately *not* a claim that libdogecoin is free of vulnerabilities.
For a C library handling key material that is not an achievable or honest
claim. The claim it supports is narrower and defensible: a declared threat
model was systematically exercised with complementary methods, findings were
tracked to disposition, and the limits of the effort are stated.

This is a living document. As the audit PRs merge and later phases run, the
tables below move from "open" to "merged" and from "in progress" to "complete."

## 2. Threat model and security tiers

The tiers below are the security level of difficulty the audit commits to.
Publishing Tier 3 — what is *not* defended — is part of the assurance case,
not an omission from it.

### Tier 1 — In scope, must defend (release-blocking)

- Memory-safety violations reachable from untrusted input: network messages,
  serialized transactions/PSBTs, BIP38-encrypted keys, base58/bech32 strings,
  imported wallet data. (CWE-119/125/787, CWE-190/191, CWE-416/415)
- Undefined behavior in consensus-adjacent or crypto paths: signed overflow,
  misaligned loads, shift UB. (CWE-758, CWE-190)
- Secret-dependent timing in key handling: privkey operations, BIP38 decrypt,
  HMAC/scalar comparisons. (CWE-208, CWE-385)
- Failure to zeroize key material, or key material reachable after free.
  (CWE-226, CWE-244, CWE-416)
- Injection/parsing confusion in string handling: format strings, unchecked
  lengths, magic-number assumptions. (CWE-134, CWE-131)

### Tier 2 — In scope, best-effort (documented, fixed opportunistically)

- Resource exhaustion from adversarial input: allocation bombs, unbounded
  counts driving allocation. (CWE-400, CWE-789)
- API-misuse hazards: functions safe only under undocumented preconditions.
- Thread-safety races beyond the registry-mutex and stateless work.
  (CWE-362)

### Tier 3 — Explicitly out of scope (declared, not defended)

- Microarchitectural attacks (Spectre-class; cache attacks beyond
  straightforward secret-indexed lookups).
- Fault injection / glitching / physical attacks.
- Compromised toolchain or build environment (covered separately by
  reproducible-build work, not this audit).
- Side channels in language bindings or downstream consumers (bindings
  audited only at the FFI boundary).

## 3. Methods applied

Each method maps to the CWE classes it credibly covers and the artifact it
produces. Status reflects the current state, not the plan.

| Method | Tooling | CWE coverage | Artifact | Status |
|---|---|---|---|---|
| Static analysis (dataflow) | CodeQL `security-extended` | CWE Top 25 | Security-tab results, per-PR | Landing (PR #359) |
| Static analysis (pattern) | cppcheck `--enable=all`, CWE-tagged | 119/125/787, 190, 401/415/416, 476 | XML report artifact + triage | Landing (PR #359) |
| Static analysis (semantic) | clang-tidy `cert-*`,`bugprone-*`,`clang-analyzer-*` | 190, 197, 758, 476, 686 | Advisory report artifact | Landing (PR #359) |
| Dynamic (sanitizers) | ASan/UBSan over full test suite | 119/125/787, 190, 758, 457 | Clean-run logs per branch | In progress; sweep reproduces #324/#325 on `0.1.5-dev` |
| Sanitizer CI gate | `make check` under ASan+UBSan | as above, continuous | Gating CI job | Open, draft (PR #328) |
| Fuzzing | libFuzzer harnesses (tx, block, wtx, logdb, protocol, PSBT, BIP38) | 119/125/787, 400, parser-state confusion | Corpora, crash triage | Infra open (PR #351); PSBT integrated (#357); BIP38 harness pending #351+#277 |
| Coverage measurement | llvm-cov over fuzz targets | validates fuzzing reach | Reachability report | Open (PR #360) |
| Constant-time verification | dudect / Welch t-test, `-O2` | 208, 385 | Per-function CT verdict | Established (#365); 2 primitives verified |
| Hand audit | Line-by-line of high-stakes paths | logic flaws tools miss (131, 640-class) | Signed-off review notes | Ongoing (BIP38/sweep, PSBT, key paths) |

Two methods are worth calling out. **Coverage measurement** (PR #360) is what
turns "the fuzzers ran" into "here is the attack surface they exercise": the
BIP38 harness, for example, was shown by replay to reach base58 decode but not
the scrypt/AES stages until a valid-key seed corpus was added, after which
`ctaes.c` reached ~84% and the EC-multiplied decrypt branch went from zero
coverage to reached. **Constant-time verification** is now established (#365):
a dudect harness measures the compiled binary at `-O2` via a Welch t-test over
fixed-vs-random secret input classes. Two primitives are verified constant-time
— `dogecoin_mem_cmp_ct` (the real exported comparison primitive, linked not
copied; max |t| = 2.2 over 38M measurements) and BIP38's `bip38_mem_eq` (|t| =
1.8 over 72M). A positive control that branches on the secret is flagged at
|t| = 691, confirming the harness can detect a leak and the passes are real.
Remaining secret-dependent paths beyond these two primitives are not yet
covered.

## 4. Findings and disposition

The audit surfaced findings across memory safety, undefined behavior,
resource exhaustion, and correctness. Each is tracked to a fix PR against
`0.1.5-dev`. Disposition labels follow the audit plan: **confirmed** (fix
filed), with false-positive / out-of-scope / hardening handled in the
per-tool triage backlogs.

### Memory safety (Tier 1)

| Finding | Location | PR | Notes |
|---|---|---|---|
| OOB write in `hmac_sha256_prepare` | `src/sha2.c` | #324 | Independently reproduced by ASan sweep on clean `0.1.5-dev`; reached via block-header scrypt hash |
| Heap overflow in `sign_raw_transaction` in-place write | `src/transaction` | #331 | |
| Stack overflow + unbounded alloc in logdb record deser | `src/logdb` | #345 | |
| Double-free in software seed decryption | `src/seal.c` | #343 | |
| Registry/eviction fixes: never-reused ids, stop evicting live entries | map/eckey/utxo/registry | #333, #335, #336, #337 | #336 also stops leaking evicted live keys |

### Undefined behavior (Tier 1)

| Finding | Location | PR | Notes |
|---|---|---|---|
| Signed-overflow shift in big-endian word assembly | `src/bip32.c`, bip37 | #325 | Independently reproduced by UBSan sweep on clean `0.1.5-dev` (HD key derivation path) |
| Unaligned word loads in `sha256_transform` | `src/sha2.c` | #326 | Independently reproduced by UBSan sweep (misaligned-pointer-use at `sha2.c:994`) |
| Signed-overflow UB in bit assembly | `src/arith_uint256.c`, `src/jpeg.c` | #327 | Independently reproduced by UBSan sweep (invalid-shift-base at `arith_uint256.c:128`, `jpeg.c:220`) |
| UB + count truncation in auxpow deserialization | `src/block.c` | #334 | |
| Integer overflow in `cstr_alloc_min_sz` sizing | `src/cstr.c` | #344 | |

**Function-type-mismatch UB (NEW — fixed in #361).**
The sanitizer sweep surfaced six `function-type-mismatch` sites (CWE-686)
confirmed by reconciliation against the full open-PR list to be not covered by
any prior audit PR: `spv.c:534/660/725` (header-db callbacks), `vector.c:82`
(`elem_free_f`), `jpeg.c:413/446` (huff callbacks). Root cause is the
generic-callback idiom (typed function stored in a `void(*)(void*)`-style
field, called through the mismatched type). Fixed in **#361** via typed
trampolines that carry the correct generic signature and cast only the data
pointer; verified with a before/after UBSan run showing the six findings
eliminated and the residual four (owned by #325/#326/#327) untouched. See
`sanitizer_sweep_report.md` §3.

### Resource exhaustion (Tier 2)

| Finding | Location | PR | Notes |
|---|---|---|---|
| Unbounded getheaders locator allocation | `src/protocol.c` | #339 | Also observed as a bounded OOM by the protocol fuzz harness |
| Unbounded OP_PUSHDATA allocation | `src/script.c` | #338 | In `copy_without_op_codeseperator` |
| Unbounded transaction record length on disk load | `src/wallet` | #342 | |
| Unbounded allocation in logdb record deser | `src/logdb` | #345 | Shares PR with the logdb stack-overflow fix |

### Correctness / robustness (Tier 1/2)

| Finding | Location | PR | Notes |
|---|---|---|---|
| Verify message payload checksum before dispatch | `src/net` | #341 | |
| Dispatch only this message's payload to handlers | `src/net` | #340 | Message-boundary confusion |
| Clean failure on malformed WIF in `sign_raw_transaction` | `src/transaction` | #332 | |
| buffer-type + unterminated copy fix | such (`coin_amount`/`subtotal`) | #358 | |
| PQC wrapper output-length assertions, reject tampered input | test/PQC | #348 | |
| cmake: liboqs link, Raccoon-G test suite | build | #347, #346 | Build-system hardening |

*Reconciled against `gh pr list` (authoritative). All PR numbers above are
confirmed against branch names and titles as of this revision.*

### Key-material lifetime (Tier 1) — CWE-226 audit

A dedicated pass audited every path that handles private keys, seeds, or
passphrase-derived key material for correct zeroization — checking that secret
temporaries are scrubbed on *all* exit paths (not only the success path) and
that the scrub covers the full buffer (not `sizeof` a pointer). The pass found
a systematic class of leaks spanning the whole key lifecycle: generation,
derivation, encoding, and at-rest encryption. It also verified the negative
space (Windows NCrypt path materialises no plaintext; no PKCS11 backend
exists) and rejected false positives (stack *arrays* where `sizeof` is correct
in `bip32.c`/`seal.c`).

| Finding | Location | PR | Notes |
|---|---|---|---|
| WIF decode zeroed `sizeof(pointer)` (8 B) not the buffer | `src/key.c` | #362 | ~30 B of the decoded private key left in freed heap |
| eckey constructors never scrubbed the WIF temp | `src/eckey.c` | #362 | Both `new_eckey` paths; all exits |
| CKD left the retained private-key copy `p` unscrubbed | `src/bip32.c` | #362 | `z` beside it was scrubbed; plain omission |
| Software seal derived AES keys never scrubbed | `src/seal.c` | #363 | encrypt + decrypt; password was scrubbed but the keys derived from it were not |
| TPM path returned decrypted **plaintext** to the allocator in the clear | `src/seal.c` | #363 | `Esys_Free` does not zero; the seed/mnemonic itself leaked |
| YubiKey path: PIN freed without zeroing, mgmt key unscrubbed | `src/seal.c` | #363 | validated against a physical YubiKey 5 (PIV) |
| Master seed + master hdnode left on the stack in wallet init | `src/wallet.c` | (pending) | **Highest severity** — the HD root; reconstructs every derived key |

Verification: `dogecoin_mem_zero` was confirmed to be a `volatile` byte-wise
write (`mem.c` → `memset_safe`) that survives `-O2` and is not elidable, so all
scrubs in this class are effective rather than optimised away. The seal fixes
were validated against the software path, a Linux TPM (swtpm) simulator, and a
physical YubiKey; byte-for-byte seed round-trips confirmed. Two incidental
error-path bugs (an `encrypted_seed` double-free and an `fclose(NULL)`) were
fixed by the seal-path cleanup consolidation. The `#324`-`#348` series double-
free work in `#343` overlaps the seal double-free; disposition tracked in #363.


### Tooling and infrastructure

| Item | PR | Status |
|---|---|---|
| Phase 0 static-analysis workflows (CodeQL filter fix + cppcheck + clang-tidy) | #359 | Approved; un-drafted, open — pending merge |
| libFuzzer harness infrastructure | #351 | Approved, open |
| Coverage reachability tooling | #360 | Open, stacked on #351 |
| PSBT (BIP174) fuzz harness + fixes | #357 | Open |
| ASAN+UBSAN CI gate | #328 | Open, draft |
| Function-pointer type-mismatch UB fix (typed trampolines) | #361 | Open — found by this sweep; verified UBSan-clean |
| PQC test assertions / cmake liboqs / raccoon-g build | #346, #347, #348 | Open |
| Key-material zeroization (key/eckey/bip32) | #362 | Draft — CWE-226 series |
| Key-material zeroization (seal: sw/TPM/YubiKey) | #363 | Draft — hardware-validated; overlaps #343 |
| Constant-time verification tests (dudect) | #365 | Draft — 2 primitives verified |
| Security assurance case + audit artifacts | #366 | Draft — this document |

## 5. Independent corroboration

The ASan/UBSan sweep of a clean `0.1.5-dev` checkout independently reproduced
two findings that already have fix PRs:

- The `hmac_sha256_prepare` OOB write (#324), reached through
  `dogecoin_block_header_scrypt_hash` → pbkdf2 → hmac — i.e. from block
  header validation, a consensus path.
- The `bip32.c` fingerprint shift UB (#325), reached through HD key
  derivation.

This matters for the assurance case in two ways: it confirms the fixes address
faults that are still live on the release branch (motivating their merge), and
it demonstrates the dynamic-analysis method catches what the plan says it
should. The sweep itself is reproducible from the documented ASan+UBSan build
(`CC=clang CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"`,
static build, full `tests` suite).

## 6. Fuzzing reachability summary

| Harness | Surface | Notable result |
|---|---|---|
| PSBT (BIP174) | serialized PSBT parsing | reproduced a heap overflow on pre-fix tree (200-byte write into 33-byte pubkey buffer) |
| protocol | p2p message deserialization | surfaced the getheaders unbounded allocation (#339), bounded in CI via `-malloc_limit_mb` |
| BIP38 (pending) | encrypted-key decrypt | seed corpus reaches scrypt (~53%) and AES/ctaes (~84%); EC-multiplied branch reached only after EC-key seed enrichment |

The coverage tooling (#360) is what makes these numbers assurance evidence
rather than anecdote: it reports which first-party source the harnesses
actually reach, and its uncovered-priority output is what drives where the
next harness or corpus investment goes. Known reachability gaps are recorded
there rather than hidden.

### BIP38 harness — completed campaign

A 4-hour libFuzzer campaign (ASan+UBSan) from the EC-enriched seed corpus
against the BIP38 decrypt harness completed **crash-clean**:

- 329,171 executions over 14,401 s (~22 exec/s — scrypt-bound by design; each
  surviving input runs the full KDF).
- Final coverage `cov: 380, ft: 834, corp: 95`; 84 new units added during the
  run. No crash, OOM, or timeout artifact; `slowest_unit_time_sec: 0`.
- Coverage progression across runs: 84 (random input) → 346 (non-EC corpus,
  overnight plateau) → 380 (EC-enriched corpus, this run). The gain past 346 is
  attributable to the EC-multiplied seed enrichment reaching the
  `bip38_decrypt_ec_multiplied_bytes` branch, which no mutation of non-EC seeds
  could reach.

This establishes a crash-clean baseline for the reachable BIP38 decrypt
surface at the exercised coverage. It is a baseline, not a completeness claim:
coverage of `bip38.c` remains partial per the #360 reachability report. The
intermediate-passphrase-code and confirmation-code parsers — a distinct
untrusted-input surface the decrypt harness does not reach — now have their own
harness and seed generator (reaching `bip38_parse_intermediate_code` and
`confirm_passphrase_ex`, ~30% of `bip38.c` from the code-parser side), pending
the same `#351`+`#277` base as the decrypt harness.

## 7. Declared limits (what this assurance case does NOT establish)

- **Constant-time verification is partial.** Two core comparison primitives
  are binary-verified constant-time at `-O2` (#365); other secret-dependent
  paths (e.g. HMAC comparisons, base58/WIF handling of key bytes) are so far
  only source-reviewed, not binary-verified.
- **No Tier 3 coverage.** Microarchitectural, fault-injection, physical, and
  toolchain-compromise attacks are out of scope by declaration.
- **Bindings audited at the boundary only.** The Python/other bindings are
  covered at the FFI surface, not internally.
- **Coverage is not completeness.** Fuzzing reaches a measured subset of the
  attack surface; files at low or zero coverage (per the #360 report) are not
  claimed to be exercised.
- **Findings inventory is a snapshot.** New findings may arise as later phases
  (CT verification, deeper hand audit, longer fuzzing) run.

## 8. Maintenance policy

Once the tooling PRs merge, the following gate ongoing changes into
`0.1.5-dev`:

- CodeQL `security-extended` on every PR (fixed by #359 to actually run on
  `0.1.5-dev`).
- cppcheck gating on `error` severity; widening to `warning` after the initial
  backlog is triaged.
- clang-tidy advisory (report artifact, non-gating) until its baseline is
  dispositioned.
- ASan+UBSan `make check` gate once #328 lands.

Every new suppression in the cppcheck baseline or clang-tidy config carries a
one-line rationale; no finding is closed without a disposition label. Sanitizer
and fuzzing sweeps are re-run on a cadence to be set by the team, with results
appended to Section 5/6.

## 9. Open items feeding the next revision

- Un-draft and merge #359; confirm the first full-tree static-analysis run.
- File the function-type-mismatch cluster (§4 UB) as a new Tier-2 hardening PR
  — **done: #361**, verified UBSan-clean for that class.
- Merge the sanitizer sweep as a checked-in assurance artifact
  (`contrib/assurance/sanitizer_sweep.sh` + report); decide on #328.
- Land #351 → rebase #360 → open the BIP38 harness PR once #277 also lands
  (both decrypt and code-parser harnesses + seed generators are staged).
- Constant-time verification: **established (#365)** for two primitives; extend
  to remaining secret-dependent paths (HMAC compares, WIF/base58 key handling)
  and wire the bounded CT gate into CI.
- Key-material zeroization (CWE-226): key/eckey/bip32 (#362) and seal (#363)
  drafted; **wallet-init master-seed leak fix pending** (highest severity).
  Resolve the #343/#363 double-free overlap.
- Reconcile #366 (this document) against merged PR numbers before un-drafting;
  it is a living record and should track the series rather than lead it.
