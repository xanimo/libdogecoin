# libdogecoin Security Audit Plan

**Status:** Draft for team review
**Scope target:** `0.1.5-dev` and release branches
**Owners:** TBD (proposed: split per phase below)

---

## 1. Purpose

Establish a scheduled, bounded audit program with defined outputs. The goal is not to prove the absence of vulnerabilities — that isn't achievable for a C library handling key material — but to (a) declare an explicit threat model, (b) systematically exercise the codebase against it with complementary methods, and (c) produce artifacts that constitute an assurance case a third party can evaluate.

## 2. Threat model and security tiers

Before running tools, we decide what we defend against. Proposed tiering:

**Tier 1 — In scope, must defend (release-blocking):**

- Memory-safety violations reachable from untrusted input: network messages, serialized transactions/PSBTs, BIP38-encrypted keys, base58/bech32 strings, imported wallet data. (CWE-119/125/787, CWE-190/191, CWE-416/415)
- Undefined behavior in consensus-adjacent or crypto paths, including signed overflow, misaligned loads, and shift UB. (CWE-758, CWE-190)
- Secret-dependent timing in key handling: privkey operations, BIP38 decryption, HMAC/scalar comparisons. (CWE-208, CWE-385)
- Failure to zeroize key material, or key material reachable after free. (CWE-226, CWE-244, CWE-416)
- Injection/parsing confusion in string handling: format strings, unchecked lengths, magic-number assumptions. (CWE-134, CWE-131)

**Tier 2 — In scope, best-effort (documented, fixed opportunistically):**

- Resource exhaustion from adversarial input (allocation bombs, decompression-style amplification in parsers). (CWE-400, CWE-789)
- API-misuse hazards: functions that are safe only if callers follow undocumented preconditions. Document or harden.
- Thread-safety races beyond what the registry-mutex and stateless work already covered. (CWE-362)

**Tier 3 — Explicitly out of scope (declared, not defended):**

- Microarchitectural attacks (Spectre-class, cache attacks beyond straightforward secret-indexed lookups).
- Fault injection / glitching, physical attacks.
- Compromised toolchain or build environment (addressed separately by reproducible-build work, not this audit).
- Side channels in bindings or downstream consumers (Python bindings audited only at the FFI boundary).

Publishing Tier 3 is what defines our security level of difficulty: the assurance case states its own limits.

## 3. Method matrix

Each method maps to the CWE classes it credibly covers and the artifact it produces. Breadth methods run over the whole library; depth methods are reserved for the high-stakes paths in §4.

| Method | Tooling | CWE coverage | Artifact produced |
|---|---|---|---|
| Static analysis (pattern) | cppcheck `--enable=all --cwe` (emits CWE IDs directly) | 119, 125, 787, 190, 401, 415, 416, 476 | Findings report with CWE tags, triage log |
| Static analysis (semantic) | clang-tidy: `cert-*`, `bugprone-*`, `clang-analyzer-*` | 190, 197, 758, 476, 686 | CI check + baseline suppression file |
| Static analysis (dataflow) | CodeQL C/C++ security-extended suite (GH Actions, free for public repos) | CWE Top 25 mapped queries | SARIF results in Security tab, per-PR gating |
| Interprocedural analysis | Infer (`--pulse`) | 476, 401, 416 across call chains | Findings report |
| Dynamic (sanitizers) | ASan/UBSan/MSan sweeps over full test suite (extends PRs #324–327 methodology) | 119, 125, 787, 190, 758, 457 | Clean-run log per sanitizer per branch |
| Fuzzing | libFuzzer harnesses from PR #351 (wtx, logdb, protocol, block, PSBT) + new BIP38 harness | 119, 125, 787, 400, parser-state confusion | Corpus, crash triage log, **coverage report** |
| Coverage measurement | `-fprofile-instr-generate` on fuzz targets, llvm-cov HTML | n/a (validates fuzzing claims) | Reachability report: which attack surface the fuzzers actually exercise |
| Constant-time verification | dudect (statistical, CI-friendly); ctgrind/valgrind client requests or Binsec/Rel for binary-level confirmation | 208, 385 | Per-function CT verdict at `-O2` on release toolchain |
| AI-assisted review | Model review passes per module, findings filed as candidate issues only | breadth across all classes | Candidate-finding list feeding human triage |
| Hand audit | Line-by-line review of §4 paths, attacker-controlled-data annotation | logic flaws tools miss (131, 640-class, protocol misuse) | Signed-off review notes per module |

Two notes on the matrix. First, the coverage report is the highest-leverage single addition: we already have fuzzers, but the assurance case is much stronger when we can show *what they reach* rather than just that they ran. Second, the constant-time row closes an important loop: source-level pattern findings (like the recent leak) are hypotheses until verified on the compiled binary, because the compiler can reintroduce secret-dependent branches at optimization time. dudect in CI gives ongoing statistical confidence; a one-time Binsec/Rel or ctgrind pass on the release binary gives the stronger verdict.

## 4. High-stakes paths (hand-audit + depth methods)

These get human line-by-line review with the explicit question "what does the attacker control here," plus CT verification where secrets are involved:

1. **BIP38 encrypt/decrypt** (PR #277 / #358 surface) — passphrase handling, scrypt parameters, AES key schedule, decrypted-key zeroization, error paths that could act as padding/format oracles.
2. **Key derivation and privkey operations** — bip32 derivation (already had the signed-shift fix), WIF encode/decode, scalar comparisons, `dogecoin_privkey` lifecycle end to end (alloc → use → zeroize → free).
3. **HMAC/hash primitives** — building on the hmac-sha256 OOB and sha256 unaligned-load fixes; verify the remaining primitives against the same failure classes.
4. **PSBT parser** (PR #317) — the largest untrusted-input surface; length fields, map key/value confusion, combinator/merge logic where two attacker-supplied PSBTs interact.
5. **Base58/bech32 and address parsing** — checksum handling, length assumptions, and verification of the recent magic-number/string-length hardening in #277.
6. **FFI boundary** (python-libdogecoin cffi surface) — audited only at the boundary: buffer ownership, length conventions, who frees what.

## 5. Phases and sequencing

**Phase 0 — Baseline (≈1 week of calendar time, low effort):** Land CodeQL, clang-tidy, and cppcheck in CI with a baseline suppression file so only new findings gate PRs. Existing findings dump into a triage backlog. Artifact: CI config + backlog issue list.

**Phase 1 — Breadth (2–3 weeks, parallelizable):** Triage the Phase 0 backlog by CWE severity and reachability from untrusted input. Run sanitizer sweeps on `0.1.5-dev`. Add the BIP38 fuzz harness and generate the coverage report for all harnesses. AI-assisted review passes run here as candidate-generation, feeding the same triage queue as the tools — same queue, same disposition labels (confirmed / false-positive / won't-fix-with-rationale).

**Phase 2 — Depth (scheduled per module, ~1 module per week per reviewer):** Hand audits of §4 paths in priority order (BIP38 first, as the most recently changed key-material surface; PSBT second, largest parser). CT verification of the crypto paths on the release toolchain. Each module concludes with signed-off review notes.

**Phase 3 — Assurance case assembly:** Collate into a single `SECURITY_ASSURANCE.md`: threat model (§2), method matrix with links to artifacts, per-module audit status, declared out-of-scope items, and a maintenance policy (which checks gate PRs going forward, cadence for re-running sweeps).

## 6. Triage and disposition rules

Every finding — tool, AI, or human — gets one of four labels: **confirmed** (issue filed, fix scheduled by tier), **false positive** (suppressed with a one-line rationale in the baseline file), **true-but-out-of-scope** (documented against Tier 3), or **hardening** (not exploitable but worth fixing; batched). No finding is closed without a label. This is what makes the audit legible to an outside reviewer later.

## 7. Division of labor (proposal)

Tools and CI wiring are mechanical and can be split freely. Hand audits should pair one primary reviewer with one confirmer per module — the primary annotates attacker-controlled data flow, the confirmer checks the annotation rather than re-deriving it, which halves the cost of two-person review. AI review passes are cheap to run per module and slot in wherever a human wants a second set of eyes before sign-off, with the standing rule that AI findings are candidates, never dispositions.

---

*Open questions for the team: (1) Do we gate releases on Tier 1 clean status only, or Tier 1 + triaged Tier 2? (2) Does the assurance doc live in-repo or on the wiki? (3) dudect CI integration currently has no owner — it stays unscheduled until someone claims it.*
