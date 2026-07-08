# Findings — `such -c transaction` validity & robustness audit

Scope: the interactive easter-egg transaction builder (`such -c transaction`,
`src/cli/such.c`), audited offline (broadcast never invoked; `--disable-net`
build + `unshare -rn`). Each finding below is independent and should be filed
as its own issue. Severity reflects that this is a demo/easter-egg app, not a
core wallet path.

Headline: **the release build is robust** — correct construction and graceful
degradation on every adversarial sequence, 0 crashes. The findings are one
tooling issue and three latent/low-severity code issues.

---

## F1 — Static AddressSanitizer build of `such`/libdogecoin is baseline-unstable (tooling)

**Severity: medium (blocks ASan-based auditing / CI); not a release-build defect.**

On this toolchain (clang-14 + glibc), a **statically** ASan-instrumented `such`
SIGSEGVs on **~25–30 % of every invocation, input-independently** — including
`such -c transaction` fed only `10` (immediate quit). Measured immediate-quit
crash rates: 9/40, 6/20, 6/25 across runs; the same uniform rate appears for a
valid address, a garbage address, and an empty menu line. The **plain build is
0/50** on all the same inputs.

Root cause is visible in the ASan log:

```
AddressSanitizer: failed to intercept '__isoc99_printf'
AddressSanitizer: failed to intercept '__isoc99_sprintf'
AddressSanitizer: failed to intercept '__isoc99_snprintf'
...
```

ASan fails to bind its printf-family interceptors in the statically-linked
configuration; the crash is a raw SIGSEGV with **no ASan heap report**, is not
reproduced under `gdb` or `valgrind` (heap-layout / timing sensitive), and even
makes `./configure` intermittently fail ("cannot run C compiled programs")
because the configure test binary itself crashes.

Impact: the brief's prescribed method (ASan+UBSan audit of the interactive app)
**cannot be applied reliably** to `such` as-is, and any ASan `make check` gate
for `such` would be flaky. This is why the harness runs its deterministic
assertions against the PLAIN vehicle and reports the ASan build's baseline
separately.

Suggested fixes to investigate: link ASan dynamically (`-shared-libasan` with
the runtime on the loader path), a newer compiler-rt, or building the
`such`/CLI objects `-fno-builtin` so the `__isoc99_*` variants aren't emitted.

Reproduce: `measure_asan_baseline()` in `run_validity_audit.sh`, or
`for i in $(seq 40); do printf '10\n' | ./such-asan -c transaction >/dev/null 2>&1; echo $?; done | grep -c 139`.

---

## F2 — `add_output` accepts an unvalidated address → latent OOB read (correctness)

**Severity: low (latent; no crash in release builds), real UB.**

The interactive "add output" path does **not** validate the destination address
before using it:

* `src/cli/such.c` `sub_menu()` case 2 calls `add_output(txindex, address, amount)`
  with the raw `getl()` string — no `verifyP2pkhAddress()` check (contrast
  `transaction_output_menu()` case 1, which *does* validate).
* `add_output()` (`src/transaction.c`) forwards it to
  `dogecoin_tx_add_address_out()` (`src/tx.c:1030`), which sizes its base58
  decode buffer as:

  ```c
  const size_t buflen = sizeof(uint8_t) * strlen(address) * 2;   // tx.c:1032
  uint8_t* buf = dogecoin_calloc(1, buflen);
  size_t r = dogecoin_base58_decode_check(address, buf, buflen);
  if (r > 0 && buf[0] == chain->b58prefix_pubkey_address)
      dogecoin_tx_add_p2pkh_hash160_out(tx, amount, &buf[1]);    // reads 20 B at &buf[1]
  ```

  For a **short** address (< ~11 chars, e.g. `"n1"`, `"D1"`, `""`), `buflen`
  is smaller than the 21-byte decoded P2PKH payload (1 version + 20 hash) that
  the `&buf[1]` read and the base58 checksum math expect, so the decode /
  `dogecoin_b58check` / hash160 path reads out of bounds of the small heap
  allocation (CWE-125). In isolation an ASan build crashes on such inputs; the
  **release build tolerates it** (the over-read lands in mapped adjacent heap —
  0/50 crashes observed), which is why it is latent rather than exploitable-as-
  observed here.

Note: the empirical crash rate seen when driving this through the ASan *menu*
is confounded by F1 (the ASan build crashes on everything), so F2 is reported
from source analysis + isolated reproduction, not from a menu crash rate.

Suggested fix: validate the address in the CLI add-output path (as case 1
already does), and/or in `dogecoin_tx_add_address_out` size `buf` to the decoded
P2PKH/P2SH width (e.g. 25) and require `r == 21` before reading `&buf[1]`.

---

## F3 — `atoi(getl())` silently treats non-numeric / empty input as 0 (robustness)

**Severity: low.**

Every menu reads its choice via `atoi(getl(...))`. `atoi` returns 0 on
non-numeric or empty input, and the menu `switch`es have no `default:` case, so
`abc`, `!`, or an empty line become a silent no-op re-prompt with no "invalid
choice" feedback. Sub-prompts are worse: `case 1` "vout index" does
`atoi(getl(...))` → a non-numeric vout is silently taken as **0**, and
"input to sign" likewise. No crash, but silent wrong-value parsing.

Suggested fix: reject non-numeric input (detect empty `strtol` conversion) and
re-prompt, and add a `default:` "invalid choice" arm to each menu.

---

## F4 — `getl()` hard-exits the whole app on EOF or over-long input (robustness)

**Severity: low.**

`getl()` (`src/transaction.c:166`, single `static char buf[100]`) and
`get_private_key()` call `exit(EXIT_FAILURE)` when `fgets` returns NULL (EOF /
Ctrl-D) **or** when the input line has no newline in the first 99 bytes (any
input ≥ 99 bytes). So Ctrl-D at any prompt, or pasting a long txid/hex, tears
down the entire session and discards all in-memory transactions rather than
re-prompting. The buffer is bounded (no overflow — good), but the whole-app
exit is abrupt for a menu program.

Confirmed benign vs the buffer hazard the source comments warn about: the two
documented `getl()` static-buffer snapshot work-arounds (`sub_menu` cases 2 and
3) are present and correct, and no additional site holds two `getl()` results
live at once without snapshotting.

Suggested fix: on over-long input, drain the rest of the line and re-prompt; on
EOF, return to the menu / exit cleanly with a message rather than
`exit(EXIT_FAILURE)` mid-operation.

---

## Verified positives (no finding)

* **Construction correctness**: inputs/outputs/amounts/scriptPubKeys encode
  correctly; a 5-DOGE output to a valid testnet address serialized to the
  expected `76a914…88ac` script; re-serialization reflects edits.
* **State integrity**: editing/signing/finding a non-existent id, delete-all
  then print, and operating on stale ids after delete-all are all handled
  gracefully (`find_transaction` is NULL-checked) — no crash, double-free, or
  UAF observed across these sequences on the release build.
* **`add_utxo` input validation**: rejects non-hex / wrong-length txids
  (requires exactly 64 hex chars) — `src/transaction.c:299-302`.
* **Offline guarantee holds**: with `--disable-net` the broadcast path is not
  compiled; the harness refuses any broadcast-capable binary and runs under
  `unshare -rn`.
