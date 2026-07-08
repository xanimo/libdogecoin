# `such -c transaction` — offline validity & robustness audit

An application-validity audit of the **interactive easter-egg transaction
builder** (`such -c transaction`, `src/cli/such.c` — the `wow()` menu). It
checks that the menu app builds correct transactions from valid input *and*
degrades gracefully on invalid / malformed / boundary / adversarial input. The
unit tests exercise the library functions; they do not drive this menu/input
layer, which is what this harness covers.

## What it does

`run_validity_audit.sh` builds `such` two ways and drives scripted stdin
sequences through the menus:

| Vehicle | Build | Role |
| --- | --- | --- |
| **PLAIN** | `-O1`, `--disable-net` | Deterministic robustness/construction assertions (this is what ships) |
| **ASAN** | `-fsanitize=address,undefined`, `--disable-net` | The brief's prescribed sanitizer vehicle; see **F1** in `FINDINGS.md` |

It reports each sequence as `[ OK ]` or `[FIND]` across four dimensions:

1. **Construction correctness** — add input/output, re-serialize, print the
   preloaded 2-in/2-out sample tx; assert `addout success: 1` and correct
   scriptPubKey/amount encoding.
2. **Input-handling robustness** — non-numeric (`abc`), empty, out-of-range
   (`99`), negative (`-1`) menu choices; EOF; non-numeric sub-prompts.
3. **Buffer / static-storage hazards** — over-long (>99 B) input at `getl`
   prompts; the amount→address static-buffer snapshot path.
4. **State integrity** — delete-all then print; edit/sign/find non-existent
   ids; add → delete-all → operate on a stale id.

## Safety — construct-and-validate only, fully offline

* **Broadcast is compiled out.** Built with `--disable-net`, so the broadcast
  menu entry (guarded by `#ifdef WITH_NET` around `broadcast_tx()`) does not
  exist. `assert_offline_binary()` **refuses to run** against any `such` whose
  menu still shows `broadcast`.
* **No network namespace.** When `unshare -rn` is available, every invocation
  runs inside a network namespace with no interfaces, so a stray connection
  cannot succeed. The audit completes with no network access.
* **Broadcast positive control.** The runner refuses any sequence tagged
  `BROADCAST`; one test *is* tagged that way and the run asserts it is refused —
  proving the guard fires (the safety analogue of a fuzzer's positive control).

## Usage

```sh
contrib/such_tx_validity/run_validity_audit.sh        # build both vehicles + run
ITERS=100 contrib/such_tx_validity/run_validity_audit.sh   # more crash samples
SKIP_ASAN=1 contrib/such_tx_validity/run_validity_audit.sh # plain vehicle only
```

Exit status is 0 when the **release** app behaved correctly on every sequence.
Reported FINDINGS (including the ASan-build instability F1) do not change the
exit code — read them in `FINDINGS.md`.

## Result summary

The **release build is robust**: correct construction, graceful input handling
(silent no-op or clean hard-exit, never a crash), safe state sequences — 0
crashes across all dimensions including adversarial address input. The audit's
findings are one **tooling** issue (F1, the ASan static build is unusable on
this toolchain) and three **latent / low-severity** code issues (F2–F4). See
`FINDINGS.md`.
