# Fuzz coverage measurement

`fuzz_coverage.sh` builds the libFuzzer harnesses (from the fuzzing
harness set) under LLVM source-based coverage instrumentation, replays a
corpus through each, and reports how much of the first-party source the
harnesses actually reach.

This exists for the audit assurance case: "we have fuzzers" is weaker
than "here is the specific attack surface the fuzzers exercise, and here
is what they don't reach yet." The uncovered-priority list is also the
input for deciding where the next harness or corpus investment goes.

## Usage

```
contrib/coverage/fuzz_coverage.sh [corpus_root]
```

With no corpus, each target gets a short bounded fuzz run to generate one
in place, so the script works from a clean tree. For meaningful numbers,
point it at an accumulated corpus:

```
contrib/coverage/fuzz_coverage.sh /path/to/persistent-corpora
```

where `persistent-corpora/` holds one subdirectory per target named after
the target (`fuzz_tx/`, `fuzz_psbt/`, ...).

Environment knobs: `SEED_RUNS` (inputs per generated corpus, default
20000), `MAX_LEN`, `OUT_DIR` (default `coverage-report`), `LLVM_SUFFIX`
(e.g. `-18` if your llvm tools are versioned).

## Output

- `coverage-report/html/index.html` — browsable line-level coverage
- `coverage-report/summary.txt` — `llvm-cov report` over first-party `src/`
- `coverage-report/uncovered.txt` — first-party `.c` files sorted by line
  coverage ascending; the top entries are the largest unexercised surface

## Reading the numbers honestly

The absolute percentages depend entirely on corpus quality. A
freshly-generated mini-corpus measures what a few minutes of fuzzing
reaches, not what the harness is capable of reaching. Two things are
robust regardless of corpus size and are what to act on:

1. **Files at 0%** with a harness that nominally targets them — this
   usually means the harness entry point bails before reaching the code,
   not that the code is hard to reach. Worth inspecting the harness.
2. **Relative ranking** of parser surface — if the largest untrusted-input
   parser (currently `psbt.c`) sits far below the serialization helpers
   feeding it, that is a corpus/harness gap to close, not noise.

## Build notes

- Coverage instrumentation goes on library objects via `CFLAGS`
  (`-fprofile-instr-generate -fcoverage-mapping`) so coverage lands in
  `src/`, not just the harness files. The profile runtime is pulled in at
  link via configure-level `LDFLAGS`.
- The build is `--enable-static --disable-shared`: linking the profile
  runtime into a shared object trips a hidden-`atexit` DSO link error, and
  static harnesses match how the fuzz CI already builds them.
- `CXX=clang++` is set because the libtool link step drives the final link
  through the C++ compiler, which must also understand the profile flag.
- Vendored trees (`secp256k1`, `libevent`, `intel`, `utf8proc`, logdb's
  red-black-tree, enclave/optee/pqc backends) are excluded from the report
  via `-ignore-filename-regex`; the audit scope is first-party code.
