# Constant-time verification (dudect)

This directory holds statistical constant-time tests for libdogecoin's
secret-handling code, built on [dudect](https://github.com/oreparaz/dudect)
(Reparaz, Balasch, Verbauwhede — "Dude, is my code constant time?").

## Why this exists

The security assurance case (Tier 1) requires that secret-dependent timing
not leak key material. Source review can say a function *looks* constant-time,
but the compiler is free to reintroduce data-dependent branches at `-O2` — so
the property must be verified on the *compiled binary at the release
optimisation level*, which is what these tests do.

dudect measures execution-time distributions for two input classes (a fixed
secret vs. random secrets) and applies Welch's t-test. A constant-time
function shows the t-statistic bounded and non-growing as measurements
accumulate; a leaky one shows |t| climbing past the ~4.5 threshold.

## Tests

- `ct_bip38_mem_eq.c` — the BIP38 fixed-length equality check used on
  secret-derived data (`bip38_mem_eq` in `src/bip38.c`), an XOR-accumulate
  comparison written specifically to avoid `memcmp`'s early-exit timing.

## Results (recorded)

Measured with clang 18 at `-O2` on x86-64:

| function under test | measurements | max \|t\| | verdict |
|---|---|---|---|
| `bip38_mem_eq` (32-byte) | 72 M | 1.8 | constant-time |
| positive control (branch on secret) | — | 691 | leak detected (as expected) |

The positive control — a variant that branches on the secret's first byte —
is what makes the negative result trustworthy: it confirms the harness
*can* detect a leak, so `bip38_mem_eq`'s stable low t is a real pass, not a
test that cannot fail. (The control is not shipped; it is described here and
easy to reproduce by replacing the compared function with an early-return
branch keyed on `a[0]`.)

## Running

```
make -f ct.mk -C contrib/ct            # or: clang -O2 -g ct_bip38_mem_eq.c -o ct_bip38_mem_eq -lm
./ct_bip38_mem_eq             # runs until leakage found or interrupted
```

Exit status is 0 when no leakage evidence is found and non-zero when a leak is
detected, so the test is usable as a CI gate. Note that dudect runs
indefinitely by design (accumulating confidence); for CI, bound it with a
measurement cap or a timeout and treat "no leak within budget" as a pass.

## Caveats

- These tests compile a **local copy** of the function under test, because the
  library implementations are `static`. The copy must be kept byte-identical
  to the library source; if `bip38_mem_eq` changes, update the harness (or
  export a testable symbol). A comment in each harness flags this.
- Timing measurement is host- and load-sensitive. Run on an otherwise-idle
  machine; a noisy host inflates the measurement variance and can mask a small
  leak. The positive control is the check that the setup is sensitive enough.
- A pass means "no timing leak detectable by this method at this optimisation
  level on this host." It is strong evidence, not a proof.
