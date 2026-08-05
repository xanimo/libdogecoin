# SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes

libdogecoin provides a complete implementation of
[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md),
the standard for splitting a master secret into a set of human-readable
mnemonic shares using Shamir's Secret Sharing.

## Overview

SLIP-0039 allows a wallet seed (or any 16–32 byte secret with an even
byte-length) to be split into *M*-of-*N* shares, where any *M* shares are
sufficient to reconstruct the secret.  Each share is a sequence of words
drawn from the official 1024-word SLIP-0039 wordlist.  The encoding
includes a 30-bit RS1024 checksum so that single-word errors are detected
before any attempt at recovery.

### Key properties

| Property | Value |
|---|---|
| Secret size | 16–32 bytes, even length |
| Default iteration exponent | 1 (10,000 PBKDF2-SHA256 rounds) |
| Share format | 20–33 space-separated lowercase words |
| Checksum | 30-bit RS1024 (3 mnemonic words) |
| Encryption | 4-round Feistel with PBKDF2-SHA256 |
| Group support | multi-group (*group_threshold*-of-*group_count*) |
| Passphrase | optional; pass empty/NULL for no passphrase |

The `dogecoin_slip0039_generate_shares` and
`dogecoin_slip0039_recover_secret` functions implement single-group
sharing (group_threshold = group_count = 1), which covers the vast
majority of real-world use cases.  Multi-group recovery is fully
supported on the decode path.

## C API

```c
#include <dogecoin/slip0039.h>

/* Split `secret` (16–32 bytes, even length) into `share_count` mnemonic
 * shares requiring `threshold` shares to recover.
 *
 * On success fills shares[0..share_count-1] and returns 0.
 * On error returns -1. */
int dogecoin_slip0039_generate_shares(
    const uint8_t* secret, size_t secret_len,
    uint8_t threshold, uint8_t share_count,
    char shares[][SLIP0039_MAX_SHARE_STR_SIZE]);

/* Recover the master secret from `share_count` mnemonic shares.
 *
 * passphrase/passphrase_len may be NULL/0 for an empty passphrase.
 * On success writes the secret to secret_out, sets *secret_len_out, returns 0.
 * On error returns -1. */
int dogecoin_slip0039_recover_secret(
    const char* shares[], size_t share_count,
    const uint8_t* passphrase, size_t passphrase_len,
    uint8_t* secret_out, size_t* secret_len_out);
```

### Constants

| Constant | Value | Description |
|---|---|---|
| `SLIP0039_MAX_SHARES` | 16 | Maximum shares per group |
| `SLIP0039_MAX_SHARE_STR_SIZE` | 320 | Buffer size for one mnemonic share string |
| `SLIP0039_MIN_SECRET_BYTES` | 16 | Minimum secret length in bytes |
| `SLIP0039_MAX_SECRET_BYTES` | 32 | Maximum secret length in bytes |

The `SLIP0039_SHARE` typedef (`char[SLIP0039_MAX_SHARE_STR_SIZE]`) is
provided as a convenience for declaring share arrays.

## Example

```c
#include <dogecoin/slip0039.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const uint8_t secret[16] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98
    };
    SLIP0039_SHARE shares[SLIP0039_MAX_SHARES];
    memset(shares, 0, sizeof(shares));

    /* Generate 2-of-3 shares (no passphrase). */
    if (dogecoin_slip0039_generate_shares(secret, 16, 2, 3, shares) != 0) {
        fprintf(stderr, "share generation failed\n");
        return 1;
    }
    for (int i = 0; i < 3; ++i)
        printf("share %d: %s\n", i + 1, shares[i]);

    /* Recover from shares 0 and 2 (no passphrase). */
    const char* recovery[2] = { shares[0], shares[2] };
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    if (dogecoin_slip0039_recover_secret(recovery, 2, NULL, 0,
                                         recovered, &recovered_len) != 0) {
        fprintf(stderr, "recovery failed\n");
        return 1;
    }
    printf("recovered %zu bytes\n", recovered_len);
    return 0;
}
```

A fully compilable version is available in `contrib/examples/example.c`.

## CLI (`such`)

### Split a secret into shares

```
./such -c slip39_split -x <secret_hex> -o <threshold> -i <share_count>
```

* `-x` — secret as a hex string (32–64 hex chars, i.e. 16–32 bytes, even length)
* `-o` — minimum shares required for recovery (1..16)
* `-i` — total number of shares to generate (≥ threshold, ≤ 16)

Each share mnemonic is printed on its own line.

**Example** (2-of-3 split):
```
./such -c slip39_split -x deadbeef0123456789abcdeffedcba98 -o 2 -i 3
```

### Recover a secret from shares

```
./such -c slip39_recover -x "<share1>,<share2>,..."
```

* `-x` — comma-separated list of mnemonic shares

The recovered secret is printed as a hex string.

**Example**:
```
./such -c slip39_recover \
  -x "academic acid acne acquire acrobat activity actress adapt adequate adjust,academic acid acne acquire acrobat activity actress adapt adequate admit"
```

## Test vectors

The test suite in `test/slip0039_tests.c` includes all official Trezor
reference vectors from
[python-shamir-mnemonic/vectors.json](https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json)
(vectors 1–20) covering:

* single-share mnemonics (128-bit and 256-bit secrets)
* invalid-checksum and invalid-padding rejection
* basic 2-of-3 sharing
* cross-identifier and cross-exponent rejection
* mismatched group thresholds/counts
* duplicate member indices
* invalid digest
* insufficient groups and members
* multi-group threshold scenarios

All 20 Trezor vectors use the passphrase `"TREZOR"` per the SLIP-0039
specification.

## References

* [SLIP-0039 specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
* [Trezor python-shamir-mnemonic reference implementation](https://github.com/trezor/python-shamir-mnemonic)
* [Trezor test vectors](https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json)
