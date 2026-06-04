# Libdogecoin Seal API

## Table of Contents

- [Libdogecoin Seal API](#libdogecoin-seal-api)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
    - [Platform support](#platform-support)
    - [Windows setup](#windows-setup)
    - [Linux setup](#linux-setup)
    - [Testing with the swtpm emulator](#testing-with-the-swtpm-emulator)
    - [Persistent-handle layout (Linux/TSS2)](#persistent-handle-layout-linuxtss2)
  - [Seed API](#seed-api)
    - [**dogecoin_encrypt_seed_with_tpm:**](#dogecoin_encrypt_seed_with_tpm)
    - [**dogecoin_decrypt_seed_with_tpm:**](#dogecoin_decrypt_seed_with_tpm)
    - [**dogecoin_encrypt_seed_with_sw:**](#dogecoin_encrypt_seed_with_sw)
    - [**dogecoin_decrypt_seed_with_sw:**](#dogecoin_decrypt_seed_with_sw)
    - [**dogecoin_encrypt_seed_with_sw_to_yubikey:**](#dogecoin_encrypt_seed_with_sw_to_yubikey)
    - [**dogecoin_decrypt_seed_with_sw_from_yubikey:**](#dogecoin_decrypt_seed_with_sw_from_yubikey)
  - [Mnemonic API](#mnemonic-api)
    - [**dogecoin_generate_mnemonic_encrypt_with_tpm:**](#dogecoin_generate_mnemonic_encrypt_with_tpm)
    - [**dogecoin_decrypt_mnemonic_with_tpm:**](#dogecoin_decrypt_mnemonic_with_tpm)
    - [**dogecoin_generate_mnemonic_encrypt_with_sw:**](#dogecoin_generate_mnemonic_encrypt_with_sw)
    - [**dogecoin_decrypt_mnemonic_with_sw:**](#dogecoin_decrypt_mnemonic_with_sw)
    - [**dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey:**](#dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey)
    - [**dogecoin_decrypt_mnemonic_with_sw_from_yubikey:**](#dogecoin_decrypt_mnemonic_with_sw_from_yubikey)
    - [**generateRandomEnglishMnemonicTPM:**](#generaterandomenglishmnemonictpm)
    - [**generateRandomEnglishMnemonicSW:**](#generaterandomenglishmnemonicsw)
  - [HD Node API](#hd-node-api)
    - [**dogecoin_generate_hdnode_encrypt_with_tpm:**](#dogecoin_generate_hdnode_encrypt_with_tpm)
    - [**dogecoin_decrypt_hdnode_with_tpm:**](#dogecoin_decrypt_hdnode_with_tpm)
    - [**dogecoin_generate_hdnode_encrypt_with_sw:**](#dogecoin_generate_hdnode_encrypt_with_sw)
    - [**dogecoin_decrypt_hdnode_with_sw:**](#dogecoin_decrypt_hdnode_with_sw)
    - [**dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey:**](#dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey)
    - [**dogecoin_decrypt_hdnode_with_sw_from_yubikey:**](#dogecoin_decrypt_hdnode_with_sw_from_yubikey)
  - [Enumeration API](#enumeration-api)
    - [**dogecoin_list_encryption_keys_in_tpm:**](#dogecoin_list_encryption_keys_in_tpm)

## Introduction

The Seal API provides hardware-backed and software-backed encryption of
cryptographic secrets: BIP-32 seeds, BIP-39 mnemonics, and `dogecoin_hdnode`
master keys. Secrets are encrypted to a persistent wrapping key and the
resulting ciphertext is stored on disk, so the plaintext never resides in
unprotected storage.

### Platform support

`src/seal.c` selects an encryption backend at compile time:

- **Windows (TBS / NCrypt)** — `_WIN64 && USE_TPM2`
- **Linux (TSS2 / ESAPI)** — `__linux__ && USE_TSS2`
- **YubiKey PIV (PKCS#11)** — `USE_YUBIKEY` (cross-platform)
- **Software (AES-256-GCM)** — always available as a fallback

Include `<dogecoin/seal.h>` and link against `-ldogecoin` to use these
functions.

### Windows setup

Requires Windows 10+ with TPM 2.0 enabled. Build with CMake:

```bat
cmake -B build -DUSE_TPM2=ON
cmake --build build --config Release
```

Verify TPM availability with `Get-Tpm` or `tpm.msc`.

### Linux setup

Install the userspace TSS2 stack and a TPM (real hardware or an emulator):

```sh
# Build dependencies
sudo apt-get install -y libtss2-dev pkg-config
# Some distros package Esys headers/libs as:
#   libtss2-esys-dev

# For local testing without real hardware
sudo apt-get install -y swtpm tpm2-tools
```

Configure libdogecoin with TSS2 support:

```sh
./autogen.sh
./configure --enable-tss2
make -j$(nproc)
```

Both autotools and CMake prefer `pkg-config` (`tss2-esys >= 2.4.0`) and fall
back to a plain library lookup. They additionally verify the
`tss2/tss2_esys.h` header is present, so a misconfigured
`libtss2-dev`/`libtss2-esys-dev` install fails at configure time rather than
at link time.

### Testing with the swtpm emulator

The unit tests under `test/tpm_tests.c` work against either a real TPM 2.0
device or the [swtpm](https://github.com/stefanberger/swtpm) emulator. The
CI matrix uses swtpm on `127.0.0.1:2321` (command port) and `2322` (control
port) and the test driver picks up `tcti=swtpm` automatically when
configured via `TPM2TOOLS_TCTI`.

The Linux backend supports swtpm and normal kernel resource-manager access
through `/dev/tpmrm0`. Direct unprivileged access to `/dev/tpm0` can reject
startup or resource-management commands on some systems.

A typical local emulator setup:

```sh
# Start swtpm in TCP socket mode
mkdir -p /tmp/swtpm-state
swtpm socket \
  --tpm2 \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear \
  --tpmstate dir=/tmp/swtpm-state \
  --log level=20 &

# Point libdogecoin / tpm2-tools at the emulator
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

# Run the project test suite (non-interactive password)
./configure --enable-tss2
make check
```

The multi-persistent slot path is gated on
`TPM2_PT_HR_TRANSIENT_AVAIL >= 4`. Older `libtpms` (e.g. Ubuntu 22.04 ships
0.9.3 with `MAX_LOADED_OBJECTS = 3`) will skip those subtests.

### Persistent-handle layout (Linux/TSS2)

Each slot's wrapping key lives at a deterministic persistent handle in the
**owner hierarchy** range (`0x81710000`–`0x817EFFFF`). The base address
encodes the kind of secret, and the low 16 bits encode the file slot:

| Kind                | Base address  | Examples                  |
|---------------------|---------------|---------------------------|
| Encrypted seed      | `0x81710000`  | `0x81710000`–`0x8171FFFF` |
| Encrypted mnemonic  | `0x81720000`  | `0x81720000`–`0x8172FFFF` |
| Encrypted HD node   | `0x81730000`  | `0x81730000`–`0x8173FFFF` |

On disk, a newly encrypted blob is stored as ciphertext only, matching the
Windows NCrypt backend:

```
.store/<encrypted_* slot file> = [ RSA-2048 ciphertext ]
```

These handles are in the vendor-reserved owner-hierarchy persistent range and
have no IANA / TCG registration.  Avoid using the same handle range for other
TPM-consuming tools on the same machine to prevent collisions.

Both the Windows NCrypt backend and Linux/TSS2 backend encrypt plaintext
directly with RSAES-PKCS1-v1_5 and an RSA-2048 TPM wrapping key.  The Linux
path intentionally uses `TPM2_ALG_RSAES` to match the Windows API behavior
(`NCRYPT_PAD_PKCS1_FLAG`), and both backends store only the raw RSA ciphertext
on disk — no wrapper or metadata.  This means the on-disk file format is
identical between the two platforms, so in a dual-boot or shared-TPM scenario
a ciphertext produced by one backend can be decrypted by the other, provided
the same physical TPM persistent key and user password are available on both
operating systems.  OAEP would be cryptographically preferable for a new
standalone format, but switching this path would break that Windows/Linux
ciphertext compatibility goal.

Each sealed plaintext is limited by the RSAES padding capacity (245 bytes for
RSA-2048: 256-byte modulus minus the 11-byte minimum RSAES-PKCS1-v1_5 encoding
overhead).  BIP-32 seeds, HD nodes, and the generated English mnemonics fit
this limit; longer non-English mnemonics may fail to seal.  Both backends
resolve the persistent TPM key by the slot's object name.

---

## Seed API

---

### **dogecoin_encrypt_seed_with_tpm:**

`dogecoin_bool dogecoin_encrypt_seed_with_tpm(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite)`

Encrypts a BIP-32 seed using the TPM and stores the ciphertext in a file
identified by `file_num`. If `overwrite` is false and a file already exists,
the function returns false. The user is prompted for a password to protect
the TPM wrapping key.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
/* populate seed ... */
dogecoin_bool ok = dogecoin_encrypt_seed_with_tpm(seed, sizeof(seed), 0, true);
```

---

### **dogecoin_decrypt_seed_with_tpm:**

`dogecoin_bool dogecoin_decrypt_seed_with_tpm(SEED seed, const int file_num)`

Decrypts a BIP-32 seed previously encrypted with
`dogecoin_encrypt_seed_with_tpm`. The user is prompted for the password used
during encryption. Returns true on success and writes the plaintext into
`seed`.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
dogecoin_bool ok = dogecoin_decrypt_seed_with_tpm(seed, 0);
```

---

### **dogecoin_encrypt_seed_with_sw:**

`dogecoin_bool dogecoin_encrypt_seed_with_sw(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)`

Encrypts a BIP-32 seed using AES-256-GCM (software path) and stores the
result in a file identified by `file_num`. Pass `test_password` as NULL to
prompt the user interactively. The raw ciphertext is also returned via
`encrypted_blob_out` and `encrypted_blob_size` when those pointers are
non-NULL.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
/* populate seed ... */
dogecoin_bool ok = dogecoin_encrypt_seed_with_sw(seed, sizeof(seed), 0, true,
                                                 NULL, NULL, NULL);
```

---

### **dogecoin_decrypt_seed_with_sw:**

`dogecoin_bool dogecoin_decrypt_seed_with_sw(SEED seed, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)`

Decrypts a BIP-32 seed previously encrypted with `dogecoin_encrypt_seed_with_sw`.
Pass `test_password` as NULL to prompt interactively. Pass a non-NULL
`encrypted_blob` to decrypt from an in-memory buffer rather than from disk.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
dogecoin_bool ok = dogecoin_decrypt_seed_with_sw(seed, 0, NULL, NULL);
```

---

### **dogecoin_encrypt_seed_with_sw_to_yubikey:**

`dogecoin_bool dogecoin_encrypt_seed_with_sw_to_yubikey(const SEED seed, const size_t size, const int file_num, const dogecoin_bool overwrite, const char* test_password)`

Encrypts a BIP-32 seed with AES-256-GCM and stores the encrypted blob on a
YubiKey via PKCS#11 PIV. Requires a connected YubiKey and the
`USE_YUBIKEY` build flag. Pass `test_password` as NULL to prompt the user.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
/* populate seed ... */
dogecoin_bool ok = dogecoin_encrypt_seed_with_sw_to_yubikey(seed, sizeof(seed),
                                                             0, true, NULL);
```

---

### **dogecoin_decrypt_seed_with_sw_from_yubikey:**

`dogecoin_bool dogecoin_decrypt_seed_with_sw_from_yubikey(SEED seed, const int file_num, const char* test_password)`

Retrieves an encrypted seed blob from a YubiKey and decrypts it with
AES-256-GCM. Requires `USE_YUBIKEY`. Pass `test_password` as NULL to prompt
interactively.

_C usage:_

```c
#include <dogecoin/seal.h>

SEED seed = {0};
dogecoin_bool ok = dogecoin_decrypt_seed_with_sw_from_yubikey(seed, 0, NULL);
```

---

## Mnemonic API

---

### **dogecoin_generate_mnemonic_encrypt_with_tpm:**

`dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_tpm(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words)`

Generates a new BIP-39 mnemonic phrase, stores it in `mnemonic`, encrypts it
with the TPM, and writes the ciphertext to a file for slot `file_num`. The
user is prompted for a password to protect the wrapping key. Use `"eng"` (the ISO 639-2 language code)
for `lang` and `" "` for `space`. Pass NULL for `words` to generate a random
mnemonic.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_generate_mnemonic_encrypt_with_tpm(
    mnemonic, 0, true, "eng", " ", NULL);
```

---

### **dogecoin_decrypt_mnemonic_with_tpm:**

`dogecoin_bool dogecoin_decrypt_mnemonic_with_tpm(MNEMONIC mnemonic, const int file_num)`

Decrypts a BIP-39 mnemonic previously encrypted with
`dogecoin_generate_mnemonic_encrypt_with_tpm`. The user is prompted for the
password used during encryption. Returns true on success and writes the
plaintext mnemonic into `mnemonic`.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_decrypt_mnemonic_with_tpm(mnemonic, 0);
```

---

### **dogecoin_generate_mnemonic_encrypt_with_sw:**

`dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_sw(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)`

Generates a BIP-39 mnemonic and encrypts it with AES-256-GCM. Pass
`test_password` as NULL to prompt interactively. The raw ciphertext is also
returned via `encrypted_blob_out` and `encrypted_blob_size` when non-NULL.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_generate_mnemonic_encrypt_with_sw(
    mnemonic, 0, true, "eng", " ", NULL, NULL, NULL, NULL);
```

---

### **dogecoin_decrypt_mnemonic_with_sw:**

`dogecoin_bool dogecoin_decrypt_mnemonic_with_sw(MNEMONIC mnemonic, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)`

Decrypts a BIP-39 mnemonic previously encrypted with
`dogecoin_generate_mnemonic_encrypt_with_sw`. Pass `test_password` as NULL
to prompt interactively. Pass a non-NULL `encrypted_blob` to decrypt from
memory instead of disk.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_decrypt_mnemonic_with_sw(mnemonic, 0, NULL, NULL);
```

---

### **dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey:**

`dogecoin_bool dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, const char* lang, const char* space, const char* words, const char* test_password)`

Generates a BIP-39 mnemonic, encrypts it with AES-256-GCM, and stores it on
a YubiKey. Requires `USE_YUBIKEY`. Pass `test_password` as NULL to prompt
the user.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey(
    mnemonic, 0, true, "eng", " ", NULL, NULL);
```

---

### **dogecoin_decrypt_mnemonic_with_sw_from_yubikey:**

`dogecoin_bool dogecoin_decrypt_mnemonic_with_sw_from_yubikey(MNEMONIC mnemonic, const int file_num, const char* test_password)`

Retrieves an encrypted mnemonic blob from a YubiKey and decrypts it.
Requires `USE_YUBIKEY`. Pass `test_password` as NULL to prompt interactively.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = dogecoin_decrypt_mnemonic_with_sw_from_yubikey(mnemonic, 0, NULL);
```

---

### **generateRandomEnglishMnemonicTPM:**

`dogecoin_bool generateRandomEnglishMnemonicTPM(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite)`

Convenience wrapper that generates a random 256-bit English BIP-39 mnemonic
and encrypts it with the TPM under slot `file_num`. Equivalent to calling
`dogecoin_generate_mnemonic_encrypt_with_tpm` with `lang="eng"`,
`space=" "`, and `words=NULL`.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = generateRandomEnglishMnemonicTPM(mnemonic, 0, true);
```

---

### **generateRandomEnglishMnemonicSW:**

`dogecoin_bool generateRandomEnglishMnemonicSW(MNEMONIC mnemonic, const int file_num, const dogecoin_bool overwrite, ENCRYPTED_BLOB* encrypted_blob, size_t* encrypted_blob_size)`

Convenience wrapper that generates a random 256-bit English BIP-39 mnemonic
and encrypts it with the software (AES-256-GCM) path under slot `file_num`.
The raw ciphertext is returned via `encrypted_blob` and
`encrypted_blob_size` when non-NULL.

_C usage:_

```c
#include <dogecoin/seal.h>

MNEMONIC mnemonic = {0};
dogecoin_bool ok = generateRandomEnglishMnemonicSW(mnemonic, 0, true, NULL, NULL);
```

---

## HD Node API

---

### **dogecoin_generate_hdnode_encrypt_with_tpm:**

`dogecoin_bool dogecoin_generate_hdnode_encrypt_with_tpm(dogecoin_hdnode* out, const int file_num, const dogecoin_bool overwrite)`

Generates a new BIP-32 HD master node, stores it in `out`, encrypts it with
the TPM, and writes the ciphertext to a file for slot `file_num`. The user is
prompted for a password to protect the wrapping key.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_generate_hdnode_encrypt_with_tpm(&node, 0, true);
```

---

### **dogecoin_decrypt_hdnode_with_tpm:**

`dogecoin_bool dogecoin_decrypt_hdnode_with_tpm(dogecoin_hdnode* out, const int file_num)`

Decrypts a BIP-32 HD node previously encrypted with
`dogecoin_generate_hdnode_encrypt_with_tpm`. The user is prompted for the
password used during encryption. Returns true and populates `out` on success.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_decrypt_hdnode_with_tpm(&node, 0);
```

---

### **dogecoin_generate_hdnode_encrypt_with_sw:**

`dogecoin_bool dogecoin_generate_hdnode_encrypt_with_sw(dogecoin_hdnode* out, const int file_num, const dogecoin_bool overwrite, const char* test_password, ENCRYPTED_BLOB* encrypted_blob_out, size_t* encrypted_blob_size)`

Generates a BIP-32 HD master node and encrypts it with AES-256-GCM. Pass
`test_password` as NULL to prompt interactively. The raw ciphertext is
returned via `encrypted_blob_out` and `encrypted_blob_size` when non-NULL.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_generate_hdnode_encrypt_with_sw(
    &node, 0, true, NULL, NULL, NULL);
```

---

### **dogecoin_decrypt_hdnode_with_sw:**

`dogecoin_bool dogecoin_decrypt_hdnode_with_sw(dogecoin_hdnode* out, const int file_num, const char* test_password, ENCRYPTED_BLOB encrypted_blob)`

Decrypts a BIP-32 HD node previously encrypted with
`dogecoin_generate_hdnode_encrypt_with_sw`. Pass `test_password` as NULL to
prompt interactively. Pass a non-NULL `encrypted_blob` to decrypt from memory
instead of disk.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_decrypt_hdnode_with_sw(&node, 0, NULL, NULL);
```

---

### **dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey:**

`dogecoin_bool dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey(dogecoin_hdnode* out, const int file_num, const dogecoin_bool overwrite, const char* test_password)`

Generates a BIP-32 HD master node, encrypts it with AES-256-GCM, and stores
it on a YubiKey. Requires `USE_YUBIKEY`. Pass `test_password` as NULL to
prompt the user.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey(
    &node, 0, true, NULL);
```

---

### **dogecoin_decrypt_hdnode_with_sw_from_yubikey:**

`dogecoin_bool dogecoin_decrypt_hdnode_with_sw_from_yubikey(dogecoin_hdnode* out, const int file_num, const char* test_password)`

Retrieves an encrypted HD node blob from a YubiKey and decrypts it.
Requires `USE_YUBIKEY`. Pass `test_password` as NULL to prompt interactively.

_C usage:_

```c
#include <dogecoin/seal.h>

dogecoin_hdnode node;
dogecoin_bool ok = dogecoin_decrypt_hdnode_with_sw_from_yubikey(&node, 0, NULL);
```

---

## Enumeration API

---

### **dogecoin_list_encryption_keys_in_tpm:**

`dogecoin_bool dogecoin_list_encryption_keys_in_tpm(wchar_t* names[], size_t* count)`

Enumerates all libdogecoin persistent handles currently provisioned in the
TPM and writes their string names into `names`. On return, `*count` contains
the number of entries populated. The caller is responsible for freeing each
`names[i]` string with `dogecoin_free`. Returns true if the enumeration
succeeded.

_C usage:_

```c
#include <dogecoin/seal.h>
#include <dogecoin/mem.h>

wchar_t* names[MAX_FILES] = {0};
size_t count = 0;
if (dogecoin_list_encryption_keys_in_tpm(names, &count)) {
    for (size_t i = 0; i < count; i++) {
        wprintf(L"slot: %ls\n", names[i]);
        dogecoin_free(names[i]);
    }
}
```

---
