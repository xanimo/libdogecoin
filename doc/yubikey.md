### YubiKey Storage of Encrypted Keys

> **Scope.** This document covers libdogecoin's **PIV-based** YubiKey integration, used by the `seal` module for encrypted seed/key storage.
>
> - **Enabled by:** `./configure --enable-yubikey`
> - **Links against:** system `libykpiv` + `libpcsclite`
> - **YubiKey application used:** PIV (Personal Identity Verification)

The YubiKey is a hardware security key that provides strong two-factor authentication and secure cryptographic operations. By integrating the YubiKey with libdogecoin, users can enhance the security of their wallets and transactions. While the integration is tested with YubiKey 5 NFC, it also works with other YubiKey models that support PIV (Personal Identity Verification).

YubiKey supports numerous cryptographic operations; for libdogecoin, we are primarily interested in the PIV application. The PIV application provides a secure way to store private keys. The YubiKey acts as secure key storage, protecting the private keys from unauthorized access.

We have integrated the YubiKey with the `seal` module, specifically for encrypted key storage. The `seal` module is responsible for encrypting and decrypting the private keys stored in the YubiKey. By using the YubiKey, users can securely store and retrieve their private keys during wallet operations.

The process involves multi-factor authentication (PIN and YubiKey) to unlock the encrypted keys, followed by the decryption of BIP39 mnemonics. The seed, master key, or mnemonic is first encrypted with software and then stored on the YubiKey. During the storage process, the user enters a management password, and to retrieve the key, the user enters the YubiKey PIN.

Its recommeded that the user download the YubiKey Manager to manage the YubiKey. The YubiKey Manager is a graphical user interface that allows users to change the PIN, management key, and other settings. The YubiKey Manager is available for Windows, macOS, and Linux from the [Yubico website](https://www.yubico.com/support/download/yubikey-manager/).

### Default PIV credentials

A factory-fresh (or `ykman piv reset`) YubiKey ships with the well-known
default PIV credentials below. libdogecoin prompts for the **management key**
when storing a key (write) and for the **PIN** when retrieving one (read):

| Credential | Factory default | Prompted for |
| --- | --- | --- |
| PIV management key | `010203040506070801020304050607080102030405060708` | storing a key (encrypt/write) |
| PIN | `123456` | retrieving a key (decrypt/read) |
| PUK | `12345678` | unblocking a locked PIN |

> **Security note.** These are public factory defaults, useful for testing and
> for first provisioning. **Change the management key, PIN, and PUK before
> storing real key material** (e.g. with the YubiKey Manager or `ykman piv`).
> Entering the wrong PIN three times blocks it, after which the PUK is required
> to reset it; the management key is not retry-limited.

### Dependencies
- `libykpiv` - The YubiKey C library for interacting with the YubiKey.
- `libykpiv-dev` - The development headers for the YubiKey C library.
- `pcscd` - The PC/SC smart card daemon for managing smart card readers.
- `libpcsclite-dev` - The development headers for the PC/SC smart card library.

### Installation
#### Linux
```sh
sudo apt-get update
sudo apt-get install libykpiv libykpiv-dev pcscd libpcsclite-dev
```

### Example C Code
```c
// Encrypt a BIP32 seed with software and store it on YubiKey
u_assert_true(dogecoin_encrypt_seed_with_sw_to_yubikey(seed, sizeof(SEED), TEST_FILE, true, test_password));
debug_print("Seed to YubiKey: %s\n", utils_uint8_to_hex(seed, sizeof(SEED)));
debug_print("Encrypted seed: %s\n", utils_uint8_to_hex(file, filesize));

// Decrypt a BIP32 seed with software after retrieving it from YubiKey
uint8_t decrypted_seed[4096] = {0};
u_assert_true(dogecoin_decrypt_seed_with_sw_from_yubikey(decrypted_seed, TEST_FILE, test_password));
debug_print("Decrypted seed: %s\n", utils_uint8_to_hex(decrypted_seed, decrypted_size));
u_assert_true(memcmp(seed, decrypted_seed, sizeof(SEED)) == 0);
```

### Command-line usage (`such`)

Build the CLI with YubiKey support (`./configure --enable-yubikey`), then pass
`-u` (`--yubikey`) together with `-y <file_num>` on any of the encrypted-key
commands. `-u` selects the YubiKey backend the same way `-j` selects the TPM
backend; the two are mutually exclusive, and both require `-y` (an encrypted
slot). Each command prompts for the wallet password, plus the YubiKey
management key when writing or the PIN when reading.

```sh
# Store a freshly generated HD master key on the YubiKey in slot 0
such -c bip32_extended_master_key -y 0 -u

# Retrieve and print that master key from the YubiKey
such -c decrypt_master_key -y 0 -u

# Store / retrieve a BIP39 mnemonic
such -c generate_mnemonic -y 0 -u -b        # -b = silent (do not echo on store)
such -c decrypt_mnemonic -y 0 -u

# Derive keys/addresses straight from the YubiKey-stored mnemonic
such -c mnemonic_to_key       -y 0 -u
such -c mnemonic_to_addresses -y 0 -u -o 0 -g 0 -i 1

# Reconstruct the master key from a YubiKey-stored seed
such -c seed_to_master_key -y 0 -u
```

`-u` accepts the same modifiers as the TPM path: `-w` (overwrite an existing
slot) and `-b` (silent). Passing `-u` on a build compiled without
`--enable-yubikey` fails with a clear "YubiKey support not compiled in" error.