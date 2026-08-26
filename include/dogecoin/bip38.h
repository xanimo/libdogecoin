/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __LIBDOGECOIN_BIP38_H__
#define __LIBDOGECOIN_BIP38_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>

LIBDOGECOIN_BEGIN_DECL

/* BIP38 constants (non-EC multiplied keys: 0x01 0x42 + flag + addresshash + ciphertext) */
#define BIP38_MAGIC_BYTE 0x01
/** Second byte: non-EC multiplied key type (BIP38). */
#define BIP38_TYPE_NON_EC 0x42
/** Flag byte: top bits reserved per BIP38; bit 5 = compressed pubkey. */
#define BIP38_FLAG_BASE 0xC0
/** EC-multiplied flag byte: bit 4 is reserved and must be zero. */
#define BIP38_FLAG_RESERVED_BIT 0x10
#define BIP38_SCRYPT_N 16384
#define BIP38_SCRYPT_R 8
#define BIP38_SCRYPT_P 8
#define BIP38_SCRYPT_KEYSIZE 64
#define BIP38_SCRYPT_SALTSIZE 4
#define BIP38_SCRYPT_DERIVED_SIZE 64

/* BIP38 encrypted key length */
#define BIP38_ENCRYPTED_KEY_LENGTH 58

/* Intermediate passphrase code and confirmation code buffer sizes */
#define BIP38_INTERMEDIATE_CODE_MAXLEN 73
#define BIP38_CONFIRMATION_CODE_MAXLEN 76
#define BIP38_SEEDB_LEN 24
#define BIP38_INTERMEDIATE_PAYLOAD_LEN 49
#define BIP38_CONFIRMATION_PAYLOAD_LEN 51

/* BIP38 address hash length */
#define BIP38_ADDRESS_HASH_LENGTH 4

/* BIP38 compressed flag */
#define BIP38_COMPRESSED_FLAG 0x20

/* BIP38 lot/sequence flag */
#define BIP38_LOT_SEQUENCE_FLAG 0x04

/* BIP38 has lot/sequence flag */
#define BIP38_HAS_LOT_SEQUENCE_FLAG 0x08

/*
 * Address-hash verification mode for decrypt / confirmation helpers.
 * Default (mainnet): embedded hash must match a Dogecoin mainnet P2PKH address.
 * Interop: also accepts testnet, regtest, and legacy Bitcoin P2PKH (0x00) for
 * strict BIP-0038 test vectors and cross-chain paper wallets.
 */
#define BIP38_ADDRESS_MATCH_MAINNET 0u
#define BIP38_ADDRESS_MATCH_INTEROP 1u

/* EC multiplied key type (second byte of payload). */
#define BIP38_TYPE_EC_MULTIPLIED 0x43

/* BIP38 encrypted key structure */
typedef struct {
    uint8_t magic_byte;
    uint8_t flag_byte;
    uint8_t address_hash[BIP38_ADDRESS_HASH_LENGTH];
    uint8_t encrypted_key[32];
    uint8_t checksum[4];
} dogecoin_bip38_encrypted_key;

/* BIP38 lot/sequence structure */
typedef struct {
    uint8_t lot[4];
    uint8_t sequence[4];
} dogecoin_bip38_lot_sequence;

/* BIP38 EC multiplied structure */
typedef struct {
    uint8_t owner_entropy[8];
    uint8_t encrypted_part1[8];
    uint8_t encrypted_part2[16];
} dogecoin_bip38_ec_multiplied;

/*
 * Function declarations
 */

/* Encrypt a private key using BIP38 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size
);

/* Decrypt a BIP38 encrypted private key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/* Decrypt with explicit address-hash matching mode (see BIP38_ADDRESS_MATCH_*). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_ex(
    const char* encrypted_key,
    const char* passphrase,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/* Decrypt with explicit passphrase byte length (NFC applied; supports embedded NUL). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_passphrase(
    const char* encrypted_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/* Decrypt with explicit passphrase length and address-hash matching mode. */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_passphrase_ex(
    const char* encrypted_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/* Non-EC encrypt with explicit passphrase byte length (NFC applied; supports embedded NUL). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt_passphrase(
    const uint8_t* private_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size
);

/* Decrypt a BIP38 encrypted private key with lot/sequence */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Decrypt with lot/sequence and explicit address-hash matching mode. */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence_ex(
    const char* encrypted_key,
    const char* passphrase,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Check if a string is a valid BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key);

/* Get the address hash from a BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_get_address_hash(
    const char* encrypted_key,
    uint8_t* address_hash_out
);

/* Verify the address hash matches the given address */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_verify_address_hash(
    const char* encrypted_key,
    const char* address
);

/* Get the flag byte from a BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_get_flag_byte(
    const char* encrypted_key,
    uint8_t* flag_byte_out
);

/* Check if a BIP38 encrypted key is compressed */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_compressed(const char* encrypted_key);

/* Check if a BIP38 encrypted key has lot/sequence */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_has_lot_sequence(const char* encrypted_key);

/* Check if a BIP38 encrypted key is EC multiplied */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_ec_multiplied(const char* encrypted_key);

/* Generate a random lot and sequence for BIP38 */
LIBDOGECOIN_API void dogecoin_bip38_generate_lot_sequence(
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Convert a private key to WIF format */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_private_key_to_wif(
    const uint8_t* private_key,
    const dogecoin_chainparams* chain,
    dogecoin_bool compressed,
    char* wif_out,
    size_t* wif_size
);

/* Convert a WIF private key to raw format */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_wif_to_private_key(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/*
 * EC-multiplied BIP38 (0x43): intermediate codes, encryption, confirmation.
 * EC mode generates a new key (passfactor * factorb); it does not wrap an arbitrary existing key.
 */

/* Owner-side intermediate passphrase string (starts with "passphrase"). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_generate_intermediate_code(
    const char* passphrase,
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    const uint8_t* ownerentropy_override,
    char* intermediate_code_out,
    size_t* intermediate_code_size
);

/*
 * Printer-side: create encrypted key (+ optional confirmation code) from intermediate code.
 * The printer never holds the owner's private key; there is no private_key_out parameter.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt_from_intermediate(
    const char* intermediate_code,
    dogecoin_bool compressed,
    const uint8_t* seedb_override,
    const char* address_chain_hint,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size
);

/* Owner verifies confirmation code matches passphrase (and optional lot/sequence). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_confirm_passphrase(
    const char* passphrase,
    const char* confirmation_code,
    char* address_out,
    size_t address_size,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Owner verifies confirmation code (Dogecoin mainnet address output by default).
 * INTEROP mode uses the same multi-chain address matching as decrypt_ex. */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_confirm_passphrase_ex(
    const char* passphrase,
    const char* confirmation_code,
    unsigned int address_match_mode,
    char* address_out,
    size_t address_size,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* One-shot EC-multiplied encrypt (optional lot/sequence, optional confirmation code). */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt_ec_multiplied(
    const char* passphrase,
    dogecoin_bool compressed,
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    const char* address_chain_hint,
    uint8_t* private_key_out,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size
);

LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_intermediate_code(const char* code);
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_confirmation_code(const char* code);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BIP38_H__
