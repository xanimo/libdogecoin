/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * BIP-0038: non-EC (0x42) and EC-multiplied (0x43) keys, intermediate codes, confirmation.
 */

#include <dogecoin/bip38.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/base58.h>
#include <dogecoin/ctaes.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/sha2.h>
#include <dogecoin/random.h>
#include <dogecoin/mem.h>
#include <dogecoin/key.h>
#include <dogecoin/ecc.h>
#include <dogecoin/address.h>
#include <dogecoin/utf8proc.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    const uint8_t* data;
    size_t len;
    uint8_t* allocated;
} bip38_passphrase_buf;

static void bip38_passphrase_acquire_bytes(
    const uint8_t* passphrase,
    size_t passphrase_len,
    bip38_passphrase_buf* out)
{
    utf8proc_uint8_t* mapped = NULL;
    utf8proc_ssize_t mapped_len;

    out->allocated = NULL;
    out->data = NULL;
    out->len = 0;
    if (!passphrase) {
        return;
    }
    if (passphrase_len == 0) {
        passphrase_len = strlen((const char*)passphrase);
    }
    mapped_len = utf8proc_map(
        passphrase,
        (utf8proc_ssize_t)passphrase_len,
        &mapped,
        UTF8PROC_STABLE | UTF8PROC_COMPOSE);
    if (mapped_len >= 0 && mapped) {
        out->allocated = mapped;
        out->data = mapped;
        out->len = (size_t)mapped_len;
        return;
    }
    out->data = passphrase;
    out->len = passphrase_len;
}

static void bip38_passphrase_acquire(const char* passphrase, bip38_passphrase_buf* out)
{
    bip38_passphrase_acquire_bytes((const uint8_t*)passphrase, 0, out);
}

static void bip38_passphrase_release(bip38_passphrase_buf* buf)
{
    if (buf && buf->allocated) {
        dogecoin_mem_zero(buf->allocated, buf->len);
        free(buf->allocated);
        buf->allocated = NULL;
        buf->data = NULL;
        buf->len = 0;
    }
}

#define BIP38_LOT_MAX 1048575u
#define BIP38_SEQUENCE_MAX 4095u
#define BIP38_PAYLOAD_LEN 39
/* dogecoin_base58_decode_check() requires data[] length >= strlen(base58 string). */
#define BIP38_BASE58_DECODE_BUFLEN 128

static dogecoin_bool bip38_mem_eq(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static dogecoin_bool bip38_validate_flags(uint8_t type_byte, uint8_t flag_byte)
{
    if (type_byte == BIP38_TYPE_NON_EC) {
        if (flag_byte != BIP38_FLAG_BASE && flag_byte != (BIP38_FLAG_BASE | BIP38_COMPRESSED_FLAG)) {
            return false;
        }
        if ((flag_byte & BIP38_LOT_SEQUENCE_FLAG) != 0) {
            return false;
        }
        if ((flag_byte & BIP38_HAS_LOT_SEQUENCE_FLAG) != 0) {
            return false;
        }
        return true;
    }
    if (type_byte == BIP38_TYPE_EC_MULTIPLIED) {
        if ((flag_byte & 0x10) != 0) {
            return false;
        }
        if ((flag_byte & BIP38_HAS_LOT_SEQUENCE_FLAG) != 0) {
            return false;
        }
        if ((flag_byte & ~(BIP38_COMPRESSED_FLAG | BIP38_LOT_SEQUENCE_FLAG)) != 0) {
            return false;
        }
        return true;
    }
    return false;
}

static dogecoin_bool bip38_decode_encrypted_payload(
    const char* encrypted_key,
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN],
    size_t* declen_out)
{
    size_t declen;

    if (!encrypted_key || !declen_out) {
        return false;
    }

    declen = dogecoin_base58_decode_check(encrypted_key, decoded, BIP38_BASE58_DECODE_BUFLEN);
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }
    if (decoded[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    if (decoded[1] != BIP38_TYPE_NON_EC && decoded[1] != BIP38_TYPE_EC_MULTIPLIED) {
        return false;
    }
    if (!bip38_validate_flags(decoded[1], decoded[2])) {
        return false;
    }
    *declen_out = declen;
    return true;
}

static const uint8_t BIP38_INTERMEDIATE_MAGIC_LOT[8] =
    {0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51};
static const uint8_t BIP38_INTERMEDIATE_MAGIC_NOLOT[8] =
    {0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53};
static const uint8_t BIP38_CONFIRMATION_MAGIC[5] =
    {0x64, 0x3B, 0xF6, 0xA8, 0x9A};

/* First four bytes of SHA256(SHA256(utf8 address)). */
static void bip38_address_hash(const char* address, uint8_t address_hash_out[4])
{
    uint8_t h[SHA256_DIGEST_LENGTH];
    sha256_raw((const uint8_t*)address, strlen(address), h);
    sha256_raw(h, SHA256_DIGEST_LENGTH, h);
    memcpy(address_hash_out, h, 4);
}

static dogecoin_bool bip38_derive_key_bytes(
    const uint8_t* passphrase,
    size_t passphrase_len,
    const uint8_t salt[4],
    uint8_t derived_key[64])
{
    bip38_passphrase_buf norm;
    dogecoin_bool ok;

    bip38_passphrase_acquire_bytes(passphrase, passphrase_len, &norm);
    if (!norm.data || norm.len == 0) {
        bip38_passphrase_release(&norm);
        return false;
    }
    ok = dogecoin_scrypt_rfc7914(
        norm.data,
        norm.len,
        salt,
        4,
        BIP38_SCRYPT_N,
        BIP38_SCRYPT_R,
        BIP38_SCRYPT_P,
        derived_key,
        BIP38_SCRYPT_DERIVED_SIZE);
    bip38_passphrase_release(&norm);
    return ok;
}

static void bip38_encrypt_halves(
    const uint8_t* private_key,
    const uint8_t* derived_64,
    uint8_t encrypted[32])
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    AES256_ctx ctx;
    AES256_init(&ctx, derivedhalf2);

    for (unsigned i = 0; i < 16; i++)
        block[i] = private_key[i] ^ derivedhalf1[i];
    AES256_encrypt(&ctx, 1, encrypted, block);

    for (unsigned i = 0; i < 16; i++)
        block[i] = private_key[16 + i] ^ derivedhalf1[16 + i];
    AES256_encrypt(&ctx, 1, encrypted + 16, block);
}

static void bip38_decrypt_halves(
    const uint8_t encrypted[32],
    const uint8_t* derived_64,
    uint8_t private_key_out[32])
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    AES256_ctx ctx;
    AES256_init(&ctx, derivedhalf2);

    AES256_decrypt(&ctx, 1, block, encrypted);
    for (unsigned i = 0; i < 16; i++)
        private_key_out[i] = block[i] ^ derivedhalf1[i];

    AES256_decrypt(&ctx, 1, block, encrypted + 16);
    for (unsigned i = 0; i < 16; i++)
        private_key_out[16 + i] = block[i] ^ derivedhalf1[16 + i];
}

static void bip38_aes256_decrypt_block(
    const uint8_t* derived_64,
    const uint8_t* cipher,
    unsigned derivedhalf1_offset,
    uint8_t* plain)
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    AES256_ctx ctx;
    AES256_init(&ctx, derivedhalf2);
    AES256_decrypt(&ctx, 1, block, cipher);
    for (unsigned i = 0; i < 16; i++)
        plain[i] = block[i] ^ derivedhalf1[derivedhalf1_offset + i];
}

static void bip38_aes256_encrypt_block(
    const uint8_t* derived_64,
    const uint8_t* plain,
    unsigned derivedhalf1_offset,
    uint8_t* cipher)
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    unsigned i;
    AES256_ctx ctx;
    for (i = 0; i < 16; i++) {
        block[i] = plain[i] ^ derivedhalf1[derivedhalf1_offset + i];
    }
    AES256_init(&ctx, derivedhalf2);
    AES256_encrypt(&ctx, 1, cipher, block);
}

static void bip38_factorb_from_seedb(const uint8_t seedb[24], uint8_t factorb_out[32])
{
    sha256_raw(seedb, 24, factorb_out);
    sha256_raw(factorb_out, 32, factorb_out);
}

static const dogecoin_chainparams* bip38_chain_from_address_hint(const char* address)
{
    if (!address || !address[0]) {
        return NULL;
    }
    if (address[0] == 'D') {
        return &dogecoin_chainparams_main;
    }
    if (address[0] == 'n' || address[0] == 'm') {
        return &dogecoin_chainparams_test;
    }
    return NULL;
}

static dogecoin_bool bip38_pubkey_to_address(
    const uint8_t* pubkey,
    size_t pubkey_len,
    dogecoin_bool compressed,
    const dogecoin_chainparams* chain,
    char* address_out)
{
    dogecoin_pubkey pk;
    dogecoin_pubkey_init(&pk);
    memcpy(pk.pubkey, pubkey, pubkey_len);
    pk.compressed = compressed;
    if (chain) {
        return dogecoin_pubkey_getaddr_p2pkh(&pk, chain, address_out);
    }
    {
        uint8_t hash160[sizeof(uint160_t)];
        dogecoin_pubkey_get_hash160(&pk, hash160);
        uint8_t payload[21];
        payload[0] = 0x00;
        memcpy(payload + 1, hash160, sizeof(hash160));
        return dogecoin_base58_encode_check(payload, 21, address_out, P2PKHLEN) != 0;
    }
}

static dogecoin_bool bip38_ec_derived_key(
    const uint8_t passpoint[33],
    const uint8_t addresshash[4],
    const uint8_t ownerentropy[8],
    uint8_t derived_out[64])
{
    uint8_t scrypt_salt[12];
    memcpy(scrypt_salt, addresshash, 4);
    memcpy(scrypt_salt + 4, ownerentropy, 8);
    return dogecoin_scrypt_rfc7914(
        passpoint,
        DOGECOIN_ECKEY_COMPRESSED_LENGTH,
        scrypt_salt,
        sizeof(scrypt_salt),
        1024,
        1,
        1,
        derived_out,
        BIP38_SCRYPT_DERIVED_SIZE);
}

static void bip38_ownerentropy_generate(
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    uint8_t ownerentropy_out[8])
{
    if (use_lot_sequence) {
        uint32_t lotsequence = lot * 4096u + sequence;
        dogecoin_random_bytes(ownerentropy_out, 4, 1);
        ownerentropy_out[4] = (uint8_t)((lotsequence >> 24) & 0xff);
        ownerentropy_out[5] = (uint8_t)((lotsequence >> 16) & 0xff);
        ownerentropy_out[6] = (uint8_t)((lotsequence >> 8) & 0xff);
        ownerentropy_out[7] = (uint8_t)(lotsequence & 0xff);
    } else {
        dogecoin_random_bytes(ownerentropy_out, 8, 1);
    }
}

static dogecoin_bool bip38_parse_intermediate_code(
    const char* intermediate_code,
    uint8_t ownerentropy_out[8],
    uint8_t passpoint_out[33],
    dogecoin_bool* has_lot_sequence_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;
    const uint8_t* magic;

    if (!intermediate_code || !ownerentropy_out || !passpoint_out || !has_lot_sequence_out) {
        return false;
    }

    declen = dogecoin_base58_decode_check(intermediate_code, decoded, sizeof(decoded));
    if (declen != BIP38_INTERMEDIATE_PAYLOAD_LEN + 4) {
        return false;
    }

    if (memcmp(decoded, BIP38_INTERMEDIATE_MAGIC_LOT, 8) == 0) {
        magic = BIP38_INTERMEDIATE_MAGIC_LOT;
        *has_lot_sequence_out = true;
    } else if (memcmp(decoded, BIP38_INTERMEDIATE_MAGIC_NOLOT, 8) == 0) {
        magic = BIP38_INTERMEDIATE_MAGIC_NOLOT;
        *has_lot_sequence_out = false;
    } else {
        return false;
    }
    (void)magic;

    memcpy(ownerentropy_out, decoded + 8, 8);
    memcpy(passpoint_out, decoded + 16, 33);
    return true;
}

static dogecoin_bool bip38_confirmation_encode(
    uint8_t flagbyte,
    const uint8_t addresshash[4],
    const uint8_t ownerentropy[8],
    const uint8_t factorb[32],
    const uint8_t derived[64],
    char* confirmation_code_out,
    size_t* confirmation_code_size)
{
    uint8_t pointb[33];
    size_t pointb_len = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    uint8_t encryptedpointb[33];
    uint8_t pointbx1[16];
    uint8_t pointbx2[16];
    uint8_t payload[BIP38_CONFIRMATION_PAYLOAD_LEN];
    size_t written;

    if (!confirmation_code_out || !confirmation_code_size) {
        return false;
    }
    if (*confirmation_code_size < BIP38_CONFIRMATION_CODE_MAXLEN) {
        return false;
    }

    dogecoin_ecc_get_pubkey(factorb, pointb, &pointb_len, true);
    encryptedpointb[0] = (uint8_t)(pointb[0] ^ (derived[63] & 0x01));
    bip38_aes256_encrypt_block(derived, pointb + 1, 0, pointbx1);
    bip38_aes256_encrypt_block(derived, pointb + 17, 16, pointbx2);
    memcpy(encryptedpointb + 1, pointbx1, 16);
    memcpy(encryptedpointb + 17, pointbx2, 16);

    memcpy(payload, BIP38_CONFIRMATION_MAGIC, 5);
    payload[5] = flagbyte;
    memcpy(payload + 6, addresshash, 4);
    memcpy(payload + 10, ownerentropy, 8);
    memcpy(payload + 18, encryptedpointb, 33);

    written = dogecoin_base58_encode_check(payload, BIP38_CONFIRMATION_PAYLOAD_LEN,
        confirmation_code_out, *confirmation_code_size);
    if (written == 0) {
        return false;
    }
    *confirmation_code_size = written;
    return true;
}

static dogecoin_bool bip38_encrypt_ec_core(
    const uint8_t passpoint[33],
    const uint8_t ownerentropy[8],
    dogecoin_bool has_lot_sequence,
    dogecoin_bool compressed,
    const uint8_t seedb[24],
    const dogecoin_chainparams* chain,
    const uint8_t* passfactor_optional,
    uint8_t* private_key_out,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size)
{
    uint8_t factorb[32];
    uint8_t passpoint_work[33];
    uint8_t addresshash[4];
    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    uint8_t encryptedpart1[16];
    uint8_t encryptedpart2[16];
    uint8_t block2[16];
    uint8_t flagbyte;
    char generated_address[P2PKHLEN];
    uint8_t payload[BIP38_PAYLOAD_LEN];
    uint8_t pubkey_buf[DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH];
    size_t pubkey_len;
    size_t written;

    if (!passpoint || !ownerentropy || !seedb || !encrypted_key_out || !encrypted_key_size) {
        return false;
    }
    if (*encrypted_key_size < BIP38_ENCRYPTED_KEY_LENGTH + 1) {
        return false;
    }

    bip38_factorb_from_seedb(seedb, factorb);

    if (passfactor_optional) {
        uint8_t priv[32];
        size_t pk_len = compressed ? DOGECOIN_ECKEY_COMPRESSED_LENGTH : DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH;
        memcpy(priv, passfactor_optional, 32);
        if (!dogecoin_ecc_private_key_tweak_mul(priv, factorb)) {
            dogecoin_mem_zero(factorb, sizeof(factorb));
            dogecoin_mem_zero(priv, sizeof(priv));
            return false;
        }
        dogecoin_ecc_get_pubkey(priv, pubkey_buf, &pk_len, compressed);
        if (private_key_out) {
            memcpy(private_key_out, priv, 32);
        }
        dogecoin_mem_zero(priv, sizeof(priv));
        pubkey_len = pk_len;
    } else {
        memcpy(passpoint_work, passpoint, 33);
        if (!dogecoin_ecc_public_key_tweak_mul(passpoint_work, factorb)) {
            dogecoin_mem_zero(factorb, sizeof(factorb));
            return false;
        }
        pubkey_len = compressed ? DOGECOIN_ECKEY_COMPRESSED_LENGTH : DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH;
        if (!dogecoin_ecc_point_serialize(passpoint_work, 33, pubkey_buf, &pubkey_len, compressed)) {
            dogecoin_mem_zero(factorb, sizeof(factorb));
            return false;
        }
    }

    if (!bip38_pubkey_to_address(pubkey_buf, pubkey_len, compressed, chain, generated_address)) {
        dogecoin_mem_zero(factorb, sizeof(factorb));
        return false;
    }
    bip38_address_hash(generated_address, addresshash);

    if (!bip38_ec_derived_key(passpoint, addresshash, ownerentropy, derived)) {
        dogecoin_mem_zero(factorb, sizeof(factorb));
        return false;
    }

    bip38_aes256_encrypt_block(derived, seedb, 0, encryptedpart1);
    memcpy(block2, encryptedpart1 + 8, 8);
    memcpy(block2 + 8, seedb + 16, 8);
    bip38_aes256_encrypt_block(derived, block2, 16, encryptedpart2);

    flagbyte = 0;
    if (compressed) {
        flagbyte |= BIP38_COMPRESSED_FLAG;
    }
    if (has_lot_sequence) {
        flagbyte |= BIP38_LOT_SEQUENCE_FLAG;
    }

    payload[0] = BIP38_MAGIC_BYTE;
    payload[1] = BIP38_TYPE_EC_MULTIPLIED;
    payload[2] = flagbyte;
    memcpy(payload + 3, addresshash, 4);
    memcpy(payload + 7, ownerentropy, 8);
    memcpy(payload + 15, encryptedpart1, 8);
    memcpy(payload + 23, encryptedpart2, 16);

    written = dogecoin_base58_encode_check(payload, BIP38_PAYLOAD_LEN, encrypted_key_out, *encrypted_key_size);
    if (written == 0) {
        dogecoin_mem_zero(derived, sizeof(derived));
        dogecoin_mem_zero(factorb, sizeof(factorb));
        return false;
    }
    *encrypted_key_size = written;

    if (confirmation_code_out && confirmation_code_size) {
        if (!bip38_confirmation_encode(flagbyte, addresshash, ownerentropy, factorb, derived,
                confirmation_code_out, confirmation_code_size)) {
            dogecoin_mem_zero(derived, sizeof(derived));
            dogecoin_mem_zero(factorb, sizeof(factorb));
            return false;
        }
    }

    dogecoin_mem_zero(derived, sizeof(derived));
    dogecoin_mem_zero(factorb, sizeof(factorb));
    return true;
}

static dogecoin_bool bip38_derive_passfactor_buf(
    const bip38_passphrase_buf* norm,
    const uint8_t ownerentropy[8],
    dogecoin_bool has_lot_sequence,
    uint8_t passfactor_out[32])
{
    const uint8_t* ownersalt = ownerentropy;
    size_t ownersalt_len = has_lot_sequence ? 4 : 8;
    uint8_t prefactor[32];

    if (!norm || !norm->data || norm->len == 0) {
        return false;
    }
    if (!dogecoin_scrypt_rfc7914(
            norm->data,
            norm->len,
            ownersalt,
            ownersalt_len,
            BIP38_SCRYPT_N,
            BIP38_SCRYPT_R,
            BIP38_SCRYPT_P,
            prefactor,
            32)) {
        return false;
    }

    if (has_lot_sequence) {
        uint8_t buf[40];
        memcpy(buf, prefactor, 32);
        memcpy(buf + 32, ownerentropy, 8);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        sha256_raw(buf, sizeof(buf), hash);
        sha256_raw(hash, SHA256_DIGEST_LENGTH, hash);
        memcpy(passfactor_out, hash, 32);
    } else {
        memcpy(passfactor_out, prefactor, 32);
    }
    dogecoin_mem_zero(prefactor, sizeof(prefactor));
    return true;
}

static dogecoin_bool bip38_derive_passfactor(
    const char* passphrase,
    const uint8_t ownerentropy[8],
    dogecoin_bool has_lot_sequence,
    uint8_t passfactor_out[32])
{
    bip38_passphrase_buf norm;
    dogecoin_bool ok;

    bip38_passphrase_acquire(passphrase, &norm);
    ok = bip38_derive_passfactor_buf(&norm, ownerentropy, has_lot_sequence, passfactor_out);
    bip38_passphrase_release(&norm);
    return ok;
}

static dogecoin_bool bip38_derive_passfactor_bytes(
    const uint8_t* passphrase,
    size_t passphrase_len,
    const uint8_t ownerentropy[8],
    dogecoin_bool has_lot_sequence,
    uint8_t passfactor_out[32])
{
    bip38_passphrase_buf norm;
    dogecoin_bool ok;

    bip38_passphrase_acquire_bytes(passphrase, passphrase_len, &norm);
    ok = bip38_derive_passfactor_buf(&norm, ownerentropy, has_lot_sequence, passfactor_out);
    bip38_passphrase_release(&norm);
    return ok;
}

static dogecoin_bool bip38_encrypt_ec_with_passphrase(
    const char* passphrase,
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    dogecoin_bool compressed,
    const uint8_t* ownerentropy_override,
    const uint8_t* seedb_override,
    const char* address_hint,
    uint8_t* private_key_out,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size);

static dogecoin_bool bip38_pubkey_find_matching_address(
    const dogecoin_pubkey* pubkey,
    const uint8_t expected_hash[4],
    unsigned int address_match_mode,
    char* address_out)
{
    char address[P2PKHLEN];
    uint8_t calc_hash[4];

    if (dogecoin_pubkey_getaddr_p2pkh(pubkey, &dogecoin_chainparams_main, address)) {
        bip38_address_hash(address, calc_hash);
        if (bip38_mem_eq(calc_hash, expected_hash, 4)) {
            if (address_out) {
                memcpy(address_out, address, P2PKHLEN);
            }
            return true;
        }
    }

    if (address_match_mode != BIP38_ADDRESS_MATCH_INTEROP) {
        return false;
    }

    {
        const dogecoin_chainparams* chains[] = {
            &dogecoin_chainparams_test,
            &dogecoin_chainparams_regtest,
        };
        size_t i;
        for (i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {
            if (!dogecoin_pubkey_getaddr_p2pkh(pubkey, chains[i], address)) {
                continue;
            }
            bip38_address_hash(address, calc_hash);
            if (bip38_mem_eq(calc_hash, expected_hash, 4)) {
                if (address_out) {
                    memcpy(address_out, address, P2PKHLEN);
                }
                return true;
            }
        }
    }

    {
        uint8_t hash160[sizeof(uint160_t)];
        dogecoin_pubkey_get_hash160(pubkey, hash160);
        uint8_t payload[21];
        payload[0] = 0x00;
        memcpy(payload + 1, hash160, sizeof(hash160));
        if (dogecoin_base58_encode_check(payload, 21, address, sizeof(address)) != 0) {
            bip38_address_hash(address, calc_hash);
            if (bip38_mem_eq(calc_hash, expected_hash, 4)) {
                if (address_out) {
                    memcpy(address_out, address, P2PKHLEN);
                }
                return true;
            }
        }
    }
    return false;
}

static dogecoin_bool bip38_privkey_matches_addresshash(
    const uint8_t* private_key,
    dogecoin_bool compressed,
    const uint8_t expected_hash[4],
    unsigned int address_match_mode)
{
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    size_t pubkey_len = compressed ? DOGECOIN_ECKEY_COMPRESSED_LENGTH : DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(private_key, pubkey.pubkey, &pubkey_len, compressed);
    pubkey.compressed = compressed;

    return bip38_pubkey_find_matching_address(
        &pubkey, expected_hash, address_match_mode, NULL);
}

static dogecoin_bool bip38_decrypt_non_ec_bytes(
    const uint8_t* decoded,
    const uint8_t* passphrase,
    size_t passphrase_len,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    uint8_t salt[4];
    memcpy(salt, decoded + 3, 4);
    const uint8_t* encrypted_body = decoded + 7;

    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    if (!bip38_derive_key_bytes(passphrase, passphrase_len, salt, derived)) {
        return false;
    }

    bip38_decrypt_halves(encrypted_body, derived, private_key_out);
    dogecoin_mem_zero(derived, sizeof(derived));

    *compressed_out = (decoded[2] & BIP38_COMPRESSED_FLAG) != 0;

    /* Address hash check (wrong passphrase yields garbage key without this). */
    if (!bip38_privkey_matches_addresshash(
            private_key_out, *compressed_out, decoded + 3, address_match_mode)) {
        dogecoin_mem_zero(private_key_out, DOGECOIN_ECKEY_PKEY_LENGTH);
        return false;
    }
    return true;
}

static dogecoin_bool bip38_decrypt_ec_multiplied_bytes(
    const uint8_t* decoded,
    const uint8_t* passphrase,
    size_t passphrase_len,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    const uint8_t flagbyte = decoded[2];
    const uint8_t* addresshash = decoded + 3;
    const uint8_t* ownerentropy = decoded + 7;
    const uint8_t* encryptedpart1 = decoded + 15;
    const uint8_t* encryptedpart2 = decoded + 23;
    dogecoin_bool has_lot_sequence = (flagbyte & BIP38_LOT_SEQUENCE_FLAG) != 0;

    uint8_t passfactor[32];
    if (!bip38_derive_passfactor_bytes(passphrase, passphrase_len, ownerentropy, has_lot_sequence, passfactor)) {
        return false;
    }

    uint8_t passpoint[33];
    size_t passpoint_len = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(passfactor, passpoint, &passpoint_len, true);

    uint8_t scrypt_salt[12];
    memcpy(scrypt_salt, addresshash, 4);
    memcpy(scrypt_salt + 4, ownerentropy, 8);

    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    if (!dogecoin_scrypt_rfc7914(
            passpoint,
            DOGECOIN_ECKEY_COMPRESSED_LENGTH,
            scrypt_salt,
            sizeof(scrypt_salt),
            1024,
            1,
            1,
            derived,
            BIP38_SCRYPT_DERIVED_SIZE)) {
        dogecoin_mem_zero(passfactor, sizeof(passfactor));
        return false;
    }

    uint8_t decrypted2[16];
    bip38_aes256_decrypt_block(derived, encryptedpart2, 16, decrypted2);

    uint8_t encryptedpart1_full[16];
    memcpy(encryptedpart1_full, encryptedpart1, 8);
    memcpy(encryptedpart1_full + 8, decrypted2, 8);

    uint8_t seedb[24];
    bip38_aes256_decrypt_block(derived, encryptedpart1_full, 0, seedb);
    memcpy(seedb + 16, decrypted2 + 8, 8);

    uint8_t factorb[32];
    sha256_raw(seedb, sizeof(seedb), factorb);
    sha256_raw(factorb, sizeof(factorb), factorb);

    memcpy(private_key_out, passfactor, 32);
    dogecoin_mem_zero(passfactor, sizeof(passfactor));
    dogecoin_mem_zero(derived, sizeof(derived));
    dogecoin_mem_zero(seedb, sizeof(seedb));

    if (!dogecoin_ecc_private_key_tweak_mul(private_key_out, factorb)) {
        dogecoin_mem_zero(private_key_out, DOGECOIN_ECKEY_PKEY_LENGTH);
        dogecoin_mem_zero(factorb, sizeof(factorb));
        return false;
    }
    dogecoin_mem_zero(factorb, sizeof(factorb));

    *compressed_out = (flagbyte & BIP38_COMPRESSED_FLAG) != 0;

    /* Address hash check (passphrase incorrect if mismatch). */
    if (!bip38_privkey_matches_addresshash(private_key_out, *compressed_out, addresshash, address_match_mode)) {
        dogecoin_mem_zero(private_key_out, DOGECOIN_ECKEY_PKEY_LENGTH);
        return false;
    }
    return true;
}

static dogecoin_bool bip38_decrypt_decoded(
    const uint8_t* decoded,
    const uint8_t* passphrase,
    size_t passphrase_len,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    if (decoded[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    if (!bip38_validate_flags(decoded[1], decoded[2])) {
        return false;
    }
    if (decoded[1] == BIP38_TYPE_NON_EC) {
        return bip38_decrypt_non_ec_bytes(
            decoded, passphrase, passphrase_len, address_match_mode, private_key_out, compressed_out);
    }
    if (decoded[1] == BIP38_TYPE_EC_MULTIPLIED) {
        return bip38_decrypt_ec_multiplied_bytes(
            decoded, passphrase, passphrase_len, address_match_mode, private_key_out, compressed_out);
    }
    return false;
}

static dogecoin_bool bip38_encrypt_non_ec_bytes(
    const uint8_t* private_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size)
{
    uint8_t address_hash[4];
    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    uint8_t encrypted[32];
    uint8_t payload[BIP38_PAYLOAD_LEN];
    size_t encsz;
    size_t w;

    if (!private_key || !passphrase || !address || !encrypted_key_out || !encrypted_key_size) {
        return false;
    }
    if (passphrase_len == 0) {
        passphrase_len = strlen((const char*)passphrase);
    }
    if (passphrase_len == 0) {
        return false;
    }
    if (*encrypted_key_size < BIP38_ENCRYPTED_KEY_LENGTH + 1) {
        return false;
    }

    bip38_address_hash(address, address_hash);
    if (!bip38_derive_key_bytes(passphrase, passphrase_len, address_hash, derived)) {
        return false;
    }

    bip38_encrypt_halves(private_key, derived, encrypted);
    dogecoin_mem_zero(derived, sizeof(derived));

    payload[0] = BIP38_MAGIC_BYTE;
    payload[1] = BIP38_TYPE_NON_EC;
    payload[2] = (uint8_t)(BIP38_FLAG_BASE | (compressed ? BIP38_COMPRESSED_FLAG : 0));
    memcpy(payload + 3, address_hash, 4);
    memcpy(payload + 7, encrypted, 32);

    encsz = *encrypted_key_size;
    w = dogecoin_base58_encode_check(payload, BIP38_PAYLOAD_LEN, encrypted_key_out, encsz);
    if (w == 0) {
        return false;
    }
    *encrypted_key_size = w;
    return true;
}

dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size)
{
    if (!passphrase) {
        return false;
    }
    return bip38_encrypt_non_ec_bytes(
        private_key,
        (const uint8_t*)passphrase,
        0,
        address,
        compressed,
        encrypted_key_out,
        encrypted_key_size);
}

dogecoin_bool dogecoin_bip38_encrypt_passphrase(
    const uint8_t* private_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size)
{
    return bip38_encrypt_non_ec_bytes(
        private_key,
        passphrase,
        passphrase_len,
        address,
        compressed,
        encrypted_key_out,
        encrypted_key_size);
}

dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    return dogecoin_bip38_decrypt_ex(
        encrypted_key,
        passphrase,
        BIP38_ADDRESS_MATCH_MAINNET,
        private_key_out,
        compressed_out);
}

dogecoin_bool dogecoin_bip38_decrypt_ex(
    const char* encrypted_key,
    const char* passphrase,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!encrypted_key || !passphrase || !private_key_out || !compressed_out) {
        return false;
    }
    if (!bip38_decode_encrypted_payload(encrypted_key, decoded, &declen)) {
        return false;
    }

    return bip38_decrypt_decoded(
        decoded,
        (const uint8_t*)passphrase,
        0,
        address_match_mode,
        private_key_out,
        compressed_out);
}

dogecoin_bool dogecoin_bip38_decrypt_passphrase(
    const char* encrypted_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    return dogecoin_bip38_decrypt_passphrase_ex(
        encrypted_key,
        passphrase,
        passphrase_len,
        BIP38_ADDRESS_MATCH_MAINNET,
        private_key_out,
        compressed_out);
}

dogecoin_bool dogecoin_bip38_decrypt_passphrase_ex(
    const char* encrypted_key,
    const uint8_t* passphrase,
    size_t passphrase_len,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!encrypted_key || !passphrase || passphrase_len == 0 || !private_key_out || !compressed_out) {
        return false;
    }
    if (!bip38_decode_encrypted_payload(encrypted_key, decoded, &declen)) {
        return false;
    }

    return bip38_decrypt_decoded(
        decoded, passphrase, passphrase_len, address_match_mode, private_key_out, compressed_out);
}

dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!encrypted_key) {
        return false;
    }
    return bip38_decode_encrypted_payload(encrypted_key, decoded, &declen);
}

dogecoin_bool dogecoin_bip38_get_address_hash(
    const char* encrypted_key,
    uint8_t* address_hash_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!encrypted_key || !address_hash_out) {
        return false;
    }
    if (!bip38_decode_encrypted_payload(encrypted_key, decoded, &declen)) {
        return false;
    }

    memcpy(address_hash_out, decoded + 3, 4);
    return true;
}

dogecoin_bool dogecoin_bip38_verify_address_hash(
    const char* encrypted_key,
    const char* address)
{
    if (!encrypted_key || !address) {
        return false;
    }

    uint8_t embedded[4];
    uint8_t calc[4];
    if (!dogecoin_bip38_get_address_hash(encrypted_key, embedded)) {
        return false;
    }
    bip38_address_hash(address, calc);
    return bip38_mem_eq(embedded, calc, 4);
}

dogecoin_bool dogecoin_bip38_get_flag_byte(
    const char* encrypted_key,
    uint8_t* flag_byte_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!encrypted_key || !flag_byte_out) {
        return false;
    }
    if (!bip38_decode_encrypted_payload(encrypted_key, decoded, &declen)) {
        return false;
    }

    *flag_byte_out = decoded[2];
    return true;
}

dogecoin_bool dogecoin_bip38_is_compressed(const char* encrypted_key)
{
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    return (flag_byte & BIP38_COMPRESSED_FLAG) != 0;
}

dogecoin_bool dogecoin_bip38_has_lot_sequence(const char* encrypted_key)
{
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    return (flag_byte & BIP38_LOT_SEQUENCE_FLAG) != 0;
}

dogecoin_bool dogecoin_bip38_is_ec_multiplied(const char* encrypted_key)
{
    if (!encrypted_key) {
        return false;
    }
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }
    return (decoded[0] == BIP38_MAGIC_BYTE && decoded[1] == BIP38_TYPE_EC_MULTIPLIED);
}

void dogecoin_bip38_generate_lot_sequence(
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    uint32_t lot_raw;
    uint32_t sequence_raw;

    if (!lot_out || !sequence_out) {
        return;
    }

    dogecoin_random_bytes((uint8_t*)&lot_raw, sizeof(lot_raw), 1);
    dogecoin_random_bytes((uint8_t*)&sequence_raw, sizeof(sequence_raw), 1);
    *lot_out = (lot_raw % BIP38_LOT_MAX) + 1u;
    *sequence_out = sequence_raw % (BIP38_SEQUENCE_MAX + 1u);
}

dogecoin_bool dogecoin_bip38_private_key_to_wif(
    const uint8_t* private_key,
    const dogecoin_chainparams* chain,
    dogecoin_bool compressed,
    char* wif_out,
    size_t* wif_size)
{
    if (!private_key || !chain || !wif_out || !wif_size) {
        return false;
    }

    uint8_t payload[34];
    payload[0] = chain->b58prefix_secret_address;
    memcpy(payload + 1, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    size_t payload_len = compressed ? 34 : 33;
    if (compressed) {
        payload[33] = 1;
    }
    if (dogecoin_base58_encode_check(payload, payload_len, wif_out, *wif_size) == 0) {
        return false;
    }
    dogecoin_mem_zero(payload, sizeof(payload));
    return true;
}

static dogecoin_bool bip38_decode_wif_payload(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    if (!wif || !chain || !private_key_out || !compressed_out) {
        return false;
    }

    const size_t wif_len = strlen(wif);
    if (wif_len < 46) {
        return false;
    }

    uint8_t* payload = (uint8_t*)dogecoin_calloc(1, wif_len + 1);
    if (!payload) {
        return false;
    }

    size_t outlen = dogecoin_base58_decode_check(wif, payload, wif_len + 1);
    /* decode_check length includes 4-byte checksum (33+4 or 34+4). */
    size_t payload_len = 0;
    if (outlen == 37) {
        payload_len = 33;
    } else if (outlen == 38) {
        payload_len = 34;
    } else {
        dogecoin_free(payload);
        return false;
    }
    if (payload[0] != chain->b58prefix_secret_address) {
        dogecoin_free(payload);
        return false;
    }

    memcpy(private_key_out, payload + 1, DOGECOIN_ECKEY_PKEY_LENGTH);
    if (payload_len == 34) {
        *compressed_out = (payload[33] == 1);
    } else {
        *compressed_out = false;
    }
    dogecoin_mem_zero(payload, wif_len);
    dogecoin_free(payload);
    return true;
}

dogecoin_bool dogecoin_bip38_wif_to_private_key(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    return bip38_decode_wif_payload(wif, chain, private_key_out, compressed_out);
}

dogecoin_bool dogecoin_bip38_is_intermediate_code(const char* code)
{
    uint8_t ownerentropy[8];
    uint8_t passpoint[33];
    dogecoin_bool has_lot_sequence;

    return bip38_parse_intermediate_code(code, ownerentropy, passpoint, &has_lot_sequence);
}

dogecoin_bool dogecoin_bip38_is_confirmation_code(const char* code)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;

    if (!code) {
        return false;
    }
    declen = dogecoin_base58_decode_check(code, decoded, sizeof(decoded));
    if (declen != BIP38_CONFIRMATION_PAYLOAD_LEN + 4) {
        return false;
    }
    return bip38_mem_eq(decoded, BIP38_CONFIRMATION_MAGIC, 5);
}

dogecoin_bool dogecoin_bip38_encrypt_ec_multiplied(
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
    size_t* confirmation_code_size)
{
    return bip38_encrypt_ec_with_passphrase(
        passphrase,
        use_lot_sequence,
        lot,
        sequence,
        compressed,
        NULL,
        NULL,
        address_chain_hint,
        private_key_out,
        encrypted_key_out,
        encrypted_key_size,
        confirmation_code_out,
        confirmation_code_size);
}

static dogecoin_bool bip38_encrypt_ec_with_passphrase(
    const char* passphrase,
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    dogecoin_bool compressed,
    const uint8_t* ownerentropy_override,
    const uint8_t* seedb_override,
    const char* address_hint,
    uint8_t* private_key_out,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size)
{
    uint8_t ownerentropy[8];
    uint8_t passfactor[32];
    uint8_t passpoint[33];
    uint8_t seedb[BIP38_SEEDB_LEN];
    size_t passpoint_len;
    const dogecoin_chainparams* chain;
    dogecoin_bool ok;

    if (use_lot_sequence && (lot == 0 || lot > BIP38_LOT_MAX || sequence > BIP38_SEQUENCE_MAX)) {
        return false;
    }

    if (ownerentropy_override) {
        memcpy(ownerentropy, ownerentropy_override, 8);
    } else {
        bip38_ownerentropy_generate(use_lot_sequence, lot, sequence, ownerentropy);
    }

    if (!bip38_derive_passfactor(passphrase, ownerentropy, use_lot_sequence, passfactor)) {
        return false;
    }

    passpoint_len = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(passfactor, passpoint, &passpoint_len, true);

    if (seedb_override) {
        memcpy(seedb, seedb_override, BIP38_SEEDB_LEN);
    } else {
        dogecoin_random_bytes(seedb, BIP38_SEEDB_LEN, 1);
    }

    chain = bip38_chain_from_address_hint(address_hint);

    ok = bip38_encrypt_ec_core(
        passpoint,
        ownerentropy,
        use_lot_sequence,
        compressed,
        seedb,
        chain,
        passfactor,
        private_key_out,
        encrypted_key_out,
        encrypted_key_size,
        confirmation_code_out,
        confirmation_code_size);

    dogecoin_mem_zero(passfactor, sizeof(passfactor));
    return ok;
}

dogecoin_bool dogecoin_bip38_generate_intermediate_code(
    const char* passphrase,
    dogecoin_bool use_lot_sequence,
    uint32_t lot,
    uint32_t sequence,
    const uint8_t* ownerentropy_override,
    char* intermediate_code_out,
    size_t* intermediate_code_size)
{
    uint8_t ownerentropy[8];
    uint8_t passfactor[32];
    uint8_t passpoint[33];
    uint8_t payload[BIP38_INTERMEDIATE_PAYLOAD_LEN];
    size_t passpoint_len;
    size_t written;

    if (!passphrase || !intermediate_code_out || !intermediate_code_size) {
        return false;
    }
    if (use_lot_sequence && (lot == 0 || lot > BIP38_LOT_MAX || sequence > BIP38_SEQUENCE_MAX)) {
        return false;
    }
    if (*intermediate_code_size < BIP38_INTERMEDIATE_CODE_MAXLEN) {
        return false;
    }

    if (ownerentropy_override) {
        memcpy(ownerentropy, ownerentropy_override, 8);
    } else {
        bip38_ownerentropy_generate(use_lot_sequence, lot, sequence, ownerentropy);
    }

    if (!bip38_derive_passfactor(passphrase, ownerentropy, use_lot_sequence, passfactor)) {
        return false;
    }

    passpoint_len = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(passfactor, passpoint, &passpoint_len, true);
    dogecoin_mem_zero(passfactor, sizeof(passfactor));

    memcpy(payload, use_lot_sequence ? BIP38_INTERMEDIATE_MAGIC_LOT : BIP38_INTERMEDIATE_MAGIC_NOLOT, 8);
    memcpy(payload + 8, ownerentropy, 8);
    memcpy(payload + 16, passpoint, 33);

    written = dogecoin_base58_encode_check(payload, BIP38_INTERMEDIATE_PAYLOAD_LEN,
        intermediate_code_out, *intermediate_code_size);
    if (written == 0) {
        return false;
    }
    *intermediate_code_size = written;
    return true;
}

dogecoin_bool dogecoin_bip38_encrypt_from_intermediate(
    const char* intermediate_code,
    dogecoin_bool compressed,
    const uint8_t* seedb_override,
    const char* address_chain_hint,
    uint8_t* private_key_out,
    char* encrypted_key_out,
    size_t* encrypted_key_size,
    char* confirmation_code_out,
    size_t* confirmation_code_size)
{
    uint8_t ownerentropy[8];
    uint8_t passpoint[33];
    uint8_t seedb[BIP38_SEEDB_LEN];
    dogecoin_bool has_lot_sequence;
    const dogecoin_chainparams* chain;

    if (!intermediate_code || !encrypted_key_out || !encrypted_key_size) {
        return false;
    }

    if (!bip38_parse_intermediate_code(intermediate_code, ownerentropy, passpoint, &has_lot_sequence)) {
        return false;
    }

    if (seedb_override) {
        memcpy(seedb, seedb_override, BIP38_SEEDB_LEN);
    } else {
        dogecoin_random_bytes(seedb, BIP38_SEEDB_LEN, 1);
    }

    chain = bip38_chain_from_address_hint(address_chain_hint);
    (void)private_key_out;

    return bip38_encrypt_ec_core(
        passpoint,
        ownerentropy,
        has_lot_sequence,
        compressed,
        seedb,
        chain,
        NULL,
        NULL,
        encrypted_key_out,
        encrypted_key_size,
        confirmation_code_out,
        confirmation_code_size);
}

dogecoin_bool dogecoin_bip38_confirm_passphrase(
    const char* passphrase,
    const char* confirmation_code,
    char* address_out,
    size_t address_size,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    return dogecoin_bip38_confirm_passphrase_ex(
        passphrase,
        confirmation_code,
        BIP38_ADDRESS_MATCH_MAINNET,
        address_out,
        address_size,
        compressed_out,
        lot_out,
        sequence_out);
}

dogecoin_bool dogecoin_bip38_confirm_passphrase_ex(
    const char* passphrase,
    const char* confirmation_code,
    unsigned int address_match_mode,
    char* address_out,
    size_t address_size,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen;
    uint8_t flagbyte;
    uint8_t addresshash[4];
    uint8_t ownerentropy[8];
    const uint8_t* encryptedpointb;
    uint8_t passfactor[32];
    uint8_t passpoint[33];
    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    uint8_t pointb[33];
    size_t pointb_len;
    dogecoin_bool has_lot_sequence;
    dogecoin_bool compressed;

    if (!passphrase || !confirmation_code || !address_out || address_size < P2PKHLEN) {
        return false;
    }

    declen = dogecoin_base58_decode_check(confirmation_code, decoded, sizeof(decoded));
    if (declen != BIP38_CONFIRMATION_PAYLOAD_LEN + 4) {
        return false;
    }
    if (memcmp(decoded, BIP38_CONFIRMATION_MAGIC, 5) != 0) {
        return false;
    }

    flagbyte = decoded[5];
    if (!bip38_validate_flags(BIP38_TYPE_EC_MULTIPLIED, flagbyte)) {
        return false;
    }

    memcpy(addresshash, decoded + 6, 4);
    memcpy(ownerentropy, decoded + 10, 8);
    encryptedpointb = decoded + 18;

    has_lot_sequence = (flagbyte & BIP38_LOT_SEQUENCE_FLAG) != 0;
    compressed = (flagbyte & BIP38_COMPRESSED_FLAG) != 0;

    pointb_len = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    if (!bip38_derive_passfactor(passphrase, ownerentropy, has_lot_sequence, passfactor)) {
        return false;
    }
    dogecoin_ecc_get_pubkey(passfactor, passpoint, &pointb_len, true);

    if (!bip38_ec_derived_key(passpoint, addresshash, ownerentropy, derived)) {
        dogecoin_mem_zero(passfactor, sizeof(passfactor));
        return false;
    }
    dogecoin_mem_zero(passfactor, sizeof(passfactor));

    pointb[0] = (uint8_t)(encryptedpointb[0] ^ (derived[63] & 0x01));
    bip38_aes256_decrypt_block(derived, encryptedpointb + 1, 0, pointb + 1);
    bip38_aes256_decrypt_block(derived, encryptedpointb + 17, 16, pointb + 17);

    if (!bip38_derive_passfactor(passphrase, ownerentropy, has_lot_sequence, passfactor)) {
        dogecoin_mem_zero(derived, sizeof(derived));
        return false;
    }

    if (!dogecoin_ecc_public_key_tweak_mul(pointb, passfactor)) {
        dogecoin_mem_zero(passfactor, sizeof(passfactor));
        dogecoin_mem_zero(derived, sizeof(derived));
        return false;
    }
    dogecoin_mem_zero(passfactor, sizeof(passfactor));
    (void)passpoint;

    {
        dogecoin_pubkey pubkey;
        uint8_t pubkey_buf[DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH];
        size_t pubkey_len = compressed ? 33u : 65u;

        dogecoin_pubkey_init(&pubkey);
        if (!dogecoin_ecc_point_serialize(pointb, 33, pubkey_buf, &pubkey_len, compressed)) {
            dogecoin_mem_zero(derived, sizeof(derived));
            return false;
        }
        memcpy(pubkey.pubkey, pubkey_buf, pubkey_len);
        pubkey.compressed = compressed;

        if (!bip38_pubkey_find_matching_address(
                &pubkey, addresshash, address_match_mode, address_out)) {
            dogecoin_mem_zero(derived, sizeof(derived));
            return false;
        }
    }

    if (compressed_out) {
        *compressed_out = compressed;
    }
    if (has_lot_sequence) {
        uint32_t lotsequence = ((uint32_t)ownerentropy[4] << 24)
            | ((uint32_t)ownerentropy[5] << 16)
            | ((uint32_t)ownerentropy[6] << 8)
            | (uint32_t)ownerentropy[7];
        if (lot_out) {
            *lot_out = lotsequence / 4096u;
        }
        if (sequence_out) {
            *sequence_out = lotsequence % 4096u;
        }
    } else {
        if (lot_out) {
            *lot_out = 0;
        }
        if (sequence_out) {
            *sequence_out = 0;
        }
    }

    dogecoin_mem_zero(derived, sizeof(derived));
    return true;
}

dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    return dogecoin_bip38_decrypt_with_lot_sequence_ex(
        encrypted_key,
        passphrase,
        BIP38_ADDRESS_MATCH_MAINNET,
        private_key_out,
        compressed_out,
        lot_out,
        sequence_out);
}

dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence_ex(
    const char* encrypted_key,
    const char* passphrase,
    unsigned int address_match_mode,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    if (lot_out) {
        *lot_out = 0;
    }
    if (sequence_out) {
        *sequence_out = 0;
    }

    if (!dogecoin_bip38_decrypt_ex(
            encrypted_key, passphrase, address_match_mode, private_key_out, compressed_out)) {
        return false;
    }

    if (dogecoin_bip38_is_ec_multiplied(encrypted_key) && dogecoin_bip38_has_lot_sequence(encrypted_key)) {
        uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
        size_t declen;
        if (!bip38_decode_encrypted_payload(encrypted_key, decoded, &declen)) {
            return false;
        }
        const uint8_t* ownerentropy = decoded + 7;
        uint32_t lotsequence = ((uint32_t)ownerentropy[4] << 24)
            | ((uint32_t)ownerentropy[5] << 16)
            | ((uint32_t)ownerentropy[6] << 8)
            | (uint32_t)ownerentropy[7];
        if (lot_out) {
            *lot_out = lotsequence / 4096;
        }
        if (sequence_out) {
            *sequence_out = lotsequence % 4096;
        }
    }
    return true;
}
