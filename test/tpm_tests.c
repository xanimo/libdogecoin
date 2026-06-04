/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2023 edtubbs                                         *
 * Copyright (c) 2022-2024 The Dogecoin Foundation                    *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>
#include <dogecoin/address.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>
#include <dogecoin/seal.h>
#include <dogecoin/utils.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined (_WIN64) && !defined(__MINGW64__)
#include <windows.h>
#include <tbs.h>
#include <ncrypt.h>
#endif

#ifndef WINVER
#define WINVER 0x0600
#endif

#if defined (__linux__) && defined (USE_TSS2)
#include <tss2/tss2_esys.h>
#define TPM_RSA_2048_CIPHERTEXT_SIZE 256
#endif

void test_tpm()
{

    // Generate a random number
    uint8_t random[32] = {0};
    dogecoin_random_bytes(random, sizeof(random), 1);

    // Define a random seed and a decrypted seed
    SEED seed = {0};
    SEED decrypted_seed = {0};

#if defined (__linux__) && defined(USE_TSS2)

    ESYS_CONTEXT* context = NULL;

    /* Initialize TPM context. If no TPM (or swtpm) is reachable on this
     * host, skip the TSS2-specific portion of the test gracefully so the
     * suite can still run in CI environments that build with --enable-tss2
     * but have no TPM available. */
    TSS2_RC result = Esys_Initialize(&context, NULL, NULL);
    if (result != TSS2_RC_SUCCESS) {
        debug_print("TSS2 Esys_Initialize failed (0x%x): no TPM available, skipping TSS2 tests\n", result);
    } else {
        result = Esys_Startup(context, TPM2_SU_CLEAR);
    }
    if (result == TSS2_RC_SUCCESS) {

    /* Get random data */
    TPM2B_DIGEST *random_bytes;
    result = Esys_GetRandom(context,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            32,
                            &random_bytes);
    u_assert_uint32_eq(result, TSS2_RC_SUCCESS);

    char* rand_hex;
    rand_hex = utils_uint8_to_hex((uint8_t*) random_bytes->buffer, random_bytes->size);
    debug_print ("Esys_GetRandom: %s\n", rand_hex);

    // Copy random_bytes to seed
    memcpy(seed, random_bytes->buffer, random_bytes->size);

    /* Probe the TPM for available transient-object capacity. libtpms (the
     * library backing swtpm in Ubuntu/Debian) is compiled with
     * MAX_LOADED_OBJECTS=3 and reserves a transient slot per persistent
     * object, so a stock swtpm cannot hold all three (seed/mnemonic/hdnode)
     * persistent wrapping keys at once. On such resource-constrained TPMs
     * we still exercise the full encrypt/decrypt round-trip for one blob
     * (seed) but skip the multi-persistent portion of the test. Real TPM
     * hardware comfortably supports enough slots and runs the full suite. */
    dogecoin_bool tpm_has_room_for_multi = false;
    {
        TPMS_CAPABILITY_DATA* cap = NULL;
        TSS2_RC cap_rc = Esys_GetCapability(context,
                                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                            TPM2_CAP_TPM_PROPERTIES,
                                            TPM2_PT_HR_TRANSIENT_AVAIL,
                                            1, NULL, &cap);
        if (cap_rc == TSS2_RC_SUCCESS && cap != NULL &&
            cap->data.tpmProperties.count >= 1 &&
            cap->data.tpmProperties.tpmProperty[0].property == TPM2_PT_HR_TRANSIENT_AVAIL) {
            uint32_t avail = cap->data.tpmProperties.tpmProperty[0].value;
            debug_print("TPM2_PT_HR_TRANSIENT_AVAIL=%u\n", avail);
            /* Need one transient slot per simultaneously-persistent key plus
             * one for the freshly-created primary; require >= 4 to run the
             * full multi-key path. */
            tpm_has_room_for_multi = (avail >= 4);
        }
        if (cap) Esys_Free(cap);
    }

    // Encrypt a random seed with the TPM2
    u_assert_true (dogecoin_encrypt_seed_with_tpm (seed, sizeof(SEED), TEST_FILE, true));
    debug_print ("Seed: %s\n", utils_uint8_to_hex (seed, sizeof (SEED)));
    {
        char filename[64] = {0};
        struct stat st = {0};
        snprintf(filename, sizeof(filename), ".store/encrypted_seed_%d", TEST_FILE);
        u_assert_true(stat(filename, &st) == 0);
        u_assert_int_eq((int)st.st_size, TPM_RSA_2048_CIPHERTEXT_SIZE);
    }

    // Decrypt the seed with the TPM2
    u_assert_true (dogecoin_decrypt_seed_with_tpm (decrypted_seed, TEST_FILE));
    debug_print ("Decrypted seed: %s\n", utils_uint8_to_hex (decrypted_seed, sizeof (SEED)));
    u_assert_mem_eq (seed, decrypted_seed, sizeof (SEED));

    if (tpm_has_room_for_multi) {
    // Generate and decrypt an HD node with the TPM2
    dogecoin_hdnode tpm_node, tpm_decrypted_node;
    u_assert_true (dogecoin_generate_hdnode_encrypt_with_tpm (&tpm_node, TEST_FILE, true));
    u_assert_true (dogecoin_decrypt_hdnode_with_tpm (&tpm_decrypted_node, TEST_FILE));
    u_assert_mem_eq (&tpm_node, &tpm_decrypted_node, sizeof (dogecoin_hdnode));

    // Generate and decrypt a mnemonic with the TPM2
    MNEMONIC tpm_mnemonic = {0};
    MNEMONIC tpm_decrypted_mnemonic = {0};
    u_assert_true (dogecoin_generate_mnemonic_encrypt_with_tpm(tpm_mnemonic, TEST_FILE, true, "eng", " ", NULL));
    u_assert_true (dogecoin_decrypt_mnemonic_with_tpm(tpm_decrypted_mnemonic, TEST_FILE));
    u_assert_mem_eq (tpm_mnemonic, tpm_decrypted_mnemonic, sizeof (MNEMONIC));

    // list encryption keys in the TPM
    wchar_t *names[MAX_FILES] = {0};
    size_t count = 0;
    u_assert_true (dogecoin_list_encryption_keys_in_tpm(names, &count));
    u_assert_true (count >= 3);
    for (size_t i = 0; i < count; i++) {
        if (names[i]) dogecoin_free(names[i]);
    }

    // test generateRandomEnglishMnemonicTPM
    u_assert_true (generateRandomEnglishMnemonicTPM(tpm_mnemonic, TEST_FILE, true));

    // test derived address helpers with encrypted objects
    char tpm_derived_address[35];
    u_assert_true (getDerivedHDAddressFromEncryptedSeed(0, 0, BIP44_CHANGE_EXTERNAL, tpm_derived_address, false, TEST_FILE) == 0);
    u_assert_true (strlen(tpm_derived_address) > 0);
    u_assert_true (getDerivedHDAddressFromEncryptedMnemonic(0, 0, BIP44_CHANGE_EXTERNAL, NULL, tpm_derived_address, false, TEST_FILE) == 0);
    u_assert_true (strlen(tpm_derived_address) > 0);
    u_assert_true (getDerivedHDAddressFromEncryptedHDNode(0, 0, BIP44_CHANGE_EXTERNAL, tpm_derived_address, false, TEST_FILE) == 0);
    u_assert_true (strlen(tpm_derived_address) > 0);
    } else {
        debug_print("TPM has < 4 transient slots available; skipping multi-key TSS2 sub-tests%s\n",
                    " (swtpm/libtpms is compile-time limited to 3 loaded objects)");

        // Still exercise enumeration of persistent encryption keys; the seed
        // wrapping key persisted above must show up.
        wchar_t *names[MAX_FILES] = {0};
        size_t count = 0;
        u_assert_true (dogecoin_list_encryption_keys_in_tpm(names, &count));
        u_assert_true (count >= 1);
        for (size_t i = 0; i < count; i++) {
            if (names[i]) dogecoin_free(names[i]);
        }
    }

    Esys_Finalize(&context);
    } else if (context != NULL) {
        Esys_Finalize(&context);
    }

#endif

    sha512_raw(&random[0], 32, seed);

    char* test_password = PASSWD_STR;

    // Encrypt a random seed with software
    u_assert_true (dogecoin_encrypt_seed_with_sw (seed, sizeof(SEED), TEST_FILE, true, test_password, NULL, NULL));
    debug_print ("Seed: %s\n", utils_uint8_to_hex (seed, sizeof (SEED)));

    // Decrypt the seed with software
    u_assert_true (dogecoin_decrypt_seed_with_sw (decrypted_seed, TEST_FILE, test_password, NULL));
    debug_print ("Decrypted seed: %s\n", utils_uint8_to_hex (decrypted_seed, sizeof (SEED)));

    // Compare the seed and the decrypted seed
    u_assert_mem_eq (seed, decrypted_seed, sizeof (SEED));

    // Define a random HD node and a decrypted HD node
    dogecoin_hdnode node, decrypted_node;

    // Generate a random HD node with software
    u_assert_true (dogecoin_generate_hdnode_encrypt_with_sw (&node, TEST_FILE, true, test_password, NULL, 0));
    debug_print ("HD node: %s\n", utils_uint8_to_hex ((uint8_t *) &node, sizeof (dogecoin_hdnode)));

    // Decrypt the HD node with software
    u_assert_true (dogecoin_decrypt_hdnode_with_sw (&decrypted_node, TEST_FILE, test_password, NULL));
    debug_print ("Decrypted HD node: %s\n", utils_uint8_to_hex ((uint8_t *) &decrypted_node, sizeof (dogecoin_hdnode)));

    // Compare the HD node and the decrypted HD node
    u_assert_mem_eq (&node, &decrypted_node, sizeof (dogecoin_hdnode));

    // Generate a mnemonic with software
    MNEMONIC mnemonic = {0};
    MNEMONIC decrypted_mnemonic = {0};

    // Generate a random mnemonic with software
    u_assert_true (dogecoin_generate_mnemonic_encrypt_with_sw(mnemonic, TEST_FILE, true, "eng", " ", NULL, test_password, NULL, NULL));
    debug_print("Mnemonic: %s\n", mnemonic);

    // Decrypt the mnemonic with software
    u_assert_true (dogecoin_decrypt_mnemonic_with_sw(decrypted_mnemonic, TEST_FILE, test_password, NULL));
    debug_print("Decrypted mnemonic: %s\n", decrypted_mnemonic);

    // Compare the mnemonic and the decrypted mnemonic
    u_assert_mem_eq (mnemonic, decrypted_mnemonic, sizeof (MNEMONIC));

    // Test encrypting and decrypting a seed with an encrypted blob
    ENCRYPTED_BLOB encrypted_blob;
    size_t encrypted_blob_size;

    // Encrypt a random seed with software into a blob
    u_assert_true(dogecoin_encrypt_seed_with_sw(seed, sizeof(SEED), NO_FILE, true, test_password, &encrypted_blob, &encrypted_blob_size));
    debug_print("Encrypted seed blob: %s\n", utils_uint8_to_hex(encrypted_blob, encrypted_blob_size));

    // Decrypt the seed with software from a blob
    u_assert_true(dogecoin_decrypt_seed_with_sw(decrypted_seed, NO_FILE, test_password, encrypted_blob));
    debug_print("Decrypted seed from blob: %s\n", utils_uint8_to_hex(decrypted_seed, sizeof(SEED)));

    // Compare the seed and the decrypted seed
    u_assert_mem_eq(seed, decrypted_seed, sizeof(SEED));

    // Test encrypting and decrypting an HD node with an encrypted blob
    u_assert_true(dogecoin_generate_hdnode_encrypt_with_sw(&node, NO_FILE, true, test_password, &encrypted_blob, &encrypted_blob_size));
    debug_print("Encrypted HD node blob: %s\n", utils_uint8_to_hex(encrypted_blob, encrypted_blob_size));

    // Decrypt the HD node with software from a blob
    u_assert_true(dogecoin_decrypt_hdnode_with_sw(&decrypted_node, NO_FILE, test_password, encrypted_blob));
    debug_print("Decrypted HD node from blob: %s\n", utils_uint8_to_hex((uint8_t*)&decrypted_node, sizeof(dogecoin_hdnode)));

    // Compare the HD node and the decrypted HD node
    u_assert_mem_eq(&node, &decrypted_node, sizeof(dogecoin_hdnode));

    // Test encrypting and decrypting a mnemonic with an encrypted blob
    u_assert_true(dogecoin_generate_mnemonic_encrypt_with_sw(mnemonic, NO_FILE, true, "eng", " ", NULL, test_password, &encrypted_blob, &encrypted_blob_size));
    debug_print("Encrypted mnemonic blob: %s\n", utils_uint8_to_hex(encrypted_blob, encrypted_blob_size));

    // Decrypt the mnemonic with software from a blob
    u_assert_true(dogecoin_decrypt_mnemonic_with_sw(decrypted_mnemonic, NO_FILE, test_password, encrypted_blob));
    debug_print("Decrypted mnemonic from blob: %s\n", decrypted_mnemonic);

    // Compare the mnemonic and the decrypted mnemonic
    u_assert_mem_eq(mnemonic, decrypted_mnemonic, sizeof(MNEMONIC));

#ifdef USE_YUBIKEY

    // Encrypt a random seed with YubiKey
    u_assert_true (dogecoin_encrypt_seed_with_sw_to_yubikey(seed, sizeof(SEED), TEST_FILE, true, test_password));
    debug_print ("Seed to YubiKey: %s\n", utils_uint8_to_hex (seed, sizeof (SEED)));

    // Decrypt the seed with YubiKey
    u_assert_true (dogecoin_decrypt_seed_with_sw_from_yubikey(decrypted_seed, TEST_FILE, test_password));
    debug_print ("Decrypted seed from YubiKey: %s\n", utils_uint8_to_hex (decrypted_seed, sizeof (SEED)));

    // Compare the seed and the decrypted seed
    u_assert_mem_eq (seed, decrypted_seed, sizeof (SEED));

    // Generate a random HD node with YubiKey
    u_assert_true (dogecoin_generate_hdnode_encrypt_with_sw_to_yubikey(&node, TEST_FILE, true, test_password));
    debug_print ("HD node to YubiKey: %s\n", utils_uint8_to_hex ((uint8_t *) &node, sizeof (dogecoin_hdnode)));

    // Decrypt the HD node with YubiKey
    u_assert_true (dogecoin_decrypt_hdnode_with_sw_from_yubikey(&decrypted_node, TEST_FILE, test_password));
    debug_print ("Decrypted HD node from YubiKey: %s\n", utils_uint8_to_hex ((uint8_t *) &decrypted_node, sizeof (dogecoin_hdnode)));

    // Compare the HD node and the decrypted HD node
    u_assert_mem_eq (&node, &decrypted_node, sizeof (dogecoin_hdnode));

    // Generate a random mnemonic with YubiKey
    u_assert_true (dogecoin_generate_mnemonic_encrypt_with_sw_to_yubikey(mnemonic, TEST_FILE, true, "eng", " ", NULL, test_password));
    debug_print("Mnemonic to YubiKey: %s\n", mnemonic);

    // Decrypt the mnemonic with YubiKey
    u_assert_true (dogecoin_decrypt_mnemonic_with_sw_from_yubikey(decrypted_mnemonic, TEST_FILE, test_password));
    debug_print("Decrypted mnemonic from YubiKey: %s\n", decrypted_mnemonic);

    // Compare the mnemonic and the decrypted mnemonic
    u_assert_mem_eq (mnemonic, decrypted_mnemonic, sizeof (MNEMONIC));

#endif

#if defined (_WIN64) && !defined(__MINGW64__) && defined(USE_TPM2) && !defined(TEST_TPM_AUTO)
    // Create TBS context (TPM2)
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_RESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
    u_assert_uint32_eq (hr, TBS_SUCCESS);

    // Get TPM device information
    TPM_DEVICE_INFO info;
    hr = Tbsi_GetDeviceInfo (sizeof (info), &info);
    u_assert_uint32_eq (hr, TBS_SUCCESS);

    // Verify TPM2
    u_assert_uint32_eq (info.tpmVersion, TPM_VERSION_20);

    // Send TPM2_CC_GetRandom command
    const BYTE cmd_random[] = {
        0x80, 0x01,             // tag: TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // commandSize: size of the entire command byte array
        0x00, 0x00, 0x01, 0x7B, // commandCode: TPM2_CC_GetRandom
        0x00, 0x20              // parameter: 32 bytes
    };
    BYTE resp_random[TBS_IN_OUT_BUF_SIZE_MAX] = { 0 };
    UINT32 resp_randomSize =  TBS_IN_OUT_BUF_SIZE_MAX;
    hr = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd_random, sizeof(cmd_random), resp_random, &resp_randomSize);
    u_assert_uint32_eq (hr, TBS_SUCCESS);
    char* rand_hex;
    rand_hex = utils_uint8_to_hex(&resp_random[12], 0x20);
    debug_print ("TPM2_CC_GetRandom response: %s\n", rand_hex);

    // Generate a random HD node with the TPM2
    u_assert_true (dogecoin_generate_hdnode_encrypt_with_tpm (&node, TEST_FILE, true));
    debug_print ("HD node: %s\n", utils_uint8_to_hex ((uint8_t *) &node, sizeof (dogecoin_hdnode)));

    // Decrypt the HD node with the TPM2
    u_assert_true (dogecoin_decrypt_hdnode_with_tpm (&decrypted_node, TEST_FILE));
    debug_print ("Decrypted HD node: %s\n", utils_uint8_to_hex ((uint8_t *) &decrypted_node, sizeof (dogecoin_hdnode)));

    // Compare the HD node and the decrypted HD node
    u_assert_mem_eq (&node, &decrypted_node, sizeof (dogecoin_hdnode));
    debug_print ("HD node and decrypted HD node are equal\n");

    // Define a random seed and a decrypted seed
    sha512_raw(&resp_random[12], 32, seed);

    // Generate a random seed with the TPM2
    u_assert_true (dogecoin_encrypt_seed_with_tpm (seed, sizeof(SEED), TEST_FILE, true));
    debug_print ("Seed: %s\n", utils_uint8_to_hex (seed, sizeof (SEED)));

    // Decrypt the seed with the TPM2
    u_assert_true (dogecoin_decrypt_seed_with_tpm (decrypted_seed, TEST_FILE));
    debug_print ("Decrypted seed: %s\n", utils_uint8_to_hex (decrypted_seed, sizeof (SEED)));

    // Compare the seed and the decrypted seed
    u_assert_mem_eq (seed, decrypted_seed, sizeof (SEED));
    debug_print ("Seed and decrypted seed are equal\n");

    // Generate a random mnemonic with the TPM2
    u_assert_true (dogecoin_generate_mnemonic_encrypt_with_tpm(mnemonic, TEST_FILE, true, "eng", " ", NULL));
    debug_print("Mnemonic: %s\n", mnemonic);

    // Decrypt the mnemonic with the TPM2
    u_assert_true (dogecoin_decrypt_mnemonic_with_tpm(decrypted_mnemonic, TEST_FILE));
    debug_print("Decrypted mnemonic: %s\n", decrypted_mnemonic);

    // Compare the mnemonic and the decrypted mnemonic
    u_assert_mem_eq (mnemonic, decrypted_mnemonic, sizeof (MNEMONIC));
    debug_print("Mnemonic and decrypted mnemonic are equal\n");

    // test generateRandomEnglishMnemonicTPM
    u_assert_true (generateRandomEnglishMnemonicTPM(mnemonic, TEST_FILE, true));
    debug_print("Mnemonic: %s\n", mnemonic);

    // test getDerivedHDAddressFromEncryptedSeed
    char derived_address[P2PKHLEN];
    u_assert_true (getDerivedHDAddressFromEncryptedSeed(0, 0, BIP44_CHANGE_EXTERNAL, derived_address, false, TEST_FILE) == 0);
    debug_print("Derived address: %s\n", derived_address);

    // test getDerivedHDAddressFromEncryptedMnemonic
    u_assert_true (getDerivedHDAddressFromEncryptedMnemonic(0, 0, BIP44_CHANGE_EXTERNAL, NULL, derived_address, false, TEST_FILE) == 0);
    debug_print("Derived address: %s\n", derived_address);

    // test getDerivedHDAddressFromEncryptedHDNode
    u_assert_true (getDerivedHDAddressFromEncryptedHDNode(0, 0, BIP44_CHANGE_EXTERNAL, derived_address, false, TEST_FILE) == 0);
    debug_print("Derived address: %s\n", derived_address);

#endif

}
