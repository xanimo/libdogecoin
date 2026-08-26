#include "libdogecoin.h"
#include <stdio.h>
#include <string.h>

// Example of how to use libdogecoin API functions:
// gcc ./examples/example.c -I./include -L./lib -ldogecoin -levent -o example

// (or in the case of this project's directory structure, and if you want to build statically):
// (after build, from the /libdogecoin project root directory)
// gcc ./contrib/examples/example.c ./.libs/libdogecoin.a -I./include/dogecoin -L./.libs -ldogecoin -levent -o example
// To include the ZK carrier section (requires --enable-zk-carrier at configure time):
// gcc ./contrib/examples/example.c ./.libs/libdogecoin.a -I./include/dogecoin -L./.libs -ldogecoin -DUSE_ZK_CARRIER -o example
//
// When libdogecoin is configured with --enable-intel-avx2 or --enable-intel-sse,
// also link the matching per-asm archives so sha256_block_{avx,sse} /
// sha512_block_{avx,sse} resolve:
//   gcc ./contrib/examples/example.c ./.libs/libdogecoin.a src/intel/*/*.a \
//       -I./include/dogecoin -lpthread -levent -levent_core -levent_extra -lm -o example
// then run 'example'.

//  for windows, from the command line: (after build, from the /libdogecoin project root directory) run:
//  "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" first to set up the environment.
//  then run: cl.exe contrib/examples/example.c /I"include\dogecoin" /link "build\Debug\dogecoin.lib" ncrypt.lib tbs.lib msvcrt.lib advapi32.lib event.lib /out:example.exe
//  then run: example.exe

int main() {
	dogecoin_ecc_start();

	// BASIC ADDRESS EXAMPLES
	printf("\n\nBEGIN BASIC ADDRESSING:\n\n");
	// create variables

	char wif_privkey[PRIVKEYWIFLEN];
	char p2pkh_pubkey[P2PKHLEN];
	char hd_master_privkey[HDKEYLEN];
	char p2pkh_master_pubkey[P2PKHLEN];
	char p2pkh_child_pubkey[P2PKHLEN];

	// keypair generation
	if (generatePrivPubKeypair(wif_privkey, p2pkh_pubkey, 0)) {
		printf("Mainnet keypair 1:\n===============================\nPrivate: %s\nPublic:  %s\n\n", wif_privkey, p2pkh_pubkey);
	}
	else {
		printf("Error occurred 1.\n");
		return -1;
	}

	if (generateHDMasterPubKeypair(hd_master_privkey, p2pkh_master_pubkey, 0)) {
		printf("Mainnet master keypair 2:\n===============================\nPrivate: %s\nPublic:  %s\n\n", hd_master_privkey, p2pkh_master_pubkey);
	}
	else {
		printf("Error occurred 2.\n");
		return -1;
	}


	if (generateDerivedHDPubkey((const char*)hd_master_privkey, (char*)p2pkh_child_pubkey)) {
		printf("Mainnet master derived keypair 3:\n===============================\nPrivate: %s\nPublic:  %s\n\n", hd_master_privkey, p2pkh_child_pubkey);
	}
	else {
		printf("Error occurred 3.\n");
		return -1;
	}
	printf("\n");

	// keypair verification
	if (verifyPrivPubKeypair(wif_privkey, p2pkh_pubkey, 0)) {
		printf("Keypair (%s, %s) is valid for mainnet 4.\n\n", wif_privkey, p2pkh_pubkey);
	}
	else {
		printf("Keypair (%s, %s) is not valid for mainnet 4.\n", wif_privkey, p2pkh_pubkey);
		return -1;
	}

	if (verifyHDMasterPubKeypair(hd_master_privkey, p2pkh_master_pubkey, 0)) {
		printf("Keypair (%s, %s) is valid for mainnet 5.\n\n", hd_master_privkey, p2pkh_master_pubkey);
	}
	else {
		printf("Keypair (%s, %s) is not valid for mainnet 5.\n", hd_master_privkey, p2pkh_master_pubkey);
		return -1;
	}

	if (verifyHDMasterPubKeypair(hd_master_privkey, p2pkh_child_pubkey, 0)) {
		printf("Keypair (%s, %s) is valid for mainnet 6.\n\n", hd_master_privkey, p2pkh_child_pubkey);
	}
	else {
		printf("Keypair (%s, %s) is not valid for mainnet 6.\n", hd_master_privkey, p2pkh_child_pubkey);
		return -1;
	}
	printf("\n");

	// address verification
	if (verifyP2pkhAddress(p2pkh_pubkey, strlen(p2pkh_pubkey))) {
		printf("Address %s is valid for mainnet 7.\n\n", p2pkh_pubkey);
	}
	else {
		printf("Address %s is not valid for mainnet 7.\n", p2pkh_pubkey);
		return -1;
	}

	if (verifyP2pkhAddress(p2pkh_master_pubkey, strlen(p2pkh_master_pubkey))) {
		printf("Address %s is valid for mainnet 8.\n\n", p2pkh_master_pubkey);
	}
	else {
		printf("Address %s is not valid for mainnet 8.\n", p2pkh_master_pubkey);
		return -1;
	}

	if (verifyP2pkhAddress(p2pkh_child_pubkey, strlen(p2pkh_child_pubkey))) {
		printf("Address %s is valid for mainnet 9.\n", p2pkh_child_pubkey);
	}
	else {
		printf("Address %s is not valid for mainnet 9.\n", p2pkh_child_pubkey);
		return -1;
	}
	printf("\n");
	// END ===========================================


	// DERIVED HD ADDRESS EXAMPLE
	printf("\n\nBEGIN HD ADDRESS DERIVATION EXAMPLE:\n\n");
	size_t extoutsize = HDKEYLEN;
	char* extout = dogecoin_char_vla(extoutsize);
	char* masterkey_main_ext = "dgpv51eADS3spNJh8h13wso3DdDAw3EJRqWvftZyjTNCFEG7gqV6zsZmucmJR6xZfvgfmzUthVC6LNicBeNNDQdLiqjQJjPeZnxG8uW3Q3gCA3e";

	/* returns a serialized extended key, not an address; see getDerivedHDAddressAsP2PKH below */
	if (getDerivedHDAddress(masterkey_main_ext, 0, false, 0, extout, true)) {
		printf("Derived HD Extended Keys:\n%s\n%s\n\n", extout, "dgpv5BeiZXttUioRMzXUhD3s2uE9F23EhAwFu9meZeY9G99YS6hJCsQ9u6PRsAG3qfVwB1T7aQTVGLsmpxMiczV1dRDgzpbUxR7utpTRmN41iV7");
	} else {
		printf("getDerviedHDAddress failed!\n");
		return -1;
	}

	char keypath[BIP44_KEY_PATH_MAX_SIZE] = "m/44'/3'/0'/0/0";
	if (getDerivedHDAddressByPath(masterkey_main_ext, keypath, extout)) {
		printf("Derived P2PKH Address:\n%s\n%s\n", extout, "DCm7oSg95sxwn3sWxYUDHgKKbB2mDmuR3B");
	} else {
		printf("getDerivedHDAddressByPath failed!\n");
		return -1;
	}

	// test getHDNodeAndExtKeyByPath
	size_t wiflen = PRIVKEYWIFLEN;
	char privkeywif_main[PRIVKEYWIFLEN];
	dogecoin_hdnode* hdnode = getHDNodeAndExtKeyByPath(masterkey_main_ext, keypath, extout, true);
	if (strcmp(utils_uint8_to_hex(hdnode->private_key, sizeof hdnode->private_key), "09648faa2fa89d84c7eb3c622e06ed2c1c67df223bc85ee206b30178deea7927") != 0) {
		printf("getHDNodeAndExtKeyByPath!\n");
	}
	dogecoin_privkey_encode_wif((const dogecoin_key*)hdnode->private_key, &dogecoin_chainparams_main, privkeywif_main, &wiflen);
	if (strcmp(privkeywif_main, "QNvtKnf9Qi7jCRiPNsHhvibNo6P5rSHR1zsg3MvaZVomB2J3VnAG") != 0) {
		printf("privkeywif_main does not match!\n");
	}
	if (strcmp(extout, "dgpv5BeiZXttUioRMzXUhD3s2uE9F23EhAwFu9meZeY9G99YS6hJCsQ9u6PRsAG3qfVwB1T7aQTVGLsmpxMiczV1dRDgzpbUxR7utpTRmN41iV7") != 0) {
		printf("extout does not match!\n");
	}
	char* privkeywifbypath = getHDNodePrivateKeyWIFByPath(masterkey_main_ext, keypath, extout, true);
	if (strcmp(privkeywifbypath, "QNvtKnf9Qi7jCRiPNsHhvibNo6P5rSHR1zsg3MvaZVomB2J3VnAG") != 0) {
		printf("private key WIF does not match!\n");
	}
	if (strcmp(extout, "dgpv5BeiZXttUioRMzXUhD3s2uE9F23EhAwFu9meZeY9G99YS6hJCsQ9u6PRsAG3qfVwB1T7aQTVGLsmpxMiczV1dRDgzpbUxR7utpTRmN41iV7") != 0) {
		printf("extout does not match!\n");
	}
	dogecoin_hdnode_free(hdnode);
	dogecoin_free(extout);
	dogecoin_free(privkeywifbypath);
	// END ===========================================

	// TOOLS EXAMPLE
	printf("\n\nTOOLS EXAMPLE:\n\n");
	char addr[P2PKHLEN];
	if (addresses_from_pubkey(&dogecoin_chainparams_main, "039ca1fdedbe160cb7b14df2a798c8fed41ad4ed30b06a85ad23e03abe43c413b2", addr)) {
		printf ("addr: %s\n", addr);
	}

	size_t pubkeylen = PUBKEYHEXLEN;
	char* pubkey=dogecoin_char_vla(pubkeylen);
	if (pubkey_from_privatekey(&dogecoin_chainparams_main, "QUaohmokNWroj71dRtmPSses5eRw5SGLKsYSRSVisJHyZdxhdDCZ", pubkey, &pubkeylen)) {
		printf ("pubkey: %s\n", pubkey);
	}
	dogecoin_free(pubkey);

	size_t privkeywiflen = PRIVKEYWIFLEN;
	char* privkeywif=dogecoin_char_vla(privkeywiflen);
	char privkeyhex[PRIVKEYHEXLEN];
	if (gen_privatekey(&dogecoin_chainparams_main, privkeywif, privkeywiflen, NULL)) {
			if (gen_privatekey(&dogecoin_chainparams_main, privkeywif, privkeywiflen, privkeyhex)) {
			printf ("privkeywif: %s\n", privkeywif);
			printf ("privkeyhex: %s\n", privkeyhex);
		}
	}
	dogecoin_free(privkeywif);
	// END ===========================================

	// SLIP-0039 EXAMPLE
	printf("\n\nSLIP-0039 EXAMPLE:\n\n");
	const uint8_t slip39_secret[] = {
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98
	};
	const size_t slip39_secret_len = sizeof(slip39_secret);
	const uint8_t slip39_threshold = 2;
	const uint8_t slip39_share_count = 3;
	SLIP0039_SHARE slip39_shares[SLIP0039_MAX_SHARES];
	dogecoin_mem_zero(slip39_shares, sizeof(slip39_shares));
	char slip39_secret_hex[(MAX_SEED_SIZE * 2) + 1];
	dogecoin_mem_zero(slip39_secret_hex, sizeof(slip39_secret_hex));
	utils_bin_to_hex((unsigned char*)slip39_secret, slip39_secret_len, slip39_secret_hex);
	if (dogecoin_slip0039_generate_shares(slip39_secret, slip39_secret_len,
	                                      slip39_threshold, slip39_share_count,
	                                      slip39_shares) != 0) {
		printf("SLIP-0039 share generation failed.\n");
		return -1;
	}
	printf("SLIP-0039 secret (hex): %s\n", slip39_secret_hex);
	for (uint8_t i = 0; i < slip39_share_count; ++i) {
		printf("SLIP-0039 share %u: %s\n", (unsigned int)(i + 1), slip39_shares[i]);
	}
	const char* slip39_recovery_shares[] = { slip39_shares[0], slip39_shares[1] };
	uint8_t slip39_recovered[MAX_SEED_SIZE];
	dogecoin_mem_zero(slip39_recovered, sizeof(slip39_recovered));
	size_t slip39_recovered_len = sizeof(slip39_recovered);
	if (dogecoin_slip0039_recover_secret(slip39_recovery_shares, 2, NULL, 0,
	                                     slip39_recovered, &slip39_recovered_len) != 0) {
		printf("SLIP-0039 secret recovery failed.\n");
		return -1;
	}
	char slip39_recovered_hex[(MAX_SEED_SIZE * 2) + 1];
	dogecoin_mem_zero(slip39_recovered_hex, sizeof(slip39_recovered_hex));
	utils_bin_to_hex(slip39_recovered, slip39_recovered_len, slip39_recovered_hex);
	printf("SLIP-0039 recovered (hex): %s\n", slip39_recovered_hex);
	if (slip39_recovered_len != slip39_secret_len ||
	    memcmp(slip39_secret, slip39_recovered, slip39_secret_len) != 0) {
		printf("SLIP-0039 recovered secret does not match original.\n");
		return -1;
	}
	printf("SLIP-0039 round-trip OK.\n");
	// END ===========================================

	// BIP44 EXAMPLE
	printf("\n\nBIP44 EXAMPLE:\n\n");

	int result;
	dogecoin_hdnode node;
	dogecoin_hdnode bip44_key;
	size_t size;

	dogecoin_hdnode_from_seed(utils_hex_to_uint8("000102030405060708090a0b0c0d0e0f"), 16, &node);
	printf ("seed: 000102030405060708090a0b0c0d0e0f\n");

	char master_key_str[HDKEYLEN];

	// Print the master key (MAINNET)
	dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, master_key_str, sizeof(master_key_str));
	printf("BIP32 master pub key: %s\n", master_key_str);
	dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, master_key_str, sizeof(master_key_str));
	printf("BIP32 master prv key: %s\n", master_key_str);

	char* change_level = BIP44_CHANGE_EXTERNAL;
	uint32_t account = BIP44_FIRST_ACCOUNT_NODE;

	// Derive the BIP 44 extended key (returns 0 on success, -1 on failure)
	if (derive_bip44_extended_key(&node, &account, NULL, change_level, NULL, false, keypath, &bip44_key) != 0) {
		printf("Error occurred.\n");
		return -1;
	}

	// Print the BIP 44 extended key
	char bip44_private_key[HDKEYLEN];
	dogecoin_hdnode_serialize_private(&bip44_key, &dogecoin_chainparams_main, bip44_private_key, sizeof(bip44_private_key));
	printf("BIP44 extended key: %s\n", bip44_private_key);

	char str[P2PKHLEN];

	// Print the BIP 44 extended public key
	char bip44_public_key[HDKEYLEN];
	dogecoin_hdnode_serialize_public(&bip44_key, &dogecoin_chainparams_main, bip44_public_key, sizeof(bip44_public_key));
	printf("BIP44 extended public key: %s\n", bip44_public_key);

	printf("%s", "Derived Addresses\n");

		char wifstr[PRIVKEYWIFLEN];
		wiflen = PRIVKEYWIFLEN;

	for (uint32_t index = BIP44_FIRST_ADDRESS_INDEX; index < BIP44_ADDRESS_GAP_LIMIT; index++) {
		// Derive the addresses (returns 0 on success, -1 on failure)
		if (derive_bip44_extended_key(&node, &account, &index, change_level, NULL, false, keypath, &bip44_key) != 0) {
			printf("Error occurred.\n");
			return -1;
		}

		// Print the private key
		dogecoin_hdnode_serialize_private(&bip44_key, &dogecoin_chainparams_main, bip44_private_key, sizeof(bip44_private_key));
		printf("private key (serialized): %s\n", bip44_private_key);

		// Print the public key
		dogecoin_hdnode_serialize_public(&bip44_key, &dogecoin_chainparams_main, bip44_public_key, sizeof(bip44_public_key));
		printf("public key (serialized): %s\n", bip44_public_key);

		// Print the wif private key
		dogecoin_privkey_encode_wif((dogecoin_key*) bip44_key.private_key, &dogecoin_chainparams_main, wifstr, &wiflen);
		printf("private key (wif): %s\n", wifstr);

		// Print the p2pkh address
		dogecoin_hdnode_get_p2pkh_address(&bip44_key, &dogecoin_chainparams_main, str, sizeof(str));
		printf("Address: %s\n", str);
	}

	// EXTENDED PUBLIC KEY DERIVATION EXAMPLE
	printf("\n\nBEGIN EXTENDED PUBLIC KEY DERIVATION:\n\n");

	// Generate the Master key from a seed
	char masterkey[HDKEYLEN];
	getHDRootKeyFromSeed(utils_hex_to_uint8("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"), MAX_SEED_SIZE, false, masterkey);
	printf("Master key: %s\n", masterkey);

	// Serialize and print the Master public key
	char master_public_key[HDKEYLEN] = {0};
	getHDPubKey(masterkey, false, master_public_key);
	printf("Master public key: %s\n", master_public_key);

	// Derive an extended normal (non-hardened) public key
	char extkeypath[KEYPATHMAXLEN] = "m/44'/3'/0'";
	char extpubkey[HDKEYLEN] = {0};
	dogecoin_hdnode* node_bypath = getHDNodeAndExtKeyByPath(masterkey, extkeypath, extpubkey, false);
	printf("(Account) Extended public key: %s\n", extpubkey);
	if (strcmp(extpubkey, "dgub8rUhDtD3YFGZTUphBfpBbzvFxSMKQXYLzg87Me2ta78r2SdVLmypBUkkxrrn9RTnchsyiJSkHZyLWxD13ibBiXtuFWktBoDaGaZjQUBLNLs") != 0) {
			printf("extpubkey does not match!\n");
	}
	dogecoin_hdnode_free(node_bypath);

	// Derive an address from the extended public key
	char derived_address2[P2PKHLEN];
	if (getDerivedHDAddressFromAcctPubKey(extpubkey, 0, BIP44_CHANGE_EXTERNAL, derived_address2, false) == 0) {
		printf("(Account) Extended public key: %s\n", extpubkey);
		if (strcmp(extpubkey, "dgub8rUhDtD3YFGZTUphBfpBbzvFxSMKQXYLzg87Me2ta78r2SdVLmypBUkkxrrn9RTnchsyiJSkHZyLWxD13ibBiXtuFWktBoDaGaZjQUBLNLs") != 0) {
			printf("extpubkey does not match!\n");
		}
		printf("Derived address 0: %s\n", derived_address2);
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// BASIC TRANSACTION FORMATION EXAMPLE
	printf("\n\nBEGIN TRANSACTION FORMATION AND SIGNING:\n\n");
	// declare keys and previous hashes
	char *external_p2pkh_addr = 	"nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";
	char *hash_2_doge = 			"b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074";
	char *hash_10_doge = 			"42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2";
	char myscriptpubkey [SCRIPTPUBKEYLEN];
	dogecoin_p2pkh_address_to_pubkey_hash (str, myscriptpubkey);

	// build transaction
	int idx = start_transaction();
	printf("Empty transaction created at index %d.\n", idx);

	if (add_utxo(idx, hash_2_doge, 1)) {
		printf("Input of value 2 dogecoin added to the transaction.\n");
	}
	else {
		printf("Error occurred.\n");
		return -1;
	}

	if (add_utxo(idx, hash_10_doge, 1)) {
		printf("Input of value 10 dogecoin added to the transaction.\n");
	}
	else {
		printf("Error occurred.\n");
		return -1;
	}

	if (add_output(idx, external_p2pkh_addr, "5.0")) {
		printf("Output of value 5 dogecoin added to the transaction.\n");
	}
	else {
		printf("Error occurred.\n");
		return -1;
	}

	// save the finalized unsigned transaction to a new index in the hash table
	int idx2 = store_raw_transaction(finalize_transaction(idx, external_p2pkh_addr, "0.00226", "12", str));
	if (idx2 > 0) {
		printf("Change returned to address %s and finalized unsigned transaction saved at index %d.\n", str, idx2);
	}
	else {
		printf("Error occurred.\n");
		return -1;
	}

	char txhex_buf[TXHEXMAXLEN + 1] = {0};
	get_raw_transaction_ex(idx, txhex_buf, sizeof(txhex_buf));
	printf("Transaction hex: %s\n", txhex_buf);
	printf("Transaction hex length: %ld\n", strlen(txhex_buf));
	printf("Transaction unsigned hex: %s\n", get_raw_transaction(idx2));
	printf("Transaction unsigned hex length: %ld\n", strlen(get_raw_transaction(idx2)));
	printf("str: %s\n", str);
	printf("my script pubkey: %s\n", myscriptpubkey);
	printf("my script pubkey length: %ld\n", strlen(myscriptpubkey));
	printf("privkeywif: %s\n", wifstr);

	// sign transaction using buffered _ex API
	if (sign_transaction_ex(idx, myscriptpubkey, wifstr, txhex_buf, sizeof(txhex_buf))) {
		printf("\nAll transaction inputs signed successfully. \nFinal transaction hex: %s\n.", txhex_buf);
	}
	else {
		printf("Error occurred.\n");
		return -1;
	}
    remove_all();
	// END ===========================================


	// BASIC MESSAGE SIGNING EXAMPLE
	printf("\n\nBEGIN BASIC MESSAGE SIGNING:\n\n");
	char* msg = "This is just a test message";
    char* privkey = "QUtnMFjt3JFk1NfeMe6Dj5u4p25DHZA54FsvEFAiQxcNP4bZkPu2";
    char* address = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
    char* sig = sign_message(privkey, msg);
	if (verify_message(sig, msg, address)) {
		printf("Addresses match!\n");
	} else {
		printf("Addresses do not match!\n");
		return -1;
	}

    // testcase 2:
    // assert modified msg will cause verification failure:
    msg = "This is a new test message";
	if (!verify_message(sig, msg, address)) {
		printf("Addresses do not match!\n");
	} else {
		printf("Addresses match!\n");
		return -1;
	}

	// testcase 3:
    msg = "This is just a test message";
	if (verify_message(sig, msg, address)) {
		printf("Addresses match!\n");
	} else {
		printf("Addresses do not match!\n");
		return -1;
	}
    dogecoin_free(sig);
	// END ===========================================


	// ADVANCED MESSAGE SIGNING EXAMPLE
	printf("\n\nBEGIN ADVANCED MESSAGE SIGNING:\n\n");
    for (int i = 0; i < 10; i++) {
        // key 1:
        int key_id = start_key(false);
        eckey* key = find_eckey(key_id);
        char* msg = "This is a test message";
        char* sig = sign_message(key->private_key_wif, msg);
        if (verify_message(sig, msg, key->address)) {
			printf("Addresses match!\n");
		} else {
			printf("Message verification failed!\n");
			return -1;
		}
        remove_eckey(key);
        dogecoin_free(sig);

        // key 2:
        int key_id2 = start_key(true);
        eckey* key2 = find_eckey(key_id2);
        char* msg2 = "This is a test message";
        char* sig2 = sign_message(key2->private_key_wif, msg2);
        if (verify_message(sig2, msg2, key2->address)) {
			printf("Addresses match!\n");
		} else {
			printf("Message verification failed!\n");
			return -1;
		}

        // test message signature verification failure:
        msg2 = "This is an altered test message";
        if (!verify_message(sig2, msg2, key2->address)) {
			printf("Addresses do not match!\n");
		} else {
			printf("Message verification failed!\n");
			return -1;
		}
        remove_eckey(key2);
        dogecoin_free(sig2);
    }

#if defined(USE_LIBOQS)
	// PQC EXAMPLE (Falcon-512, Dilithium2)
	printf("\n\nBEGIN PQC EXAMPLE:\n\n");

	// Falcon-512: keypair + sign + verify + 32-byte carrier commitment.
	uint8_t *falcon_pk = NULL, *falcon_sk = NULL, *falcon_sig = NULL;
	size_t falcon_pk_len = 0, falcon_sk_len = 0, falcon_sig_len = 0;
	uint8_t pqc_msg[32];
	for (int i = 0; i < 32; ++i) pqc_msg[i] = (uint8_t)i;

	if (dogecoin_falcon512_keypair(&falcon_pk, &falcon_pk_len, &falcon_sk, &falcon_sk_len)
	    && dogecoin_falcon512_sign(falcon_sk, falcon_sk_len, pqc_msg, sizeof pqc_msg, &falcon_sig, &falcon_sig_len)
	    && dogecoin_falcon512_verify(falcon_pk, falcon_pk_len, pqc_msg, sizeof pqc_msg, falcon_sig, falcon_sig_len)) {
		uint8_t falcon_commit[DOGECOIN_PQC_FALCON_COMMIT_LEN];
		if (dogecoin_falcon512_commit_bytes(falcon_pk, falcon_pk_len, falcon_sig, falcon_sig_len, falcon_commit)) {
			printf("Falcon-512 keypair/sign/verify/commit OK.\n");
		} else {
			printf("Falcon-512 commit_bytes failed.\n");
			return -1;
		}
	} else {
		printf("Falcon-512 keypair/sign/verify failed.\n");
		return -1;
	}
	dogecoin_free(falcon_pk);
	dogecoin_free(falcon_sk);
	dogecoin_free(falcon_sig);

	// Dilithium2: keypair + sign + verify + 32-byte carrier commitment.
	uint8_t *dil_pk = NULL, *dil_sk = NULL, *dil_sig = NULL;
	size_t dil_pk_len = 0, dil_sk_len = 0, dil_sig_len = 0;

	if (dogecoin_dilithium2_keypair(&dil_pk, &dil_pk_len, &dil_sk, &dil_sk_len)
	    && dogecoin_dilithium2_sign(dil_sk, dil_sk_len, pqc_msg, sizeof pqc_msg, &dil_sig, &dil_sig_len)
	    && dogecoin_dilithium2_verify(dil_pk, dil_pk_len, pqc_msg, sizeof pqc_msg, dil_sig, dil_sig_len)) {
		uint8_t dil_commit[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN];
		if (dogecoin_dilithium2_commit_bytes(dil_pk, dil_pk_len, dil_sig, dil_sig_len, dil_commit)) {
			printf("Dilithium2 keypair/sign/verify/commit OK.\n");
		} else {
			printf("Dilithium2 commit_bytes failed.\n");
			return -1;
		}
	} else {
		printf("Dilithium2 keypair/sign/verify failed.\n");
		return -1;
	}
	dogecoin_free(dil_pk);
	dogecoin_free(dil_sk);
	dogecoin_free(dil_sig);
#endif

#if defined(USE_RACCOON_G)
	// RACCOON-G-44 EXAMPLE (sign/verify + HD derivation)
	printf("\n\nBEGIN RACCOON-G-44 EXAMPLE:\n\n");

	uint8_t *rac_pk = NULL, *rac_sk = NULL, *rac_sig = NULL;
	size_t rac_pk_len = 0, rac_sk_len = 0, rac_sig_len = 0;
	uint8_t rac_msg[32];
	for (int i = 0; i < 32; ++i) rac_msg[i] = (uint8_t)(0xa0 + i);

	if (dogecoin_raccoong44_keypair(&rac_pk, &rac_pk_len, &rac_sk, &rac_sk_len)
	    && dogecoin_raccoong44_sign(rac_sk, rac_sk_len, rac_msg, sizeof rac_msg, &rac_sig, &rac_sig_len)
	    && dogecoin_raccoong44_verify(rac_pk, rac_pk_len, rac_msg, sizeof rac_msg, rac_sig, rac_sig_len)) {
		printf("Raccoon-G-44 keypair/sign/verify OK.\n");
	} else {
		printf("Raccoon-G-44 keypair/sign/verify failed.\n");
		return -1;
	}

	// BIP32-style HD derivation (non-hardened): pub-only derive_pub must
	// match pk from derive_priv, and the child sk must sign+verify.
	uint8_t rac_chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
	memset(rac_chaincode, 0x42, sizeof rac_chaincode);
	uint8_t *rac_child_sk = NULL, *rac_child_pk = NULL, *rac_child_pubonly = NULL;
	size_t rac_child_sk_len = 0, rac_child_pk_len = 0, rac_child_pubonly_len = 0;
	if (dogecoin_raccoong44_hd_derive_priv(rac_sk, rac_sk_len, rac_pk, rac_pk_len,
	                                       rac_chaincode, 7, /*hardened=*/false,
	                                       &rac_child_sk, &rac_child_sk_len,
	                                       &rac_child_pk, &rac_child_pk_len)
	    && dogecoin_raccoong44_hd_derive_pub(rac_pk, rac_pk_len, rac_chaincode, 7,
	                                         &rac_child_pubonly, &rac_child_pubonly_len)
	    && rac_child_pk_len == rac_child_pubonly_len
	    && memcmp(rac_child_pk, rac_child_pubonly, rac_child_pk_len) == 0) {
		printf("Raccoon-G-44 non-hardened pub-only derivation matches derive_priv.\n");

		uint8_t *rac_child_sig = NULL;
		size_t rac_child_sig_len = 0;
		if (dogecoin_raccoong44_sign(rac_child_sk, rac_child_sk_len, rac_msg, sizeof rac_msg,
		                             &rac_child_sig, &rac_child_sig_len)
		    && dogecoin_raccoong44_verify(rac_child_pk, rac_child_pk_len, rac_msg, sizeof rac_msg,
		                                  rac_child_sig, rac_child_sig_len)) {
			printf("Raccoon-G-44 HD child sign/verify OK.\n");
		} else {
			printf("Raccoon-G-44 HD child sign/verify failed.\n");
			return -1;
		}
		dogecoin_free(rac_child_sig);
	} else {
		printf("Raccoon-G-44 HD derivation failed.\n");
		return -1;
	}
	dogecoin_free(rac_child_sk);
	dogecoin_free(rac_child_pk);
	dogecoin_free(rac_child_pubonly);
	dogecoin_free(rac_pk);
	dogecoin_free(rac_sk);
	dogecoin_free(rac_sig);
#endif

#if defined(USE_ZK_CARRIER)
	// ZK CARRIER EXAMPLE (Groth16 payload encode/decode + commitment)
	printf("\n\nBEGIN ZK CARRIER EXAMPLE:\n\n");

	// Synthetic public inputs / proof bytes (real input comes from snarkjs).
	const uint8_t zk_pub[]   = {0x01, 0x02, 0x03, 0x04, 0x05};
	const uint8_t zk_proof[] = "{\"pi_a\":[\"1\",\"2\"],\"pi_b\":[],\"pi_c\":[]}";

	uint8_t* zk_payload = NULL;
	size_t zk_payload_len = 0;
	dogecoin_zk_err_t zk_err = dogecoin_zk_encode_payload(
	    DOGECOIN_ZK_MODE_GROTH16, 0xDEADBEEF,
	    zk_pub, sizeof zk_pub,
	    zk_proof, sizeof zk_proof,
	    NULL, 0,
	    &zk_payload, &zk_payload_len);
	if (zk_err != DOGECOIN_ZK_OK) {
		printf("dogecoin_zk_encode_payload failed: %s\n", dogecoin_zk_strerror(zk_err));
		return -1;
	}

	dogecoin_zk_mode_t zk_mode_out;
	uint32_t zk_cid_out;
	const uint8_t *zk_pub_out, *zk_proof_out, *zk_vk_out = NULL;
	size_t zk_pub_out_len = 0, zk_proof_out_len = 0, zk_vk_out_len = 0;
	zk_err = dogecoin_zk_decode_payload(zk_payload, zk_payload_len,
	                                    &zk_mode_out, &zk_cid_out,
	                                    &zk_pub_out, &zk_pub_out_len,
	                                    &zk_proof_out, &zk_proof_out_len,
	                                    &zk_vk_out, &zk_vk_out_len);
	if (zk_err == DOGECOIN_ZK_OK
	    && zk_mode_out == DOGECOIN_ZK_MODE_GROTH16
	    && zk_cid_out == 0xDEADBEEF
	    && zk_pub_out_len == sizeof zk_pub
	    && memcmp(zk_pub_out, zk_pub, sizeof zk_pub) == 0
	    && zk_proof_out_len == sizeof zk_proof
	    && memcmp(zk_proof_out, zk_proof, sizeof zk_proof) == 0) {
		printf("ZK Groth16 payload encode/decode round-trip OK.\n");
	} else {
		printf("ZK Groth16 payload decode mismatch: %s\n", dogecoin_zk_strerror(zk_err));
		return -1;
	}

	// SHA256d commitment over the canonical payload bytes.
	uint8_t zk_commit[32];
	zk_err = dogecoin_zk_get_commitment_hash(zk_payload, zk_payload_len, zk_commit);
	if (zk_err == DOGECOIN_ZK_OK) {
		printf("ZK commitment hash computed (32 bytes).\n");
	} else {
		printf("dogecoin_zk_get_commitment_hash failed: %s\n", dogecoin_zk_strerror(zk_err));
		return -1;
	}

	dogecoin_free(zk_payload);
#endif

#if defined(USE_TPM2)
	// TPM2 TESTS
	printf("\n\nBEGIN TPM2 TESTS:\n\n");

	// test dogecoin_encrypt_seed_with_tpm
	SEED seed = {0};
	if (dogecoin_encrypt_seed_with_tpm(seed, sizeof(seed), TEST_FILE, true)) {
		printf("Seed encrypted with TPM2.\n");
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test dogecoin_generate_mnemonic_encrypt_with_tpm
	MNEMONIC mnemonic = {0};
	if (dogecoin_generate_mnemonic_encrypt_with_tpm(mnemonic, TEST_FILE, true, "eng", " ", NULL)) {
		printf("Mnemonic generated and encrypted with TPM2.\n");
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test dogecoin_generate_hdnode_encrypt_with_tpm
	dogecoin_hdnode out;
	if (dogecoin_generate_hdnode_encrypt_with_tpm(&out, TEST_FILE, true)) {
		printf("HD node generated and encrypted with TPM2.\n");
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test generateRandomEnglishMnemonicTPM
	if (generateRandomEnglishMnemonicTPM(mnemonic, TEST_FILE, true)) {
		printf("Mnemonic: %s\n", mnemonic);
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test getDerivedHDAddressFromEncryptedSeed
	char derived_address[P2PKHLEN];
	if (getDerivedHDAddressFromEncryptedSeed(0, 0, BIP44_CHANGE_EXTERNAL, derived_address, false, TEST_FILE) == 0) {
		printf("Derived address: %s\n", derived_address);
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test getDerivedHDAddressFromEncryptedMnemonic
	if (getDerivedHDAddressFromEncryptedMnemonic(0, 0, BIP44_CHANGE_EXTERNAL, NULL, derived_address, false, TEST_FILE) == 0) {
		printf("Derived address: %s\n", derived_address);
	} else {
		printf("Error occurred.\n");
		return -1;
	}

	// test getDerivedHDAddressFromEncryptedHDNode
	if (getDerivedHDAddressFromEncryptedHDNode(0, 0, BIP44_CHANGE_EXTERNAL, derived_address, false, TEST_FILE) == 0) {
		printf("Derived address: %s\n", derived_address);
	} else {
		printf("Error occurred.\n");
		return -1;
	}

#endif

	// CHAIN PREFIX HELPERS
	printf("\n\nBEGIN CHAIN PREFIX HELPERS:\n\n");
	{
		const char* mainnet_addr = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
		const char* testnet_addr = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";
		printf("isMainnet(%s) = %d\n", mainnet_addr, isMainnetFromB58Prefix(mainnet_addr));
		printf("isTestnet(%s) = %d\n", testnet_addr, isTestnetFromB58Prefix(testnet_addr));
		const dogecoin_chainparams* cp = chain_from_b58_prefix((char*)mainnet_addr);
		printf("chain_from_b58_prefix: %s\n", cp ? cp->chainname : "(null)");
		printf("chain_from_b58_prefix_bool: %d\n", chain_from_b58_prefix_bool((char*)testnet_addr));
	}

	// TOOL WRAPPERS
	printf("\n\nBEGIN TOOL WRAPPERS:\n\n");
	{
		char wif[PRIVKEYWIFLEN];
		char hex[PRIVKEYHEXLEN];
		size_t wsz = PRIVKEYWIFLEN;
		if (genPrivkey(false, wif, wsz, hex)) {
			printf("genPrivkey wif=%s hex=%s\n", wif, hex);
		}
		char pub_hex[PUBKEYHEXLEN];
		size_t psz = PUBKEYHEXLEN;
		if (getPubkeyFromPrivkey(wif, false, pub_hex, &psz)) {
			printf("getPubkeyFromPrivkey: %s\n", pub_hex);
		}
		char p2pkh_from_pub[P2PKHLEN];
		if (getAddressFromPubkey(pub_hex, false, p2pkh_from_pub)) {
			printf("getAddressFromPubkey: %s\n", p2pkh_from_pub);
		}
		char script_hex[SCRIPTPUBKEYLEN];
		if (dogecoin_p2pkh_address_to_pubkey_hash(p2pkh_from_pub, script_hex)) {
			printf("p2pkh_address_to_pubkey_hash (script): %s\n", script_hex);
		}
		/* dogecoin_address_to_pubkey_hash returns a pointer into a static
		 * internal buffer; it must NOT be freed by the caller. */
		char* pkh_from_addr = dogecoin_address_to_pubkey_hash(p2pkh_from_pub);
		if (pkh_from_addr) {
			printf("dogecoin_address_to_pubkey_hash: %s\n", pkh_from_addr);
			char roundtrip[P2PKHLEN];
			if (getAddrFromPubkeyHash(pkh_from_addr, false, roundtrip)) {
				printf("getAddrFromPubkeyHash: %s\n", roundtrip);
			}
			if (getAddrFromScriptPubKey(script_hex, false, roundtrip)) {
				printf("getAddrFromScriptPubKey: %s\n", roundtrip);
			}
			char p2pkh_from_hash[P2PKHLEN];
			/* takes raw scriptPubKey bytes, so decode the hex first */
			if (dogecoin_pubkey_hash_to_p2pkh_address((char*)utils_hex_to_uint8(script_hex), strlen(script_hex) / 2, p2pkh_from_hash, &dogecoin_chainparams_main)) {
				printf("pubkey_hash_to_p2pkh_address: %s\n", p2pkh_from_hash);
			}
		}
		/* dogecoin_private_key_wif_to_pubkey_hash allocates with
		 * dogecoin_malloc; caller owns the buffer and must free it. */
		char* pkh_from_wif = dogecoin_private_key_wif_to_pubkey_hash(wif);
		if (pkh_from_wif) {
			printf("dogecoin_private_key_wif_to_pubkey_hash: %s\n", pkh_from_wif);
			dogecoin_free(pkh_from_wif);
		}
	}

	// PRIVKEY/PUBKEY STRUCTURE APIs
	printf("\n\nBEGIN PRIVKEY/PUBKEY STRUCTURE APIs:\n\n");
	{
		dogecoin_key priv;
		dogecoin_privkey_init(&priv);
		if (!dogecoin_privkey_gen(&priv)) { printf("privkey_gen failed\n"); return -1; }
		printf("privkey is_valid: %d\n", dogecoin_privkey_is_valid(&priv));

		char privwif[PRIVKEYWIFLEN];
		size_t plen = PRIVKEYWIFLEN;
		dogecoin_privkey_encode_wif(&priv, &dogecoin_chainparams_main, privwif, &plen);
		printf("privkey wif: %s\n", privwif);

		dogecoin_key priv2;
		dogecoin_privkey_init(&priv2);
		if (!dogecoin_privkey_decode_wif(privwif, &dogecoin_chainparams_main, &priv2)) {
			printf("privkey_decode_wif failed\n"); return -1;
		}
		printf("decoded privkey is_valid: %d\n", dogecoin_privkey_is_valid(&priv2));

		// wrappers
		// getDecodedPrivKeyWif writes the raw 32-byte private key (binary, not hex)
		uint8_t priv_bin[DOGECOIN_ECKEY_PKEY_LENGTH];
		if (!getDecodedPrivKeyWif(privwif, false, (char*)priv_bin)) {
			printf("getDecodedPrivKeyWif returned 0\n");
		}
		char wif_encoded[PRIVKEYWIFLEN];
		size_t wlen2 = PRIVKEYWIFLEN;
		getWifEncodedPrivKey((const char*)priv.privkey, false, wif_encoded, &wlen2);
		printf("getWifEncodedPrivKey: %s\n", wif_encoded);

		// pubkey API
		dogecoin_pubkey pub;
		dogecoin_pubkey_init(&pub);
		pub.compressed = true;
		dogecoin_pubkey_from_key(&priv, &pub);
		printf("pubkey is_valid: %d\n", dogecoin_pubkey_is_valid(&pub));
		char addrout[P2PKHLEN];
		dogecoin_pubkey_getaddr_p2pkh(&pub, &dogecoin_chainparams_main, addrout);
		printf("pubkey_getaddr_p2pkh: %s\n", addrout);

		// sign / recover / verify via compact sig
		uint8_t msgbuf[] = "hello libdogecoin";
		uint256_t digest;
		sha256_raw(msgbuf, sizeof(msgbuf) - 1, digest);
		unsigned char sigcmp[64];
		size_t siglen = sizeof(sigcmp);
		int recid = -1;
		if (dogecoin_key_sign_hash_compact_recoverable_fcomp(&priv, digest, sigcmp, &siglen, &recid)) {
			printf("compact sig generated, recid=%d\n", recid);
			dogecoin_pubkey recovered;
			dogecoin_pubkey_init(&recovered);
			recovered.compressed = true;
			if (dogecoin_key_recover_pubkey(sigcmp, digest, recid, &recovered)) {
				printf("pubkey recovered, is_valid=%d\n", dogecoin_pubkey_is_valid(&recovered));
			}
			printf("verify_sigcmp: %d\n", dogecoin_pubkey_verify_sigcmp(&pub, digest, sigcmp));
		}
		dogecoin_privkey_cleanse(&priv);
		dogecoin_privkey_cleanse(&priv2);
		dogecoin_pubkey_cleanse(&pub);
	}

	// ECC API
	printf("\n\nBEGIN ECC API:\n\n");
	{
		uint8_t privbytes[DOGECOIN_ECKEY_PKEY_LENGTH];
		dogecoin_random_bytes(privbytes, sizeof(privbytes), 0);
		// ensure it's in range: just use known test vector style by hashing
		sha256_raw(privbytes, sizeof(privbytes), privbytes);

		uint8_t pubbytes[DOGECOIN_ECKEY_COMPRESSED_LENGTH];
		size_t pubsize = sizeof(pubbytes);
		dogecoin_ecc_get_pubkey(privbytes, pubbytes, &pubsize, true);
		printf("ecc_get_pubkey size=%zu first=%02x\n", pubsize, pubbytes[0]);

		uint256_t hash;
		uint8_t data[] = "ecc test";
		sha256_raw(data, sizeof(data) - 1, hash);
		unsigned char sigder[74];
		size_t sigderlen = sizeof(sigder);
		if (dogecoin_ecc_sign(privbytes, hash, sigder, &sigderlen)) {
			printf("ecc_sign der len=%zu\n", sigderlen);
			printf("ecc_verify_sig: %d\n", dogecoin_ecc_verify_sig(pubbytes, true, hash, sigder, sigderlen));
		}
	}

	// MNEMONIC / SEED
	printf("\n\nBEGIN MNEMONIC / SEED:\n\n");
	{
		MNEMONIC mnemonic = {0};
		if (generateRandomEnglishMnemonic("128", mnemonic) == 0) {
			printf("mnemonic (128): %s\n", mnemonic);
		}
		if (dogecoin_verify_mnemonic(mnemonic, "eng", " ", NULL) == 0) {
			printf("mnemonic verified\n");
		}
		SEED seed = {0};
		if (dogecoin_seed_from_mnemonic(mnemonic, NULL, seed) == 0) {
			printf("seed[0..3]: %02x%02x%02x%02x\n", seed[0], seed[1], seed[2], seed[3]);
		}
		char hd_priv[HDKEYLEN];
		char hd_p2pkh[P2PKHLEN];
		if (generateHDMasterPubKeypairFromMnemonic(hd_priv, hd_p2pkh, mnemonic, NULL, false) == 0) {
			printf("HD master from mnemonic addr=%s\n", hd_p2pkh);
			if (verifyHDMasterPubKeypairFromMnemonic(hd_priv, hd_p2pkh, mnemonic, NULL, false) == 0) {
				printf("HD master verified against mnemonic\n");
			}
		}
		char addr_from_mn[P2PKHLEN];
		if (getDerivedHDAddressFromMnemonic(0, 0, BIP44_CHANGE_EXTERNAL, mnemonic, NULL, addr_from_mn, false) == 0) {
			printf("derived addr from mnemonic: %s\n", addr_from_mn);
		}
		// entropy-driven path: HEX_ENTROPY is a fixed char buffer; zero-init
		// guarantees null termination after the 32 hex chars.
		MNEMONIC m2 = {0};
		HEX_ENTROPY zero_entropy = {0};
		memcpy(zero_entropy, "00000000000000000000000000000000", 32);
		if (generateEnglishMnemonic(zero_entropy, "128", m2) == 0) {
			printf("mnemonic (from zero entropy): %s\n", m2);
		}
	}

	// HDNODE PRIMITIVES
	printf("\n\nBEGIN HDNODE PRIMITIVES:\n\n");
	{
		dogecoin_hdnode* n = dogecoin_hdnode_new();
		SEED s;
		dogecoin_random_bytes(s, sizeof(s), 0);
		dogecoin_hdnode_from_seed(s, MAX_SEED_SIZE, n);
		dogecoin_hdnode_fill_public_key(n);

		char pub_hex_out[2 * DOGECOIN_ECKEY_COMPRESSED_LENGTH + 1];
		size_t ps = sizeof(pub_hex_out);
		dogecoin_hdnode_get_pub_hex(n, pub_hex_out, &ps);
		printf("hdnode pub_hex: %s\n", pub_hex_out);

		uint160_t h160;
		dogecoin_hdnode_get_hash160(n, h160);
		char h160_hex[41];
		utils_bin_to_hex((unsigned char*)h160, sizeof(h160), h160_hex);
		printf("hdnode hash160: %s\n", h160_hex);

		dogecoin_hdnode* copy = dogecoin_hdnode_copy(n);
		dogecoin_hdnode_private_ckd(copy, 0);
		dogecoin_hdnode_public_ckd(copy, 0);

		char serialized[HDKEYLEN];
		dogecoin_hdnode_serialize_private(n, &dogecoin_chainparams_main, serialized, sizeof(serialized));
		dogecoin_hdnode deserialized;
		if (dogecoin_hdnode_deserialize(serialized, &dogecoin_chainparams_main, &deserialized)) {
			printf("hdnode deserialize OK, depth=%u\n", deserialized.depth);
		}

		// extended key derivation wrappers
		KEY_PATH kp_acct = "m/44'/3'/0'";
		KEY_PATH kp_child = "m/0/0";
		KEY_PATH kp_full = "m/44'/3'/0'/0/0";
		char ext_out[HDKEYLEN];
		if (deriveExtKeyFromHDKey(serialized, kp_acct, false, ext_out)) {
			printf("deriveExtKeyFromHDKey: %s\n", ext_out);
		}
		char pub_ext[HDKEYLEN];
		char pub_from_priv[HDKEYLEN];
		getHDPubKey(ext_out, false, pub_from_priv);
		if (deriveExtPubKeyFromHDKey(pub_from_priv, kp_child, false, pub_ext)) {
			printf("deriveExtPubKeyFromHDKey: %s\n", pub_ext);
		}

		// bip32 tools
		char master_tool[HDKEYLEN];
		if (genHDMaster(false, master_tool, sizeof(master_tool)) == 0) {
			printf("genHDMaster OK\n");
			char ext_tool[HDKEYLEN];
			if (deriveHDExtFromMaster(false, master_tool, kp_full, ext_tool, sizeof(ext_tool)) == 0) {
				printf("deriveHDExtFromMaster OK\n");
			}
		}

		// BIP44 wrappers
		char bip44_ext[HDKEYLEN];
		char bip44_ext_pub[HDKEYLEN];
		KEY_PATH kp_out = {0};
		uint32_t acct = 0, idxv = 0;
		if (deriveBIP44ExtendedKey(serialized, &acct, BIP44_CHANGE_EXTERNAL, &idxv, NULL, bip44_ext, kp_out)) {
			printf("deriveBIP44ExtendedKey path=%s\n", kp_out);
		}
		if (deriveBIP44ExtendedPublicKey(serialized, &acct, BIP44_CHANGE_EXTERNAL, &idxv, NULL, bip44_ext_pub, kp_out)) {
			printf("deriveBIP44ExtendedPublicKey OK\n");
		}

		// getDerivedHDAddressAsP2PKH / getDerivedHDKeyByPath
		char p2pkh_out[P2PKHLEN];
		if (getDerivedHDAddressAsP2PKH(serialized, 0, false, 0, p2pkh_out)) {
			printf("getDerivedHDAddressAsP2PKH: %s\n", p2pkh_out);
		}
		char key_out[HDKEYLEN];
		if (getDerivedHDKeyByPath(serialized, kp_full, key_out, true)) {
			printf("getDerivedHDKeyByPath OK\n");
		}

		dogecoin_hdnode_free(copy);
		dogecoin_hdnode_free(n);
	}

	// KOINU CONVERSION
	printf("\n\nBEGIN KOINU CONVERSION:\n\n");
	{
		char coins_str[32];
		koinu_to_coins_str(1234567890ULL, coins_str, sizeof(coins_str));
		printf("1234567890 koinu = %s DOGE\n", coins_str);
		uint64_t k = coins_to_koinu_str("42.5");
		printf("42.5 DOGE = %llu koinu\n", (unsigned long long)k);
	}

	// MEMORY HELPERS
	printf("\n\nBEGIN MEMORY HELPERS:\n\n");
	{
		char* b = dogecoin_char_vla(64);
		unsigned char* ub = dogecoin_uchar_vla(64);
		void* zeros = dogecoin_calloc(4, 16);
		memset(b, 'A', 63); b[63] = '\0';
		dogecoin_mem_zero(b, 64);
		printf("mem_zero first byte: %d\n", b[0]);
		dogecoin_free(b);
		dogecoin_free(ub);
		dogecoin_free(zeros);
	}

	// VECTOR API
	printf("\n\nBEGIN VECTOR API:\n\n");
	{
		vector_t* v = vector_new(4, NULL);
		int a = 1, bv = 2, c = 3, d = 4;
		vector_add(v, &a);
		vector_add(v, &bv);
		vector_add(v, &c);
		vector_add(v, &d);
		printf("vector len=%zu, find(&c)=%zd\n", v->len, vector_find(v, &c));
		vector_remove(v, &a);
		vector_remove_idx(v, 0);
		vector_remove_range(v, 0, 1);
		vector_resize(v, 8);
		printf("after removals len=%zu alloc=%zu\n", v->len, v->alloc);
		vector_free(v, true);
	}

	// RANDOM
	printf("\n\nBEGIN RANDOM:\n\n");
	{
		uint8_t rnd[16];
		if (dogecoin_random_bytes(rnd, sizeof(rnd), 0)) {
			char hex[33];
			utils_bin_to_hex(rnd, sizeof(rnd), hex);
			printf("random: %s\n", hex);
		}
	}

	// CRYPTO DIGESTS
	printf("\n\nBEGIN CRYPTO DIGESTS:\n\n");
	{
		const char* m = "abc";
		size_t ml = strlen(m);
		uint8_t h1[SHA1_DIGEST_LENGTH];
		uint8_t h2[SHA256_DIGEST_LENGTH];
		uint8_t h5[SHA512_DIGEST_LENGTH];
		uint8_t r160[20];
		sha1_Raw((const uint8_t*)m, ml, h1);
		sha256_raw((const uint8_t*)m, ml, h2);
		sha512_raw((const uint8_t*)m, ml, h5);
		rmd160((const uint8_t*)m, ml, r160);
		char buf[129];
		utils_bin_to_hex(h1, SHA1_DIGEST_LENGTH, buf); printf("sha1: %s\n", buf);
		utils_bin_to_hex(h2, SHA256_DIGEST_LENGTH, buf); printf("sha256: %s\n", buf);
		utils_bin_to_hex(h5, SHA512_DIGEST_LENGTH, buf); printf("sha512: %s\n", buf);
		utils_bin_to_hex(r160, 20, buf); printf("rmd160: %s\n", buf);

		uint8_t key[] = "secret";
		uint8_t mac[SHA256_DIGEST_LENGTH];
		hmac_sha1(key, sizeof(key) - 1, (const uint8_t*)m, ml, h1);
		hmac_sha256(key, sizeof(key) - 1, (const uint8_t*)m, ml, mac);
		hmac_sha512(key, sizeof(key) - 1, (const uint8_t*)m, ml, h5);
		utils_bin_to_hex(mac, SHA256_DIGEST_LENGTH, buf); printf("hmac-sha256: %s\n", buf);

		uint8_t derived[32];
		pbkdf2_hmac_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, derived, sizeof(derived));
		utils_bin_to_hex(derived, 32, buf); printf("pbkdf2-sha256: %s\n", buf);
		uint8_t derived512[64];
		pbkdf2_hmac_sha512((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, derived512);
		utils_bin_to_hex(derived512, 64, buf); printf("pbkdf2-sha512: %s\n", buf);
	}

	// BASE58
	printf("\n\nBEGIN BASE58:\n\n");
	{
		const uint8_t payload[] = {0x00, 0x01, 0x02, 0x03, 0x04};
		char b58[64];
		size_t b58sz = sizeof(b58);
		dogecoin_base58_encode(b58, &b58sz, payload, sizeof(payload));
		printf("base58 encoded: %s\n", b58);
		uint8_t dec[16];
		size_t decsz = sizeof(dec);
		dogecoin_base58_decode(dec, &decsz, b58, strlen(b58));
		printf("base58 decoded len=%zu\n", decsz);

		char chk[64];
		size_t chkn = dogecoin_base58_encode_check(payload, sizeof(payload), chk, sizeof(chk));
		printf("base58check (len=%zu): %s\n", chkn, chk);
		uint8_t chkdec[16];
		size_t chkdn = dogecoin_base58_decode_check(chk, chkdec, sizeof(chkdec));
		printf("base58check decoded len=%zu\n", chkdn);
	}

	// TRANSACTION OBJECT API
	printf("\n\nBEGIN TRANSACTION OBJECT API:\n\n");
	{
		dogecoin_tx* tx = dogecoin_tx_new();
		printf("tx is_coinbase (empty): %d\n", dogecoin_tx_is_coinbase(tx));
		dogecoin_tx_add_address_out(tx, &dogecoin_chainparams_main, 100000000, "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS");
		uint8_t fake_hash_buf[SHA256_DIGEST_LENGTH];
		sha256_raw((const uint8_t*)"ph", 2, fake_hash_buf);
		uint160_t h160;
		memcpy(h160, fake_hash_buf, sizeof(h160)); // truncate 32->20 bytes for hash160
		dogecoin_tx_add_p2pkh_hash160_out(tx, 50000000, h160);
		dogecoin_tx_add_p2sh_hash160_out(tx, 25000000, h160);
		const uint8_t data_payload[] = {'h','e','l','l','o'};
		dogecoin_tx_add_data_out(tx, 0, data_payload, sizeof(data_payload));

		uint256_t txh;
		dogecoin_tx_hash(tx, txh);
		char buf[65];
		utils_bin_to_hex(txh, 32, buf);
		printf("tx hash: %s\n", buf);

		dogecoin_tx* tx2 = dogecoin_tx_new();
		dogecoin_tx_copy(tx2, tx);
		dogecoin_tx_free(tx2);
		dogecoin_tx_free(tx);
	}

	// ADVANCED TX BUILDER (buffered / _ex variants)
	printf("\n\nBEGIN ADVANCED TX BUILDER:\n\n");
	{
		int tix = start_transaction();
		add_utxo(tix, "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", 1);
		add_output(tix, "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde", "1.0");
		char fbuf[TXHEXMAXLEN];
		int fr = finalize_transaction_ex(tix, "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde", "0.001", "2", "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde", fbuf, sizeof(fbuf));
		printf("finalize_transaction_ex rc=%d len=%zu\n", fr, strlen(fbuf));

		char getbuf[TXHEXMAXLEN];
		int grc = get_raw_transaction_ex(tix, getbuf, sizeof(getbuf));
		printf("get_raw_transaction_ex rc=%d\n", grc);

		// store / clear
		int idx3 = store_raw_transaction(getbuf);
		printf("store_raw_transaction idx=%d\n", idx3);
		clear_transaction(idx3);

		remove_all();
	}

	// QR ENCODE
	printf("\n\nBEGIN QR ENCODE:\n\n");
	{
		const char* qr_addr = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
		uint8_t qr_bits[4096] = {0};
		int qsize = qrgen_p2pkh_to_qrbits(qr_addr, qr_bits);
		printf("qrgen_p2pkh_to_qrbits size=%d\n", qsize);
		char qr_str[8192];
		qrgen_p2pkh_to_qr_string(qr_addr, qr_str);
		printf("qrgen_p2pkh_to_qr_string length=%zu\n", strlen(qr_str));
	}

	// ECKEY HASH TABLE
	printf("\n\nBEGIN ECKEY HASH TABLE:\n\n");
	{
		eckey* k = new_eckey(false);
		add_eckey(k);
		eckey* found = find_eckey(k->idx);
		printf("eckey idx=%d addr=%s found=%d\n", k->idx, k->address, found != NULL);
		eckey* k2 = new_eckey_from_privkey(k->private_key_wif);
		printf("eckey_from_privkey addr=%s\n", k2->address);
		dogecoin_key_free(k2);
		/* remove_eckey also frees the eckey via dogecoin_key_free */
		remove_eckey(k);
	}

	// SPV CLIENT LIFECYCLE (no network loop)
	printf("\n\nBEGIN SPV CLIENT LIFECYCLE:\n\n");
	{
		dogecoin_spv_client* spv = dogecoin_spv_client_new(&dogecoin_chainparams_test, false, true, true, false, 0, NULL);
		if (spv) {
			printf("spv client created\n");
			dogecoin_spv_enable_smpv(spv, true);
			dogecoin_spv_client_free(spv);
			printf("spv client freed\n");
		}
	}

	// SMPV CLIENT
	printf("\n\nBEGIN SMPV CLIENT:\n\n");
	{
		dogecoin_smpv_client* sc = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
		if (sc) {
			dogecoin_smpv_start(sc);
			const char* watch_addr = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
			dogecoin_smpv_add_watcher(sc, watch_addr);
			dogecoin_smpv_watcher* w = dogecoin_smpv_get_watcher(sc, watch_addr);
			if (w) {
				char* wjson = dogecoin_smpv_watcher_to_json(w);
				if (wjson) { printf("watcher json len=%zu\n", strlen(wjson)); dogecoin_free(wjson); }
			}
			uint32_t tt = 0, wa = 0;
			dogecoin_smpv_get_stats(sc, &tt, &wa);
			printf("smpv stats total_txs=%u watched=%u\n", tt, wa);
			dogecoin_smpv_remove_watcher(sc, watch_addr);
			dogecoin_smpv_stop(sc);
			dogecoin_smpv_client_free(sc);
			printf("smpv client freed\n");
		}
	}

	// MULTISIG P2SH EXAMPLE
	//
	// Demonstrates the offline P2SH redeem-script + address derivation
	// (`get_p2sh_multisig_address`). The cosigner pubkeys below are public
	// information only; no cosigner private keys (WIFs) are bundled with the
	// example. To actually spend a P2SH-multisig UTXO, call
	// `sign_indexed_raw_transaction_ex(txindex, 0, redeem_script_hex,
	//                                  SIGHASH_ALL, cosigner_wif, buf, cap)`
	// once per cosigner — feeding each returned hex back in as the next call's
	// transaction. See doc/transaction_extended.md for the full M-of-N
	// signing recipe.
	printf("\n\nBEGIN MULTISIG P2SH EXAMPLE:\n\n");

	// Known 2-of-3 cosigner pubkeys (public, reproducible values).
	const char* ms_pubs[3] = {
		"03f59f55e1237358524f59ec304d560b384c35101bc0c830fe0f0734b16c1f2f27",
		"038abd7a75751f046aca1c72fb1eb02af0088ef5832db0c703f9a7d4973958eaa2",
		"0262bed3c8c9b168a72915da0ef3b4712d0346367575d10b1c6816c78325f31c85",
	};

	// 1. Derive the 2-of-3 P2SH address and redeem script from the ordered pubkeys.
	char ms_p2sh_addr[P2PKHLEN];
	char ms_redeem_hex[1200]; // safe for up to 15-of-15
	if (!get_p2sh_multisig_address(ms_pubs, 3, 2, 0 /* mainnet */,
	                                ms_p2sh_addr, sizeof(ms_p2sh_addr),
	                                ms_redeem_hex, sizeof(ms_redeem_hex))) {
		printf("Failed to derive multisig P2SH address.\n");
		return -1;
	}

	printf("2-of-3 redeem script: %s\n", ms_redeem_hex);
	printf("2-of-3 P2SH address:  %s\n", ms_p2sh_addr);

	// 2. Sanity check: the derived address must match the address that would be
	// computed by hash160-then-base58check of the same redeem script (this is
	// just a self-consistency check — no funds are touched).
	{
		const char expected_mainnet_p2sh[] = "A4WG8CySzTzVYNssp2iKf8eXmDzRwPrSWA";
		if (strcmp(ms_p2sh_addr, expected_mainnet_p2sh) != 0) {
			printf("P2SH address %s does not match expected derivation %s.\n",
			        ms_p2sh_addr, expected_mainnet_p2sh);
			return -1;
		}
		printf("P2SH address derivation matches expected value.\n");
	}
	printf("Multisig P2SH derivation OK.\n");
	// END ===========================================



	// PSBT (BIP174) EXAMPLE
	printf("\n\nBEGIN PSBT (BIP174) EXAMPLE:\n\n");
	{
		// 1. Generate a fresh EC keypair that will act as the signer.
		dogecoin_key psbt_priv;
		dogecoin_privkey_init(&psbt_priv);
		if (!dogecoin_privkey_gen(&psbt_priv)) {
			printf("Error: psbt privkey_gen failed.\n");
			return -1;
		}
		dogecoin_pubkey psbt_pub;
		dogecoin_pubkey_init(&psbt_pub);
		psbt_pub.compressed = true;
		dogecoin_pubkey_from_key(&psbt_priv, &psbt_pub);
		char psbt_addr[P2PKHLEN];
		dogecoin_pubkey_getaddr_p2pkh(&psbt_pub, &dogecoin_chainparams_main, psbt_addr);
		printf("Signer address: %s\n", psbt_addr);

		// 2. Build the "previous tx" (the UTXO being spent):
		//    a single P2PKH output of 10 DOGE to the signer address.
		dogecoin_tx* psbt_prev_tx = dogecoin_tx_new();
		dogecoin_tx_add_address_out(psbt_prev_tx, &dogecoin_chainparams_main, 1000000000LL, psbt_addr);

		// 3. Build an unsigned spending tx via the transaction builder.
		//    vout=0 makes the input reference prev_tx output at index 0.
		//    Compute the real txid of psbt_prev_tx so the PSBT signer can verify
		//    the UTXO hash matches the input being signed.
		//    dogecoin_tx_hash returns raw bytes; add_utxo (via utils_uint256_sethex)
		//    expects the display/explorer format where bytes are reversed, so reverse
		//    before converting to hex.
		uint256_t psbt_prev_txid_raw;
		dogecoin_tx_hash(psbt_prev_tx, psbt_prev_txid_raw);
		uint8_t psbt_prev_txid_rev[32];
		for (int psbt_ri = 0; psbt_ri < 32; psbt_ri++)
			psbt_prev_txid_rev[psbt_ri] = psbt_prev_txid_raw[31 - psbt_ri];
		char psbt_real_txid[65];
		utils_bin_to_hex(psbt_prev_txid_rev, 32, psbt_real_txid);
		char psbt_dest[] = "D6a52RGbfvKDzKTh8carkGd1vNdAurHmaS";
		int psbt_tix = start_transaction();
		add_utxo(psbt_tix, psbt_real_txid, 0);
		add_output(psbt_tix, psbt_dest, "9.9");
		char* psbt_unsigned_hex = finalize_transaction(psbt_tix, psbt_dest, "0.1", "10", psbt_addr);
		if (!psbt_unsigned_hex) {
			printf("Error: finalize_transaction failed for PSBT example.\n");
			dogecoin_tx_free(psbt_prev_tx);
			dogecoin_pubkey_cleanse(&psbt_pub);
			dogecoin_privkey_cleanse(&psbt_priv);
			remove_all();
			return -1;
		}

		// 4. Deserialize the unsigned hex into a dogecoin_tx object.
		size_t psbt_hlen = strlen(psbt_unsigned_hex);
		unsigned char* psbt_ubuf = dogecoin_uchar_vla(psbt_hlen / 2 + 1);
		size_t psbt_ulen = 0;
		utils_hex_to_bin(psbt_unsigned_hex, psbt_ubuf, psbt_hlen, &psbt_ulen);
		dogecoin_tx* psbt_spend_tx = dogecoin_tx_new();
		dogecoin_tx_deserialize(psbt_ubuf, psbt_ulen, psbt_spend_tx, NULL);
		dogecoin_free(psbt_ubuf);
		remove_all();

		// 5. Creator role: wrap the unsigned tx in a PSBT.
		dogecoin_psbt* psbt = dogecoin_psbt_create(psbt_spend_tx);
		dogecoin_tx_free(psbt_spend_tx);
		if (!psbt) {
			printf("Error: dogecoin_psbt_create failed.\n");
			dogecoin_tx_free(psbt_prev_tx);
			dogecoin_pubkey_cleanse(&psbt_pub);
			dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		printf("PSBT created (BIP174 creator role).\n");

		// 6. Serialize to hex and base64 for transport / storage.
		char* psbt_hex = dogecoin_psbt_to_hex(psbt);
		char* psbt_b64 = dogecoin_psbt_to_base64(psbt);
		printf("PSBT hex    (%zu chars): %s\n", strlen(psbt_hex), psbt_hex);
		printf("PSBT base64 (%zu chars): %s\n", strlen(psbt_b64), psbt_b64);

		// 7. Round-trip: deserialize from hex and verify the re-serialized output matches.
		dogecoin_psbt* psbt_rt = NULL;
		if (!dogecoin_psbt_from_hex(psbt_hex, &psbt_rt)) {
			printf("Error: psbt hex round-trip deserialize failed.\n");
			dogecoin_free(psbt_hex); dogecoin_free(psbt_b64);
			dogecoin_psbt_free(psbt);
			dogecoin_tx_free(psbt_prev_tx);
			dogecoin_pubkey_cleanse(&psbt_pub); dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		char* psbt_rt_hex = dogecoin_psbt_to_hex(psbt_rt);
		if (strcmp(psbt_hex, psbt_rt_hex) != 0) {
			printf("Error: PSBT hex round-trip mismatch.\n");
			dogecoin_free(psbt_hex); dogecoin_free(psbt_b64); dogecoin_free(psbt_rt_hex);
			dogecoin_psbt_free(psbt); dogecoin_psbt_free(psbt_rt);
			dogecoin_tx_free(psbt_prev_tx);
			dogecoin_pubkey_cleanse(&psbt_pub); dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		printf("PSBT hex round-trip OK.\n");
		dogecoin_free(psbt_rt_hex);
		dogecoin_psbt_free(psbt_rt);
		dogecoin_free(psbt_hex);
		dogecoin_free(psbt_b64);

		// 8. Updater role: attach the full previous tx so the signer can derive the
		//    sighash and verify the P2PKH scriptPubKey.
		dogecoin_psbt_input_set_utxo(psbt, 0, psbt_prev_tx);
		dogecoin_tx_free(psbt_prev_tx);
		printf("PSBT updater: UTXO attached to input 0.\n");

		// 9. Signer role: add partial signatures for all inputs we can sign.
		if (!dogecoin_psbt_sign(psbt, &psbt_priv)) {
			printf("Error: dogecoin_psbt_sign failed.\n");
			dogecoin_psbt_free(psbt);
			dogecoin_pubkey_cleanse(&psbt_pub); dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		printf("PSBT signer: input 0 signed.\n");

		// 10. Finalizer role: build final_script_sig for each signed input.
		if (!dogecoin_psbt_finalize(psbt)) {
			printf("Error: dogecoin_psbt_finalize failed.\n");
			dogecoin_psbt_free(psbt);
			dogecoin_pubkey_cleanse(&psbt_pub); dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		printf("PSBT finalizer: all inputs finalized.\n");

		// 11. Extractor role: produce the fully-signed transaction.
		dogecoin_tx* psbt_signed = dogecoin_psbt_extract(psbt);
		if (!psbt_signed) {
			printf("Error: dogecoin_psbt_extract failed.\n");
			dogecoin_psbt_free(psbt);
			dogecoin_pubkey_cleanse(&psbt_pub); dogecoin_privkey_cleanse(&psbt_priv);
			return -1;
		}
		uint256_t psbt_txhash;
		dogecoin_tx_hash(psbt_signed, psbt_txhash);
		char psbt_txhash_hex[65];
		utils_bin_to_hex(psbt_txhash, 32, psbt_txhash_hex);
		printf("Extracted signed tx hash: %s\n", psbt_txhash_hex);
		dogecoin_tx_free(psbt_signed);
		dogecoin_psbt_free(psbt);
		dogecoin_pubkey_cleanse(&psbt_pub);
		dogecoin_privkey_cleanse(&psbt_priv);
		printf("PSBT example complete.\n");
	}
	// END ===========================================


	printf("\nTESTS COMPLETE!\n");
	dogecoin_ecc_stop();
}
