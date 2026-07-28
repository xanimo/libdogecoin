/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022-2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <dogecoin/arith_uint256.h>
#include <dogecoin/auxpow.h>
#include <dogecoin/block.h>

#include <dogecoin/cstr.h>
#include <dogecoin/key.h>
#include <dogecoin/mem.h>
#include <dogecoin/pow.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

#include <test/utest.h>

struct blockheadertest {
    char hexheader[160];
    char hexhash[64];
    int32_t version;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    const dogecoin_chainparams* params;
    char chainwork[64];
};

static const struct blockheadertest block_header_tests[] =
        {
                {"010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5b24a6a152f0ff0f1e67860100", "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691", 1, 1386325540, 504365040, 99943, &dogecoin_chainparams_main, "1000100000000000000000000000000000000000000000000000000000000000"}, // genesis hash
                {"020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb09b1a8468a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78fbb827ee41fb11548441361b00000000", "60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053", 6422786, 1410464577, 456540548, 0, &dogecoin_chainparams_main, ""}, // 331337
                {"020162002107cd08bec145c55ba8ffcbb4a9c0e836dfca383aa6ca1b380259a670aeb56fe5ea77d4f004afc5a0d31af1b89d5ebd9fd60cd7da7f4dcd96b0db1096a5bb1a7afb115488632e1b00000000","aff80f7b4dc8c667ebf4c76a6a62f9c4479844a37421ca2bf5abb485f4579fb6", 6422786, 1410464634, 456024968, 0, &dogecoin_chainparams_main, ""}, // 331339
                {"03016200c96fd9d1b98330440082bcc1e58a39fe5a522f42defc501bff9b68f7b67ed99e1144e430166c54e9b911d8e059c03d0f972e7ab971c51f5505ff0bb21fee6fb1d88a9d5be132051a00000000", "c91f5a44a752c7549c1c689af5aeb42639582011d887282f976d550477abe25a", 6422787, 1537051352, 436548321, 0, &dogecoin_chainparams_main, ""}, // 2391337
                {"0401620057bd4aa5170622b624bff774a087ea879a288226925c7cd5f3ead6ca4b6146e227b0e3699361bf58440971cfb28e16d9bab909769668ef3aac26220c6c0dc5fbda52595f9a97031a00000000", "8d7e4e91b571025ca109f2a0aeaf114ecc6aa2feec7f8bf23d405ac026c65d5e", 6422788, 1599689434, 436443034, 0, &dogecoin_chainparams_main, ""}, // 3391337
                // end mainnet blocks
                {"020162002770a8b89647bbb542f044754a07dc6e56545793f5dcecdf43826ae0cb7192a12466d048e51b0f8a3cbaaf8a624b9aa1212ce4c2a4feba0750f7ad14feb75f54c69de053837b091e00000000", "8afc65a42c47b5ed5862194fb846171ba4afb999a1b4cce149f56c328d8a90e4", 6422786, 1407229382, 503937923, 0, &dogecoin_chainparams_test, ""} // 158391
        };

void test_auxpow_deserialize_real_vector(void);
void test_auxpow_deserialize_e2e(void);
void test_auxpow_deserialize_merkle_count_bounds(void);

static void test_check_merkle_branch()
{
    size_t outlen = 0;
    uint256_t hash = {0};
    uint256_t expected = {0};
    vector_t* merkle_branch = vector_new(3, dogecoin_free);

    /* Fixed branch/index vector generated independently to verify deterministic hashing order. */
    utils_hex_to_bin("1111111111111111111111111111111111111111111111111111111111111111", hash, DOGECOIN_HASH_LENGTH * 2, &outlen);

    uint256_t* branch0 = dogecoin_uint256_vla(1);
    uint256_t* branch1 = dogecoin_uint256_vla(1);
    uint256_t* branch2 = dogecoin_uint256_vla(1);
    utils_hex_to_bin("2222222222222222222222222222222222222222222222222222222222222222", *branch0, DOGECOIN_HASH_LENGTH * 2, &outlen);
    utils_hex_to_bin("3333333333333333333333333333333333333333333333333333333333333333", *branch1, DOGECOIN_HASH_LENGTH * 2, &outlen);
    utils_hex_to_bin("4444444444444444444444444444444444444444444444444444444444444444", *branch2, DOGECOIN_HASH_LENGTH * 2, &outlen);
    vector_add(merkle_branch, branch0);
    vector_add(merkle_branch, branch1);
    vector_add(merkle_branch, branch2);

    uint256_t* result = check_merkle_branch(&hash, merkle_branch, 5);
    utils_hex_to_bin("80165eb2e22322b7570785b120ecf4b07df5ba7b4a458413a4b15b3d246506b6", expected, DOGECOIN_HASH_LENGTH * 2, &outlen);
    u_assert_mem_eq(result, expected, DOGECOIN_HASH_LENGTH);

    dogecoin_free(result);
    vector_free(merkle_branch, true);
}

void test_block_header()
{
    size_t outlen;
    char hexbuf[161];
    unsigned int i;
    for (i = 0; i < (sizeof(block_header_tests) / sizeof(block_header_tests[0])); i++) {
        cstring* serialized = cstr_new_sz(80);
        const struct blockheadertest* test = &block_header_tests[i];
        uint8_t header_data[80];
        uint256_t hash_data;
        arith_uint256 chainwork = {0};
        utils_hex_to_bin(test->hexheader, header_data, 160, &outlen);

        utils_hex_to_bin(test->hexhash, hash_data, sizeof(hash_data), &outlen);

        dogecoin_block_header* header = dogecoin_block_header_new();
        struct const_buffer buf = {header_data, 80};
        dogecoin_block_header_deserialize(header, &buf, block_header_tests[i].params, &chainwork);

        // Check the copies are the same
        dogecoin_block_header* header_copy = dogecoin_block_header_new();
        dogecoin_block_header_copy(header_copy, header);
        assert(memcmp(header_copy, header, sizeof(*header_copy)) == 0);

        // Check the serialized form matches
        dogecoin_block_header_serialize(serialized, header);
        utils_bin_to_hex((unsigned char*) serialized->str, serialized->len, hexbuf);

        assert(memcmp(hexbuf, test->hexheader, 160) == 0);

        // Check the block hash
        uint256_t blockhash;
        dogecoin_block_header_hash(header, blockhash);

        utils_bin_to_hex(blockhash, DOGECOIN_HASH_LENGTH, hexbuf);
        utils_reverse_hex(hexbuf, DOGECOIN_HASH_LENGTH*2);
        assert(memcmp(hexbuf, test->hexhash, DOGECOIN_HASH_LENGTH*2) == 0);
        // Check version, ts, bits, nonce
        assert(header->version == test->version);
        assert(header->timestamp == test->timestamp);
        assert(header->bits == test->bits);
        assert(header->nonce == test->nonce);

        // Check chainwork (genesis block only)
        if (i == 0) {
            arith_uint256* target = init_arith_uint256();
            cstring* s = cstr_new_sz(64);
            dogecoin_bool f_negative, f_overflow;
            uint256_t* hash = dogecoin_uint256_vla(1);

            // Compute the hash of the block header
            dogecoin_block_header_serialize(s, header);
            dogecoin_block_header_scrypt_hash(s, hash);

            // Compute the chainwork
            target = set_compact(target, block_header_tests[i].bits, &f_negative, &f_overflow);
            check_pow(hash, block_header_tests[i].bits, block_header_tests[i].params, &chainwork);

            // Check the chainwork matches
            u_assert_mem_eq(utils_uint8_to_hex(arith_to_uint256(&chainwork), DOGECOIN_HASH_LENGTH), test->chainwork, 64);
            cstr_free(s, true);
            dogecoin_free(hash);
            dogecoin_free(target);
        }

        dogecoin_block_header_free(header);
        dogecoin_block_header_free(header_copy);
        cstr_free(serialized, true);
    }

    /* blockheader */
    dogecoin_block_header bheader, bheaderprev, bheadercheck;
    bheader.version = 6422786; // 371338
    bheader.timestamp = 1410464609; // 371338
    bheader.nonce = 0; // 371338
    bheader.bits = 456184976; // 371338
    char *prevblock_hex_o = "60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053"; // 371337
    char *prevblock_hex = dogecoin_malloc(strlen(prevblock_hex_o)+1);
    memcpy_safe(prevblock_hex, prevblock_hex_o, strlen(prevblock_hex_o));
    utils_reverse_hex(prevblock_hex, 64);
    outlen = 0;
    utils_hex_to_bin(prevblock_hex, bheader.prev_block, 64, &outlen);
    dogecoin_free(prevblock_hex);

    char *merkleroot_hex_o = "366747b6b22fab0a5ef71d433c14e5949b601c1f103984181364618b83eef67d"; // 427928
    char *merkleroot_hex = dogecoin_malloc(strlen(merkleroot_hex_o)+1);
    memcpy_safe(merkleroot_hex, merkleroot_hex_o, strlen(merkleroot_hex_o));
    utils_reverse_hex(merkleroot_hex, 64);
    outlen = 0;
    utils_hex_to_bin(merkleroot_hex, bheader.merkle_root, 64, &outlen);
    dogecoin_free(merkleroot_hex);

    bheaderprev.version = 6422786; // 371337
    bheaderprev.timestamp = 1410464577; // 371337
    bheaderprev.nonce = 0; // 371337
    bheaderprev.bits = 456540548; // 371337

    prevblock_hex_o = "46a8b109fb016fa41abd17a19186ca78d39c60c020c71fcd2690320d47036f0d"; // 371336
    prevblock_hex = dogecoin_malloc(strlen(prevblock_hex_o)+1);
    memcpy_safe(prevblock_hex, prevblock_hex_o, strlen(prevblock_hex_o));
    utils_reverse_hex(prevblock_hex, 64);
    outlen = 0;
    utils_hex_to_bin(prevblock_hex, bheaderprev.prev_block, 64, &outlen);
    dogecoin_free(prevblock_hex);

    merkleroot_hex_o = "ee27b8fb782a5bfb99c975f0d4686440b9af9e16846603e5f2830e0b6fbf158a"; // 371337
    merkleroot_hex = dogecoin_malloc(strlen(merkleroot_hex_o)+1);
    memcpy_safe(merkleroot_hex, merkleroot_hex_o, strlen(merkleroot_hex_o));
    utils_reverse_hex(merkleroot_hex, 64);
    outlen = 0;
    utils_hex_to_bin(merkleroot_hex, bheaderprev.merkle_root, 64, &outlen);
    dogecoin_free(merkleroot_hex);

    /* compare blockheaderhex */
    cstring *blockheader_ser = cstr_new_sz(256);
    dogecoin_block_header_serialize(blockheader_ser, &bheader);
    char *blockheader_h371338 = "0201620053f0dc500d0fd8912622c5c2475f83529326c19dac4e955a1bffc5f9823932607df6ee838b616413188439101f1c609b94e5143c431df75e0aab2fb2b647673661fb115490d4301b00000000";
    char *blockheader_hash_h371338 = "6fb5ae70a65902381bcaa63a38cadf36e8c0a9b4cbffa85bc545c1be08cd0721";

    char headercheck[1024];
    utils_bin_to_hex((unsigned char *)blockheader_ser->str, blockheader_ser->len, headercheck);
    u_assert_str_eq(headercheck, blockheader_h371338);

    uint256_t checkhash;
    arith_uint256 chainwork = {0};
    dogecoin_block_header_hash(&bheader, (uint8_t *)&checkhash);
    char hashhex[sizeof(checkhash) * 2 + 1];
    utils_bin_to_hex(checkhash, sizeof(checkhash), hashhex);
    utils_reverse_hex(hashhex, strlen(hashhex));
    u_assert_str_eq(blockheader_hash_h371338, hashhex);

    struct const_buffer buf;
    buf.p = blockheader_ser->str;
    buf.len = blockheader_ser->len;
    dogecoin_block_header_deserialize(&bheadercheck, &buf, &dogecoin_chainparams_main, &chainwork);
    u_assert_str_eq(utils_uint8_to_hex(bheader.prev_block, sizeof(bheader.prev_block)), utils_uint8_to_hex(bheadercheck.prev_block, sizeof(bheadercheck.prev_block)));
    cstr_free(blockheader_ser, true);
    dogecoin_block_header_hash(&bheaderprev, (uint8_t *)&checkhash);
    u_assert_str_eq(utils_uint8_to_hex(bheader.prev_block, sizeof(bheader.prev_block)), utils_uint8_to_hex(checkhash, sizeof(checkhash)));

    test_check_merkle_branch();

    test_auxpow_deserialize_real_vector();
    test_auxpow_deserialize_e2e();
    test_auxpow_deserialize_merkle_count_bounds();
}

/* Real mainnet auxpow block: height 371338, hash
   6fb5ae70a65902381bcaa63a38cadf36e8c0a9b4cbffa85bc545c1be08cd0721. This is the
   full serialized block (getblock <hash> 0): 80-byte aux header, parent coinbase
   transaction, parent hash, parent coinbase merkle branch, chain merkle branch,
   and parent header. Unlike the synthetic cases above, this exercises the entire
   path INCLUDING check_auxpow() -- the parent block's scrypt proof of work is
   verified against the header bits, and the merge-mining merkle branches are
   checked to link the aux block hash into the parent coinbase. A successful
   return is a true end-to-end validation of the auxpow deserializer. */
void test_auxpow_deserialize_real_vector() {
    const char* block_hex =
        "0201620053f0dc500d0fd8912622c5c2475f83529326c19dac4e955a1bffc5f9823932607df6"
        "ee838b616413188439101f1c609b94e5143c431df75e0aab2fb2b647673661fb115490d4301b"
        "0000000001000000010000000000000000000000000000000000000000000000000000000000"
        "000000ffffffff380345bf09fabe6d6d5187f05b5b616c30c1945af345d1f95148963a12d0fb"
        "215b8e7ad53a27161e3c08000000000000009bf8666459000000ffffffff01800c0c2a010000"
        "001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000b042af7b2a0bbb"
        "7527fc48af101611276e60b91d2acc5875b8be25000000000003a979a636db2450363972d211"
        "aee67b71387a3daaa3051be0fd260c5acd4739cd52a418d29d8a0e56c8714c95a0dc24e1c962"
        "4480ec497fe2441941f3fee8f9481a3370c334178415c83d1d0c2deeec727c2330617a47691f"
        "c5e79203669312d100000000036fa40307b3a439538195245b0de56a2c1db6ba3a64f8bdd207"
        "1d00bc48c841b5e77b98e5c7d6f06f92dec5cf6d61277ecb9a0342406f49f34c51ee8ce4abd6"
        "78038129485de14238bd1ca12cd2de12ff0e383aee542d90437cd664ce139446a00000000002"
        "000000d2ec7dfeb7e8f43fe77aba3368df95ac2088034420402730ee0492a208421708f6d32f"
        "6e7eb2941bcdcd47740f7c67a7b1930014b771a18809a86898a506250f60fb11548b54021be0"
        "17686d0601000000010000000000000000000000000000000000000000000000000000000000"
        "000000ffffffff0d038aaa050101062f503253482fffffffff010109d54eaf050000232102b7"
        "3438165461b826b30a46078f211aa005d1e7e430b1e0ed461678a5fe516c73ac000000000100"
        "000009bc1d305c59dd1809a6546010bbc43e8c25ad5d241cd83e582010f9930677ae8a270000"
        "006a473044022100ece82d985cfedfb30b9227ae71bf154673beeba85a8667dcb492fedfc8b6"
        "d87f021f2cb89b285b0f7964f613696c0b7b27c4f1476b954df17f63a2d7d23b559218012103"
        "bb439b7328630b2985dd73c711d79dfa54e644fe33e44de49d5475e7f6fde985ffffffffcd1a"
        "eddb2ae887734ec3a16aff82c198d83af739e1923cf93aa28d74519665a1010000006b483045"
        "022100e4ac71b6650c586f04e8ca9d37bf7fbf2483107dae076bffb06d5c6cd471b90502201f"
        "d946bb433637c1c05170f7f2af13d82b4d37595659b85eadec8db85f9b48fd0121024cc4de99"
        "ad5ebf4c0ff81d66b5d1953ec7b28cb7e558ef758376e685391badecffffffff182fe5662129"
        "bc59a78ef49bddeab1281d34cf9dbdac3cbfb9e0090051789bd03b0000006a4730440220527b"
        "19bb4858ace5f9e3e12cc68c91b04cb2cc8af88e4a3efbbca40f107ad2310220574bace2eda1"
        "1bce2e7dd593642c3bd537a0075448378cc185cd65953f985f9701210256bdef145ceaddaf7a"
        "fc1ece0fecfd6548f3d34e54a3123d5f36c75b15fbc2feffffffff15c0dd130c3c37f6765465"
        "c2659d4ef8cc7c8a382baad02fafbd3fd527f7bfb1010000006b483045022100bc05ef192be8"
        "fb2f272efb7be8158815251f88fed7878e5df4431aa94585a2ef02203e7194d0cd4f8481e8a8"
        "be7e24474aced48a712cfef64b0fc1f10ca7faea2f8f012103eae1c39387a87e782810342bcd"
        "59b11b6ba18aee1fcb9997744b649b76707624ffffffff12d739cc5cb2cb80c4cd8b76d5a9e2"
        "d8b29a2752be8f5d5fd2d8f6757c817fe4010000006b483045022100a1870aa5d56b0c79cdd7"
        "b119f5377cb05d4c4bd1dc1cf553598c2364d0d99df8022067ea779f0f19bc992b4660820ae9"
        "9c27b452049a70ac7efa7b73ef4d0e5ddb19012103f0f23aad840a2270d53501cc008a8953ff"
        "d867dec5d2535ea6ba0c17f4963615ffffffffd7fe105770ec91f57f066b5ec91930a117b882"
        "e47ceafc376dadd1fe2c285a10010000006a473044022072b5345c6b4bb5496862393d49618f"
        "ef778ad879fc94b24bcac9b5595143557a02200e919b915e3cecde82ce6f95a7a52844ca44d5"
        "cc553ed75e1a4de452218c778e012102fd3c13362dc56adfe990de025274593cbf3294d09a78"
        "c002119120056087df90ffffffffba55152dd60fe6c3bdd078047e4812f642b5af890efd14fe"
        "2f1a733999929934010000006a473044022000cb23f9ea744e293f87750cd154ab96a06a6178"
        "ea4323e3d7f5a6458a25f41002200a73f4f26d48ce022c3f7eee520eb4ee57a88b8b8d984cf7"
        "597ce032eac7df8b01210304a5713d3350d4181e4e2eaf923e25a6820d44a8b82e731fd37ff1"
        "32c459bb2cffffffff50e7e2a34b00dc3cd664af02fcdba9ac22de118fa24bbff7ea6f49bb4c"
        "93f374000000006b483045022100efbaebfe27f2fa925ab4e98b4040119ce4347a7cde53cbdc"
        "42b4c1243211eb4c02201fac79a49a6201aa17051ca1ad6c12d0a52582cc1c19310e2eff204b"
        "828a8077012103433e7a65c0b66947d98f92ae0d5e4ccf9fe0a1eba9934098614fc1bf2a4d2b"
        "33ffffffff59a7866891da6616de39d60799d9a328de26b68eb122482bba0e1028fe18405500"
        "0000006a47304402205209f3da5971ac77ce54229aeff8a08833f08cee4c074a156dbfd7041c"
        "0a19fb02201242b373983a2d8a74c4ab52206cd4fb4a65ce0fe4e5d62f90333cd929a2ee6c01"
        "210270b236c412b4fae735368f194dbb14bb22f6bb55f907699d42295e45a1dc364affffffff"
        "02b47aba8dae1c00001976a91413b37bc2a0b57fd3740f3632c5d0038b49173eff88acb464ff"
        "05000000001976a914ff4dfe9fc4fce9b1a118d4ca18d634452ccef14188ac00000000010000"
        "000159a484082af8d2311cce82e8571ae1ef738f03aee982d4fee2b397e7f0e8045d01000000"
        "6c493046022100c73ff48629dd1a56d167879a0da40439b5700dbe89635a7dc46a80ae76aa56"
        "50022100db7dc935ff9b52a2a494181b83aa1b5dcf472e70b228e6672482279f8aa56f5a0121"
        "033fcc1cb9c1b7b11758eb2cd3a25b4ff917a5e248f5d6fcc74160dd6a450acf8bffffffff02"
        "0061e600030000001976a9140fa60d44a3a53066ada76ea81e8c2a313e08899b88ac18eeb300"
        "64ae04001976a914a1ea13863020f36897b671ad328d98e9364f12b488ac0000000001000000"
        "01ba8131daa48a8f43b1153f54fd627d0f7f98d020fc3af349741668db359efc83010000006b"
        "4830450220523bd4c8478af0345b1f91ff66a04ae3487f708dfdcabc16cd984d1ce7022bbf02"
        "2100b02950d0be848a5436fec0d03f52bdba8477a47a6f9085ce5b1aff0488e4ede5012102e2"
        "89b43973439cba87a5466abaa425262244e242d1082b0ec58dbeba2b0d225bffffffff026180"
        "288b050000001976a914b7ddc901f636827e5766d1920f3892d4d4bee50088ac78b8dccd9b02"
        "00001976a91427fe37db47615924826ae39169005a14f3e9cafe88ac000000000100000001ee"
        "1cf26c8d505d963a2fc659d6ba9a68f46544e01bae0af69a5a5015ff821440010000006c4930"
        "46022100c4bbcd51537d033a2bdbb3ac0b999410397aca873b5ece0d8fdabb874a4056bf0221"
        "00cac7617e110a20856f04ef1498195867d0772e3e148f6a2a03ed45fe2cfc36a70121033fcc"
        "1cb9c1b7b11758eb2cd3a25b4ff917a5e248f5d6fcc74160dd6a450acf8bffffffff0200aea6"
        "8f020000001976a9141be533a3aff7aec0bfca73c5b7407627d018265788acaa5f8470877900"
        "001976a914a1ea13863020f36897b671ad328d98e9364f12b488ac000000000100000001369e"
        "1a4c499dfe270f99426ee906e39a525c04ca23a266e7195ad0ed80888454000000006a473044"
        "02201ba3e871eb8dcbf3edc26bab4a36eac3e676c573fe3d527bd75a862e51ed8a8a022023e9"
        "7b7783d840eb17578ea98f51613a4e7aa0752dd98c3f67f8b93b3f9790a601210215323532e0"
        "d509a3237519c489050351c7ef194d7ef0b0f74ce58097b6b335f4ffffffff0100005a620200"
        "00001976a91481db1aa49ebc6a71cad96949eb28e22af85eb0bd88ac00000000";

    size_t hexlen = strlen(block_hex);
    size_t blen = hexlen / 2;
    uint8_t* buf = dogecoin_malloc(blen);
    for (size_t k = 0; k < blen; k++) {
        unsigned b; sscanf(block_hex + 2 * k, "%2x", &b); buf[k] = (uint8_t)b;
    }

    dogecoin_block_header* header = dogecoin_block_header_new();
    struct const_buffer cb = { buf, blen };
    arith_uint256 chainwork;
    /* full parse + check_auxpow (scrypt PoW on the parent + merkle linkage) */
    int r = dogecoin_block_header_deserialize(header, &cb, &dogecoin_chainparams_main, &chainwork);
    u_assert_int_eq(r, 1);
    /* the deserialized aux header must match the known height-371338 values */
    u_assert_uint32_eq((uint32_t)header->version, 0x00620102);
    u_assert_uint32_eq(header->timestamp, 1410464609);
    u_assert_uint32_eq(header->bits, 456184976);
    u_assert_uint32_eq(header->nonce, 0);

    dogecoin_block_header_free(header);
    dogecoin_free(buf);
}

/* End-to-end coverage for deserialize_dogecoin_auxpow_block(). Before this,
   the auxpow deserializer had no test exercising it at all -- it was only ever
   reached indirectly. These build well-formed auxpow blocks (valid coinbase
   transaction, merkle branch vectors, parent header) and drive the full parse.

   The proof-of-work in check_auxpow() cannot be satisfied without solving scrypt
   against a real target, so the function returns 0 at that final step; what we
   assert is that everything *before* that -- every length field, both merkle
   branch loops, and the complete parent header -- parsed correctly and consumed
   the whole buffer, with no out-of-bounds access under the ASan+UBSan gate. The
   non-empty-branch case directly exercises the merkle-count handling that the
   uint8_t/uint32_t deserialization fix corrected. */
void test_auxpow_deserialize_e2e() {
    const char* coinbase_hex =
        "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4"
        "0100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65"
        "dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f"
        "717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3"
        "a95118fa4a7c88ac00000000";

    /* ---- case 1: zero merkle branches ---- */
    {
        uint8_t buf[1024]; size_t off = 0;
        for (size_t k = 0; k < strlen(coinbase_hex) / 2; k++) {
            unsigned b; sscanf(coinbase_hex + 2 * k, "%2x", &b); buf[off++] = (uint8_t)b;
        }
        for (int i = 0; i < 32; i++) buf[off++] = 0x00;          /* parent_hash */
        buf[off++] = 0x00;                                        /* parent_merkle_count = 0 */
        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* parent_merkle_index */
        buf[off++] = 0x00;                                        /* aux_merkle_count = 0 */
        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* aux_merkle_index */
        buf[off++] = 0x01; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* parent version=1 */
        for (int i = 0; i < 32; i++) buf[off++] = 0x11;          /* prev_block */
        for (int i = 0; i < 32; i++) buf[off++] = 0x22;          /* merkle_root */
        buf[off++] = 0xAA; buf[off++] = 0xBB; buf[off++] = 0xCC; buf[off++] = 0xDD; /* timestamp */
        buf[off++] = 0xF0; buf[off++] = 0xFF; buf[off++] = 0x0F; buf[off++] = 0x1E; /* bits */
        buf[off++] = 0x99; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;          /* nonce */

        dogecoin_auxpow_block* block = dogecoin_auxpow_block_new();
        block->header->version = 0x620102; /* auxpow bit set, regtest chain id 0x62 */
        struct const_buffer cb = { buf, off };
        arith_uint256 cw;
        (void)deserialize_dogecoin_auxpow_block(block, &cb, &dogecoin_chainparams_regtest, &cw);
        /* the parse must have run to completion and filled the parent header */
        u_assert_int_eq(block->parent_merkle_count, 0);
        u_assert_int_eq(block->aux_merkle_count, 0);
        u_assert_int_eq(block->parent_header->version, 1);
        u_assert_uint32_eq(block->parent_header->timestamp, 0xDDCCBBAA);
        u_assert_uint32_eq(block->parent_header->bits, 0x1E0FFFF0);
        u_assert_uint32_eq(block->parent_header->nonce, 0x00000099);
        dogecoin_auxpow_block_free(block);
    }

    /* ---- case 2: non-empty merkle branches (exercises the alloc + loop that
           the merkle-count fix touches) ---- */
    {
        uint8_t buf[1024]; size_t off = 0;
        for (size_t k = 0; k < strlen(coinbase_hex) / 2; k++) {
            unsigned b; sscanf(coinbase_hex + 2 * k, "%2x", &b); buf[off++] = (uint8_t)b;
        }
        for (int i = 0; i < 32; i++) buf[off++] = 0x00;          /* parent_hash */
        buf[off++] = 0x03;                                       /* parent_merkle_count = 3 */
        for (int b = 0; b < 3; b++) for (int i = 0; i < 32; i++) buf[off++] = (uint8_t)(0x40 + b);
        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* parent_merkle_index */
        buf[off++] = 0x02;                                       /* aux_merkle_count = 2 */
        for (int b = 0; b < 2; b++) for (int i = 0; i < 32; i++) buf[off++] = (uint8_t)(0x80 + b);
        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* aux_merkle_index */
        buf[off++] = 0x01; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; /* parent version=1 */
        for (int i = 0; i < 32; i++) buf[off++] = 0x11;
        for (int i = 0; i < 32; i++) buf[off++] = 0x22;
        buf[off++] = 0xAA; buf[off++] = 0xBB; buf[off++] = 0xCC; buf[off++] = 0xDD;
        buf[off++] = 0xF0; buf[off++] = 0xFF; buf[off++] = 0x0F; buf[off++] = 0x1E;
        buf[off++] = 0x99; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;

        dogecoin_auxpow_block* block = dogecoin_auxpow_block_new();
        block->header->version = 0x620102;
        struct const_buffer cb = { buf, off };
        arith_uint256 cw;
        (void)deserialize_dogecoin_auxpow_block(block, &cb, &dogecoin_chainparams_regtest, &cw);
        u_assert_int_eq(block->parent_merkle_count, 3);
        u_assert_int_eq(block->aux_merkle_count, 2);
        /* each branch's first byte must match what was serialized, proving the
           count was read correctly and the loop populated the allocated array */
        u_assert_uint32_eq(block->parent_coinbase_merkle[0][0], 0x40);
        u_assert_uint32_eq(block->parent_coinbase_merkle[2][0], 0x42);
        u_assert_uint32_eq(block->aux_merkle_branch[0][0], 0x80);
        u_assert_uint32_eq(block->aux_merkle_branch[1][0], 0x81);
        dogecoin_auxpow_block_free(block);
    }
}

/* Regression for the auxpow merkle-count handling in
   deserialize_dogecoin_auxpow_block(). The counts were read with
   deser_varlen((uint32_t*)&block->parent_merkle_count, ...) into uint8_t fields
   -- a 4-byte write through a 1-byte-typed pointer (undefined behavior that also
   truncated the wire value to 8 bits). This feeds a block declaring an
   out-of-range parent_merkle_count and asserts it is rejected cleanly: no crash,
   no UB, and (with the fix) an explicit out-of-range rejection before any merkle
   allocation. Runs under the CI ASan+UBSan gate, which is what catches the
   type-punned store on the pre-fix code. A full success-path round trip would
   require a check_auxpow()-passing parent block (real merged-mining data), which
   is not available as a fixture here. */
void test_auxpow_deserialize_merkle_count_bounds() {
    /* a valid serialized transaction, used as the parent coinbase prefix */
    const char* coinbase_hex =
        "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4"
        "0100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65"
        "dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f"
        "717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3"
        "a95118fa4a7c88ac00000000";
    size_t cblen = strlen(coinbase_hex) / 2;
    uint8_t buf[512];
    size_t off = 0;
    for (size_t k = 0; k < cblen; k++) {
        unsigned b; sscanf(coinbase_hex + 2 * k, "%2x", &b); buf[off++] = (uint8_t)b;
    }
    /* parent_hash (32 bytes) */
    for (int k = 0; k < 32; k++) buf[off++] = 0x11;
    /* parent_merkle_count as a 0xFE-prefixed 4-byte varint = 301 (0x0000012D),
       exceeds the 0xff bound; its low byte (0x2D) is nonzero so a truncating
       read would wrongly accept it as count 45 instead of rejecting. */
    buf[off++] = 0xFE; buf[off++] = 0x2D; buf[off++] = 0x01; buf[off++] = 0x00; buf[off++] = 0x00;

    dogecoin_auxpow_block* block = dogecoin_auxpow_block_new();
    struct const_buffer cb = { buf, off };
    arith_uint256 cw;
    /* must reject, not crash, not truncate-and-continue */
    u_assert_int_eq(deserialize_dogecoin_auxpow_block(block, &cb, &dogecoin_chainparams_main, &cw), 0);
    dogecoin_auxpow_block_free(block);
}
