/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <dogecoin/bip32.h>
#include "utest.h"
#include <dogecoin/utils.h>

void test_bip32() {
    dogecoin_hdnode node, node2, node3, node4;
    char str[112];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    /* init m */
    dogecoin_hdnode_from_seed(utils_hex_to_uint8("000102030405060708090a0b0c0d0e0f"), 16, &node);

    /* [Chain m] */
    memcpy(private_key_master,
           utils_hex_to_uint8("c6991eeda06c82a61001dd0bed02a1b2597997b684cab51550ad8c0ce75c0a6b"),
           32);
    memcpy(chain_code_master,
           utils_hex_to_uint8("97c57681261f358eb33ae52625d79472e264acfa78c163e98c3db882c1317567"),
           32);
    u_assert_int_eq(node.fingerprint, 0x00000000);
    u_assert_mem_eq(node.chain_code, chain_code_master, 32);
    u_assert_mem_eq(node.private_key, private_key_master, 32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02c768a99915cf995e8507f5accdef995fd912cd4559def5862d29d229c04d2943"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv51eADS3spNJh9SHVGLuKReia8srv3ripH7j8kAS8PFuRsZQLnaAHpHmRz3Mg2DzyRjJKSSunwYByEhGiJzfWQfqcfnmMqg4WPL6CV9Coww4");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));

    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DQKnfKgsqVDxXjcCUKSs8Xz7bDe2SNcyof");

    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8kXBZ7ymNWy2SHweJaXHYWGAbSEYsykXZiWLuGq7BNxSRcX3CLi4TbB5ZGHwUmjfRxcT6zsN88G4C85duZ13naXKyszHKhvrdPsVjRnCjX5");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    /* [Chain m/0'] */
    char path0[] = "m/0'";
    dogecoin_hd_generate_key(&node, path0, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xD2700AA0);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("ce0b2fcd904a6d31577926feba13d0794482d1216fb082306c768cffbfb8a8ba"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("9a890ef773091cbd474a3be0a90b04f3925fa2a4f39b9e0bcadfb90926b30657"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03e0e0e17e610cd45a711a73d2c3149c7475ea3bde422dc70b88427d53773b5854"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv5551MfWQawkQLi5tQZ4Fr1baCKMyE3FSJHBiv9VA27KEJWx3VHYhVQuZZyNjRk3jewTP7Bv33L27hngKMzTzPBwhM1tqjmYadC24PWukcmD");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));

    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DFVFuPWwf4gjNWGDUcr3tnmG4ZybmiePNb");

    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8ox2hMSJ96QjdZk3SngDxs9Aesjc4AH9asxw5Ft8pENEra4ju46U8iKD9EnNAvr5NLgNX847FoiNGrhHj1dXQyAaNTo8WXxk69U2kjojQvL");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    /* [Chain m/0'/1] */
    char path1[] = "m/0'/1";
    dogecoin_hd_generate_key(&node, path1, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x718164DE);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("444d91108670c756dc1fc5c48023c5961b530fd6ed7763c61b3793580f598268"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("d4902277c6f24ac3113d0c8ae389bec3449a69d7ffb0b9b75f89c6a91b52dc15"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0248b40c7ef24243cb22951a7390f9bdce63fabf18ee4728f8ea41f7db00ad2588"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv56EpU8W81bdsi5HBRx1h2HV7UVnXVfuJY9JtSLDi4peMcTPSiguYiTAsXhbGkruNaySGVyNXJceUp4kK4pVduTDmXkPigxeSvDGWL5UReCg");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DEuuUquaYJkUTKZ8etWPH8WoAWiJuwhFpt");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8q7qopS1ZkJCzvwLUBdf992hw4AAKnw1pk66bScgrwhNAWW98TTKMkaX6uTayf7KJ4AkCwGNSabpsoLHewGJXBHkimC84oevNcvcW1JpRXf");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/1/2'] */
    char path2[] = "m/0'/1/2'";
    dogecoin_hd_generate_key(&node, path2, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x6B329E6D);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("254ea17f8678de07075e52145bb7be38464b4d517b019a1c60ea92a36c9e9295"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("412ab9d543cd7b468e5a8708fd4056962d4da0ac445b75e1a3beee50a9efa773"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0220184660a1049c146c961e00ca717630abd6628096aafa5159b01dd86c0cd639"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv585GMy1DBbcxsuoh4Tcw5R1xJGDaPsWrZfACj4CtPduEwJYvq4FfbV4rFkfAerRg2rszXqBtuJ1U1fM7whxPoTinZo1jz24Tqf7frqzWXDi");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DJDLeTs1bVTLfsoA8NXfyNu91AhjzkRYFc");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8rxHhew6jkHJAmTr6hEuCGZYkpbDDzYZrFwQtAbsBkxFVMfdEpoSEnUVpyLWcxzqCNGEQbDsmw7gJKbhG9fHqy77wzeBcC97EUY13EMh57s");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/1/2'/2] */
    char path3[] = "m/0'/1/2'/2";
    dogecoin_hd_generate_key(&node, path3, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x8F671330);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("4ee017f071c253816de69b343e2a4023adc5bef62808ce58d3ea86460fa362bf"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("a06ae1220b77ba077db88e7ea4a3ab25436a714b4bbc7811aa95234bc1a914f7"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02f6c1d0573e467cb5a2e32ab4d8a1b33bc1dd034fb27756714342ebe677be30f9"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv5ADqRWvZr6Mxk6MzCWmFafC4Qq2Jw2uDMyakJk2Mc35ixseMqA8Xg8uUBZvViCvt7p4L24gS5eLYnkHhCQGG8PbRjQZ5fiff1HLtVEyhpLo");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "D6DpKdDwqjedSVEX3Vboc4D9CWNX6MX7Lf");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8u6rmCrTQF2J2x29EkPDhWjesPPwm9vveaMxTrRLQA8jWvm4EvgJKSK7koWRtY4nwy4LfyTaNDdC5KYkphRoVFTwSvanz6cQJQdbEEBVkZ8");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/1/2'/2/1000000000] */
    char path4[] = "m/0'/1/2'/2/1000000000";
    dogecoin_hd_generate_key(&node, path4, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x0BDCAAEA);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("e781f4b6b7001ac95bc27831913b03bc86e7fc8de869d78a921385a41f356319"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("3b5e09554e87c16cc9e7c365b2e3bec7e5ff0a9fe75c301fd8714bebccc330da"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03950f35f7e23f68b5a79aef4f041965b4080edfa30149aac7dae2312a8c07a8cf"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "dgpv5B8toj9zZz2xXqKmyY3s9HgN6m4FnLW52gjV21E2nEY8NMK2vnXrMFcgxUP9eRd5iM8jFB6FZzp9Y92xcvVh8zxRgH3ta2UKWQRaZ2EThTM");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DQXYoCMPUqy5CKy9pstWZCdinADCAGFkfJ");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8v1v9R5t88hHpgyw1mfqG9DxZKRtcTXnKHWhB7d1aMb8vQRjLZ5czZ2LXjwJdpiDaRxPNQv4W1L57g8Wh2tXtrh56hL6wiHysCrb1vUYcdq");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(dogecoin_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    char str_pub_ckd[] = "dgub8ni9FJceneQCtAfhezgYfKrYfo1P959gmrhEiD2xxuEZYxhUNxm1f19Gg2EsiZG33ywfxcahMBvAe69gj9h4xad7b7eMWrXZniiB9PBXEdb";

    r = dogecoin_hdnode_deserialize(str_pub_ckd, &dogecoin_chainparams_main, &node4);
    r = dogecoin_hdnode_public_ckd(&node4, 123);
    u_assert_int_eq(r, true);
    dogecoin_hdnode_serialize_public(&node4, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "dgub8pbH768fzx5CkM6iJdDqTfrr53Df8wBa7H6jV5N7A4fLjnrhakh99VwCFkXiHLP8sj5jhnn9AfuzFCxecGo8uaigfUjtUJtcHgo9NAWN9yT");


    r = dogecoin_hdnode_public_ckd(&node4, 0x80000000 + 1); //try deriving a hardened key (= must fail)
    u_assert_int_eq(r, false);

    char str_pub_ckd_tn[] = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";

    r = dogecoin_hdnode_deserialize(str_pub_ckd_tn, &dogecoin_chainparams_test, &node4);
    r = dogecoin_hdnode_public_ckd(&node4, 123);
    u_assert_int_eq(r, true);
    dogecoin_hdnode_get_p2pkh_address(&node4, &dogecoin_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "ncjhiYnSD1pUiD2t2DWXezjZZww5H76n3P");
    size_t size = sizeof(str);
    size_t sizeSmall = 55;
    r = dogecoin_hdnode_get_pub_hex(&node4, str, &sizeSmall);
    u_assert_int_eq(r, false);
    r = dogecoin_hdnode_get_pub_hex(&node4, str, &size);
    u_assert_int_eq(size, 66);
    u_assert_int_eq(r, true);
    u_assert_str_eq(str, "0391a9964e79f39cebf9b59eb2151b500bd462e589682d6ceebe8e15970bfebf8b");
    dogecoin_hdnode_serialize_public(&node4, &dogecoin_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "tpubD8MQJFN9LVzG8pktwoQ7ApWWKLfUUhonQkeXe8gqi9tFMtMdC34g6Ntj5K6V1hdzR3to2z7dGnQbXaoZSsFkVky7TFWZjmC9Ez4Gog6ujaD");

    dogecoin_hdnode *nodeheap;
    nodeheap = dogecoin_hdnode_new();
    dogecoin_hdnode *nodeheap_copy = dogecoin_hdnode_copy(nodeheap);

    u_assert_int_eq(memcmp(nodeheap->private_key, nodeheap_copy->private_key, 32), 0);
    u_assert_int_eq(memcmp(nodeheap->public_key, nodeheap_copy->public_key, 33), 0)

    dogecoin_hdnode_free(nodeheap);
    dogecoin_hdnode_free(nodeheap_copy);
}
