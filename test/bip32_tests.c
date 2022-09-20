/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "utest.h"

#include <dogecoin/bip32.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>

void test_bip32()
{
    dogecoin_hdnode node, node2, node3, node4;
    char str[112];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    /* init m */
    dogecoin_hdnode_from_seed(utils_hex_to_uint8("000102030405060708090a0b0c0d0e0f"), 16, &node);

    /* [Chain m] */
    memcpy_safe(private_key_master,
           utils_hex_to_uint8("c6991eeda06c82a61001dd0bed02a1b2597997b684cab51550ad8c0ce75c0a6b"),
           32);
    memcpy_safe(chain_code_master,
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
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    /* [Chain m/0'] */
    char path0[] = "m/0'";
    dogecoin_hd_generate_key(&node, path0, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xD2700AA0);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("1513fccd7575b5f7fa7dcd00364ca4960eb4f0ddfbbab765cae03fe0e152a6c6"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("f5f4a1a26afeacb5886b04bae6407b1eed955960509c15e91ea6b0dc9aed42da"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0231228bb67dd68651088f54977903bb7ab478e0af0c2434aa38f640908ba34b53"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv5551MfWQawkQSWkvgCy47pgawVD7pWsNtmqU7Vsy4Qe9m8pNgBCUinLzJBjZqUgY89ogQz15nkBZWqcEF8Xnur15HvVwc6Ni4aaxjwsWdLA");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));

    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "D7KA2XbodJxksgtvFeY5FdG9XdzcdnwaMP");

    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8ox2hMSJ96QjjNR5iSb2EgEBQ3akedu6BNcgGcGwrXhAKBw55wkFN5kdsPAo4pF6TeC69Hu9RgjKiUhZe2GE5Q1dWDWB9RLwLSsDR3RuDfm");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    /* [Chain m/0'/3] */
    char path1[] = "m/0'/3";
    dogecoin_hd_generate_key(&node, path1, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x17D75284);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("4d95bf7a4a3593c18a46723db822e406d6358df458261a72eacb0009f2da3398"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("00f6c28b63f3a6b680d1f84baa3ecd87e72c01dcbf2a527d9d1976cef656e5a7"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02035917563dc21c91544159571c68f779cbc0608eab9bd166a3b1cbdd2dcf73e1"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv55abRjNSKfzULe5xd9onNWNacWnPF5fp38LnixtRKyNJyzpn651yG65Qo3wELkFyZRiy8ianHZ4LqzaAgCs6yHb3xiRyBsFJvG5FrWyrQAx");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DNr4yi1woUwiXRxnPTtzRUTtqwTjV2b2tG");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8pTcmRJKspeodVk7fPRkVMvB55A25ChXKj7zt5HQ86RKY3wUVqZjuPV4NGtBzLBaH8C2nyRrKUbvNQEeibf63HaS5tUQRPsvC2hQ9qP94T2");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/3/2'] */
    char path2[] = "m/0'/3/2'";
    dogecoin_hd_generate_key(&node, path2, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xC239E3B7);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("c7e15bb328b40fa6fb92bf00019ab0bd0d9a5b12cdfa46c0762d4abf4916b413"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("283a9279e19f94bdbf5ab89764f543c3dca0839d9287ac9e26bdcb31092ba2e5"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03e9102440edf7cf95eadca8df769b9638b9e62797065601a84ca4718d1e9eba3a"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv58iNE91voH327713eXyS6e6L8smWf8P9A5un4Cn8hRdLLh375dYk8a9TvMPuWuyA93vV8RP3TNX9VEgdo4Wzg7rX69Q3gTQ81ydHsoyYqT3");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DL9VFWxsNA9u5FvUncimTPNieqoxcuPTbE");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8sbPZpwpMRhMPxfCgmbQDVdvbS99VFQrSggzDKB7VYgLtk9oVQ6WmsZ7VdjV8kWz8wU3yNFu8iXnmyXtyUKiCMkrQ8bKLrXZ9YMWfc5qbc3");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/3/2'/2] */
    char path3[] = "m/0'/3/2'/2";
    dogecoin_hd_generate_key(&node, path3, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0xA49CD862);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("1233c742f888bf3308674e7fb3d82b1c2ef8ca77a1fdd08f80f8cafd4a56722e"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("9450c6c592de7c5efcf1e7b168d20135523dc61107ac350626d66edd3c49bb37"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03091459c74d06068e97781e425b0d4dbbab6fe5074d7c88fa86ea16411883561d"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgpv5ANss1uVaasc1nbP8uKFtv4sGDHy1nYS1PDNq5zPtLkXEVVY3aba4rP9kbuyyRaspqe54pRxEnDbGk63BoyvsGKSUAxizMB3je3HAVhZLg7");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "D7yUdhctLK3KyKQdW7THQiNxiRvUj4KHXa");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8uFuChqP8jXwJeFYB8wE1mcTimfbqua9HyzazCPNgToXnYcETM9Li9noKqjKJSgRjMGo8mD6RkTG2USQMLr4iuwPBsq57swZ6jsqmstxvZW");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));

    /* [Chain m/0'/3/2'/2/1000000000] */
    char path4[] = "m/0'/3/2'/2/1000000000";
    dogecoin_hd_generate_key(&node, path4, private_key_master, chain_code_master, false);
    u_assert_int_eq(node.fingerprint, 0x1F16A926);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("fab81e2e015d055e1077d1f0f236be2c09f55392b7af13a8217dd25c3d656e27"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("97a1af59b27d93fe673ead0b542a03a077fb20f37218340430bbc9e17a21549b"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03d584ce7a0c6289a944fdad5c354384e85c90e75016aa812979a1c1615989adf1"),
                    33);
    dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "dgpv5BH6Cfbt67y2GjLFKf8QHrFz36eScKxDuLw4cgthLrb7uYdFbdDyZH5U5XxvHRrF2VSSrjBVnStysJkAt9DRJoQgutoXPVpojC93VrLTNyw");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(dogecoin_hdnode));
    dogecoin_hdnode_get_p2pkh_address(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "DSGJCw4NJGbJ9SYe7mR1W6wbMjGoko6n8u");
    dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "dgub8vA7YMXmeGdMZazQMtkNQhoaVf25SSywBwiGmoHg8ye8Tbjx1PmkCaV7eoJq2yzBKfEZmDk2m7dWmHhNX4bh6W5JgakgPoEqboJHdafi4vw");
    r = dogecoin_hdnode_deserialize(str, &dogecoin_chainparams_main, &node2);
    u_assert_int_eq(r, true);
    memcpy_safe(&node3, &node, sizeof(dogecoin_hdnode));
    dogecoin_mem_zero(&node3.private_key, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(dogecoin_hdnode));


    char str_pub_ckd[] = "dgub8kXBZ7ymNWy2SDyf2FW3u9Y29xNHSqXEAdJer8Zh4pXKS61eCFPLByJeX2NyGaNVNXBjMHE9NpXfH4u9JUJKbrRCNFPeJ54gQN9RQTzUNDx";

    dogecoin_hdnode_deserialize(str_pub_ckd, &dogecoin_chainparams_main, &node4);
    r = dogecoin_hdnode_public_ckd(&node4, 124); // double check i >= 2 to the 31st power + 3 = 0x80000003 dogecoin coin_type bip44
    u_assert_int_eq(r, true);
    dogecoin_hdnode_serialize_public(&node4, &dogecoin_chainparams_main, str, sizeof(str));
    u_assert_str_eq(str, "dgub8o73HfBFaVpyuR1D8qzAAmqerNH17DaJTY9afFenUKWKhgiP6eo2DbiUqYS4mMqsnwBMbAyJMbH2acX1H778iUcTUphzR38Ck2rSRgV12Fz");

    r = dogecoin_hdnode_public_ckd(&node4, 0x80000003 + 1); //try deriving a hardened key (= must fail)
    u_assert_int_eq(r, false);

    char str_pub_ckd_tn[] = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";

    dogecoin_hdnode_deserialize(str_pub_ckd_tn, &dogecoin_chainparams_test, &node4);
    r = dogecoin_hdnode_public_ckd(&node4, 124); // double check i >= 2 to the 31st power + 3 = 0x80000003 dogecoin coin_type bip44
    u_assert_int_eq(r, true);
    dogecoin_hdnode_get_p2pkh_address(&node4, &dogecoin_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "nbsFtuY3Yxxe1SqcuFCxZc9GXqHERoxTmp");
    size_t size = sizeof(str);
    size_t sizeSmall = 55;
    r = dogecoin_hdnode_get_pub_hex(&node4, str, &sizeSmall);
    u_assert_int_eq(r, false);
    r = dogecoin_hdnode_get_pub_hex(&node4, str, &size);
    u_assert_int_eq(size, 66);
    u_assert_int_eq(r, true);
    u_assert_str_eq(str, "0345717c8722bd243ec5c7109ce52e95a353588403684057c2664f7ad3d7065ed5");
    dogecoin_hdnode_serialize_public(&node4, &dogecoin_chainparams_test, str, sizeof(str));
    u_assert_str_eq(str, "tpubD8MQJFN9LVzG9L2CzDwdBRfnyvoJWr8zGR8UrAsMjq89BqGwLQihzyrMJVaMm1WE91LavvHKqfWtk6Ce5Rr8mdPEacB1R2Ln6mc92FNPihs");

    dogecoin_hdnode* nodeheap;
    nodeheap = dogecoin_hdnode_new();
    dogecoin_hdnode* nodeheap_copy = dogecoin_hdnode_copy(nodeheap);

    u_assert_int_eq(memcmp(nodeheap->private_key, nodeheap_copy->private_key, 32), 0);
    u_assert_int_eq(memcmp(nodeheap->public_key, nodeheap_copy->public_key, 33), 0)

    dogecoin_hdnode_free(nodeheap);
    dogecoin_hdnode_free(nodeheap_copy);
}
