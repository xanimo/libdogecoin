/**********************************************************************
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "utest.h"

#include <dogecoin/address.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/utils.h>

void test_address()
{
    /* initialize testing variables for simple keypair gen */
    char privkeywif_main[53];
    char privkeywif_test[53];
    char p2pkh_pubkey_main[35];
    char p2pkh_pubkey_test[35];
    dogecoin_mem_zero(privkeywif_main, sizeof(privkeywif_main));
    dogecoin_mem_zero(privkeywif_test, sizeof(privkeywif_test));
    // test generation ability
    u_assert_int_eq(generatePrivPubKeypair(privkeywif_main, NULL, false), true)
    u_assert_int_eq(generatePrivPubKeypair(privkeywif_main, p2pkh_pubkey_main, false), true)
    u_assert_int_eq(generatePrivPubKeypair(privkeywif_test, p2pkh_pubkey_test, true), true);

    /* test keypair basic exterior validity */
    u_assert_int_eq(strncmp(privkeywif_main,   "Q", 1), 0);
    u_assert_int_eq(strncmp(p2pkh_pubkey_main, "D", 1), 0);
    u_assert_int_eq(strncmp(privkeywif_test,   "c", 1), 0);
    u_assert_int_eq(strncmp(p2pkh_pubkey_test, "n", 1), 0);

    /* test keypair association */
    u_assert_int_eq(verifyPrivPubKeypair(privkeywif_main, p2pkh_pubkey_main, false), true);
    u_assert_int_eq(verifyPrivPubKeypair(privkeywif_test, p2pkh_pubkey_test, true), true);
    u_assert_int_eq(verifyPrivPubKeypair(privkeywif_main, p2pkh_pubkey_main, true), false);
    u_assert_int_eq(verifyPrivPubKeypair(privkeywif_test, p2pkh_pubkey_test, false), false);
    u_assert_int_eq(verifyPrivPubKeypair(privkeywif_main, p2pkh_pubkey_test, false), false);
    u_assert_int_eq(verifyPrivPubKeypair("QWgNKvA5LPD1HpopRFghjz6jPipHRAUrLjqTt7paxYX8cTbu5eRs", "D7AM5jDQ7xRRK7bMCZ87e4BsFxHxCdDbXd", false), true);
    u_assert_int_eq(verifyPrivPubKeypair("QWgNKvA5LPD1HpopRFghjz6jPipHRAUrLjqTt7paxYX8cTbu5eRs", "DCncxpcZW3GEyqs17KrqAfs4cR844JkimG", false), false);

    /* test internal validity */
    u_assert_int_eq(verifyP2pkhAddress("Dasdfasdfasdfasdfasdfasdfasdfasdfx", strlen("Dasdfasdfasdfasdfasdfasdfasdfasdfx")), false);
    u_assert_int_eq(verifyP2pkhAddress("DP6xxxDJxxxJAaWucRfsPvXLPGRyF3DdeP", strlen("DP6xxxDJxxxJAaWucRfsPvXLPGRyF3DdeP")), false);
    u_assert_int_eq(verifyP2pkhAddress(p2pkh_pubkey_main, strlen(p2pkh_pubkey_main)), true);
    u_assert_int_eq(verifyP2pkhAddress(p2pkh_pubkey_test, strlen(p2pkh_pubkey_test)), true);


    /* initialize testing variables for hd keypair gen */
    size_t masterkeylen = 200;
    size_t pubkeylen = 35;

    char* masterkey_main = dogecoin_char_vla(masterkeylen);
    char* masterkey_test=dogecoin_char_vla(masterkeylen);
    char* p2pkh_master_pubkey_main=dogecoin_char_vla(pubkeylen);
    char* p2pkh_master_pubkey_test=dogecoin_char_vla(pubkeylen);
    dogecoin_mem_zero(masterkey_main, masterkeylen);
    dogecoin_mem_zero(masterkey_test, masterkeylen);
    dogecoin_mem_zero(p2pkh_master_pubkey_main, pubkeylen);
    dogecoin_mem_zero(p2pkh_master_pubkey_test, pubkeylen);

    /* test generation ability */
    u_assert_int_eq(generateHDMasterPubKeypair(masterkey_main, NULL, false), true)
    u_assert_int_eq(generateHDMasterPubKeypair(NULL, NULL, false), true)
    u_assert_int_eq(generateHDMasterPubKeypair(NULL, NULL, NULL), true)
    u_assert_int_eq(generateHDMasterPubKeypair(masterkey_main, p2pkh_master_pubkey_main, false), true);
    u_assert_int_eq(generateHDMasterPubKeypair(masterkey_test, p2pkh_master_pubkey_test, true), true);

    /* test master keypair basic external validity */
    //TODO: public keys
    u_assert_int_eq(strncmp(masterkey_main,   "dgpv", 4), 0);
    u_assert_int_eq(strncmp(masterkey_test,   "tprv", 1), 0);

    /* test master keypair association */
    u_assert_int_eq(verifyHDMasterPubKeypair(masterkey_main, p2pkh_master_pubkey_main, false), true);
    u_assert_int_eq(verifyHDMasterPubKeypair(masterkey_test, p2pkh_master_pubkey_test, true), true);
    u_assert_int_eq(verifyHDMasterPubKeypair("dgpv51eADS3spNJh7z2oc8LgNLeJiwiPNgdEFcdtAhtCqDQ76SwphcQq74jZCRTZ2nF5RpmKx9P4Mm55RTopNQePWiSBfzyJ3jgRoxVbVLF6BCY", "DJt45oTXDxBiJBRZeMtXm4wu4kc5yPePYn", false), true);
    u_assert_int_eq(verifyHDMasterPubKeypair("dgpv51eADS3spNJh7z2oc8LgNLeJiwiPNgdEFcdtAhtCqDQ76SwphcQq74jZCRTZ2nF5RpmKx9P4Mm55RTopNQePWiSBfzyJ3jgRoxVbVLF6BCY", "DDDXCMUCXCFK3UHXsjqSkzwoqt79K6Rn6k", false), false);

    // test hd address format correctness
    u_assert_int_eq(verifyP2pkhAddress(p2pkh_master_pubkey_main, strlen(p2pkh_master_pubkey_main)), true);
    u_assert_int_eq(verifyP2pkhAddress(p2pkh_master_pubkey_test, strlen(p2pkh_master_pubkey_test)), true);


    /* initialize testing variables for derived pubkeys */

    char* child_key_main=dogecoin_char_vla(masterkeylen);
    char* child_key_test=dogecoin_char_vla(masterkeylen);
    char* str=dogecoin_char_vla(pubkeylen);
    /* test child key derivation ability */
    u_assert_int_eq(generateDerivedHDPubkey(masterkey_main, NULL), true)
    u_assert_int_eq(generateDerivedHDPubkey(NULL, NULL), false)
    u_assert_int_eq(generateDerivedHDPubkey(masterkey_main, child_key_main), true);
    u_assert_int_eq(generateDerivedHDPubkey(masterkey_test, child_key_test), true);
    u_assert_int_eq(generateDerivedHDPubkey("dgpv51eADS3spNJhA6LG5QycrFmQQtxg7ztFJQuamYiytZ4x4FUC7pG5B7fUTHBDB7g6oGaCVwuGF2i75r1DQKyFSauAHUGBAi89NaggpdUP3yK", str), true)
    u_assert_str_eq("DEByFfUQ3AxcFFet9afr8wxxedQysRduWN", str);
    u_assert_int_eq(generateDerivedHDPubkey("tprv8ZgxMBicQKsPeM5HaRoH4AuGX2Jsf8rgQvcFGCvjQxvAn1Bv8SAx8cPQsnmKsB6WjvGWsNiNsrNS2d3quUkYpK2ofctFw87SXodGhBPHiUM", str), true)
    u_assert_str_eq("noBtVVtAvvh5oapFjHHyTSxxEUTykUZ3oR", str);

    /* test child key/master key association */
    u_assert_int_eq(verifyHDMasterPubKeypair(masterkey_main, child_key_main, false), true);
    u_assert_int_eq(verifyHDMasterPubKeypair(masterkey_test, child_key_test, true), true);
    u_assert_int_eq(verifyP2pkhAddress(child_key_main, strlen(child_key_main)), true);
    u_assert_int_eq(verifyP2pkhAddress(child_key_test, strlen(child_key_test)), true);

    /* ckd address generation */
    size_t extoutsize = 112;
    char* extout = dogecoin_char_vla(extoutsize);
    char* masterkey_main_ext = "dgpv51eADS3spNJh8h13wso3DdDAw3EJRqWvftZyjTNCFEG7gqV6zsZmucmJR6xZfvgfmzUthVC6LNicBeNNDQdLiqjQJjPeZnxG8uW3Q3gCA3e";
    int res = getDerivedHDAddress(masterkey_main_ext, 0, false, 0, extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CrZ8Y8GQNxuxjY1arA892HCcviQdsKwiCpWS115r8UpKTYEZVLFzW9ryXmc6PndeHW7BJtJynrxfrdDrCoTDYjfi7UF59miuQJnaeiRYiz");
    res = getDerivedHDAddress(masterkey_main_ext, 0, false, 0, extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8wjaUE49xXdFFbCAd5n6Fspo5V63TzMezobib7Q4eFXpsWevyFt2doZWYjNwevu8tjCD7BB7utq8RiHEGrtDvu7iKZ9iPsaszaXvNQrscKD");
    res = getDerivedHDAddress(masterkey_main_ext, 0, true, 0, extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8w5Co1RcXUkqHYE5KdFE13pQdkoBnd9G14BgBav6JexHbhaMJM7pJ63BVt4B1D9gDs8BMM8GPEzgpHHjh8DDfVw8kT3Q7KRE8iXNNM8Z6vd");
    res = getDerivedHDAddress(masterkey_main_ext, 0, true, 0, extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CCBTKViyL6VzgZvHPdFtCGpBCRYxW7YiTQU2UX7WXuH3eTetaa3endXvdauMwQhzJQvX1tfEdTqsie88EpTFocGBq5M2vfM6oCtWXQzWpP");
    res = getDerivedHDAddress(masterkey_main_ext, 1, false, 1, extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CrZ8Y8GQNxv1ER9tm66ArcMmHgF6H9NmeQoEkFNu913CEuYiSsUKqBwn9bWwcyRiWZ9YxyVCTA8YHqWLehjU9rKDK87sn9koJNv52KKJSN");
    res = getDerivedHDAddress(masterkey_main_ext, 1, false, 1, extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8wjaUE49xXdFJ65Jvzi4Hi9xDr3svQB64FC1PreMhG43kJ2F8DREy8bbMP2aVPSuUYGiqgQCYBsa2Vc47N6ZjCdNjwh2d5fZhJry63Ygeks");
    res = getDerivedHDAddress(masterkey_main_ext, 1, true, 1, extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CCBTKViyL6W36k7eYgPFrP9yrNPN4gsoY8c1SJuSWw5HuQe5HsJrGULuM2yq3oSMXQDU1YoTQVyBDVDRZ76tJmFwJsdyrH73tVf2V1o14f");
    res = getDerivedHDAddress(masterkey_main_ext, 1, true, 1, extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8w5Co1RcXUkqKxQGgnJMNhvkSQk2CBib68upAYhtEdz5qxXLV4R5VZszUYh6u7Uwfx6y5HbEfA8VPwt29SbrJz7SCuB7mnH6rMHarimr7AL");

    printf("\ngetDerivedHDAddressByPath tests:\n\n");
    // hardened paths
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/0'/0/0", extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CrZ8Y8GQNxuxjY1arA892HCcviQdsKwiCpWS115r8UpKTYEZVLFzW9ryXmc6PndeHW7BJtJynrxfrdDrCoTDYjfi7UF59miuQJnaeiRYiz");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/0'/0/0", extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8wjaUE49xXdFFbCAd5n6Fspo5V63TzMezobib7Q4eFXpsWevyFt2doZWYjNwevu8tjCD7BB7utq8RiHEGrtDvu7iKZ9iPsaszaXvNQrscKD");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/0'/1/0", extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CCBTKViyL6VzgZvHPdFtCGpBCRYxW7YiTQU2UX7WXuH3eTetaa3endXvdauMwQhzJQvX1tfEdTqsie88EpTFocGBq5M2vfM6oCtWXQzWpP");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/0'/1/0", extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8w5Co1RcXUkqHYE5KdFE13pQdkoBnd9G14BgBav6JexHbhaMJM7pJ63BVt4B1D9gDs8BMM8GPEzgpHHjh8DDfVw8kT3Q7KRE8iXNNM8Z6vd");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/1'/0/1", extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CrZ8Y8GQNxv1ER9tm66ArcMmHgF6H9NmeQoEkFNu913CEuYiSsUKqBwn9bWwcyRiWZ9YxyVCTA8YHqWLehjU9rKDK87sn9koJNv52KKJSN");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/1'/0/1", extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8wjaUE49xXdFJ65Jvzi4Hi9xDr3svQB64FC1PreMhG43kJ2F8DREy8bbMP2aVPSuUYGiqgQCYBsa2Vc47N6ZjCdNjwh2d5fZhJry63Ygeks");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/1'/1/1", extout, true);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgpv5CCBTKViyL6W36k7eYgPFrP9yrNPN4gsoY8c1SJuSWw5HuQe5HsJrGULuM2yq3oSMXQDU1YoTQVyBDVDRZ76tJmFwJsdyrH73tVf2V1o14f");
    res = getDerivedHDAddressByPath(masterkey_main_ext, "m/44'/3'/1'/1/1", extout, false);
    u_assert_int_eq(res, true);
    printf("extout: %s\n", extout);
    u_assert_str_eq(extout, "dgub8w5Co1RcXUkqKxQGgnJMNhvkSQk2CBib68upAYhtEdz5qxXLV4R5VZszUYh6u7Uwfx6y5HbEfA8VPwt29SbrJz7SCuB7mnH6rMHarimr7AL");

    /*free up VLAs*/
    free(masterkey_main);
    free(masterkey_test);
    free(p2pkh_master_pubkey_main);
    free(p2pkh_master_pubkey_test);
    free(child_key_main);
    free(child_key_test);
    free(str);
    free(extout);
}
