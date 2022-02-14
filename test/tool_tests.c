/**********************************************************************
 * Copyright (c) 2016 Jonas Schnelli                                  *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <dogecoin/crypto/base58.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/tool.h>
#include <dogecoin/utils.h>

#include "utest.h"

void test_tool()
{
    char addr[100];
    u_assert_int_eq(address_from_pubkey(&dogecoin_chainparams_main, "02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f", addr), true);
    u_assert_str_eq(addr, "DSztgmhTsjfS7xxDPyVNeunmBbjaJMfz92");

    size_t pubkeylen = 100;
    char pubkey[pubkeylen];
    u_assert_int_eq(pubkey_from_privatekey(&dogecoin_chainparams_main, "33040696a8f446e49c604fae51f6b342ca86a4021145552ed02682a17e158aff", pubkey, &pubkeylen), 0);
    printf("pubkey %s\n", pubkey);
    
    // u_assert_str_eq(pubkey, "QUbonNAYntLsprrUKRDPDeTuYeeBPjpPpPJhVvNPXFA1Be8ZXimF"); // need to fix

    size_t privkeywiflen = 100;
    char privkeywif[privkeywiflen];
    char privkeyhex[100];
    u_assert_int_eq(gen_privatekey(&dogecoin_chainparams_main, privkeywif, privkeywiflen, NULL), true);
    u_assert_int_eq(gen_privatekey(&dogecoin_chainparams_main, privkeywif, privkeywiflen, privkeyhex), true);

    uint8_t privkey_data[strlen(privkeywif)];
    size_t outlen = dogecoin_base58_decode_check(privkeywif, privkey_data, sizeof(privkey_data));
    u_assert_int_eq(privkey_data[0] == dogecoin_chainparams_main.b58prefix_secret_address, true);

    char privkey_hex_or_null[65];
    utils_bin_to_hex(privkey_data+1, DOGECOIN_ECKEY_PKEY_LENGTH, privkey_hex_or_null);
    u_assert_str_eq(privkeyhex,privkey_hex_or_null);

    size_t masterkeysize = 200;
    char masterkey[masterkeysize];
    u_assert_int_eq(hd_gen_master(&dogecoin_chainparams_main, masterkey, masterkeysize), true);
    u_assert_int_eq(hd_print_node(&dogecoin_chainparams_main, masterkey), true);

    size_t extoutsize = 200;
    char extout[extoutsize];
    u_assert_int_eq(hd_derive(&dogecoin_chainparams_main, "dgpv51eADS3spNJh9jYHA541MVTWDT3Rbx2oG49XKQDce4yJehwQzQ6vt8sscpKGeWm8xAoxv5KE2dvcPBk2PhLNkYBBFwjZuHfGFCnGpUg3w99", "m/3", extout, extoutsize), true);
    u_assert_str_eq(extout, "dgpv54TsC9Zf7TsWfXeNL7v3V7GmxzruBMtVhUD6Uv8qc3PQzhE1TxCKsuZSMSMzGZ4VWjzXuVWCCJqYNjCZhvuXox4cnsCALRjCMPiTMBmoKaD");

    u_assert_int_eq(hd_derive(&dogecoin_chainparams_main, "dgpv51eADS3spNJh9uouguKrH4W3GjsMfmKwKSibvuLEvXMUSm4PKXEX7kHoYNMYcdV6U9bDWQaBK2KBmmSwjnJgjU8KDfKrnRNU1skK3cd6n7X", "m/3'", extout, extoutsize), true);
    u_assert_str_eq(extout, "dgpv54VzeeUhqyXybnPSQJHcfVoK1kBZhLxNLJ9QvXr4kNh59VTxjVggdqPsjW8dZbH5baZ9jdLZxqQUV3xVPAV6hHQ4WhwnWoR3wuZtE2AwhSo");

    u_assert_int_eq(hd_derive(&dogecoin_chainparams_main, "dgpv51eADS3spNJh9gCpE1AyQ9NpMGkGh6MJKxM84Tf87KVLNeodEW76V2nJJRPorYLGnvZGJKTgEgvqGCtf9VS9RqhfJaTxV7iqm86VpMUNi5G", "m/3", extout, extoutsize), true);
    
}
