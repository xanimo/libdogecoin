/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include <assert.h>

#ifndef _MSC_VER
#include <getopt.h>
#include <unistd.h>
#else
#include <win/wingetopt.h>
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_CONFIG_H)
#include "libdogecoin-config.h"
#endif

#include <dogecoin/chainparams.h>
#include <dogecoin/base58.h>
#include <dogecoin/bip39.h>
#include <dogecoin/ecc.h>
#include <dogecoin/net.h>
#include <dogecoin/spv.h>
#include <dogecoin/protocol.h>
#include <dogecoin/random.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tool.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/wallet.h>
#include <dogecoin/bip39.h>

/* This is a list of all the options that can be used with the program. */
static struct option long_options[] = {
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"ips", no_argument, NULL, 'i'},
        {"debug", no_argument, NULL, 'd'},
        {"maxnodes", no_argument, NULL, 'm'},
        {"mnemonic", no_argument, NULL, 'n'},
        {"dbfile", no_argument, NULL, 'f'},
        {"continuous", no_argument, NULL, 'c'},
        {"address", no_argument, NULL, 'a'},
        {"checkpoint", no_argument, NULL, 'p'},
        {"full_sync", no_argument, NULL, 'b'},
        {"wallet", no_argument, NULL, 'w'},
        {NULL, 0, NULL, 0} };

/**
 * Print_version() prints the version of the program
 */
static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    }

/**
 * This function prints the usage of the spvnode command
 */
static void print_usage() {
    print_version();
    printf("Usage: spvnode (-c|continuous) (-i|-ips <ip,ip,...]>) (-m[--maxpeers] <int>) (-t[--testnet]) (-f <headersfile|0 for in mem only>) (-r[--regtest]) (-d[--debug]) (-s[--timeout] <secs>) <command>\n");
    printf("Supported commands:\n");
    printf("        scan      (scan blocks up to the tip, creates header.db file)\n");
    printf("\nExamples: \n");
    printf("Sync up to the chain tip and stores all headers in headers.db (quit once synced):\n");
    printf("> spvnode scan\n\n");
    printf("Sync up to the chain tip and give some debug output during that process:\n");
    printf("> spvnode -d scan\n\n");
    printf("Sync up, show debug info, don't store headers in file (only in memory), wait for new blocks:\n");
    printf("> spvnode -d -f 0 -c scan\n\n");
    }

/**
 * Prints an error message to the screen
 *
 * @param er The error message to display.
 *
 * @return Nothing.
 */
static bool showError(const char* er) {
    printf("Error: %s\n", er);
    return 1;
    }

/**
 * When a new block is added to the blockchain, this function is called
 *
 * @param client The client object.
 * @param node The node that sent the message.
 * @param newtip The new tip of the headers chain.
 *
 * @return A boolean value.
 */
dogecoin_bool spv_header_message_processed(struct dogecoin_spv_client_* client, dogecoin_node* node, dogecoin_blockindex* newtip) {
    UNUSED(client);
    UNUSED(node);
    if (newtip) {
        printf("New headers tip height %d\n", newtip->height);
        }
    return true;
    }

static dogecoin_bool quit_when_synced = true;
/**
 * When the sync is complete, print a message and either exit or wait for new blocks or relevant
 * transactions
 *
 * @param client The client object.
 */
void spv_sync_completed(dogecoin_spv_client* client) {
    printf("Sync completed, at height %d\n", client->headers_db->getchaintip(client->headers_db_ctx)->height);
    if (quit_when_synced) {
        dogecoin_node_group_shutdown(client->nodegroup);
    } else {
        printf("Waiting for new blocks or relevant transactions...\n");
        dogecoin_wallet* wallet = (dogecoin_wallet*)client->sync_transaction_ctx;
        printf("Wallet balance: %ld\n", dogecoin_wallet_get_balance(wallet));
    }
}

int main(int argc, char* argv[]) {
    int ret = 0;
    int long_index = 0;
    int opt = 0;
    char* data = 0;
    char* ips = 0;
    dogecoin_bool debug = false;
    int timeout = 15;
    int maxnodes = 10;
    char* dbfile = 0;
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;
    char* address = NULL;
    dogecoin_bool use_checkpoint = false;
    char* mnemonic_in = 0;
    dogecoin_bool full_sync = false;
    dogecoin_bool wallet_cmd = false;

    if (argc <= 1 || strlen(argv[argc - 1]) == 0 || argv[argc - 1][0] == '-') {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
        }
    data = argv[argc - 1];

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "i:ctrds:m:n:f:a:p:b:w:", long_options, &long_index)) != -1) {
        switch (opt) {
                case 'c':
                    quit_when_synced = false;
                    break;
                case 't':
                    chain = &dogecoin_chainparams_test;
                    break;
                case 'r':
                    chain = &dogecoin_chainparams_regtest;
                    break;
                case 'd':
                    debug = true;
                    break;
                case 's':
                    timeout = (int)strtol(optarg, (char**)NULL, 10); // value stored is never read
                    break;
                case 'i':
                    ips = optarg;
                    break;
                case 'm':
                    maxnodes = (int)strtol(optarg, (char**)NULL, 10); // value stored is never read
                    break;
                case 'n':
                    mnemonic_in = optarg;
                    break;
                case 'f':
                    dbfile = optarg;
                    break;
                case 'a':
                    address = optarg;
                    break;
                case 'p':
                    use_checkpoint = true;
                    break;
                case 'b':
                    full_sync = true;
                    break;
                case 'w':
                    wallet_cmd = true;
                    break;
                case 'v':
                    print_version();
                    exit(EXIT_SUCCESS);
                    break;
                default:
                    print_usage();
                    exit(EXIT_FAILURE);
            }
        }

    if (strcmp(data, "scan") == 0) {
        dogecoin_ecc_start();
        dogecoin_spv_client* client = dogecoin_spv_client_new(chain, debug, (dbfile && (dbfile[0] == '0' || (strlen(dbfile) > 1 && dbfile[0] == 'n' && dbfile[0] == 'o'))) ? true : false, use_checkpoint, full_sync);
        client->header_message_processed = spv_header_message_processed;
        client->sync_completed = spv_sync_completed;

        int num;
        FILE* fptr;
        fptr = fopen("use_checkpoints", "w");
        if (fptr == NULL) exit(1);
        num = use_checkpoint;
        fprintf(fptr, "%d", num);
        fclose(fptr);
#if WITH_WALLET
        dogecoin_wallet* wallet = dogecoin_wallet_new(chain);
        int error;
        dogecoin_bool created;
        // prefix chain to wallet file name:
        char* wallet_suffix = "_wallet.db";
        char* wallet_prefix = (char*)chain->chainname;
        char* walletfile = concat(wallet_prefix, wallet_suffix);
        dogecoin_bool res = dogecoin_wallet_load(wallet, walletfile, &error, &created);
        dogecoin_free(walletfile);
        if (!res) {
            fprintf(stdout, "Loading wallet failed\n");
            exit(EXIT_FAILURE);
            }
        if (created) {
            // create a new key
            dogecoin_hdnode node;
            SEED seed;
            if (mnemonic_in) {
                // generate seed from mnemonic
                dogecoin_seed_from_mnemonic(mnemonic_in, NULL, seed);
                }
            else {
                res = dogecoin_random_bytes(seed, sizeof(seed), true);
                if (!res) {
                    fprintf(stdout, "Generating random bytes failed\n");
                    exit(EXIT_FAILURE);
                    }
                }
            dogecoin_hdnode_from_seed(seed, sizeof(seed), &node);
            dogecoin_wallet_set_master_key_copy(wallet, &node);
            }
        else {
            // ensure we have a key
            // TODO
            }

        dogecoin_wallet_addr* waddr;

        if (address != NULL) {
            waddr = dogecoin_wallet_addr_new();
            if (!dogecoin_p2pkh_address_to_wallet_pubkeyhash(address, waddr, wallet)) {
                exit(EXIT_FAILURE);
            }
        } else {
            waddr = dogecoin_wallet_next_addr(wallet);
        }

        size_t strsize = 128;
        char str[strsize];
        dogecoin_p2pkh_addr_from_hash160(waddr->pubkeyhash, wallet->chain, str, strsize);
        printf("Wallet addr: %s (child %d)\n", str, waddr->childindex);

        /* Creating a vector of addresses and storing them in the wallet. */
        vector* addrs = vector_new(1, free);
        dogecoin_wallet_get_addresses(wallet, addrs);
        unsigned int i;
        for (i = 0; i < addrs->len; i++) {
            char* addr = vector_idx(addrs, i);
            printf("Addr: %s\n", addr);
            }
        vector_free(addrs, true);
        printf("vec_wtxes: %ld\n", wallet->vec_wtxes->len);
        printf("spends: %ld\n", wallet->spends->len);
        printf("waddr_vector: %ld\n", wallet->waddr_vector->len);
        for (i = 0; i < wallet->vec_wtxes->len; i++) {
            dogecoin_wtx* wtx = vector_idx(wallet->vec_wtxes, i);                
            char* coin_amount[21];
            dogecoin_mem_zero(coin_amount, 21);
            uint64_t tx_out_total = 0;
            int length = wtx->tx->vout->len;
            int selected = -1;
            printf("length: %d\n", length);
            for (int j = 0; j < length; j++) {
                dogecoin_tx_out* tx_out = vector_idx(wtx->tx->vout, j);
                tx_out_total += tx_out->value;
                printf("\n--------------------------------\n");
                printf("output index:       %d\n", j);
                printf("script public key:  %s\n", utils_uint8_to_hex((const uint8_t*)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
                koinu_to_coins_str(tx_out->value, (char*)coin_amount);
                printf("amount:             %s\n", (char*)coin_amount);
                printf("total:              %s\n", (char*)tx_out_total);
            }
            char* subtotal[21];
            dogecoin_mem_zero(subtotal, 21);
            koinu_to_coins_str(tx_out_total, (char*)subtotal);
            printf("subtotal - desired fee: %s\n", (char*)subtotal);
            }
        printf("Wallet balance: %ld\n", dogecoin_wallet_get_balance(wallet));

        client->sync_transaction = dogecoin_wallet_check_transaction;
        client->sync_transaction_ctx = wallet;
#endif
        char* header_suffix = "_headers.db";
        char* header_prefix = (char*)chain->chainname;
        char* headersfile = concat(header_prefix, header_suffix);

        // read use_checkpoints to num variable:
        if ((fptr = fopen("use_checkpoints", "r")) == NULL) exit(1);
        if (!fscanf(fptr, "%d", &num)) exit(1);
        fclose(fptr);

        // if not equal with user input (-p | use_checkpoint) then write to file:
        if (num != use_checkpoint) {
            ret = unlink(headersfile);
            if (ret == 0) printf("%s unlinked successfully\n", headersfile);
            else printf("Error: unable to unlink %s\n", headersfile);
            fptr = fopen("use_checkpoints", "w");
            if (fptr == NULL) exit(1);
            num = use_checkpoint;
            fprintf(fptr, "%d", num);
            fclose(fptr);
        }

        dogecoin_bool response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headersfile));
        dogecoin_free(headersfile);
        if (!response) {
            printf("Could not load or create headers database...aborting\n");
            ret = EXIT_FAILURE;
        } else {
            printf("done\n");
            printf("Discover peers...");
            dogecoin_spv_client_discover_peers(client, ips);
            printf("Connecting to the p2p network...\n");
            dogecoin_spv_client_runloop(client);
            dogecoin_spv_client_free(client);
            ret = EXIT_SUCCESS;
            }
        dogecoin_ecc_stop();
        }
    else {
        printf("Invalid command (use -?)\n");
        ret = EXIT_FAILURE;
        }
    return ret;
    }