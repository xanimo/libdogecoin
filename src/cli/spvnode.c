/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli
 Copyright (c) 2023 bluezr
 Copyright (c) 2023-2024 The Dogecoin Foundation

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

#ifndef WIN32
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <assert.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#include <unistd.h>
#else
#include <win/wingetopt.h>
#endif

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>

#if defined(HAVE_CONFIG_H)
#include "libdogecoin-config.h"
#endif

#include <dogecoin/chainparams.h>
#include <dogecoin/constants.h>
#include <dogecoin/base58.h>
#include <dogecoin/bip37.h>
#include <dogecoin/bip39.h>
#include <dogecoin/ecc.h>
#include <dogecoin/mem.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/koinu.h>
#include <dogecoin/net.h>
#include <dogecoin/seal.h>
#include <dogecoin/smpv.h>
#include <dogecoin/spv.h>
#include <dogecoin/protocol.h>
#include <dogecoin/random.h>
#include <dogecoin/rest.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tool.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/wallet.h>

#ifndef WIN32
#define BD_NO_CHDIR          01 /* Don't chdir ("/") */
#define BD_NO_CLOSE_FILES    02 /* Don't close all open files */
#define BD_NO_REOPEN_STD_FDS 04 /* Don't reopen stdin, stdout, and stderr
                                   to /dev/null */
#define BD_NO_UMASK0        010 /* Don't do a umask(0) */
#define BD_MAX_CLOSE       8192 /* Max file descriptors to close if
                                   sysconf(_SC_OPEN_MAX) is indeterminate */

int // returns 0 on success -1 on error
become_daemon(int flags)
{
  int maxfd, fd;

  /* The first fork will change our pid
   * but the sid and pgid will be the
   * calling process.
   */
  switch(fork())                    // become background process
  {
    case -1: return -1;
    case 0: break;                  // child falls through
    default: _exit(EXIT_SUCCESS);   // parent terminates
  }

  /*
   * Run the process in a new session without a controlling
   * terminal. The process group ID will be the process ID
   * and thus, the process will be the process group leader.
   * After this call the process will be in a new session,
   * and it will be the progress group leader in a new
   * process group.
   */
  if(setsid() == -1)                // become leader of new session
    return -1;

  /*
   * We will fork again, also known as a
   * double fork. This second fork will orphan
   * our process because the parent will exit.
   * When the parent process exits the child
   * process will be adopted by the init process
   * with process ID 1.
   * The result of this second fork is a process
   * with the parent as the init process with an ID
   * of 1. The process will be in it's own session
   * and process group and will have no controlling
   * terminal. Furthermore, the process will not
   * be the process group leader and thus, cannot
   * have the controlling terminal if there was one.
   */
  switch(fork())
  {
    case -1: return -1;
    case 0: break;                  // child breaks out of case
    default: _exit(EXIT_SUCCESS);   // parent process will exit
  }

  if(!(flags & BD_NO_UMASK0))
    umask(0);                       // clear file creation mode mask

//   if(!(flags & BD_NO_CHDIR))
//     chdir("/");                     // change to root directory

  if(!(flags & BD_NO_CLOSE_FILES))  // close all open files
  {
    maxfd = sysconf(_SC_OPEN_MAX);
    if(maxfd == -1)
      maxfd = BD_MAX_CLOSE;         // if we don't know then guess
    for(fd = 0; fd < maxfd; fd++)
      close(fd);
  }

  if(!(flags & BD_NO_REOPEN_STD_FDS))
  {
    /* now time to go "dark"!
     * we'll close stdin
     * then we'll point stdout and stderr
     * to /dev/null
     */
    close(STDIN_FILENO);

    fd = open("/dev/null", O_RDWR);
    if(fd != STDIN_FILENO)
      return -1;
    if(dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
      return -2;
    if(dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
      return -3;
  }

  return 0;
}
#endif

/* This is a list of all the options that can be used with the program. */
static struct option long_options[] = {
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"ips", no_argument, NULL, 'i'},
        {"debug", no_argument, NULL, 'd'},
        {"maxnodes", no_argument, NULL, 'm'},
        {"mnemonic", no_argument, NULL, 'n'},
        {"pass_phrase", no_argument, NULL, 's'},
        {"dbfile", no_argument, NULL, 'f'},
        {"continuous", no_argument, NULL, 'c'},
        {"address", no_argument, NULL, 'a'},
        {"full_sync", no_argument, NULL, 'b'},
        {"checkpoint", no_argument, NULL, 'p'},
        {"wallet_file", required_argument, NULL, 'w'},
        {"headers_file", required_argument, NULL, 'h'},
        {"no_prompt", no_argument, NULL, 'l'},
        {"encrypted_file", required_argument, NULL, 'y'},
        {"use_tpm", no_argument, NULL, 'j'},
        {"master_key", no_argument, NULL, 'k'},
        {"http_server", required_argument, NULL, 'u'},
        {"smpv", no_argument, NULL, 'x'},
        {"filtered_blocks", no_argument, NULL, 'g'},
        {"select_checkpoint", no_argument, NULL, 'q'},
        {"daemon", no_argument, NULL, 'z'},
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
    printf("Usage: spvnode (-c|continuous) (-i|--ips <ip,ip,...>) (-m[--maxpeers] <int>) (-f <headersfile|0 for in mem only>) \
(-a|--address <address>) (-n|--mnemonic <seed_phrase>) (-s|[--pass_phrase]) (-y|--encrypted_file <file_num 0-999>) \
(-w|--wallet_file <filename>) (-h|--headers_file <filename>) (-l|[--no_prompt]) (-b[--full_sync]) (-p[--checkpoint]) (-k[--master_key]) (-j[--use_tpm]) \
(-u|--http_server <ip:port>) (-x|--smpv) (-g|--filtered_blocks) (-q|--select_checkpoint) (-t|--testnet) (-r|--regtest) (-d|--debug) <command>\n");
    printf("Supported commands:\n");
    printf("        scan      (scan blocks up to the tip, creates header.db file)\n");
    printf("\nExamples: \n");
    printf("Sync up to the chain tip and stores all headers in headers.db (quit once synced):\n");
    printf("> ./spvnode scan\n\n");
    printf("Sync up to the chain tip and give some debug output during that process:\n");
    printf("> ./spvnode -d scan\n\n");
    printf("Sync up, show debug info, don't store headers in file (only in memory), wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -b scan\n\n");
    printf("Sync up, with an address, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -a \"DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -w \"./main_wallet.db\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with an address, show debug info, with a headers file, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -a \"DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1\" -w \"./main_wallet.db\" -h \"./main_headers.db\" -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -s -b scan\n\n");
    printf("Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks, use TPM:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -s -j -b scan\n\n");
    printf("Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -k -b scan\n\n");
    printf("Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key, use TPM:\n");
    printf("> ./spvnode -d -f 0 -c -y 0 -k -j -b scan\n\n");
    printf("Sync up, with mnemonic \"test\", BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -n \"test\" -s -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:\n");
    printf("> ./spvnode -d -f 0 -c -w \"./main_wallet.db\" -y 0 -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use TPM:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -j -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use master key:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -k -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", with encrypted mnemonic 0, show debug info, with a headers file \"main_headers.db\", wait for new blocks, use master key, use TPM:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -h \"./main_headers.db\" -y 0 -k -j -b scan\n\n");
    printf("Sync up, with a wallet file \"main_wallet.db\", show debug info, wait for new blocks, enable http server:\n");
    printf("> ./spvnode -d -c -w \"./main_wallet.db\" -u \"0.0.0.0:8080\" -b scan\n\n");
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
    UNUSED(node);
    if (newtip) {
        time_t timestamp = client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp;
        printf("New headers tip height %d from %s\n", newtip->height, ctime(&timestamp));
        }
    return true;
    }

static dogecoin_bool quit_when_synced = true;
static dogecoin_bool spv_enable_filtered_blocks = false;
static dogecoin_bool spv_select_checkpoint = false;
static int spv_filter_oldest_utxo_height = 0;

static int spv_choose_checkpoint_index(const dogecoin_chainparams* chain, dogecoin_bool prompt, int max_height)
{
    const dogecoin_checkpoint* checkpoints = NULL;
    int count = 0;
    int latest = 0;
    int selected = 0;
    int default_idx = 0;
    int i;

    if (chain == &dogecoin_chainparams_main) {
        checkpoints = dogecoin_mainnet_checkpoint_array;
        count = (int)(sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]));
    } else if (chain == &dogecoin_chainparams_test) {
        checkpoints = dogecoin_testnet_checkpoint_array;
        count = (int)(sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]));
    } else {
        return -1;
    }

    if (count <= 0) return -1;

    latest = count - 1;
    selected = latest;
    default_idx = latest;

    if (max_height >= 0) {
        default_idx = 0;
        for (i = 0; i < count; i++) {
            if ((int)checkpoints[i].height <= max_height) {
                default_idx = i;
            } else {
                break;
            }
        }
        selected = default_idx;
    }

    printf("Available checkpoints (%d total):\n", count);
    for (i = 0; i < count; i++) {
        printf("  %2d) height %u\n", (i + 1), checkpoints[i].height);
    }

    if (!prompt) return selected;

    printf("Select checkpoint [1-%d] (default %d): ", count, (default_idx + 1));
    fflush(stdout);
    {
        char input[32];
        if (fgets(input, sizeof(input), stdin)) {
            int choice = atoi(input);
            if (choice >= 1 && choice <= count) {
                if (max_height >= 0 && (int)checkpoints[choice - 1].height > max_height) {
                    printf("Selected checkpoint is newer than loaded headers start height %d, using default %u instead.\n",
                           max_height, checkpoints[default_idx].height);
                    selected = default_idx;
                } else {
                    selected = choice - 1;
                }
            }
        }
    }

    return selected;
}
/**
 * When the sync is complete, print a message and either exit or wait for new blocks or relevant
 * transactions
 *
 * @param client The client object.
 */
void spv_sync_completed(dogecoin_spv_client* client) {
    dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
    int tip_height = tip->height;
    int available_start_height = tip_height;
    int request_start_height;
    int request_depth;
    dogecoin_blockindex* cursor = tip;
    dogecoin_headers_db* headers_db = (dogecoin_headers_db*)client->headers_db_ctx;
    while (cursor && cursor->prev) cursor = cursor->prev;
    if (cursor) available_start_height = (int)cursor->height;
    if (headers_db && headers_db->headers_tree_file) {
        long old_pos = ftell(headers_db->headers_tree_file);
        dogecoin_bool can_restore_pos = (old_pos >= 0);
        uint8_t rec[SPV_HEADERS_FILE_REC_LEN];
        if (fseek(headers_db->headers_tree_file, SPV_HEADERS_FILE_HDR_LEN, SEEK_SET) == 0 &&
            fread(rec, sizeof(rec), 1, headers_db->headers_tree_file) == 1) {
            struct const_buffer rec_buf = { rec, sizeof(rec) };
            uint256_t first_block_hash;
            uint32_t h = 0;
            uint256_t first_block_chainwork;
            deser_u256(first_block_hash, &rec_buf);
            deser_u32(&h, &rec_buf);
            deser_u256(first_block_chainwork, &rec_buf);
            available_start_height = (int)h;
        }
        if (can_restore_pos) fseek(headers_db->headers_tree_file, old_pos, SEEK_SET);
    }
    request_start_height = available_start_height;
    if (request_start_height < 0) request_start_height = 0;
    if (request_start_height > tip_height) request_start_height = tip_height;
    request_depth = (tip_height - request_start_height) + 1;
    printf("Sync completed, at height %d\n", tip_height);

    /* If a bloom filter is active, request filtered blocks from the last
       checkpoint to tip to discover UTXOs. Per BIP37, the peer responds
       with a merkleblock for every requested block — blocks with matching
       transactions include the matched TXs, while non-matching blocks
       come back with 0 matched transactions. */
    if (client->bloom_filter && client->bloom_filter_len > 0) {
        printf("Requesting historical filtered blocks for UTXO discovery from height %d to %d (starting from current checkpoint or genesis)...\n",
               request_start_height, tip_height);
        if (spv_filter_oldest_utxo_height > 0 && spv_filter_oldest_utxo_height < available_start_height) {
            const dogecoin_checkpoint* checkpoints = NULL;
            int checkpoint_count = 0;
            int i;
            int suggested_checkpoint_height = available_start_height;

            if (client->chainparams == &dogecoin_chainparams_main) {
                checkpoints = dogecoin_mainnet_checkpoint_array;
                checkpoint_count = (int)(sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]));
            } else if (client->chainparams == &dogecoin_chainparams_test) {
                checkpoints = dogecoin_testnet_checkpoint_array;
                checkpoint_count = (int)(sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]));
            }
            if (checkpoints && checkpoint_count > 0) {
                suggested_checkpoint_height = (int)checkpoints[0].height;
                for (i = 0; i < checkpoint_count; i++) {
                    if ((int)checkpoints[i].height <= spv_filter_oldest_utxo_height) {
                        suggested_checkpoint_height = (int)checkpoints[i].height;
                    } else {
                        break;
                    }
                }
            }
            printf("Warning: oldest wallet UTXO height %d is older than locally available headers start %d.\n",
                   spv_filter_oldest_utxo_height, available_start_height);
            printf("Warning: additional historical matches before %d cannot be discovered in this run until headers are synced from that range.\n",
                   available_start_height);
            printf("Note: already-known wallet transactions from that older range are still retained and do not need to be re-requested.\n");
            printf("Hint: rerun with -q/--select_checkpoint and choose a checkpoint at or before height %d (e.g. %d).\n",
                   spv_filter_oldest_utxo_height, suggested_checkpoint_height);
        }
        dogecoin_net_spv_request_filtered_history(client, request_depth);
    }

    if (quit_when_synced) {
        dogecoin_node_group_shutdown(client->nodegroup);
    } else {
        printf("Waiting for new blocks or relevant transactions...\n");
    }
}

// Signal callback for shutdown requests
void handle_shutdown_signal(evutil_socket_t sig, short events, void* user_data) {
    (void)sig;
    (void)events;
    dogecoin_spv_client* client = (dogecoin_spv_client*)user_data;

    printf("Disconnecting...\n");
    if (client && client->nodegroup) {
        dogecoin_node_group_shutdown(client->nodegroup);
        if (client->nodegroup->event_base) {
            event_base_loopbreak(client->nodegroup->event_base);
        }
    }
}

int main(int argc, char* argv[]) {
    int ret = 0;
    int long_index = 0;
    int opt = 0;
    char* data = 0;
    char* ips = 0;
    dogecoin_bool debug = false;
    int maxnodes = 10;
    char* dbfile = 0;
    dogecoin_bool in_memory_headers = false;
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;
    char* address = NULL;
    dogecoin_bool use_checkpoint = false;
    char* pass = 0;
    char* mnemonic_in = 0;
    char* name = 0;
    char* headers_name = 0;
    dogecoin_bool full_sync = false;
    dogecoin_bool have_decl_daemon = false;
    dogecoin_bool prompt = true;
    dogecoin_bool encrypted = false;
    dogecoin_bool master_key = false;
    dogecoin_bool tpm = false;
    char* http_server = NULL;
    int file_num = NO_FILE;
    dogecoin_bool smpv_cli_enable = false;
    int selected_checkpoint_index = -1;
    if (argc <= 1 || strlen(argv[argc - 1]) == 0 || argv[argc - 1][0] == '-') {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
        }
    data = argv[argc - 1];

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "i:ctrdsm:n:f:y:u:w:h:a:lbpzkj:xgq", long_options, &long_index)) != -1) {
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
                case 'i':
                    ips = optarg;
                    break;
                case 's':
                    pass = getpass("BIP39 passphrase: \n");
                    break;
                case 'm':
                    maxnodes = (int)strtol(optarg, (char**)NULL, 10);
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
                case 'b':
                    full_sync = true;
                    break;
                case 'p':
                    use_checkpoint = true;
                    break;
                case 'h':
                    headers_name = optarg;
                    break;
                case 'l':
                    prompt = false;
                    break;
                case 'y':
                    encrypted = true;
                    file_num = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'k':
                    master_key = true;
                    break;
                case 'j':
                    tpm = true;
                    break;
                case 'w':
                    name = optarg;
                    break;
                case 'u':
                    http_server = optarg;
                    if (!isdigit(http_server[0])) {
                        printf("Please add the ip and port after -u and try again. e.g. '-u 0.0.0.0:8080'\n");
                        exit(EXIT_FAILURE);
                    }
                    break;
                case 'z':
                    have_decl_daemon = true;
                    break;
                case 'v':
                    print_version();
                    exit(EXIT_SUCCESS);
                    break;
                case 'x':
                    smpv_cli_enable = true;
                    break;
                case 'g':
                    spv_enable_filtered_blocks = true;
                    break;
                case 'q':
                    spv_select_checkpoint = true;
                    use_checkpoint = true;
                    break;
                default:
                    print_usage();
                    exit(EXIT_FAILURE);
            }
        }

    if (strcmp(data, "scan") == 0) {
        dogecoin_ecc_start();
        in_memory_headers = (dbfile && ((strcmp(dbfile, "0") == 0) || (strcmp(dbfile, "no") == 0)));
        dogecoin_spv_client* client = dogecoin_spv_client_new(chain, debug, in_memory_headers, use_checkpoint, full_sync, maxnodes, http_server);

        if (http_server) {
            evhttp_set_gencb(client->nodegroup->http_server, dogecoin_http_request_cb, client);
        }
        if (smpv_cli_enable) {
            dogecoin_spv_enable_smpv(client, true);
            printf("[smpv] enabled via CLI flag\n");
        }
        client->header_message_processed = spv_header_message_processed;
        client->sync_completed = spv_sync_completed;
#if WITH_WALLET
        dogecoin_wallet_opts wopts = {
            .mnemonic_in = mnemonic_in,
            .pass = pass,
            .encrypted = encrypted,
            .tpm = tpm,
            .file_num = file_num,
            .master_key = master_key,
            .prompt = prompt
        };
        dogecoin_wallet* wallet = dogecoin_wallet_init(
            chain,
            address,
            name,
            &wopts);
        if (!wallet) {
            printf("Could not initialize wallet...\n");
            // clear and free the passphrase
            if (pass) {
                dogecoin_mem_zero (pass, strlen(pass));
                dogecoin_free(pass);
                }
            dogecoin_spv_client_free(client);
            dogecoin_ecc_stop();
            return EXIT_FAILURE;
        }
        // clear and free the passphrase
        if (pass) {
            dogecoin_mem_zero (pass, strlen(pass));
            dogecoin_free(pass);
            }
        print_utxos(wallet);

        if (smpv_cli_enable && client->smpv_enabled && client->smpv_ctx) {
            unsigned int i;
            if (address && address[0] != '\0') {
                size_t addr_len = strlen(address);
                char* addr_copy = (char*)dogecoin_calloc(addr_len + 1, 1);
                if (addr_copy) {
                    memcpy(addr_copy, address, addr_len);
                    char* saveptr = NULL;
                    char* tok = strtok_r(addr_copy, " ", &saveptr);
                    while (tok) {
                        dogecoin_smpv_add_watcher((dogecoin_smpv_client*)client->smpv_ctx, tok);
                        tok = strtok_r(NULL, " ", &saveptr);
                    }
                    dogecoin_free(addr_copy);
                }
            }

            for (i = 0; i < wallet->waddr_vector->len; i++) {
                dogecoin_wallet_addr* waddr = vector_idx(wallet->waddr_vector, i);
                if (!waddr || waddr->ignore) continue;
                {
                    char waddr_str[P2PKHLEN];
                    if (dogecoin_p2pkh_addr_from_hash160(waddr->pubkeyhash, chain, waddr_str, sizeof(waddr_str))) {
                        dogecoin_smpv_add_watcher((dogecoin_smpv_client*)client->smpv_ctx, waddr_str);
                    }
                }
            }
        }

        /* Optional BIP37 filter setup using filterload with fixed-size bloom. */
        if (spv_enable_filtered_blocks && (wallet->waddr_vector->len > 0 || HASH_COUNT(wallet->utxos) > 0)) {
            dogecoin_bip37_filter* filter = dogecoin_bip37_filter_new(0, 1); /* random tweak, UPDATE_ALL */
            if (!filter) {
                printf("Failed to initialize BIP37 bloom filter\n");
                dogecoin_wallet_free(wallet);
                dogecoin_spv_client_free(client);
                dogecoin_ecc_stop();
                return EXIT_FAILURE;
            }
            unsigned int i;
            for (i = 0; i < wallet->waddr_vector->len; i++) {
                dogecoin_wallet_addr* waddr = vector_idx(wallet->waddr_vector, i);
                if (waddr->ignore) continue;
                dogecoin_bip37_filter_add(filter, waddr->pubkeyhash, sizeof(uint160_t));
            }

            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                /* Only confirmed chain heights (>0) are useful for historical scan bounds. */
                if (utxo->height > 0 &&
                    (spv_filter_oldest_utxo_height == 0 || utxo->height < spv_filter_oldest_utxo_height)) {
                    spv_filter_oldest_utxo_height = utxo->height;
                }

                /* Add txid itself so historical funding transactions can match. */
                dogecoin_bip37_filter_add(filter, utxo->txid, 32);

                /* Add outpoint so spending transactions can match later. */
                uint8_t outpoint[36];
                memcpy(outpoint, utxo->txid, 32);
                uint32_t vout_le = htole32(utxo->vout);
                memcpy(outpoint + 32, &vout_le, 4);
                dogecoin_bip37_filter_add(filter, outpoint, 36);
                char txid_hex[sizeof(utxo->txid) * 2 + 1];
                utils_bin_to_hex(utxo->txid, sizeof(utxo->txid), txid_hex);
                debug_print("  - txid: %s vout: %d block_height: %d\n",
                            txid_hex, utxo->vout, utxo->height);
            }

            dogecoin_bool loaded = dogecoin_spv_client_filterload(client,
                                                                 filter->data,
                                                                 filter->data_len,
                                                                 filter->n_hash_funcs,
                                                                 filter->n_tweak,
                                                                 filter->n_flags);
            if (loaded) {
                printf("Initial filterload sent (fixed max size, %u hash funcs)\n", filter->n_hash_funcs);
            } else {
                printf("Failed to send initial filterload\n");
            }
            dogecoin_bip37_filter_free(filter);
        } else if (spv_enable_filtered_blocks) {
            printf("Empty wallet - no BIP37 filter set\n");
        } else {
            printf("Filtered block mode disabled (use -g/--filtered_blocks to enable)\n");
        }

        client->sync_transaction = dogecoin_wallet_check_transaction;
        client->sync_transaction_ctx = wallet;
#endif
        char* header_suffix = "_headers.db";
        char* header_prefix = (char*)chain->chainname;
        char* headersfile = NULL;
        dogecoin_bool response = false;
        if (mnemonic_in) {
            // mnemonic was provided, so store headers in separate file
            char* wallet_type = "_mnemonic";
            char* header_type_prefix = concat(header_prefix, wallet_type);
            headersfile = concat(header_type_prefix, header_suffix);
            dogecoin_free(header_type_prefix);
            if (headers_name) {
                // Load headers file name with headers name:
                response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headers_name), prompt);
            } else {
                // Otherwise, use default headers file name:
                response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headersfile), prompt);
            }
        }
        else if (headers_name) {
            // Load headers file name with headers name:
            response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headers_name), prompt);
        } else {
            // Otherwise, use default headers file name:
            headersfile = concat(header_prefix, header_suffix);
            response = dogecoin_spv_client_load(client, (dbfile ? dbfile : headersfile), prompt);
        }

        dogecoin_free(headersfile);
        if (!response) {
            printf("Could not load or create headers database...aborting\n");
#if WITH_WALLET
            dogecoin_wallet_free(wallet);
#endif
            dogecoin_spv_client_free(client);
            dogecoin_ecc_stop();
            return EXIT_FAILURE;
        } else {
            if (spv_select_checkpoint) {
                int loaded_start_height = -1;
                dogecoin_blockindex* loaded_tip = client->headers_db->getchaintip(client->headers_db_ctx);
                if (loaded_tip) {
                    dogecoin_blockindex* start_cursor = loaded_tip;
                    while (start_cursor && start_cursor->prev) start_cursor = start_cursor->prev;
                    if (start_cursor && start_cursor->height > 0) {
                        loaded_start_height = (int)start_cursor->height;
                    }
                }
                if (!in_memory_headers && loaded_start_height > 0) {
                    printf("Ignoring checkpoint selection: existing headers are already loaded (start height %d).\n", loaded_start_height);
                    printf("Checkpoint selection is only available for new headers storage or in-memory headers mode.\n");
                } else {
                    selected_checkpoint_index = spv_choose_checkpoint_index(chain, prompt, (prompt ? loaded_start_height : -1));
                    if (selected_checkpoint_index >= 0) {
                        const dogecoin_checkpoint* checkpoints = (chain == &dogecoin_chainparams_main) ?
                            dogecoin_mainnet_checkpoint_array : dogecoin_testnet_checkpoint_array;
                        uint256_t hash;
                        utils_uint256_sethex((char*)checkpoints[selected_checkpoint_index].hash, (uint8_t*)&hash);
                        arith_uint256 checkpoint_chainwork;
                        uint_to_arith(&checkpoint_chainwork, &client->chainparams->minimumchainwork);
                        client->headers_db->set_checkpoint_start(
                            client->headers_db_ctx,
                            hash,
                            checkpoints[selected_checkpoint_index].height,
                            checkpoint_chainwork);
                        printf("Selected checkpoint height %u\n", checkpoints[selected_checkpoint_index].height);
                    }
                }
            }
            if (have_decl_daemon) {
#if defined(HAVE_DECL_DAEMON) && !defined(WIN32)
                const char *LOGNAME = "libdogecoin-spvnode";

                // turn this process into a daemon
                ret = become_daemon(0);
                if(ret)
                {
                    syslog(LOG_USER | LOG_ERR, "error starting");
                    closelog();
                    return EXIT_FAILURE;
                }

                // we are now a daemon!
                // printf now will go to /dev/null

                // open up the system log
                openlog(LOGNAME, LOG_PID, LOG_USER);
                syslog(LOG_USER | LOG_INFO, "starting");

                // run forever in the background
                while(1)
                {
                    sleep(60);
                    syslog(LOG_USER | LOG_INFO, "running");
                }
#else
            fprintf(stderr, "Error: -z | --daemon is not supported on this operating system\n");
            return false;
#endif
            }
            printf("done\n");
            printf("Discover peers...\n");
            dogecoin_spv_client_discover_peers(client, ips);

            printf("Connecting to the p2p network...\n");
            printf("Press CTRL+C or send SIGINT/SIGTERM to disconnect.\n");
            struct event* sigint_event = evsignal_new(client->nodegroup->event_base, SIGINT, handle_shutdown_signal, client);
            struct event* sigterm_event = evsignal_new(client->nodegroup->event_base, SIGTERM, handle_shutdown_signal, client);
            if (!sigint_event || !sigterm_event || event_add(sigint_event, NULL) != 0 || event_add(sigterm_event, NULL) != 0) {
                fprintf(stderr, "Error: failed to register shutdown signal handlers\n");
                if (sigint_event) {
                    event_free(sigint_event);
                }
                if (sigterm_event) {
                    event_free(sigterm_event);
                }
                dogecoin_spv_client_free(client);
#if WITH_WALLET
                dogecoin_wallet_free(wallet);
#endif
                dogecoin_ecc_stop();
                return EXIT_FAILURE;
            }
            dogecoin_spv_client_runloop(client);
            event_free(sigint_event);
            event_free(sigterm_event);
            dogecoin_spv_client_free(client);
            printf("done\n");
            ret = EXIT_SUCCESS;
#if WITH_WALLET
            dogecoin_wallet_free(wallet);
#endif
            }
        dogecoin_ecc_stop();
    } else if (strcmp(data, "sanity") == 0) {
#if WITH_WALLET
    dogecoin_ecc_start();
    if (address != NULL) {
        char delim[] = " ";
        // copy address into a new string, strtok modifies the string
        char* address_copy = strdup(address);

        // backup existing default wallet file prior to radio doge functions test
        const dogecoin_chainparams *params = chain_from_b58_prefix(address_copy);
        dogecoin_wallet *tmp = dogecoin_wallet_new(params);
        int result;
        FILE *file;
        if ((file = fopen(tmp->filename, "r")))
        {
            fclose(file);
#ifdef WIN32
            #include <winbase.h>
            result = CopyFile((char*)tmp->filename, "tmp.bin", true);
            if (result == 1) result = 0;
#else
            result = file_copy((char *)tmp->filename, "tmp.bin");
#endif
            if (result != 0) {
                printf( "could not copy '%s' %d\n", tmp->filename, result );
            } else {
                printf( "File '%s' copied to 'tmp.bin'\n", tmp->filename);
            }
        }

        char *ptr;
        char* temp_address_copy = address_copy;

        while((ptr = strtok_r(temp_address_copy, delim, &temp_address_copy))) {
            int res = dogecoin_register_watch_address_with_node(ptr);
            printf("registered:     %d %s\n", res, ptr);
            uint64_t amount = dogecoin_get_balance(ptr);
            if (amount > 0) {
                char* amount_str = dogecoin_get_balance_str(ptr);
                printf("total:          %s\n", amount_str);
                unsigned int utxo_count = dogecoin_get_utxos_length(ptr);
                if (utxo_count) {
                    printf("utxo count:     %d\n", utxo_count);
                    unsigned int i = 1;
                    for (; i <= utxo_count; i++) {
                        printf("txid:           %s\n", dogecoin_get_utxo_txid_str(ptr, i));
                        printf("vout:           %d\n", dogecoin_get_utxo_vout(ptr, i));
                        char* utxo_amount_str = dogecoin_get_utxo_amount(ptr, i);
                        printf("amount:         %s\n", utxo_amount_str);
                        dogecoin_free(utxo_amount_str);
                    }
                }
                dogecoin_free(amount_str);
            }
            res = dogecoin_unregister_watch_address_with_node(ptr);
            printf("unregistered:   %s\n", res ? "true" : "false");
        }

        if ((file = fopen("tmp.bin", "r"))) {
            fclose(file);
#ifdef WIN32
            #include <winbase.h>
            char *tmp_filename = _strdup((char *)tmp->filename);
            char *filename = _strdup((char *)tmp->filename);
            replace_last_after_delim(filename, "\\", "tmp.bin");
            LPVOID message;
            result = DeleteFile(tmp->filename);
            if (!result) {
                FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&message, 0, NULL);
                printf("ERROR: %s\n", (char *)message);
            }
            result = rename(filename, tmp->filename);
            dogecoin_free(filename);
            dogecoin_free(tmp_filename);
#else
            result = rename("tmp.bin", tmp->filename);
#endif
            if( result != 0 ) {
                printf( "could not copy 'tmp.bin' %d\n", result );
            } else {
                printf( "File 'tmp.bin' copied to '%s'\n", tmp->filename);
            }
        }
        dogecoin_wallet_free(tmp);
        dogecoin_free(address_copy);
    }

    dogecoin_ecc_stop();
#endif
    } else {
        printf("Invalid command (use -?)\n");
        ret = EXIT_FAILURE;
        }
    return ret;
    }
