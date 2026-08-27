/**********************************************************************
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022-2023 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <dogecoin/arith_uint256.h>
#include <dogecoin/block.h>
#include <dogecoin/net.h>
#include <dogecoin/utils.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tx.h>

/**
 * The timer_cb function is called every 60 seconds to check if the node has been
 * connected for more than 5 minutes.
 * If it has, the node is disconnected
 *
 * @param node The node that the timer is being called on.
 * @param now The current time in seconds.
 *
 * @return static dogecoin_bool (uint8_t)
 */
static dogecoin_bool timer_cb(dogecoin_node *node, uint64_t *now)
{
    if (node->time_started_con + 60 < *now)
        dogecoin_node_disconnect(node);

    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
    return true;
}

/**
 * This function is called by the
 * logger when it needs to write to the log
 *
 * @param format The format string.
 *
 * @return 1
 */
DISABLE_WARNING_PUSH
DISABLE_WARNING(-Wunused-function)
static int default_write_log(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    return 1;
}
DISABLE_WARNING_POP

/**
 * It parses a command from the network
 *
 * @param node The node that received the message.
 * @param hdr The header of the message.
 * @param buf The buffer containing the message.
 *
 * @return Nothing.
 */
dogecoin_bool parse_cmd(struct dogecoin_node_ *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    (void)(node);
    (void)(hdr);
    (void)(buf);
    return true;
}

/**
 * We send a getheaders message to the node, and then we send a getdata message to the node
 *
 * @param node The node that received the message.
 * @param hdr The header of the message.
 * @param buf The buffer containing the message payload.
 *
 * @return Nothing.
 */
void postcmd(struct dogecoin_node_ *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    if (strcmp(hdr->command, "block") == 0)
    {
        dogecoin_block_header header;
        arith_uint256 chainwork = {0};
        if (!dogecoin_block_header_deserialize(&header, buf, node->nodegroup->chainparams, &chainwork)) return;

        uint32_t vsize;
        if (!deser_varlen(&vsize, buf)) return;
        unsigned int i;
        for (i = 0; i < vsize; i++)
        {
            dogecoin_tx *tx = dogecoin_tx_new(); //needs to be on the heep
            dogecoin_tx_deserialize(buf->p, buf->len, tx, NULL);

            dogecoin_tx_free(tx);
        }

        dogecoin_node_disconnect(node);
    }

    if (strcmp(hdr->command, "inv") == 0)
    {
        // directly create a getdata message
        cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, "getdata", buf->p, buf->len);

        uint32_t vsize;
        uint8_t hash[36];
        uint32_t type;
        if (!deser_varlen(&vsize, buf)) return;
        unsigned int i;
        for (i = 0; i < vsize; i++)
        {
            if (!deser_u32(&type, buf)) return;
            if (!deser_u256(hash, buf)) return;

        }

        /* send message */
        dogecoin_node_send(node, p2p_msg);

        /* cleanup */
        cstr_free(p2p_msg, true);
    }

    if (strcmp(hdr->command, "headers") == 0)
    {
        /* send getblock command */

        /* request some headers (from the genesis block) */
        vector_t *blocklocators = vector_new(1, NULL);
        uint256_t from_hash;
        utils_uint256_sethex("c7e47980df148701d04fb81a84acce85d8fb3556c7b1ff1cd021023b7c9f9593", from_hash); // height 428694
        uint256_t stop_hash;
        utils_uint256_sethex("1910002ddc9705c0799236589b91304404f45728f805bac7c94fc42ac0db1248", stop_hash); // height 428695

        vector_add(blocklocators, from_hash);

        cstring *getheader_msg = cstr_new_sz(256);
        dogecoin_p2p_msg_getheaders(blocklocators, stop_hash, getheader_msg);

        /* create p2p message */
        cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, "getblocks", getheader_msg->str, getheader_msg->len);
        cstr_free(getheader_msg, true);

        /* send message */
        dogecoin_node_send(node, p2p_msg);

        /* cleanup */
        vector_free(blocklocators, true);
        cstr_free(p2p_msg, true);
    }
}

/**
 * When a node's connection state changes, this function is called
 *
 * @param node The node that the connection state changed for.
 */
void node_connection_state_changed(struct dogecoin_node_ *node)
{
    (void)(node);
}

void handshake_done(struct dogecoin_node_ *node)
{
    /* make sure only one node is used for header sync */
    size_t i;
    for(i = 0; i < node->nodegroup->nodes->len; i++)
    {
        dogecoin_node *check_node = vector_idx(node->nodegroup->nodes, i);
        if ((check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC)
            return;
    }

    // request some headers (from the genesis block)
    vector_t *blocklocators = vector_new(1, NULL);
    vector_add(blocklocators, (void *)node->nodegroup->chainparams->genesisblockhash);

    cstring *getheader_msg = cstr_new_sz(256);
    dogecoin_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    /* create p2p message */
    cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, "getheaders", getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    /* send message */
    node->state |= NODE_HEADERSYNC;
    dogecoin_node_send(node, p2p_msg);

    /* cleanup */
    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

void test_net_basics_plus_download_block()
{

    vector_t *ips = vector_new(10, free);
    unsigned int seed_index;
    /* dogecoin_chainparams has up to 8 dns seeds */
    for (seed_index = 0; seed_index < 8; seed_index++) {
        const dogecoin_dns_seed seed = dogecoin_chainparams_test.dnsseeds[seed_index];
        if (strlen(seed.domain) == 0) {
            continue;
        }
        dogecoin_get_peers_from_dns(seed.domain, ips, dogecoin_chainparams_test.default_port, AF_INET);
        unsigned int i;
        for (i = 0; i < ips->len; i++) {
            debug_print("dns seed ip %d: %s\n", i, (char *)vector_idx(ips, i));
        }
        /* exit if we get peers from a seed */
        if (ips->len > 0) {
            break;
        }
    }
    vector_free(ips, true);

    dogecoin_node *node_wrong = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(node_wrong, "0.0.0.1:1"), true);

    dogecoin_node *node_timeout_direct = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(node_timeout_direct, "127.0.0.1:1234"), true);

    dogecoin_node *node_timeout_indirect = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(node_timeout_indirect, "8.8.8.8:44556"), true);

    dogecoin_node *node = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(node, "138.201.55.219:44556"), true);

    dogecoin_node_group* group = dogecoin_node_group_new(NULL);
    group->desired_amount_connected_nodes = 1;

    dogecoin_node_group_add_node(group, node_wrong);
    dogecoin_node_group_add_node(group, node_timeout_direct);
    dogecoin_node_group_add_node(group, node_timeout_indirect);
    dogecoin_node_group_add_node(group, node);

    group->periodic_timer_cb = timer_cb;

    group->log_write_cb = net_write_log_null;
    group->parse_cmd_cb = parse_cmd;
    group->postcmd_cb = postcmd;
    group->node_connection_state_changed_cb = node_connection_state_changed;
    group->handshake_done_cb = handshake_done;

    dogecoin_node_group_connect_next_nodes(group);

    dogecoin_node_group_event_loop(group);

    dogecoin_node_group_free(group); //will also free the nodes structures from the heap
}

/* Covers the peer-recovery state machine without touching a socket: the retry
   backoff schedule, and which addresses maintenance makes eligible again.
   dogecoin_node_group_maintenance() ends in connect_next_nodes(), which only
   arms async connects, so nothing here dials as long as the loop is not run. */
void test_net_peer_recovery()
{
    /* Backoff doubles from the base and clamps at the max. */
    dogecoin_node* n = dogecoin_node_new();
    uint64_t expected[] = { 30, 60, 120, 240, 300, 300, 300 };
    unsigned int i;
    for (i = 0; i < sizeof expected / sizeof expected[0]; i++) {
        uint64_t before = (uint64_t)time(NULL);
        u_assert_uint32_eq(n->conn_failures, i);
        dogecoin_node_arm_retry(n);
        u_assert_true(n->retry_at >= before + expected[i]);
        u_assert_true(n->retry_at <= before + expected[i] + 2);
    }
    u_assert_uint32_eq((uint32_t)expected[0], DOGECOIN_RETRY_BACKOFF_BASE_S);
    u_assert_uint32_eq((uint32_t)expected[4], DOGECOIN_RETRY_BACKOFF_MAX_S);
    dogecoin_node_free(n);

    /* At target, maintenance is a no-op: a due address stays disconnected. */
    dogecoin_node_group* group = dogecoin_node_group_new(NULL);
    group->desired_amount_connected_nodes = 1;

    dogecoin_node* connected = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(connected, "192.0.2.1:22556"), true);
    dogecoin_node_group_add_node(group, connected);
    connected->state |= NODE_CONNECTED;

    dogecoin_node* due = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(due, "192.0.2.2:22556"), true);
    dogecoin_node_group_add_node(group, due);
    due->state |= NODE_DISCONNECTED | NODE_ERRORED;
    due->retry_at = 0;

    dogecoin_node_group_maintenance(group);
    u_assert_int_eq((due->state & NODE_DISCONNECTED) == NODE_DISCONNECTED, true);

    /* Below target, a due address is revived and its error bits cleared, while
       one whose backoff has not elapsed is left alone. */
    connected->state &= ~NODE_CONNECTED;
    group->desired_amount_connected_nodes = 4;

    dogecoin_node* waiting = dogecoin_node_new();
    u_assert_int_eq(dogecoin_node_set_ipport(waiting, "192.0.2.3:22556"), true);
    dogecoin_node_group_add_node(group, waiting);
    waiting->state |= NODE_DISCONNECTED | NODE_ERRORED;
    waiting->retry_at = (uint64_t)time(NULL) + 600;

    dogecoin_node_group_maintenance(group);

    u_assert_int_eq((due->state & NODE_DISCONNECTED) == NODE_DISCONNECTED, false);
    u_assert_int_eq((due->state & NODE_ERRORED) == NODE_ERRORED, false);
    u_assert_int_eq((waiting->state & NODE_DISCONNECTED) == NODE_DISCONNECTED, true);

    dogecoin_node_group_free(group);
}
