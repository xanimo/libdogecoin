/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <dogecoin/block.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/headersdb.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/net/net.h>
#include <dogecoin/net/spv.h>
#include <dogecoin/net/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

/* The code below is a simple way to set a maximum response time for the server. */
static const unsigned int HEADERS_MAX_RESPONSE_TIME = 60;
/* The code below is checking if the time difference between the current time and the last time the
state was changed is greater than 5 seconds. */
static const unsigned int MIN_TIME_DELTA_FOR_STATE_CHECK = 5;
/* The code below is a function that is used to calculate the number of blocks to deduct from the start
of the scan to get the start of the scan. */
static const unsigned int BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM = 5;
/* The code below is a simple way to calculate the number of blocks in 15 minutes. */
static const unsigned int BLOCKS_DELTA_IN_S = 900;
/* The code below is checking if the number of nodes at the same height is equal to 2. */
static const unsigned int COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT = 2;

/* A timer callback function. */
static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now);
/* This is the function that is called when a new message is received from the network. */
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf);
/* This is the function that is called when the handshake is done. */
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node);

/**
 * The function sets the nodegroup's postcmd_cb to dogecoin_net_spv_post_cmd,
 * the nodegroup's handshake_done_cb to dogecoin_net_spv_node_handshake_done,
 * the nodegroup's node_connection_state_changed_cb to NULL, and the
 * nodegroup's periodic_timer_cb to dogecoin_net_spv_node_timer_callback
 * 
 * @param nodegroup The nodegroup to set the callbacks for.
 */
void dogecoin_net_set_spv(dogecoin_node_group *nodegroup)
{
    // printf("dogecoin_net_set_spv\n");
    nodegroup->postcmd_cb = dogecoin_net_spv_post_cmd;
    nodegroup->handshake_done_cb = dogecoin_net_spv_node_handshake_done;
    nodegroup->node_connection_state_changed_cb = NULL;
    nodegroup->periodic_timer_cb = dogecoin_net_spv_node_timer_callback;
}

/**
 * The function creates a new dogecoin_spv_client object and initializes it
 * 
 * @param params The chainparams struct that we created earlier.
 * @param debug If true, the node will print out debug messages to stdout.
 * @param headers_memonly If true, the headers database will not be loaded from disk.
 * 
 * @return A pointer to a dogecoin_spv_client object.
 */
dogecoin_spv_client* dogecoin_spv_client_new(const dogecoin_chainparams *params, dogecoin_bool debug, dogecoin_bool headers_memonly)
{
    // printf("dogecoin_spv_client_new\n");
    dogecoin_spv_client* client;
    client = dogecoin_calloc(1, sizeof(*client));

    client->last_headersrequest_time = 0; //!< time when we requested the last header package
    client->last_statecheck_time = 0;
    client->oldest_item_of_interest = time(NULL)-5*60;
    client->stateflags = SPV_HEADER_SYNC_FLAG;

    client->chainparams = params;

    client->nodegroup = dogecoin_node_group_new(params);
    client->nodegroup->ctx = client;
    client->nodegroup->desired_amount_connected_nodes = 8; /* TODO */

    dogecoin_net_set_spv(client->nodegroup);

    if (debug) {
        client->nodegroup->log_write_cb = net_write_log_printf;
    }

    if (params == &dogecoin_chainparams_main || params == &dogecoin_chainparams_test) {
        client->use_checkpoints = true;
    }
    client->headers_db = &dogecoin_headers_db_interface_file;
    client->headers_db_ctx = client->headers_db->init(params, headers_memonly);

    // set callbacks
    client->header_connected = NULL;
    client->called_sync_completed = false;
    client->sync_completed = NULL;
    client->header_message_processed = NULL;
    client->sync_transaction = NULL;

    return client;
}

/**
 * It adds peers to the nodegroup.
 * 
 * @param client the dogecoin_spv_client object
 * @param ips A comma-separated list of IPs or seeds to connect to.
 */
void dogecoin_spv_client_discover_peers(dogecoin_spv_client* client, const char *ips)
{
    dogecoin_node_group_add_peers_by_ip_or_seed(client->nodegroup, ips);
}

/**
 * The function loops through all the nodes in the node group and connects to the next nodes in the
 * node group
 * 
 * @param client The dogecoin_spv_client object.
 */
void dogecoin_spv_client_runloop(dogecoin_spv_client* client)
{
    /* This code is connecting the next nodes in the node group. */
    dogecoin_node_group_connect_next_nodes(client->nodegroup);
    /* The code below is a loop that runs the event loop for the dogecoin node group. */
    dogecoin_node_group_event_loop(client->nodegroup);
}

/**
 * It frees the memory allocated for the client
 * 
 * @param client The client object to be freed.
 * 
 * @return Nothing.
 */
void dogecoin_spv_client_free(dogecoin_spv_client *client)
{
    if (!client)
        return;

    /* Checking if the client has a headers database. */
    if (client->headers_db)
    {
        client->headers_db->free(client->headers_db_ctx);
        client->headers_db_ctx = NULL;
        client->headers_db = NULL;
    }

    if (client->nodegroup) {
        dogecoin_node_group_free(client->nodegroup);
        client->nodegroup = NULL;
    }

    dogecoin_free(client);
}

/**
 * Loads the headers database from a file
 * 
 * @param client the client object
 * @param file_path The path to the headers database file.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_spv_client_load(dogecoin_spv_client *client, const char *file_path)
{
    if (!client)
        return false;

    if (!client->headers_db)
        return false;

    return client->headers_db->load(client->headers_db_ctx, file_path);

}

/**
 * If we are in the header sync state, we request headers from a random node
 * 
 * @param node the node that we are checking
 * @param now The current time in seconds.
 */
void dogecoin_net_spv_periodic_statecheck(dogecoin_node *node, uint64_t *now)
{
    /* statecheck logic */
    /* ================ */

    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;

    client->nodegroup->log_write_cb("Statecheck: amount of connected nodes: %d\n", dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED));

    /* check if the node chosen for NODE_HEADERSYNC during SPV_HEADER_SYNC has stalled */
    if (client->last_headersrequest_time > 0 && *now > client->last_headersrequest_time)
    {
        int64_t timedetla = *now - client->last_headersrequest_time;
        /* This code is checking if the time difference between the current time and the time of the
        last request is greater than the maximum response time. */
        if (timedetla > HEADERS_MAX_RESPONSE_TIME)
        {
            client->nodegroup->log_write_cb("No header response in time (used %d) for node %d\n", timedetla, node->nodeid);
            /* disconnect the node if we haven't got a header after requesting some with a getheaders message */
            node->state &= ~NODE_HEADERSYNC;
            dogecoin_node_disconnect(node);
            client->last_headersrequest_time = 0;
            dogecoin_net_spv_request_headers(client);
        }
    }
    /* Checking if the time of the last request is greater than the current time. */
    if (node->time_last_request > 0 && *now > node->time_last_request)
    {
        // we are downloading blocks from this peer
        int64_t timedetla = *now - node->time_last_request;

        client->nodegroup->log_write_cb("No block response in time (used %d) for node %d\n", timedetla, node->nodeid);
        /* This code is checking if the time difference between the current time and the time of the
        last request is greater than the maximum response time. */
        if (timedetla > HEADERS_MAX_RESPONSE_TIME)
        {
            /* disconnect the node if a blockdownload has stalled */
            dogecoin_node_disconnect(node);
            node->time_last_request = 0;
            /* The code below is requesting the headers of the blockchain from the dogecoin network. */
            dogecoin_net_spv_request_headers(client);
        }
    }

    /* check if we need to sync headers from a different peer */
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG)
    {
        /* This code is requesting the headers of the blockchain from the dogecoin network. */
        dogecoin_net_spv_request_headers(client);
    }
    /* headers sync should be done at this point */

    /* Checking to see if the client has been idle for more than
        the timeout period. If it has, it will send a message to the
        server to see if the client is still alive. */
    client->last_statecheck_time = *now;
}

/**
 * This function is called by the dogecoin_node_timer_callback function. 
 * 
 * It checks if the last_statecheck_time is greater than the minimum time delta for state checks. 
 * 
 * If it is, it calls the dogecoin_net_spv_periodic_statecheck function. 
 * 
 * The dogecoin_net_spv_periodic_statecheck function checks if the node is connected to the network. 
 * 
 * If it is, it checks if the node is synced. 
 * 
 * If it is, it checks if the node is in the mempool. 
 * 
 * If it is, it checks if the node is in the blockchain. 
 * 
 * If it is, it checks if the node is in the mempool. 
 * 
 * If it is, it checks if the node is in the blockchain. 
 * 
 * If it is, it checks if the node is in the
 * 
 * @param node The node that the timer is being called on.
 * @param now the current time in seconds since the epoch
 * 
 * @return A boolean value.
 */
static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now)
{
    /* Creating a new dogecoin_spv_client object and assigning it to the node's nodegroup's ctx. */
    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;

    /* Checking if the client has been idle for a certain amount of time. */
    if (client->last_statecheck_time + MIN_TIME_DELTA_FOR_STATE_CHECK < *now)
    {
        /* do a state check only every <n> seconds */
        dogecoin_net_spv_periodic_statecheck(node, now);
    }

    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
    return true;
}

/**
 * Fill up the blocklocators vector with the blocklocators from the headers database
 * 
 * @param client the spv client
 * @param blocklocators a vector of block hashes that we want to scan from
 * 
 * @return The blocklocators are being returned.
 */
void dogecoin_net_spv_fill_block_locator(dogecoin_spv_client *client, vector *blocklocators) {
    int64_t min_timestamp = client->oldest_item_of_interest - BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S; /* ensure we going back ~144 blocks */
    if (client->headers_db->getchaintip(client->headers_db_ctx)->height == 0) {
        /* Checking if the oldest item of interest is older than the number of blocks that we want to
        deduct from the start of the scan. */
        if (client->use_checkpoints && client->oldest_item_of_interest > BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) {
            const dogecoin_checkpoint *checkpoint = memcmp(client->chainparams, &dogecoin_chainparams_main, 4) == 0 ? &dogecoin_mainnet_checkpoint_array : &dogecoin_testnet_checkpoint_array;
            size_t mainnet_checkpoint_size = sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]);
            size_t testnet_checkpoint_size = sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]);
            size_t length = memcmp(client->chainparams, &dogecoin_chainparams_main, 8) == 0 ? mainnet_checkpoint_size : testnet_checkpoint_size;
            int i;
            for (i = length - 1; i >= 0; i--) {
                printf("i: %d\n", i);
                printf("hash: %s\n", checkpoint[i].hash);
                printf("timestamp: %d\n", checkpoint[i].timestamp);
                printf("min_timestamp: %ld\n", min_timestamp);
                if (checkpoint[i].timestamp < min_timestamp) {
                    uint256 *hash = dogecoin_calloc(1, sizeof(uint256));
                    utils_uint256_sethex((char *)checkpoint[i].hash, (uint8_t *)hash);
                    vector_add(blocklocators, (void *)hash);
                    if (!client->headers_db->has_checkpoint_start(client->headers_db_ctx)) {
                        client->headers_db->set_checkpoint_start(client->headers_db_ctx, *hash, checkpoint[i].height);
                    }
                }
            }
            if (blocklocators->len > 0) return; // return if we could fill up the blocklocator with checkpoints 
        }
        uint256 *hash = dogecoin_calloc(1, sizeof(uint256));
        /* Copying the genesis block hash into the hash variable. */
        memcpy(hash, &client->chainparams->genesisblockhash, sizeof(uint256));
        /* Adding the hash of the block to the blocklocators vector. */
        vector_add(blocklocators, (void *)hash);
        client->nodegroup->log_write_cb("Setting blocklocator with genesis block\n");
    } else {
        /* Filling the blocklocator_tip with the blocklocators. */
        client->headers_db->fill_blocklocator_tip(client->headers_db_ctx, blocklocators);
    }
}

/**
 * This function is called when a node is in headers sync state. It will request the next block headers
 * from the node
 * 
 * @param node The node that is requesting headers or blocks.
 * @param blocks boolean, true if we want to request blocks, false if we want to request headers
 */
void dogecoin_net_spv_node_request_headers_or_blocks(dogecoin_node *node, dogecoin_bool blocks)
{
    // printf("dogecoin_net_spv_node_request_headers_or_blocks\n");
    // request next headers
    vector *blocklocators = vector_new(1, free);

    dogecoin_net_spv_fill_block_locator((dogecoin_spv_client *)node->nodegroup->ctx, blocklocators);

    cstring *getheader_msg = cstr_new_sz(256);
    dogecoin_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    /* create p2p message */
    cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, (blocks ? DOGECOIN_MSG_GETBLOCKS : DOGECOIN_MSG_GETHEADERS), getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    /* send message */
    dogecoin_node_send(node, p2p_msg);
    node->state |= ( blocks ? NODE_BLOCKSYNC : NODE_HEADERSYNC);

    /* remember last headers request time */
    if (blocks) {
        node->time_last_request = time(NULL);
    } else {
        /* This is the code that is called when a new block is received. */
        ((dogecoin_spv_client*)node->nodegroup->ctx)->last_headersrequest_time = time(NULL);
    }

    /* cleanup */
    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

/**
 * If we have not yet reached the height of the blockchain tip, we request headers from a peer. If we
 * have reached the height of the blockchain tip, we request blocks from a peer
 * 
 * @param client the spv client
 * 
 * @return dogecoin_bool
 */
dogecoin_bool dogecoin_net_spv_request_headers(dogecoin_spv_client *client)
{
    /* make sure only one node is used for header sync */
    size_t i;
    for(i = 0; i < client->nodegroup->nodes->len; ++i)
    {
        
        dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
        /* The code below is checking to see if the node is in the headersync or blocksync state and if
        it is connected. If it is, then it returns true. */
        if (((check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC || (check_node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC) && (check_node->state & NODE_CONNECTED) == NODE_CONNECTED) { return true; }
    }

    /* We are not downloading headers at this point */
    /* try to request headers from a peer where the version handshake has been done */
    dogecoin_bool new_headers_available = false;
    unsigned int nodes_at_same_height = 0;
    /* Checking if the timestamp of the latest block is greater than the oldest item of interest minus
    the block gap to deduct from the start scan from. */
    if (client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp < client->oldest_item_of_interest - (BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S))
    {
        size_t i;
        for(i = 0; i < client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            /* Checking if the node is connected and if it has completed the version handshake. */
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                /* Checking if the best known height of the node is greater than the current height of
                the blockchain. */
                if (check_node->bestknownheight > client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    dogecoin_net_spv_node_request_headers_or_blocks(check_node, false);
                    new_headers_available = true;
                    return new_headers_available;
                /* Checking if the best known height of the node is equal to the current height of the blockchain. */
                } else if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
            }
        }
    }

    /* Checking if the new headers are available and if there are any nodes connected to the nodegroup. */
    if (!new_headers_available && dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED) > 0) {
        // try to fetch blocks if no new headers are available but connected nodes are reachable
        size_t i;
        for(i = 0; i< client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            /* Checking if the node is connected and if it has completed the version handshake. */
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                /* Checking if the best known height of the node is greater than the current height of
                the blockchain. */
                if (check_node->bestknownheight > client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    dogecoin_net_spv_node_request_headers_or_blocks(check_node, true);
                    return true;
                /* Checking if the best known height of the node is equal to the current tip height. */
                } else if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
            }
        }
    }

    /* Checking if the number of nodes at the same height is greater than or equal to the number of
    nodes at the same height and if the client has not already called the sync completed function
    and if the sync completed function has been called. */
    if (nodes_at_same_height >= COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT && !client->called_sync_completed && client->sync_completed)
    {
        client->sync_completed(client);
        client->called_sync_completed = true;
    }

    /* we could not request more headers, need more peers to connect to */
    return false;
}

/**
 * When the handshake is done, we request the headers
 * 
 * @param node The node that just completed the handshake.
 */
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node)
{
    dogecoin_net_spv_request_headers((dogecoin_spv_client*)node->nodegroup->ctx);
}

/**
 * The function is called when a new message is received from a peer
 * 
 * @param node
 * @param hdr
 * @param buf
 * 
 * @return Nothing.
 */
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf)
{

    /* Creating a new dogecoin_spv_client object and assigning it to the node's nodegroup's ctx. */
    dogecoin_spv_client *client = (dogecoin_spv_client *)node->nodegroup->ctx;

    /* Checking if the message is an INV message and if the node is in the block sync state. */
    if (strcmp(hdr->command, DOGECOIN_MSG_INV) == 0 && (node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC)
    {
        struct const_buffer original_inv = { buf->p, buf->len };
        uint32_t varlen;
        deser_varlen(&varlen, buf);
        dogecoin_bool contains_block = false;

        client->nodegroup->log_write_cb("Get inv request with %d items\n", varlen);

        /* Checking if the inv contains a block. If it does, it will set the contains_block flag to true. */
        unsigned int i;
        for (i = 0; i < varlen; i++)
        {
            uint32_t type;
            deser_u32(&type, buf);
            if (type == DOGECOIN_INV_TYPE_BLOCK)
                contains_block = true;

            /* skip the hash, we are going to directly use the inv-buffer for the getdata */
            /* this means we don't support invs contanining blocks and txns as a getblock answer */
            if (type == DOGECOIN_INV_TYPE_BLOCK) {
                /* Deserializing the last_requested_inv field of the node struct. */
                deser_u256(node->last_requested_inv, buf);
            } else {
                /* Skipping the first 32 bytes of the buffer. */
                deser_skip(buf, 32);
            }
        }

        /* Requesting the blocks that are in the inv message. */
        if (contains_block)
        {
            node->time_last_request = time(NULL);

            /* request the blocks */
            client->nodegroup->log_write_cb("Requesting %d blocks\n", varlen);
            /* Creating a new message object and setting the magic number, command, and payload. */
            cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, DOGECOIN_MSG_GETDATA, original_inv.p, original_inv.len);
            /* Sending a message to the node. */
            dogecoin_node_send(node, p2p_msg);
            /* The code below is freeing the memory allocated for the p2p_msg. */
            cstr_free(p2p_msg, true);

            // if (varlen >= 500) {
            //     /* directly request more blocks */
            //     /* not sure if this is clever if we want to download, as example, the complete chain */
            //     dogecoin_net_spv_node_request_headers_or_blocks(node, true);
            // }
        }
    }
    /* The code below is checking if the command is equal to the string DOGECOIN_MSG_BLOCK. If it is,
    it will check if the command is equal to the string DOGECOIN_MSG_BLOCK. If it is, it will check
    if the command is equal to the string DOGECOIN_MSG_BLOCK. If it is, it will check if the command
    is equal to the string DOGECOIN_MSG_BLOCK. If it is, it will check if the command is equal to
    the */
    if (strcmp(hdr->command, DOGECOIN_MSG_BLOCK) == 0)
    {
        dogecoin_bool connected;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
        printf("dogecoin_blockindex: pindex->height %u\n", pindex->height);
        printf("dogecoin_blockindex: pindex->hash %s\n", pindex->hash);
        printf("dogecoin_blockindex: pindex->prev->height %u\n", pindex->prev->height);
        /* deserialize the p2p header */
        if (!pindex) {
            return;
        }

        uint32_t amount_of_txs;
        if (!deser_varlen(&amount_of_txs, buf)) {
            return;
        }

        // flag off the block request stall check
        node->time_last_request = time(NULL);

        // for now, turn of stall checks if we are near the tip
        if (pindex->header.timestamp > node->time_last_request - 30*60) {
            printf("for now, turn of stall checks if we are near the tip");
            node->time_last_request = 0;
        }

        /* for now, only scan if the block could be connected on top */
        if (connected) {
            /* The code below is a callback function that is called when the header is connected. */
            if (client->header_connected) { client->header_connected(client); }
            time_t lasttime = pindex->header.timestamp;
            printf("Downloaded new block with size %d at height %d (%s)\n", hdr->data_len, pindex->height, ctime(&lasttime));
            uint64_t start = time(NULL);
            printf("Start parsing %d transactions...\n", amount_of_txs);

            size_t consumedlength = 0;
            /* Creating a random number of transactions to be added to the block. */
            unsigned int i;
            for (i = 0; i < amount_of_txs; i++)
            {
                dogecoin_tx* tx = dogecoin_tx_new();
                /* Deserializing the transaction. */
                if (!dogecoin_tx_deserialize(buf->p, buf->len, tx, &consumedlength, true)) {
                    printf("Error deserializing transaction\n");
                }
                /* The code below is skipping the bytes that have already been read. */
                deser_skip(buf, consumedlength);

                /* send info to possible callback */
                if (client->sync_transaction) { client->sync_transaction(client->sync_transaction_ctx, tx, i, pindex); }

                dogecoin_tx_free(tx);
            }
            printf("done (took %llu secs)\n", (unsigned long long)(time(NULL) - start));
        } else {
            fprintf(stderr, "Could not connect block on top of the chain\n");
        }

        if (dogecoin_hash_equal(node->last_requested_inv, pindex->hash)) {
            // last requested block reached, consider stop syncing
            if (!client->called_sync_completed && client->sync_completed) { client->sync_completed(client); client->called_sync_completed = true; }
        }
    }
    /* Checking if the header is connected to the blockchain.
    If it is connected, it will call the header_connected callback function.
    If it is not connected, it will mark the node as missbehaving. */
    if (strcmp(hdr->command, DOGECOIN_MSG_HEADERS) == 0)
    {
        uint32_t amount_of_headers;
        if (!deser_varlen(&amount_of_headers, buf)) return;
        uint64_t now = time(NULL);
        client->nodegroup->log_write_cb("Got %d headers (took %d s) from node %d\n", amount_of_headers, now - client->last_headersrequest_time, node->nodeid);

        // flag off the request stall check
        client->last_headersrequest_time = 0;

        unsigned int connected_headers = 0;
        unsigned int i;
        for (i = 0; i < amount_of_headers; i++)
        {
            dogecoin_bool connected;
            dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
            /* deserialize the p2p header */
            if (!pindex)
            {
                printf("header deserialization failed!\n");
                client->nodegroup->log_write_cb("Header deserialization failed (node %d)\n", node->nodeid);
                return;
            }
            /* skip tx count */
            if (!deser_skip(buf, 1)) {
                printf("skip tx count!\n");
                client->nodegroup->log_write_cb("Header deserialization (tx count skip) failed (node %d)\n", node->nodeid);
                return;
            }
            
            if (!connected)
            {
                /* error, header sequence missmatch
                   mark node as missbehaving */
                client->nodegroup->log_write_cb("Got invalid headers (not in sequence) from node %d\n", node->nodeid);
                node->state &= ~NODE_HEADERSYNC;
                dogecoin_node_misbehave(node);

                /* see if we can fetch headers from a different peer */
                dogecoin_net_spv_request_headers(client);
            } else {
                if (client->header_connected) { client->header_connected(client); }
                connected_headers++;
                /* Checking if the block timestamp is greater than the oldest item of interest minus
                the block gap to deduct to start the scan from. */
                if (pindex->header.timestamp > client->oldest_item_of_interest - (BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) ) {

                    /* we should start loading block from this point */
                    client->stateflags &= ~SPV_HEADER_SYNC_FLAG;
                    client->stateflags |= SPV_FULLBLOCK_SYNC_FLAG;
                    node->state &= ~NODE_HEADERSYNC;
                    node->state |= NODE_BLOCKSYNC;

                    /* Logging the start of the block loading process. */
                    client->nodegroup->log_write_cb("start loading block from node %d at height %d at time: %ld\n", node->nodeid, client->headers_db->getchaintip(client->headers_db_ctx)->height, client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp);
                    /* This code is requesting the headers or blocks from the dogecoin network. */
                    dogecoin_net_spv_node_request_headers_or_blocks(node, true);

                    /* ignore the rest of the headers */
                    /* we are going to request blocks now */
                    break;
                }
            }
        }
        /* Checking to see if the client has a chaintip. */
        dogecoin_blockindex *chaintip = client->headers_db->getchaintip(client->headers_db_ctx);

        client->nodegroup->log_write_cb("Connected %d headers\n", connected_headers);
        client->nodegroup->log_write_cb("Chaintip at height %d\n", chaintip->height);

        /* call the header message processed callback and allow canceling the further logic commands */
        if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
            return;

        /* Checking if the node is synced with the blockchain. */
        if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
        {
            /* peer sent maximal amount of headers, very likely, there will be more */
            time_t lasttime = chaintip->header.timestamp;
            client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
            dogecoin_net_spv_node_request_headers_or_blocks(node, false);
        }
        /* headers download seems to be completed */
        /* we should have switched to block request if the oldest_item_of_interest was set correctly */
    }
    if (strcmp(hdr->command, DOGECOIN_MSG_CFILTER) == 0)
    {
        client->nodegroup->log_write_cb("Got DOGECOIN_MSG_CFILTER\n");
    }
    if (strcmp(hdr->command, DOGECOIN_MSG_CFHEADERS) == 0)
    {
        client->nodegroup->log_write_cb("Got DOGECOIN_MSG_CFHEADERS\n");
    }
    if (strcmp(hdr->command, DOGECOIN_MSG_CFCHECKPT) == 0)
    {
        client->nodegroup->log_write_cb("Got DOGECOIN_MSG_CFCHECKPT\n");
    }
}
