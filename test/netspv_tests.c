#include "utest.h"
#include <unistd.h>

#include <dogecoin/block.h>
#include <dogecoin/net/net.h>
#include <dogecoin/net/spv.h>

void test_spv_sync_completed(dogecoin_spv_client* client) {
    printf("Sync completed, at height %d\n", client->headers_db->getchaintip(client->headers_db_ctx)->height);
    dogecoin_node_group_shutdown(client->nodegroup);
}

dogecoin_bool test_spv_header_message_processed(struct dogecoin_spv_client_ *client, dogecoin_node *node, dogecoin_blockindex *newtip) {
    UNUSED(client);
    UNUSED(node);
    if (newtip) {
        printf("New headers tip height %d\n", newtip->height);
    }
    return true;
}

void test_netspv()
{
    /* Deleting the file `headers.db` if it exists. */
    unlink("headers.db");
    /* It creates a new client object. */
    dogecoin_spv_client* client = dogecoin_spv_client_new(&dogecoin_chainparams_test, false, false);
    /* This is a callback function that is called when a new header is received. */
    client->header_message_processed = test_spv_header_message_processed;
    /* This is a callback function that is called when the sync is completed. */
    client->sync_completed = test_spv_sync_completed;

    /* It loads the headers database from the file `headers.db`. */
    dogecoin_spv_client_load(client, "headers.db");

    printf("Discover peers...");
    /* Discovering peers. */
    dogecoin_spv_client_discover_peers(client, NULL);
    printf("done\n");
    printf("Start interacting with the p2p network...\n");
    /* Starting the client. */
    dogecoin_spv_client_runloop(client);
    dogecoin_spv_client_free(client);
}
