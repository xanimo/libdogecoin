/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * SMPV (Simplified Mempool Payment Verification) Test Suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/smpv.h>
#include <dogecoin/chainparams.h>

/* Test data */
static const char* TEST_ADDRESS_1 = "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP";
static const char* TEST_ADDRESS_2 = "D8Y66wE9nOtW8WnU0Xs7Rd5cC9i4kL3nQ";
static const char* TEST_RAW_TX =
    "0100000001a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890000000006a47304402201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef02201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef01210234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456ffffffff0100e1f505000000001976a9141234567890abcdef1234567890abcdef1234567890abcdef88ac00000000";

/* Test callback function */
static void test_tx_callback(const dogecoin_smpv_tx* tx, const char* address, void* user_data) {
    (void)user_data; /* Suppress unused parameter warning */
    debug_print("%s", "  Transaction callback received\n");
    debug_print("    TXID: %s\n", tx->txid ? tx->txid : "NULL");
    debug_print("    Address: %s\n", address ? address : "NULL");
    debug_print("    Size: %llu bytes\n", (unsigned long long)tx->size);
    debug_print("    Timestamp: %llu\n", (unsigned long long)tx->timestamp);
}

/* Test SMPV client creation and destruction */
void test_smpv_client_creation() {
    debug_print("%s", "Testing SMPV client creation...\n");

    /* Test with mainnet */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client\n");
        return;
    }

    if (client->chain_params != &dogecoin_chainparams_main) {
        debug_print("%s", "  Wrong chain params\n");
        return;
    }

    if (client->watcher_count != 0) {
        debug_print("%s", "  Wrong initial watcher count\n");
        return;
    }

    if (client->mempool_tx_count != 0) {
        debug_print("%s", "  Wrong initial tx count\n");
        return;
    }

    if (client->is_running != false) {
        debug_print("%s", "  Should not be running initially\n");
        return;
    }

    debug_print("%s", "  Client created successfully\n");

    /* Test with testnet */
    dogecoin_smpv_client* testnet_client = dogecoin_smpv_client_new(&dogecoin_chainparams_test);
    if (!testnet_client) {
        debug_print("%s", "  Failed to create testnet client\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (testnet_client->chain_params != &dogecoin_chainparams_test) {
        debug_print("%s", "  Wrong testnet chain params\n");
        dogecoin_smpv_client_free(client);
        dogecoin_smpv_client_free(testnet_client);
        return;
    }

    debug_print("%s", "  Testnet client created successfully\n");

    /* Test with NULL chain params */
    dogecoin_smpv_client* null_client = dogecoin_smpv_client_new(NULL);
    if (null_client) {
        debug_print("%s", "  Should not create client with NULL params\n");
        dogecoin_smpv_client_free(client);
        dogecoin_smpv_client_free(testnet_client);
        return;
    }

    debug_print("%s", "  NULL chain params handled correctly\n");

    /* Clean up */
    dogecoin_smpv_client_free(client);
    dogecoin_smpv_client_free(testnet_client);

    debug_print("%s", "  SMPV client creation test passed\n\n");
}

/* Test address watching functionality */
void test_address_watching() {
    debug_print("%s", "Testing address watching functionality...\n");

    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client\n");
        return;
    }

    /* Test adding addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        debug_print("%s", "  Failed to add first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->watcher_count != 1) {
        debug_print("%s", "  Wrong watcher count after adding first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Added first address\n");

    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        debug_print("%s", "  Failed to add second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->watcher_count != 2) {
        debug_print("%s", "  Wrong watcher count after adding second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Added second address\n");

    /* Test adding duplicate address */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        debug_print("%s", "  Should handle duplicate address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->watcher_count != 2) {
        debug_print("%s", "  Watcher count should not change for duplicate\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Duplicate address handled correctly\n");

    /* Test getting watcher */
    dogecoin_smpv_watcher* watcher = dogecoin_smpv_get_watcher(client, TEST_ADDRESS_1);
    if (!watcher) {
        debug_print("%s", "  Failed to get watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (strcmp(watcher->address, TEST_ADDRESS_1) != 0) {
        debug_print("%s", "  Wrong watcher address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (watcher->is_active != true) {
        debug_print("%s", "  Watcher should be active\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Retrieved watcher successfully\n");

    /* Test getting non-existent watcher */
    watcher = dogecoin_smpv_get_watcher(client, "D9Z77xF0oPvX9XnV1Yt8Se6dD0j5lM4oR");
    if (watcher) {
        debug_print("%s", "  Should not find non-existent watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Non-existent watcher handled correctly\n");

    /* Test removing address */
    if (!dogecoin_smpv_remove_watcher(client, TEST_ADDRESS_1)) {
        debug_print("%s", "  Failed to remove address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->watcher_count != 1) {
        debug_print("%s", "  Wrong watcher count after removal\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Removed address successfully\n");

    /* Test removing non-existent address */
    if (dogecoin_smpv_remove_watcher(client, "D9Z77xF0oPvX9XnV1Yt8Se6dD0j5lM4oR")) {
        debug_print("%s", "  Should not remove non-existent address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Non-existent address removal handled correctly\n");

    /* Test with NULL parameters */
    if (dogecoin_smpv_add_watcher(NULL, TEST_ADDRESS_1)) {
        debug_print("%s", "  Should not add watcher with NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_add_watcher(client, NULL)) {
        debug_print("%s", "  Should not add watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  NULL parameter handling correct\n");

    dogecoin_smpv_client_free(client);

    debug_print("%s", "  Address watching test passed\n\n");
}

/* Test transaction processing */
void test_transaction_processing() {
    debug_print("%s", "Testing transaction processing...\n");

    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client\n");
        return;
    }

    /* Add test addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        debug_print("%s", "  Failed to add test address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        debug_print("%s", "  Failed to add second test address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Added test addresses\n");

    /* Test transaction processing with callback */
    if (!dogecoin_smpv_process_tx(client, TEST_RAW_TX, test_tx_callback, NULL)) {
        debug_print("%s", "  Failed to process transaction\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->mempool_tx_count != 1) {
        debug_print("%s", "  Wrong mempool tx count after processing\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Transaction processed successfully\n");

    /* Test with NULL parameters */
    if (dogecoin_smpv_process_tx(NULL, TEST_RAW_TX, test_tx_callback, NULL)) {
        debug_print("%s", "  Should not process with NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_process_tx(client, NULL, test_tx_callback, NULL)) {
        debug_print("%s", "  Should not process with NULL tx data\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  NULL parameter handling correct\n");

    dogecoin_smpv_client_free(client);

    debug_print("%s", "  Transaction processing test passed\n\n");
}

/* Test client start/stop functionality */
void test_client_control() {
    debug_print("%s", "Testing client start/stop functionality...\n");

    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client\n");
        return;
    }

    /* Test starting client */
    if (!dogecoin_smpv_start(client)) {
        debug_print("%s", "  Failed to start client\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (client->is_running != true) {
        debug_print("%s", "  Client should be running\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Client started successfully\n");

    /* Test stopping client */
    dogecoin_smpv_stop(client);
    if (client->is_running != false) {
        debug_print("%s", "  Client should be stopped\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Client stopped successfully\n");

    /* Test starting NULL client */
    if (dogecoin_smpv_start(NULL)) {
        debug_print("%s", "  Should not start NULL client\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  NULL client handling correct\n");

    dogecoin_smpv_client_free(client);

    debug_print("%s", "  Client control test passed\n\n");
}

/* Test statistics and utility functions */
void test_statistics_and_utils() {
    debug_print("%s", "Testing statistics and utility functions...\n");

    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client\n");
        return;
    }

    /* Add some addresses */
    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_1)) {
        debug_print("%s", "  Failed to add first address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (!dogecoin_smpv_add_watcher(client, TEST_ADDRESS_2)) {
        debug_print("%s", "  Failed to add second address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    /* Test statistics */
    uint32_t total_txs, watched_addresses;

    dogecoin_smpv_get_stats(client, &total_txs, &watched_addresses);
    if (watched_addresses != 2) {
        debug_print("%s", "  Wrong watched addresses count\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (total_txs != 0) {
        debug_print("%s", "  Wrong initial tx count\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Statistics retrieved successfully\n");
    debug_print("    Watched addresses: %u\n", watched_addresses);
    debug_print("    Total transactions: %u\n", total_txs);

    /* Test JSON output */
    dogecoin_smpv_watcher* watcher = dogecoin_smpv_get_watcher(client, TEST_ADDRESS_1);
    if (!watcher) {
        debug_print("%s", "  Failed to get watcher for JSON test\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    char* json = dogecoin_smpv_watcher_to_json(watcher);
    if (!json) {
        debug_print("%s", "  Failed to generate watcher JSON\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  Watcher JSON generated successfully\n");
    debug_print("    JSON: %s\n", json);
    dogecoin_free(json);

    dogecoin_smpv_client_free(client);

    debug_print("%s", "  Statistics and utility test passed\n\n");
}

/* Test error handling */
void test_error_handling() {
    debug_print("%s", "Testing error handling...\n");

    /* Test NULL client operations */
    dogecoin_smpv_client_free(NULL);
    if (dogecoin_smpv_add_watcher(NULL, TEST_ADDRESS_1)) {
        debug_print("%s", "  Should not add watcher with NULL client\n");
        return;
    }

    if (dogecoin_smpv_remove_watcher(NULL, TEST_ADDRESS_1)) {
        debug_print("%s", "  Should not remove watcher with NULL client\n");
        return;
    }

    if (dogecoin_smpv_get_watcher(NULL, TEST_ADDRESS_1)) {
        debug_print("%s", "  Should not get watcher with NULL client\n");
        return;
    }

    if (dogecoin_smpv_start(NULL)) {
        debug_print("%s", "  Should not start NULL client\n");
        return;
    }

    dogecoin_smpv_stop(NULL);
    if (dogecoin_smpv_process_tx(NULL, TEST_RAW_TX, NULL, NULL)) {
        debug_print("%s", "  Should not process tx with NULL client\n");
        return;
    }

    if (dogecoin_smpv_get_tx(NULL, "test")) {
        debug_print("%s", "  Should not get tx with NULL client\n");
        return;
    }

    dogecoin_smpv_update_tx_status(NULL, "test", true, "block", 1);
    dogecoin_smpv_get_stats(NULL, NULL, NULL);

    debug_print("%s", "  NULL client operations handled gracefully\n");

    /* Test NULL parameter operations */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        debug_print("%s", "  Failed to create client for error testing\n");
        return;
    }

    if (dogecoin_smpv_add_watcher(client, NULL)) {
        debug_print("%s", "  Should not add watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_remove_watcher(client, NULL)) {
        debug_print("%s", "  Should not remove watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_get_watcher(client, NULL)) {
        debug_print("%s", "  Should not get watcher with NULL address\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_process_tx(client, NULL, NULL, NULL)) {
        debug_print("%s", "  Should not process tx with NULL data\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_get_tx(client, NULL)) {
        debug_print("%s", "  Should not get tx with NULL txid\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    dogecoin_smpv_update_tx_status(client, NULL, true, NULL, 1);

    debug_print("%s", "  NULL parameter operations handled gracefully\n");

    /* Test utility functions with NULL */
    dogecoin_smpv_tx_free(NULL);
    if (dogecoin_smpv_tx_to_json(NULL)) {
        debug_print("%s", "  Should not generate JSON for NULL tx\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    if (dogecoin_smpv_watcher_to_json(NULL)) {
        debug_print("%s", "  Should not generate JSON for NULL watcher\n");
        dogecoin_smpv_client_free(client);
        return;
    }

    debug_print("%s", "  NULL utility function calls handled gracefully\n");

    dogecoin_smpv_client_free(client);

    debug_print("%s", "  Error handling test passed\n\n");
}

/* Main test function for the test framework */
void test_smpv() {
    debug_print("%s", "SMPV (Simplified Mempool Payment Verification) Test Suite\n");
    debug_print("%s", "========================================================\n\n");

    test_smpv_client_creation();
    test_address_watching();
    test_transaction_processing();
    test_client_control();
    test_statistics_and_utils();
    test_error_handling();

    debug_print("%s", "All SMPV tests completed\n");
}
