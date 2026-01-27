# SMPV (Simplified Mempool Payment Verification)

SMPV is a lightweight system for tracking mempool transactions for specific Dogecoin addresses, similar to how the [dogecoin-wallet](https://github.com/qlpqlp/dogecoin-wallet) detects mempool transactions.

## Overview

SMPV provides real-time monitoring of mempool transactions for watched addresses, allowing applications to:

- Track incoming and outgoing transactions
- Monitor transaction sizes
- Receive real-time notifications
- Generate statistics and reports
- Handle both confirmed and unconfirmed transactions

> Note: SMPV operates on mempool data only and does not calculate transaction fees. Fee computation requires UTXO context that is not available during mempool tracking.

## Features

### Core Functionality
- **Address Watching**: Add/remove addresses to monitor
- **Transaction Processing**: Process raw mempool transactions
- **Real-time Notifications**: Callback-based transaction alerts
- **Statistics**: Track transaction counts and activity
- **JSON Export**: Generate JSON reports for integration

### Key Benefits
- **Lightweight**: Minimal resource usage
- **Real-time**: Immediate transaction detection
- **Flexible**: Easy integration with existing applications
- **Reliable**: Robust error handling and memory management

## Enabling SMPV in `spvnode`

SMPV is optional. To enable it in the `spvnode` tool, start `spvnode` with the SMPV flag:

```bash
./spvnode -x scan
```

If you are also running the HTTP server, the SMPV endpoints are documented separately in `rest.md`:

```bash
./spvnode -x -u 127.0.0.1:8080 scan
```

## API Reference

### Client Management

#### `dogecoin_smpv_client_new()`
```c
dogecoin_smpv_client* dogecoin_smpv_client_new(const dogecoin_chainparams* chain_params);
```
Creates a new SMPV client for the specified chain parameters.

**Parameters:**
- `chain_params`: Chain parameters (mainnet/testnet)

**Returns:**
- New SMPV client on success
- `NULL` on failure

#### `dogecoin_smpv_client_free()`
```c
void dogecoin_smpv_client_free(dogecoin_smpv_client* client);
```
Frees an SMPV client and all associated resources.

### Address Watching

#### `dogecoin_smpv_add_watcher()`
```c
dogecoin_bool dogecoin_smpv_add_watcher(dogecoin_smpv_client* client, const char* address);
```
Adds an address to the watch list.

**Parameters:**
- `client`: SMPV client
- `address`: Dogecoin address to watch

**Returns:**
- `true` on success
- `false` on failure

#### `dogecoin_smpv_remove_watcher()`
```c
dogecoin_bool dogecoin_smpv_remove_watcher(dogecoin_smpv_client* client, const char* address);
```
Removes an address from the watch list.

#### `dogecoin_smpv_get_watcher()`
```c
dogecoin_smpv_watcher* dogecoin_smpv_get_watcher(const dogecoin_smpv_client* client, const char* address);
```
Gets watcher information for an address.

### Transaction Processing

#### `dogecoin_smpv_process_tx()`
```c
dogecoin_bool dogecoin_smpv_process_tx(
    dogecoin_smpv_client* client,
    const char* raw_tx_hex,
    dogecoin_smpv_tx_callback callback,
    void* user_data
);
```
Processes a raw mempool transaction.

**Parameters:**
- `client`: SMPV client
- `raw_tx_hex`: Raw transaction hex string
- `callback`: Callback function for notifications
- `user_data`: User data for callback

**Returns:**
- `true` if transaction was processed
- `false` if not relevant or error occurred

#### `dogecoin_smpv_get_tx()`
```c
dogecoin_smpv_tx* dogecoin_smpv_get_tx(const dogecoin_smpv_client* client, const char* txid);
```
Gets a transaction by its ID.

### Client Control

#### `dogecoin_smpv_start()`
```c
dogecoin_bool dogecoin_smpv_start(dogecoin_smpv_client* client);
```
Starts SMPV monitoring.

#### `dogecoin_smpv_stop()`
```c
void dogecoin_smpv_stop(dogecoin_smpv_client* client);
```
Stops SMPV monitoring.

### Statistics and Utilities

#### `dogecoin_smpv_get_stats()`
```c
void dogecoin_smpv_get_stats(
    const dogecoin_smpv_client* client,
    uint32_t* total_txs,
    uint32_t* watched_addresses
);
```
Gets mempool statistics.

#### `dogecoin_smpv_tx_to_json()`
```c
char* dogecoin_smpv_tx_to_json(const dogecoin_smpv_tx* tx);
```
Converts a transaction to JSON format.

#### `dogecoin_smpv_watcher_to_json()`
```c
char* dogecoin_smpv_watcher_to_json(const dogecoin_smpv_watcher* watcher);
```
Converts a watcher to JSON format.

## Data Structures

### `dogecoin_smpv_client`
```c
typedef struct {
    const dogecoin_chainparams* chain_params;
    dogecoin_smpv_watcher* watchers;
    dogecoin_smpv_tx* mempool_txs;
    uint32_t watcher_count;
    uint32_t mempool_tx_count;
    dogecoin_bool is_running;
    uint64_t last_update_time;
} dogecoin_smpv_client;
```

### `dogecoin_smpv_tx`
```c
typedef struct {
    char* txid;                    /* Transaction ID (hex string) */
    char* raw_hex;                 /* Raw transaction hex */
    dogecoin_tx* decoded_tx;       /* Decoded transaction */
    uint64_t size;                 /* Transaction size in bytes */
    uint64_t timestamp;            /* When transaction was first seen */
    dogecoin_bool is_confirmed;    /* Whether transaction is confirmed */
    uint32_t confirmations;        /* Number of confirmations */
    char* block_hash;              /* Block hash if confirmed */
    uint32_t block_height;         /* Block height if confirmed */
} dogecoin_smpv_tx;
```

### `dogecoin_smpv_watcher`
```c
typedef struct {
    char* address;                 /* Dogecoin address being watched */
    uint64_t total_received;       /* Total received in koinu */
    uint64_t total_sent;           /* Total sent in koinu */
    uint64_t balance;              /* Current balance in koinu */
    uint32_t tx_count;             /* Number of transactions */
    dogecoin_bool is_active;       /* Whether watcher is active */
} dogecoin_smpv_watcher;
```

## Usage Example

This example creates an SMPV client, adds two watched addresses, and processes a raw transaction hex string.

```c
#include <stdio.h>

#include <dogecoin/chainparams.h>
#include <dogecoin/smpv.h>

/* Callback function for transaction notifications */
static void tx_callback(const dogecoin_smpv_tx* tx, const char* address, void* user_data)
{
    (void)user_data;
    printf("New transaction for %s: %s\n", address, tx->txid);
    printf("Size: %llu bytes\n", (unsigned long long)tx->size);
}

int main(void)
{
    /* Create SMPV client */
    dogecoin_smpv_client* client = dogecoin_smpv_client_new(&dogecoin_chainparams_main);
    if (!client) {
        printf("Failed to create SMPV client\n");
        return 1;
    }

    /* Add addresses to watch */
    dogecoin_smpv_add_watcher(client, "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP");
    dogecoin_smpv_add_watcher(client, "D8Y66wE9nOtW8WnU0Xs7Rd5cC9i4kL3nQ");

    /* Start monitoring */
    if (!dogecoin_smpv_start(client)) {
        printf("Failed to start SMPV\n");
        dogecoin_smpv_client_free(client);
        return 1;
    }

    /*
     * Process a transaction.
     * In a real integration, raw_tx_hex would typically come from a mempool feed
     * (e.g. inv/tx messages from a peer connection).
     */
    const char* raw_tx_hex = "0100000001..."; /* Raw transaction hex */
    dogecoin_smpv_process_tx(client, raw_tx_hex, tx_callback, NULL);

    /* Get statistics */
    uint32_t total_txs = 0;
    uint32_t watched_addresses = 0;
    dogecoin_smpv_get_stats(client, &total_txs, &watched_addresses);

    printf("Watched addresses: %u\n", watched_addresses);
    printf("Mempool transactions: %u\n", total_txs);

    /* Clean up */
    dogecoin_smpv_stop(client);
    dogecoin_smpv_client_free(client);

    return 0;
}
```



## Building and Testing

SMPV is built as part of libdogecoin and does not require standalone build scripts. It is exercised through `spvnode` and covered by the standard libdogecoin test suite.

## License

SMPV is part of libdogecoin and is licensed under the same terms as the main library.
