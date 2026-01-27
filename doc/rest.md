# Libdogecoin SPV REST API Documentation

## Table of Contents
- [Libdogecoin SPV REST API Documentation](#dogecoin-spv-rest-api-documentation)
  - [Table of Contents](#table-of-contents)
  - [Abstract](#abstract)
  - [Endpoints](#endpoints)
    - [GET /getBalance](#get-getbalance)
    - [GET /getAddresses](#get-getaddresses)
    - [GET /getTransactions](#get-gettransactions)
    - [GET /getUTXOs](#get-getutxos)
    - [GET /getWallet](#get-getwallet)
    - [GET /getHeaders](#get-getheaders)
    - [GET /getChaintip](#get-getchaintip)
    - [GET /getTimestamp](#get-gettimestamp)
    - [GET /getLastBlockInfo](#get-getlastblockinfo)
    - [GET /getRawTx](#get-getrawtx)
    - [GET /viewTx](#get-viewtx)
    - [GET /stats](#get-stats)
    - [GET /chainStats](#get-chainstats)
    - [GET /smpvStats](#get-smpvstats)
    - [GET /smpvTx](#get-smpvtx)

## Abstract

This document describes the REST API endpoints exposed by the Libdogecoin SPV node. The API provides access to wallet information, such as balance, addresses, transactions, UTXOs, as well as wallet and blockchain data like wallet files, headers, and the chain tip. The API is designed to facilitate interaction with the Libdogecoin SPV node programmatically.

## Endpoints

### GET **/getBalance**

Retrieves the total balance of the wallet.

#### **Request**

- **Method:** `GET`
- **URL:** `/getBalance`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  Wallet balance: <balance>
  ```

  Where `<balance>` is the total balance of the wallet in Dogecoin.

#### **Example**

```bash
curl http://localhost:<port>/getBalance
```

#### **Sample Response**

```
Wallet balance: 123.45678900
```

---

### GET **/getAddresses**

Retrieves all addresses associated with the wallet.

#### **Request**

- **Method:** `GET`
- **URL:** `/getAddresses`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  address: <address1>
  address: <address2>
  ...
  ```

  Each line contains an address associated with the wallet.

#### **Example**

```bash
curl http://localhost:<port>/getAddresses
```

#### **Sample Response**

```
address: DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L
address: DQe1QeG4FxhEgvfuvGfC7oL5G2G87huuxU
```

---

### GET **/getTransactions**

Retrieves all spent (non-spendable) transactions associated with the wallet.

#### **Request**

- **Method:** `GET`
- **URL:** `/getTransactions`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  ----------------------
  txid:           <txid>
  vout:           <vout>
  address:        <address>
  script_pubkey:  <script_pubkey>
  amount:         <amount>
  confirmations:  <confirmations>
  spendable:      <spendable>
  solvable:       <solvable>
  ...
  Spent Balance: <total_spent_balance>
  ```

  Information about each spent transaction (UTXO) and the total spent balance.

#### **Example**

```bash
curl http://localhost:<port>/getTransactions
```

#### **Sample Response**

```
----------------------
txid:           e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
vout:           0
address:        DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L
script_pubkey:  76a9144621d6a7f3b4ebbaee4e2d8c10eafbf1ccbc9c0a88ac
amount:         50.00000000
confirmations:  100
spendable:      0
solvable:       1
Spent Balance: 50.00000000
```

---

### GET **/getUTXOs**

Retrieves all unspent transaction outputs (UTXOs) associated with the wallet.

#### **Request**

- **Method:** `GET`
- **URL:** `/getUTXOs`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  ----------------------
  Unspent UTXO:
  txid:           <txid>
  vout:           <vout>
  address:        <address>
  script_pubkey:  <script_pubkey>
  amount:         <amount>
  confirmations:  <confirmations>
  spendable:      <spendable>
  solvable:       <solvable>
  ...
  Total Unspent: <total_unspent_balance>
  ```

  Information about each unspent transaction output and the total unspent balance.

#### **Example**

```bash
curl http://localhost:<port>/getUTXOs
```

#### **Sample Response**

```
----------------------
Unspent UTXO:
txid:           b1fea5241c4a1d7d1e6c6d619fbf3bb8b1ec3f1f1d2f4c5b6a7c8d9e0f1a2b3c
vout:           1
address:        DQe1QeG4FxhEgvfuvGfC7oL5G2G87huuxU
script_pubkey:  76a9145d6a7f3b4ebbaee4e2d8c10eafbf1ccbc9c0a88ac
amount:         75.00000000
confirmations:  100
spendable:      1
solvable:       1
Total Unspent: 75.00000000
```

---

### GET **/getWallet**

Downloads the wallet file associated with the node.

#### **Request**

- **Method:** `GET`
- **URL:** `/getWallet`

#### **Response**

- **Content-Type:** `application/octet-stream`
- **Body:**

  Binary data of the wallet file.

#### **Example**

```bash
curl -O http://localhost:<port>/getWallet
```

#### **Notes**

- The response is a binary file.
- Ensure that it's secure as it contains sensitive information.

---

### GET **/getHeaders**

Downloads the headers file used by the SPV node.

#### **Request**

- **Method:** `GET`
- **URL:** `/getHeaders`

#### **Response**

- **Content-Type:** `application/octet-stream`
- **Body:**

  Binary data of the headers file.

#### **Example**

```bash
curl -O http://localhost:<port>/getHeaders
```

#### **Notes**

- The response is a binary file containing blockchain headers.
- Useful for debugging or analysis purposes.

---

### GET **/getChaintip**

Retrieves the current chain tip (the latest block height known to the node).

#### **Request**

- **Method:** `GET`
- **URL:** `/getChaintip`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  Chain tip: <block_height>
  ```

  Where `<block_height>` is the height of the latest block known to the SPV node.

#### **Example**

```bash
curl http://localhost:<port>/getChaintip
```

#### **Sample Response**

```
Chain tip: 3500000
```

---

### GET **/getTimestamp**

Retrieves the current timestamp of the SPV node.

#### **Request**

- **Method:** `GET`
- **URL:** `/getTimestamp`

#### **Response**

- **Content-Type:** `text/plain`
- **Body:**

  ```
  Timestamp: <timestamp>
  ```

  Where `<timestamp>` is the current date and local time of the SPV node.

#### **Example**

  ```bash
  curl http://localhost:<port>/getTimestamp
  ```

#### **Sample Response**

```
2024-10-26 15:30:00
```

---

### GET **/getLastBlockInfo**

Retrieves information about the last block processed by the SPV node.

#### **Request**

- **Method:** `GET`

- **URL:** `/getLastBlockInfo`

#### **Response**

- **Content-Type:** `text/plain`

- **Body:**

  ```
  Block size: <last_block_size>
  Tx count: <last_block_tx_count>
  Total tx size: <last_block_total_tx_size>
  ```

  Where:
  - `<last_block_size>` is the size of the last block in bytes.
  - `<last_block_tx_count>` is the number of transactions in the last block.
  - `<last_block_total_tx_size>` is the total size of transactions in the last block.

#### **Example**

```bash
curl http://localhost:<port>/getLastBlockInfo
```

#### **Sample Response**

```
Block size: 4130
Tx count: 11
Total tx size: 3355
```

---

### GET **/getRawTx**

Returns the raw transaction (hex) for a given transaction ID present in the wallet DB.

#### **Request**

* **Method:** `GET`
* **URL:** `/getRawTx?txid=<64-hex>`

#### **Response**

* **Content-Type:** `text/plain`
* **Body:**

  ```
  <raw-tx-hex>
  ```
* **Errors:**

  * `400 Bad Request` missing/invalid `txid`
  * `404 Not Found` transaction not found in wallet DB

#### **Example**

```bash
curl "http://localhost:<port>/getRawTx?txid=7c6728205d56b2b625463a10ade9c9a7ab2bf19ae2e05328f1f39e6f943c397b"
```

---

### GET **/viewTx**

Shows wallet-scoped details for a single transaction, optionally filtered to one output.

#### **Request**

* **Method:** `GET`
* **URL:** `/viewTx?txid=<64-hex>[&vout=<n>]`

#### **Response**

* **Content-Type:** `text/plain`
* **Body (on match):**

  ```
  ----------------------
  txid:           <txid>
  vout:           <vout>
  address:        <address>
  script_pubkey:  <script_pubkey>
  amount:         <amount>
  confirmations:  <confirmations>
  height:         <height>
  spendable:      <0|1>
  solvable:       <0|1>
  ```
* **If no match:**

  ```
  No matching UTXOs for txid
  ```
* **Errors:**

  * `400 Bad Request` missing/invalid `txid`

#### **Examples**

```bash
# All wallet UTXOs from this tx
curl "http://localhost:<port>/viewTx?txid=7c6728205d56b2b625463a10ade9c9a7ab2bf19ae2e05328f1f39e6f943c397b"

# Only vout 2
curl "http://localhost:<port>/viewTx?txid=7c6728205d56b2b625463a10ade9c9a7ab2bf19ae2e05328f1f39e6f943c397b&vout=2"
```

---

### GET **/stats**

Aggregates recent on-chain activity seen by the SPV session.

#### **Request**

* **Method:** `GET`
* **URL:** `/stats`
* **Query params (optional):**

  * `secs=<N>` time window in seconds (default `86400`)
  * `blocks=<M>` use last M blocks instead of a time window (overrides `secs` if provided)
  * Alias: `/stats24h` (equivalent to `/stats?secs=86400`)

#### **Response**

* **Content-Type:** `text/plain`
* **Body (key: value per line):**

  ```
  === Stats (window=<secs> s) ===
  blocks: <uint>
  transactions: <uint64>
  tps: <float>
  volume: <DOGE-string>
  volume_koinu: <uint64>
  median_fee_per_block: <DOGE-string>
  avg_fee_per_block: <DOGE-string>
  median_fee_per_kb: <DOGE-string>
  avg_fee_per_kb: <DOGE-string>
  outputs: <uint64>
  bytes: <uint64>
  ```

#### **Example**

```bash
curl "http://localhost:<port>/stats?blocks=11&secs=86400"
```

#### **Sample Response**

```
=== Stats (window=86400 s) ===
blocks: 11
transactions: 368
tps: 0.0043
volume: 115806761.13803503
volume_koinu: 11580676113803503
median_fee_per_block: 4.08844296
avg_fee_per_block: 10.61592847
median_fee_per_kb: 0.00122113
avg_fee_per_kb: 0.00317245
outputs: 791
bytes: 325765
```

---

### GET **/chainStats**

Session totals and on-disk sizes observed by the SPV node for this run.

#### **Request**

* **Method:** `GET`
* **URL:** `/chainStats`

#### **Response**

* **ontent-Type:** `text/plain`
* **Body (key: value per line):**

  ```
  === Chain Stats (SPV session) ===
  tip_height: <int>
  tip_time: <YYYY-MM-DD HH:MM:SS|unknown>
  tip_bits: 0x<hex>
  headers_bytes: <uint64>
  blocks_total: <uint64>
  transactions_total: <uint64>
  outputs_total: <uint64>
  output_value_total: <DOGE-string>
  fees_total: <DOGE-string>
  block_bytes_total: <uint64>
  approx_chain_bytes: <uint64>
  uptime_sec: <uint64>
  ```

#### **Example**

```bash
curl "http://localhost:<port>/chainStats"
```

#### **Sample Response**

```
=== Chain Stats (SPV session) ===
tip_height: 5870150
tip_time: 2024-10-26 15:30:00
tip_bits: 0x196beff5
headers_bytes: 34567890
blocks_total: 123456
transactions_total: 7890123
outputs_total: 4567890
output_value_total: 123456789.12345678
fees_total: 12345.67890123
block_bytes_total: 234567890
approx_chain_bytes: 345678901
uptime_sec: 3600
```

---

### GET `/smpvStats`

Lightweight status and counters for the SMPV (Simplified Mempool Payment Verification) tracker.
SMPV must be enabled with the CLI flag `-x` (e.g., `spvnode -x ...`).

**Request**

* Method: `GET`
* URL: `/smpvStats`

**Response**

* Content-Type: `text/plain`
* Body (key: value per line):

```
=== SMPV ===
enabled: <0|1>
mempool_txs: <uint32>
watchers: <uint32>
confirmed: <uint32>
unconfirmed: <uint32>
total_bytes: <uint64>
last_seen_ts: <unix-epoch>
last_seen_age_sec: <uint>
types_p2pk: <uint64>
types_p2pkh: <uint64>
types_p2sh: <uint64>
types_multisig: <uint64>
types_op_return: <uint64>
types_nonstandard: <uint64>
types_vout_total: <uint64>
coinbase_txs: <uint64>   # usually 0 in mempool
```

**Example**

```bash
curl "http://localhost:<port>/smpvStats"
```

**Sample Response**

```
=== SMPV ===
enabled: 1
mempool_txs: 37
watchers: 2
confirmed: 0
unconfirmed: 37
total_bytes: 118764
last_seen_ts: 1727190021
last_seen_age_sec: 3
types_p2pk: 4
types_p2pkh: 55
types_p2sh: 2
types_multisig: 0
types_op_return: 1
types_nonstandard: 0
types_vout_total: 62
coinbase_txs: 0
```

---

### GET `/smpvTx`

Return a single mempool transaction as JSON (when tracked by SMPV).

**Request**

* Method: `GET`
* URL: `/smpvTx?id=<txid>`

**Response**

* Content-Type: `application/json`
* Body: SMPV transaction object (fields as defined in `dogecoin_smpv_tx_to_json()`, see `doc/smpv.md`).

**Example**

```bash
curl "http://localhost:<port>/smpvTx?id=a65792df3f399a3436fc7c088ae9ef5fc81530010dc02a216731c971ac25dead"
```

**Sample Response**

```json
{
  "txid": "a65792df3f399a3436fc7c088ae9ef5fc81530010dc02a216731c971ac25dead",
  "size": 1677,
  "vin": 1,
  "vout": 1,
  "coinbase": false,
  "outval": 123328000,
  "types": {
    "p2pk": 0,
    "p2pkh": 1,
    "p2sh": 0,
    "multisig": 0,
    "op_return": 0,
    "nonstandard": 0
  }
}
```

---

## Additional Information

- **Server Address:** Replace `<port>` in the examples with the port number where your Libdogecoin SPV node is running.
- **Content Types:**
  - Endpoints returning plain text data use `Content-Type: text/plain`.
  - Endpoints returning binary data use `Content-Type: application/octet-stream`.
- **Security Considerations:**
  - Sensitive endpoints like `/getWallet` expose critical data.
  - Always safeguard your wallet file to prevent unauthorized access to your funds.

## Usage Notes

- **cURL:** The examples use `curl` for simplicity. You can use any HTTP node to interact with the API.
- **Error Handling:** If an endpoint encounters an error, it will respond with an appropriate HTTP status code and message.
  - For example, if the wallet file is not found:

    ```
    HTTP/1.1 404 Not Found
    Content-Type: text/plain

    Wallet file not found
    ```

- **Concurrency:** The SPV node should handle multiple concurrent requests gracefully. However, ensure that shared resources like the wallet and UTXO set are managed in a thread-safe manner.
