# Libdogecoin Transaction API

## Table of Contents

- [Libdogecoin Transaction API](#libdogecoin-transaction-api)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Working Transaction API](#working-transaction-api)
    - [**new_transaction**](#new_transaction)
    - [**add_transaction**](#add_transaction)
    - [**find_transaction**](#find_transaction)
    - [**remove_transaction**](#remove_transaction)
  - [Essential Transaction API](#essential-transaction-api)
    - [**start_transaction**](#start_transaction)
    - [**add_utxo**](#add_utxo)
    - [**add_output**](#add_output)
    - [**finalize_transaction**](#finalize_transaction)
    - [**finalize_transaction_ex**](#finalize_transaction_ex)
    - [**get_raw_transaction**](#get_raw_transaction)
    - [**get_raw_transaction_ex**](#get_raw_transaction_ex)
    - [**clear_transaction**](#clear_transaction)
    - [**sign_raw_transaction**](#sign_raw_transaction)
    - [**sign_raw_transaction_ex**](#sign_raw_transaction_ex)
    - [**sign_transaction**](#sign_transaction)
    - [**store_raw_transaction**](#store_raw_transaction)
    - [**sign_indexed_raw_transaction_ex**](#sign_indexed_raw_transaction_ex)
    - [**sign_transaction_ex**](#sign_transaction_ex)
    - [**sign_transaction_w_privkey_ex**](#sign_transaction_w_privkey_ex)

## Introduction

The high level 'essential' API provided by libdogecoin for working with simple transactions revolve around a structure defined as a `working_transaction` which is comprised of an index as an integer meant for retrieval, a dogecoin_tx 'transaction' structure as seen above, and finally a UT_hash_handle which stores our working_transaction struct in a hash table (using Troy D. Hanson's uthash library: see ./include/dogecoin/uthash.h and visit https://troydhanson.github.io/uthash/ for more information) which allow us to generate multiple transactions per "session". This `working_transaction` structure is defined as such:

Buffered `_ex` transaction APIs are retained as the primary API surface (for example `sign_raw_transaction_ex`). Where thread safety can be provided without changing parameters, the original API is preferred over adding extra aliases.

Thread-safety policy: `_ts` APIs are used when explicit context ownership is required. For APIs that can be made thread-safe without signature changes, the original API names are used directly.

The higher-level index functions also provide `_ts` variants that take an explicit `dogecoin_transaction_context*` and route through the per-object transaction primitives (`dogecoin_tx_add_input_ts`, `dogecoin_tx_add_output_ts`, `dogecoin_tx_finalize_ts`): `add_utxo_ts`, `add_output_ts`, `finalize_transaction_ts`, `save_raw_transaction_ts`, `get_raw_transaction_ts`, and `clear_transaction_ts`. The non-`_ts` functions are thin wrappers that delegate to these against the per-thread default context, so both paths share a single implementation. The thread-safe CLI builds (`such_ts`, `sendtx_ts`, `spvnode_ts`) call the `_ts` variants. See [thread_safety.md](thread_safety.md).

```C
typedef struct working_transaction {
    int index;
    dogecoin_tx* transaction;
    UT_hash_handle hh;
} working_transaction;
```

The functions that have been built around this `working_transaction` structure and flow of operation are comprised of 4 macros, which are explained further in the following section describing the [working transaction API](#working-transaction-api). used to interact with uthash. For more detailed technical information about the `dogecoin_tx` structure and Dogecoin transactions in general, please refer to the [extended transaction documentation](./transaction_extended.md).

The api itself is a higher level interface that contains all the necessary operations for building Dogecoin transactions from scratch. The generic process for building a transaction is as follows:

- Create an empty transaction.
- Add inputs from your wallet's UTXOs.
- Add outputs describing amount and recipient.
- Return any leftover change back to your address.
- Sign all inputs with your wallet's private key.

All of these steps can be done purely with Libdogecoin API, by calling directly from C and including the "libdogecoin.h" header file. For details on the usage of this API, jump to the [Essential API](#essential-transaction-api) section.

## Working Transaction API

These functions are designed to be "under the hood" and obfuscated from the end user as you will see in the Essential functions later on. They are to be used for manipulating the hash table which stores transactions in memory, and are already implemented within the Essential functions, so there is no need to call them again.

---

### **new_transaction**

`working_transaction* new_transaction()`

This function instantiates a new working_transaction structure for use. It allocates memory using `dogecoin_calloc()`, auto increments the index, instantiates a new dogecoin_tx structure, adds the working_transaction to the hash table and finally returns a pointer to the newly created working_transaction.

_C usage:_

```C
working_transaction* transaction = new_transaction();
```

---

### **add_transaction**

`void add_transaction(working_transaction *working_tx)`

This function takes a working_transaction generated from `new_transaction()` and adds it to the hash table.

_C usage:_

```C
working_transaction* working_tx = new_transaction();
add_transaction(working_tx);
```

---

### **find_transaction**

`working_transaction* find_transaction(int idx)`

This function returns a pointer to the working transaction at the specified index. If no transaction exists at that index, the function will return a NULL pointer.

_C usage:_

```C
working_transaction* working_tx = find_transaction(1);
```

---

### **remove_transaction**

`void remove_transaction(working_transaction *working_tx)`

This function removes a working_transaction from the hash table and deallocates all memory dedicated to the working_transaction and the objects it contains using `dogecoin_free()`.

_C usage:_

```C
working_transaction* working_tx = find_transaction(1);
remove_transaction(working_tx);
```

## Essential Transaction API

These functions implement the core functionality of Libdogecoin for building transactions, and are described in depth below. You can access them through a C program, by including the `libdogecoin.h` header in the source code and including the `libdogecoin.a` library at compile time.

---

### **start_transaction**

`int start_transaction()`

This function instantiates a new working_transaction structure and returns its index for future retrieval as an integer. This new working_transaction will contain an empty hex, which is "01000000000000000000". Note that anytime a new working transaction is created, it must also be removed at the end of the session by calling either `clear_transaction()`, otherwise a memory leak may occur.

_C usage:_

```C
#include "libdogecoin.h"

int main() {
    int index = start_transaction();
    // build onto the working transaction here
    clear_transaction(index);
}
```

---

### **add_utxo**

`int add_utxo(int txindex, char* hex_utxo_txid, int vout)`

An unspent transaction output (utxo) is an output of a previous transaction in which funds were sent to the user's address. These can be spent by including them as inputs in a new transaction. This function takes in a working_transaction's index as an integer (txindex), a raw hexadecimal string id of the transaction containing the utxo to spend (hex_utxo_txid), and index of the desired utxo within the previous transaction's list of outputs (vout). The utxo is then added to the working_transaction->transaction->vin field, returning either 1 for success or 0 for failure.

_C usage:_

```C
#include "libdogecoin.h"

int main() {
    char* prev_output_txid = "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074"; // worth 2 dogecoin
    int prev_output_n = 1;

    int index = start_transaction();
    if (!add_utxo(index, prev_output_txid, prev_output_n)) {
        // handle failure, return false; or printf("failure\n"); etc...
    }
    clear_transaction(index);
}
```

---

### **add_output**

`int add_output(int txindex, char* destinationaddress, char* amount)`

In order to actually spend utxos, the user must specify the new recipient address and how much of the total input amount will be sent to this address. This function takes in a working_transaction's index as an integer (txindex), the string p2pkh address of the new recipient (destinationaddress), and the amount in Dogecoin (amount) to send. This new output will be added to the working_transaction->transaction->vout field, returning either 1 for success or 0 for failure.

_C usage:_

```C
#include "libdogecoin.h"

int main() {
    char* prev_output_txid = "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2"; // worth 10 dogecoin
    int prev_output_n = 1;
    char* external_address = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";

    int index = start_transaction();
    add_utxo(index, prev_output_txid, prev_output_n);
    if (!add_output(index, external_address, "5.0")) { // 5 dogecoin to be sent
        // error handling here
    }
    clear_transaction(index);
}
```

---

### **finalize_transaction**

`char* finalize_transaction(int txindex, char* destinationaddress, char* subtractedfee, char* out_dogeamount_for_verification, char* changeaddress)`

Because Dogecoin protocol requires that utxos must be spent in full, an additional output is usually included in a transaction to return all the leftover funds to the sender. This function automatically handles both creating this extra output and reserving some funds for the network fee. It takes in a working_transaction's index as an integer (txindex), the external destination address we are sending to (destinationaddress), the desired fee to be subtracted (subtractedfee), the total amount of all inputs included through `add_utxo()` (out_dogeamount_for_verification), and the public key of the sender (public_key). In addition to making change and deducting the fee, it checks that all of the recipients included in the transaction outputs are valid by converting their script hashes to p2pkh, and returns false if any are not found. Otherwise, the hex of the finalized transaction is returned as a string.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    char* prev_output_txid_2 = "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074"; // worth 2 dogecoin
    char* prev_output_txid_10 = "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2"; // worth 10 dogecoin
    int prev_output_n_2 = 1;
    int prev_output_n_10 = 1;
    char* external_address = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";
    char* my_address = "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy";

    int index = start_transaction();
    add_utxo(index, prev_output_txid_2, prev_output_n_2);
    add_utxo(index, prev_output_txid_10, prev_output_n_10);
    add_output(index, external_address, "5.0");

    // finalize transaction with min fee of 0.00226 doge on the input total of 12 dogecoin
    char* rawhex = finalize_transaction(index, external_address, "0.00226", "12.0", my_address);
    printf("Finalized transaction hex is %s.", rawhex);
    clear_transaction(index);
}
```

---

### **finalize_transaction_ex**

```c
int finalize_transaction_ex(int txindex, const char* destinationaddress, const char* subtractedfee, const char* total_in_doge, const char* changeaddress, char* out_hex, size_t out_cap);
```

`finalize_transaction_ex` one-shots the *“close & return change”* step while **avoiding a heap allocation**: it finalizes the working transaction at `txindex`, figures out fees / change exactly as `finalize_transaction()` does, hex-serialises the result straight into the caller-supplied buffer `out_hex` (whose capacity in bytes is `out_cap`), then returns the number of characters written (not counting the terminating `'\0'`).
If any argument is invalid or the buffer is too small the function returns 0.

*C usage:*

```c
// build the TX (add_utxo / add_output)

char txhex[TXHEXMAXLEN + 1];          // +1 for the NUL
int n = finalize_transaction_ex(idx,
                                "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde", // destination
                                "0.00226",                            // fee
                                "12.0",                               // total inputs
                                "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy", // change back here
                                txhex,
                                sizeof(txhex));

if (n == 0) {
    // handle error
} else {
    printf("Finalised TX (%d chars):\n%s\n", n, txhex);
}
```

---

### **get_raw_transaction**

`char* get_raw_transaction(int txindex)`

This function takes in a working_transaction's index as an integer (txindex) and returns the current working_transaction in raw hexadecimal format.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    int index = start_transaction();
    char* rawhex = get_raw_transaction(index);
    printf("The transaction hex at index %d is %s.\n", index, rawhex);
    clear_transaction(index);
}
```

---


### **get_raw_transaction_ex**

```c
int get_raw_transaction_ex(int   txindex,
                           char* buf,
                           size_t buf_cap);
```

The `get_raw_transaction_ex` function writes the raw hexadecimal representation of the working transaction at index `txindex` into the caller-supplied buffer `buf` (of total size `buf_cap`). On success it returns the number of characters written (not counting the terminating `'\0'`); if the index is invalid, a pointer is NULL, or the buffer is too small, it returns 0. Unlike `get_raw_transaction()`, this version avoids allocating a new string on the heap, making it ideal when you already manage your own buffer.

*C usage:*

```c
char buf[TXHEXMAXLEN + 1];
int len = get_raw_transaction_ex(index, buf, sizeof(buf));
if (len == 0) {
    // handle error
} else {
    printf("Transaction hex: %s\n", buf);
}
```

---

### **clear_transaction**

`void clear_transaction(int txindex)`

This function takes in a working_transaction's index as an integer (txindex), and removes the transaction at that index from the hash table. All memory dedicated to transaction objects, such as dogecoin_tx_in and dogecoin_tx_out, is freed from within this function.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    int index = start_transaction();
    clear_transaction(index);
    printf("The transaction hex at index %d is %s.\n", index, get_raw_transaction(index)); // should return (null)
}
```

---

### **sign_raw_transaction**

`int sign_raw_transaction(int inputindex, char* incomingrawtx, char* scripthex, int sighashtype, char* privkey)`

This function takes in an index denoting which of the current transaction's inputs to sign (inputindex), the raw hexadecimal representation of the transaction to sign (incomingrawtx), the pubkey script in hexadecimal format (scripthex), the signature hash type (sighashtype) and the WIF-encoded private key used to sign the input (privkey). Signature hash type in normal use cases is set to 1 to denote that anyone can pay. In C, the function returns a boolean denoting success, but the actual signed transaction hex is passed back through incomingrawtx. **Important:** `sign_raw_transaction` must be run within a secp256k1 context, which can be created by calling `dogecoin_ecc_start()` and `dogecoin_ecc_stop()` as shown below.

**Note:** The `incomingrawtx` buffer **must** be the buffer returned by `get_raw_transaction()`, otherwise the signed hex may overflow.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    char* prev_output_txid_2 = "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074"; // worth 2 dogecoin
    char* prev_output_txid_10 = "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2"; // worth 10 dogecoin
    int prev_output_n_2 = 1;
    int prev_output_n_10 = 1;
    char* external_address = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";
    char* my_address = "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy";
    char* my_script_pubkey = "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac";
    char* my_privkey = "ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy";

    int index = start_transaction();
    add_utxo(index, prev_output_txid_2, prev_output_n_2);
    add_utxo(index, prev_output_txid_10, prev_output_n_10);
    add_output(index, external_address, "5.0");
    finalize_transaction(index, external_address, "0.00226", "12.0", my_address);

    //sign both inputs of the current finalized transaction
    dogecoin_ecc_start();
    char* rawhex = get_raw_transaction(index);
    sign_raw_transaction(0, rawhex, my_script_pubkey, 1, my_privkey);
    sign_raw_transaction(1, rawhex, my_script_pubkey, 1, my_privkey);
    dogecoin_ecc_stop();
    printf("The final signed transaction hex is: %s\n", rawhex);
    clear_transaction(index);
}
```

---

### **sign_raw_transaction_ex**

```c
int sign_raw_transaction_ex(int           inputindex,
                            const char*   incomingrawtx,
                            char*         signedrawtx,
                            size_t*       signed_size,
                            const char*   scripthex,
                            int           sighashtype,
                            const char*   privkey);
```

The `sign_raw_transaction_ex` function offers a two-step interface for signing a single input of a raw transaction. In **query mode**, you pass `signedrawtx == NULL`; the function writes the required buffer size (including the null terminator) into `*signed_size` and returns 1. In **write mode**, you allocate at least that many bytes, pass the buffer in `signedrawtx` (with `*signed_size` set to its capacity), and call it again. On success it writes the signed transaction hex (plus `'\0'`) into your buffer and returns 1; on failure it returns 0. This pattern avoids extra heap allocations when you want to supply your own output buffer.

*C usage:*

```c
// Stage 1: query required size
size_t need = 0;
if (!sign_raw_transaction_ex(0, rawhex, NULL, &need, scripthex, 1, wif)) {
    // error
}

// Stage 2: allocate and sign
char *out = malloc(need);
if (!out) { /* OOM */ }
if (!sign_raw_transaction_ex(0, rawhex, out, &need, scripthex, 1, wif)) {
    // error
}
printf("Signed transaction: %s\n", out);
free(out);
```

---

### **sign_transaction**

`int sign_transaction(int txindex, char* script_pubkey, char* privkey)`

This function takes in a working transaction structure's index as an integer (txindex), the pubkey in script hex form (script_pubkey) and the WIF-encoded private key (privkey). Each input is then signed using the specified private key, and the final signed transaction is saved to the hash table, which can be retrieved using `get_raw_transaction()`. The return value of `sign_transaction()` is a boolean denoting whether the signing was successful, but the output from `get_raw_transaction()` is a fully signed transaction that--if all information is valid--can be broadcast to miners and incorporated into the blockchain. **Important:** `sign_transaction` must also be run within a secp256k1 context, which can be created by calling `dogecoin_ecc_start()` and `dogecoin_ecc_stop()` as shown below.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    char* prev_output_txid_2 = "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074"; // worth 2 dogecoin
    char* prev_output_txid_10 = "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2"; // worth 10 dogecoin
    int prev_output_n_2 = 1;
    int prev_output_n_10 = 1;
    char* external_address = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";
    char* my_address = "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy";
    char* my_script_pubkey = "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac";
    char* my_privkey = "ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy";

    int index = start_transaction();
    add_utxo(index, prev_output_txid_2, prev_output_n_2);
    add_utxo(index, prev_output_txid_10, prev_output_n_10);
    add_output(index, external_address, "5.0");
    finalize_transaction(index, external_address, "0.00226", "12.0", my_address);

    //sign both inputs of the current finalized transaction
    dogecoin_ecc_start();
    if (!sign_transaction(index, my_script_pubkey, my_privkey)) {
        // error handling here
    }
    dogecoin_ecc_stop();
    printf("The final signed transaction hex is: %s\n", get_raw_transaction(index));
    clear_transaction(index);
}
```

---

### **store_raw_transaction**

`int store_raw_transaction(char* incomingrawtx)`

This function is equivalent to `save_raw_transaction` but takes the next available index in the hash table to save the provided transaction hex (incomingrawtx), rather than allowing the user to specify which index. It then returns this automatically chosen index as an integer.

_C usage:_

```C
#include "libdogecoin.h"
#include <stdio.h>

int main() {
    char* hex_to_store = "0100000001746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffff0000000000";
    int index = store_raw_transaction(hex_to_store);
    printf("The transaction hex at index %d is %s.\n", index, get_raw_transaction(index));
    clear_transaction(index);
}
```

---

### **sign_indexed_raw_transaction_ex**

```c
int sign_indexed_raw_transaction_ex(int txindex,
                                    int inputindex,
                                    const char* scripthex,
                                    int sighashtype,
                                    const char* privkey,
                                    char* buf,
                                    size_t buf_cap);
```

Signs **one** specific input (`inputindex`) of the working transaction stored at `txindex`, writes the fully-updated raw-hex straight into the caller-supplied buffer `buf` (capacity `buf_cap`) and returns the number of hex characters written (not counting the terminating `'\0'`).
If the buffer is too small or any argument is invalid the function returns 0.

```c
char signedhex[TXHEXMAXLEN + 1];
int n = sign_indexed_raw_transaction_ex(idx,        /* tx we're editing   */
                                        0,          /* which vin to sign  */
                                        scripthex,  /* utxo's scriptPubKey*/
                                        1,          /* SIGHASH_ALL        */
                                        wif,        /* signing key        */
                                        signedhex,
                                        sizeof signedhex);
if (n == 0) { /* error */ }
```

### **sign_transaction_ex**

```c
int sign_transaction_ex(int txindex,
                         const char* script_pubkey,
                         const char* privkey,
                         char* buf,
                         size_t buf_cap);
```

High-level helper that iterates over **all** inputs of the working transaction at `txindex`, signing each one with the same `script_pubkey` / `privkey` pair, then emits the completely-signed transaction hex into `buf`.
Return-value semantics are identical to the previous function.

```c
char finalhex[TXHEXMAXLEN + 1];
if (!sign_transaction_ex(idx, scripthex, wif, finalhex, sizeof finalhex)) {
    /* signing failed */
}
printf("fully-signed tx:\n%s\n", finalhex);
```

### **sign_transaction_w_privkey_ex**

```c
int sign_transaction_w_privkey_ex(int txindex,
                                  const char* privkey,
                                  char* buf,
                                  size_t buf_cap);
```

Single-key convenience wrapper: derives the P2PKH `scriptPubKey` from `privkey`, signs **every** input of the transaction at `txindex`, and streams the result into `buf`.
Ideal for the common *all inputs belong to the same wallet* scenario.

```c
char txhex[TXHEXMAXLEN + 1];
if (!sign_transaction_w_privkey_ex(idx, wif, txhex, sizeof txhex)) {
    /* error */
}
```

