/*

 The MIT License (MIT)

 Copyright (c) 2024 edtubbs, bluezr
 Copyright (c) 2024 The Dogecoin Foundation

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

#include <dogecoin/rest.h>

#include <dogecoin/blockchain.h>
#include <dogecoin/koinu.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/spv.h>
#include <dogecoin/wallet.h>


/**
 * This function is called when an http request is received
 * It handles the request and sends a response
 *
 * @param req the request
 * @param arg the client
 *
 * @return Nothing.
 */
void dogecoin_http_request_cb(struct evhttp_request *req, void *arg) {
    dogecoin_spv_client* client = (dogecoin_spv_client*)arg;
    dogecoin_wallet* wallet = (dogecoin_wallet*)client->sync_transaction_ctx;
    if (!wallet) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    const struct evhttp_uri* uri = evhttp_request_get_evhttp_uri(req);
    const char* path = evhttp_uri_get_path(uri);

    struct evbuffer *evb = NULL;
    evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    if (strcmp(path, "/getBalance") == 0) {
        int64_t balance = dogecoin_wallet_get_balance(wallet);
        char balance_str[32] = {0};
        koinu_to_coins_str(balance, balance_str);
        evbuffer_add_printf(evb, "Wallet balance: %s\n", balance_str);
    } else if (strcmp(path, "/getAddresses") == 0) {
        vector* addresses = vector_new(10, dogecoin_free);
        dogecoin_wallet_get_addresses(wallet, addresses);
        for (unsigned int i = 0; i < addresses->len; i++) {
            char* address = vector_idx(addresses, i);
            evbuffer_add_printf(evb, "address: %s\n", address);
        }
        vector_free(addresses, true);
    } else if (strcmp(path, "/getTransactions") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64 = 0;

        if (HASH_COUNT(utxos) > 0) {
            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, utxos, utxo, tmp) {
                if (!utxo->spendable) {
                    // For spent UTXOs
                    evbuffer_add_printf(evb, "%s\n", "----------------------");
                    evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof utxo->txid));
                    evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                    evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                    evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                    evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                    evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                    evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                    evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                    wallet_total_u64 += coins_to_koinu_str(utxo->amount);
                }
            }
        }

        // Convert and print totals for spent UTXOs.
        koinu_to_coins_str(wallet_total_u64, wallet_total);
        evbuffer_add_printf(evb, "Spent Balance: %s\n", wallet_total);
    } else if (strcmp(path, "/getUTXOs") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64_unspent = 0;

        dogecoin_utxo* utxo;
        dogecoin_utxo* tmp;

        HASH_ITER(hh, wallet->utxos, utxo, tmp) {
            if (utxo->spendable) {
                // For unspent UTXOs
                evbuffer_add_printf(evb, "----------------------\n");
                evbuffer_add_printf(evb, "Unspent UTXO:\n");
                evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof(utxo->txid)));
                evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                wallet_total_u64_unspent += coins_to_koinu_str(utxo->amount);
            }
        }

        // Convert and print totals for unspent UTXOs.
        koinu_to_coins_str(wallet_total_u64_unspent, wallet_total);
        evbuffer_add_printf(evb, "Total Unspent: %s\n", wallet_total);
    } else if (strcmp(path, "/getWallet") == 0) {
        // Get the wallet file
        FILE* file = wallet->dbfile;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Wallet file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the wallet file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the wallet file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            fclose(file);
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (!result) {
            evbuffer_free(evb);
            free(buffer);
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getHeaders") == 0) {
        // Get the headers file
        dogecoin_headers_db* headers_db = (dogecoin_headers_db *)(client->headers_db_ctx);
        FILE* file = headers_db->headers_tree_file;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Headers file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the headers file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the headers file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            fclose(file);
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (!result) {
            evbuffer_free(evb);
            free(buffer);
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getChaintip") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        evbuffer_add_printf(evb, "Chain tip: %d\n", tip->height);
    } else {
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
        evbuffer_free(evb);
        return;
    }

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}

/**
 * This function is validates sections of an ip
 * if user decides to use http server
 *
 * @param s the part of the ip we are validating
 *
 * @return bool.
 */
bool valid_ip_section(const char* s)
{
    int n = strlen(s);
 
    // if length of passed string is
    // more than 3 then it is not valid
    if (n > 3)
        return false;
 
    // check if the string only contains digits
    // if not then return false
    for (int i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
 
    int x = atoi(s);
 
    // the string is valid if the number
    // generated is between 0 to 255
    return (x >= 0 && x <= 255);
}

/**
 * This function is validates the port
 * if user decides to use http server
 *
 * @param s the port we are validating
 *
 * @return bool.
 */
bool valid_port_section(const char* s)
{
    int n = strlen(s);
 
    // if length of passed string is
    // more than 5 then it is not valid
    if (n > 5)
        return false;
 
    // check if the string only contains digits
    // if not then return false
    for (int i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
 
    int x = atoi(s);
 
    // the string is valid if the number
    // generated is between 0 to 65,535
    return (x >= 0 && x <=  65535);
}

/**
 * This function is validates an ip
 * if user decides to use http server
 *
 * @param s the part of the ip we are validating
 *
 * @return 1 if ip is valid, 0 if not.
 */
int is_valid_ip(char* ip)
{
    printf("ip: %s\n", ip);
    // if empty string then return false
    if (ip == NULL)
        return 0;
    int num, dots = 0;
    int len = strlen(ip);
    int count = 0;
 
    // the number dots in the original
    // string should be 3
    // for it to be valid
    for (int i = 0; i < len; i++) {
        if (ip[i] == '.')
            count++;
    }
    printf("count: %d\n", count);
    if (count != 3)
        return false;
 
    // See following link for strtok()
 
    char* ptr = strtok(ip, DELIM_DOT);
    if (ptr == NULL)
        return 0;
 
    while (ptr) {
        /* after parsing string, it must be valid */
        if (valid_ip_section(ptr)) {
            /* parse remaining string */
            ptr = strtok(NULL, ".");
            if (ptr != NULL)
                ++dots;
        }
        else
            return 0;
    }
 
    /* valid IP string must contain 3 dots */
    // this is for the cases such as 1...1 where
    // originally the no. of dots is three but
    // after iteration of the string we find
    // it is not valid
    if (dots != 3)
        return 0;
    printf("success\n");
    return 1;
}

/**
 * This function is validates a port
 * if user decides to use http server
 *
 * @param s the port we are validating
 *
 * @return 1 if port is valid, 0 if not.
 */
int is_valid_port(char* port)
{
    if (port == NULL)
        return 0;
    int num, colon = 0;
    int len = strlen(port);
    int count = 0;
 
    // the number dots in the original
    // string should be 3
    // for it to be valid
    for (int i = 0; i < len; i++) {
        if (port[i] == ':')
            count++;
    }
    printf("count: %d\n", count);
    if (count != 1)
        return false;
 
    // See following link for strtok()
 
    char* ptr = strtok(port, DELIM_COLON);
    if (ptr == NULL)
        return 0;
 
    while (ptr) {
        /* after parsing string, it must be valid */
        if (valid_port_section(ptr)) {
            /* parse remaining string */
            ptr = strtok(NULL, ":");
            if (ptr != NULL)
                ++colon;
        }
        else
            return 0;
    }
 
    /* valid IP string must contain 3 dots */
    // this is for the cases such as 1...1 where
    // originally the no. of dots is three but
    // after iteration of the string we find
    // it is not valid
    if (colon != 1)
        return 0;
    printf("success\n");
    return 1;
}
