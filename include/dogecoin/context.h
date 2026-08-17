/*

 The MIT License (MIT)

 Copyright (c) 2024-2026 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_CONTEXT_H__
#define __LIBDOGECOIN_CONTEXT_H__

#include <dogecoin/chainparams.h>
#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

struct dogecoin_transaction_context;
struct dogecoin_eckey_context;

typedef struct dogecoin_context_ {
    const dogecoin_chainparams* chain_params;
    struct dogecoin_transaction_context* tx_ctx;
    struct dogecoin_eckey_context* key_ctx;
    void* ecc_ctx;
    void* rng_state;
    void* refcount_lock;
    int enable_net;
    int error_code;
    uint32_t refcount;
    int thread_safe; //!nonzero when constructed via dogecoin_ctx_new_ts()
    char last_error[256];
} dogecoin_context;

LIBDOGECOIN_API dogecoin_context* dogecoin_context_new(dogecoin_bool testnet, dogecoin_bool enable_net);
LIBDOGECOIN_API void dogecoin_context_acquire(dogecoin_context* ctx);
LIBDOGECOIN_API void dogecoin_context_release(dogecoin_context* ctx);
LIBDOGECOIN_API const dogecoin_chainparams* dogecoin_context_get_chainparams(const dogecoin_context* ctx);
LIBDOGECOIN_API struct dogecoin_transaction_context* dogecoin_context_get_transaction_context(dogecoin_context* ctx);
LIBDOGECOIN_API struct dogecoin_eckey_context* dogecoin_context_get_eckey_context(dogecoin_context* ctx);
LIBDOGECOIN_API void* dogecoin_context_get_ecc_context(dogecoin_context* ctx);
LIBDOGECOIN_API void* dogecoin_context_get_rng_state(dogecoin_context* ctx);
LIBDOGECOIN_API void dogecoin_context_set_error(dogecoin_context* ctx, int code, const char* msg);
LIBDOGECOIN_API int dogecoin_context_get_error_code(const dogecoin_context* ctx);
LIBDOGECOIN_API const char* dogecoin_context_get_error(const dogecoin_context* ctx);
LIBDOGECOIN_API int dogecoin_generate_keypair_ex(dogecoin_context* ctx, char* wif, size_t* wif_size, char* addr, size_t* addr_size);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_CONTEXT_H__
