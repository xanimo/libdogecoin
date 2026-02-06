/*

 The MIT License (MIT)

 Copyright (c) 2023-2026 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_BIP37_H__
#define __LIBDOGECOIN_BIP37_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/serialize.h>

/* Callback used for each matched leaf txid while traversing a merkleblock. */
typedef dogecoin_bool (*dogecoin_bip37_match_cb)(const uint8_t txid[32], uint32_t pos, void* ctx);
typedef dogecoin_bool (*dogecoin_bip37_match_info_cb)(const uint8_t txid[32], uint32_t pos, dogecoin_bool consumed, void* ctx);
typedef int (*dogecoin_bip37_log_cb)(const char* fmt, ...);

/* Fixed-size BIP37 bloom filter container used by CLI/SPV helpers. */
typedef struct dogecoin_bip37_filter_ {
    uint8_t* data;
    size_t data_len;
    uint32_t n_hash_funcs;
    uint32_t n_tweak;
    uint8_t n_flags;
} dogecoin_bip37_filter;

LIBDOGECOIN_BEGIN_DECL

dogecoin_bool dogecoin_bip37_build_filtered_getdata_payload(const struct const_buffer* inv_payload,
                                                            uint8_t** out_payload,
                                                            uint32_t* out_len,
                                                            uint32_t* item_count);

/* Traverse/verify partial merkle tree and report matched tx leaves via callback. */
dogecoin_bool dogecoin_bip37_traverse_merkle_matches(uint32_t nTx,
                                                     const uint8_t* hashes,
                                                     uint32_t hashCount,
                                                     const uint8_t* flags,
                                                     uint32_t flags_len,
                                                     const uint8_t header_merkle[32],
                                                     const uint8_t block_hash[32],
                                                     int block_height,
                                                     const char* filter_debug_dump,
                                                     dogecoin_bip37_match_cb on_match,
                                                     void* match_ctx);

dogecoin_bool dogecoin_bip37_merkle_extract_match_tree(uint32_t nTx,
                                                         const uint8_t* hashes,
                                                         uint32_t hashCount,
                                                         const uint8_t* flags,
                                                         uint32_t flags_len,
                                                         const uint8_t header_merkle[32],
                                                         const uint8_t block_hash[32],
                                                         int block_height,
                                                         const char* filter_debug_dump,
                                                         void** match_tree,
                                                          uint32_t* match_pending,
                                                          dogecoin_bip37_log_cb log_cb);

dogecoin_bool dogecoin_bip37_merkle_match_consume(void** match_tree,
                                                  uint32_t* match_pending,
                                                  const uint8_t txid[32],
                                                  uint32_t* out_pos);

dogecoin_bool dogecoin_bip37_merkle_for_each_match(void* match_tree,
                                                   dogecoin_bip37_match_info_cb cb,
                                                   void* ctx);

/* Allocate a fixed-size BIP37 bloom filter (uses protocol max size/hash count). */
dogecoin_bip37_filter* dogecoin_bip37_filter_new(uint32_t tweak, uint8_t flags);
/* Add a data item (address hash/outpoint/script fragment) to the bloom filter. */
dogecoin_bool dogecoin_bip37_filter_add(dogecoin_bip37_filter* filter,
                                        const uint8_t* data,
                                        size_t data_len);
/* Free a bloom filter previously allocated by dogecoin_bip37_filter_new. */
void dogecoin_bip37_filter_free(dogecoin_bip37_filter* filter);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_BIP37_H__ */
