/*

 The MIT License (MIT)

 Copyright (c) 2018 Bitcoin Core developers
 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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

/**
 * @file compact_filter.c
 * @brief BIP 157 Client Side Block Filtering protocol implementation.
 */

#include <string.h>

#include <dogecoin/cf_checkpoints.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/compact_filter.h>
#include <dogecoin/hash.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

/* Wrapper for cstr_free to use as vector element free callback */
static void cstr_free_void(void *ptr) {
    cstr_free((cstring *)ptr, true);
}

/* ================================================================ */
/*  Message Serialization                                           */
/* ================================================================ */

void dogecoin_p2p_msg_getcfilters_ser(const dogecoin_getcfilters_msg *msg, cstring *out) {
    if (!msg || !out) return;
    ser_bytes(out, &msg->filter_type, 1);
    ser_u32(out, msg->start_height);
    ser_u256(out, msg->stop_hash);
}

void dogecoin_p2p_msg_getcfheaders_ser(const dogecoin_getcfheaders_msg *msg, cstring *out) {
    if (!msg || !out) return;
    ser_bytes(out, &msg->filter_type, 1);
    ser_u32(out, msg->start_height);
    ser_u256(out, msg->stop_hash);
}

void dogecoin_p2p_msg_getcfcheckpt_ser(const dogecoin_getcfcheckpt_msg *msg, cstring *out) {
    if (!msg || !out) return;
    ser_bytes(out, &msg->filter_type, 1);
    ser_u256(out, msg->stop_hash);
}

/* ================================================================ */
/*  Message Deserialization                                         */
/* ================================================================ */

dogecoin_bool dogecoin_p2p_msg_cfilter_deser(dogecoin_cfilter_msg *msg, struct const_buffer *buf) {
    if (!msg || !buf) return false;

    /* filter_type (1 byte) -- BIP157: FilterType | BlockHash | NumFilterBytes | FilterBytes */
    if (buf->len < 1) return false;
    deser_bytes(&msg->filter_type, buf, 1);

    /* block_hash (32 bytes) */
    if (!deser_u256(msg->block_hash, buf)) return false;

    /* filter_data (var_bytes: compact_size + data) */
    uint32_t filter_len;
    if (!deser_varlen(&filter_len, buf)) return false;

    if (buf->len < filter_len) return false;

    if (msg->filter_data) {
        cstr_free(msg->filter_data, true);
    }
    msg->filter_data = cstr_new_buf(buf->p, filter_len);
    buf->p = (const uint8_t *)buf->p + filter_len;
    buf->len -= filter_len;

    return true;
}

dogecoin_bool dogecoin_p2p_msg_cfheaders_deser(dogecoin_cfheaders_msg *msg, struct const_buffer *buf) {
    if (!msg || !buf) return false;

    /* filter_type (1 byte) */
    if (buf->len < 1) return false;
    deser_bytes(&msg->filter_type, buf, 1);

    /* stop_hash (32 bytes) */
    if (!deser_u256(msg->stop_hash, buf)) return false;

    /* prev_filter_header (32 bytes) */
    if (!deser_u256(msg->prev_filter_header, buf)) return false;

    /* filter_hashes_length (compact_size) */
    uint32_t n_hashes;
    if (!deser_varlen(&n_hashes, buf)) return false;

    /* n_hashes is an attacker-controlled count read straight off the wire (up to
       0xFFFFFFFF). Each hash that follows is 32 bytes, so a message can declare at
       most buf->len / 32 of them. Without this check vector_new() below allocates
       n_hashes pointers -- and it rounds the reservation *up* to a power of two, so
       0xFFFFFFFF becomes a 2^32 * sizeof(void*) (~34 GB) calloc -- before a single
       hash is read: a memory-exhaustion DoS from a ~10-byte cfheaders message.
       BIP157 also caps a getcfheaders span at 2000 blocks, so bound by that too. */
    if (n_hashes > buf->len / DOGECOIN_HASH_LENGTH) return false;
    if (n_hashes > MAX_GETCFHEADERS_SIZE) return false;

    /* Deserialize each 32-byte filter hash */
    if (msg->filter_hashes) {
        vector_free(msg->filter_hashes, true);
    }
    msg->filter_hashes = vector_new(n_hashes, dogecoin_free);
    if (!msg->filter_hashes) return false;

    uint32_t i;
    for (i = 0; i < n_hashes; i++) {
        uint256_t *hash = dogecoin_calloc(1, sizeof(uint256_t));
        if (!deser_u256(*hash, buf)) {
            dogecoin_free(hash);
            return false;
        }
        vector_add(msg->filter_hashes, hash);
    }

    return true;
}

dogecoin_bool dogecoin_p2p_msg_cfcheckpt_deser(dogecoin_cfcheckpt_msg *msg, struct const_buffer *buf) {
    if (!msg || !buf) return false;

    /* filter_type (1 byte) */
    if (buf->len < 1) return false;
    deser_bytes(&msg->filter_type, buf, 1);

    /* stop_hash (32 bytes) */
    if (!deser_u256(msg->stop_hash, buf)) return false;

    /* filter_headers_length (compact_size) */
    uint32_t n_headers;
    if (!deser_varlen(&n_headers, buf)) return false;

    /* Same unbounded-allocation hazard as cfheaders above: n_headers comes off the
       wire and feeds vector_new(), which reserves a power-of-two number of pointers
       (~34 GB at 0xFFFFFFFF) before any header is read. Each checkpoint is a 32-byte
       hash, so reject any count the remaining buffer cannot possibly hold. Checkpoints
       are one per 1000 blocks, so the buffer bound is the meaningful limit here. */
    if (n_headers > buf->len / DOGECOIN_HASH_LENGTH) return false;

    /* Deserialize each 32-byte filter header checkpoint */
    if (msg->filter_headers) {
        vector_free(msg->filter_headers, true);
    }
    msg->filter_headers = vector_new(n_headers, dogecoin_free);
    if (!msg->filter_headers) return false;

    uint32_t i;
    for (i = 0; i < n_headers; i++) {
        uint256_t *hdr = dogecoin_calloc(1, sizeof(uint256_t));
        if (!deser_u256(*hdr, buf)) {
            dogecoin_free(hdr);
            return false;
        }
        vector_add(msg->filter_headers, hdr);
    }

    return true;
}

/* ================================================================ */
/*  Message Lifecycle                                               */
/* ================================================================ */

void dogecoin_cfilter_msg_init(dogecoin_cfilter_msg *msg) {
    if (!msg) return;
    msg->filter_type = GCS_BASIC_FILTER_TYPE;
    dogecoin_mem_zero(msg->block_hash, sizeof(uint256_t));
    msg->filter_data = NULL;
}

void dogecoin_cfilter_msg_free(dogecoin_cfilter_msg *msg) {
    if (!msg) return;
    if (msg->filter_data) {
        cstr_free(msg->filter_data, true);
        msg->filter_data = NULL;
    }
}

void dogecoin_cfheaders_msg_init(dogecoin_cfheaders_msg *msg) {
    if (!msg) return;
    msg->filter_type = GCS_BASIC_FILTER_TYPE;
    dogecoin_mem_zero(msg->stop_hash, sizeof(uint256_t));
    dogecoin_mem_zero(msg->prev_filter_header, sizeof(uint256_t));
    msg->filter_hashes = NULL;
}

void dogecoin_cfheaders_msg_free(dogecoin_cfheaders_msg *msg) {
    if (!msg) return;
    if (msg->filter_hashes) {
        vector_free(msg->filter_hashes, true);
        msg->filter_hashes = NULL;
    }
}

void dogecoin_cfcheckpt_msg_init(dogecoin_cfcheckpt_msg *msg) {
    if (!msg) return;
    msg->filter_type = GCS_BASIC_FILTER_TYPE;
    dogecoin_mem_zero(msg->stop_hash, sizeof(uint256_t));
    msg->filter_headers = NULL;
}

void dogecoin_cfcheckpt_msg_free(dogecoin_cfcheckpt_msg *msg) {
    if (!msg) return;
    if (msg->filter_headers) {
        vector_free(msg->filter_headers, true);
        msg->filter_headers = NULL;
    }
}

/* ================================================================ */
/*  Compact Filter State Management                                 */
/* ================================================================ */

dogecoin_compact_filter_state* dogecoin_compact_filter_state_new(void) {
    dogecoin_compact_filter_state *state = dogecoin_calloc(1, sizeof(dogecoin_compact_filter_state));
    if (!state) return NULL;
    state->enabled = false;
    state->filter_type = GCS_BASIC_FILTER_TYPE;
    state->cfheaders_tip_height = 0;
    dogecoin_mem_zero(state->cfheaders_tip_hash, sizeof(uint256_t));
    dogecoin_mem_zero(state->genesis_filter_header, sizeof(uint256_t));
    state->filter_headers = vector_new(4096, dogecoin_free);
    state->checkpoints = vector_new(64, dogecoin_free);
    state->cfheaders_base_height = 1;
    state->filters_tip_height = 0;
    state->cfilter_batch_end = 0;
    state->pending_start_height = 0;
    dogecoin_mem_zero(state->pending_stop_hash, sizeof(uint256_t));
    state->awaiting_response = false;
    state->last_request_time = 0;
    state->watched_scripts = vector_new(16, cstr_free_void);
    state->matched_block_hashes = vector_new(64, dogecoin_free);
    state->matched_block_heights = vector_new(64, dogecoin_free);
    state->matched_blocks_fetched = 0;
    state->cf_block_fetch_active = false;
    state->par_num_workers = 0;
    state->par_next_height = 0;
    state->par_flush_height = 0;
    state->par_bufs = NULL;
    state->cfh_par_n = 0;
    state->cfh_par_done = 0;
    state->cfh_par_data = NULL;
    state->cfh_par_base = 1;
    state->cfh_par_total = 0;
    state->cfh_par_chunks = NULL;
    state->filter_headers_flat = NULL;
    state->filter_headers_flat_base = 1;
    state->filter_headers_flat_len = 0;
    return state;
}

void dogecoin_compact_filter_state_free(dogecoin_compact_filter_state *state) {
    if (!state) return;
    if (state->filter_headers) {
        vector_free(state->filter_headers, true);
        state->filter_headers = NULL;
    }
    if (state->checkpoints) {
        vector_free(state->checkpoints, true);
        state->checkpoints = NULL;
    }
    if (state->watched_scripts) {
        vector_free(state->watched_scripts, true);
        state->watched_scripts = NULL;
    }
    if (state->matched_block_hashes) {
        vector_free(state->matched_block_hashes, true);
        state->matched_block_hashes = NULL;
    }
    if (state->matched_block_heights) {
        vector_free(state->matched_block_heights, true);
        state->matched_block_heights = NULL;
    }
    if (state->par_bufs) {
        uint8_t pi;
        for (pi = 0; pi < state->par_num_workers; pi++) {
            cf_par_buf *b = &state->par_bufs[pi];
            if (b->records) {
                uint32_t cnt = (b->batch_end >= b->batch_start) ? (b->batch_end - b->batch_start + 1) : 0;
                uint32_t ri;
                for (ri = 0; ri < cnt; ri++) {
                    if (b->records[ri].filter_data)
                        cstr_free(b->records[ri].filter_data, true);
                }
                dogecoin_free(b->records);
                b->records = NULL;
            }
        }
        dogecoin_free(state->par_bufs);
        state->par_bufs = NULL;
    }
    if (state->cfh_par_data) {
        dogecoin_free(state->cfh_par_data);
        state->cfh_par_data = NULL;
    }
    if (state->cfh_par_chunks) {
        dogecoin_free(state->cfh_par_chunks);
        state->cfh_par_chunks = NULL;
    }
    if (state->filter_headers_flat) {
        dogecoin_free(state->filter_headers_flat);
        state->filter_headers_flat = NULL;
    }
    dogecoin_free(state);
}

void dogecoin_compact_filter_state_reset(dogecoin_compact_filter_state *state) {
    if (!state) return;
    state->cfheaders_tip_height = 0;
    dogecoin_mem_zero(state->cfheaders_tip_hash, sizeof(uint256_t));
    dogecoin_mem_zero(state->genesis_filter_header, sizeof(uint256_t));
    if (state->filter_headers) {
        vector_free(state->filter_headers, true);
        state->filter_headers = vector_new(4096, dogecoin_free);
    }
    if (state->checkpoints) {
        vector_free(state->checkpoints, true);
        state->checkpoints = vector_new(64, dogecoin_free);
    }
    state->cfheaders_base_height = 1;
    state->filters_tip_height = 0;
    state->pending_start_height = 0;
    dogecoin_mem_zero(state->pending_stop_hash, sizeof(uint256_t));
    state->awaiting_response = false;
    state->last_request_time = 0;
    /* Keep watched_scripts - they don't change on reset */
    if (state->matched_block_hashes) {
        vector_free(state->matched_block_hashes, true);
        state->matched_block_hashes = vector_new(64, dogecoin_free);
    }
    if (state->matched_block_heights) {
        vector_free(state->matched_block_heights, true);
        state->matched_block_heights = vector_new(64, dogecoin_free);
    }
    state->matched_blocks_fetched = 0;
    state->cf_block_fetch_active = false;
    /* Free parallel cfheaders download state */
    if (state->cfh_par_data) {
        dogecoin_free(state->cfh_par_data);
        state->cfh_par_data = NULL;
    }
    if (state->cfh_par_chunks) {
        dogecoin_free(state->cfh_par_chunks);
        state->cfh_par_chunks = NULL;
    }
    state->cfh_par_n = 0;
    state->cfh_par_done = 0;
    state->cfh_par_total = 0;
    if (state->filter_headers_flat) {
        dogecoin_free(state->filter_headers_flat);
        state->filter_headers_flat = NULL;
        state->filter_headers_flat_len = 0;
    }

    /* Reset parallel cfilter state but keep par_num_workers and par_bufs allocation */
    state->par_next_height = 0;
    state->par_flush_height = 0;
    if (state->par_bufs) {
        uint8_t pi;
        for (pi = 0; pi < state->par_num_workers; pi++) {
            cf_par_buf *b = &state->par_bufs[pi];
            if (b->records) {
                uint32_t cnt = (b->batch_end >= b->batch_start) ? (b->batch_end - b->batch_start + 1) : 0;
                uint32_t ri;
                for (ri = 0; ri < cnt; ri++) {
                    if (b->records[ri].filter_data)
                        cstr_free(b->records[ri].filter_data, true);
                }
                dogecoin_free(b->records);
                b->records = NULL;
            }
            b->node_id = -1;
            b->received = 0;
            b->complete = false;
        }
    }
}

/* ================================================================ */
/*  Compact Filter Validation and Header Computation                */
/* ================================================================ */

void dogecoin_compact_filter_compute_header(const cstring *filter_data, const uint256_t prev_filter_header, uint256_t header_out) {
    if (!filter_data) {
        dogecoin_mem_zero(header_out, sizeof(uint256_t));
        return;
    }

    /* filter_hash = dbl_sha256(filter_data) */
    uint256_t filter_hash;
    dogecoin_hash((const unsigned char *)filter_data->str, filter_data->len, filter_hash);

    /* filter_header = dbl_sha256(filter_hash || prev_filter_header) */
    uint8_t combined[64];
    memcpy(combined, filter_hash, 32);
    memcpy(combined + 32, prev_filter_header, 32);
    dogecoin_hash(combined, 64, header_out);
}

dogecoin_bool dogecoin_compact_filter_validate(const cstring *filter_data, const uint256_t prev_filter_header, const uint256_t expected_filter_header) {
    if (!filter_data) return false;

    uint256_t computed_header;
    dogecoin_compact_filter_compute_header(filter_data, prev_filter_header, computed_header);

    return memcmp(computed_header, expected_filter_header, 32) == 0;
}

/* ================================================================ */
/*  BIP 157 Hardcoded Checkpoint Helpers                            */
/* ================================================================ */

const dogecoin_cf_checkpoint* dogecoin_cf_get_checkpoints(
    const dogecoin_chainparams *chain, size_t *count_out)
{
    if (!chain || !count_out) return NULL;

    if (chain == &dogecoin_chainparams_main) {
        *count_out = dogecoin_mainnet_cf_checkpoint_count;
        return dogecoin_mainnet_cf_checkpoint_array;
    } else if (chain == &dogecoin_chainparams_test) {
        *count_out = dogecoin_testnet_cf_checkpoint_count;
        return dogecoin_testnet_cf_checkpoint_array;
    } else if (chain == &dogecoin_chainparams_regtest) {
        *count_out = dogecoin_regtest_cf_checkpoint_count;
        return dogecoin_regtest_cf_checkpoint_array;
    }

    /* Unknown chain — fallback: try chainname comparison */
    if (strcmp(chain->chainname, "main") == 0) {
        *count_out = dogecoin_mainnet_cf_checkpoint_count;
        return dogecoin_mainnet_cf_checkpoint_array;
    } else if (strcmp(chain->chainname, "testnet3") == 0) {
        *count_out = dogecoin_testnet_cf_checkpoint_count;
        return dogecoin_testnet_cf_checkpoint_array;
    } else if (strcmp(chain->chainname, "regtest") == 0) {
        *count_out = dogecoin_regtest_cf_checkpoint_count;
        return dogecoin_regtest_cf_checkpoint_array;
    }

    *count_out = 0;
    return NULL;
}

dogecoin_bool dogecoin_cf_validate_checkpoints(
    const dogecoin_chainparams *chain, const vector_t *peer_checkpoints)
{
    if (!chain || !peer_checkpoints) return false;

    size_t hardcoded_count = 0;
    const dogecoin_cf_checkpoint *hardcoded = dogecoin_cf_get_checkpoints(chain, &hardcoded_count);

    /* No hardcoded checkpoints: nothing to validate against — pass */
    if (!hardcoded || hardcoded_count == 0) return true;

    /*
     * Dogecoin Core (and Bitcoin Core) sends checkpoints at heights 1000, 2000, 3000 ...
     * peer_checkpoints[i] = filter header at height (i+1) * CFCHECKPT_INTERVAL.
     * Index mapping: cp_idx = height / CFCHECKPT_INTERVAL - 1.
     * So hardcoded height 1000 → cp_idx 0, height 2000 → cp_idx 1, etc.
     */
    for (size_t i = 0; i < hardcoded_count; i++) {
        if (hardcoded[i].height == 0 || hardcoded[i].filter_header == NULL) break;

        uint32_t cp_idx = hardcoded[i].height / CFCHECKPT_INTERVAL - 1;

        if (cp_idx >= peer_checkpoints->len) continue; /* peer's chain is shorter */

        /* Convert hardcoded hex → uint256_t for comparison */
        uint256_t hardcoded_hash;
        utils_uint256_sethex((char *)hardcoded[i].filter_header, hardcoded_hash);

        const uint256_t *peer_hash = (const uint256_t *)vector_idx(peer_checkpoints, cp_idx);
        if (memcmp(hardcoded_hash, peer_hash, 32) != 0) {
            return false; /* mismatch — peer data is invalid */
        }
    }

    return true;
}

size_t dogecoin_cf_load_hardcoded_checkpoints(
    dogecoin_compact_filter_state *state, const dogecoin_chainparams *chain)
{
    if (!state || !chain) return 0;

    size_t hardcoded_count = 0;
    const dogecoin_cf_checkpoint *hardcoded = dogecoin_cf_get_checkpoints(chain, &hardcoded_count);

    if (!hardcoded || hardcoded_count == 0) return 0;

    /* Free existing checkpoints if any */
    if (state->checkpoints) {
        vector_free(state->checkpoints, true);
    }

    /*
     * Determine the highest checkpoint index we need.
     * The vector must be contiguous from index 0..max_cp_idx.
     * Find the max height, compute max_cp_idx, and size the vector.
     */
    uint32_t max_height = 0;
    for (size_t i = 0; i < hardcoded_count; i++) {
        if (hardcoded[i].height == 0 || hardcoded[i].filter_header == NULL) break;
        if (hardcoded[i].height > max_height) max_height = hardcoded[i].height;
    }

    if (max_height == 0) {
        state->checkpoints = vector_new(1, dogecoin_free);
        return 0;
    }

    uint32_t max_cp_idx = max_height / CFCHECKPT_INTERVAL - 1;
    uint32_t n_slots = max_cp_idx + 1;

    state->checkpoints = vector_new(n_slots, dogecoin_free);

    /* Pre-fill all slots with zero hashes */
    for (uint32_t j = 0; j < n_slots; j++) {
        uint256_t *slot = dogecoin_calloc(1, sizeof(uint256_t));
        vector_add(state->checkpoints, slot);
    }

    /* Now fill in the hardcoded values */
    size_t loaded = 0;
    for (size_t i = 0; i < hardcoded_count; i++) {
        if (hardcoded[i].height == 0 || hardcoded[i].filter_header == NULL) break;

        uint32_t cp_idx = hardcoded[i].height / CFCHECKPT_INTERVAL - 1;
        if (cp_idx >= state->checkpoints->len) continue;

        uint256_t *slot = (uint256_t *)vector_idx(state->checkpoints, cp_idx);
        utils_uint256_sethex((char *)hardcoded[i].filter_header, *slot);
        loaded++;
    }

    return loaded;
}
