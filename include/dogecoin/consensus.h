/*

 The MIT License (MIT)

 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_CONSENSUS_H__
#define __LIBDOGECOIN_CONSENSUS_H__

#include <stdint.h>

#include <dogecoin/block.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** Merkle */
uint256* compute_merkle_root(const vector* leaves, dogecoin_bool* mutated);
vector* compute_merkle_branch(const vector* leaves, uint32_t position);
uint256* compute_merkle_root_from_branch(const uint256* leaf, const vector* branch, uint32_t position);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256* block_merkle_root(const dogecoin_block* block, dogecoin_bool* mutated);

/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using compute_merkle_root_from_branch.
 */
vector* block_merkle_branch(const dogecoin_block* block, uint32_t position);

/** Validation */
/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
static const unsigned char REJECT_DUST = 0x41;
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

static enum {
    MODE_VALID,   //!< everything ok
    MODE_INVALID, //!< network rule violation (DoS value may be set)
    MODE_ERROR,   //!< run-time error
} mode;

typedef struct validation_state {
    int mode;
    int n_dos;
    char* str_reject_reason;
    unsigned int ch_reject_code;
    dogecoin_bool corruption_possible;
    char* str_debug_message;
    void (*DoS)(struct validation_state* state, int level, bool ret,
            unsigned int ch_reject_code_in, const char* str_reject_reason_in,
            bool corruption_in, const char* str_debug_message_in);
    dogecoin_bool (*invalid)(struct validation_state* state, bool ret,
                unsigned int _ch_reject_code, const char* _str_reject_reason,
                const char* _str_debug_message);
    dogecoin_bool (*err)(struct validation_state* state, const char* str_reject_reason_in);
} validation_state;

dogecoin_bool DoS(struct validation_state* state, int level, bool ret,
            unsigned int ch_reject_code_in, const char* str_reject_reason_in,
            bool corruption_in, const char* str_debug_message_in) {
    state->ch_reject_code = ch_reject_code_in;
    state->str_reject_reason = (char*)str_reject_reason_in;
    state->corruption_possible = corruption_in;
    state->str_debug_message = (char*)str_debug_message_in;
    if (state->mode == MODE_ERROR)
        return ret;
    state->n_dos += level;
    state->mode = MODE_INVALID;
    return ret;
}
dogecoin_bool invalid(struct validation_state* state, bool ret,
                unsigned int _ch_reject_code, const char* _str_reject_reason,
                const char* _str_debug_message) {
    return DoS(state, 0, ret, _ch_reject_code, _str_reject_reason, false, _str_debug_message);
}
dogecoin_bool err(struct validation_state* state, const char* str_reject_reason_in) {
    if (state->mode == MODE_VALID)
        state->str_reject_reason = (char*)str_reject_reason_in;
    state->mode = MODE_ERROR;
    return false;
}
const dogecoin_bool is_valid(struct validation_state* state) {
    return state->mode == MODE_VALID;
}
const dogecoin_bool return_invalid(struct validation_state* state) {
    return state->mode == MODE_INVALID;
}
const dogecoin_bool is_err(struct validation_state* state) {
    return state->mode == MODE_ERROR;
}
const dogecoin_bool is_invalid(struct validation_state* state, int *n_dos_out) {
    if (return_invalid(state)) {
        n_dos_out = state->n_dos;
        return true;
    }
    return false;
}
const dogecoin_bool corruption_possible(struct validation_state* state) {
    return state->corruption_possible;
}
void set_corruption_possible(struct validation_state* state) {
    state->corruption_possible = true;
}
const unsigned int get_reject_code(struct validation_state* state) { return state->ch_reject_code; }
const char* get_reject_reason(struct validation_state* state) { return state->str_reject_reason; }
const char* get_debug_message(struct validation_state* state) { return state->str_debug_message; }

validation_state* init_validation_state() {
    validation_state* state = dogecoin_calloc(1, sizeof(*state));
    state->mode = MODE_VALID;
    state->n_dos = 0;
    state->ch_reject_code = 0;
    state->corruption_possible = false;
    return state;
}

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_CONSENSUS_H__
