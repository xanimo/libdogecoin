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

#include <assert.h>

#include <dogecoin/base58.h>
#include <dogecoin/koinu.h>
#include <dogecoin/psbt.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/uthash.h>
#include <dogecoin/utils.h>


/**
 * @brief This function instantiates a new working psbt_input,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working psbt_input. 
 */
psbt_input* new_psbt_input() {
    psbt_input* input = (struct psbt_input*)dogecoin_calloc(1, sizeof *input);
    input->idx = HASH_COUNT(psbt_inputs) + 1;
    return input;
}

/**
 * @brief This function takes a pointer to an existing working
 * psbt_input object and adds it to the hash table.
 * 
 * @param psbt_input The pointer to the working psbt_input.
 * 
 * @return Nothing.
 */
void add_psbt_input(psbt_input *input) {
    psbt_input* psbt_input_old;
    HASH_FIND_INT(psbt_inputs, &input->idx, psbt_input_old);
    if (psbt_input_old == NULL) {
        HASH_ADD_INT(psbt_inputs, idx, input);
    } else {
        HASH_REPLACE_INT(psbt_inputs, idx, input, psbt_input_old);
    }
    dogecoin_free(psbt_input_old);
}

/**
 * @brief This function takes an index and returns the working
 * psbt_input associated with that index in the hash table.
 * 
 * @param idx The index of the target working psbt_input.
 * 
 * @return The pointer to the working psbt_input associated with
 * the provided index.
 */
psbt_input* find_psbt_input(int idx) {
    psbt_input* input;
    HASH_FIND_INT(psbt_inputs, &idx, input);
    return input;
}

/**
 * @brief This function removes the specified working psbt_input
 * from the hash table and frees the psbt_inputs in memory.
 * 
 * @param input The pointer to the psbt_input to remove.
 * 
 * @return Nothing.
 */
void remove_psbt_input(psbt_input* input) {
    HASH_DEL(psbt_inputs, input); /* delete it (psbt_inputs advances to next) */
    dogecoin_psbt_input_free(input);
}

/**
 * @brief This function frees the memory allocated
 * for an psbt_input.
 * 
 * @param input The pointer to the psbt_input to be freed.
 * 
 * @return Nothing.
 */
void dogecoin_psbt_input_free(psbt_input* input)
{
    dogecoin_free(input);
}

/**
 * @brief This function creates a new psbt_input, places it in
 * the hash table, and returns the index of the new psbt_input,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new psbt_input.
 */
int start_psbt_input() {
    psbt_input* input = new_psbt_input();
    int index = input->idx;
    add_psbt_input(input);
    return index;
}

/**
 * @brief This function instantiates a new working psbt_output,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working psbt_output. 
 */
psbt_output* new_psbt_output() {
    psbt_output* output = (struct psbt_output*)dogecoin_calloc(1, sizeof *output);
    output->idx = HASH_COUNT(psbt_outputs) + 1;
    return output;
}

/**
 * @brief This function takes a pointer to an existing working
 * psbt_output object and adds it to the hash table.
 * 
 * @param output The pointer to the working psbt_output.
 * 
 * @return Nothing.
 */
void add_psbt_output(psbt_output *output) {
    psbt_output* psbt_output_old;
    HASH_FIND_INT(psbt_outputs, &output->idx, psbt_output_old);
    if (psbt_output_old == NULL) {
        HASH_ADD_INT(psbt_outputs, idx, output);
    } else {
        HASH_REPLACE_INT(psbt_outputs, idx, output, psbt_output_old);
    }
    dogecoin_free(psbt_output_old);
}

/**
 * @brief This function takes an index and returns the working
 * psbt_output associated with that index in the hash table.
 * 
 * @param idx The index of the target working psbt_output.
 * 
 * @return The pointer to the working psbt_output associated with
 * the provided index.
 */
psbt_output* find_psbt_output(int idx) {
    psbt_output* output;
    HASH_FIND_INT(psbt_outputs, &idx, output);
    return output;
}

/**
 * @brief This function removes the specified working psbt_output
 * from the hash table and frees the psbt_outputs in memory.
 * 
 * @param output The pointer to the psbt_output to remove.
 * 
 * @return Nothing.
 */
void remove_psbt_output(psbt_output* output) {
    HASH_DEL(psbt_outputs, output); /* delete it (psbt_outputs advances to next) */
    dogecoin_psbt_output_free(output);
}

/**
 * @brief This function frees the memory allocated
 * for an psbt_output.
 * 
 * @param output The pointer to the psbt_output to be freed.
 * 
 * @return Nothing.
 */
void dogecoin_psbt_output_free(psbt_output* output)
{
    dogecoin_free(output);
}

/**
 * @brief This function creates a new psbt_output, places it in
 * the hash table, and returns the index of the new psbt_output,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new psbt_output.
 */
int start_psbt_output() {
    psbt_output* output = new_psbt_output();
    int index = output->idx;
    add_psbt_output(output);
    return index;
}

/**
 * @brief This function instantiates a new working psbt,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working psbt. 
 */
psbt* new_psbt() {
    psbt* psbt = (struct psbt*)dogecoin_calloc(1, sizeof *psbt);
    psbt->tx = dogecoin_tx_new();
    psbt->idx = HASH_COUNT(psbts) + 1;
    return psbt;
}

/**
 * @brief This function takes a pointer to an existing working
 * psbt object and adds it to the hash table.
 * 
 * @param psbt The pointer to the working psbt.
 * 
 * @return Nothing.
 */
void add_psbt(psbt *new_psbt) {
    psbt* psbt_old;
    HASH_FIND_INT(psbts, &new_psbt->idx, psbt_old);
    if (psbt_old == NULL) {
        HASH_ADD_INT(psbts, idx, new_psbt);
    } else {
        HASH_REPLACE_INT(psbts, idx, new_psbt, psbt_old);
    }
    dogecoin_free(psbt_old);
}

/**
 * @brief This function takes an index and returns the working
 * psbt associated with that index in the hash table.
 * 
 * @param idx The index of the target working psbt.
 * 
 * @return The pointer to the working psbt associated with
 * the provided index.
 */
psbt* find_psbt(int idx) {
    psbt* psbt;
    HASH_FIND_INT(psbts, &idx, psbt);
    return psbt;
}

/**
 * @brief This function removes the specified working psbt
 * from the hash table and frees the psbts in memory.
 * 
 * @param psbt The pointer to the psbt to remove.
 * 
 * @return Nothing.
 */
void remove_psbt(psbt* psbt) {
    HASH_DEL(psbts, psbt); /* delete it (psbts advances to next) */
    dogecoin_psbt_free(psbt);
}

/**
 * @brief This function frees the memory allocated
 * for an psbt.
 * 
 * @param psbt The pointer to the psbt to be freed.
 * 
 * @return Nothing.
 */
void dogecoin_psbt_free(psbt* psbt)
{
    dogecoin_tx_free(psbt->tx);
    dogecoin_free(psbt);
}

/**
 * @brief This function creates a new psbt, places it in
 * the hash table, and returns the index of the new psbt,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @return The index of the new psbt.
 */
int start_psbt() {
    psbt* psbt = new_psbt();
    int index = psbt->idx;
    add_psbt(psbt);
    return index;
}

bool psbt_isnull(psbt* psbt) {
    return psbt->tx->version == 1 \
    && psbt->tx->vin->len == 0 \
    && psbt->tx->vout->len == 0 \
    && psbt->tx->locktime == 0;
}
