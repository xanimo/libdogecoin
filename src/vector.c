/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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

#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

/**
 * Create a new vector with a given size and return a pointer to it
 * 
 * @param res The size of the vector.
 * @param free_f A function that will be called when a vector element is freed.
 * 
 * @return A vector pointer.
 */
vector* vector_new(size_t res, void (*free_f)(void*))
{
    vector* vec = dogecoin_calloc(1, sizeof(vector));
    if (!vec)
        return NULL;

    vec->alloc = 8;
    while (vec->alloc < res)
        vec->alloc *= 2;

    vec->elem_free_f = free_f;
    vec->data = dogecoin_calloc(1, vec->alloc * sizeof(void*));
    if (!vec->data) {
        dogecoin_free(vec);
        return NULL;
    }

    return vec;
}

/**
 * If the vector has a
 * free function, call it on each element. Then free the data
 * 
 * @param vec the vector to free
 * 
 * @return Nothing
 */
static void vector_free_data(vector* vec)
{
    if (!vec->data)
        return;

    if (vec->elem_free_f) {
        unsigned int i;
        for (i = 0; i < vec->len; i++)
            if (vec->data[i]) {
                vec->elem_free_f(vec->data[i]);
                vec->data[i] = NULL;
            }
    }

    dogecoin_free(vec->data);
    vec->data = NULL;
    vec->alloc = 0;
    vec->len = 0;
}

/**
 * This function frees the memory allocated for the vector
 * 
 * @param vec the vector to be freed
 * @param free_array If true, the array will be freed. If false, the array will not be freed.
 * 
 * @return Nothing
 */
void vector_free(vector* vec, dogecoin_bool free_array)
{
    if (!vec) {
        return;
    }

    if (free_array) {
        vector_free_data(vec);
    }

    dogecoin_mem_zero(vec, sizeof(*vec));
    dogecoin_free(vec);
}

/**
 * "Grow the vector to a new size, if necessary."
 * 
 * The function is pretty simple. It checks the current size of the vector, and if it's less than the
 * minimum size, it doubles the size of the vector. If the vector is already at the maximum size, it
 * returns false. Otherwise, it returns true
 * 
 * @param vec the vector to grow
 * @param min_sz The minimum size of the vector.
 * 
 * @return A bool
 */
static dogecoin_bool vector_grow(vector* vec, size_t min_sz)
{
    size_t new_alloc = vec->alloc;
    while (new_alloc < min_sz) {
        new_alloc *= 2;
    }

    if (vec->alloc == new_alloc) {
        return true;
    }

    void* new_data = dogecoin_realloc(vec->data, new_alloc * sizeof(void*));
    if (!new_data) {
        return false;
    }

    vec->data = new_data;
    vec->alloc = new_alloc;
    return true;
}

/**
 * Return the index of the first element in the vector that matches the given data
 * 
 * @param vec the vector to search
 * @param data The data to search for.
 * 
 * @return The index of the data in the vector.
 */
ssize_t vector_find(vector* vec, void* data)
{
    if (vec && vec->len) {
        size_t i;
        for (i = 0; i < vec->len; i++) {
            if (vec->data[i] == data) {
                return (ssize_t)i;
            }
        }
    }

    return -1;
}

/**
 * If the vector is full,
 * grow it by one element and then add the data
 * 
 * @param vec The vector to add the data to.
 * @param data The data to be added to the vector.
 * 
 * @return Nothing
 */
dogecoin_bool vector_add(vector* vec, void* data)
{
    if (vec->len == vec->alloc) {
        if (!vector_grow(vec, vec->len + 1)) {
            return false;
        }
    }

    vec->data[vec->len] = data;
    vec->len++;
    return true;
}

/**
 * Remove the elements from the vector starting at position pos and ending at pos + len
 * 
 * @param vec the vector to remove from
 * @param pos The starting position of the range to remove.
 * @param len The number of elements to remove.
 * 
 * @return Nothing
 */
void vector_remove_range(vector* vec, size_t pos, size_t len)
{
    if (!vec || ((pos + len) > vec->len)) {
        return;
    }

    if (vec->elem_free_f) {
        unsigned int i, count;
        for (i = pos, count = 0; count < len; i++, count++) {
            vec->elem_free_f(vec->data[i]);
        }
    }

    memmove(&vec->data[pos], &vec->data[pos + len], (vec->len - pos - len) * sizeof(void*));
    vec->len -= len;
}

/**
 * Remove the element at the given position from the vector
 * 
 * @param vec the vector to remove from
 * @param pos The index of the element to remove.
 */
void vector_remove_idx(vector* vec, size_t pos)
{
    vector_remove_range(vec, pos, 1);
}

/**
 * Remove the element at the given index from the vector
 * 
 * @param vec the vector to remove the data from
 * @param data The data to be removed.
 * 
 * @return A boolean value.
 */
dogecoin_bool vector_remove(vector* vec, void* data)
{
    ssize_t idx = vector_find(vec, data);
    if (idx < 0) {
        return false;
    }

    vector_remove_idx(vec, idx);
    return true;
}

/**
 * If the new size is the same as the old size, do nothing. If the new size is less than the old size,
 * free the elements that are beyond the new size. If the new size is greater than the old size, grow
 * the vector and set the new elements to NULL
 * 
 * @param vec the vector to resize
 * @param newsz the new size of the vector
 * 
 * @return The return value is a boolean value indicating whether the resize was successful.
 */
dogecoin_bool vector_resize(vector* vec, size_t newsz)
{
    unsigned int i;

    /* same size */
    if (newsz == vec->len) {
        return true;
    }

    /* truncate */
    else if (newsz < vec->len) {
        size_t del_count = vec->len - newsz;

        for (i = (vec->len - del_count); i < vec->len; i++) {
            if (vec->elem_free_f) {
                vec->elem_free_f(vec->data[i]);
            }
            vec->data[i] = NULL;
        }

        vec->len = newsz;
        return true;
    }

    /* last possibility: grow */
    if (!vector_grow(vec, newsz)) {
        return false;
    }

    /* set new elements to NULL */
    for (i = vec->len; i < newsz; i++) {
        vec->data[i] = NULL;
    }

    return true;
}
