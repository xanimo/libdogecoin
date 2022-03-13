/*

 The MIT License (MIT)

 Copyright (c) 2016 libbtc developers
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dogecoin/mem.h>

void* dogecoin_malloc_internal(size_t size);
void* dogecoin_calloc_internal(size_t count, size_t size);
void* dogecoin_realloc_internal(void* ptr, size_t size);
void dogecoin_free_internal(void* ptr);

static const dogecoin_mem_mapper default_mem_mapper = {dogecoin_malloc_internal, dogecoin_calloc_internal, dogecoin_realloc_internal, dogecoin_free_internal};
static dogecoin_mem_mapper current_mem_mapper = {dogecoin_malloc_internal, dogecoin_calloc_internal, dogecoin_realloc_internal, dogecoin_free_internal};

/**
 * This function sets the current memory mapper to the default memory mapper
 */
void dogecoin_mem_set_mapper_default()
{
    current_mem_mapper = default_mem_mapper;
}

/**
 * Set the current memory mapper to the given mapper.
 * 
 * @param mapper The name of the mapper to use.
 */
void dogecoin_mem_set_mapper(const dogecoin_mem_mapper mapper)
{
    current_mem_mapper = mapper;
}

/**
 * "Allocate memory using the current memory mapper."
 * 
 * The memory mapper is a function that takes a size and returns a pointer to that size of memory
 * 
 * @param size The size of the memory block to be allocated.
 * 
 * @return A pointer to the allocated memory.
 */
void* dogecoin_malloc(size_t size)
{
    return current_mem_mapper.dogecoin_malloc(size);
}

/**
 * "Calloc is a function that allocates memory for an array of objects of the given size, and
 * initializes all the bytes of each object to zero."
 * 
 * Now, let's look at the implementation of the function:
 * 
 * @param count The number of elements to allocate.
 * @param size The size of the memory block to allocate.
 * 
 * @return A pointer to the allocated memory.
 */
void* dogecoin_calloc(size_t count, size_t size)
{
    return current_mem_mapper.dogecoin_calloc(count, size);
}

/**
 * It takes a pointer to a block of memory and a size, and returns a pointer to a block of memory of
 * the given size
 * 
 * @param ptr The pointer to the memory block to be reallocated.
 * @param size the size of the new memory block
 * 
 * @return The address of the new memory block.
 */
void* dogecoin_realloc(void* ptr, size_t size)
{
    return current_mem_mapper.dogecoin_realloc(ptr, size);
}

/**
 * It takes a pointer to a memory region and frees it
 * 
 * @param ptr The pointer to the memory to be freed.
 */
void dogecoin_free(void* ptr)
{
    current_mem_mapper.dogecoin_free(ptr);
}

/**
 * "Allocate memory for a given size, and return a pointer to it."
 * 
 * The function is called "dogecoin_malloc_internal" because it is an internal function.  It is called
 * by the function "dogecoin_malloc" which is the function that you will use to allocate memory
 * 
 * @param size The size of the memory block to be allocated.
 * 
 * @return The address of the allocated memory.
 */
void* dogecoin_malloc_internal(size_t size)
{
    void* result;

    if ((result = malloc(size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: malloc failed in dogecoin_malloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

/**
 * It allocates memory for an array of count elements of size size.
 * 
 * @param count The number of elements to allocate.
 * @param size The size of the array to be allocated.
 * 
 * @return The address of the allocated memory.
 */
void* dogecoin_calloc_internal(size_t count, size_t size)
{
    void* result;

    if ((result = calloc(count, size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: calloc failed in dogecoin_calloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

/**
 * If the realloc function
 * returns a non-null pointer, then return that pointer. Otherwise, print an
 * error message and exit the program
 * 
 * @param ptr The pointer to the memory block to be reallocated.
 * @param size The size of the memory block you want to allocate.
 * 
 * @return The result of the realloc function.
 */
void* dogecoin_realloc_internal(void* ptr, size_t size)
{
    void* result;

    if ((result = realloc(ptr, size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: realloc failed in dogecoin_realloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

/**
 * It frees the memory pointed to by ptr
 * 
 * @param ptr The pointer to the memory to be freed.
 */
void dogecoin_free_internal(void* ptr)
{
    free(ptr);
}

errno_t memset_s(volatile void *v, rsize_t smax, int c, rsize_t n) {
  if (v == NULL) return EINVAL;
  if (smax > RSIZE_MAX) return EINVAL;
  if (n > smax) return EINVAL;
 
  volatile unsigned char *p = v;
  while (smax-- && n--) {
    *p++ = c;
  }
 
  return 0;
}

/**
 * "memset_s() is a secure version of memset()."
 * 
 * The memset_s() function is a secure version of memset() that fills the memory pointed to by dst with
 * zeros
 * 
 * @param dst The destination buffer to be zeroed.
 * @param len The length of the memory block to zero.
 */
volatile void* dogecoin_mem_zero(volatile void* dst, size_t len)
{
    memset_s(dst, len, 0, len);
    return 0;
}
