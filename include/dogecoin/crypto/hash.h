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

#ifndef __LIBDOGECOIN_CRYPTO_HASH_H__
#define __LIBDOGECOIN_CRYPTO_HASH_H__

#include <dogecoin/crypto/sha2.h>
#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * Given a hash, return true if the hash is empty
 * 
 * @param hash The hash of the block to check.
 * 
 * @return A boolean value.
 */
LIBDOGECOIN_API static inline dogecoin_bool dogecoin_hash_is_empty(uint256 hash)
{
    return hash[0] == 0 && !memcmp(hash, hash + 1, 19);
}

/**
 * Clear the hash value
 * 
 * @param hash the hash to clear
 */
LIBDOGECOIN_API static inline void dogecoin_hash_clear(uint256 hash)
{
    memset(hash, 0, DOGECOIN_HASH_LENGTH);
}

/**
 * Compare the first 32 bytes of the given hashes. If they are equal, return true, otherwise return
 * false.
 * 
 * @param hash_a The hash of the block header that we are comparing.
 * @param hash_b The hash of the block to be checked.
 * 
 * @return A boolean value.
 */
LIBDOGECOIN_API static inline dogecoin_bool dogecoin_hash_equal(uint256 hash_a, uint256 hash_b)
{
    return (memcmp(hash_a, hash_b, DOGECOIN_HASH_LENGTH) == 0);
}

/**
 * Given a destination hash and a source hash, copy the source hash into the destination hash
 * 
 * @param hash_dest the destination hash
 * @param hash_src the hash of the block header
 */
LIBDOGECOIN_API static inline void dogecoin_hash_set(uint256 hash_dest, const uint256 hash_src)
{
    memcpy(hash_dest, hash_src, DOGECOIN_HASH_LENGTH);
}

/**
 * The function takes in a pointer to a buffer of data, the length of the buffer, and a pointer to a
 * buffer to store the hash in. 
 * It then hashes the data twice, and stores the result in the second buffer
 * 
 * @param datain the data to be hashed
 * @param length The length of the data to be hashed.
 * @param hashout the output of the sha256_raw function
 */
LIBDOGECOIN_API static inline void dogecoin_hash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout);
    sha256_raw(hashout, SHA256_DIGEST_LENGTH, hashout); // dogecoin double sha256 hash
}

/**
 * Given a string of data, hash it twice using SHA256
 * 
 * @param datain The data to be hashed.
 * @param length The length of the data to be hashed.
 * @param hashout the output of the double sha256 hash
 * 
 * @return A boolean value.
 */
LIBDOGECOIN_API static inline dogecoin_bool dogecoin_dblhash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout);
    sha256_raw(hashout, SHA256_DIGEST_LENGTH, hashout); // dogecoin double sha256 hash
    return true;
}

/**
 * Given a string of data, calculate the SHA256 hash of that data
 * 
 * @param datain the data to be hashed
 * @param length the length of the data to hash
 * @param hashout the output hash
 */
LIBDOGECOIN_API static inline void dogecoin_hash_sngl_sha256(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_raw(datain, length, hashout); // single sha256 hash
}

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_CRYPTO_HASH_H__
