/**
 * Copyright (c) 2026 edtubbs
 * Copyright (c) 2026 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __LIBDOGECOIN_SLIP0039_H__
#define __LIBDOGECOIN_SLIP0039_H__

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/* SLIP-0039 mnemonic constants */
/* each share is a space-separated list of words from the 1024-word SLIP-0039 wordlist */
/* a 256-bit secret produces 33 words per share (max 8 chars/word + space) */
/* 320 chars is a comfortable upper bound including the terminating null */
#ifndef SLIP0039_DECLS_DEFINED
#define SLIP0039_DECLS_DEFINED
#define SLIP0039_MAX_SHARES 16
#define SLIP0039_MAX_SHARE_STR_SIZE 320
#define SLIP0039_MIN_SECRET_BYTES 16
#define SLIP0039_MAX_SECRET_BYTES 32

/* null-terminated string buffer holding one SLIP-0039 share */
typedef char SLIP0039_SHARE[SLIP0039_MAX_SHARE_STR_SIZE];

/* generates SLIP-0039 mnemonic shares for a binary secret */
/* secret: secret bytes to split, secret_len: length in bytes */
/* threshold: shares required to recover, share_count: shares to generate */
/* shares: output buffer for generated share strings */
/* returns 0 on success, -1 on invalid input or failure */
LIBDOGECOIN_API int dogecoin_slip0039_generate_shares(const uint8_t* secret, size_t secret_len, uint8_t threshold, uint8_t share_count, char shares[][SLIP0039_MAX_SHARE_STR_SIZE]);

/* recovers a binary secret from SLIP-0039 mnemonic shares */
/* shares: input share strings, share_count: number of shares provided */
/* passphrase: optional passphrase bytes, passphrase_len: length in bytes */
/* secret_out: output buffer for recovered secret bytes */
/* secret_len_out: in/out size of secret_out and recovered length */
/* returns 0 on success, -1 on invalid input or recovery failure */
LIBDOGECOIN_API int dogecoin_slip0039_recover_secret(const char* shares[], size_t share_count, const uint8_t* passphrase, size_t passphrase_len, uint8_t* secret_out, size_t* secret_len_out);
#endif /* SLIP0039_DECLS_DEFINED */

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SLIP0039_H__
