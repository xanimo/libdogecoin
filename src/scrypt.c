/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include <dogecoin/mem.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if defined(USE_SSE2) && !defined(USE_SSE2_ALWAYS)
#ifdef _MSC_VER
// MSVC 64bit is unable to use inline asm
#include <intrin.h>
#else
// GCC Linux or i686-w64-mingw32
#include <cpuid.h>
#endif
#endif

#ifdef _MSC_VER
  #define INLINE __inline
#else
  #define INLINE inline
#endif

#ifndef __DragonFly__
static INLINE uint32_t
be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static INLINE void
be32enc(void *pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

void scrypt_1024_1_1_256_sp_generic(const char *input, char *output, char *scratchpad)
{
	uint8_t B[128];
	uint32_t X[32];
	uint32_t *V;
	uint32_t i, j, k;

	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	pbkdf2_hmac_sha256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

	for (k = 0; k < 32; k++)
		X[k] = le32dec(&B[4 * k]);

	for (i = 0; i < 1024; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i++) {
		j = 32 * (X[16] & 1023);
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}

	for (k = 0; k < 32; k++)
		le32enc(&B[4 * k], X[k]);

	pbkdf2_hmac_sha256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
	swap_bytes((uint8_t*)output, 32);
}

#if defined(USE_SSE2)
void (*scrypt_1024_1_1_256_sp_detected)(const char *input, char *output, char *scratchpad) = &scrypt_1024_1_1_256_sp_generic;

void scrypt_detect_sse2()
{
#if defined(USE_SSE2_ALWAYS)
    printf("scrypt: using scrypt-sse2 as built.\n");
#else // USE_SSE2_ALWAYS
    // 32bit x86 Linux or Windows, detect cpuid features
    unsigned int cpuid_edx=0;
#if defined(_MSC_VER)
    // MSVC
    int x86cpuid[4];
    __cpuid(x86cpuid, 1);
    cpuid_edx = (unsigned int)x86cpuid[3];
#else // _MSC_VER
    // Linux or i686-w64-mingw32 (gcc-4.6.3)
    unsigned int eax, ebx, ecx;
    __get_cpuid(1, &eax, &ebx, &ecx, &cpuid_edx);
#endif // _MSC_VER

    if (cpuid_edx & 1<<26)
    {
        scrypt_1024_1_1_256_sp_detected = &scrypt_1024_1_1_256_sp_sse2;
        printf("scrypt: using scrypt-sse2 as detected.\n");
    }
    else
    {
        scrypt_1024_1_1_256_sp_detected = &scrypt_1024_1_1_256_sp_generic;
        printf("scrypt: using scrypt-generic, SSE2 unavailable.\n");
    }
#endif // USE_SSE2_ALWAYS
}
#endif

void scrypt_1024_1_1_256(const char *input, char *output)
{
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
    memset(scratchpad, 0, sizeof(scratchpad));
    scrypt_1024_1_1_256_sp(input, output, scratchpad);
}

/* --- RFC 7914 scrypt (BIP38 and other password KDFs) --- */

static void scrypt_rfc7914_blkxor(uint32_t* dest, const uint32_t* src, size_t len)
{
    size_t i;
    for (i = 0; i < len / 4; i++)
        dest[i] ^= src[i];
}

static void scrypt_rfc7914_salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    size_t i;

    memcpy(x, B, 64);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);

        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);

        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);

        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);

        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);

        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);

        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);

        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
#undef R
    }
    for (i = 0; i < 16; i++)
        B[i] += x[i];
}

static void scrypt_rfc7914_blockmix_salsa8(uint32_t* Bin, uint32_t* Bout, uint32_t* X, size_t r)
{
    size_t i;

    memcpy(X, &Bin[(2 * r - 1) * 16], 64);

    for (i = 0; i < 2 * r; i += 2) {
        scrypt_rfc7914_blkxor(X, &Bin[i * 16], 64);
        scrypt_rfc7914_salsa20_8(X);

        memcpy(&Bout[i * 8], X, 64);

        scrypt_rfc7914_blkxor(X, &Bin[i * 16 + 16], 64);
        scrypt_rfc7914_salsa20_8(X);

        memcpy(&Bout[i * 8 + r * 16], X, 64);
    }
}

static uint64_t scrypt_rfc7914_integerify(uint32_t* B, size_t r)
{
    const uint32_t* X = B + (2 * r - 1) * 16;
    return (((uint64_t)(X[1]) << 32) + X[0]);
}

static void scrypt_rfc7914_smix(uint8_t* B, size_t r, uint64_t N, uint32_t* V, uint32_t* XY)
{
    uint32_t* X = XY;
    uint32_t* Y = &XY[32 * r];
    uint32_t* Z = &XY[64 * r];
    uint64_t i;
    uint64_t j;
    size_t k;

    for (k = 0; k < 32 * r; k++)
        X[k] = le32dec(&B[4 * k]);

    for (i = 0; i < N; i += 2) {
        memcpy(&V[i * (32 * r)], X, 128 * r);
        scrypt_rfc7914_blockmix_salsa8(X, Y, Z, r);

        memcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);
        scrypt_rfc7914_blockmix_salsa8(Y, X, Z, r);
    }

    for (i = 0; i < N; i += 2) {
        j = scrypt_rfc7914_integerify(X, r) & (N - 1);

        scrypt_rfc7914_blkxor(X, &V[j * (32 * r)], 128 * r);
        scrypt_rfc7914_blockmix_salsa8(X, Y, Z, r);

        j = scrypt_rfc7914_integerify(Y, r) & (N - 1);

        scrypt_rfc7914_blkxor(Y, &V[j * (32 * r)], 128 * r);
        scrypt_rfc7914_blockmix_salsa8(Y, X, Z, r);
    }

    for (k = 0; k < 32 * r; k++)
        le32enc(&B[4 * k], X[k]);
}

static void* scrypt_rfc7914_alloc_aligned(size_t size, size_t align, void** base_out)
{
    void* p = malloc(size + align - 1);
    *base_out = p;
    if (!p)
        return NULL;
    return (void*)(((uintptr_t)p + align - 1) & ~(uintptr_t)(align - 1));
}

int dogecoin_scrypt_rfc7914(
    const uint8_t* passwd,
    size_t passwdlen,
    const uint8_t* salt,
    size_t saltlen,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    uint8_t* buf,
    size_t buflen)
{
    void *B0 = NULL, *V0 = NULL, *XY0 = NULL;
    uint8_t* B;
    uint32_t* V;
    uint32_t* XY;
    uint32_t i;

    if (buflen > (((uint64_t)1 << 32) - 1) * 32)
        return 0;
    if ((uint64_t)r * (uint64_t)p >= (1ULL << 30))
        return 0;
    if (r == 0 || p == 0)
        return 0;
    if (((N & (N - 1)) != 0) || (N < 2))
        return 0;
    if (r > SIZE_MAX / 128 / p)
        return 0;
    if (N > SIZE_MAX / 128 / r)
        return 0;

    B = (uint8_t*)scrypt_rfc7914_alloc_aligned(128 * r * p + 63, 64, &B0);
    if (!B0)
        return 0;
    XY = (uint32_t*)scrypt_rfc7914_alloc_aligned((256 * r + 64) + 63, 64, &XY0);
    if (!XY0) {
        free(B0);
        return 0;
    }
    V = (uint32_t*)scrypt_rfc7914_alloc_aligned(128 * r * N + 63, 64, &V0);
    if (!V0) {
        free(XY0);
        free(B0);
        return 0;
    }

    pbkdf2_hmac_sha256(passwd, (int)passwdlen, salt, (int)saltlen, 1, B, (int)(p * 128 * r));

    for (i = 0; i < p; i++) {
        scrypt_rfc7914_smix(&B[i * 128 * r], r, N, V, XY);
    }

    pbkdf2_hmac_sha256(passwd, (int)passwdlen, B, (int)(p * 128 * r), 1, buf, (int)buflen);

    dogecoin_mem_zero(V0, 128 * r * N + 63);
    dogecoin_mem_zero(XY0, (256 * r + 64) + 63);
    dogecoin_mem_zero(B0, 128 * r * p + 63);
    free(V0);
    free(XY0);
    free(B0);
    return 1;
}
