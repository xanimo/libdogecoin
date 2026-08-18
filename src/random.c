/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum
 Copyright (c) 2024 bluezr
 Copyright (c) 2024 The Dogecoin Foundation

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

#include <dogecoin/common.h>
#include <dogecoin/mem.h>
#include <dogecoin/random.h>

#include <assert.h>
#ifdef HAVE_CONFIG_H
#include "libdogecoin-config.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* The device the POSIX fallback reads entropy from. Normally set by the build:
   -DRANDOM_DEVICE=... from CMake, or libdogecoin-config.h under autotools.
   The guard is a backstop for configurations that define neither -- it must
   never be reached silently in a shipped build, which is why the value it
   picks is the conservative one rather than a blocking device. */
#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif
#if defined _WIN32
#ifdef _MSC_VER
#include <win/winunistd.h>
#endif
#else
#include <unistd.h>
#endif
#if defined _WIN32 && ! defined __CYGWIN__
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# if HAVE_BCRYPT_H
#  include <bcrypt.h>
# else
#  define NTSTATUS LONG
typedef void* BCRYPT_ALG_HANDLE;
#  define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#  if HAVE_LIB_BCRYPT
extern NTSTATUS WINAPI BCryptGenRandom(BCRYPT_ALG_HANDLE, UCHAR*, ULONG, ULONG);
#  endif
# endif
# if !HAVE_LIB_BCRYPT
#include <wincrypt.h>
#  ifndef CRYPT_VERIFY_CONTEXT
#   define CRYPT_VERIFY_CONTEXT 0xF0000000
#  endif
# endif
#endif

#if defined _WIN32 && ! defined __CYGWIN__

/* Don't assume that UNICODE is not defined.  */
#undef LoadLibrary
#define LoadLibrary LoadLibraryA
#undef CryptAcquireContext
#define CryptAcquireContext CryptAcquireContextA

#if !HAVE_LIB_BCRYPT
/* Avoid warnings from gcc -Wcast-function-type.  */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#define GetProcAddress \
     (void *)GetProcAddress
#pragma GCC diagnostic pop

/* BCryptGenRandom with the BCRYPT_USE_SYSTEM_PREFERRED_RNG flag works only
   starting with Windows 7.  */
typedef NTSTATUS(WINAPI* BCryptGenRandomFuncType) (BCRYPT_ALG_HANDLE, UCHAR*, ULONG, ULONG);

/* These are published exactly once by rng_initialize_once() under
   InitOnceExecuteOnce(), so concurrent first use can neither double-initialize
   nor observe a half-initialized loader. After the one-time init completes they
   are immutable and may be read locklessly. */
static BCryptGenRandomFuncType BCryptGenRandomFunc = NULL;
static HCRYPTPROV crypt_provider = 0;
static int crypt_provider_ok = 0;
static INIT_ONCE rng_init_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
rng_initialize_once(PINIT_ONCE InitOnce, PVOID Parameter, PVOID* Context)
    {
    (void)InitOnce;
    (void)Parameter;
    (void)Context;
    HMODULE bcrypt = LoadLibrary("bcrypt.dll");
    if (bcrypt != NULL)
        {
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wpedantic"
        BCryptGenRandomFunc =
            (BCryptGenRandomFuncType)GetProcAddress(bcrypt, "BCryptGenRandom"); // TODO: find specific type to cast to when building mingw32
        #pragma GCC diagnostic pop
        }
    /* Acquire the deprecated CryptGenRandom provider as a fallback for systems
       where BCryptGenRandom is unavailable. */
    if (CryptAcquireContextA(&crypt_provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFY_CONTEXT))
        crypt_provider_ok = 1;
    return TRUE;
    }

# else
#  define BCryptGenRandomFunc BCryptGenRandom
# endif
#endif

void dogecoin_random_init_internal(void);
dogecoin_bool dogecoin_random_bytes_internal(uint8_t* buf, uint32_t len, const uint8_t update_seed);

static const dogecoin_rnd_mapper default_rnd_mapper = { dogecoin_random_init_internal, dogecoin_random_bytes_internal };
static DOGECOIN_THREAD_LOCAL dogecoin_rnd_mapper current_rnd_mapper = { dogecoin_random_init_internal, dogecoin_random_bytes_internal };

void dogecoin_rnd_set_mapper_default()
    {
    current_rnd_mapper = default_rnd_mapper;
    }

void dogecoin_rnd_set_mapper(const dogecoin_rnd_mapper mapper)
    {
    current_rnd_mapper = mapper;
    }

/* Struct-free entry point for callers that include only libdogecoin.h, which
   cannot carry the mapper's struct definition without colliding with
   dogecoin/random.h. Keeps the default initialiser: a platform generator that
   needs no setup is the normal case, and the default init is a no-op. */
void dogecoin_rnd_set_bytes_cb(dogecoin_bool (*cb)(uint8_t* buf, uint32_t len, const uint8_t update_seed))
    {
    if (!cb) { dogecoin_rnd_set_mapper_default(); return; }
    current_rnd_mapper.dogecoin_random_init  = dogecoin_random_init_internal;
    current_rnd_mapper.dogecoin_random_bytes = cb;
    }

void dogecoin_random_init(void)
    {
    current_rnd_mapper.dogecoin_random_init();
    }

dogecoin_bool dogecoin_random_bytes(uint8_t* buf, uint32_t len, const uint8_t update_seed)
    {
    return current_rnd_mapper.dogecoin_random_bytes(buf, len, update_seed);
    }

#ifdef TESTING
/*
 * This branch replaces the CSPRNG with srand(time(NULL)) and rand(), which
 * would make every key this library generates predictable from the wall clock.
 * Nothing in the build system defines TESTING -- not CMakeLists.txt, not
 * configure.ac -- so it is unreachable today. The guard is here so that it
 * stays unreachable in anything shipped: a release build sets NDEBUG, and
 * combining the two must fail loudly at compile time rather than quietly
 * produce guessable keys.
 */
#ifdef NDEBUG
#error "TESTING replaces the RNG with srand()/rand(); it must never be enabled in a release build"
#endif

void dogecoin_random_init_internal(void)
    {
    srand(time(NULL));
    }

dogecoin_bool dogecoin_random_bytes_internal(uint8_t* buf, uint32_t len, const uint8_t update_seed)
    {
    (void)update_seed;
    for (uint32_t i = 0; i < len; i++)
        buf[i] = rand();
    return true;
    }
#else
/* An enclave or trusted application supplies its own generator through
   dogecoin_rnd_set_mapper(), which replaces this whole function rather than
   short-circuiting part of it. The old set_rng()/rng_ptr hook did the latter:
   it returned early on success but fell through to the POSIX fallback below on
   any failure, which is the one path an enclave cannot take. It was also never
   declared in any header, so each backend wrote its own prototype and all three
   disagreed on the callback's type. */
void dogecoin_random_init_internal(void)
    {
    }
dogecoin_bool dogecoin_random_bytes_internal(uint8_t* buf, uint32_t len, const uint8_t update_seed)
    {
#ifdef WIN32
    (void)update_seed;
    /* BCryptGenRandom, defined in <bcrypt.h>
         <https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom>
         with the BCRYPT_USE_SYSTEM_PREFERRED_RNG flag
         works in Windows 7 and newer.  */
#if !HAVE_LIB_BCRYPT
    /* One-time, race-free loader: resolves BCryptGenRandom and acquires the
       legacy CryptGenRandom provider exactly once across all threads. */
    InitOnceExecuteOnce(&rng_init_once, rng_initialize_once, NULL, NULL);
    if (BCryptGenRandomFunc != NULL
        && BCryptGenRandomFunc(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 /*STATUS_SUCCESS*/)
        return true;
    /* CryptGenRandom, defined in <wincrypt.h>
       <https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom>
       works in older releases as well, but is now deprecated.
       CryptAcquireContext, defined in <wincrypt.h>
       <https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta>  */
    if (crypt_provider_ok) {
        if (!CryptGenRandom(crypt_provider, len, buf)) {
            errno = EIO;
            dogecoin_mem_zero(buf, len);
            return false;
            }
        return true;
        }
# else
    if (BCryptGenRandomFunc(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 /*STATUS_SUCCESS*/)
        return true;
# endif
    /* No usable RNG at all. This must report failure, not -1: the return type
       is dogecoin_bool, which is a uint8_t, so -1 arrives at the caller as 255
       -- a true value. Every caller writing `if (!dogecoin_random_bytes(...))`
       saw success while buf still held whatever was on the stack. */
    errno = ENOSYS;
    dogecoin_mem_zero(buf, len);
    return false;
#else
    (void)update_seed; //unused
    FILE* frand = fopen(RANDOM_DEVICE, "rb");
    if (!frand)
        return false;
    size_t len_read = fread(buf, 1, len, frand);
    fclose(frand);
    /* A short read must fail the call, not just trip an assert: assert() is
       compiled out under NDEBUG, which CMake's Release configuration sets by
       default (-O3 -DNDEBUG). In that build a partial read left the tail of buf
       holding whatever was already in that memory and still returned true, so a
       caller would use uninitialised bytes as key material.
       Zero the buffer as well as returning false, so that a caller which ignores
       the return value gets an obviously-unusable all-zero key rather than
       something that looks random enough to spend to. */
    if (len_read != len) {
        dogecoin_mem_zero(buf, len);
        return false;
    }
    return true;
#endif
    }
#endif

void random_seed(struct fast_random_context* this)
{
    dogecoin_random_init();
    uint256_t seed;
    dogecoin_mem_zero(seed, 32);
    dogecoin_random_bytes(seed, 32, 0);
    this->rng->setkey(this->rng, seed, 32);
    this->requires_seed = false;
}

void fill_byte_buffer(struct fast_random_context* this)
{
    if (this->requires_seed) {
        random_seed(this);
    }
    this->rng->output(this->rng, this->bytebuf, sizeof(this->bytebuf));
    this->bytebuf_size = sizeof(this->bytebuf);
}

uint256_t* rand256(struct fast_random_context* this)
{
    if (this->bytebuf_size < 32) {
        fill_byte_buffer(this);
    }
    uint256_t* ret = dogecoin_uint256_vla(1);
    memcpy(ret, this->bytebuf + 64 - this->bytebuf_size, 32);
    this->bytebuf_size -= 32;
    return ret;
}

/** Generate a random 64-bit integer. */
uint64_t rand64(struct fast_random_context* this)
{
    if (this->requires_seed) random_seed(this);
    unsigned char buf[8];
    this->rng->output(this->rng, buf, 8);
    return read_le64(buf);
}

void fill_bit_buffer(struct fast_random_context* this)
{
    this->bitbuf = rand64(this);
    this->bitbuf_size = 64;
}

/** Generate a random (bits)-bit integer. */
uint64_t randbits(struct fast_random_context* this, int bits)
{
    if (bits == 0) {
        return 0;
    } else if (bits > 32) {
        return rand64(this) >> (64 - bits);
    } else {
        if (this->bitbuf_size < bits) fill_bit_buffer(this);
        uint64_t zero = 0;
        uint64_t ret = this->bitbuf & (~zero >> (64 - bits));
        this->bitbuf >>= bits;
        this->bitbuf_size -= bits;
        return ret;
    }
}

uint64_t randrange(struct fast_random_context* this, uint64_t range)
{
    assert(range);
    --range;
    int bits = count_bits(range);
    while (true) {
        uint64_t ret = randbits(this, bits);
        if (ret <= range) return ret;
    }
}

/** Generate a random 32-bit integer. */
uint32_t rand32(struct fast_random_context* this) { return randbits(this, 32); }

/** Generate a random boolean. */
dogecoin_bool randbool(struct fast_random_context* this) { return randbits(this, 1); }

struct fast_random_context* init_fast_random_context(dogecoin_bool f_deterministic, const uint256_t* seed) {
    struct fast_random_context* this = dogecoin_calloc(1, sizeof(*this));
    this->requires_seed = false;
    this->random_seed = random_seed;
    this->fill_bit_buffer = fill_bit_buffer;
    this->fill_byte_buffer = fill_byte_buffer;
    this->rand256 = rand256;
    this->rand64 = rand64;
    this->randbits = randbits;
    this->rand32 = rand32;
    this->randbool = randbool;
    if (!f_deterministic) {
        if (seed == NULL) {
            this->rng = chacha20_new();
            random_seed(this);
        }
        return this;
    } else {
        this->rng = chacha20_init((const unsigned char*)seed, 32);
    }
    return this;
}

void free_fast_random_context(struct fast_random_context* this) {
    if (this->rng != NULL) {
        chacha20_free(this->rng);
    }
    dogecoin_free(this);
}
