/*

 The MIT License (MIT)
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 edtubbs
 Copyright (c) 2023-2024 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_DOGECOIN_H__
#define __LIBDOGECOIN_DOGECOIN_H__

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pull in libdogecoin-config.h early so platform gates below (e.g. USE_OPTEE)
 * are visible before we decide whether to enable a pthread-backed mutex. */
#if defined(HAVE_CONFIG_H) && !defined(USE_LIB)
#include <config/libdogecoin-config.h>
#endif

#ifdef _WIN32
/* Require Windows 8+ so both winnls.h's NormalizationKD/NormalizeString and
 * winsock2.h's htonll/ntohll prototypes are visible to all consumers of this
 * header. (NormalizationKD needs 0x0600, htonll needs 0x0602.) */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef WINVER
#define WINVER 0x0602
#endif
/* Avoid pulling in legacy <winsock.h> from <windows.h>, which would conflict
 * with <winsock2.h> included by libdogecoin's net code on MSVC. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#define DOGECOIN_HAVE_THREADS 1
/* Only enable pthread-backed mutexes on hosted POSIX-like targets where we
 * know <pthread.h> exists AND the pthread runtime will be linked.  Bare-metal
 * / freestanding targets such as OP-TEE Trusted Applications (libutee) ship a
 * <pthread.h> via the cross toolchain headers but cannot resolve
 * pthread_mutex_* at link time, so they fall through to the no-op stubs. */
#elif !defined(USE_OPTEE) && \
      (defined(__GLIBC__) || defined(__BIONIC__) || defined(__APPLE__) || \
       defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
       defined(__DragonFly__) || defined(__CYGWIN__) || defined(__MINGW32__) || \
       defined(__MINGW64__) || defined(__sun) || defined(__HAIKU__))
#include <pthread.h>
#define DOGECOIN_HAVE_THREADS 1
#endif

typedef uint8_t dogecoin_bool; //!serialize, c/c++ save bool

struct dogecoin_context_;
/* Short-form context alias used by the `_ts` API surface. */
typedef struct dogecoin_context_ dogecoin_ctx;

typedef struct dogecoin_mutex_ {
#ifdef _WIN32
    CRITICAL_SECTION handle;
#elif defined(DOGECOIN_HAVE_THREADS)
    pthread_mutex_t handle;
#else
    /* Freestanding/baremetal targets (e.g. OP-TEE TAs) without a threading
     * runtime: keep the struct compilable; the inline helpers below become
     * no-ops, and TS APIs must not be invoked in such builds. */
    int handle;
#endif
    dogecoin_bool initialized;
} dogecoin_mutex_t;

#ifndef __cplusplus
#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif
#endif //__cplusplus

#ifdef __cplusplus
#define LIBDOGECOIN_BEGIN_DECL extern "C" {
#define LIBDOGECOIN_END_DECL }
#else
#define LIBDOGECOIN_BEGIN_DECL /* empty */
#define LIBDOGECOIN_END_DECL   /* empty */
#endif

#ifndef LIBDOGECOIN_API
#if defined(_WIN32)
#ifdef LIBDOGECOIN_BUILD
#define LIBDOGECOIN_API __declspec(dllexport)
#else
#define LIBDOGECOIN_API
#endif
#elif defined(__GNUC__) && defined(LIBDOGECOIN_BUILD)
#define LIBDOGECOIN_API __attribute__((visibility("default")))
#else
#define LIBDOGECOIN_API
#endif
#endif

#if defined(_MSC_VER)
#define DOGECOIN_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define DOGECOIN_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define DOGECOIN_THREAD_LOCAL __thread
#else
/* Fallback for compilers without TLS support. */
#define DOGECOIN_THREAD_LOCAL
#endif

#if defined(_MSC_VER)
    #define DISABLE_WARNING_PUSH           __pragma(warning( push ))
    #define DISABLE_WARNING_POP            __pragma(warning( pop ))
    #define DISABLE_WARNING(warningNumber) __pragma(warning( disable : warningNumber ))

    #define DISABLE_WARNING_UNREFERENCED_FORMAL_PARAMETER    DISABLE_WARNING(4100)
    #define DISABLE_WARNING_UNREFERENCED_FUNCTION            DISABLE_WARNING(4505)
    // other warnings you want to deactivate...
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;

    //MLUMIN:MSVC - need winsock for msvc
    #pragma comment(lib, "Ws2_32.lib")
    #pragma comment(lib, "wsock32.lib")
    //MLUMIN:MSVC - need Iphlpapi.lib for __imp_f_nametoindex in msvc
    #pragma comment(lib, "Iphlpapi.lib")
    //MLUMIN:MSVC - need strtok_r redefined as strtok_s in msvc
    #define strtok_r strtok_s


#elif defined(__GNUC__) || defined(__clang__)
    #define DO_PRAGMA(X) _Pragma(#X)
    #define DISABLE_WARNING_PUSH           DO_PRAGMA(GCC diagnostic push)
    #define DISABLE_WARNING_POP            DO_PRAGMA(GCC diagnostic pop)
    #define DISABLE_WARNING(warningName)   DO_PRAGMA(GCC diagnostic ignored #warningName)

    #define DISABLE_WARNING_UNREFERENCED_FORMAL_PARAMETER    DISABLE_WARNING(-Wunused-parameter)
    #define DISABLE_WARNING_UNREFERENCED_FUNCTION            DISABLE_WARNING(-Wunused-function)
   // other warnings you want to deactivate...

#else
    #define DISABLE_WARNING_PUSH
    #define DISABLE_WARNING_POP
    #define DISABLE_WARNING_UNREFERENCED_FORMAL_PARAMETER
    #define DISABLE_WARNING_UNREFERENCED_FUNCTION
    // other warnings you want to deactivate:

#endif

#ifndef ENABLE_DEBUG
#define ENABLE_DEBUG 0
#endif
#ifdef ENABLE_DEBUG
#define debug_print(fmt, ...) \
        do { if (ENABLE_DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)
#endif

/* Constants for ECC */
#define DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH 65
#define DOGECOIN_ECKEY_COMPRESSED_LENGTH 33
#define DOGECOIN_ECKEY_PKEY_LENGTH 32
#define DOGECOIN_HASH_LENGTH 32
#define DOGECOIN_HASH_HEX_LENGTH (DOGECOIN_HASH_LENGTH * 2 + 1)

/* Accepted hex character set for strspn validation */
#define VALID_HEX_CHARS "0123456789abcdefABCDEF"
#define VALID_BASE58_CHARS "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

/* Constants for BIP32 */
#define MAX_SEED_SIZE 64
#define HDKEYLEN 112
#define PRIVKEYWIFLEN 53
#define P2PKHLEN 35
#define PRIVKEYHEXLEN DOGECOIN_ECKEY_PKEY_LENGTH * 2 + 1
#define PUBKEYHEXLEN 67
#define PUBKEYHASHLEN 41
#define SCRIPTPUBKEYLEN 51 // 40 + 6 + 4 + 1
#define KEYPATHMAXLEN 256

/* Constants for transaction */
#define SCRIPT_PUBKEY_LENGTH 25
#define MAX_SERIALIZE_SIZE 2048

#define DOGECOIN_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define DOGECOIN_MAX(a, b) (((a) > (b)) ? (a) : (b))

LIBDOGECOIN_BEGIN_DECL

/* Data array types */
typedef uint8_t uint256_t[32];
typedef uint8_t uint160_t[20];
typedef uint8_t SEED[MAX_SEED_SIZE];

static const int WIDTH = 0x0000100/32;

LIBDOGECOIN_API dogecoin_ctx* dogecoin_ctx_new(dogecoin_bool testnet, dogecoin_bool enable_net);
LIBDOGECOIN_API dogecoin_ctx* dogecoin_ctx_new_ts(dogecoin_bool testnet, dogecoin_bool enable_net);
LIBDOGECOIN_API void dogecoin_ctx_acquire(dogecoin_ctx* ctx);
LIBDOGECOIN_API void dogecoin_ctx_release(dogecoin_ctx* ctx);
LIBDOGECOIN_API int dogecoin_ctx_is_thread_safe(const dogecoin_ctx* ctx);

static inline dogecoin_bool dogecoin_mutex_init(dogecoin_mutex_t* mutex)
{
    if (!mutex) return false;
#ifdef _WIN32
    InitializeCriticalSection(&mutex->handle);
    mutex->initialized = true;
    return true;
#elif defined(DOGECOIN_HAVE_THREADS)
    if (pthread_mutex_init(&mutex->handle, NULL) != 0) {
        mutex->initialized = false;
        return false;
    }
    mutex->initialized = true;
    return true;
#else
    (void)mutex;
    return false;
#endif
}

static inline void dogecoin_mutex_lock(dogecoin_mutex_t* mutex)
{
    if (!mutex || !mutex->initialized) return;
#ifdef _WIN32
    EnterCriticalSection(&mutex->handle);
#elif defined(DOGECOIN_HAVE_THREADS)
    pthread_mutex_lock(&mutex->handle);
#else
    (void)mutex;
#endif
}

static inline void dogecoin_mutex_unlock(dogecoin_mutex_t* mutex)
{
    if (!mutex || !mutex->initialized) return;
#ifdef _WIN32
    LeaveCriticalSection(&mutex->handle);
#elif defined(DOGECOIN_HAVE_THREADS)
    pthread_mutex_unlock(&mutex->handle);
#else
    (void)mutex;
#endif
}

static inline void dogecoin_mutex_destroy(dogecoin_mutex_t* mutex)
{
    if (!mutex || !mutex->initialized) return;
#ifdef _WIN32
    DeleteCriticalSection(&mutex->handle);
#elif defined(DOGECOIN_HAVE_THREADS)
    pthread_mutex_destroy(&mutex->handle);
#endif
    mutex->initialized = false;
}

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_DOGECOIN_H__
