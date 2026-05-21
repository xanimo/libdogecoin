/**
 * Copyright (c) 2015-2016 The Bitcoin Core developers
 * Copyright (c) 2024-2026 edtubbs
 * Copyright (c) 2024-2026 The Dogecoin Foundation
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <float.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef _WIN32
#include <windows.h>
#elif defined(__arm__) || defined(__aarch64__)
#include <time.h>
#else
#include <x86intrin.h>
#endif

/* libdogecoin */
#include <dogecoin/dogecoin.h>    /* brings public API, incl. ECC */
#include <dogecoin/sha2.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/hash.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/tx.h>
#include <dogecoin/mem.h>
#include <dogecoin/random.h>
#include <dogecoin/utils.h>
#include <dogecoin/pqc_falcon.h>
#ifdef USE_RACCOON_G
#include <dogecoin/pqc_raccoon.h>
#endif
#include <dogecoin/ecc.h>

#define BUFFER_SIZE (1000 * 1000)
#define HASH_SIZE 32
#define MAX_BENCHMARKS 50

typedef struct {
    double start, end, minTime, maxTime, totalTime;
    uint64_t startCycles, endCycles, minCycles, maxCycles, totalCycles, count;
    uint8_t *input;
    uint8_t *output;
} benchmark_context;

/* Structure to store benchmark results for analysis */
typedef struct {
    char name[32];
    char category[64];
    uint64_t count;
    double minTime;
    double maxTime;
    double avgTime;
    uint64_t minCycles;
    uint64_t maxCycles;
    uint64_t avgCycles;
} benchmark_result;

/* Global storage for all benchmark results */
static benchmark_result results[MAX_BENCHMARKS];
static int num_results = 0;

#if defined(__GNUC__) || defined(__clang__)
static void bench_require(int ok, const char* op) __attribute__((unused));
#endif
static void bench_require(int ok, const char* op) {
    if (!ok) {
        fprintf(stderr, "Benchmark fatal: %s failed\n", op);
        exit(EXIT_FAILURE);
    }
}

/* ---- timing helpers ---- */
static double gettimedouble(void) {
#ifdef _WIN32
    /* Use GetTickCount64 if available (Vista+), otherwise fall back to GetTickCount */
    #if defined(_WIN64) || (defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600)
        return (double)GetTickCount64() / 1000.0;
    #else
        /* For 32-bit Windows or older MinGW, use GetTickCount (32-bit, wraps every 49.7 days) */
        return (double)GetTickCount() / 1000.0;
    #endif
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
#endif
}

static uint64_t perf_cpucycles(void) {
#ifdef _WIN32
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (uint64_t)li.QuadPart;
#elif defined(__arm__) || defined(__aarch64__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
#else
    return (uint64_t)__rdtsc();
#endif
}

/* ---- harness ---- */
typedef void (*bench_fn)(benchmark_context *);

static void run_benchmark(bench_fn fn, const char *name, const char *category) {
    benchmark_context ctx;
    ctx.input = (uint8_t*)calloc(BUFFER_SIZE, sizeof(uint8_t));
    ctx.output = (uint8_t*)malloc(HASH_SIZE);
    ctx.minTime = DBL_MAX;
    ctx.maxTime = DBL_MIN;
    ctx.minCycles = UINT64_MAX;
    ctx.maxCycles = 0;
    ctx.totalTime = 0.0;
    ctx.totalCycles = 0;
    ctx.count = 0;

    ctx.start = gettimedouble();
    ctx.startCycles = perf_cpucycles();

    while (1) {
        fn(&ctx);

        double time = ctx.end - ctx.start;
        uint64_t cycles = ctx.endCycles - ctx.startCycles;

        ctx.count++;
        if (time   < ctx.minTime)   ctx.minTime   = time;
        if (time   > ctx.maxTime)   ctx.maxTime   = time;
        if (cycles < ctx.minCycles) ctx.minCycles = cycles;
        if (cycles > ctx.maxCycles) ctx.maxCycles = cycles;

        if (ctx.totalTime > 3.0) break;

        ctx.start = ctx.end;
        ctx.startCycles = ctx.endCycles;
    }

    double avgTime = ctx.count ? ctx.totalTime / (double)ctx.count : 0.0;
    uint64_t avgCycles = ctx.count ? ctx.totalCycles / ctx.count : 0ULL;

    printf("%-16s %-8lu %-10.6f %-10.6f %-10.6f %-12lu %-12lu %-12llu\n",
           name,
           (unsigned long)ctx.count,
           ctx.minTime,
           ctx.maxTime,
           avgTime,
           (unsigned long)ctx.minCycles,
           (unsigned long)ctx.maxCycles,
           (unsigned long long)avgCycles);

    /* Store result for later analysis */
    if (num_results < MAX_BENCHMARKS) {
        strncpy(results[num_results].name, name, sizeof(results[num_results].name) - 1);
        results[num_results].name[sizeof(results[num_results].name) - 1] = '\0';
        strncpy(results[num_results].category, category, sizeof(results[num_results].category) - 1);
        results[num_results].category[sizeof(results[num_results].category) - 1] = '\0';
        results[num_results].count = ctx.count;
        results[num_results].minTime = ctx.minTime;
        results[num_results].maxTime = ctx.maxTime;
        results[num_results].avgTime = avgTime;
        results[num_results].minCycles = ctx.minCycles;
        results[num_results].maxCycles = ctx.maxCycles;
        results[num_results].avgCycles = avgCycles;
        num_results++;
    }

    free(ctx.input);
    free(ctx.output);
}

/* ---- baselines ---- */

static void sha256_bench(benchmark_context *ctx) {
    sha256_raw(ctx->input, BUFFER_SIZE, ctx->output);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void scrypt_bench(benchmark_context *ctx) {
    scrypt_1024_1_1_256((char *)ctx->input, (char *)ctx->output);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void hash256_bench(benchmark_context *ctx) {
    uint256_t h;
    dogecoin_dblhash(ctx->input, BUFFER_SIZE, h);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void sha512_bench(benchmark_context *ctx) {
    uint8_t h512[SHA512_DIGEST_LENGTH];
    sha512_raw(ctx->input, BUFFER_SIZE, h512);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void rmd160_bench(benchmark_context *ctx) {
    uint8_t h160[20];
    rmd160(ctx->input, BUFFER_SIZE, h160);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* ---- Falcon (requires --enable-liboqs) ---- */
#ifdef USE_LIBOQS
static void falcon512_keypair_bench(benchmark_context *ctx) {
    uint8_t *pk = NULL, *sk = NULL; size_t pk_len = 0, sk_len = 0;
    (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    if (pk) dogecoin_free(pk);
    if (sk) dogecoin_free(sk);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon512_sign_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL; static size_t pk_len = 0, sk_len = 0;
    if (!pk || !sk) (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
    uint8_t *sig = NULL; size_t sig_len = 0;
    (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
    if (sig) dogecoin_free(sig);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon512_verify_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    static size_t pk_len = 0, sk_len = 0, sig_len = 0;
    static int primed = 0;
    if (!primed) {
        (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
        (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
        primed = 1;
    }
    (void)dogecoin_falcon512_verify(pk, pk_len, ctx->input, 32, sig, sig_len);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void falcon512_commit_bytes_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    static size_t pk_len = 0, sk_len = 0, sig_len = 0;
    static int primed = 0;
    if (!primed) {
        (void)dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len);
        (void)dogecoin_falcon512_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len);
        primed = 1;
    }
    uint8_t commit32[32];
    (void)dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit32);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

#ifdef USE_RACCOON_G
/* ---- Raccoon-G (requires --enable-raccoon-g) ---- */
static void raccoong44_keypair_bench(benchmark_context *ctx) {
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_len = 0;
    size_t sk_len = 0;
    bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
    if (pk) dogecoin_free(pk);
    if (sk) dogecoin_free(sk);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void raccoong44_sign_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL;
    static uint8_t *sk = NULL;
    static size_t pk_len = 0;
    static size_t sk_len = 0;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (!pk || !sk) bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
    bench_require(dogecoin_raccoong44_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len), "dogecoin_raccoong44_sign");
    if (sig) dogecoin_free(sig);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void raccoong44_verify_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL;
    static uint8_t *sk = NULL;
    static uint8_t *sig = NULL;
    static size_t pk_len = 0;
    static size_t sk_len = 0;
    static size_t sig_len = 0;
    static int primed = 0;
    if (!primed) {
        bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
        bench_require(dogecoin_raccoong44_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len), "dogecoin_raccoong44_sign");
        primed = 1;
    }
    bench_require(dogecoin_raccoong44_verify(pk, pk_len, ctx->input, 32, sig, sig_len), "dogecoin_raccoong44_verify");
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void raccoong44_commit_bytes_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL;
    static uint8_t *sk = NULL;
    static uint8_t *sig = NULL;
    static size_t pk_len = 0;
    static size_t sk_len = 0;
    static size_t sig_len = 0;
    static int primed = 0;
    if (!primed) {
        bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
        bench_require(dogecoin_raccoong44_sign(sk, sk_len, ctx->input, 32, &sig, &sig_len), "dogecoin_raccoong44_sign");
        primed = 1;
    }
    uint8_t commit32[32];
    bench_require(dogecoin_raccoong44_commit_bytes(pk, pk_len, sig, sig_len, commit32), "dogecoin_raccoong44_commit_bytes");
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void raccoong44_hd_hardened_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL;
    static uint8_t *sk = NULL;
    static size_t pk_len = 0;
    static size_t sk_len = 0;
    static int primed = 0;
    if (!primed) {
        bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
        primed = 1;
    }
    uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
    sha256_raw(ctx->input, BUFFER_SIZE, chaincode);
    uint8_t *child_sk = NULL;
    uint8_t *child_pk = NULL;
    size_t child_sk_len = 0;
    size_t child_pk_len = 0;
    bench_require(dogecoin_raccoong44_hd_derive_priv(sk, sk_len, pk, pk_len, chaincode, 0, true,
                                                     &child_sk, &child_sk_len, &child_pk, &child_pk_len),
                  "dogecoin_raccoong44_hd_derive_priv");
    if (child_sk) dogecoin_free(child_sk);
    if (child_pk) dogecoin_free(child_pk);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void raccoong44_hd_nonhardened_bench(benchmark_context *ctx) {
    static uint8_t *pk = NULL;
    static uint8_t *sk = NULL;
    static size_t pk_len = 0;
    static size_t sk_len = 0;
    static int primed = 0;
    if (!primed) {
        bench_require(dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len), "dogecoin_raccoong44_keypair");
        primed = 1;
    }
    uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
    sha256_raw(ctx->input, BUFFER_SIZE, chaincode);
    uint8_t *child_pk = NULL;
    size_t child_pk_len = 0;
    bench_require(dogecoin_raccoong44_hd_derive_pub(pk, pk_len, chaincode, 1, &child_pk, &child_pk_len),
                  "dogecoin_raccoong44_hd_derive_pub");
    if (child_pk) dogecoin_free(child_pk);
    ctx->end = gettimedouble();
    ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start;
    ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}
#endif /* USE_RACCOON_G */

/* ---- Other PQC Algorithms (Dilithium, SPHINCS+) ---- */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <oqs/sig.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* Generic PQC benchmark helper */
typedef struct {
    const char *alg_name;
    OQS_SIG *alg;
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *sig;
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
    int primed;
} pqc_bench_state;

static pqc_bench_state dilithium2_state = {0};
static pqc_bench_state dilithium3_state = {0};
static pqc_bench_state dilithium5_state = {0};
static pqc_bench_state sphincs_shake_128s_state = {0};
static pqc_bench_state sphincs_shake_128f_state = {0};

/* Helper to check if a PQC algorithm is available by name */
static dogecoin_bool pqc_alg_is_available(const char *alg_name) {
    OQS_SIG *alg = OQS_SIG_new(alg_name);
    if (alg) {
        OQS_SIG_free(alg);
        return true;
    }
    return false;
}

static void pqc_init_state(pqc_bench_state *state, const char *alg_name) {
    if (state->primed) return;
    state->alg_name = alg_name;
    state->alg = OQS_SIG_new(alg_name);
    if (!state->alg) return;
    
    state->pk = (uint8_t*)dogecoin_malloc(state->alg->length_public_key);
    state->sk = (uint8_t*)dogecoin_malloc(state->alg->length_secret_key);
    state->sig = (uint8_t*)dogecoin_malloc(state->alg->length_signature);
    
    if (!state->pk || !state->sk || !state->sig) {
        if (state->pk) dogecoin_free(state->pk);
        if (state->sk) dogecoin_free(state->sk);
        if (state->sig) dogecoin_free(state->sig);
        OQS_SIG_free(state->alg);
        state->alg = NULL;
        return;
    }
    
    OQS_STATUS st = OQS_SIG_keypair(state->alg, state->pk, state->sk);
    if (st != OQS_SUCCESS) {
        dogecoin_free(state->pk);
        dogecoin_free(state->sk);
        dogecoin_free(state->sig);
        OQS_SIG_free(state->alg);
        state->alg = NULL;
        return;
    }
    
    state->primed = 1;
}

static void pqc_keypair_bench_generic(benchmark_context *ctx, const char *alg_name) {
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) return;
    
    uint8_t *pk = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    uint8_t *sk = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    
    if (pk && sk) {
        OQS_STATUS st = OQS_SIG_keypair(alg, pk, sk);
        if (st != OQS_SUCCESS) {
            bench_require(0, "OQS_SIG_keypair");
        }
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    
    OQS_SIG_free(alg);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_sign_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) pqc_init_state(state, alg_name);
    if (!state->alg) return;
    
    size_t sig_len = 0;
    OQS_STATUS st = OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
    if (st != OQS_SUCCESS) {
        bench_require(0, "OQS_SIG_sign");
    }
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_verify_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) {
        pqc_init_state(state, alg_name);
        if (state->alg) {
            size_t sig_len = 0;
            OQS_STATUS st = OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
            if (st != OQS_SUCCESS) {
                bench_require(0, "OQS_SIG_sign");
            }
        }
    }
    if (!state->alg) return;
    
    OQS_STATUS st = OQS_SIG_verify(state->alg, ctx->input, 32, state->sig, state->alg->length_signature, state->pk);
    if (st != OQS_SUCCESS) {
        bench_require(0, "OQS_SIG_verify");
    }
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void pqc_commit_bench_generic(benchmark_context *ctx, pqc_bench_state *state, const char *alg_name) {
    if (!state->primed) {
        pqc_init_state(state, alg_name);
        if (state->alg) {
            size_t sig_len = 0;
            OQS_STATUS st = OQS_SIG_sign(state->alg, state->sig, &sig_len, ctx->input, 32, state->sk);
            if (st != OQS_SUCCESS) {
                bench_require(0, "OQS_SIG_sign");
            }
        }
    }
    if (!state->alg) return;
    
    uint8_t commit32[32];
    sha256_context sha_ctx;
    sha256_init(&sha_ctx);
    sha256_write(&sha_ctx, state->pk, state->alg->length_public_key);
    sha256_write(&sha_ctx, state->sig, state->alg->length_signature);
    sha256_finalize(&sha_ctx, commit32);
    
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* Helper to get actual Dilithium algorithm name (tries ML-DSA and legacy names) */
static const char* get_dilithium2_name(void) {
    if (pqc_alg_is_available("ML-DSA-44")) return "ML-DSA-44";
    if (pqc_alg_is_available("Dilithium2")) return "Dilithium2";
    return NULL;
}
static const char* get_dilithium3_name(void) {
    if (pqc_alg_is_available("ML-DSA-65")) return "ML-DSA-65";
    if (pqc_alg_is_available("Dilithium3")) return "Dilithium3";
    return NULL;
}
static const char* get_dilithium5_name(void) {
    if (pqc_alg_is_available("ML-DSA-87")) return "ML-DSA-87";
    if (pqc_alg_is_available("Dilithium5")) return "Dilithium5";
    return NULL;
}

/* Dilithium2 benchmarks - use string names for compatibility */
static void dilithium2_keypair_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium2_name();
    if (alg) pqc_keypair_bench_generic(ctx, alg);
}
static void dilithium2_sign_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium2_name();
    if (alg) pqc_sign_bench_generic(ctx, &dilithium2_state, alg);
}
static void dilithium2_verify_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium2_name();
    if (alg) pqc_verify_bench_generic(ctx, &dilithium2_state, alg);
}
static void dilithium2_commit_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium2_name();
    if (alg) pqc_commit_bench_generic(ctx, &dilithium2_state, alg);
}

/* Dilithium3 benchmarks - use string names for compatibility */
static void dilithium3_keypair_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium3_name();
    if (alg) pqc_keypair_bench_generic(ctx, alg);
}
static void dilithium3_sign_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium3_name();
    if (alg) pqc_sign_bench_generic(ctx, &dilithium3_state, alg);
}
static void dilithium3_verify_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium3_name();
    if (alg) pqc_verify_bench_generic(ctx, &dilithium3_state, alg);
}
static void dilithium3_commit_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium3_name();
    if (alg) pqc_commit_bench_generic(ctx, &dilithium3_state, alg);
}

/* Dilithium5 benchmarks - use string names for compatibility */
static void dilithium5_keypair_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium5_name();
    if (alg) pqc_keypair_bench_generic(ctx, alg);
}
static void dilithium5_sign_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium5_name();
    if (alg) pqc_sign_bench_generic(ctx, &dilithium5_state, alg);
}
static void dilithium5_verify_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium5_name();
    if (alg) pqc_verify_bench_generic(ctx, &dilithium5_state, alg);
}
static void dilithium5_commit_bench(benchmark_context *ctx) {
    const char *alg = get_dilithium5_name();
    if (alg) pqc_commit_bench_generic(ctx, &dilithium5_state, alg);
}

/* SPHINCS+ SHAKE-128s benchmarks - use string names for compatibility */
static void sphincs_shake_128s_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}
static void sphincs_shake_128s_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &sphincs_shake_128s_state, "SPHINCS+-SHAKE-128s-simple");
}

/* SPHINCS+ SHAKE-128f benchmarks - use string names for compatibility */
static void sphincs_shake_128f_keypair_bench(benchmark_context *ctx) {
    pqc_keypair_bench_generic(ctx, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_sign_bench(benchmark_context *ctx) {
    pqc_sign_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_verify_bench(benchmark_context *ctx) {
    pqc_verify_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
}
static void sphincs_shake_128f_commit_bench(benchmark_context *ctx) {
    pqc_commit_bench_generic(ctx, &sphincs_shake_128f_state, "SPHINCS+-SHAKE-128f-simple");
}

#endif /* USE_LIBOQS */

/* ---- secp256k1 via ECC module (no direct secp includes) ---- */

static void make_valid_privkey(uint8_t sk[32]) {
    /* try random bytes until valid */
    while (1) {
        dogecoin_random_bytes(sk, 32, 0);
        if (dogecoin_ecc_verify_privatekey(sk)) return;
        sk[0] ^= 0x01; /* nudge */
        if (dogecoin_ecc_verify_privatekey(sk)) return;
    }
}

static void make_msg32(const uint8_t *src, uint8_t out32[32]) {
    sha256_raw(src, 64, out32);
}

static void secp_keypair_bench(benchmark_context *ctx) {
    /* keypair = generate priv + derive compressed pub */
    uint8_t sk[32]; make_valid_privkey(sk);
    uint8_t pk[33]; size_t pklen = 33;
    dogecoin_ecc_get_pubkey(sk, pk, &pklen, true);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void secp_sign_bench(benchmark_context *ctx) {
    /* reuse one key for stable sign throughput */
    static int primed = 0;
    static uint8_t sk[32];
    if (!primed) { make_valid_privkey(sk); primed = 1; }

    uint8_t msg32[32]; make_msg32(ctx->input, msg32);
    uint256_t msg_hash; memcpy(msg_hash, msg32, 32);
    unsigned char sigder[80]; size_t siglen = sizeof(sigder);
    (void)dogecoin_ecc_sign(sk, msg_hash, sigder, &siglen);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

static void secp_verify_bench(benchmark_context *ctx) {
    /* prime msg/pair/sig once, then verify repeatedly */
    static int primed = 0;
    static uint8_t pk[33]; static size_t pklen = 33;
    static uint8_t msg32[32];
    static uint256_t msg_hash = {0};
    static unsigned char sigder[80]; static size_t siglen = 0;

    if (!primed) {
        uint8_t sk[32]; make_valid_privkey(sk);
        pklen = 33; dogecoin_ecc_get_pubkey(sk, pk, &pklen, true);
        make_msg32(ctx->input, msg32);
        memcpy(msg_hash, msg32, 32);
        siglen = sizeof(sigder);
        (void)dogecoin_ecc_sign(sk, msg_hash, sigder, &siglen);
        primed = 1;
    }

    (void)dogecoin_ecc_verify_sig(pk, true, msg_hash, sigder, siglen);
    ctx->end = gettimedouble(); ctx->endCycles = perf_cpucycles();
    ctx->totalTime += ctx->end - ctx->start; ctx->totalCycles += ctx->endCycles - ctx->startCycles;
}

/* ---- Analysis and Ranking Functions ---- */

#ifdef USE_LIBOQS
/* Comparison function for sorting by average time (ascending) */
static int compare_avg_time(const void *a, const void *b) {
    const benchmark_result *ra = (const benchmark_result *)a;
    const benchmark_result *rb = (const benchmark_result *)b;
    if (ra->avgTime < rb->avgTime) return -1;
    if (ra->avgTime > rb->avgTime) return 1;
    return 0;
}

/* Find result by name */
static benchmark_result* find_result(const char *name) {
    for (int i = 0; i < num_results; i++) {
        if (strcmp(results[i].name, name) == 0) {
            return &results[i];
        }
    }
    return NULL;
}
static dogecoin_bool is_pqc_result_name(const char *name) {
    if (!name) return false;
    return (strncmp(name, "Falcon", 6) == 0 ||
            strncmp(name, "Raccoon", 7) == 0 ||
            strncmp(name, "Dilith", 6) == 0 ||
            strncmp(name, "SPHNCS", 6) == 0);
}

static benchmark_result* fastest_pqc_for_suffix(const char *suffix) {
    benchmark_result *best = NULL;
    for (int i = 0; i < num_results; i++) {
        if (!is_pqc_result_name(results[i].name)) continue;
        if (!strstr(results[i].name, suffix)) continue;
        if (!best || results[i].avgTime < best->avgTime) best = &results[i];
    }
    return best;
}

/* Print performance analysis and rankings */
static void print_analysis(void) {
    if (num_results == 0) return;

    printf("\n");
    printf("================================================================================================================================\n");
    printf("PERFORMANCE ANALYSIS & RANKINGS\n");
    printf("================================================================================================================================\n");

    /* Category-based rankings */
    printf("\n--- Rankings by Category ---\n\n");
    
    /* Define category groups */
    const char *categories[][3] = {
        {"Hash Algorithms", "hash", NULL},
        {"Classical ECC (secp256k1)", "ecc-keypair", "ecc-sign,ecc-verify"},
        {"PQC Key Generation", "pqc-keypair", NULL},
        {"PQC Signing", "pqc-sign", NULL},
        {"PQC Verification", "pqc-verify", NULL},
        {"PQC Commits", "pqc-commit", NULL},
        {"PQC HD Derivations", "pqc-hd", NULL}
    };
    
    for (int cat = 0; cat < 7; cat++) {
        const char *cat_name = categories[cat][0];
        const char *cat_prefix = categories[cat][1];
        
        /* Collect results for this category */
        benchmark_result cat_results[MAX_BENCHMARKS];
        int cat_count = 0;
        
        for (int i = 0; i < num_results; i++) {
            dogecoin_bool matches = false;
            
            /* Check if result matches this category */
            if (strncmp(results[i].category, cat_prefix, strlen(cat_prefix)) == 0) {
                matches = true;
            }
            /* Special handling for multi-category (ecc operations) */
            if (categories[cat][2] != NULL) {
                if (strstr(categories[cat][2], results[i].category)) {
                    matches = true;
                }
            }
            
            if (matches) {
                cat_results[cat_count++] = results[i];
            }
        }
        
        if (cat_count == 0) continue;
        
        /* Sort within category */
        qsort(cat_results, cat_count, sizeof(benchmark_result), compare_avg_time);
        
        /* Print category header and results */
        printf("• %s:\n", cat_name);
        for (int i = 0; i < cat_count; i++) {
            double ops_per_sec = cat_results[i].avgTime > 0 ? 1.0 / cat_results[i].avgTime : 0;
            printf("  %d. %-16s  %10.6f sec  (%10.0f ops/sec)\n",
                   i + 1,
                   cat_results[i].name,
                   cat_results[i].avgTime,
                   ops_per_sec);
        }
        printf("\n");
    }

    /* Quick digest to reduce cognitive load from full ranking dump */
    printf("--- Quick Digest ---\n");
    benchmark_result *fast_kp = fastest_pqc_for_suffix("-kp");
    benchmark_result *fast_sig = fastest_pqc_for_suffix("-sig");
    benchmark_result *fast_ver = fastest_pqc_for_suffix("-ver");
    benchmark_result *fast_cmt = fastest_pqc_for_suffix("-cmt");
    if (fast_kp) printf("• Fastest PQC keygen:      %-12s (%.6f sec)\n", fast_kp->name, fast_kp->avgTime);
    if (fast_sig) printf("• Fastest PQC signing:     %-12s (%.6f sec)\n", fast_sig->name, fast_sig->avgTime);
    if (fast_ver) printf("• Fastest PQC verify:      %-12s (%.6f sec)\n", fast_ver->name, fast_ver->avgTime);
    if (fast_cmt) printf("• Fastest PQC commitment:  %-12s (%.6f sec)\n", fast_cmt->name, fast_cmt->avgTime);
    printf("\n");

    /* Key comparisons */
    printf("--- Key Performance Comparisons ---\n");
    
    /* Find specific benchmarks for comparison */
    benchmark_result *falcon_kp = find_result("Falcon512-kp");
    benchmark_result *falcon_sig = find_result("Falcon512-sig");
    benchmark_result *falcon_ver = find_result("Falcon512-ver");
    benchmark_result *raccoon_kp = find_result("RaccoonG-kp");
    benchmark_result *raccoon_sig = find_result("RaccoonG-sig");
    benchmark_result *raccoon_ver = find_result("RaccoonG-ver");
    benchmark_result *secp_kp = find_result("secp-kp");
    benchmark_result *secp_sig = find_result("secp-sig");
    benchmark_result *secp_ver = find_result("secp-ver");
    benchmark_result *sphincs_s_kp = find_result("SPHNCS128s-kp");
    benchmark_result *sphincs_s_sig = find_result("SPHNCS128s-sig");
    benchmark_result *sphincs_f_kp = find_result("SPHNCS128f-kp");
    benchmark_result *dilith2_kp = find_result("Dilith2-kp");
    benchmark_result *dilith2_sig = find_result("Dilith2-sig");
    
    if (secp_kp && falcon_kp) {
        double ratio = falcon_kp->avgTime / secp_kp->avgTime;
        printf("• Keypair Generation:\n");
        printf("  - Falcon512 is %.1fx SLOWER than secp256k1 (%.6f vs %.6f sec)\n",
               ratio, falcon_kp->avgTime, secp_kp->avgTime);
        if (dilith2_kp) {
            double ratio2 = dilith2_kp->avgTime / secp_kp->avgTime;
            printf("  - Dilithium2 is %.1fx SLOWER than secp256k1 (%.6f vs %.6f sec)\n",
                   ratio2, dilith2_kp->avgTime, secp_kp->avgTime);
        }
    }
    
    if (secp_sig && falcon_sig) {
        double ratio = falcon_sig->avgTime / secp_sig->avgTime;
        printf("• Signing:\n");
        printf("  - Falcon512 is %.1fx SLOWER than secp256k1 (%.6f vs %.6f sec)\n",
               ratio, falcon_sig->avgTime, secp_sig->avgTime);
        if (dilith2_sig) {
            double ratio2 = dilith2_sig->avgTime / secp_sig->avgTime;
            printf("  - Dilithium2 is %.1fx SLOWER than secp256k1 (%.6f vs %.6f sec)\n",
                   ratio2, dilith2_sig->avgTime, secp_sig->avgTime);
        }
    }
    
    if (secp_ver && falcon_ver) {
        double ratio = falcon_ver->avgTime / secp_ver->avgTime;
        printf("  - Falcon512 verification is %.2fx vs secp256k1 (%.6f vs %.6f sec)\n",
               ratio, falcon_ver->avgTime, secp_ver->avgTime);
    }
    if (secp_ver && raccoon_ver) {
        double ratio = raccoon_ver->avgTime / secp_ver->avgTime;
        printf("  - Raccoon-G verification is %.2fx vs secp256k1 (%.6f vs %.6f sec)\n",
               ratio, raccoon_ver->avgTime, secp_ver->avgTime);
    }
    
    if (falcon_kp && sphincs_s_kp) {
        double ratio = sphincs_s_kp->avgTime / falcon_kp->avgTime;
        printf("• SPHINCS+ vs Falcon512:\n");
        printf("  - SPHINCS128s keypair is %.1fx SLOWER than Falcon512 (%.6f vs %.6f sec)\n",
               ratio, sphincs_s_kp->avgTime, falcon_kp->avgTime);
    }
    
    if (falcon_sig && sphincs_s_sig) {
        double ratio = sphincs_s_sig->avgTime / falcon_sig->avgTime;
        printf("  - SPHINCS128s signing is %.0fx SLOWER than Falcon512 (%.6f vs %.6f sec)\n",
               ratio, sphincs_s_sig->avgTime, falcon_sig->avgTime);
    }
    
    if (falcon_kp && sphincs_f_kp) {
        double ratio = sphincs_f_kp->avgTime / falcon_kp->avgTime;
        printf("  - SPHINCS128f keypair is %.2fx vs Falcon512 (%.6f vs %.6f sec)\n",
               ratio, sphincs_f_kp->avgTime, falcon_kp->avgTime);
    }

    /* Category winners */
    printf("\n--- Category Winners (Fastest in Each Operation) ---\n");
    
    const char *op_types[] = {"keypair", "sign", "verify", "commit"};
    const char *op_names[] = {"Key Generation", "Signing", "Verification", "Commit"};
    
    for (int c = 0; c < 4; c++) {
        double best_time = DBL_MAX;
        const char *best_name = NULL;
        
        for (int i = 0; i < num_results; i++) {
            /* Check if this benchmark is in the operation category */
            if (strstr(results[i].name, "-kp") && strcmp(op_types[c], "keypair") == 0) {
                if (results[i].avgTime < best_time) {
                    best_time = results[i].avgTime;
                    best_name = results[i].name;
                }
            } else if (strstr(results[i].name, "-sig") && strcmp(op_types[c], "sign") == 0) {
                if (results[i].avgTime < best_time) {
                    best_time = results[i].avgTime;
                    best_name = results[i].name;
                }
            } else if (strstr(results[i].name, "-ver") && strcmp(op_types[c], "verify") == 0) {
                if (results[i].avgTime < best_time) {
                    best_time = results[i].avgTime;
                    best_name = results[i].name;
                }
            } else if (strstr(results[i].name, "-cmt") && strcmp(op_types[c], "commit") == 0) {
                if (results[i].avgTime < best_time) {
                    best_time = results[i].avgTime;
                    best_name = results[i].name;
                }
            }
        }
        
        if (best_name) {
            printf("• Fastest %s: %s (%.6f sec, %.0f ops/sec)\n",
                   op_names[c], best_name, best_time, 1.0 / best_time);
        }
    }

    benchmark_result *dilith2_ver = find_result("Dilith2-ver");

    /* Summary (derived from measured results above) */
    printf("\n--- Summary ---\n");
    printf("Measured benchmark takeaways:\n");
    if (falcon_ver && secp_ver && secp_ver->avgTime > 0.0) {
        printf("• Falcon512 verify vs secp verify: %.2fx (%.6f vs %.6f sec)\n",
               falcon_ver->avgTime / secp_ver->avgTime, falcon_ver->avgTime, secp_ver->avgTime);
    }
    if (dilith2_ver && falcon_ver && falcon_ver->avgTime > 0.0) {
        printf("• Dilith2 verify vs Falcon512 verify: %.2fx (%.6f vs %.6f sec)\n",
               dilith2_ver->avgTime / falcon_ver->avgTime, dilith2_ver->avgTime, falcon_ver->avgTime);
    }
    if (sphincs_s_sig && falcon_sig && falcon_sig->avgTime > 0.0) {
        printf("• SPHINCS128s sign vs Falcon512 sign: %.0fx (%.6f vs %.6f sec)\n",
               sphincs_s_sig->avgTime / falcon_sig->avgTime, sphincs_s_sig->avgTime, falcon_sig->avgTime);
    }
    if (falcon_ver || dilith2_ver || sphincs_s_sig) {
        printf("• Tagged PQC commitments are benchmarked in the PQC Commits section above\n");
    }
    if (raccoon_kp || raccoon_sig) {
        printf("• Raccoon-G HD derivation throughput is benchmarked in PQC HD Derivations above\n");
    }

    /* Security-strength characteristic table for quick PQC comparison context */
#ifdef USE_LIBOQS
    printf("\n--- Security-Strength Characteristics (NIST categories) ---\n");
    printf("  %-14s %-12s %-s\n", "Algorithm", "Category", "Approx. classical security");
    if (find_result("secp-kp"))        printf("  %-14s %-12s %-s\n", "secp256k1", "N/A", "~128-bit (ECDLP, non-PQC)");
    if (find_result("Falcon512-kp"))   printf("  %-14s %-12s %-s\n", "Falcon-512", "Level 1", "~128-bit");
    if (find_result("RaccoonG-kp"))    printf("  %-14s %-12s %-s\n", "Raccoon-G", "Level 2*", "~128-192-bit*");
    if (find_result("Dilith2-kp"))     printf("  %-14s %-12s %-s\n", "Dilithium2", "Level 2", "~128-bit");
    if (find_result("Dilith3-kp"))     printf("  %-14s %-12s %-s\n", "Dilithium3", "Level 3", "~192-bit");
    if (find_result("Dilith5-kp"))     printf("  %-14s %-12s %-s\n", "Dilithium5", "Level 5", "~256-bit");
    if (find_result("SPHNCS128s-kp"))  printf("  %-14s %-12s %-s\n", "SPHINCS128s", "Level 1", "~128-bit");
    if (find_result("SPHNCS128f-kp"))  printf("  %-14s %-12s %-s\n", "SPHINCS128f", "Level 1", "~128-bit");
    if (find_result("RaccoonG-kp"))    printf("  %-14s %-12s %-s\n", "", "*", "Raccoon-G security estimate depends on parameter-set target");
    printf("  Note: These are algorithm strength targets, separate from measured throughput above.\n");
#endif
}
#endif

/* ---- main ---- */

int main(void) {
    /* init ECC once for secp benches */
    (void)dogecoin_ecc_start();

    printf("%-16s %-8s %-10s %-10s %-10s %-12s %-12s %-12s\n",
           "#Benchmark", "Count", "Min Time", "Max Time", "Avg Time",
           "Min Cycles", "Max Cycles", "Avg Cycles");
    printf("================================================================================================================================\n");

    /* baselines */
    printf("\n--- Classical Baselines ---\n");
    run_benchmark(sha256_bench,       "SHA256", "hash");
    run_benchmark(hash256_bench,      "SHA256D", "hash");
    run_benchmark(sha512_bench,       "SHA512", "hash");
    run_benchmark(rmd160_bench,       "RMD160", "hash");
    run_benchmark(scrypt_bench,       "Scrypt", "hash");

    /* secp256k1 via ECC module - classical baseline for comparison */
    printf("\n--- secp256k1 (Classical ECC Baseline) ---\n");
    run_benchmark(secp_keypair_bench, "secp-kp", "ecc-keypair");
    run_benchmark(secp_sign_bench,    "secp-sig", "ecc-sign");
    run_benchmark(secp_verify_bench,  "secp-ver", "ecc-verify");

#ifdef USE_LIBOQS
    /* Falcon-512 - primary PQC baseline */
    printf("\n--- Falcon-512 (Primary PQC Baseline) ---\n");
    run_benchmark(falcon512_keypair_bench,      "Falcon512-kp", "pqc-keypair");
    run_benchmark(falcon512_sign_bench,         "Falcon512-sig", "pqc-sign");
    run_benchmark(falcon512_verify_bench,       "Falcon512-ver", "pqc-verify");
    run_benchmark(falcon512_commit_bytes_bench, "Falcon512-cmt", "pqc-commit");

    /* Raccoon-G (includes HD derivation primitives) */
#ifdef USE_RACCOON_G
    printf("\n--- Raccoon-G (PQC + HD Derivation) ---\n");
    if (dogecoin_raccoong44_is_available()) {
        run_benchmark(raccoong44_keypair_bench,      "RaccoonG-kp", "pqc-keypair");
        run_benchmark(raccoong44_sign_bench,         "RaccoonG-sig", "pqc-sign");
        run_benchmark(raccoong44_verify_bench,       "RaccoonG-ver", "pqc-verify");
        run_benchmark(raccoong44_commit_bytes_bench, "RaccoonG-cmt", "pqc-commit");
        run_benchmark(raccoong44_hd_hardened_bench,  "RaccoonG-hdh", "pqc-hd");
        run_benchmark(raccoong44_hd_nonhardened_bench, "RaccoonG-hdn", "pqc-hd");
    } else {
        printf("%-16s %s\n", "RaccoonG", "not available");
    }
#endif

    /* Dilithium variants - compare against Falcon */
    printf("\n--- Dilithium (NIST PQC Standard) - Compare vs Falcon ---\n");
    if (get_dilithium2_name()) {
        run_benchmark(dilithium2_keypair_bench, "Dilith2-kp", "pqc-keypair");
        run_benchmark(dilithium2_sign_bench,    "Dilith2-sig", "pqc-sign");
        run_benchmark(dilithium2_verify_bench,  "Dilith2-ver", "pqc-verify");
        run_benchmark(dilithium2_commit_bench,  "Dilith2-cmt", "pqc-commit");
    } else {
        printf("%-16s %s\n", "Dilithium2", "not available");
    }
    
    if (get_dilithium3_name()) {
        run_benchmark(dilithium3_keypair_bench, "Dilith3-kp", "pqc-keypair");
        run_benchmark(dilithium3_sign_bench,    "Dilith3-sig", "pqc-sign");
        run_benchmark(dilithium3_verify_bench,  "Dilith3-ver", "pqc-verify");
        run_benchmark(dilithium3_commit_bench,  "Dilith3-cmt", "pqc-commit");
    } else {
        printf("%-16s %s\n", "Dilithium3", "not available");
    }
    
    if (get_dilithium5_name()) {
        run_benchmark(dilithium5_keypair_bench, "Dilith5-kp", "pqc-keypair");
        run_benchmark(dilithium5_sign_bench,    "Dilith5-sig", "pqc-sign");
        run_benchmark(dilithium5_verify_bench,  "Dilith5-ver", "pqc-verify");
        run_benchmark(dilithium5_commit_bench,  "Dilith5-cmt", "pqc-commit");
    } else {
        printf("%-16s %s\n", "Dilithium5", "not available");
    }

    /* SPHINCS+ variants - compare against Falcon */
    printf("\n--- SPHINCS+ (Hash-based) - Compare vs Falcon ---\n");
    if (pqc_alg_is_available("SPHINCS+-SHAKE-128s-simple")) {
        run_benchmark(sphincs_shake_128s_keypair_bench, "SPHNCS128s-kp", "pqc-keypair");
        run_benchmark(sphincs_shake_128s_sign_bench,    "SPHNCS128s-sig", "pqc-sign");
        run_benchmark(sphincs_shake_128s_verify_bench,  "SPHNCS128s-ver", "pqc-verify");
        run_benchmark(sphincs_shake_128s_commit_bench,  "SPHNCS128s-cmt", "pqc-commit");
    } else {
        printf("%-16s %s\n", "SPHINCS128s", "not available");
    }
    
    if (pqc_alg_is_available("SPHINCS+-SHAKE-128f-simple")) {
        run_benchmark(sphincs_shake_128f_keypair_bench, "SPHNCS128f-kp", "pqc-keypair");
        run_benchmark(sphincs_shake_128f_sign_bench,    "SPHNCS128f-sig", "pqc-sign");
        run_benchmark(sphincs_shake_128f_verify_bench,  "SPHNCS128f-ver", "pqc-verify");
        run_benchmark(sphincs_shake_128f_commit_bench,  "SPHNCS128f-cmt", "pqc-commit");
    } else {
        printf("%-16s %s\n", "SPHINCS128f", "not available");
    }
#else
    printf("\n--- PQC Algorithms (liboqs disabled) ---\n");
    printf("%-16s %s\n", "Falcon512",    "skipped (liboqs disabled)");
    printf("%-16s %s\n", "RaccoonG",     "skipped (liboqs disabled)");
    printf("%-16s %s\n", "Dilithium",    "skipped (liboqs disabled)");
    printf("%-16s %s\n", "SPHINCS+",     "skipped (liboqs disabled)");
#endif

    /* Print detailed analysis only when PQC benchmarks are compiled in. */
#ifdef USE_LIBOQS
    print_analysis();
#endif

    printf("\n================================================================================================================================\n");
    printf("\nBuild Options:\n");
#if defined(__AVX2__) && USE_AVX2
    printf("  AVX2 SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE
    printf("  SSE SHA256\n");
#endif
#if defined(__SSE2__) && USE_SSE2
    printf("  SSE2 Scrypt\n");
#endif
#ifdef USE_LIBOQS
    printf("  liboqs enabled:\n");
    printf("    - Falcon-512 (primary PQC baseline)\n");
#ifdef USE_RACCOON_G
    printf("    - Raccoon-G (PQC + BIP32-style HD derivations)\n");
#endif
    printf("    - Dilithium-2/3/5 (NIST standard, lattice-based)\n");
    printf("    - SPHINCS+ (hash-based, conservative security)\n");
#endif
    printf("  secp256k1 (classical ECC baseline)\n");
#ifdef USE_LIBOQS
    printf("\nNote: All PQC algorithms use OP_RETURN commits for off-chain SPV verification\n");
#endif

    dogecoin_ecc_stop();
    return 0;
}
