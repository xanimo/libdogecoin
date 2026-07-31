/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define CLOSE_SOCK(s) closesocket(s)
#else
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  define CLOSE_SOCK(s) close(s)
#endif

#include <dogecoin/cfheadersdb_file.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/filter_bootstrap.h>
#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>

/* ================================================================ */
/*  Internal file-format constants (mirrors cfheadersdb_file.c)    */
/* ================================================================ */

static const uint8_t k_cfhdr_magic[4]  = {0xCF, 0x68, 0x44, 0x52};
static const uint8_t k_cfdata_magic[4] = {0xCF, 0xDA, 0x54, 0x41};
static const uint32_t k_cf_version     = 2;

/* ================================================================ */
/*  Internal helpers                                                */
/* ================================================================ */

/** Compute SHA256 of a file.  Returns false on I/O error. */
static dogecoin_bool sha256_of_file(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    sha256_context ctx;
    sha256_init(&ctx);
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, n);
    int err = ferror(f);
    fclose(f);
    if (err) return false;
    sha256_finalize(&ctx, out);
    return true;
}

/** Encode bytes to lowercase hex.  out must have room for 2*len+1 bytes. */
static void bytes_to_hex(const uint8_t *src, size_t len, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = h[(src[i] >> 4) & 0xf];
        out[i * 2 + 1] = h[src[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/** Decode a 64-char hex string to 32 bytes.  Returns false on bad input. */
static dogecoin_bool hex_to_bytes32(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) < 64) return false;
    for (int i = 0; i < 32; i++) {
        unsigned int hi, lo;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/** Write the 40-byte v2 file header (magic + version=2 + 32 zero bytes). */
static dogecoin_bool write_file_hdr(FILE *f, const uint8_t magic[4])
{
    if (fwrite(magic, 4, 1, f) != 1) return false;
    uint32_t v = htole32(k_cf_version);
    if (fwrite(&v, 4, 1, f) != 1) return false;
    uint8_t zeros[32]; memset(zeros, 0, 32);
    return (fwrite(zeros, 32, 1, f) == 1);
}

/* ================================================================ */
/*  URL parsing and download                                        */
/* ================================================================ */

static dogecoin_bool parse_url(const char *url,
                                char *scheme, size_t sl,
                                char *host,   size_t hl,
                                uint16_t *port_out,
                                char *path,   size_t pl)
{
    const char *sep = strstr(url, "://");
    if (!sep) return false;
    size_t slen = (size_t)(sep - url);
    if (slen >= sl) return false;
    memcpy(scheme, url, slen); scheme[slen] = '\0';

    const char *p = sep + 3;
    const char *slash = strchr(p, '/');
    const char *colon = memchr(p, ':', slash ? (size_t)(slash - p) : strlen(p));
    size_t hlen = colon ? (size_t)(colon - p)
                        : (slash ? (size_t)(slash - p) : strlen(p));
    if (hlen >= hl) return false;
    memcpy(host, p, hlen); host[hlen] = '\0';

    *port_out = 80;
    if (colon) {
        char pb[8]; size_t plen;
        const char *ce = slash ? slash : colon + strlen(colon);
        plen = (size_t)(ce - (colon + 1));
        if (plen < sizeof(pb)) {
            memcpy(pb, colon + 1, plen); pb[plen] = '\0';
            *port_out = (uint16_t)atoi(pb);
        }
    }

    if (slash) snprintf(path, pl, "%s", slash);
    else { if (pl < 2) return false; path[0] = '/'; path[1] = '\0'; }
    return true;
}

/**
 * Locale-independent ASCII case-insensitive compare.
 *
 * strncasecmp() is POSIX and does not exist in the MSVC runtime, which spells
 * it _strnicmp -- linking the Windows build failed with an unresolved external
 * once this file started being compiled there.  Rather than add a platform
 * #ifdef, do the comparison directly: it is only used on HTTP header names,
 * where the locale sensitivity of strncasecmp() is unwanted anyway (a Turkish
 * locale maps 'I' to a dotless lowercase and would mis-compare "Content-Length").
 */
static int bootstrap_ascii_strncasecmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

/**
 * Blocking HTTP/1.0 GET → stream body to dest_path and compute SHA256.
 * Returns false on network or non-200 HTTP response.
 */
static dogecoin_bool http_get_to_file(const char *host, uint16_t port,
                                       const char *path,
                                       const char *dest_path,
                                       uint8_t sha256_out[32],
                                       uint64_t *bytes_out)
{
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        fprintf(stderr, "bootstrap: cannot resolve '%s'\n", host);
        return false;
    }

#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = -1;
#endif
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
        if (sock == INVALID_SOCKET) continue;
#else
        if (sock < 0) continue;
#endif
        if (connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) break;
        CLOSE_SOCK(sock);
#ifdef _WIN32
        sock = INVALID_SOCKET;
#else
        sock = -1;
#endif
    }
    freeaddrinfo(res);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
#else
    if (sock < 0) {
#endif
        fprintf(stderr, "bootstrap: cannot connect to %s:%u\n", host, (unsigned)port);
        return false;
    }

    /* Send HTTP/1.0 GET (no chunked encoding, no keep-alive). */
    char req[2048];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: libdogecoin-bootstrap/1.0\r\n"
        "Connection: close\r\n\r\n",
        path, host);
    if (send(sock, req, (size_t)rlen, 0) != rlen) {
        CLOSE_SOCK(sock); return false;
    }

    /* Read response headers byte-by-byte until \r\n\r\n. */
    char hdrbuf[8192]; size_t hdrlen = 0; dogecoin_bool hdone = false;
    while (!hdone && hdrlen < sizeof(hdrbuf) - 1) {
        char c;
        if (recv(sock, &c, 1, 0) <= 0) break;
        hdrbuf[hdrlen++] = c;
        if (hdrlen >= 4 &&
            hdrbuf[hdrlen-4]=='\r' && hdrbuf[hdrlen-3]=='\n' &&
            hdrbuf[hdrlen-2]=='\r' && hdrbuf[hdrlen-1]=='\n') {
            hdrbuf[hdrlen] = '\0'; hdone = true;
        }
    }
    if (!hdone) { CLOSE_SOCK(sock); return false; }

    int status = 0;
    sscanf(hdrbuf, "HTTP/%*s %d", &status);
    if (status != 200) {
        fprintf(stderr, "bootstrap: HTTP %d fetching %s%s\n", status, host, path);
        CLOSE_SOCK(sock); return false;
    }

    /* Parse Content-Length (case-insensitive search). */
    int64_t content_len = -1;
    for (char *lp = hdrbuf; *lp; ) {
        if (bootstrap_ascii_strncasecmp(lp, "content-length:", 15) == 0) {
            content_len = (int64_t)strtoull(lp + 15, NULL, 10);
            break;
        }
        lp = strchr(lp, '\n');
        if (!lp) break;
        lp++;
    }

    FILE *f = fopen(dest_path, "wb");
    if (!f) { CLOSE_SOCK(sock); return false; }

    sha256_context sha; sha256_init(&sha);
    uint8_t buf[65536]; uint64_t total = 0; ssize_t nr;
    while ((nr = recv(sock, (char*)buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, (size_t)nr, f);
        sha256_write(&sha, buf, (size_t)nr);
        total += (uint64_t)nr;
    }
    fclose(f);
    CLOSE_SOCK(sock);
    sha256_finalize(&sha, sha256_out);
    if (bytes_out) *bytes_out = total;

    if (content_len >= 0 && total != (uint64_t)content_len) {
        fprintf(stderr, "bootstrap: incomplete download (%llu / %lld bytes)\n",
                (unsigned long long)total, (long long)content_len);
        remove(dest_path);
        return false;
    }
    return true;
}

/** Copy a local file to dest, computing SHA256 on the way. */
static dogecoin_bool file_copy_sha(const char *src, const char *dst,
                                    uint8_t sha256_out[32], uint64_t *bytes_out)
{
    FILE *in  = fopen(src, "rb");
    if (!in)  return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return false; }
    sha256_context sha; sha256_init(&sha);
    uint8_t buf[65536]; size_t n; uint64_t total = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
        sha256_write(&sha, buf, n);
        total += n;
    }
    int err = ferror(in) || ferror(out);
    fclose(in); fclose(out);
    if (err) return false;
    sha256_finalize(&sha, sha256_out);
    if (bytes_out) *bytes_out = total;
    return true;
}

/**
 * Download a URL to dest_path; compute SHA256 of the result.
 * Supports file:// (local copy) and http:// (TCP GET).
 */
static dogecoin_bool url_download(const char *url, const char *dest_path,
                                   uint8_t sha256_out[32], uint64_t *bytes_out)
{
    if (strncmp(url, "file://", 7) == 0) {
        return file_copy_sha(url + 7, dest_path, sha256_out, bytes_out);
    }
    if (strncmp(url, "http://", 7) == 0) {
        char scheme[8], host[256], path[2048]; uint16_t port;
        if (!parse_url(url, scheme, sizeof(scheme), host, sizeof(host),
                       &port, path, sizeof(path))) {
            fprintf(stderr, "bootstrap: malformed URL: %s\n", url);
            return false;
        }
        return http_get_to_file(host, port, path, dest_path, sha256_out, bytes_out);
    }
    fprintf(stderr, "bootstrap: unsupported URL scheme: %s\n", url);
    return false;
}

/* ================================================================ */
/*  Checkpoint lookup                                               */
/* ================================================================ */

/**
 * Return the cf_checkpoint array and count for the given chain.
 * Sets *arr and *count; returns false if no checkpoints exist.
 */
static dogecoin_bool get_cf_checkpoints(const dogecoin_chainparams *params,
                                         const dogecoin_cf_checkpoint **arr,
                                         size_t *count)
{
    if (strcmp(params->chainname, "main") == 0) {
        *arr   = dogecoin_mainnet_cf_checkpoint_array;
        *count = dogecoin_mainnet_cf_checkpoint_count;
        return (*count > 0);
    }
    if (strcmp(params->chainname, "test") == 0) {
        *arr   = dogecoin_testnet_cf_checkpoint_array;
        *count = dogecoin_testnet_cf_checkpoint_count;
        return (*count > 0);
    }
    *arr = NULL; *count = 0;
    return false;
}

/**
 * Verify that tip_cfheader (32 LE bytes) matches the compiled-in checkpoint
 * for check_height.  check_height must be a multiple of 1000.
 *
 * Returns true if no checkpoint exists for that height (can't verify → skip).
 * Returns false only on a definite mismatch.
 */
static dogecoin_bool verify_tip_cfheader(const uint8_t tip_cfheader[32],
                                          uint32_t check_height,
                                          const dogecoin_chainparams *params)
{
    const dogecoin_cf_checkpoint *arr; size_t count;
    if (!get_cf_checkpoints(params, &arr, &count)) return true; /* no table */

    if (check_height == 0 || check_height % 1000 != 0) return true;

    uint32_t idx = check_height / 1000 - 1;
    if (idx >= count || !arr[idx].filter_header) return true; /* no entry */

    /* Checkpoint hex is display-order (big-endian); convert to LE internal. */
    uint8_t expected[32];
    char cp_hex[65];
    strncpy(cp_hex, arr[idx].filter_header, 64); cp_hex[64] = '\0';
    utils_uint256_sethex(cp_hex, expected); /* display→LE */

    if (memcmp(tip_cfheader, expected, 32) != 0) {
        char got_hex[65];
        bytes_to_hex(tip_cfheader, 32, got_hex);
        fprintf(stderr,
            "bootstrap: cfheader mismatch at height %u\n"
            "  expected: %s\n"
            "  got:      %s\n",
            check_height, arr[idx].filter_header, got_hex);
        return false;
    }
    return true;
}

/* ================================================================ */
/*  Export: single-pass slice of cfheaders.dat                     */
/* ================================================================ */

typedef struct {
    uint32_t chunk_count;
    uint32_t chunk_size;
    dogecoin_bootstrap_chunk *chunks;
    FILE    **files;     /* one open file per chunk */
    uint8_t   prev_fh[32]; /* filter header of the last record seen */
} cfh_export_ctx;

static dogecoin_bool export_cfheaders_chunks(
    const char *src_path,
    const char *outdir,
    cfh_export_ctx *ctx)
{
    FILE *src = fopen(src_path, "rb");
    if (!src) { fprintf(stderr, "bootstrap: cannot open %s\n", src_path); return false; }

    /* Read source genesis_filter_header from offset 8 */
    uint8_t src_genesis[32]; memset(src_genesis, 0, 32);
    if (fseek(src, 8, SEEK_SET) == 0)
        (void)fread(src_genesis, 32, 1, src);
    fseek(src, CF_HEADERS_FILE_HDR_LEN, SEEK_SET);

    /* Open all chunk output files and write placeholder headers */
    ctx->files = dogecoin_calloc(ctx->chunk_count, sizeof(FILE *));
    for (uint32_t ci = 0; ci < ctx->chunk_count; ci++) {
        char fname[128], path[1024];
        snprintf(fname, sizeof(fname), "cfheaders-%u-%u.dat",
                 ctx->chunks[ci].start_height, ctx->chunks[ci].end_height);
        snprintf(path, sizeof(path), "%s/%s", outdir, fname);
        ctx->files[ci] = fopen(path, "w+b");
        if (!ctx->files[ci]) {
            fprintf(stderr, "bootstrap: cannot create %s\n", path);
            fclose(src);
            return false;
        }
        /* Placeholder header; genesis_fh filled in when we hit start_height */
        write_file_hdr(ctx->files[ci], k_cfhdr_magic);
    }

    /* Chunk 0's genesis = source genesis */
    memcpy(ctx->prev_fh, src_genesis, 32);
    /* Patch it in now */
    fseek(ctx->files[0], 8, SEEK_SET);
    fwrite(src_genesis, 32, 1, ctx->files[0]);
    fseek(ctx->files[0], 0, SEEK_END);

    uint8_t rec[CF_HEADERS_FILE_REC_LEN];
    uint32_t prev_ci = 0;

    while (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, src) == 1) {
        uint32_t h; memcpy(&h, rec, 4); h = le32toh(h);

        /* Which chunk does this height belong to? */
        uint32_t ci = (h - 1) / ctx->chunk_size;
        if (ci >= ctx->chunk_count) ci = ctx->chunk_count - 1;

        /* When we cross a chunk boundary, patch the new chunk's genesis_fh */
        if (ci > prev_ci) {
            for (uint32_t nc = prev_ci + 1; nc <= ci; nc++) {
                fseek(ctx->files[nc], 8, SEEK_SET);
                fwrite(ctx->prev_fh, 32, 1, ctx->files[nc]);
                fseek(ctx->files[nc], 0, SEEK_END);
            }
            prev_ci = ci;
        }

        fwrite(rec, CF_HEADERS_FILE_REC_LEN, 1, ctx->files[ci]);

        /* Record tip cfheader for this chunk */
        if (h == ctx->chunks[ci].end_height || ci == ctx->chunk_count - 1)
            memcpy(ctx->chunks[ci].tip_cfheader, rec + 4, 32);

        memcpy(ctx->prev_fh, rec + 4, 32);
    }
    fclose(src);

    /* Also capture the final tip for the last chunk (may not be at exact boundary) */
    memcpy(ctx->chunks[ctx->chunk_count - 1].tip_cfheader, ctx->prev_fh, 32);

    return true;
}

/* ================================================================ */
/*  Export: single-pass slice of cfilters.dat                      */
/* ================================================================ */

static dogecoin_bool export_cfilters_chunks(
    const char *src_path,
    const char *outdir,
    uint32_t chunk_count,
    uint32_t chunk_size,
    dogecoin_bootstrap_chunk *chunks)
{
    FILE *src = fopen(src_path, "rb");
    if (!src) { fprintf(stderr, "bootstrap: cannot open %s\n", src_path); return false; }
    if (fseek(src, CF_HEADERS_FILE_HDR_LEN, SEEK_SET) != 0) {
        fclose(src); return false;
    }

    FILE **files = dogecoin_calloc(chunk_count, sizeof(FILE *));
    for (uint32_t ci = 0; ci < chunk_count; ci++) {
        char fname[128], path[1024];
        snprintf(fname, sizeof(fname), "cfilters-%u-%u.dat",
                 chunks[ci].start_height, chunks[ci].end_height);
        snprintf(path, sizeof(path), "%s/%s", outdir, fname);
        files[ci] = fopen(path, "w+b");
        if (!files[ci]) {
            fprintf(stderr, "bootstrap: cannot create %s\n", path);
            fclose(src);
            for (uint32_t j = 0; j < ci; j++) if (files[j]) fclose(files[j]);
            dogecoin_free(files);
            return false;
        }
        write_file_hdr(files[ci], k_cfdata_magic);
    }

    dogecoin_bool ok = true;
    uint8_t hdr[CF_FILTERS_FILE_REC_HDR_LEN];

    while (fread(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, src) == 1) {
        uint32_t h, dlen;
        memcpy(&h,    hdr,      4); h    = le32toh(h);
        memcpy(&dlen, hdr + 36, 4); dlen = le32toh(dlen);

        uint32_t ci = (h - 1) / chunk_size;
        if (ci >= chunk_count) ci = chunk_count - 1;

        uint8_t *data = NULL;
        if (dlen > 0) {
            data = dogecoin_malloc(dlen);
            if (!data || fread(data, dlen, 1, src) != 1) {
                dogecoin_free(data); ok = false; break;
            }
        }

        fwrite(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, files[ci]);
        if (dlen > 0 && data) fwrite(data, dlen, 1, files[ci]);
        dogecoin_free(data);
    }

    for (uint32_t ci = 0; ci < chunk_count; ci++)
        if (files[ci]) fclose(files[ci]);
    dogecoin_free(files);
    fclose(src);
    return ok;
}

/* ================================================================ */
/*  Manifest I/O                                                    */
/* ================================================================ */

static dogecoin_bool write_manifest(const char *outdir,
                                     uint32_t chunk_count,
                                     dogecoin_bootstrap_chunk *chunks,
                                     const char *chain)
{
    char mpath[1024];
    snprintf(mpath, sizeof(mpath), "%s/%s", outdir, FILTER_BOOTSTRAP_MANIFEST);
    FILE *f = fopen(mpath, "wb");
    if (!f) { fprintf(stderr, "bootstrap: cannot write manifest %s\n", mpath); return false; }

    fprintf(f, "version=%u\n", FILTER_BOOTSTRAP_VERSION);
    fprintf(f, "chain=%s\n", chain);
    fprintf(f, "chunk_count=%u\n\n", chunk_count);

    char hex[65];
    for (uint32_t i = 0; i < chunk_count; i++) {
        dogecoin_bootstrap_chunk *c = &chunks[i];
        fprintf(f, "chunk_%u_start=%u\n",          i, c->start_height);
        fprintf(f, "chunk_%u_end=%u\n",             i, c->end_height);
        fprintf(f, "chunk_%u_cfheaders_url=%s\n",  i, c->cfheaders_url);
        fprintf(f, "chunk_%u_cfilters_url=%s\n",   i, c->cfilters_url);
        bytes_to_hex(c->cfheaders_sha256, 32, hex);
        fprintf(f, "chunk_%u_cfheaders_sha256=%s\n", i, hex);
        bytes_to_hex(c->cfilters_sha256, 32, hex);
        fprintf(f, "chunk_%u_cfilters_sha256=%s\n",  i, hex);
        bytes_to_hex(c->tip_cfheader,    32, hex);
        fprintf(f, "chunk_%u_tip_cfheader=%s\n\n",   i, hex);
    }
    fclose(f);
    printf("Manifest written: %s\n", mpath);
    return true;
}

dogecoin_bootstrap_manifest* dogecoin_bootstrap_manifest_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "bootstrap: cannot open manifest %s\n", path); return NULL; }

    dogecoin_bootstrap_manifest *m = dogecoin_calloc(1, sizeof(*m));
    m->version     = 0;
    m->chain[0]    = '\0';
    m->chunk_count = 0;
    m->chunks      = NULL;

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline / CR */
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = '\0';
        if (ll == 0 || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line, *val = eq + 1;

        if (strcmp(key, "version") == 0)     { m->version = (uint32_t)atoi(val); }
        else if (strcmp(key, "chain") == 0)  { strncpy(m->chain, val, sizeof(m->chain)-1); }
        else if (strcmp(key, "chunk_count") == 0) {
            m->chunk_count = (uint32_t)atoi(val);
            if (m->chunk_count > 0 && !m->chunks)
                m->chunks = dogecoin_calloc(m->chunk_count, sizeof(*m->chunks));
        }
        else {
            /* chunk_N_field=val */
            if (strncmp(key, "chunk_", 6) != 0) continue;
            const char *p = key + 6;
            char *us = strchr(p, '_');
            if (!us) continue;
            uint32_t idx = (uint32_t)atoi(p);
            if (!m->chunks || idx >= m->chunk_count) continue;
            const char *field = us + 1;
            dogecoin_bootstrap_chunk *c = &m->chunks[idx];

            if      (strcmp(field, "start") == 0)
                c->start_height = (uint32_t)atoi(val);
            else if (strcmp(field, "end") == 0)
                c->end_height = (uint32_t)atoi(val);
            else if (strcmp(field, "cfheaders_url") == 0)
                strncpy(c->cfheaders_url, val, sizeof(c->cfheaders_url)-1);
            else if (strcmp(field, "cfilters_url") == 0)
                strncpy(c->cfilters_url, val, sizeof(c->cfilters_url)-1);
            else if (strcmp(field, "cfheaders_sha256") == 0)
                hex_to_bytes32(val, c->cfheaders_sha256);
            else if (strcmp(field, "cfilters_sha256") == 0)
                hex_to_bytes32(val, c->cfilters_sha256);
            else if (strcmp(field, "tip_cfheader") == 0)
                hex_to_bytes32(val, c->tip_cfheader);
        }
    }
    fclose(f);

    if (m->version != FILTER_BOOTSTRAP_VERSION) {
        fprintf(stderr, "bootstrap: unsupported manifest version %u\n", m->version);
        dogecoin_bootstrap_manifest_free(m);
        return NULL;
    }
    if (!m->chunks && m->chunk_count > 0) {
        dogecoin_bootstrap_manifest_free(m);
        return NULL;
    }
    return m;
}

void dogecoin_bootstrap_manifest_free(dogecoin_bootstrap_manifest *m)
{
    if (!m) return;
    dogecoin_free(m->chunks);
    dogecoin_free(m);
}

/* ================================================================ */
/*  Public: export                                                  */
/* ================================================================ */

dogecoin_bool dogecoin_bootstrap_export(
    const char *cfheaders_src,
    const char *cfilters_src,
    const char *outdir,
    const char *base_url,
    const dogecoin_chainparams *params)
{
    if (!outdir || !params) return false;

    /* Resolve default source paths */
    cstring *cfh_obj = NULL, *cfd_obj = NULL;
    if (!cfheaders_src) {
        cfh_obj = cstr_new_sz(512);
        dogecoin_get_default_datadir(cfh_obj);
        while (cfh_obj->len > 0 && cfh_obj->str[cfh_obj->len-1] == '\0') cfh_obj->len--;
        cstr_append_buf(cfh_obj, "/filter/basic/cfheaders.dat", 27);
        cstr_append_c(cfh_obj, '\0');
        cfheaders_src = cfh_obj->str;
    }
    if (!cfilters_src) {
        cfd_obj = cstr_new_sz(512);
        dogecoin_get_default_datadir(cfd_obj);
        while (cfd_obj->len > 0 && cfd_obj->str[cfd_obj->len-1] == '\0') cfd_obj->len--;
        cstr_append_buf(cfd_obj, "/filter/basic/cfilters.dat", 26);
        cstr_append_c(cfd_obj, '\0');
        cfilters_src = cfd_obj->str;
    }

    /* Find the height range in cfheaders.dat */
    struct stat sb;
    if (stat(cfheaders_src, &sb) != 0 || sb.st_size <= (long)CF_HEADERS_FILE_HDR_LEN) {
        fprintf(stderr, "bootstrap: cfheaders.dat missing or empty\n");
        if (cfh_obj) cstr_free(cfh_obj, true);
        if (cfd_obj) cstr_free(cfd_obj, true);
        return false;
    }
    long num_recs = (sb.st_size - (long)CF_HEADERS_FILE_HDR_LEN) / CF_HEADERS_FILE_REC_LEN;
    if (num_recs <= 0) {
        fprintf(stderr, "bootstrap: no cfheaders records\n");
        if (cfh_obj) cstr_free(cfh_obj, true);
        if (cfd_obj) cstr_free(cfd_obj, true);
        return false;
    }

    FILE *cfh = fopen(cfheaders_src, "rb");
    if (!cfh) { if (cfh_obj) cstr_free(cfh_obj, true); if (cfd_obj) cstr_free(cfd_obj, true); return false; }

    uint8_t rec[CF_HEADERS_FILE_REC_LEN];
    fseek(cfh, CF_HEADERS_FILE_HDR_LEN, SEEK_SET);
    if (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, cfh) != 1) { fclose(cfh); return false; }
    uint32_t first_h; memcpy(&first_h, rec, 4); first_h = le32toh(first_h);

    fseek(cfh, -(long)CF_HEADERS_FILE_REC_LEN, SEEK_END);
    if (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, cfh) != 1) { fclose(cfh); return false; }
    uint32_t last_h; memcpy(&last_h, rec, 4); last_h = le32toh(last_h);
    fclose(cfh);

    printf("bootstrap: exporting heights %u..%u\n", first_h, last_h);

    const uint32_t chunk_size  = FILTER_BOOTSTRAP_CHUNK_SIZE;
    const uint32_t chunk_count = (last_h + chunk_size - 1) / chunk_size;

    dogecoin_bootstrap_chunk *chunks = dogecoin_calloc(chunk_count, sizeof(*chunks));

    /* Build chunk URL and filename strings.
     * URL fields are 1024 bytes; filenames are at most 64 bytes, so cap base at 920. */
    char base[920];
    size_t blen = base_url ? strlen(base_url) : 0;
    if (blen > 0 && base_url[blen-1] != '/')
        snprintf(base, sizeof(base), "%s/", base_url);
    else
        snprintf(base, sizeof(base), "%s", base_url ? base_url : "");

    for (uint32_t ci = 0; ci < chunk_count; ci++) {
        chunks[ci].start_height = ci * chunk_size + 1;
        chunks[ci].end_height   = (ci + 1) * chunk_size;
        if (chunks[ci].end_height > last_h) chunks[ci].end_height = last_h;

        char cfh_name[64], cfd_name[64];
        snprintf(cfh_name, sizeof(cfh_name), "cfheaders-%u-%u.dat",
                 chunks[ci].start_height, chunks[ci].end_height);
        snprintf(cfd_name, sizeof(cfd_name), "cfilters-%u-%u.dat",
                 chunks[ci].start_height, chunks[ci].end_height);
        snprintf(chunks[ci].cfheaders_url, sizeof(chunks[ci].cfheaders_url), "%s%s", base, cfh_name);
        snprintf(chunks[ci].cfilters_url,  sizeof(chunks[ci].cfilters_url),  "%s%s", base, cfd_name);
    }

    /* Single-pass cfheaders export */
    printf("Exporting cfheaders chunks...\n");
    cfh_export_ctx cfh_ctx;
    cfh_ctx.chunk_count = chunk_count;
    cfh_ctx.chunk_size  = chunk_size;
    cfh_ctx.chunks      = chunks;
    cfh_ctx.files       = NULL;
    memset(cfh_ctx.prev_fh, 0, 32);

    dogecoin_bool ok = export_cfheaders_chunks(cfheaders_src, outdir, &cfh_ctx);

    /* Close chunk files and compute SHA256 */
    if (cfh_ctx.files) {
        for (uint32_t ci = 0; ci < chunk_count; ci++) {
            if (cfh_ctx.files[ci]) fclose(cfh_ctx.files[ci]);
            /* SHA256 */
            char path[1024];
            snprintf(path, sizeof(path), "%s/cfheaders-%u-%u.dat",
                     outdir, chunks[ci].start_height, chunks[ci].end_height);
            sha256_of_file(path, chunks[ci].cfheaders_sha256);

            /* Verify tip cfheader at exact checkpoint boundary */
            uint32_t cp_h = (chunks[ci].end_height / 1000) * 1000;
            if (ok && !verify_tip_cfheader(chunks[ci].tip_cfheader, cp_h, params)) {
                fprintf(stderr, "bootstrap: cfheader verification failed for chunk %u\n", ci);
                ok = false;
            }
        }
        dogecoin_free(cfh_ctx.files);
    }

    /* Single-pass cfilters export */
    if (ok) {
        printf("Exporting cfilters chunks...\n");
        ok = export_cfilters_chunks(cfilters_src, outdir, chunk_count, chunk_size, chunks);
        for (uint32_t ci = 0; ci < chunk_count && ok; ci++) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/cfilters-%u-%u.dat",
                     outdir, chunks[ci].start_height, chunks[ci].end_height);
            sha256_of_file(path, chunks[ci].cfilters_sha256);
        }
    }

    /* Write manifest */
    if (ok) {
        write_manifest(outdir, chunk_count, chunks,
                       params->chainname);
    }

    dogecoin_free(chunks);
    if (cfh_obj) cstr_free(cfh_obj, true);
    if (cfd_obj) cstr_free(cfd_obj, true);
    return ok;
}

/* ================================================================ */
/*  Import: append chunk records to local DB                        */
/* ================================================================ */

/**
 * Append cfheaders records from a chunk file to the destination cfheaders.dat.
 * Skips records with height <= skip_below.
 */
static dogecoin_bool append_cfheaders_chunk(const char *chunk_path,
                                             const char *dst_path,
                                             uint32_t skip_below)
{
    FILE *src = fopen(chunk_path, "rb");
    if (!src) { fprintf(stderr, "bootstrap: cannot open %s\n", chunk_path); return false; }

    /* Read the chunk's genesis_filter_header (the prev filter header for height start-1) */
    uint8_t chunk_genesis[32]; memset(chunk_genesis, 0, 32);
    if (fseek(src, 8, SEEK_SET) == 0)
        (void)fread(chunk_genesis, 32, 1, src);
    fseek(src, CF_HEADERS_FILE_HDR_LEN, SEEK_SET);

    /* Open destination for append (must already exist with v2 header) */
    FILE *dst = fopen(dst_path, "r+b");
    if (!dst) {
        /* Create fresh */
        dst = fopen(dst_path, "w+b");
        if (!dst) { fclose(src); return false; }
        write_file_hdr(dst, k_cfhdr_magic);
        /* Patch genesis_fh */
        fseek(dst, 8, SEEK_SET);
        fwrite(chunk_genesis, 32, 1, dst);
    }
    fseek(dst, 0, SEEK_END);

    uint8_t rec[CF_HEADERS_FILE_REC_LEN]; uint32_t written = 0;
    while (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, src) == 1) {
        uint32_t h; memcpy(&h, rec, 4); h = le32toh(h);
        if (h <= skip_below) continue;
        fwrite(rec, CF_HEADERS_FILE_REC_LEN, 1, dst);
        written++;
    }

    fclose(src); fclose(dst);
    printf("  cfheaders: appended %u records\n", written);
    return true;
}

/**
 * Append cfilters records from a chunk file to the destination cfilters.dat.
 * Skips records with height <= skip_below.
 */
static dogecoin_bool append_cfilters_chunk(const char *chunk_path,
                                            const char *dst_path,
                                            uint32_t skip_below)
{
    FILE *src = fopen(chunk_path, "rb");
    if (!src) { fprintf(stderr, "bootstrap: cannot open %s\n", chunk_path); return false; }
    fseek(src, CF_HEADERS_FILE_HDR_LEN, SEEK_SET);

    FILE *dst = fopen(dst_path, "r+b");
    if (!dst) {
        dst = fopen(dst_path, "w+b");
        if (!dst) { fclose(src); return false; }
        write_file_hdr(dst, k_cfdata_magic);
    }
    fseek(dst, 0, SEEK_END);

    uint8_t hdr[CF_FILTERS_FILE_REC_HDR_LEN]; uint32_t written = 0;
    while (fread(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, src) == 1) {
        uint32_t h, dlen;
        memcpy(&h,    hdr,      4); h    = le32toh(h);
        memcpy(&dlen, hdr + 36, 4); dlen = le32toh(dlen);

        uint8_t *data = NULL;
        if (dlen > 0) {
            data = dogecoin_malloc(dlen);
            if (!data || fread(data, dlen, 1, src) != 1) {
                dogecoin_free(data); break;
            }
        }
        if (h > skip_below) {
            fwrite(hdr, CF_FILTERS_FILE_REC_HDR_LEN, 1, dst);
            if (dlen > 0 && data) fwrite(data, dlen, 1, dst);
            written++;
        }
        dogecoin_free(data);
    }

    fclose(src); fclose(dst);
    printf("  cfilters:  appended %u records\n", written);
    return true;
}

/** Find the tip height stored in a cfheaders.dat file (0 if empty). */
static uint32_t cfheaders_tip_height(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) != 0 || sb.st_size <= (long)CF_HEADERS_FILE_HDR_LEN) return 0;
    long recs = (sb.st_size - (long)CF_HEADERS_FILE_HDR_LEN) / CF_HEADERS_FILE_REC_LEN;
    if (recs <= 0) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, -(long)CF_HEADERS_FILE_REC_LEN, SEEK_END);
    uint8_t rec[CF_HEADERS_FILE_REC_LEN];
    uint32_t h = 0;
    if (fread(rec, CF_HEADERS_FILE_REC_LEN, 1, f) == 1) {
        memcpy(&h, rec, 4); h = le32toh(h);
    }
    fclose(f);
    return h;
}

/* ================================================================ */
/*  Public: import                                                  */
/* ================================================================ */

dogecoin_bool dogecoin_bootstrap_import(
    const char *manifest_path,
    const char *cfheaders_dst,
    const char *cfilters_dst,
    const dogecoin_chainparams *params,
    dogecoin_bootstrap_progress_cb progress_cb,
    void *ctx)
{
    if (!manifest_path || !params) return false;

    dogecoin_bootstrap_manifest *m = dogecoin_bootstrap_manifest_load(manifest_path);
    if (!m) return false;

    /* Verify chain matches */
    if (strcmp(m->chain, params->chainname) != 0) {
        fprintf(stderr, "bootstrap: manifest chain '%s' != expected '%s'\n",
                m->chain, params->chainname);
        dogecoin_bootstrap_manifest_free(m);
        return false;
    }

    /* Resolve destination paths */
    cstring *cfh_obj = NULL, *cfd_obj = NULL;
    if (!cfheaders_dst) {
        cfh_obj = cstr_new_sz(512);
        dogecoin_get_default_datadir(cfh_obj);
        while (cfh_obj->len > 0 && cfh_obj->str[cfh_obj->len-1] == '\0') cfh_obj->len--;
        cstr_append_buf(cfh_obj, "/filter/basic/cfheaders.dat", 27);
        cstr_append_c(cfh_obj, '\0');
        cfheaders_dst = cfh_obj->str;
    }
    if (!cfilters_dst) {
        cfd_obj = cstr_new_sz(512);
        dogecoin_get_default_datadir(cfd_obj);
        while (cfd_obj->len > 0 && cfd_obj->str[cfd_obj->len-1] == '\0') cfd_obj->len--;
        cstr_append_buf(cfd_obj, "/filter/basic/cfilters.dat", 26);
        cstr_append_c(cfd_obj, '\0');
        cfilters_dst = cfd_obj->str;
    }

    /* Check local tip — skip chunks already present */
    uint32_t local_tip = cfheaders_tip_height(cfheaders_dst);
    printf("bootstrap: local cfheaders tip = %u, manifest has %u chunks\n",
           local_tip, m->chunk_count);

    uint64_t bytes_done = 0, bytes_total = 0;
    dogecoin_bool ok = true;

    for (uint32_t ci = 0; ci < m->chunk_count && ok; ci++) {
        dogecoin_bootstrap_chunk *c = &m->chunks[ci];

        if (c->end_height <= local_tip) {
            printf("Chunk %u/%u (heights %u..%u): already present, skipping\n",
                   ci + 1, m->chunk_count, c->start_height, c->end_height);
            continue;
        }

        printf("Chunk %u/%u: heights %u..%u\n",
               ci + 1, m->chunk_count, c->start_height, c->end_height);

        /* --- Download cfheaders chunk --- */
        char tmp_cfh[1024], tmp_cfd[1024];
        snprintf(tmp_cfh, sizeof(tmp_cfh), "%s.cfh_tmp", cfheaders_dst);
        snprintf(tmp_cfd, sizeof(tmp_cfd), "%s.cfd_tmp", cfilters_dst);

        printf("  Downloading cfheaders...\n");
        uint8_t got_sha[32]; uint64_t got_bytes = 0;
        if (!url_download(c->cfheaders_url, tmp_cfh, got_sha, &got_bytes)) {
            fprintf(stderr, "bootstrap: download failed: %s\n", c->cfheaders_url);
            ok = false; break;
        }
        if (memcmp(got_sha, c->cfheaders_sha256, 32) != 0) {
            char got_hex[65], exp_hex[65];
            bytes_to_hex(got_sha, 32, got_hex);
            bytes_to_hex(c->cfheaders_sha256, 32, exp_hex);
            fprintf(stderr, "bootstrap: cfheaders SHA256 mismatch\n"
                    "  expected: %s\n  got:      %s\n", exp_hex, got_hex);
            remove(tmp_cfh); ok = false; break;
        }
        bytes_done += got_bytes;

        /* Verify tip cfheader against checkpoint */
        uint32_t cp_h = (c->end_height / 1000) * 1000;
        if (!verify_tip_cfheader(c->tip_cfheader, cp_h, params)) {
            remove(tmp_cfh); ok = false; break;
        }

        /* --- Download cfilters chunk --- */
        printf("  Downloading cfilters...\n");
        if (!url_download(c->cfilters_url, tmp_cfd, got_sha, &got_bytes)) {
            fprintf(stderr, "bootstrap: download failed: %s\n", c->cfilters_url);
            remove(tmp_cfh); ok = false; break;
        }
        if (memcmp(got_sha, c->cfilters_sha256, 32) != 0) {
            char got_hex[65], exp_hex[65];
            bytes_to_hex(got_sha, 32, got_hex);
            bytes_to_hex(c->cfilters_sha256, 32, exp_hex);
            fprintf(stderr, "bootstrap: cfilters SHA256 mismatch\n"
                    "  expected: %s\n  got:      %s\n", exp_hex, got_hex);
            remove(tmp_cfh); remove(tmp_cfd); ok = false; break;
        }
        bytes_done += got_bytes;

        /* --- Append to local DB --- */
        uint32_t skip = (c->start_height > local_tip) ? local_tip : local_tip;
        ok = ok && append_cfheaders_chunk(tmp_cfh, cfheaders_dst, skip);
        ok = ok && append_cfilters_chunk(tmp_cfd, cfilters_dst, skip);

        remove(tmp_cfh); remove(tmp_cfd);

        if (progress_cb)
            progress_cb(ci, m->chunk_count, bytes_done, bytes_total, ctx);

        printf("  Chunk %u complete.\n", ci + 1);
    }

    dogecoin_bootstrap_manifest_free(m);
    if (cfh_obj) cstr_free(cfh_obj, true);
    if (cfd_obj) cstr_free(cfd_obj, true);
    return ok;
}
