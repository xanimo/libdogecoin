/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2022 edtubbs
 * Copyright (c) 2022 bluezr
 * Copyright (c) 2022 The Dogecoin Foundation
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

#include <unistd.h>
#include <uchar.h>
#include <unistr.h>
#include <wchar.h>
#include <uninorm.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unicode/utypes.h>
#include <unicode/ustring.h>
#include <unicode/unorm2.h>
#include <bip39/index.h>

#include <dogecoin/bip39.h>
#include <dogecoin/utils.h>
#include <dogecoin/options.h>
#include <dogecoin/random.h>
#include <dogecoin/sha2.h>

#if USE_BIP39_CACHE

static int bip39_cache_index = 0;

static CONFIDENTIAL struct {
  bool set;
  char mnemonic[256];
  char passphrase[64];
  uint8_t seed[512 / 8];
} bip39_cache[BIP39_CACHE_SIZE];

void bip39_cache_clear(void) {
  dogecoin_mem_zero(bip39_cache, sizeof(bip39_cache));
  bip39_cache_index = 0;
}

#endif

/*
 * This function reads the language file once and loads an array of words for
 * repeated use.
 */
char * wordlist[2049] = {0};

void get_custom_wordlist(const char *filepath) {
    int i = 0;
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(filepath, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        strtok(line, "\n");
        wordlist[i] = malloc(read + 1);
        strcpy(wordlist[i], line);
        i++;
    }

    fclose(fp);
    if (line) free(line);
}

void get_words(const char *lang) {
    int i = 0;
    for (; i <= 2049; i++) {
      if (strcmp(lang,"spa") == 0) {
          wordlist[i]=(char*)wordlist_spa[i];
      } else if (strcmp(lang,"eng") == 0) {
          wordlist[i]=(char*)wordlist_eng[i];
      } else if (strcmp(lang,"jpn") == 0) {
          wordlist[i]=(char*)wordlist_jpn[i];
      } else if (strcmp(lang,"ita") == 0) {
          wordlist[i]=(char*)wordlist_ita[i];
      } else if (strcmp(lang,"fra") == 0) {
          wordlist[i]=(char*)wordlist_fra[i];
      } else if (strcmp(lang,"kor") == 0) {
          wordlist[i]=(char*)wordlist_kor[i];
      } else if (strcmp(lang,"sc") == 0) {
          wordlist[i]=(char*)wordlist_sc[i];
      } else if (strcmp(lang,"tc") == 0) {
          wordlist[i]=(char*)wordlist_tc[i];
      } else if (strcmp(lang,"cze") == 0) {
          wordlist[i]=(char*)wordlist_cze[i];
      } else if (strcmp(lang,"por") == 0) {
          wordlist[i]=(char*)wordlist_por[i];
      } else {
          fprintf(stderr, "Language or language file does not exist.\n");
      }
    }
}

const char *mnemonic_generate(int strength) {
  if (strength % 32 || strength < 128 || strength > 256) {
    return 0;
  }
  uint8_t data[32] = {0};
  dogecoin_cheap_random_bytes(data, 32);
  const char *r = mnemonic_from_data(data, strength / 8);
  dogecoin_mem_zero(data, sizeof(data));
  return r;
}

static CONFIDENTIAL char mnemo[24 * 10];

const char *mnemonic_from_data(const uint8_t *data, int len) {
  if (len % 4 || len < 16 || len > 32) {
    return 0;
  }

  uint8_t bits[32 + 1] = {0};

  sha256_raw(data, len, bits);
  // checksum
  bits[len] = bits[0];
  // data
  memcpy(bits, data, len);

  int mlen = len * 3 / 4;

  int i = 0, j = 0, idx = 0;
  char *p = mnemo;
  for (i = 0; i < mlen; i++) {
    idx = 0;
    for (j = 0; j < 11; j++) {
      idx <<= 1;
      idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
    }
    strcpy(p, wordlist[idx]);
    p += strlen(wordlist[idx]);
    *p = (i < mlen - 1) ? ' ' : 0;
    p++;
  }
  dogecoin_mem_zero(bits, sizeof(bits));

  return mnemo;
}

void mnemonic_clear(void) { dogecoin_mem_zero(mnemo, sizeof(mnemo)); }

int mnemonic_to_bits(const char *mnemonic, uint8_t *bits) {
  if (!mnemonic) {
    return 0;
  }

  uint32_t i = 0, n = 0;

  while (mnemonic[i]) {
    if (mnemonic[i] == ' ') {
      n++;
    }
    i++;
  }
  n++;

  // check that number of words is valid for BIP-39:
  // (a) between 128 and 256 bits of initial entropy (12 - 24 words)
  // (b) number of bits divisible by 33 (1 checksum bit per 32 input bits)
  //     - that is, (n * 11) % 33 == 0, so n % 3 == 0
  if (n < 12 || n > 24 || (n % 3)) {
    return 0;
  }

  char current_word[10] = {0};
  uint32_t j = 0, ki = 0, bi = 0;
  uint8_t result[32 + 1] = {0};

  dogecoin_mem_zero(result, sizeof(result));
  i = 0;
  while (mnemonic[i]) {
    j = 0;
    while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
      if (j >= sizeof(current_word) - 1) {
        return 0;
      }
      current_word[j] = mnemonic[i];
      i++;
      j++;
    }
    current_word[j] = 0;
    if (mnemonic[i] != 0) {
      i++;
    }
    int k = mnemonic_find_word(current_word);
    if (k < 0) {  // word not found
      return 0;
    }
    for (ki = 0; ki < 11; ki++) {
      if (k & (1 << (10 - ki))) {
        result[bi / 8] |= 1 << (7 - (bi % 8));
      }
      bi++;
    }
  }
  if (bi != n * 11) {
    return 0;
  }
  memcpy(bits, result, sizeof(result));
  dogecoin_mem_zero(result, sizeof(result));

  // returns amount of entropy + checksum BITS
  return n * 11;
}

int mnemonic_check(const char *mnemonic) {
  uint8_t bits[32 + 1] = {0};
  int mnemonic_bits_len = mnemonic_to_bits(mnemonic, bits);
  if (mnemonic_bits_len != (12 * 11) && mnemonic_bits_len != (18 * 11) &&
      mnemonic_bits_len != (24 * 11)) {
    return 0;
  }
  int words = mnemonic_bits_len / 11;

  uint8_t checksum = bits[words * 4 / 3];
  sha256_raw(bits, words * 4 / 3, bits);
  if (words == 12) {
    return (bits[0] & 0xF0) == (checksum & 0xF0);  // compare first 4 bits
  } else if (words == 18) {
    return (bits[0] & 0xFC) == (checksum & 0xFC);  // compare first 6 bits
  } else if (words == 24) {
    return bits[0] == checksum;  // compare 8 bits
  }
  return 0;
}

typedef uint32_t u8chr_t;

// Avoids truncating multibyte UTF-8 encoding at the end.
char *u8strncpy(char *dest, const char *src, size_t n)
{
  int k = n-1;
  int i;
  if (n) {
    dest[k] = 0;
    strncpy(dest,src,n);
    if (dest[k] & 0x80) { // Last byte has been overwritten
      for (i=k; (i>0) && ((k-i) < 3) && ((dest[i] & 0xC0) == 0x80); i--) ;
      switch(k-i) {
        case 0:                                 dest[i] = '\0'; break;
        case 1:  if ( (dest[i] & 0xE0) != 0xC0) dest[i] = '\0'; break;
        case 2:  if ( (dest[i] & 0xF0) != 0xE0) dest[i] = '\0'; break;
        case 3:  if ( (dest[i] & 0xF8) != 0xF0) dest[i] = '\0'; break;
      }
    }
  }
  return dest;
}

static uint8_t const u8_length[] = {
// 0 1 2 3 4 5 6 7 8 9 A B C D E F
   1,1,1,1,1,1,1,1,0,0,0,0,2,2,3,4
} ;

#define u8length(s) u8_length[(((uint8_t *)(s))[0] & 0xFF) >> 4]

int u8chrisvalid(u8chr_t c)
{
  if (c <= 0x7F) return 1;                    // [1]

  if (0xC280 <= c && c <= 0xDFBF)             // [2]
     return ((c & 0xE0C0) == 0xC080);

  if (0xEDA080 <= c && c <= 0xEDBFBF)         // [3]
     return 0; // Reject UTF-16 surrogates

  if (0xE0A080 <= c && c <= 0xEFBFBF)         // [4]
     return ((c & 0xF0C0C0) == 0xE08080);

  if (0xF0908080 <= c && c <= 0xF48FBFBF)     // [5]
     return ((c & 0xF8C0C0C0) == 0xF0808080);

  return 0;
}

int u8next(char *txt, u8chr_t *ch)
{
   int len;
   u8chr_t encoding = 0;

   len = u8length(txt);
  int i=0;
   for (; i<len && txt[i] != '\0'; i++) {
      encoding = (encoding << 8) | txt[i];
   }

   errno = 0;
   if (len == 0 || !u8chrisvalid(encoding)) {
      encoding = txt[0];
      len = 1;
      errno = EINVAL;
   }

   if (ch) *ch = encoding;

   return encoding ? len : 0 ;
}

// from UTF-8 encoding to Unicode Codepoint
uint32_t u8decode(u8chr_t c)
{
  uint32_t mask;

  if (c > 0x7F) {
    mask = (c <= 0x00EFBFBF)? 0x000F0000 : 0x003F0000 ;
    c = ((c & 0x07000000) >> 6) |
        ((c & mask )      >> 4) |
        ((c & 0x00003F00) >> 2) |
         (c & 0x0000003F);
  }

  return c;
}

// From Unicode Codepoint to UTF-8 encoding
u8chr_t u8encode(uint32_t codepoint)
{
  u8chr_t c = codepoint;

  if (codepoint > 0x7F) {
    c =  (codepoint & 0x000003F) 
       | (codepoint & 0x0000FC0) << 2 
       | (codepoint & 0x003F000) << 4
       | (codepoint & 0x01C0000) << 6;

    if      (codepoint < 0x0000800) c |= 0x0000C080;
    else if (codepoint < 0x0010000) c |= 0x00E08080;
    else                            c |= 0xF0808080;
  }
  return c;
}

int u8chrisblank(u8chr_t c)
{
  return (c == 0x20)
      || (c == 0x09)
      || (c == 0xC2A0)
      || (c == 0xE19A80)
      || ((0xE28080 <= c) && (c <= 0xE2808A))
      || (c == 0xE280AF)
      || (c == 0xE2819F)
      || (c == 0xE38080)
      ;
}
typedef unsigned char utf8_t;

#define isunicode(c) (((c)&0xc0)==0xc0)

int utf8_decode(const char *str,int *i) {
    const utf8_t *s = (const utf8_t *)str; // Use unsigned chars
    int u = *s,l = 1;
    if(isunicode(u)) {
        int a = (u&0x20)? ((u&0x10)? ((u&0x08)? ((u&0x04)? 6 : 5) : 4) : 3) : 2;
        if(a<6 || !(u&0x02)) {
            int b,p = 0;
            u = ((u<<(a+1))&0xff)>>(a+1);
            for(b=1; b<a; ++b)
                u = (u<<6)|(s[l++]&0x3f);
        }
    }
    if(i) *i += l;
    return u;
}

int utf8_encode(char *out, uint32_t utf)
{
  if (utf <= 0x7F) {
    // Plain ASCII
    out[0] = (char) utf;
    out[1] = 0;
    return 1;
  }
  else if (utf <= 0x07FF) {
    // 2-byte unicode
    out[0] = (char) (((utf >> 6) & 0x1F) | 0xC0);
    out[1] = (char) (((utf >> 0) & 0x3F) | 0x80);
    out[2] = 0;
    return 2;
  }
  else if (utf <= 0xFFFF) {
    // 3-byte unicode
    out[0] = (char) (((utf >> 12) & 0x0F) | 0xE0);
    out[1] = (char) (((utf >>  6) & 0x3F) | 0x80);
    out[2] = (char) (((utf >>  0) & 0x3F) | 0x80);
    out[3] = 0;
    return 3;
  }
  else if (utf <= 0x10FFFF) {
    // 4-byte unicode
    out[0] = (char) (((utf >> 18) & 0x07) | 0xF0);
    out[1] = (char) (((utf >> 12) & 0x3F) | 0x80);
    out[2] = (char) (((utf >>  6) & 0x3F) | 0x80);
    out[3] = (char) (((utf >>  0) & 0x3F) | 0x80);
    out[4] = 0;
    return 4;
  }
  else { 
    // error - use replacement character
    out[0] = (char) 0xEF;  
    out[1] = (char) 0xBF;
    out[2] = (char) 0xBD;
    out[3] = 0;
    return 0;
  }
}

void print_string_as_hex( const char *str )
{
    while ( *str != '\0' )
    {
        printf( "%02X\n", (unsigned char)*str );
        str++;
    }
}

typedef unsigned char byte;
typedef unsigned int codepoint;
/**
 * Reads the next UTF-8-encoded character from the byte array ranging
 * from {@code *pstart} up to, but not including, {@code end}. If the
 * conversion succeeds, the {@code *pstart} iterator is advanced,
 * the codepoint is stored into {@code *pcp}, and the function returns
 * 0. Otherwise the conversion fails, {@code errno} is set to
 * {@code EILSEQ} and the function returns -1.
 */
int
from_utf8(const byte **pstart, const byte *end, codepoint *pcp) {
        size_t len, i;
        codepoint cp, min;
        const byte *buf;

        buf = *pstart;
        if (buf == end)
                goto error;

        if (buf[0] < 0x80) {
                len = 1;
                min = 0;
                cp = buf[0];
        } else if (buf[0] < 0xC0) {
                goto error;
        } else if (buf[0] < 0xE0) {
                len = 2;
                min = 1 << 7;
                cp = buf[0] & 0x1F;
        } else if (buf[0] < 0xF0) {
                len = 3;
                min = 1 << (5 + 6);
                cp = buf[0] & 0x0F;
        } else if (buf[0] < 0xF8) {
                len = 4;
                min = 1 << (4 + 6 + 6);
                cp = buf[0] & 0x07;
        } else {
                goto error;
        }

        if (buf + len > end)
                goto error;

        for (i = 1; i < len; i++) {
                if ((buf[i] & 0xC0) != 0x80)
                        goto error;
                cp = (cp << 6) | (buf[i] & 0x3F);
        }

        if (cp < min)
                goto error;

        if (0xD800 <= cp && cp <= 0xDFFF)
                goto error;

        if (0x110000 <= cp)
                goto error;

        *pstart += len;
        *pcp = cp;
        return 0;

error:
        errno = EILSEQ;
        return -1;
}

static void
assert_valid(const byte **buf, const byte *end, codepoint expected) {
        codepoint cp;

        if (from_utf8(buf, end, &cp) == -1) {
                fprintf(stderr, "invalid unicode sequence for codepoint %u\n", expected);
                exit(EXIT_FAILURE);
        }

        if (cp != expected) {
                fprintf(stderr, "expected %u, got %u\n", expected, cp);
                exit(EXIT_FAILURE);
        }
}

static void
assert_invalid(const char *name, const byte **buf, const byte *end) {
        const byte *p;
        codepoint cp;

        p = *buf + 1;
        if (from_utf8(&p, end, &cp) == 0) {
                fprintf(stderr, "unicode sequence \"%s\" unexpectedly converts to %#x.\n", name, cp);
                exit(EXIT_FAILURE);
        }
        *buf += (*buf)[0] + 1;
}

static const byte valid[] = {
        0x00, /* first ASCII */
        0x7F, /* last ASCII */
        0xC2, 0x80, /* first two-byte */
        0xDF, 0xBF, /* last two-byte */
        0xE0, 0xA0, 0x80, /* first three-byte */
        0xED, 0x9F, 0xBF, /* last before surrogates */
        0xEE, 0x80, 0x80, /* first after surrogates */
        0xEF, 0xBF, 0xBF, /* last three-byte */
        0xF0, 0x90, 0x80, 0x80, /* first four-byte */
        0xF4, 0x8F, 0xBF, 0xBF /* last codepoint */
};

static const byte invalid[] = {
        1, 0x80,
        1, 0xC0,
        1, 0xC1,
        2, 0xC0, 0x80,
        2, 0xC2, 0x00,
        2, 0xC2, 0x7F,
        2, 0xC2, 0xC0,
        3, 0xE0, 0x80, 0x80,
        3, 0xE0, 0x9F, 0xBF,
        3, 0xED, 0xA0, 0x80,
        3, 0xED, 0xBF, 0xBF,
        4, 0xF0, 0x80, 0x80, 0x80,
        4, 0xF0, 0x8F, 0xBF, 0xBF,
        4, 0xF4, 0x90, 0x80, 0x80
};

static size_t code_to_utf8(unsigned char *const buffer, const unsigned int code)
{
    if (code <= 0x7F) {
        buffer[0] = code;
        return 1;
    }
    if (code <= 0x7FF) {
        buffer[0] = 0xC0 | (code >> 6);            /* 110xxxxx */
        buffer[1] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 2;
    }
    if (code <= 0xFFFF) {
        buffer[0] = 0xE0 | (code >> 12);           /* 1110xxxx */
        buffer[1] = 0x80 | ((code >> 6) & 0x3F);   /* 10xxxxxx */
        buffer[2] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 3;
    }
    if (code <= 0x10FFFF) {
        buffer[0] = 0xF0 | (code >> 18);           /* 11110xxx */
        buffer[1] = 0x80 | ((code >> 12) & 0x3F);  /* 10xxxxxx */
        buffer[2] = 0x80 | ((code >> 6) & 0x3F);   /* 10xxxxxx */
        buffer[3] = 0x80 | (code & 0x3F);          /* 10xxxxxx */
        return 4;
    }
    return 0;
}

const char *nfkd(const char *input) {
//     UErrorCode status = U_ZERO_ERROR;
//     const UNormalizer2 *nfkd = unorm2_getNFKDInstance(&status);
//     if (U_FAILURE(status)) {
//         fprintf(stderr, "Error getting NFKD instance: %s\n", u_errorName(status));
//         return NULL;
//     }

//     UChar *input_u = calloc(strlen(input) + 1, sizeof(UChar));
//     if (input_u == NULL) {
//         fprintf(stderr, "Error allocating memory for input UChar\n");
//         return NULL;
//     }
//     u_strFromUTF8(input_u, strlen(input) + 1, NULL, input, strlen(input), &status);
//     if (U_FAILURE(status)) {
//         fprintf(stderr, "Error converting input to UChar: %s\n", u_errorName(status));
//         free(input_u);
//         return NULL;
//     }

//     int32_t normalized_length = unorm2_normalize(nfkd, input_u, -1, NULL, 0, &status);
//     if (status != U_BUFFER_OVERFLOW_ERROR) {
//         fprintf(stderr, "Error getting length of normalized UChar: %s\n", u_errorName(status));
//         free(input_u);
//         return NULL;
//     }
//     status = U_ZERO_ERROR;

//     UChar *normalized_u = calloc(normalized_length + 1, sizeof(UChar));
//     if (normalized_u == NULL) {
//         fprintf(stderr, "Error allocating memory for normalized UChar\n");
//         free(input_u);
//         return NULL;
//     }

//     unorm2_normalize(nfkd, input_u, -1, normalized_u, normalized_length + 1, &status);
//     if (U_FAILURE(status)) {
//         fprintf(stderr, "Error normalizing UChar: %s\n", u_errorName(status));
//         free(input_u);
//         free(normalized_u);
//         return NULL;
//     }
//     free(input_u);

//     UChar *normalized_utf8 = calloc(normalized_length * 4 + 1, sizeof(UChar));
//     if (normalized_utf8 == NULL) {
//         fprintf(stderr, "Error allocating memory for normalized UTF-8\n");
//         free(normalized_u);
//         return NULL;
//     }
//     u_strToUTF8((char*)normalized_utf8, normalized_length * 4 + 1, NULL, normalized_u, normalized_length, &status);
//     if (U_FAILURE(status)) {
//         fprintf(stderr, "Error converting normalized UChar to UTF-8: %s\n", u_errorName(status));
//         free(normalized_u);
//         free(normalized_utf8);
//         return NULL;
//     }

// free(normalized_u);

// return (const char *)normalized_utf8;
  u8chr_t encoding = 0;
  int len = u8length(input);
  printf("u8len: %d\n", len);
  int i=0;
  for (; i<len && input[i] != '\0'; i++) {
    encoding = (encoding << 8) | input[i];
  }
  printf("encoding: %d\n", encoding);
  printf("chisvalid: %d\n", u8chrisvalid(encoding));
  errno = 0;
  if (len == 0 || !u8chrisvalid(encoding)) {
    encoding = input[0];
    len = 1;
    errno = EINVAL;
  }
  printf("ret: %d\n", encoding ? len : 0);
  printf("errno: %d\n", errno);
  printf("errno: %s\n", strerror(errno));
  uint32_t dec = u8decode(encoding);
  printf("dec: %u\n", dec);
  u8chr_t enc = u8encode(dec);
  printf("enc: %d\n", enc);
  printf("isblank: %d\n", u8chrisblank(enc));
  printf("mbslen: %ld\n", wcslen(input));
  printf("mbslen: %d\n", strlen(input));
  printf("u8len: %d\n", u8chrisvalid(encoding));
  int l, z;
  char* output = dogecoin_char_vla(strlen(input) + 1);
  char* out ;
  if (!u8chrisvalid(encoding)) {
    for(i=0; i<strlen(input) && input[i]!='\0'; ) {
      if(!isunicode(input[i])) i++;
      else {
          l = 0;
          z = utf8_decode(&input[i],&l);
          char* codepoint = dogecoin_char_vla(l);
          sprintf(codepoint, "0x%04X", z);
          printf("hex codepoint:  %s\n", codepoint);


          uint32_t h;
          sscanf(codepoint, "%x", &h);
          u8chr_t u8ch = u8encode(h);
          printf("h (dec codept): %d\n", h);
          printf("u8ch:           %04x\n", u8ch);

          int len = utf8_encode(&out, h);
          printf("len:            %d\n", len);
          printf("u8length(&out): %d\n", u8length(&out));
          printf("out:            %s\n", &out);

          print_string_as_hex(&out);
          
          sprintf(&output[i], "%s", &out);
          
          printf("output: %s\n", output);
          printf("output: %zu\n", strlen(output));
          printf("Unicode value at %d is U+%04X and it\'s %d bytes.\n",i,z,l);
          i += l;
      }
    }
    printf("input:      %s\n", input);
    printf("input len:  %zu\n", strlen(input));
    printf("output:     %s\n", output);
    printf("output len: %zu\n", strlen(output));
    return output;
  }
  return input;
}

// passphrase must be at most 256 characters otherwise it would be truncated
void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total)) {
  mnemonic = nfkd(mnemonic);
  int mnemoniclen = strlen(mnemonic);
  int passphraselen = strnlen(passphrase, 256);
#if USE_BIP39_CACHE
  // check cache
  if (mnemoniclen < 256 && passphraselen < 64) {
    int i;
    for (i = 0; i < BIP39_CACHE_SIZE; i++) {
      if (!bip39_cache[i].set) continue;
      if (strcmp(bip39_cache[i].mnemonic, mnemonic) != 0) continue;
      if (strcmp(bip39_cache[i].passphrase, passphrase) != 0) continue;
      // found the correct entry
      memcpy(seed, bip39_cache[i].seed, 512 / 8);
      return;
    }
  }
#endif
  uint8_t salt[8 + 256] = {0};
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase, passphraselen);
  static CONFIDENTIAL pbkdf2_hmac_sha512_context pctx;
  pbkdf2_hmac_sha512_init(&pctx, (const uint8_t *)mnemonic, mnemoniclen, salt,
                          passphraselen + 8);
  if (progress_callback) {
    progress_callback(0, BIP39_PBKDF2_ROUNDS);
  }
  int i;
  for (i = 0; i < 16; i++) {
    pbkdf2_hmac_sha512_write(&pctx, BIP39_PBKDF2_ROUNDS / 16);
    if (progress_callback) {
      progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 16,
                        BIP39_PBKDF2_ROUNDS);
    }
  }
  pbkdf2_hmac_sha512_finalize(&pctx, seed);
  dogecoin_mem_zero(salt, sizeof(salt));
#if USE_BIP39_CACHE
  // store to cache
  if (mnemoniclen < 256 && passphraselen < 64) {
    bip39_cache[bip39_cache_index].set = true;
    strcpy(bip39_cache[bip39_cache_index].mnemonic, mnemonic);
    strcpy(bip39_cache[bip39_cache_index].passphrase, passphrase);
    memcpy(bip39_cache[bip39_cache_index].seed, seed, 512 / 8);
    bip39_cache_index = (bip39_cache_index + 1) % BIP39_CACHE_SIZE;
  }
#endif
}

// binary search for finding the word in the wordlist
int mnemonic_find_word(const char *word) {
  int lo = 0, hi = BIP39_WORD_COUNT - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    int cmp = strcmp(word, wordlist[mid]);
    if (cmp == 0) {
      return mid;
    }
    if (cmp > 0) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return -1;
}

const char *mnemonic_complete_word(const char *prefix, int len) {
  // we need to perform linear search,
  // because we want to return the first match
  int i;
  for (i = 0; i < BIP39_WORD_COUNT; i++) {
    if (strncmp(wordlist[i], prefix, len) == 0) {
      return wordlist[i];
    }
  }
  return NULL;
}

const char *mnemonic_get_word(int index) {
  if (index >= 0 && index < BIP39_WORD_COUNT) {
    return wordlist[index];
  } else {
    return NULL;
  }
}

uint32_t mnemonic_word_completion_mask(const char *prefix, int len) {
  if (len <= 0) {
    return 0x3ffffff;  // all letters (bits 1-26 set)
  }
  uint32_t res = 0;
  int i;
  for (i = 0; i < BIP39_WORD_COUNT; i++) {
    const char *word = wordlist[i];
    if (strncmp(word, prefix, len) == 0 && word[len] >= 'a' &&
        word[len] <= 'z') {
      res |= 1 << (word[len] - 'a');
    }
  }
  return res;
}

/**
 * @brief This funciton generates a mnemonic for
 * a given entropy size and language
 *
 * @param entropy_size The 128, 160, 192, 224, or 256 bits of entropy
 * @param language The ISO 639-2 code for the mnemonic language
 *
 * @return mnemonic code words
*/
const char* dogecoin_generate_mnemonic (const char* entropy_size, const char* language)
{
    static char words[] = "";

    if (entropy_size != NULL && language != NULL) {
        /* load word file into memory */
        get_words(language);

        /* convert string value to long */
        long entropyBits = strtol(entropy_size, NULL, 10);

        /* actual program call */
        mnemonic_generate(entropyBits);

    }

    return words;
}
