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
#include <wctype.h>
#include <uninorm.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
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

int u8strlen(const char *s)
{
  int len=0;
  while (*s) {
    if ((*s & 0xC0) != 0x80) len++ ;
    s++;
  }
  return len;
}

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

static const unsigned int offsetsFromUTF8[6] = 
{
    0x00000000UL, 0x00003080UL, 0x000E2080UL,
    0x03C82080UL, 0xFA082080UL, 0x82082080UL
};

static const unsigned char trailingBytesForUTF8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};

int bbx_utf8_skip(const char *utf8)
{
  return trailingBytesForUTF8[(unsigned char) *utf8] + 1;
}

int bbx_utf8_getch(const char *utf8)
{
    int ch;
    int nb;

    nb = trailingBytesForUTF8[(unsigned char)*utf8];
    ch = 0;
    switch (nb) 
    {
            /* these fall through deliberately */
        case 3: ch += (unsigned char)*utf8++; ch <<= 6;
        case 2: ch += (unsigned char)*utf8++; ch <<= 6;
        case 1: ch += (unsigned char)*utf8++; ch <<= 6;
        case 0: ch += (unsigned char)*utf8++;
    }
    ch -= offsetsFromUTF8[nb];

    return ch;
}

int bbx_utf8_putch(char *out, int ch)
{
  char *dest = out;
  if (ch < 0x80) 
  {
     *dest++ = (char)ch;
  }
  else if (ch < 0x800) 
  {
    *dest++ = (ch>>6) | 0xC0;
    *dest++ = (ch & 0x3F) | 0x80;
  }
  else if (ch < 0x10000) 
  {
     *dest++ = (ch>>12) | 0xE0;
     *dest++ = ((ch>>6) & 0x3F) | 0x80;
     *dest++ = (ch & 0x3F) | 0x80;
  }
  else if (ch < 0x110000) 
  {
     *dest++ = (ch>>18) | 0xF0;
     *dest++ = ((ch>>12) & 0x3F) | 0x80;
     *dest++ = ((ch>>6) & 0x3F) | 0x80;
     *dest++ = (ch & 0x3F) | 0x80;
  }
  else
    return 0;
  return dest - out;
}

char* cat[] = {
  "hangol_jamo",
  "jp_punctuation", 
  "jp_hiragana", 
  "jp_katakana", 
  "fw_roman_hw_katakana", 
  "cjk_unified_common", 
  "cjk_unified_rare", 
  "cjk_unified_very_rare"
  };

int classify(int codepoint, char* cat)
{
  if (strcmp(cat, "hangol_jamo")==0) {
    return codepoint >= 0x1100 && codepoint <= 0x11FF;
  } else if (strcmp(cat, "jp_punctuation")==0) {
    return codepoint >= 0x3000 && codepoint <= 0x303F;
  } else if (strcmp(cat, "jp_hiragana")==0) {
    return codepoint >= 0x3040 && codepoint <= 0x309F;
  } else if (strcmp(cat, "jp_katakana")==0) {
    return codepoint >= 0x30A0 && codepoint <= 0x30FF;
  } else if (strcmp(cat, "fw_roman_hw_katakana")==0) {
    return codepoint >= 0xFF00 && codepoint <= 0xFFEF;
  } else if (strcmp(cat, "cjk_unified_common")==0) {
    return codepoint >= 0x4E00 && codepoint <= 0x9FAF;
  } else if (strcmp(cat, "cjk_unifed_rare")==0) {
    return codepoint >= 0x3400 && codepoint <= 0x4DBF;
  } else if (strcmp(cat, "cjk_unified_very_rare")==0) {
    return codepoint >= 0x20000 && codepoint <= 0x2A6DF;
  } else {
    printf("unrecognized category!\n");
    return false;
  }
}

const char *nfkd(const char *input) {
  u8chr_t encoding = 0;
  int len = u8length(input);
  int i=0;
  for (; i<len && input[i] != '\0'; i++) {
    encoding = (encoding << 8) | input[i];
  }
  errno = 0;
  if (len == 0 || !u8chrisvalid(encoding)) {
    encoding = input[0];
    len = 1;
    errno = EINVAL;
  }

  int l, z, first_char, jp_hiragana = 0, cjk_unified_common = 0, hangol_jamo = 0;

  // grab first char for language detection:
  first_char = utf8_decode(&input[0], &l);

  jp_hiragana = classify(first_char, "jp_hiragana");
  cjk_unified_common = classify(first_char, "cjk_unified_common");
  hangol_jamo = classify(first_char, "hangol_jamo");
  
  // jp_hiragana seems to be only problematic char set so
  // return input as-is for hangol_jamo and cjk_unified_common:
  if (hangol_jamo || cjk_unified_common) return input;
  if (!u8chrisvalid(encoding)) {
    char* output = dogecoin_calloc(1, strlen(input) - 1);
    for(i = 0; i < strlen(input) - 1 && input[i] != '\0';) {
        if (!isunicode(input[i])) i++;
        else {
          l = 0;
          z = utf8_decode(&input[i], &l);
          char* out;
          if (z==12288 && jp_hiragana) z=32;
          out = dogecoin_calloc(1, l + 1);
          bbx_utf8_putch(out, z);
          append(output, out);
          dogecoin_free(out);
          i += l;
        }
    }
    // return properly parsed string:
    input=output;
    free(output);
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
  memcpy(salt, nfkd("mnemonic"), 8);
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
