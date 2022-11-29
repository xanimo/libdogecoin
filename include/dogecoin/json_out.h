/*

 The MIT License (MIT)

 Copyright (c) 2022 raffecat
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

#ifndef __LIBDOGECOIN_JSON_OUT_H__
#define __LIBDOGECOIN_JSON_OUT_H__

#include <dogecoin/dogecoin.h>

enum doge_stream_flags {        // bit flags:
    doge_stream_error = 1,      // an error encoding the stream (stream is invalid)
    doge_stream_indent = 2,     // JSON: use indentation (pretty-print)
    doge_stream_need_comma = 4, // JSON: subsequent value requires a comma prefix
};

struct doge_stream_segment;
struct cstring;
struct dogecoin_tx_;

// allocate on the stack - contents are private.
typedef struct doge_stream {
    uint32_t ofs;               // offset within current tail segment
    uint32_t flags;             // doge_stream_flags
    struct doge_stream_segment* head;  // head segment (linked list via `next`)
    struct doge_stream_segment* tail;  // current tail segment
    uint32_t depth;             // indentation depth for JSON (optional)
} doge_stream;

// initialise an output stream with an initial empty segment.
// doge_stream should be allocated on the stack.
doge_stream doge_stream_new_membuf(uint32_t flags); // doge_stream_flags

// free a doge_stream instance.
void doge_stream_free(doge_stream* s);

// append N bytes to a doge_stream.
void doge_stream_out_n(doge_stream* s, const char* str, size_t n);

// append bytes between 'begin' and 'end' (excludes end)
void doge_stream_out_slice(doge_stream* s, const char* begin, const char* end);

// encode bytes as HEX and append to the stream.
void doge_stream_out_hex(doge_stream* s, const unsigned char* data, size_t len);

// copy the stream contents into a new cstring.
struct cstring* doge_stream_to_cstring(doge_stream* s);

// JSON output to stream.
void doge_json_out_str(doge_stream* out, const char* value);
void doge_json_out_str_begin(doge_stream* out);
void doge_json_out_str_end(doge_stream* out);
void doge_json_out_hex_str(doge_stream* out, const unsigned char* data, size_t len);
void doge_json_out_raw(doge_stream* out, char* value);
void doge_json_out_dbl(doge_stream* out, double value);
void doge_json_out_int(doge_stream* out, int64_t value);
void doge_json_out_bool(doge_stream* out, dogecoin_bool value);
void doge_json_out_null(doge_stream* out);
void doge_json_out_obj_begin(doge_stream* out);
void doge_json_out_obj_key(doge_stream* out, const char* key);
void doge_json_out_obj_end(doge_stream* out);
void doge_json_out_arr_begin(doge_stream* out);
void doge_json_out_arr_end(doge_stream* out);

// Script disassembly output to stream.
void doge_script_out_asm(doge_stream* out, const unsigned char* script, size_t len);

// Transaction output to stream.
void doge_txn_to_json(doge_stream* out, const struct dogecoin_tx_* tx);

#endif
