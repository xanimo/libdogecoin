/*

 The MIT License (MIT)

 Copyright (c) 2024 edtubbs, bluezr
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

#ifndef __LIBDOGECOIN_REST_H__
#define __LIBDOGECOIN_REST_H__

#include <dogecoin/dogecoin.h>

#include <stdbool.h>

#include <event2/buffer.h>
#include <event2/http.h>

LIBDOGECOIN_BEGIN_DECL

#define DELIM_DOT "."
#define DELIM_COLON ":"

LIBDOGECOIN_API void dogecoin_http_request_cb(struct evhttp_request *req, void *arg);
LIBDOGECOIN_API bool valid_ip_section(const char* s);
LIBDOGECOIN_API bool valid_port_section(const char* s);
LIBDOGECOIN_API int is_valid_ip(char* ip);
LIBDOGECOIN_API int is_valid_port(char* port);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_REST_H__
