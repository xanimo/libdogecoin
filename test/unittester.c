/**********************************************************************
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libdogecoin-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utest.h"

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x, c) __builtin_expect((x), (c))
#else
#define EXPECT(x, c) (x)
#endif

#define TEST_FAILURE(msg)                                        \
    do {                                                         \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
        abort();                                                 \
    } while (0)

#define CHECK(cond)                                        \
    do {                                                   \
        if (EXPECT(!(cond), 0)) {                          \
            TEST_FAILURE("test condition failed: " #cond); \
        }                                                  \
    } while (0)

int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;

int main()
{
    return U_TESTS_FAIL;
}
