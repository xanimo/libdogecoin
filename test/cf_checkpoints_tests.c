/**********************************************************************
 * Copyright (c) 2026 bluezr                                          *
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <dogecoin/cf_checkpoints.h>
#include <dogecoin/compact_filter.h>

#include <string.h>

/* These arrays are trust anchors: a filter header chain is accepted because it
 * agrees with them. They are also 12,862 lines of generated data that nobody
 * can review by reading, so the properties they are supposed to have are
 * asserted here instead.
 *
 * The spacing check is the load-bearing one. It is per network -- 1,000 on
 * mainnet, 10,000 on testnet -- and getcfcheckpt responds at multiples of
 * CFCHECKPT_INTERVAL regardless, so an entry at an unexpected height would be
 * compared against the wrong response element and reject a chain that is fine.
 */
static void check_cf_array(const dogecoin_cf_checkpoint *arr,
                           size_t count,
                           uint32_t spacing)
{
    size_t i;

    u_assert_true(count > 0);

    for (i = 0; i < count; i++) {
        size_t hexlen = strlen(arr[i].filter_header);

        /* 32 bytes hex-encoded; anything shorter leaves the anchor partly
           uninitialised once it is parsed. */
        u_assert_int_eq((int)hexlen, 64);
        u_assert_true(strspn(arr[i].filter_header, "0123456789abcdefABCDEF") == hexlen);

        /* Every height sits on the network's spacing, and the first entry is
           one interval in rather than at genesis. */
        u_assert_true(arr[i].height > 0);
        u_assert_int_eq((int)(arr[i].height % spacing), 0);

        if (i == 0) continue;

        /* Strictly increasing and contiguous: a gap would silently skip an
           anchor, and a repeat would compare two responses against one. */
        u_assert_true(arr[i].height > arr[i - 1].height);
        u_assert_int_eq((int)(arr[i].height - arr[i - 1].height), (int)spacing);
    }
}

void test_cf_checkpoints(void)
{
    check_cf_array(dogecoin_mainnet_cf_checkpoint_array,
                   dogecoin_mainnet_cf_checkpoint_count,
                   CFCHECKPT_INTERVAL);

    /* Ten times the protocol interval, deliberately -- see cf_checkpoints.h. */
    check_cf_array(dogecoin_testnet_cf_checkpoint_array,
                   dogecoin_testnet_cf_checkpoint_count,
                   CFCHECKPT_INTERVAL * 10);

    /* Mainnet anchors must reach further than testnet's do in count terms is
       not a safe assumption -- testnet is the longer chain -- so assert only
       that both are populated and that mainnet starts at the protocol
       interval, which is what a getcfcheckpt response will be keyed to. */
    u_assert_int_eq((int)dogecoin_mainnet_cf_checkpoint_array[0].height,
                    (int)CFCHECKPT_INTERVAL);
}
