/**********************************************************************
 * Copyright (c) 2026 bluezr                                          *
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <dogecoin/chainparams.h>
#include <dogecoin/utils.h>

#include <string.h>

/* The parallel header downloader builds one segment per adjacent pair of
 * checkpoints and treats each checkpoint hash as a trust anchor: it skips
 * proof-of-work between them and verifies only that each segment lands on its
 * terminal hash. Every property that relies on -- segment count, ordering,
 * non-overlap, the anchors themselves -- comes from these arrays, and nothing
 * checked them.
 *
 * The exported counts are load-bearing rather than cosmetic. They exist
 * because callers used to derive the length with sizeof(array)/sizeof(*array),
 * which on an extern array yields whatever bound the header declares. The
 * headers said [87] and [33] against 90 real entries, so a checkpoint
 * extension compiled, passed the suite, and was silently ignored. */

static void check_array(const char *name,
                        const dogecoin_checkpoint *arr,
                        size_t count)
{
    size_t i;

    /* A zero count would make every loop below vacuous, which is the failure
     * mode this file exists to prevent. */
    u_assert_true(count > 0);

    for (i = 0; i < count; i++) {
        size_t hexlen = strlen(arr[i].hash);

        /* 32 bytes, hex-encoded. utils_uint256_sethex reads a fixed width, so
         * a short string leaves the tail of the anchor uninitialised rather
         * than failing. */
        u_assert_int_eq((int)hexlen, 64);
        u_assert_true(strspn(arr[i].hash, "0123456789abcdefABCDEF") == hexlen);

        /* Timestamp and bits are carried into the header DB for the anchor, so
         * a zeroed entry would seed it with something meaningless. */
        u_assert_true(arr[i].timestamp != 0);
        u_assert_true(arr[i].target != 0);

        if (i == 0) continue;

        /* Strictly increasing. Equal heights would produce a zero-length
         * segment; decreasing heights would produce one whose stop is below
         * its start, and the downloader would wait forever for headers that
         * cannot arrive. */
        u_assert_true(arr[i].height > arr[i - 1].height);

        /* Distinct anchors. Two checkpoints sharing a hash would let a
         * segment satisfy its terminal check against the wrong block. */
        u_assert_true(strcmp(arr[i].hash, arr[i - 1].hash) != 0);
    }

    (void)name;
}

void test_checkpoints()
{
    check_array("mainnet",
                dogecoin_mainnet_checkpoint_array,
                dogecoin_mainnet_checkpoint_count);

    check_array("testnet",
                dogecoin_testnet_checkpoint_array,
                dogecoin_testnet_checkpoint_count);

    /* Guard the bug that motivated exporting the counts: if anyone reverts to
     * sizeof() on the extern array, this stops matching the real length.
     * sizeof on an array of unknown bound is a constraint violation, so this
     * has to compare against something the definition controls. */
    u_assert_true(dogecoin_mainnet_checkpoint_count >
                  dogecoin_testnet_checkpoint_count);

    /* Entry 0 is genesis, on both chains. The downloader relies on this: it
     * starts building segments at index 1 and supplies genesis separately as
     * the first segment's start anchor, so N checkpoints yield N-1 segments.
     * If a non-genesis checkpoint were ever prepended, segment 0 would span
     * genesis..that height while claiming to span genesis..checkpoint[1], and
     * the terminal-hash check would reject it.
     *
     * Asserted rather than assumed because the author of this test assumed the
     * opposite and was wrong. */
    u_assert_int_eq((int)dogecoin_mainnet_checkpoint_array[0].height, 0);
    u_assert_int_eq((int)dogecoin_testnet_checkpoint_array[0].height, 0);

    /* Only entry 0 may be genesis; a second height-0 entry would produce a
     * zero-length segment. Covered by the strictly-increasing check above, but
     * stated here because it is the property the segment builder depends on. */
    u_assert_true(dogecoin_mainnet_checkpoint_array[1].height > 0);
    u_assert_true(dogecoin_testnet_checkpoint_array[1].height > 0);
}
