/**********************************************************************
 * Copyright (c) 2024 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <test/utest.h>

#include <dogecoin/map.h>

/* Regression for the id-reuse / HASH_REPLACE-eviction defect in the map.c
   stores. Both new_hash() and new_map() derived ids from HASH_COUNT()+1, so
   removing an entry let the next start_hash()/start_map() mint the id of a
   still-live entry, which add_hash()/add_map() then evicted via HASH_REPLACE
   (silently destroying and freeing a live entry). With a monotonic id source
   the third entry gets a fresh id and the second survives. */
void test_map_idx_not_reused()
{
    /* ---- hashes store ---- */
    remove_all_hashes();
    {
        int a = start_hash();
        int b = start_hash();
        u_assert_true(a > 0 && b > 0 && a != b);

        hash* ha = find_hash(a);
        u_assert_true(ha != NULL);
        remove_hash(ha);

        int c = start_hash();
        u_assert_true(c != b);                  /* must not recycle b's id */
        u_assert_true(find_hash(b) != NULL);    /* b survived (not evicted) */
        u_assert_true(find_hash(c) != NULL);

        int present = 0;
        for (int i = 1; i <= 16; i++) if (find_hash(i)) present++;
        u_assert_int_eq(present, 2);            /* exactly b and c remain */
    }
    remove_all_hashes();

    /* ---- maps store ---- */
    remove_all_maps();
    {
        int a = start_map();
        int b = start_map();
        u_assert_true(a > 0 && b > 0 && a != b);

        map* ma = find_map(a);
        u_assert_true(ma != NULL);
        remove_map(ma);

        int c = start_map();
        u_assert_true(c != b);
        u_assert_true(find_map(b) != NULL);
        u_assert_true(find_map(c) != NULL);
    }
    remove_all_maps();
    remove_all_hashes();
}
